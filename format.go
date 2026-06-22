package filesystem_zfs

// format.go – Creates a new, empty ZFS pool image.
//
// The pool is a single-device, ashift=12 (4 KiB blocks), no compression pool
// with a single empty root dataset.  It is intentionally minimal: no snapshots,
// no dedup, no feature-flag housekeeping beyond what Open() needs.
//
// On-disk layout (all offsets relative to file start, partOff=0):
//
//   0x000000  Label L0  (256 KiB)
//   0x040000  Label L1  (256 KiB)
//   0x080000  MOS objset block                    (4 KiB)
//   0x081000  MOS object array                    (16 KiB, 32 dnodes)
//   0x085000  Pool directory ZAP                  (4 KiB)
//   0x086000  ZPL objset block                    (4 KiB)
//   0x087000  ZPL object array                    (16 KiB, 32 dnodes)
//   0x08B000  ZPL master node ZAP                 (4 KiB)
//   0x08C000  ZPL unlinked set ZAP                (4 KiB)
//   0x08D000  Root directory ZAP                  (4 KiB)
//   0x08E000  (next free offset for new writes)
//   ...
//   size-0x80000  Label L2  (256 KiB)
//   size-0x40000  Label L3  (256 KiB)

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

// FormatConfig holds optional parameters for Format.
type FormatConfig struct {
	// PoolName is stored in the vdev label nvlist; defaults to "data".
	PoolName string
	// PoolGUID is the 64-bit pool GUID; a time-derived value is used when zero.
	PoolGUID uint64
}

const (
	// Pool data layout (byte offsets from partition start)
	fmtMOSObjsetOff     = 512 * 1024                   // 0x080000
	fmtMOSObjArrayOff   = fmtMOSObjsetOff + 4*1024     // 0x081000
	fmtPoolDirZAPOff    = fmtMOSObjArrayOff + 16*1024  // 0x085000
	fmtZPLObjsetOff     = fmtPoolDirZAPOff + 4*1024    // 0x086000
	fmtZPLObjArrayOff   = fmtZPLObjsetOff + 4*1024     // 0x087000
	fmtMasterNodeZAPOff = fmtZPLObjArrayOff + 16*1024  // 0x08B000
	fmtUnlinkedZAPOff   = fmtMasterNodeZAPOff + 4*1024 // 0x08C000
	fmtRootDirZAPOff    = fmtUnlinkedZAPOff + 4*1024   // 0x08D000
	// SA infrastructure data blocks (ZPL objects 4..6). The kernel reads
	// these at mount to interpret each znode's SA bonus. See safat.go.
	fmtSAMasterZAPOff   = fmtRootDirZAPOff + 4*1024    // SA master node microZAP (SA_ATTRS)
	fmtSARegistryZAPOff = fmtSAMasterZAPOff + 4*1024   // attribute REGISTRY microZAP
	fmtSALayoutsHdrOff  = fmtSARegistryZAPOff + 4*1024 // LAYOUTS fat-ZAP header block (blkid 0)
	fmtSALayoutsLeafOff = fmtSALayoutsHdrOff + 4*1024  // LAYOUTS fat-ZAP leaf block (blkid 1)
	fmtSALayoutsIndOff  = fmtSALayoutsLeafOff + 4*1024 // LAYOUTS L1 indirect block (2 BPs)
	fmtConfigOff        = fmtSALayoutsIndOff + 4*1024  // (packed MOS config nvlist)
	fmtFeatReadZAPOff   = fmtConfigOff + 16*1024       // 0x092000 (features_for_read ZAP)
	fmtFeatWriteZAPOff  = fmtFeatReadZAPOff + 4*1024   // 0x093000 (features_for_write ZAP)
	fmtFeatDescZAPOff   = fmtFeatWriteZAPOff + 4*1024  // 0x094000 (feature_descriptions ZAP)
	// DSL special-directory hierarchy that dsl_pool_open() requires on a
	// v5000 pool: the root DSL dir's child map ($MOS/$FREE/$ORIGIN), the
	// three special dirs, the $ORIGIN head dataset + its origin snapshot,
	// their deadlists, and the pool-wide free bpobj. See the block-build
	// section for how each object is wired.
	fmtRootChildZAPOff = fmtFeatDescZAPOff + 4*1024  // 0x095000 root dir child map
	fmtMOSDirOff       = fmtRootChildZAPOff + 4*1024 // 0x096000 $MOS child map
	fmtFreeDirChildOff = fmtMOSDirOff + 4*1024       // 0x097000 $FREE child map
	fmtOriginChildOff  = fmtFreeDirChildOff + 4*1024 // 0x098000 $ORIGIN child map
	fmtOriginHeadDLOff = fmtOriginChildOff + 4*1024  // 0x099000 $ORIGIN head deadlist ZAP
	fmtOriginSnapDLOff = fmtOriginHeadDLOff + 4*1024 // 0x09A000 origin snapshot deadlist ZAP
	fmtFreeBpobjOff    = fmtOriginSnapDLOff + 4*1024 // 0x09B000 pool free bpobj data block
	// Per-DSL-dir property ZAPs. dsl_prop_get_dd() does
	// zap_lookup(dd_props_zapobj, ...) while resolving inherited
	// properties; a zero props zapobj points at MOS object 0 (the
	// meta-dnode, not a ZAP) and zap_lookup returns EINVAL, failing
	// dsl_pool_open. Each dir therefore needs a real (empty) props ZAP.
	fmtRootPropsOff   = fmtFreeBpobjOff + 4*1024 // 0x09C000 root dir props
	fmtMOSPropsOff    = fmtRootPropsOff + 4*1024 // 0x09D000 $MOS dir props
	fmtFreePropsOff   = fmtMOSPropsOff + 4*1024  // 0x09E000 $FREE dir props
	fmtOriginPropsOff = fmtFreePropsOff + 4*1024 // 0x09F000 $ORIGIN dir props
	// $ORIGIN head dataset's snapshot-name map. dsl_dataset_get_snapname()
	// (reached when zdb sets ZFS_DEBUG_SNAPNAMES) does
	// zap_value_search(head->ds_snapnames_zapobj, snapobj) to name the
	// origin snapshot; a zero snapnames obj points at MOS object 0 and
	// returns EINVAL. The ZAP maps "$ORIGIN" → the snapshot object.
	fmtOriginSnapNamesOff = fmtOriginPropsOff + 4*1024 // 0x0A0000
	// Deferred-frees ("sync") bpobj. spa_load_impl() requires the
	// pool-directory "sync_bplist" entry and opens it as a bpobj
	// (spa_deferred_bpobj); a missing entry fails the load with ENOENT.
	fmtSyncBpobjOff = fmtOriginSnapNamesOff + 4*1024 // 0x0A1000
	// Root head dataset's own deadlist + snapshot-name map. When
	// dmu_objset_find enumerates the pool's filesystems it holds the root
	// head dataset (object 3) and opens/closes its deadlist; a zero
	// deadlist obj makes dsl_deadlist_close dereference an unopened buffer
	// and zdb -d segfaults.
	fmtRootDLOff        = fmtSyncBpobjOff + 4*1024 // 0x0A2000 root head deadlist
	fmtRootSnapNamesOff = fmtRootDLOff + 4*1024    // 0x0A3000 root head snap map
	// Metaslab spacemap region. The metaslab_array object's data block
	// holds one uint64 per metaslab (the per-metaslab space_map object
	// number). Each metaslab that has had any allocation also gets a
	// space_map object whose data block holds the on-disk space-map log.
	// For our small images everything Format() writes lands in metaslab 0,
	// so only metaslab 0 needs a populated space map; the remaining
	// metaslabs are entirely free (array entry 0 / no space_map object).
	fmtMetaslabArrayOff = fmtRootSnapNamesOff + 4*1024 // 0x0A4000 metaslab_array data block
	fmtSpaceMap0Off     = fmtMetaslabArrayOff + 4*1024 // 0x0A5000 metaslab-0 space_map log
	fmtInitialNextFree  = fmtSpaceMap0Off + 4*1024     // 0x0A6000

	fmtObjArraySize = 16 * 1024 // 16 KiB = 32 × 512-byte dnodes
	fmtObjArrayObjs = fmtObjArraySize / dnodeMinSize

	// fmtConfigBlkSize is the data-block size of the packed config object.
	// 16 KiB comfortably holds our small config nvlist.
	fmtConfigBlkSize = 16 * 1024

	// MOS object numbers
	fmtMOSPoolDirObj    = 1
	fmtMOSDSLDirObj     = 2
	fmtMOSDSLDatasetObj = 3
	fmtMOSConfigObj     = 4 // packed pool config nvlist (DMU_OT_PACKED_NVLIST)
	fmtMOSFeatReadObj   = 5 // features_for_read ZAP (empty on a no-feature pool)
	fmtMOSFeatWriteObj  = 6 // features_for_write ZAP (empty on a no-feature pool)
	fmtMOSFeatDescObj   = 7 // feature_descriptions ZAP (empty on a no-feature pool)
	// DSL special-directory hierarchy (objects 8..19). dsl_pool_open()
	// on a v5000 pool walks the root DSL dir's child map for the three
	// special dirs $MOS / $FREE / $ORIGIN, then for $ORIGIN holds its
	// head dataset and that head's prev-snapshot (the origin snap). Each
	// dataset opens its deadlist; the pool also opens the free bpobj
	// named by the pool-directory "free_bpobj" entry.
	fmtMOSRootChildObj    = 8  // root DSL dir child map ($MOS/$FREE/$ORIGIN)
	fmtMOSDirObj          = 9  // $MOS special DSL dir
	fmtMOSFreeDirObj      = 10 // $FREE special DSL dir
	fmtMOSOriginDirObj    = 11 // $ORIGIN special DSL dir
	fmtMOSDirChildObj     = 12 // $MOS dir's (empty) child map
	fmtMOSFreeChildObj    = 13 // $FREE dir's (empty) child map
	fmtMOSOriginHeadObj   = 14 // $ORIGIN head dataset
	fmtMOSOriginChildObj  = 15 // $ORIGIN dir's (empty) child map
	fmtMOSOriginSnapObj   = 16 // origin snapshot dataset
	fmtMOSOriginHeadDL    = 17 // $ORIGIN head dataset deadlist
	fmtMOSOriginSnapDL    = 18 // origin snapshot deadlist
	fmtMOSFreeBpobjObj    = 19 // pool-wide free bpobj
	fmtMOSRootPropsObj    = 20 // root DSL dir props ZAP (empty)
	fmtMOSDirPropsObj     = 21 // $MOS dir props ZAP (empty)
	fmtMOSFreePropsObj    = 22 // $FREE dir props ZAP (empty)
	fmtMOSOriginPropsObj  = 23 // $ORIGIN dir props ZAP (empty)
	fmtMOSOriginSnapNames = 24 // $ORIGIN head dataset snapshot-name map
	fmtMOSSyncBpobjObj    = 25 // deferred-frees ("sync") bpobj
	fmtMOSRootDLObj       = 26 // root head dataset deadlist
	fmtMOSRootSnapNames   = 27 // root head dataset snapshot-name map
	// Metaslab objects. The metaslab_array (object 28) is a uint64 array
	// naming each metaslab's space_map object; only metaslab 0 carries any
	// allocation on a freshly formatted pool, so it is the single space_map
	// object (29). The leaf vdev's "metaslab_array" nvpair points at 28.
	fmtMOSMetaslabArray = 28 // DMU_OT_OBJECT_ARRAY: array of space_map obj nums
	fmtMOSSpaceMap0Obj  = 29 // DMU_OT_SPACE_MAP for metaslab 0
	// fmtMOSObjCount is the number of allocated MOS objects (1..29); it
	// is the objset block pointer's fill count. Keep in sync with the
	// highest fmtMOS* object number above.
	fmtMOSObjCount = 29
	// fmtZPLObjCount is the number of allocated ZPL objects (master node,
	// unlinked set, root dir, SA master/registry/layouts = 1..6).
	fmtZPLObjCount = 6

	// ZPL object numbers
	fmtZPLMasterNode = 1
	fmtZPLUnlinked   = 2
	fmtZPLRootDir    = 3
	fmtZPLSAMaster   = 4 // DMU_OT_SA_MASTER_NODE (SA_ATTRS): REGISTRY+LAYOUTS
	fmtZPLSARegistry = 5 // DMU_OT_SA_ATTR_REGISTRATION
	fmtZPLSALayouts  = 6 // DMU_OT_SA_ATTR_LAYOUTS (fat-ZAP, uint16 arrays)

	fmtPoolVersion = 5000      // pool feature flags version
	fmtZPLVersion  = uint64(5) // ZPL version
	fmtPoolTXG     = uint64(1) // genesis transaction group

	// fmtFeatSpacemapHistogram is the GUID of the spacemap_histogram
	// feature. Once Format() emits a metaslab space_map with a
	// space_map_phys_t bonus, zdb's verify_spacemap_refcounts() expects the
	// feature refcount for this GUID to equal the number of such space maps
	// (get_metaslab_refcount counts every metaslab whose space map has a
	// sizeof(space_map_phys_t) bonus). We emit exactly one space map
	// (metaslab 0), so the feature is enabled in the label/MOS-config
	// "features_for_read" nvlist and — because spacemap_histogram is a
	// READONLY_COMPAT feature — its refcount (=1) is stored in the
	// features_for_WRITE MOS ZAP (see featWriteZAP below).
	fmtFeatSpacemapHistogram = "com.delphix:spacemap_histogram"

	// fmtVdevMetaslabArray is the MOS object id recorded in the leaf
	// vdev's metaslab_array nvpair. It points at the DMU_OT_OBJECT_ARRAY
	// (object 28) whose data block lists the per-metaslab space_map object
	// numbers, letting the metaslab loader open the vdev's allocation space
	// (required by `zpool import` and by `zdb -bcc` space accounting).
	fmtVdevMetaslabArray = fmtMOSMetaslabArray

	// fmtMetaslabShift is log2 of the metaslab size (16 MiB). It matches
	// the "metaslab_shift" written to the label / MOS config nvlists and is
	// the granularity at which Format() partitions the vdev asize into
	// metaslabs. Space-map entry offsets/runs are in 2^ashift (smShift)
	// units, independent of this value.
	fmtMetaslabShift = 24
)

// vdevGUIDFor derives the single leaf vdev's guid from the pool guid.
// It must differ from the pool guid (OpenZFS treats a leaf whose guid
// equals the root/pool guid as a duplicate of the root and reports a
// missing top-level vdev). The mix is deterministic so a given PoolGUID
// always yields the same vdev guid, keeping Format() reproducible.
func vdevGUIDFor(poolGUID uint64) uint64 {
	g := poolGUID ^ 0x9E3779B97F4A7C15 // golden-ratio mix
	if g == 0 {
		g = poolGUID | 1
	}
	return g
}

// Format creates a new empty ZFS pool in the file at path.
// sizeBytes must be at least 4 MiB.
// On success, the newly created pool is opened and returned; the caller must
// call Close when done.
func Format(path string, sizeBytes int64, cfg FormatConfig) (FS, error) {
	const minSize = 4 * 1024 * 1024
	if sizeBytes < minSize {
		return nil, fmt.Errorf("zfs: format: size %d below minimum %d bytes", sizeBytes, minSize)
	}

	poolName := cfg.PoolName
	if poolName == "" {
		poolName = "data"
	}
	poolGUID := cfg.PoolGUID
	if poolGUID == 0 {
		poolGUID = uint64(time.Now().UnixNano()) | 1
	}
	// The single leaf (= top-level) vdev needs a guid distinct from the
	// pool guid, exactly as real `zpool create` does: pool_guid
	// identifies the pool, top_guid/guid identify the vdev.
	vdevGUID := vdevGUIDFor(poolGUID)
	now := uint64(time.Now().Unix())

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("zfs: format: %w", err)
	}
	f.Truncate(sizeBytes)

	w := f

	// ── helper: write a block at absolute offset ─────────────────────────────
	writeAt := func(off int64, b []byte) error {
		_, err := w.WriteAt(b, off)
		return err
	}

	// ── makeBP: convenience wrapper for makeBlkptr with compress=off and a
	// fletcher4 block checksum computed over the physical block bytes
	// `phys`. fletcher4 is the algorithm real `zpool create` uses for the
	// MOS objset, dnode arrays, ZAPs and data on OpenZFS 2.3, so emitting
	// it (with the matching blk_prop checksum-type) lets `zdb -e -p` verify
	// our blocks during MOS/objset traversal. `phys` must be exactly the
	// bytes written at `off`. ───────────────────────────────────────────
	makeBP := func(off int64, physSize, logicalSize int, dtype uint8, phys []byte) blkptr {
		bp := makeBlkptrCksum(off, physSize, logicalSize, zcompressOff, dtype, 0, fmtPoolTXG, zioChecksumFletch4)
		setBPChecksum(&bp, phys)
		return bp
	}

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// 1. Build ZAP blocks
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

	// Pool directory ZAP: "root_dataset" → 2, "config" → 4,
	// "features_for_read" → 5, "features_for_write" → 6.
	poolDirZAP := newMicroZAPBlock(poolBlockSize)
	mzapInsert(poolDirZAP, dmuPoolRootDataset, fmtMOSDSLDirObj)
	mzapInsert(poolDirZAP, dmuPoolConfig, fmtMOSConfigObj)
	mzapInsert(poolDirZAP, dmuPoolFeaturesForRead, fmtMOSFeatReadObj)
	mzapInsert(poolDirZAP, dmuPoolFeaturesForWrite, fmtMOSFeatWriteObj)
	mzapInsert(poolDirZAP, dmuPoolFeatureDescriptions, fmtMOSFeatDescObj)
	mzapInsert(poolDirZAP, dmuPoolFreeBpobj, fmtMOSFreeBpobjObj)
	mzapInsert(poolDirZAP, dmuPoolSyncBpobj, fmtMOSSyncBpobjObj)

	// Root DSL dir's child map: the three special dirs dsl_pool_open()
	// requires. Each value is the MOS object number of that special dir.
	rootChildZAP := newMicroZAPBlock(poolBlockSize)
	mzapInsert(rootChildZAP, dslMOSDirName, fmtMOSDirObj)
	mzapInsert(rootChildZAP, dslFreeDirName, fmtMOSFreeDirObj)
	mzapInsert(rootChildZAP, dslOriginDirName, fmtMOSOriginDirObj)

	// Each special dir has its own (empty) child map.
	mosDirChildZAP := newMicroZAPBlock(poolBlockSize)
	freeDirChildZAP := newMicroZAPBlock(poolBlockSize)
	originDirChildZAP := newMicroZAPBlock(poolBlockSize)

	// Deadlists for the $ORIGIN head dataset and the origin snapshot are
	// empty microZAPs (mintxg → sub-bpobj); their dl_phys bonus tracks
	// zero used/comp/uncomp.
	originHeadDLZAP := newMicroZAPBlock(poolBlockSize)
	originSnapDLZAP := newMicroZAPBlock(poolBlockSize)

	// The bpobjs' data blocks hold arrays of blkptr_t entries; an empty
	// bpobj (num_blkptrs = 0) needs only a zero-filled block.
	freeBpobjBlock := make([]byte, poolBlockSize)
	syncBpobjBlock := make([]byte, poolBlockSize)

	// Empty per-dir property ZAPs (type DMU_OT_DSL_PROPS).
	rootPropsZAP := newMicroZAPBlock(poolBlockSize)
	mosPropsZAP := newMicroZAPBlock(poolBlockSize)
	freePropsZAP := newMicroZAPBlock(poolBlockSize)
	originPropsZAP := newMicroZAPBlock(poolBlockSize)

	// $ORIGIN head dataset's snapshot-name map: "$ORIGIN" → the origin
	// snapshot object, so dsl_dataset_get_snapname's zap_value_search
	// resolves the snapshot's name.
	originSnapNamesZAP := newMicroZAPBlock(poolBlockSize)
	mzapInsert(originSnapNamesZAP, dslOriginDirName, fmtMOSOriginSnapObj)

	// Root head dataset's deadlist (microZAP) + empty snapshot-name map.
	rootDLZAP := newMicroZAPBlock(poolBlockSize)
	rootSnapNamesZAP := newMicroZAPBlock(poolBlockSize)

	// features_for_read / features_for_write / feature_descriptions ZAPs.
	//
	// spacemap_histogram is a READONLY_COMPAT feature, so OpenZFS stores
	// its refcount in the features_for_WRITE ZAP (spa_feat_for_write_obj),
	// NOT features_for_read — feature_get_refcount_from_disk() picks the
	// ZAP by the ZFEATURE_FLAG_READONLY_COMPAT flag. The matching "enabled"
	// boolean still goes in the label's "features_for_read" nvlist (labels
	// only carry that one feature nvlist). The refcount equals the number
	// of metaslab space_maps with a space_map_phys_t bonus (1).
	featReadZAP := newMicroZAPBlock(poolBlockSize)
	featWriteZAP := newMicroZAPBlock(poolBlockSize)
	mzapInsert(featWriteZAP, fmtFeatSpacemapHistogram, 1)
	// feature_descriptions maps GUID → human string (a fat-ZAP value);
	// it is advisory only (zdb's refcount audit never reads it), so we
	// leave it empty rather than emit a malformed microZAP uint64 value.
	featDescZAP := newMicroZAPBlock(poolBlockSize)

	// ZPL master node ZAP. The kernel's zfs_init_fs() reads these at mount:
	//   "VERSION"      → ZPL version (5)
	//   "ROOT"         → root directory object
	//   "SA_ATTRS"     → SA master node object (REGISTRY + LAYOUTS); required
	//                    so sa_setup() can resolve each znode's layout.
	//   "DELETE_QUEUE" → unlinked set object (tolerated-missing, but real
	//                    pools always carry it; we point it at the unlinked ZAP).
	masterNodeZAP := newMicroZAPBlock(poolBlockSize)
	mzapInsert(masterNodeZAP, zplKeyRoot, fmtZPLRootDir)
	mzapInsert(masterNodeZAP, zplKeyVersion, fmtZPLVersion)
	mzapInsert(masterNodeZAP, zplKeySAAttrs, fmtZPLSAMaster)
	mzapInsert(masterNodeZAP, zplKeyDeleteQueue, fmtZPLUnlinked)

	// Unlinked set ZAP: empty
	unlinkedZAP := newMicroZAPBlock(poolBlockSize)

	// Root directory ZAP: empty
	rootDirZAP := newMicroZAPBlock(poolBlockSize)

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// 2. Build ZPL object array (16 KiB)
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	zplObjArray := make([]byte, fmtObjArraySize)

	// Object 1: ZPL master node ZAP dnode
	zplMasterDN := newDnode(dmotMasterNode, 1, dmotNone, 0)
	zplMasterDN.datablkszsec = uint16(poolBlockSize / 512) // 8
	zplMasterDN.setBlkptrAt(0, makeBP(fmtMasterNodeZAPOff, poolBlockSize, poolBlockSize, dmotMasterNode, masterNodeZAP))
	zplMasterDN.encode()
	copy(zplObjArray[fmtZPLMasterNode*dnodeMinSize:], zplMasterDN.raw)

	// Object 2: Unlinked set ZAP dnode
	zplUnlinkedDN := newDnode(dmotUnlinkedSet, 1, dmotNone, 0)
	zplUnlinkedDN.datablkszsec = uint16(poolBlockSize / 512)
	zplUnlinkedDN.setBlkptrAt(0, makeBP(fmtUnlinkedZAPOff, poolBlockSize, poolBlockSize, dmotUnlinkedSet, unlinkedZAP))
	zplUnlinkedDN.encode()
	copy(zplObjArray[fmtZPLUnlinked*dnodeMinSize:], zplUnlinkedDN.raw)

	// Object 3: Root directory dnode with SA bonus
	rootSAAttrs := &saAttrs{
		mode:   0o040755, // drwxr-xr-x
		size:   0,
		gen:    1,
		uid:    0,
		gid:    0,
		parent: fmtZPLRootDir,
		links:  2,
		atime:  [2]uint64{now, 0},
		mtime:  [2]uint64{now, 0},
		ctime:  [2]uint64{now, 0},
		crtime: [2]uint64{now, 0},
	}
	layout := saZnodeLayout()
	saBonus := writeSABonus(rootSAAttrs, layout)
	zplRootDN := newDnode(dmotDirContents, 1, dmotSA, uint16(len(saBonus)))
	zplRootDN.datablkszsec = uint16(poolBlockSize / 512)
	zplRootDN.setBlkptrAt(0, makeBP(fmtRootDirZAPOff, poolBlockSize, poolBlockSize, dmotDirContents, rootDirZAP))
	// Write bonus into dnode raw
	bonusStart := dnodeHdrSize + 1*blkptrSize
	copy(zplRootDN.raw[bonusStart:], saBonus)
	zplRootDN.encode()
	copy(zplObjArray[fmtZPLRootDir*dnodeMinSize:], zplRootDN.raw)

	// ── Objects 4/5/6: SA infrastructure (REGISTRY + LAYOUTS + master) ──
	// These let the OpenZFS kernel resolve each znode's SA layout at mount.
	// See safat.go for the on-disk encoding details.
	//
	// REGISTRY (obj 5): microZAP, attr-name → ATTR_ENCODE(num,len,bswap).
	saRegistryZAP := newMicroZAPBlock(poolBlockSize)
	for _, a := range zfsAttrTable {
		mzapInsert(saRegistryZAP, a.name, attrEncode(a.attr, a.length, a.bswap))
	}
	saRegistryDN := newDnode(dmotSAAttrRegistration, 1, dmotNone, 0)
	saRegistryDN.datablkszsec = uint16(poolBlockSize / 512)
	saRegistryDN.setBlkptrAt(0, makeBP(fmtSARegistryZAPOff, poolBlockSize, poolBlockSize, dmotSAAttrRegistration, saRegistryZAP))
	saRegistryDN.encode()
	copy(zplObjArray[fmtZPLSARegistry*dnodeMinSize:], saRegistryDN.raw)

	// LAYOUTS (obj 6): fat-ZAP, "N" → uint16 array of attribute numbers.
	// We register layout saZnodeLayoutNum = our znode packing order.
	layoutAttrs := saZnodeLayout()
	layoutVals := make([]uint64, len(layoutAttrs))
	for i, a := range layoutAttrs {
		layoutVals[i] = uint64(a)
	}
	saLayoutsHdr, saLayoutsLeaf, errLay := buildFatZAPObject(poolBlockSize, mzapDefaultSalt, []fatZAPEntry{
		{name: fmt.Sprintf("%d", saZnodeLayoutNum), intLen: 2, values: layoutVals},
	})
	if errLay != nil {
		return nil, fmt.Errorf("zfs: build LAYOUTS fat-zap: %w", errLay)
	}
	// The fat-ZAP object spans two logical 4 KiB blocks (header=blkid 0,
	// leaf=blkid 1) reached through one L1 indirect block holding both BPs.
	saLayHdrBP := makeBP(fmtSALayoutsHdrOff, poolBlockSize, poolBlockSize, dmotSAAttrLayouts, saLayoutsHdr)
	saLayLeafBP := makeBP(fmtSALayoutsLeafOff, poolBlockSize, poolBlockSize, dmotSAAttrLayouts, saLayoutsLeaf)
	saLayIndBlock := make([]byte, poolBlockSize)
	encodeBlkptr(saLayHdrBP, saLayIndBlock[0*blkptrSize:1*blkptrSize])
	encodeBlkptr(saLayLeafBP, saLayIndBlock[1*blkptrSize:2*blkptrSize])
	// L1 indirect BP: level 1, logical/physical size = one indirect block,
	// fletcher4 over the indirect block bytes, datatype = SA layouts.
	saLayIndBP := makeBlkptrCksum(fmtSALayoutsIndOff, poolBlockSize, poolBlockSize,
		zcompressOff, dmotSAAttrLayouts, 1, fmtPoolTXG, zioChecksumFletch4)
	// blk_fill of an indirect BP is the number of non-hole block pointers
	// reachable below it. The L1 indirect block holds two L0 data BPs
	// (header + leaf), so fill = 2; zdb's traversal verifies child fills
	// sum to the parent's and reports EBADE on a mismatch.
	saLayIndBP.fill = 2
	setBPChecksum(&saLayIndBP, saLayIndBlock)
	saLayoutsDN := newDnode(dmotSAAttrLayouts, 1, dmotNone, 0)
	saLayoutsDN.datablkszsec = uint16(poolBlockSize / 512)
	saLayoutsDN.indblkshift = 12 // 4 KiB indirect blocks
	saLayoutsDN.nlevels = 2
	saLayoutsDN.maxblkid = 1 // two data blocks: header + leaf
	saLayoutsDN.setBlkptrAt(0, saLayIndBP)
	saLayoutsDN.encode()
	copy(zplObjArray[fmtZPLSALayouts*dnodeMinSize:], saLayoutsDN.raw)

	// SA master node (obj 4): microZAP, "REGISTRY"→5, "LAYOUTS"→6.
	saMasterZAP := newMicroZAPBlock(poolBlockSize)
	mzapInsert(saMasterZAP, saKeyRegistry, fmtZPLSARegistry)
	mzapInsert(saMasterZAP, saKeyLayouts, fmtZPLSALayouts)
	saMasterDN := newDnode(dmotSAMasterNode, 1, dmotNone, 0)
	saMasterDN.datablkszsec = uint16(poolBlockSize / 512)
	saMasterDN.setBlkptrAt(0, makeBP(fmtSAMasterZAPOff, poolBlockSize, poolBlockSize, dmotSAMasterNode, saMasterZAP))
	saMasterDN.encode()
	copy(zplObjArray[fmtZPLSAMaster*dnodeMinSize:], saMasterDN.raw)

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// 3. Build ZPL objset block (4 KiB)
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	zplObjset := make([]byte, poolBlockSize)
	// ZPL meta_dnode (object 0): describes the ZPL object array
	zplMetaDN := newDnode(dmotDnode, 1, dmotNone, 0)
	zplMetaDN.datablkszsec = uint16(fmtObjArraySize / 512) // 32
	zplMetaBP := makeBP(fmtZPLObjArrayOff, fmtObjArraySize, fmtObjArraySize, dmotDnode, zplObjArray)
	zplMetaBP.fill = fmtZPLObjCount
	zplMetaDN.setBlkptrAt(0, zplMetaBP)
	zplMetaDN.encode()
	copy(zplObjset[0:], zplMetaDN.raw)
	// os_type = 2 (DMU_OST_ZFS) at offset 704
	binary.LittleEndian.PutUint64(zplObjset[objsetTypeOff:], dmuOSTZFS)

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// 4. Build MOS object array (16 KiB)
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	mosObjArray := make([]byte, fmtObjArraySize)

	// Object 1: Pool directory ZAP
	poolDirDN := newDnode(dmotObjectDirectory, 1, dmotNone, 0)
	poolDirDN.datablkszsec = uint16(poolBlockSize / 512)
	poolDirDN.setBlkptrAt(0, makeBP(fmtPoolDirZAPOff, poolBlockSize, poolBlockSize, dmotObjectDirectory, poolDirZAP))
	poolDirDN.encode()
	copy(mosObjArray[fmtMOSPoolDirObj*dnodeMinSize:], poolDirDN.raw)

	// Object 2: DSL directory dnode. The bonus must be a FULL
	// dsl_dir_phys_t: OpenZFS dsl_dir_hold_obj() asserts
	// `doi_bonus_size >= sizeof(dsl_dir_phys_t)` (= 0x100 = 256 bytes),
	// so a short 96-byte bonus aborts `zdb -e` / import at
	// dsl_pool_open(). We zero-fill the trailing fields (quota, reserved,
	// the props/deleg ZAP object ids, used-breakdown, clones, pad), which
	// is the valid empty state for a freshly created pool.
	dslDirBonus := make([]byte, dslDirPhysSize) // sizeof(dsl_dir_phys_t)
	binary.LittleEndian.PutUint64(dslDirBonus[ddHeadDatasetObj:], fmtMOSDSLDatasetObj)
	// dd_child_dir_zapobj: dsl_pool_open() walks this child map for the
	// $MOS / $FREE / $ORIGIN special directories. Without it the lookup
	// runs against object 0 and dsl_pool_open fails with EINVAL.
	binary.LittleEndian.PutUint64(dslDirBonus[ddChildDirZAPObj:], fmtMOSRootChildObj)
	binary.LittleEndian.PutUint64(dslDirBonus[ddPropsZAPObj:], fmtMOSRootPropsObj)
	binary.LittleEndian.PutUint64(dslDirBonus[ddFlags:], dsFlagUsedBreakdown)
	dslDirDN := newDnode(dmotDSLDir, 1, dmotDSLDir, uint16(len(dslDirBonus)))
	copy(dslDirDN.raw[dnodeHdrSize+blkptrSize:], dslDirBonus)
	dslDirDN.encode()
	copy(mosObjArray[fmtMOSDSLDirObj*dnodeMinSize:], dslDirDN.raw)

	// Object 3: root head DSL dataset (bonus = dsl_dataset_phys with
	// ds_bp → ZPL objset). It also needs a real deadlist and snapshot-name
	// map: dmu_objset_find holds this dataset and opens/closes its
	// deadlist, and a zero deadlist obj makes dsl_deadlist_close crash.
	dslDSBonus := make([]byte, dslDatasetPhysSize)
	binary.LittleEndian.PutUint64(dslDSBonus[dsDirObj:], fmtMOSDSLDirObj) // ds_dir_obj
	// ds_prev_snap_obj must reference the origin snapshot: with the
	// $ORIGIN feature present, dsl_dataset_hold_obj asserts every
	// non-origin dataset descends from a snapshot. Real `zpool create`
	// makes the root dataset a clone of the origin snapshot (obj 16).
	binary.LittleEndian.PutUint64(dslDSBonus[dsPrevSnapObj:], fmtMOSOriginSnapObj) // ds_prev_snap_obj
	// ds_prev_snap_txg must be STRICTLY less than the birth txg of every
	// block this live dataset owns, or `zdb -bcc` block traversal treats
	// those blocks as belonging to the prev snapshot and skips them
	// (traverse_dataset visits only bp->blk_birth > td_min_txg, and
	// td_min_txg = ds_prev_snap_txg for a head dataset). Our genesis pool
	// births every block at fmtPoolTXG (1), so prev_snap_txg must be 0 —
	// the origin snapshot conceptually predates the very first txg. (Real
	// `zpool create` instead births the root dataset's objset a few txgs
	// after the txg-1 origin snapshot; we have only one txg, so we lower
	// the watermark instead of raising the births.) The prev_snap_obj link
	// to the origin snapshot is unchanged, so dsl_dataset_hold_obj's
	// "every non-origin dataset descends from a snapshot" invariant holds.
	binary.LittleEndian.PutUint64(dslDSBonus[dsPrevSnapTxg:], 0)                       // ds_prev_snap_txg
	binary.LittleEndian.PutUint64(dslDSBonus[dsSnapnamesZAPObj:], fmtMOSRootSnapNames) // ds_snapnames_zapobj
	binary.LittleEndian.PutUint64(dslDSBonus[dsCreationTime:], now)                    // ds_creation_time
	binary.LittleEndian.PutUint64(dslDSBonus[dsCreationTxg:], fmtPoolTXG)              // ds_creation_txg
	binary.LittleEndian.PutUint64(dslDSBonus[dsDeadlistObj:], fmtMOSRootDLObj)         // ds_deadlist_obj
	binary.LittleEndian.PutUint64(dslDSBonus[dsFlags:], dsFlagUniqueAccurate)          // ds_flags
	zplBP := makeBP(fmtZPLObjsetOff, poolBlockSize, poolBlockSize, dmotObjset, zplObjset)
	zplBP.fill = fmtZPLObjCount
	encodeBlkptr(zplBP, dslDSBonus[dsBP:dsBP+blkptrSize])
	dslDatasetDN := newDnode(dmotDSLDataset, 1, dmotDSLDataset, uint16(len(dslDSBonus)))
	copy(dslDatasetDN.raw[dnodeHdrSize+blkptrSize:], dslDSBonus)
	dslDatasetDN.encode()
	copy(mosObjArray[fmtMOSDSLDatasetObj*dnodeMinSize:], dslDatasetDN.raw)

	// Object 4: packed pool config nvlist (DMU_OT_PACKED_NVLIST). The MOS
	// config carries the same identity as the label but wraps the leaf in
	// the synthetic "root" top-level vdev (matching the "MOS Configuration"
	// dump of a real pool). spa_load reads this to build its trusted
	// config; without it the import fails with ENOENT on 'config'.
	configNV := buildMOSConfigNVList(poolName, poolGUID, vdevGUID, uint64(sizeBytes), now)
	configBlock := make([]byte, fmtConfigBlkSize)
	copy(configBlock, configNV)
	// OpenZFS load_nvlist() reads the packed size from the object's bonus
	// (a single uint64 written by DMU_OT_PACKED_NVLIST_SIZE), then
	// dmu_read()s exactly that many bytes and nvlist_unpack()s them. A
	// missing/zero bonus size makes the read return EIO ("unable to
	// retrieve MOS config"). Store the exact packed length in an 8-byte
	// bonus of type DMU_OT_PACKED_NVLIST_SIZE.
	configBonus := make([]byte, 8)
	binary.LittleEndian.PutUint64(configBonus, uint64(len(configNV)))
	configDN := newDnode(dmotPackedNVList, 1, dmotPackedNVListSize, uint16(len(configBonus)))
	configDN.datablkszsec = uint16(fmtConfigBlkSize / 512)
	configDN.used = uint64(fmtConfigBlkSize)
	configDN.flags = dnodeFlagUsedBytes
	configDN.setBlkptrAt(0, makeBP(fmtConfigOff, fmtConfigBlkSize, fmtConfigBlkSize, dmotPackedNVList, configBlock))
	copy(configDN.raw[dnodeHdrSize+blkptrSize:], configBonus)
	configDN.encode()
	copy(mosObjArray[fmtMOSConfigObj*dnodeMinSize:], configDN.raw)

	// Objects 5 & 6: features_for_read / features_for_write ZAPs. These are
	// ordinary (empty) microZAPs of object type DMU_OT_ZAP; spa_load reads
	// each feature's refcount from here during feature-flag checking.
	featReadDN := newDnode(dmotZAPOther, 1, dmotNone, 0)
	featReadDN.datablkszsec = uint16(poolBlockSize / 512)
	featReadDN.setBlkptrAt(0, makeBP(fmtFeatReadZAPOff, poolBlockSize, poolBlockSize, dmotZAPOther, featReadZAP))
	featReadDN.encode()
	copy(mosObjArray[fmtMOSFeatReadObj*dnodeMinSize:], featReadDN.raw)

	featWriteDN := newDnode(dmotZAPOther, 1, dmotNone, 0)
	featWriteDN.datablkszsec = uint16(poolBlockSize / 512)
	featWriteDN.setBlkptrAt(0, makeBP(fmtFeatWriteZAPOff, poolBlockSize, poolBlockSize, dmotZAPOther, featWriteZAP))
	featWriteDN.encode()
	copy(mosObjArray[fmtMOSFeatWriteObj*dnodeMinSize:], featWriteDN.raw)

	featDescDN := newDnode(dmotZAPOther, 1, dmotNone, 0)
	featDescDN.datablkszsec = uint16(poolBlockSize / 512)
	featDescDN.setBlkptrAt(0, makeBP(fmtFeatDescZAPOff, poolBlockSize, poolBlockSize, dmotZAPOther, featDescZAP))
	featDescDN.encode()
	copy(mosObjArray[fmtMOSFeatDescObj*dnodeMinSize:], featDescDN.raw)

	// ── DSL special-directory hierarchy (objects 8..19) ──────────────────
	// dsl_pool_open() on a v5000 pool requires the root DSL dir to expose
	// a child map naming $MOS / $FREE / $ORIGIN, then (for $ORIGIN) holds
	// the head dataset and its prev-snapshot, each opening a deadlist; the
	// pool also opens the free bpobj named by the pool directory. Helpers
	// (putDSLDir / putDSLDataset / putZAPObj / putDeadlist / putBpobj)
	// encode one MOS dnode each into mosObjArray.

	// Object 8: root DSL dir's child map (microZAP, type DSL_DIR_CHILD_MAP).
	putZAPObj(mosObjArray, fmtMOSRootChildObj, dmotDSLDirChildMap, fmtRootChildZAPOff, poolBlockSize, rootChildZAP, makeBP)

	// Objects 9/10/11: the $MOS / $FREE / $ORIGIN special DSL dirs. $MOS
	// and $FREE have no head dataset (head=0); $ORIGIN's head dataset is
	// object 14. All three parent back to the root DSL dir (object 2) and
	// own an (empty) child map.
	putDSLDir(mosObjArray, fmtMOSDirObj, dslDirFields{
		parentObj: fmtMOSDSLDirObj, childZAP: fmtMOSDirChildObj,
		propsZAP: fmtMOSDirPropsObj, creation: now,
	})
	putDSLDir(mosObjArray, fmtMOSFreeDirObj, dslDirFields{
		parentObj: fmtMOSDSLDirObj, childZAP: fmtMOSFreeChildObj,
		propsZAP: fmtMOSFreePropsObj, creation: now,
	})
	putDSLDir(mosObjArray, fmtMOSOriginDirObj, dslDirFields{
		parentObj: fmtMOSDSLDirObj, headDataset: fmtMOSOriginHeadObj,
		childZAP: fmtMOSOriginChildObj, propsZAP: fmtMOSOriginPropsObj, creation: now,
	})

	// Objects 12/13/15: the three special dirs' (empty) child maps.
	putZAPObj(mosObjArray, fmtMOSDirChildObj, dmotDSLDirChildMap, fmtMOSDirOff, poolBlockSize, mosDirChildZAP, makeBP)
	putZAPObj(mosObjArray, fmtMOSFreeChildObj, dmotDSLDirChildMap, fmtFreeDirChildOff, poolBlockSize, freeDirChildZAP, makeBP)
	putZAPObj(mosObjArray, fmtMOSOriginChildObj, dmotDSLDirChildMap, fmtOriginChildOff, poolBlockSize, originDirChildZAP, makeBP)

	// Object 14: $ORIGIN head dataset. Its ZPL bp is a HOLE (the origin
	// has no on-disk objset), prev_snap points at the origin snapshot
	// (16), and it carries its own deadlist (17). dsl_pool_open holds
	// this then its prev-snapshot.
	putDSLDataset(mosObjArray, fmtMOSOriginHeadObj, dslDatasetFields{
		dirObj: fmtMOSOriginDirObj, prevSnap: fmtMOSOriginSnapObj, prevSnapTxg: fmtPoolTXG,
		snapNamesZAP: fmtMOSOriginSnapNames,
		deadlist:     fmtMOSOriginHeadDL, creation: now, creationTxg: fmtPoolTXG,
		guid: vdevGUIDFor(poolGUID ^ 0xA11C), flags: dsFlagUniqueAccurate,
	})

	// Object 16: the origin snapshot. next_snap points back at the head
	// (14); num_children = 2 (matches real `zpool create`); bp HOLE.
	putDSLDataset(mosObjArray, fmtMOSOriginSnapObj, dslDatasetFields{
		dirObj: fmtMOSOriginDirObj, nextSnap: fmtMOSOriginHeadObj, numChildren: 2,
		deadlist: fmtMOSOriginSnapDL, creation: now, creationTxg: fmtPoolTXG,
		guid: vdevGUIDFor(poolGUID ^ 0x5A0F), flags: dsFlagUniqueAccurate, isSnap: true,
	})

	// Objects 17/18: the two deadlists (microZAP + dsl_deadlist_phys
	// bonus). Empty: no sub-bpobjs, zero used/comp/uncomp.
	putDeadlist(mosObjArray, fmtMOSOriginHeadDL, fmtOriginHeadDLOff, poolBlockSize, originHeadDLZAP, makeBP)
	putDeadlist(mosObjArray, fmtMOSOriginSnapDL, fmtOriginSnapDLOff, poolBlockSize, originSnapDLZAP, makeBP)

	// Object 19: pool-wide free bpobj (empty: bpobj header bonus, no
	// block pointers). Named by the pool directory's "free_bpobj" key.
	putBpobj(mosObjArray, fmtMOSFreeBpobjObj, fmtFreeBpobjOff, poolBlockSize, makeBP)

	// Object 25: deferred-frees ("sync") bpobj (empty). Named by the pool
	// directory's "sync_bplist" key; spa_load opens spa_deferred_bpobj.
	putBpobj(mosObjArray, fmtMOSSyncBpobjObj, fmtSyncBpobjOff, poolBlockSize, makeBP)

	// Objects 26/27: root head dataset's deadlist + (empty) snapshot-name
	// map. dmu_objset_find opens and closes the deadlist while walking the
	// pool's datasets.
	putDeadlist(mosObjArray, fmtMOSRootDLObj, fmtRootDLOff, poolBlockSize, rootDLZAP, makeBP)
	putZAPObj(mosObjArray, fmtMOSRootSnapNames, dmotDSLDSSnapMap, fmtRootSnapNamesOff, poolBlockSize, rootSnapNamesZAP, makeBP)

	// Objects 20..23: empty per-dir property ZAPs (DMU_OT_DSL_PROPS).
	// dsl_prop_get_dd() does zap_lookup(dd_props_zapobj, ...); each dir
	// must therefore name a real ZAP object, not object 0.
	putZAPObj(mosObjArray, fmtMOSRootPropsObj, dmotDSLProps, fmtRootPropsOff, poolBlockSize, rootPropsZAP, makeBP)
	putZAPObj(mosObjArray, fmtMOSDirPropsObj, dmotDSLProps, fmtMOSPropsOff, poolBlockSize, mosPropsZAP, makeBP)
	putZAPObj(mosObjArray, fmtMOSFreePropsObj, dmotDSLProps, fmtFreePropsOff, poolBlockSize, freePropsZAP, makeBP)
	putZAPObj(mosObjArray, fmtMOSOriginPropsObj, dmotDSLProps, fmtOriginPropsOff, poolBlockSize, originPropsZAP, makeBP)

	// Object 24: $ORIGIN head dataset's snapshot-name map (DSL_DS_SNAP_MAP).
	putZAPObj(mosObjArray, fmtMOSOriginSnapNames, dmotDSLDSSnapMap, fmtOriginSnapNamesOff, poolBlockSize, originSnapNamesZAP, makeBP)

	// ── Objects 28/29: metaslab_array + metaslab-0 space_map ─────────────
	// Partition the vdev asize into 2^fmtMetaslabShift metaslabs. Every
	// block Format() writes lives in the contiguous data span
	// [fmtMOSObjsetOff, fmtInitialNextFree), which falls entirely inside
	// metaslab 0 (metaslab 0 = [0, 16 MiB)). So metaslab 0's space map
	// records that one ALLOC run and the remaining metaslabs are wholly
	// free (their metaslab_array slot stays 0, no space_map object).
	//
	// Because the data span is gapless, its byte length equals the sum of
	// every block's DVA asize — i.e. exactly what `zdb -bcc` block
	// traversal counts as allocated — so smp_alloc balances against
	// traversal and the "size != alloc (leaked)" assertion is satisfied.
	ml := chooseMetaslabLayout(vdevAsize(sizeBytes), fmtMetaslabShift)

	allocStart := int64(fmtMOSObjsetOff)
	allocEnd := int64(fmtInitialNextFree)
	allocBytes := allocEnd - allocStart

	// metaslab-0 space-map log: a single ALLOC run at intra-metaslab offset
	// allocStart (metaslab 0 begins at vdev offset 0) covering allocBytes.
	sm0Log := encodeSpaceMapLog([]smRange{{off: allocStart, length: allocBytes, typ: smAlloc}})
	sm0Block := make([]byte, poolBlockSize)
	copy(sm0Block, sm0Log)
	sm0Bonus := makeSpaceMapPhys(fmtMOSSpaceMap0Obj, len(sm0Log), allocBytes)
	sm0DN := newDnode(dmotSpaceMap, 1, dmotSpaceMapHdr, uint16(len(sm0Bonus)))
	sm0DN.datablkszsec = uint16(poolBlockSize / 512)
	sm0DN.used = uint64(poolBlockSize)
	sm0DN.flags = dnodeFlagUsedBytes
	sm0DN.setBlkptrAt(0, makeBP(fmtSpaceMap0Off, poolBlockSize, poolBlockSize, dmotSpaceMap, sm0Block))
	copy(sm0DN.raw[dnodeBonusOff(1):], sm0Bonus)
	sm0DN.encode()
	copy(mosObjArray[fmtMOSSpaceMap0Obj*dnodeMinSize:], sm0DN.raw)

	// metaslab_array data block: one uint64 per metaslab = its space_map
	// object number (0 = no allocation yet). Only metaslab 0 has a space
	// map (object fmtMOSSpaceMap0Obj); slots 1..count-1 stay 0.
	msArrayBlock := make([]byte, poolBlockSize)
	binary.LittleEndian.PutUint64(msArrayBlock[0:], fmtMOSSpaceMap0Obj)
	msArrayDN := newDnode(dmotObjectArray, 1, dmotNone, 0)
	msArrayDN.datablkszsec = uint16(poolBlockSize / 512)
	msArrayDN.used = uint64(poolBlockSize)
	msArrayDN.flags = dnodeFlagUsedBytes
	// maxblkid 0: a single data block holds all `ml.count` entries (count is
	// tiny for our images — at most a few hundred uint64s in 4 KiB).
	msArrayDN.setBlkptrAt(0, makeBP(fmtMetaslabArrayOff, poolBlockSize, poolBlockSize, dmotObjectArray, msArrayBlock))
	msArrayDN.encode()
	copy(mosObjArray[fmtMOSMetaslabArray*dnodeMinSize:], msArrayDN.raw)
	// A single 4 KiB block holds 512 uint64 slots — enough for any pool up
	// to 512 × 16 MiB = 8 GiB. For larger vdevs the high metaslab slots
	// read back as 0 (= no space_map = entirely free), which is still sound
	// because all of Format()'s allocations are confined to metaslab 0; the
	// extra free metaslabs simply contribute 0 to smp_alloc.
	_ = ml.count

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// 5. Build MOS objset block (4 KiB)
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	mosObjset := make([]byte, poolBlockSize)
	// MOS meta_dnode: describes the MOS object array. Its block pointer's
	// fill count must equal the number of allocated MOS objects: zdb's
	// dump_objset() asserts object_count == usedobjs, and usedobjs is read
	// from the objset block pointer's fill (== meta-dnode bp fill). We
	// allocate objects 1..fmtMOSObjCount, so fill = fmtMOSObjCount.
	mosMetaDN := newDnode(dmotDnode, 1, dmotNone, 0)
	mosMetaDN.datablkszsec = uint16(fmtObjArraySize / 512) // 32
	mosMetaBP := makeBP(fmtMOSObjArrayOff, fmtObjArraySize, fmtObjArraySize, dmotDnode, mosObjArray)
	mosMetaBP.fill = fmtMOSObjCount
	mosMetaDN.setBlkptrAt(0, mosMetaBP)
	mosMetaDN.encode()
	copy(mosObjset[0:], mosMetaDN.raw)
	// os_type = 1 (DMU_OST_META) at offset 704
	binary.LittleEndian.PutUint64(mosObjset[objsetTypeOff:], dmuOSTMeta)

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// 6. Write all pool data blocks
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	writes := []struct {
		off  int64
		data []byte
	}{
		{fmtMOSObjsetOff, mosObjset},
		{fmtMOSObjArrayOff, mosObjArray},
		{fmtPoolDirZAPOff, poolDirZAP},
		{fmtZPLObjsetOff, zplObjset},
		{fmtZPLObjArrayOff, zplObjArray},
		{fmtMasterNodeZAPOff, masterNodeZAP},
		{fmtUnlinkedZAPOff, unlinkedZAP},
		{fmtRootDirZAPOff, rootDirZAP},
		{fmtSAMasterZAPOff, saMasterZAP},
		{fmtSARegistryZAPOff, saRegistryZAP},
		{fmtSALayoutsHdrOff, saLayoutsHdr},
		{fmtSALayoutsLeafOff, saLayoutsLeaf},
		{fmtSALayoutsIndOff, saLayIndBlock},
		{fmtConfigOff, configBlock},
		{fmtFeatReadZAPOff, featReadZAP},
		{fmtFeatWriteZAPOff, featWriteZAP},
		{fmtFeatDescZAPOff, featDescZAP},
		{fmtRootChildZAPOff, rootChildZAP},
		{fmtMOSDirOff, mosDirChildZAP},
		{fmtFreeDirChildOff, freeDirChildZAP},
		{fmtOriginChildOff, originDirChildZAP},
		{fmtOriginHeadDLOff, originHeadDLZAP},
		{fmtOriginSnapDLOff, originSnapDLZAP},
		{fmtFreeBpobjOff, freeBpobjBlock},
		{fmtRootPropsOff, rootPropsZAP},
		{fmtMOSPropsOff, mosPropsZAP},
		{fmtFreePropsOff, freePropsZAP},
		{fmtOriginPropsOff, originPropsZAP},
		{fmtOriginSnapNamesOff, originSnapNamesZAP},
		{fmtSyncBpobjOff, syncBpobjBlock},
		{fmtRootDLOff, rootDLZAP},
		{fmtRootSnapNamesOff, rootSnapNamesZAP},
		{fmtMetaslabArrayOff, msArrayBlock},
		{fmtSpaceMap0Off, sm0Block},
	}
	// Shift every data write past VDEV_LABEL_START_SIZE so the on-disk
	// layout matches what real `zpool create` produces. The DVA values
	// embedded in block pointers are sector counts relative to the data
	// area (computed via makeBP(off, ...)); the read side adds
	// vdevLabelStartSize back via dvaOffset(), so both sides agree.
	for _, wr := range writes {
		writeAt(vdevLabelStartSize+wr.off, wr.data)
	}

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// 7. Build the rootbp (pointing to the MOS objset)
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	rootBP := makeBP(fmtMOSObjsetOff, poolBlockSize, poolBlockSize, dmotObjset, mosObjset)
	// The objset block pointer's fill is the objset's allocated-object
	// count (zdb prints it as "N objects" and asserts it on dump).
	rootBP.fill = fmtMOSObjCount

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// 8. Build and encode the uberblock
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// ub_guid_sum is the sum of EVERY vdev guid in the MOS config tree —
	// both the synthetic root top-level vdev (whose guid == pool_guid) and
	// the leaf. OpenZFS recomputes this from the trusted config during
	// spa_load and rejects the pool ("uberblock guid sum doesn't match MOS
	// guid sum") if it differs.
	ubGuidSum := poolGUID + vdevGUID
	ub := encodeUberblock(fmtPoolVersion, fmtPoolTXG, ubGuidSum, now, rootBP)

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// 9. Build and write the four vdev labels
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	nvBuf := buildLabelNVList(poolName, poolGUID, vdevGUID, uint64(sizeBytes), now)

	// Labels L0/L1 at the start, L2/L3 at the end
	labelOffsets := []int64{
		0,
		vdevLabelSize,
		sizeBytes - 2*vdevLabelSize,
		sizeBytes - vdevLabelSize,
	}
	for _, labelOff := range labelOffsets {
		writeAt(labelOff, buildLabel(nvBuf, ub, labelOff, fmtPoolTXG))
	}

	f.Sync()
	f.Close()

	return Open(path, -1)
}

// ── Uberblock encoding ───────────────────────────────────────────────────────

// encodeUberblock serialises a ZFS uberblock to a 1024-byte buffer.
// Layout (LE):
//
//	[0..7]    magic
//	[8..15]   version
//	[16..23]  txg
//	[24..31]  guid_sum
//	[32..39]  timestamp (unix seconds)
//	[40..167] rootbp (128 bytes)
//	[168..]   zero-padded
func encodeUberblock(version, txg, guidSum, ts uint64, rootBP blkptr) []byte {
	buf := make([]byte, uberblockSize)
	le := binary.LittleEndian
	le.PutUint64(buf[0:], uberblockMagic)
	le.PutUint64(buf[8:], version)
	le.PutUint64(buf[16:], txg)
	le.PutUint64(buf[24:], guidSum)
	le.PutUint64(buf[32:], ts)
	encodeBlkptr(rootBP, buf[40:168])
	return buf
}

// ── Vdev label ───────────────────────────────────────────────────────────────

// buildLabel constructs a 256 KiB vdev label.
// Layout (matches OpenZFS sys/vdev_label.h VDEV_PAD_SIZE / VDEV_PHYS_SIZE):
//
//	[0x00000 .. 0x02000)  vl_pad1         (8 KiB, zeroed)
//	[0x02000 .. 0x04000)  vl_pad2 / boot  (8 KiB, zeroed)
//	[0x04000 .. 0x20000)  vl_vdev_phys    (112 KiB, XDR nvlist + zio_eck_t)
//	[0x20000 .. 0x40000)  vl_uberblock    (128 KiB uberblock ring)
//
// labelOff is the absolute byte offset of this label within the vdev;
// it seeds the ZIO_CHECKSUM_LABEL verifier for every checksummed region
// (the vdev_phys nvlist and each uberblock slot). txg is the uberblock's
// transaction group, which selects the active slot in the ring.
func buildLabel(nvBuf, ub []byte, labelOff int64, txg uint64) []byte {
	label := make([]byte, vdevLabelSize)

	// ── vdev_phys (XDR nvlist) at 0x4000, 112 KiB including its
	// trailing zio_eck_t self-checksum. ───────────────────────────────
	const nvOff = vdevPhysOffset // = 0x4000
	nvRegion := label[nvOff : nvOff+vdevPhysSize]
	if len(nvBuf) > vdevPhysSize-zioEckSize {
		nvBuf = nvBuf[:vdevPhysSize-zioEckSize]
	}
	copy(nvRegion, nvBuf)
	labelSelfChecksum(nvRegion, uint64(labelOff)+nvOff)

	// ── uberblock ring at 0x20000. Slots are max(1<<ashift, 1 KiB)
	// bytes; for our ashift=12 pools that is 4 KiB, giving 32 slots.
	// The active uberblock lives at slot (txg % nslots). ──────────────
	const ubBase = uberblockRegionOffset
	slotSize := uberblockSlotSize // 4 KiB for ashift=12
	nslots := uberblockRegionSize / slotSize
	slot := int(txg % uint64(nslots))
	ubAt := ubBase + slot*slotSize
	ubSlot := label[ubAt : ubAt+slotSize]
	if len(ub) > slotSize-zioEckSize {
		ub = ub[:slotSize-zioEckSize]
	}
	copy(ubSlot, ub)
	labelSelfChecksum(ubSlot, uint64(labelOff)+uint64(ubAt))

	return label
}

// vdevAsize returns the leaf vdev's allocatable size: the total device
// bytes minus the leading label/boot reserve (VDEV_LABEL_START_SIZE) and
// the two trailing labels, aligned DOWN to a metaslab (2^fmtMetaslabShift)
// boundary. This is the value written as "asize" in the label / MOS config
// nvlists and the span the metaslabs partition. DVA offsets in block
// pointers are measured from byte 0 of this allocatable area.
func vdevAsize(totalBytes int64) int64 {
	asize := totalBytes - vdevLabelStartSize - 2*vdevLabelSize
	if asize < 0 {
		asize = 0
	}
	asize &^= (int64(1) << fmtMetaslabShift) - 1
	return asize
}

// buildLabelNVList constructs the XDR-encoded nvlist for a vdev label.
//
// The field set mirrors what real `zpool create` writes (verified
// against an OpenZFS 2.3 label dump) so that `zdb -l` reports a
// complete config: the top-level carries pool identity plus top_guid /
// guid / vdev_children, and the single leaf vdev under vdev_tree
// carries id / guid / path / metaslab_array / metaslab_shift / ashift /
// asize / is_log / create_txg.
//
// asize is the usable data area (total minus the four labels and the
// boot reserve), rounded down to a metaslab boundary, matching how
// OpenZFS derives vdev asize.
func buildLabelNVList(poolName string, poolGUID, vdevGUID uint64, totalBytes, ts uint64) []byte {
	// Usable size = total - leading label/boot reserve (4 MiB) - two
	// trailing labels, aligned down to a metaslab boundary.
	metaslabShift := uint64(fmtMetaslabShift)
	asize := vdevAsize(int64(totalBytes))

	// The label's vdev_tree is the TOP-LEVEL vdev itself — for our single
	// file-backed disk that is the leaf directly, NOT wrapped in a
	// synthetic "root" node. Real `zpool create` on a file vdev writes
	// `type: 'file'` here with guid == top_guid; the importer synthesises
	// the enclosing root vdev on its own. Emitting our own extra "root"
	// child made OpenZFS see a root-under-root and report "1 missing
	// top-level vdevs" (EOVERFLOW / error=75) at vdev_tree open, which
	// blocked `zdb -e -p` and `zpool import`.
	vdevTree := nvList{
		nvString("type", "file"),
		nvUint64("id", 0),
		nvUint64("guid", vdevGUID),
		nvString("path", "/dev/disk/by-id/"+poolName),
		nvUint64("metaslab_array", fmtVdevMetaslabArray),
		nvUint64("metaslab_shift", metaslabShift),
		nvUint64("ashift", 12),
		nvUint64("asize", uint64(asize)),
		nvUint64("is_log", 0),
		nvUint64("create_txg", fmtPoolTXG),
	}
	config := nvList{
		nvUint64("version", fmtPoolVersion),
		nvString("name", poolName),
		nvUint64("state", 0), // POOL_STATE_ACTIVE
		nvUint64("txg", fmtPoolTXG),
		nvUint64("pool_guid", poolGUID),
		nvUint64("errata", 0),
		nvUint64("timestamp", ts),
		nvUint64("top_guid", vdevGUID),
		nvUint64("guid", vdevGUID),
		nvUint64("vdev_children", 1),
		nvNVList("vdev_tree", vdevTree),
		// version 5000 = feature-flags pool; OpenZFS spa_load rejects the
		// label with "invalid label: 'features_for_read' missing" if this
		// nvlist is absent. We enable no read-incompatible features, so an
		// empty list is correct and lets the importer proceed.
		nvNVList("features_for_read", nvList{
			// spacemap_histogram is active because the writer emits a
			// metaslab space_map with a space_map_phys_t bonus; zdb's
			// space-map refcount audit requires the feature be enabled
			// here AND counted in the features_for_write MOS ZAP
			// (spacemap_histogram is READONLY_COMPAT; see featWriteZAP).
			nvBoolean(fmtFeatSpacemapHistogram),
		}),
	}
	return encodeNVListFull(config)
}

// makeBPFunc is the type of Format()'s makeBP closure: it builds a
// fletcher4-checksummed, uncompressed, level-0 block pointer for the
// physical bytes `phys` written at `off`. The DSL-hierarchy helpers take
// it so they can checksum their data blocks identically to the rest of
// Format().
type makeBPFunc func(off int64, physSize, logicalSize int, dtype uint8, phys []byte) blkptr

// dnodeBonusOff is the byte offset of the bonus buffer within a dnode
// that has nblkptr block pointers: 64-byte header + nblkptr × 128.
func dnodeBonusOff(nblkptr int) int { return dnodeHdrSize + nblkptr*blkptrSize }

// putZAPObj encodes a single-block microZAP dnode into mosObjArray at
// object number obj. `zap` is the exact ZAP block bytes scheduled for
// writing at byte offset off, so the block pointer's checksum is computed
// over the real content. dtype is the DMU object type (e.g.
// DMU_OT_DSL_DIR_CHILD_MAP for a DSL child map).
func putZAPObj(mosObjArray []byte, obj int, dtype uint8, off int64, blockSize int, zap []byte, makeBP makeBPFunc) {
	dn := newDnode(dtype, 1, dmotNone, 0)
	dn.datablkszsec = uint16(blockSize / 512)
	dn.setBlkptrAt(0, makeBP(off, blockSize, blockSize, dtype, zap))
	dn.encode()
	copy(mosObjArray[obj*dnodeMinSize:], dn.raw)
}

// dslDirFields are the dsl_dir_phys_t fields Format() populates.
type dslDirFields struct {
	parentObj   uint64
	headDataset uint64
	childZAP    uint64
	propsZAP    uint64
	creation    uint64
}

// putDSLDir encodes a DSL directory dnode (no data block — all state is
// in the dsl_dir_phys_t bonus) into mosObjArray at object number obj.
func putDSLDir(mosObjArray []byte, obj int, f dslDirFields) {
	bonus := make([]byte, dslDirPhysSize)
	le := binary.LittleEndian
	le.PutUint64(bonus[ddCreationTime:], f.creation)
	le.PutUint64(bonus[ddHeadDatasetObj:], f.headDataset)
	le.PutUint64(bonus[ddParentObj:], f.parentObj)
	le.PutUint64(bonus[ddChildDirZAPObj:], f.childZAP)
	le.PutUint64(bonus[ddPropsZAPObj:], f.propsZAP)
	le.PutUint64(bonus[ddFlags:], dsFlagUsedBreakdown)
	dn := newDnode(dmotDSLDir, 1, dmotDSLDir, uint16(len(bonus)))
	copy(dn.raw[dnodeBonusOff(1):], bonus)
	dn.encode()
	copy(mosObjArray[obj*dnodeMinSize:], dn.raw)
}

// dslDatasetFields are the dsl_dataset_phys_t fields Format() populates.
// The ZPL bp is left as a HOLE (all zero) — the origin datasets have no
// on-disk objset, matching real `zpool create`.
type dslDatasetFields struct {
	dirObj       uint64
	prevSnap     uint64
	prevSnapTxg  uint64
	nextSnap     uint64
	snapNamesZAP uint64
	numChildren  uint64
	deadlist     uint64
	creation     uint64
	creationTxg  uint64
	guid         uint64
	flags        uint64
	isSnap       bool
}

// putDSLDataset encodes a DSL dataset dnode (state in the
// dsl_dataset_phys_t bonus, ZPL bp = HOLE) into mosObjArray at object
// number obj.
func putDSLDataset(mosObjArray []byte, obj int, f dslDatasetFields) {
	bonus := make([]byte, dslDatasetPhysSize)
	le := binary.LittleEndian
	le.PutUint64(bonus[dsDirObj:], f.dirObj)
	le.PutUint64(bonus[dsPrevSnapObj:], f.prevSnap)
	le.PutUint64(bonus[dsPrevSnapTxg:], f.prevSnapTxg)
	le.PutUint64(bonus[dsNextSnapObj:], f.nextSnap)
	le.PutUint64(bonus[dsSnapnamesZAPObj:], f.snapNamesZAP)
	le.PutUint64(bonus[dsNumChildren:], f.numChildren)
	le.PutUint64(bonus[dsCreationTime:], f.creation)
	le.PutUint64(bonus[dsCreationTxg:], f.creationTxg)
	le.PutUint64(bonus[dsDeadlistObj:], f.deadlist)
	le.PutUint64(bonus[dsGUID:], f.guid)
	le.PutUint64(bonus[dsFlags:], f.flags)
	// ds_bp stays a HOLE (zeroed): the origin head/snapshot have no
	// on-disk objset on a freshly created pool.
	bonusType := uint8(dmotDSLDataset)
	dn := newDnode(dmotDSLDataset, 1, bonusType, uint16(len(bonus)))
	if f.isSnap {
		dn.flags = dnodeFlagUsedBytes
	}
	copy(dn.raw[dnodeBonusOff(1):], bonus)
	dn.encode()
	copy(mosObjArray[obj*dnodeMinSize:], dn.raw)
}

// putDeadlist encodes a DSL deadlist dnode: a single-block microZAP
// (mintxg → sub-bpobj, empty here) with a dsl_deadlist_phys_t bonus
// (zero used/comp/uncomp). dsl_deadlist_open() requires both.
func putDeadlist(mosObjArray []byte, obj int, off int64, blockSize int, zap []byte, makeBP makeBPFunc) {
	bonus := make([]byte, dslDeadlistPhysSize) // zeroed dl_used/comp/uncomp
	dn := newDnode(dmotDeadlist, 1, dmotDeadlistHdr, uint16(len(bonus)))
	dn.datablkszsec = uint16(blockSize / 512)
	dn.flags = dnodeFlagUsedBytes
	dn.setBlkptrAt(0, makeBP(off, blockSize, blockSize, dmotDeadlist, zap))
	copy(dn.raw[dnodeBonusOff(1):], bonus)
	dn.encode()
	copy(mosObjArray[obj*dnodeMinSize:], dn.raw)
}

// bpobjPhysSize is sizeof(the populated prefix of bpobj_phys_t) that real
// `zpool create` writes for the free bpobj: bpo_num_blkptrs, bpo_bytes,
// bpo_comp, bpo_uncomp, bpo_subobjs, bpo_num_subobjs = 6 × 8 = 48 bytes.
const bpobjPhysSize = 48

// putBpobj encodes an empty bpobj dnode (bpobj_phys_t bonus, zero block
// pointers) into mosObjArray at object number obj.
func putBpobj(mosObjArray []byte, obj int, off int64, blockSize int, makeBP makeBPFunc) {
	block := make([]byte, blockSize) // no blkptr entries
	bonus := make([]byte, bpobjPhysSize)
	dn := newDnode(dmotBPObj, 1, dmotBPObjHdr, uint16(len(bonus)))
	dn.datablkszsec = uint16(blockSize / 512)
	dn.setBlkptrAt(0, makeBP(off, blockSize, blockSize, dmotBPObj, block))
	copy(dn.raw[dnodeBonusOff(1):], bonus)
	dn.encode()
	copy(mosObjArray[obj*dnodeMinSize:], dn.raw)
}

// buildMOSConfigNVList builds the packed pool config nvlist stored in the
// MOS "config" object. It mirrors the on-import "MOS Configuration" that
// real `zpool create` writes: the same pool identity as the label, but
// with vdev_tree as the synthetic "root" top-level vdev that contains the
// single leaf as children[0]. spa_load reads this to assemble its trusted
// config after the untrusted label config gets it as far as the MOS.
func buildMOSConfigNVList(poolName string, poolGUID, vdevGUID uint64, totalBytes, ts uint64) []byte {
	metaslabShift := uint64(fmtMetaslabShift)
	asize := vdevAsize(int64(totalBytes))

	leaf := nvList{
		nvString("type", "file"),
		nvUint64("id", 0),
		nvUint64("guid", vdevGUID),
		nvString("path", "/dev/disk/by-id/"+poolName),
		nvUint64("metaslab_array", fmtVdevMetaslabArray),
		nvUint64("metaslab_shift", metaslabShift),
		nvUint64("ashift", 12),
		nvUint64("asize", uint64(asize)),
		nvUint64("is_log", 0),
		nvUint64("create_txg", fmtPoolTXG),
	}
	root := nvList{
		nvString("type", "root"),
		nvUint64("id", 0),
		nvUint64("guid", poolGUID),
		nvUint64("create_txg", fmtPoolTXG),
		nvNVListArray("children", []nvList{leaf}),
	}
	config := nvList{
		nvUint64("version", fmtPoolVersion),
		nvString("name", poolName),
		nvUint64("state", 0),
		nvUint64("txg", fmtPoolTXG),
		nvUint64("pool_guid", poolGUID),
		nvUint64("errata", 0),
		nvUint64("vdev_children", 1),
		nvNVList("vdev_tree", root),
		nvNVList("features_for_read", nvList{
			// spacemap_histogram is active because the writer emits a
			// metaslab space_map with a space_map_phys_t bonus; zdb's
			// space-map refcount audit requires the feature be enabled
			// here AND counted in the features_for_write MOS ZAP
			// (spacemap_histogram is READONLY_COMPAT; see featWriteZAP).
			nvBoolean(fmtFeatSpacemapHistogram),
		}),
	}
	return encodeNVListFull(config)
}
