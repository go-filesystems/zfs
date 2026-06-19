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
	fmtConfigOff        = fmtRootDirZAPOff + 4*1024    // 0x08E000 (packed MOS config nvlist)
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
	fmtRootDLOff        = fmtSyncBpobjOff + 4*1024     // 0x0A2000 root head deadlist
	fmtRootSnapNamesOff = fmtRootDLOff + 4*1024        // 0x0A3000 root head snap map
	fmtInitialNextFree  = fmtRootSnapNamesOff + 4*1024 // 0x0A4000

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
	// Object 28 is the metaslab array (DMU_OT_OBJECT_ARRAY) named by the
	// top-level vdev's metaslab_array nvpair; objects 29.. are the
	// per-metaslab space-map objects (DMU_OT_SPACE_MAP). The number of
	// space maps is the metaslab count, chosen at format time, so the
	// fill count is computed dynamically (see fmtMetaslabArrayObj usage).
	fmtMetaslabArrayObj  = 28 // metaslab array object
	fmtMOSFixedObjCount  = 28 // objects 1..28 are always present
	fmtFirstSpaceMapObj  = 29 // first per-metaslab space-map object

	// fmtMOSObjCount is the number of always-present MOS objects (1..27),
	// kept for code that does not account for the variable metaslab
	// objects. The objset fill count is computed as
	// fmtMOSFixedObjCount + metaslabCount (see Format()).
	fmtMOSObjCount = 27
	// fmtZPLObjCount is the number of allocated ZPL objects (master node,
	// unlinked set, root dir = 1..3).
	fmtZPLObjCount = 3

	// ZPL object numbers
	fmtZPLMasterNode = 1
	fmtZPLUnlinked   = 2
	fmtZPLRootDir    = 3

	fmtPoolVersion = 5000      // pool feature flags version
	fmtZPLVersion  = uint64(5) // ZPL version
	fmtPoolTXG     = uint64(1) // genesis transaction group

	// fmtVdevAshift is the vdev allocation shift (4 KiB blocks).
	fmtVdevAshift = 12
)

// metaslabLayout captures the metaslab geometry Format() emits: the
// metaslab_array object id, the per-metaslab shift/size, the count, and
// the asize aligned down to a whole metaslab boundary (the value written
// into the vdev nvlist so asize == count<<shift).
type metaslabLayout struct {
	arrayObj uint64
	shift    uint
	msSize   uint64
	count    uint64
	asize    uint64
}

// computeMetaslabLayout derives the metaslab geometry for a vdev whose raw
// usable data area is rawAsize bytes (total minus the leading
// label/boot reserve and the two trailing labels). When the area is too
// small for even one metaslab the layout has count 0 and arrayObj 0
// (no metaslab objects are emitted; metaslab_array stays 0).
func computeMetaslabLayout(rawAsize uint64) metaslabLayout {
	shift, msSize, count, asize := chooseMetaslabShift(rawAsize, fmtVdevAshift)
	ml := metaslabLayout{shift: shift, msSize: msSize, count: count, asize: asize}
	if count > 0 {
		ml.arrayObj = fmtMetaslabArrayObj
	}
	return ml
}

// rawVdevAsize returns the unaligned usable data area for a vdev of
// totalBytes: total minus the leading label/boot reserve (4 MiB) and the
// two trailing labels.
func rawVdevAsize(totalBytes uint64) uint64 {
	a := int64(totalBytes) - vdevLabelStartSize - 2*vdevLabelSize
	if a < 0 {
		return 0
	}
	return uint64(a)
}

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

	// Metaslab geometry for the single top-level vdev. The vdev nvlists
	// (label + MOS config) record metaslab_array / metaslab_shift / asize
	// from this, and the MOS gets the metaslab array object plus one
	// space-map object per metaslab (see step 4b below).
	ml := computeMetaslabLayout(rawVdevAsize(uint64(sizeBytes)))

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
	// We enable one read-only-compatible feature,
	// com.delphix:spacemap_histogram, whose refcount equals the number of
	// metaslabs whose space-map object carries a histogram-sized bonus.
	// zdb's verify_spacemap_refcounts() counts every metaslab space map
	// whose bonus dbuf is sizeof(space_map_phys_t) (which a 1-blkptr space
	// map dnode always is) and compares it against this feature's
	// refcount; without the feature the audit reports
	// "space map refcount mismatch" and zdb exits non-zero. The refcount
	// lives in features_for_write because the feature is READONLY_COMPAT.
	featReadZAP := newMicroZAPBlock(poolBlockSize)
	featWriteZAP := newMicroZAPBlock(poolBlockSize)
	featDescZAP := newMicroZAPBlock(poolBlockSize)
	if ml.count > 0 {
		mzapInsert(featWriteZAP, featSpacemapHistogram, ml.count)
	}

	// ZPL master node ZAP: "ROOT"→3, "VERSION"→5
	masterNodeZAP := newMicroZAPBlock(poolBlockSize)
	mzapInsert(masterNodeZAP, zplKeyRoot, fmtZPLRootDir)
	mzapInsert(masterNodeZAP, zplKeyVersion, fmtZPLVersion)

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
	layout := defaultSALayout()
	saBonus := writeSABonus(rootSAAttrs, layout)
	zplRootDN := newDnode(dmotDirContents, 1, dmotSA, uint16(len(saBonus)))
	zplRootDN.datablkszsec = uint16(poolBlockSize / 512)
	zplRootDN.setBlkptrAt(0, makeBP(fmtRootDirZAPOff, poolBlockSize, poolBlockSize, dmotDirContents, rootDirZAP))
	// Write bonus into dnode raw
	bonusStart := dnodeHdrSize + 1*blkptrSize
	copy(zplRootDN.raw[bonusStart:], saBonus)
	zplRootDN.encode()
	copy(zplObjArray[fmtZPLRootDir*dnodeMinSize:], zplRootDN.raw)

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
	binary.LittleEndian.PutUint64(dslDSBonus[dsPrevSnapObj:], fmtMOSOriginSnapObj)     // ds_prev_snap_obj
	// ds_prev_snap_txg must be STRICTLY LESS than the birth txg of the
	// root filesystem's objset block: zdb's block traversal (and the
	// kernel scrub) attribute a dataset's blocks only when
	// bp_birth > ds_prev_snap_txg, otherwise the block is charged to the
	// prior snapshot. Our genesis writes the ZPL objset at fmtPoolTXG, so
	// the head's prev_snap_txg is fmtPoolTXG-1; with the origin snapshot
	// at fmtPoolTXG this keeps the clone relationship valid while letting
	// the ZPL objset (birth=fmtPoolTXG) be traversed under the head — so
	// `zdb -bcc` reaches every ZPL block and the alloc total reconciles.
	binary.LittleEndian.PutUint64(dslDSBonus[dsPrevSnapTxg:], fmtPoolTXG-1)            // ds_prev_snap_txg
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
	configNV := buildMOSConfigNVList(poolName, poolGUID, vdevGUID, uint64(sizeBytes), now, ml)
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

	// ── 4b. Metaslab array (object 28) + per-metaslab space maps ─────────
	// The top-level vdev's data area is divided into ml.count metaslabs of
	// ml.msSize bytes. The metaslab array object is a flat uint64[] whose
	// i-th element is metaslab i's space-map object number; each space-map
	// object records its metaslab's ALLOC/FREE history. All of Format()'s
	// pool blocks live contiguously at the front of the data area (in
	// metaslab 0), so only metaslab 0 has a non-empty space map; the rest
	// are empty. The single ALLOC extent for metaslab 0 spans exactly the
	// contiguous region the writer fills — including the metaslab/space-map
	// blocks themselves — so the alloc total reconciles with block
	// traversal (`zdb -bcc` no longer reports leaked / size != alloc).
	//
	// metaWrites collects the data blocks for these objects; they are
	// appended to the main write list below. Offsets continue past the
	// fixed layout (fmtInitialNextFree) and stay contiguous.
	var metaWrites []struct {
		off  int64
		data []byte
	}
	if ml.count > 0 {
		// Lay out: metaslab array block (4 KiB), then one 16 KiB space-map
		// data block per metaslab, all contiguous starting at the end of
		// the fixed layout.
		arrayOff := int64(fmtInitialNextFree)
		spaceMapBaseOff := arrayOff + poolBlockSize
		// finalUsedEnd is the first byte past every block the writer has
		// laid down (fixed layout + metaslab array + all space maps). The
		// metaslab-0 ALLOC extent runs [fmtMOSObjsetOff, finalUsedEnd).
		finalUsedEnd := spaceMapBaseOff + int64(ml.count)*spaceMapBlockSize

		// Metaslab array data block: count uint64 entries = the space-map
		// object id of each metaslab (objects fmtFirstSpaceMapObj..).
		arrayBlock := make([]byte, poolBlockSize)
		for i := uint64(0); i < ml.count; i++ {
			smObj := uint64(fmtFirstSpaceMapObj) + i
			binary.LittleEndian.PutUint64(arrayBlock[i*8:], smObj)
		}
		// Object 28: the metaslab array dnode (DMU_OT_OBJECT_ARRAY).
		arrayDN := newDnode(dmotObjectArray, 1, dmotNone, 0)
		arrayDN.datablkszsec = uint16(poolBlockSize / 512)
		arrayDN.used = uint64(poolBlockSize)
		arrayDN.flags = dnodeFlagUsedBytes
		arrayDN.setBlkptrAt(0, makeBP(arrayOff, poolBlockSize, poolBlockSize, dmotObjectArray, arrayBlock))
		arrayDN.encode()
		copy(mosObjArray[fmtMetaslabArrayObj*dnodeMinSize:], arrayDN.raw)
		metaWrites = append(metaWrites, struct {
			off  int64
			data []byte
		}{arrayOff, arrayBlock})

		// One space-map object per metaslab.
		for i := uint64(0); i < ml.count; i++ {
			smObj := uint64(fmtFirstSpaceMapObj) + i
			smOff := spaceMapBaseOff + int64(i)*spaceMapBlockSize

			var entries []byte
			var objsize uint64
			var alloc int64
			if i == 0 {
				// Metaslab 0 holds every pool block: encode a single ALLOC
				// extent covering [fmtMOSObjsetOff, finalUsedEnd), expressed
				// relative to the metaslab-0 start (data-area offset 0).
				allocStart := uint64(fmtMOSObjsetOff)
				allocLen := uint64(finalUsedEnd) - allocStart
				entries, objsize = encodeSpaceMapEntries(
					[][2]uint64{{allocStart, allocLen}}, fmtVdevAshift, fmtPoolTXG)
				alloc = int64(allocLen)
			}
			// space-map data block (16 KiB): entries then zero padding.
			smBlock := make([]byte, spaceMapBlockSize)
			copy(smBlock, entries)
			// Object dnode (DMU_OT_SPACE_MAP) with a space_map_phys_t bonus.
			smBonus := spaceMapPhysBonus(smObj, objsize, alloc)
			smDN := newDnode(dmotSpaceMap, 1, dmotSpaceMapHdr, uint16(len(smBonus)))
			smDN.datablkszsec = uint16(spaceMapBlockSize / 512)
			smDN.indblkshift = 14 // 16 KiB indirect blocks (matches dblk)
			smDN.used = uint64(spaceMapBlockSize)
			smDN.flags = dnodeFlagUsedBytes
			smDN.setBlkptrAt(0, makeBP(smOff, spaceMapBlockSize, spaceMapBlockSize, dmotSpaceMap, smBlock))
			copy(smDN.raw[dnodeBonusOff(1):], smBonus)
			smDN.encode()
			copy(mosObjArray[smObj*dnodeMinSize:], smDN.raw)
			metaWrites = append(metaWrites, struct {
				off  int64
				data []byte
			}{smOff, smBlock})
		}
	}

	// mosFillCount is the objset's allocated-object count: the always-present
	// objects (1..fmtMOSFixedObjCount) plus one space-map object per metaslab.
	mosFillCount := uint64(fmtMOSObjCount)
	if ml.count > 0 {
		mosFillCount = uint64(fmtMOSFixedObjCount) + ml.count
	}

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
	mosMetaBP.fill = mosFillCount
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
	}
	// Shift every data write past VDEV_LABEL_START_SIZE so the on-disk
	// layout matches what real `zpool create` produces. The DVA values
	// embedded in block pointers are sector counts relative to the data
	// area (computed via makeBP(off, ...)); the read side adds
	// vdevLabelStartSize back via dvaOffset(), so both sides agree.
	writes = append(writes, metaWrites...)
	for _, wr := range writes {
		writeAt(vdevLabelStartSize+wr.off, wr.data)
	}

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// 7. Build the rootbp (pointing to the MOS objset)
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	rootBP := makeBP(fmtMOSObjsetOff, poolBlockSize, poolBlockSize, dmotObjset, mosObjset)
	// The objset block pointer's fill is the objset's allocated-object
	// count (zdb prints it as "N objects" and asserts it on dump).
	rootBP.fill = mosFillCount

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
	nvBuf := buildLabelNVList(poolName, poolGUID, vdevGUID, uint64(sizeBytes), now, ml)

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
func buildLabelNVList(poolName string, poolGUID, vdevGUID uint64, totalBytes, ts uint64, ml metaslabLayout) []byte {
	// asize is the usable data area aligned down to a whole metaslab
	// boundary (asize == count<<shift), exactly as OpenZFS derives it.
	metaslabShift := ml.shift
	asize := int64(ml.asize)

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
		nvUint64("metaslab_array", ml.arrayObj),
		nvUint64("metaslab_shift", uint64(metaslabShift)),
		nvUint64("ashift", fmtVdevAshift),
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
		nvNVList("features_for_read", nvList{}),
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
func buildMOSConfigNVList(poolName string, poolGUID, vdevGUID uint64, totalBytes, ts uint64, ml metaslabLayout) []byte {
	leaf := nvList{
		nvString("type", "file"),
		nvUint64("id", 0),
		nvUint64("guid", vdevGUID),
		nvString("path", "/dev/disk/by-id/"+poolName),
		nvUint64("metaslab_array", ml.arrayObj),
		nvUint64("metaslab_shift", uint64(ml.shift)),
		nvUint64("ashift", fmtVdevAshift),
		nvUint64("asize", uint64(ml.asize)),
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
		nvNVList("features_for_read", nvList{}),
	}
	return encodeNVListFull(config)
}
