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
	fmtInitialNextFree  = fmtRootDirZAPOff + 4*1024    // 0x08E000

	fmtObjArraySize = 16 * 1024 // 16 KiB = 32 × 512-byte dnodes
	fmtObjArrayObjs = fmtObjArraySize / dnodeMinSize

	// MOS object numbers
	fmtMOSPoolDirObj    = 1
	fmtMOSDSLDirObj     = 2
	fmtMOSDSLDatasetObj = 3

	// ZPL object numbers
	fmtZPLMasterNode = 1
	fmtZPLUnlinked   = 2
	fmtZPLRootDir    = 3

	fmtPoolVersion = 5000      // pool feature flags version
	fmtZPLVersion  = uint64(5) // ZPL version
	fmtPoolTXG     = uint64(1) // genesis transaction group
)

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

	// ── makeBP: convenience wrapper for makeBlkptr with compress=off ─────────
	makeBP := func(off int64, physSize, logicalSize int, dtype uint8) blkptr {
		return makeBlkptr(off, physSize, logicalSize, zcompressOff, dtype, 0, fmtPoolTXG)
	}

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// 1. Build ZAP blocks
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

	// Pool directory ZAP: "root_dataset" → fmtMOSDSLDirObj (2)
	poolDirZAP := newMicroZAPBlock(poolBlockSize)
	mzapInsert(poolDirZAP, dmuPoolRootDataset, fmtMOSDSLDirObj)

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
	zplMasterDN.setBlkptrAt(0, makeBP(fmtMasterNodeZAPOff, poolBlockSize, poolBlockSize, dmotMasterNode))
	zplMasterDN.encode()
	copy(zplObjArray[fmtZPLMasterNode*dnodeMinSize:], zplMasterDN.raw)

	// Object 2: Unlinked set ZAP dnode
	zplUnlinkedDN := newDnode(dmotUnlinkedSet, 1, dmotNone, 0)
	zplUnlinkedDN.datablkszsec = uint16(poolBlockSize / 512)
	zplUnlinkedDN.setBlkptrAt(0, makeBP(fmtUnlinkedZAPOff, poolBlockSize, poolBlockSize, dmotUnlinkedSet))
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
	zplRootDN.setBlkptrAt(0, makeBP(fmtRootDirZAPOff, poolBlockSize, poolBlockSize, dmotDirContents))
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
	zplMetaDN.setBlkptrAt(0, makeBP(fmtZPLObjArrayOff, fmtObjArraySize, fmtObjArraySize, dmotDnode))
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
	poolDirDN.setBlkptrAt(0, makeBP(fmtPoolDirZAPOff, poolBlockSize, poolBlockSize, dmotObjectDirectory))
	poolDirDN.encode()
	copy(mosObjArray[fmtMOSPoolDirObj*dnodeMinSize:], poolDirDN.raw)

	// Object 2: DSL directory dnode (bonus = dsl_dir_phys with dd_head_dataset_obj=3)
	dslDirBonus := make([]byte, 96) // 12 × uint64 = 96 bytes
	binary.LittleEndian.PutUint64(dslDirBonus[ddHeadDatasetObj:], fmtMOSDSLDatasetObj)
	dslDirDN := newDnode(dmotDSLDir, 1, dmotDSLDir, uint16(len(dslDirBonus)))
	copy(dslDirDN.raw[dnodeHdrSize+blkptrSize:], dslDirBonus)
	dslDirDN.encode()
	copy(mosObjArray[fmtMOSDSLDirObj*dnodeMinSize:], dslDirDN.raw)

	// Object 3: DSL dataset dnode (bonus = dsl_dataset_phys with ds_bp → ZPL objset)
	dslDSBonus := make([]byte, 320)
	binary.LittleEndian.PutUint64(dslDSBonus[dsDirObj:], fmtMOSDSLDirObj) // ds_dir_obj
	binary.LittleEndian.PutUint64(dslDSBonus[dsCreationTime:], now)       // ds_creation_time
	binary.LittleEndian.PutUint64(dslDSBonus[dsCreationTxg:], fmtPoolTXG) // ds_creation_txg
	zplBP := makeBP(fmtZPLObjsetOff, poolBlockSize, poolBlockSize, dmotObjset)
	encodeBlkptr(zplBP, dslDSBonus[dsBP:dsBP+blkptrSize])
	dslDatasetDN := newDnode(dmotDSLDataset, 1, dmotDSLDataset, uint16(len(dslDSBonus)))
	copy(dslDatasetDN.raw[dnodeHdrSize+blkptrSize:], dslDSBonus)
	dslDatasetDN.encode()
	copy(mosObjArray[fmtMOSDSLDatasetObj*dnodeMinSize:], dslDatasetDN.raw)

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// 5. Build MOS objset block (4 KiB)
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	mosObjset := make([]byte, poolBlockSize)
	// MOS meta_dnode: describes the MOS object array
	mosMetaDN := newDnode(dmotDnode, 1, dmotNone, 0)
	mosMetaDN.datablkszsec = uint16(fmtObjArraySize / 512) // 32
	mosMetaDN.setBlkptrAt(0, makeBP(fmtMOSObjArrayOff, fmtObjArraySize, fmtObjArraySize, dmotDnode))
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
	rootBP := makeBP(fmtMOSObjsetOff, poolBlockSize, poolBlockSize, dmotObjset)

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// 8. Build and encode the uberblock
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	ub := encodeUberblock(fmtPoolVersion, fmtPoolTXG, poolGUID, now, rootBP)

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// 9. Build and write the four vdev labels
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	nvBuf := buildLabelNVList(poolName, poolGUID, poolGUID, uint64(sizeBytes), now)

	// Labels L0/L1 at the start, L2/L3 at the end
	labelOffsets := []int64{
		0,
		vdevLabelSize,
		sizeBytes - 2*vdevLabelSize,
		sizeBytes - vdevLabelSize,
	}
	for _, labelOff := range labelOffsets {
		writeAt(labelOff, buildLabel(nvBuf, ub))
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
// Layout:
//
//	[0..4K)       boot block (zeroed)
//	[4K..4K+108K) nvlist
//	[4K+108K..128K) padding
//	[128K..256K)  uberblock ring (128 × 1KiB slots, ub in slot 0)
func buildLabel(nvBuf, ub []byte) []byte {
	label := make([]byte, vdevLabelSize)
	// nvlist at offset 4K, max 112K (boot block is 4K, uberblock region at 128K)
	nvOff := 4 * 1024
	if len(nvBuf) > 112*1024 {
		nvBuf = nvBuf[:112*1024]
	}
	copy(label[nvOff:], nvBuf)
	// uberblock slot 0 at 128K
	ubSlot0 := uberblockRegionOffset
	if len(ub) > uberblockSize {
		ub = ub[:uberblockSize]
	}
	copy(label[ubSlot0:], ub)
	return label
}

// buildLabelNVList constructs the XDR-encoded nvlist for a vdev label.
// This is the minimal set of fields that allows `zpool import` to identify
// the pool.
func buildLabelNVList(poolName string, poolGUID, vdevGUID uint64, totalBytes, ts uint64) []byte {
	// Vdev tree: root vdev containing one disk child
	diskChild := nvList{
		nvString("type", "disk"),
		nvUint64("id", 0),
		nvUint64("guid", vdevGUID),
		nvUint64("ashift", 12),
		nvUint64("asize", uint64(totalBytes)),
		nvUint64("is_log", 0),
	}
	rootChild := nvList{
		nvString("type", "root"),
		nvUint64("id", 0),
		nvUint64("guid", poolGUID),
		nvNVListArray("children", []nvList{diskChild}),
	}
	config := nvList{
		nvUint64("version", fmtPoolVersion),
		nvString("name", poolName),
		nvUint64("state", 0), // POOL_STATE_ACTIVE
		nvUint64("txg", fmtPoolTXG),
		nvUint64("pool_guid", poolGUID),
		nvUint64("errata", 0),
		nvUint64("timestamp", ts),
		nvNVList("vdev_tree", rootChild),
	}
	return encodeNVListFull(config)
}
