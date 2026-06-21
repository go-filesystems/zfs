package filesystem_zfs

// dnode.go – ZFS dnode_phys_t parsing.
//
// A dnode is 512 or 1024 bytes:
//   [0]     dn_type        (dmu_object_type_t)
//   [1]     dn_indblkshift (log2 of indirect block body size)
//   [2]     dn_nlevels     (1 = direct, 2 = one indirect level, …)
//   [3]     dn_nblkptr     (number of block pointers in this dnode)
//   [4]     dn_bonustype   (dmu_object_type_t of bonus data)
//   [5]     dn_checksum
//   [6]     dn_compress
//   [7]     dn_flags
//   [8..9]  dn_datablkszsec (data block size in 512B sectors, LE)
//   [10..11] dn_bonuslen   (length of bonus data, LE)
//   [12]    dn_extra_slots  (additional 512B dnode slots occupied, for 1024B dnode = 1)
//   [13..15] dn_pad2
//   [16..23] dn_maxblkid   (largest populated block id, LE)
//   [24..31] dn_used        (bytes or sectors of used space, LE)
//   [32..63] dn_pad3[4]
//   [64 + i*128 …] blkptr[i] for i in [0, dn_nblkptr)
//   [64 + dn_nblkptr*128 …] bonus data (dn_bonuslen bytes)

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	dnodeMinSize = 512
	dnodeHdrSize = 64 // size of dnode header before blkptrs

	// dnodeFlagUsedBytes is DNODE_FLAG_USED_BYTES: dn_used counts bytes
	// (not 512B sectors). OpenZFS sets it on objects whose dn_used we want
	// interpreted directly in bytes.
	dnodeFlagUsedBytes = 0x1

	// DMU object types (dmu_object_type_t)
	dmotNone               = 0
	dmotObjectDirectory    = 1 // MOS pool dir
	dmotObjectArray        = 2
	dmotPackedNVList       = 3
	dmotPackedNVListSize   = 4
	dmotBPObj              = 5
	dmotBPObjHdr           = 6
	dmotSpaceMapHdr        = 7
	dmotSpaceMap           = 8
	dmotIntentLog          = 9
	dmotDnode              = 10
	dmotObjset             = 11
	dmotDSLDir             = 12
	dmotDSLDirChildMap     = 13
	dmotDSLDSSnapMap       = 14
	dmotDSLProps           = 15
	dmotDSLDataset         = 16
	dmotZnode              = 17 // old pre-SA znode
	dmotOldACL             = 18
	dmotPlainFileContents  = 19
	dmotDirContents        = 20 // ZAP directory
	dmotMasterNode         = 21 // ZAP master node
	dmotUnlinkedSet        = 22 // ZAP
	dmotZVol               = 23
	dmotZVolProp           = 24
	dmotPlainOther         = 25
	dmotUint64Other        = 26
	dmotZAPOther           = 27
	dmotErrorLog           = 28
	dmotSPAHistory         = 29
	dmotSPAHistoryOffsets  = 30
	dmotPoolProps          = 31
	dmotDSLPerms           = 32
	dmotACL                = 33
	dmotSysACL             = 34
	dmotFUID               = 35
	dmotFUIDSize           = 36
	dmotNextClones         = 37
	dmotScanQueue          = 38
	dmotUserGroupUsed      = 39
	dmotUserGroupQuota     = 40
	dmotUserRefs           = 41
	dmotDDTZAP             = 42
	dmotDDTStats           = 43
	dmotSA                 = 44 // System Attributes buffer
	dmotSAMasterNode       = 45 // ZAP
	dmotSAAttrRegistration = 46 // ZAP
	dmotSAAttrLayouts      = 47 // ZAP
	dmotScanXlate          = 48
	dmotDedup              = 49
	dmotDeadlist           = 50
	dmotDeadlistHdr        = 51
	dmotDSLClones          = 52
	dmotBPObjSubobj        = 53
)

// dnode represents a parsed ZFS dnode.
type dnode struct {
	typ          uint8
	indblkshift  uint8
	nlevels      uint8
	nblkptr      uint8
	bonusType    uint8
	checksum     uint8
	compress     uint8
	flags        uint8
	datablkszsec uint16 // data block size in 512B sectors
	bonuslen     uint16
	extraSlots   uint8
	maxblkid     uint64
	used         uint64
	raw          []byte // full dnode bytes for blkptr/bonus extraction
}

// dnodeSize returns the total byte size of this dnode (512 or 1024 for extra_slots=1).
func (dn *dnode) dnodeSize() int {
	return (1 + int(dn.extraSlots)) * dnodeMinSize
}

// dataBlockSize returns the data block size in bytes.
func (dn *dnode) dataBlockSize() int {
	return int(dn.datablkszsec) * 512
}

// blkptrAt returns the i-th block pointer of this dnode (i < dn.nblkptr).
func (dn *dnode) blkptrAt(i int) blkptr {
	base := dnodeHdrSize + i*blkptrSize
	return parseBlkptr(dn.raw[base : base+blkptrSize])
}

// setBlkptrAt overwrites the i-th block pointer in the raw dnode.
func (dn *dnode) setBlkptrAt(i int, bp blkptr) {
	base := dnodeHdrSize + i*blkptrSize
	encodeBlkptr(bp, dn.raw[base:base+blkptrSize])
}

// bonusData returns the bonus buffer bytes (up to dn.bonuslen).
func (dn *dnode) bonusData() []byte {
	base := dnodeHdrSize + int(dn.nblkptr)*blkptrSize
	end := base + int(dn.bonuslen)
	if end > len(dn.raw) {
		end = len(dn.raw)
	}
	return dn.raw[base:end]
}

// parseDnode parses a 512-byte (or 1024-byte) slice into a dnode.
func parseDnode(b []byte) (*dnode, error) {
	if len(b) < dnodeMinSize {
		return nil, fmt.Errorf("zfs: dnode buf too short: %d", len(b))
	}
	le := binary.LittleEndian
	dn := &dnode{
		typ:          b[0],
		indblkshift:  b[1],
		nlevels:      b[2],
		nblkptr:      b[3],
		bonusType:    b[4],
		checksum:     b[5],
		compress:     b[6],
		flags:        b[7],
		datablkszsec: le.Uint16(b[8:]),
		bonuslen:     le.Uint16(b[10:]),
		extraSlots:   b[12],
		maxblkid:     le.Uint64(b[16:]),
		used:         le.Uint64(b[24:]),
	}
	size := (1 + int(dn.extraSlots)) * dnodeMinSize
	if len(b) < size {
		size = len(b)
	}
	dn.raw = make([]byte, size)
	copy(dn.raw, b[:size])
	return dn, nil
}

// encodeDnode serialises dn back into dn.raw (header fields).
func (dn *dnode) encode() {
	le := binary.LittleEndian
	dn.raw[0] = dn.typ
	dn.raw[1] = dn.indblkshift
	dn.raw[2] = dn.nlevels
	dn.raw[3] = dn.nblkptr
	dn.raw[4] = dn.bonusType
	dn.raw[5] = dn.checksum
	dn.raw[6] = dn.compress
	dn.raw[7] = dn.flags
	le.PutUint16(dn.raw[8:], dn.datablkszsec)
	le.PutUint16(dn.raw[10:], dn.bonuslen)
	dn.raw[12] = dn.extraSlots
	le.PutUint64(dn.raw[16:], dn.maxblkid)
	le.PutUint64(dn.raw[24:], dn.used)
}

// newDnode creates a fresh dnode of the given type.
// nblkptr must be 1, 2, or 3.
// bonusType is the type of bonus data; bonusLen is its length.
func newDnode(typ uint8, nblkptr uint8, bonusType uint8, bonusLen uint16) *dnode {
	dn := &dnode{
		typ:         typ,
		indblkshift: 17, // default: 128KB indirect blocks
		nlevels:     1,
		nblkptr:     nblkptr,
		bonusType:   bonusType,
		bonuslen:    bonusLen,
		raw:         make([]byte, dnodeMinSize),
	}
	// datablkszsec: default 128KB = 256 × 512
	dn.datablkszsec = 256
	dn.encode()
	return dn
}

// readDataBlock reads data block blockID from dnode dn using the block tree.
// r is the underlying device, partOff is partition byte offset.
//
// When r is a cryptingReader (the FS was opened with a wrapping
// key and the dataset is encrypted) readBlock transparently
// decrypts encrypted blocks before returning them.
func readDataBlock(r io.ReaderAt, partOff int64, dn *dnode, blockID uint64) ([]byte, error) {
	if dn.nlevels == 0 || dn.nblkptr == 0 {
		return make([]byte, dn.dataBlockSize()), nil
	}
	bp, err := findDataBP(r, partOff, dn, blockID)
	if err != nil {
		return nil, err
	}
	if bp.isNull() {
		return make([]byte, dn.dataBlockSize()), nil
	}
	return readBlock(r, partOff, bp)
}

// findDataBP traverses indirect block levels to find the block pointer for blockID.
func findDataBP(r io.ReaderAt, partOff int64, dn *dnode, blockID uint64) (blkptr, error) {
	if dn.nlevels == 1 {
		// Direct: block pointer is in the dnode itself
		if blockID >= uint64(dn.nblkptr) {
			return blkptr{}, fmt.Errorf("zfs: blockID %d >= nblkptr %d", blockID, dn.nblkptr)
		}
		return dn.blkptrAt(int(blockID)), nil
	}

	// Multi-level: start from level dn.nlevels-1 down to level 1
	// Each indirect block contains (indirBlockSize / 128) block pointers.
	indirBlockSz := int(1) << dn.indblkshift // bytes per indirect block body
	bpsPerBlock := uint64(indirBlockSz / blkptrSize)

	// Indirect blocks at level L cover bpsPerBlock^L data blocks each.
	// Find which root blkptr to use.
	level := int(dn.nlevels) - 1
	covered := bpsPerBlock
	for i := 1; i < level; i++ {
		covered *= bpsPerBlock
	}

	rpIdx := blockID / covered
	if rpIdx >= uint64(dn.nblkptr) {
		return blkptr{}, fmt.Errorf("zfs: blockID %d exceeds dnode capacity", blockID)
	}
	bp := dn.blkptrAt(int(rpIdx))
	remaining := blockID % covered

	for level > 0 {
		if bp.isNull() {
			return blkptr{}, nil
		}
		indirData, err := readBlock(r, partOff, bp)
		if err != nil {
			return blkptr{}, fmt.Errorf("zfs: read indirect block level %d: %w", level, err)
		}
		level--
		covered /= bpsPerBlock
		idx := remaining / covered
		remaining = remaining % covered
		bp = parseBlkptr(indirData[idx*blkptrSize : idx*blkptrSize+blkptrSize])
	}
	return bp, nil
}

// readDnodeData reads all data bytes of a dnode (up to maxblkid+1 blocks).
func readDnodeData(r io.ReaderAt, partOff int64, dn *dnode) ([]byte, error) {
	if dn.maxblkid == 0 && dn.blkptrAt(0).isNull() {
		return nil, nil
	}
	blkSz := dn.dataBlockSize()
	if blkSz == 0 {
		return nil, nil
	}
	n := dn.maxblkid + 1
	data := make([]byte, 0, int(n)*blkSz)
	for i := uint64(0); i < n; i++ {
		blk, err := readDataBlock(r, partOff, dn, i)
		if err != nil {
			return nil, err
		}
		data = append(data, blk...)
	}
	return data, nil
}
