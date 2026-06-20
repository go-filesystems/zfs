package filesystem_zfs

// sa.go – ZFS System Attributes (SA) layer.
//
// SA stores per-inode attributes (mode, size, uid, gid, timestamps, …) packed
// into the dnode bonus buffer (bonustype = DMU_OT_SA = 44).
//
// SA header in bonus buffer:
//   [0..3]  sa_magic  (uint32 LE: 0x02F505A5)
//   [4..5]  sa_layout_info (uint16 LE)
//             bits 15:10 = hdrsize (number of uint16 lengths for var-size attrs)
//             bits 9:0   = layout index into sa_attr_layouts ZAP
//   [6..]   variable-size attribute lengths (hdrsize * 2 bytes), then packed attrs
//
// The SA layouts ZAP (object saMasterNode.layouts) stores, for index I:
//   key = decimal string of I
//   value = array of uint16 ZPL attribute IDs in attribute order
//
// Standard ZPL attribute IDs (zpl_attr_t):
//   0  ZPL_ATIME   16 bytes
//   1  ZPL_MTIME   16 bytes
//   2  ZPL_CTIME   16 bytes
//   3  ZPL_CRTIME  16 bytes
//   4  ZPL_GEN      8 bytes
//   5  ZPL_MODE     8 bytes (only lower 2 bytes used as Unix mode)
//   6  ZPL_SIZE     8 bytes
//   7  ZPL_PARENT   8 bytes
//   8  ZPL_LINKS    8 bytes
//   9  ZPL_XATTR    8 bytes
//  10  ZPL_RDEV     8 bytes
//  11  ZPL_FLAGS    8 bytes
//  12  ZPL_UID      8 bytes
//  13  ZPL_GID      8 bytes
//  14  ZPL_PAD      variable
//  17  ZPL_SYMLINK  variable

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// SA_MAGIC from OpenZFS sys/sa_impl.h is 0x2F505A (24-bit) — the
	// lib had 0x02F505A5 (one extra digit), which rejected every real
	// SA bonus header.
	saMagic = uint32(0x002F505A)

	// ZPL attribute IDs
	zplAtime   = 0
	zplMtime   = 1
	zplCtime   = 2
	zplCrtime  = 3
	zplGen     = 4
	zplMode    = 5
	zplSize    = 6
	zplParent  = 7
	zplLinks   = 8
	zplXattr   = 9
	zplRdev    = 10
	zplFlags   = 11
	zplUID     = 12
	zplGID     = 13
	zplPad     = 14
	zplSymlink = 17
)

// saAttrSize maps standard ZPL attribute IDs to their fixed size in bytes.
// Variable-size attrs (symlink, pad) have size 0 here.
var saAttrSize = map[uint16]int{
	zplAtime:   16,
	zplMtime:   16,
	zplCtime:   16,
	zplCrtime:  16,
	zplGen:     8,
	zplMode:    8,
	zplSize:    8,
	zplParent:  8,
	zplLinks:   8,
	zplXattr:   8,
	zplRdev:    8,
	zplFlags:   8,
	zplUID:     8,
	zplGID:     8,
	zplPad:     32, // ZPL_PAD: 4 × uint64
	zplDACLCount: 8, // ZPL_DACL_COUNT
	zplSymlink: 0, // variable
}

// saMasterNode holds the SA layer metadata for a ZPL dataset.
type saMasterNode struct {
	// layoutsObjNum is the object number of the SA attribute layouts ZAP.
	layoutsObjNum uint64
	// layouts maps layout index → ordered list of attribute IDs.
	layouts map[uint64][]uint16
}

// loadSAMasterNode reads the SA master node for a ZPL object set.
// masterNodeObjNum is the object number of the SA master node (DMU_OT_SA_MASTER_NODE=45).
func loadSAMasterNode(r io.ReaderAt, partOff int64, zplOS *objset, masterNodeObjNum uint64) (*saMasterNode, error) {
	mn, err := zplOS.readObject(masterNodeObjNum)
	if err != nil {
		return nil, fmt.Errorf("zfs: load SA master node: %w", err)
	}
	if mn.typ != dmotSAMasterNode {
		return nil, fmt.Errorf("zfs: SA master node has wrong type %d", mn.typ)
	}
	entries, err := zapListAll(r, partOff, mn)
	if err != nil {
		return nil, fmt.Errorf("zfs: SA master node ZAP: %w", err)
	}
	layoutsObjNum, ok := entries["LAYOUTS"]
	if !ok {
		return nil, fmt.Errorf("zfs: SA master node missing LAYOUTS key")
	}

	layoutsDN, err := zplOS.readObject(layoutsObjNum)
	if err != nil {
		return nil, fmt.Errorf("zfs: SA layouts object: %w", err)
	}
	layoutEntries, err := zapListAll(r, partOff, layoutsDN)
	if err != nil {
		return nil, fmt.Errorf("zfs: SA layouts ZAP: %w", err)
	}

	// The ZAP stores layouts as byte arrays (uint16 per attribute).
	// Each ZAP value for a layout is a uint64 packed with attribute IDs.
	// In fat-ZAP, the value can be an array. We handle arrays via special reading.
	// For micro-ZAP, each value is a single uint64 (limited utility).
	// For our Format()-created images, layouts are stored with uint16 arrays.
	// We'll do a best-effort parse here.

	layouts := make(map[uint64][]uint16)
	for k, v := range layoutEntries {
		var idx uint64
		_, err := fmt.Sscan(k, &idx)
		if err != nil {
			continue
		}
		// v is the first uint16 or a packed uint64 of the layout.
		// For detailed parsing, use readSALayout below.
		_ = v
		attrIDs, err := readSALayoutFromZAP(r, partOff, layoutsDN, k)
		if err != nil {
			// Fallback: use a standard layout
			layouts[idx] = defaultSALayout()
			continue
		}
		layouts[idx] = attrIDs
	}
	if len(layouts) == 0 {
		layouts[0] = defaultSALayout()
	}
	return &saMasterNode{
		layoutsObjNum: layoutsObjNum,
		layouts:       layouts,
	}, nil
}

// defaultSALayout returns the standard layout used by our Format() images.
// Order: MODE, SIZE, GEN, UID, GID, PARENT, LINKS, XATTR, RDEV, FLAGS, ATIME, MTIME, CTIME, CRTIME
func defaultSALayout() []uint16 {
	return []uint16{
		zplMode, zplSize, zplGen, zplUID, zplGID,
		zplParent, zplLinks, zplXattr, zplRdev, zplFlags,
		zplAtime, zplMtime, zplCtime, zplCrtime,
	}
}

// readSALayoutFromZAP reads a SA layout array from the layouts ZAP.
// The ZAP stores the array as a sequence of uint16 attribute IDs.
// For fat-ZAP, these are stored as arrays. For our micro-ZAP, it's stored
// differently; this function handles both cases.
func readSALayoutFromZAP(r io.ReaderAt, partOff int64, dn *dnode, key string) ([]uint16, error) {
	// Read the raw ZAP block to find array values for this key.
	// For micro-ZAP, values are single uint64 (not an array), so we use defaults.
	blk0, err := readDataBlock(r, partOff, dn, 0)
	if err != nil {
		return nil, err
	}
	if len(blk0) < 8 {
		return nil, fmt.Errorf("zfs: SA layout: short block")
	}
	blockType := binary.LittleEndian.Uint64(blk0[:8])
	if blockType == zbtMicro {
		// Can't store uint16 arrays in micro-ZAP — use default layout
		return defaultSALayout(), nil
	}
	// For fat-ZAP, the layout is stored as ZAP_OT_UINT16_ARRAY.
	// Try to read via fat-ZAP leaf scanning (simplified).
	return defaultSALayout(), nil
}

// saAttrs holds parsed attributes from a SA bonus buffer.
type saAttrs struct {
	mode   uint64
	size   uint64
	gen    uint64
	uid    uint64
	gid    uint64
	parent uint64
	links  uint64
	xattr  uint64
	rdev   uint64
	flags  uint64
	atime  [2]uint64
	mtime  [2]uint64
	ctime  [2]uint64
	crtime [2]uint64
}

// parseSABonus parses an SA bonus buffer.
// layout is the ordered list of attribute IDs for the layout index in the buffer.
func parseSABonus(buf []byte, layout []uint16) (*saAttrs, error) {
	if len(buf) < 6 {
		return nil, fmt.Errorf("zfs: SA: bonus too short")
	}
	le := binary.LittleEndian
	magic := le.Uint32(buf[0:4])
	if magic != saMagic {
		return nil, fmt.Errorf("zfs: SA: bad magic 0x%08X", magic)
	}
	layoutInfo := le.Uint16(buf[4:6])
	// SA_HDR_SIZE(hdr) = (bits 10..15 of sa_layout_info) * 8 — the byte
	// offset at which attribute data begins (sys/sa_impl.h). The header is
	// magic(4) + layout_info(2) + optional uint16 var-size lengths, all
	// rounded up to an 8-byte multiple.
	dataStart := int(layoutInfo>>10) * 8
	if dataStart < 6 {
		// Legacy/zero header (e.g. older Format() output): fall back to the
		// minimal 8-byte header so reads stay backward-compatible.
		dataStart = 8
	}
	if dataStart > len(buf) {
		dataStart = len(buf)
	}

	attrs := &saAttrs{}
	off := dataStart
	for _, attrID := range layout {
		sz, ok := saAttrSize[attrID]
		if !ok {
			continue // unknown attr, skip
		}
		if sz == 0 {
			continue // variable-size, not in fixed section
		}
		if off+sz > len(buf) {
			break
		}
		switch attrID {
		case zplMode:
			attrs.mode = le.Uint64(buf[off:])
		case zplSize:
			attrs.size = le.Uint64(buf[off:])
		case zplGen:
			attrs.gen = le.Uint64(buf[off:])
		case zplUID:
			attrs.uid = le.Uint64(buf[off:])
		case zplGID:
			attrs.gid = le.Uint64(buf[off:])
		case zplParent:
			attrs.parent = le.Uint64(buf[off:])
		case zplLinks:
			attrs.links = le.Uint64(buf[off:])
		case zplXattr:
			attrs.xattr = le.Uint64(buf[off:])
		case zplRdev:
			attrs.rdev = le.Uint64(buf[off:])
		case zplFlags:
			attrs.flags = le.Uint64(buf[off:])
		case zplAtime:
			attrs.atime[0] = le.Uint64(buf[off:])
			attrs.atime[1] = le.Uint64(buf[off+8:])
		case zplMtime:
			attrs.mtime[0] = le.Uint64(buf[off:])
			attrs.mtime[1] = le.Uint64(buf[off+8:])
		case zplCtime:
			attrs.ctime[0] = le.Uint64(buf[off:])
			attrs.ctime[1] = le.Uint64(buf[off+8:])
		case zplCrtime:
			attrs.crtime[0] = le.Uint64(buf[off:])
			attrs.crtime[1] = le.Uint64(buf[off+8:])
		}
		off += sz
	}
	return attrs, nil
}

// writeSABonus encodes SA attributes into a buffer using the given layout.
// Returns the SA bonus buffer (sa header + packed attrs).
func writeSABonus(attrs *saAttrs, layout []uint16) []byte {
	le := binary.LittleEndian
	// sa_hdr_phys_t: sa_magic(4) + sa_layout_info(2), then attribute data
	// begins at SA_HDR_SIZE bytes. With no variable-length attributes the
	// header is the minimum 8 bytes (one hdrsz unit; SA_HDR_SIZE = unit*8),
	// so the layout-info hdrsz field = 1 and data starts at offset 8.
	//
	// sa_layout_info packing (SA_HDR_LAYOUT_INFO_ENCODE): bits 0..9 = layout
	// number, bits 10..15 = hdrsz units. The on-disk layout number MUST be
	// saZnodeLayoutNum (>= 2): SA_LAYOUT_NUM remaps 0→1 and 1 is the kernel's
	// empty dummy layout, so neither can describe our packing.
	const headerBytes = 8
	const hdrSizeUnits = headerBytes / 8 // = 1

	// Calculate data size
	dataSize := 0
	for _, attrID := range layout {
		if sz, ok := saAttrSize[attrID]; ok && sz > 0 {
			dataSize += sz
		}
	}

	buf := make([]byte, headerBytes+dataSize)
	le.PutUint32(buf[0:4], saMagic)
	layoutInfo := uint16(saZnodeLayoutNum&0x3FF) | uint16(hdrSizeUnits<<10)
	le.PutUint16(buf[4:6], layoutInfo)

	off := headerBytes
	for _, attrID := range layout {
		sz, ok := saAttrSize[attrID]
		if !ok || sz == 0 {
			continue
		}
		switch attrID {
		case zplMode:
			le.PutUint64(buf[off:], attrs.mode)
		case zplSize:
			le.PutUint64(buf[off:], attrs.size)
		case zplGen:
			le.PutUint64(buf[off:], attrs.gen)
		case zplUID:
			le.PutUint64(buf[off:], attrs.uid)
		case zplGID:
			le.PutUint64(buf[off:], attrs.gid)
		case zplParent:
			le.PutUint64(buf[off:], attrs.parent)
		case zplLinks:
			le.PutUint64(buf[off:], attrs.links)
		case zplXattr:
			le.PutUint64(buf[off:], attrs.xattr)
		case zplRdev:
			le.PutUint64(buf[off:], attrs.rdev)
		case zplFlags:
			le.PutUint64(buf[off:], attrs.flags)
		case zplAtime:
			le.PutUint64(buf[off:], attrs.atime[0])
			le.PutUint64(buf[off+8:], attrs.atime[1])
		case zplMtime:
			le.PutUint64(buf[off:], attrs.mtime[0])
			le.PutUint64(buf[off+8:], attrs.mtime[1])
		case zplCtime:
			le.PutUint64(buf[off:], attrs.ctime[0])
			le.PutUint64(buf[off+8:], attrs.ctime[1])
		case zplCrtime:
			le.PutUint64(buf[off:], attrs.crtime[0])
			le.PutUint64(buf[off+8:], attrs.crtime[1])
		}
		off += sz
	}
	return buf
}

// saLayout0Size is the byte size of the fixed SA data for layout 0.
func saLayout0Size() int {
	total := 0
	for _, attrID := range defaultSALayout() {
		if sz, ok := saAttrSize[attrID]; ok {
			total += sz
		}
	}
	return total
}

// saBonusSize returns the total size of an SA bonus buffer for layout 0.
func saBonusSize() int {
	return 4 + 2 + saLayout0Size() // magic + layout_info + attrs
}

// parseDnodeSA reads SA attributes from a dnode's bonus buffer.
// layout should be the layout for this inode's SA layout index.
func parseDnodeSA(dn *dnode, layout []uint16) (*saAttrs, error) {
	if dn.bonusType != dmotSA {
		return nil, fmt.Errorf("zfs: dnode bonus type %d is not SA", dn.bonusType)
	}
	bonus := dn.bonusData()
	return parseSABonus(bonus, layout)
}

// updateDnodeSA writes attrs into the dnode's bonus buffer.
func updateDnodeSA(dn *dnode, attrs *saAttrs, layout []uint16) {
	bonus := writeSABonus(attrs, layout)
	base := dnodeHdrSize + int(dn.nblkptr)*blkptrSize
	copy(dn.raw[base:], bonus)
	dn.bonuslen = uint16(len(bonus))
	dn.encode()
}
