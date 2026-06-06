package filesystem_zfs

// objset.go – ZFS object set (objset_phys_t) reader.
//
// Object set layout:
//   [0..511]    os_meta_dnode  (dnode_phys_t that describes the object array)
//   [512..703]  os_zil_header  (192 bytes, ignored for reads)
//   [704..711]  os_type        (uint64 LE: DMU_OST_META=1, DMU_OST_ZFS=2, …)
//   [712..719]  os_flags
//   [720..]     os_portable_mac (32 bytes), os_local_mac (32 bytes), pad
//
// The meta_dnode (object 0) is a special dnode whose data blocks are arrays
// of dnode_phys_t. Object N lives at byte offset N*512 within that array.

import (
	"fmt"
	"io"
)

const (
	objsetMetaDnodeOff = 0
	objsetZILHdrOff    = 512
	objsetTypeOff      = 704
	objsetHdrSize      = 1024

	// DMU object set types (dmu_objset_type_t)
	dmuOSTNone = 0
	dmuOSTMeta = 1
	dmuOSTZFS  = 2
	dmuOSTZVol = 3
)

// objset provides access to a DMU object set.
type objset struct {
	r         io.ReaderAt
	partOff   int64
	bp        blkptr // block pointer that points to this objset
	metaDnode *dnode // object 0 – describes the object array
	osType    uint64
	raw       []byte // cached raw objset block
}

// openObjset reads an object set from block pointer bp.
func openObjset(r io.ReaderAt, partOff int64, bp blkptr) (*objset, error) {
	if bp.isNull() {
		return nil, fmt.Errorf("zfs: null objset block pointer")
	}
	data, err := readBlock(r, partOff, bp)
	if err != nil {
		return nil, fmt.Errorf("zfs: read objset: %w", err)
	}
	if len(data) < objsetHdrSize {
		return nil, fmt.Errorf("zfs: objset block too small: %d bytes", len(data))
	}
	metaDnode, _ := parseDnode(data[objsetMetaDnodeOff : objsetMetaDnodeOff+dnodeMinSize])
	// Read os_type (uint64 LE at offset 704).
	osType := uint64(data[704]) | uint64(data[705])<<8 | uint64(data[706])<<16 | uint64(data[707])<<24 |
		uint64(data[708])<<32 | uint64(data[709])<<40 | uint64(data[710])<<48 | uint64(data[711])<<56
	return &objset{
		r:         r,
		partOff:   partOff,
		bp:        bp,
		metaDnode: metaDnode,
		osType:    osType,
		raw:       data,
	}, nil
}

// readObject returns the dnode for object number objNum.
// Object 0 is the meta_dnode itself.
func (os *objset) readObject(objNum uint64) (*dnode, error) {
	if objNum == 0 {
		return os.metaDnode, nil
	}

	// Object N is at byte offset (N * dnodeMinSize) in the object array.
	// The meta_dnode's data blocks are the object array.
	dnSz := uint64(dnodeMinSize) // default; may be 1024 for extra_slots=1
	blkSz := uint64(os.metaDnode.dataBlockSize())
	if blkSz == 0 {
		blkSz = 16384 // 128KB / some block size; typically 16384 for objsets
	}

	byteOff := objNum * dnSz
	blockID := byteOff / blkSz
	offsetInBlock := int(byteOff % blkSz)

	blk, err := readDataBlock(os.r, os.partOff, os.metaDnode, blockID)
	if err != nil {
		return nil, fmt.Errorf("zfs: read object %d block: %w", objNum, err)
	}
	if offsetInBlock+dnodeMinSize > len(blk) {
		return nil, fmt.Errorf("zfs: object %d out of block bounds", objNum)
	}
	return parseDnode(blk[offsetInBlock : offsetInBlock+dnodeMinSize])
}

// writeObject writes dn.raw back to the object array at the correct position.
// This is a low-level operation; callers must also update the meta_dnode if
// the object array grew.
func (os *objset) writeObject(objNum uint64, dn *dnode) error {
	if objNum == 0 {
		copy(os.metaDnode.raw, dn.raw)
		os.metaDnode = dn
		// Update raw objset block
		copy(os.raw[objsetMetaDnodeOff:], dn.raw[:dnodeMinSize])
		return nil
	}
	blkSz := uint64(os.metaDnode.dataBlockSize())
	if blkSz == 0 {
		blkSz = 16384
	}
	byteOff := objNum * uint64(dnodeMinSize)
	blockID := byteOff / blkSz
	offsetInBlock := int(byteOff % blkSz)

	blk, err := readDataBlock(os.r, os.partOff, os.metaDnode, blockID)
	if err != nil {
		return fmt.Errorf("zfs: read object block %d for write: %w", blockID, err)
	}
	if offsetInBlock+dnodeMinSize > len(blk) {
		return fmt.Errorf("zfs: object %d: offset out of block", objNum)
	}
	copy(blk[offsetInBlock:], dn.raw[:dnodeMinSize])
	return os.writeObjectBlock(blockID, blk)
}

// writeObjectBlock writes blk as data block blockID of the meta_dnode.
// This is called by writeObject.
func (os *objset) writeObjectBlock(blockID uint64, data []byte) error {
	if int(blockID) >= int(os.metaDnode.nblkptr) {
		return fmt.Errorf("zfs: object block %d out of meta_dnode capacity", blockID)
	}
	bp := os.metaDnode.blkptrAt(int(blockID))
	if bp.isNull() {
		return fmt.Errorf("zfs: no block allocated for object block %d", blockID)
	}
	offset := os.partOff + bp.dvaOffset(0)
	f, ok := os.r.(io.WriterAt)
	if !ok {
		return fmt.Errorf("zfs: object set reader not writable")
	}
	if _, err := f.WriteAt(data, offset); err != nil {
		return fmt.Errorf("zfs: write object block %d: %w", blockID, err)
	}
	return nil
}

// findObjectByType returns the object number of the first object with the given type.
// Starts scan from fromObj; returns (0, nil) if none found.
func (os *objset) findObjectByType(fromObj, maxObj uint64, typ uint8) (uint64, error) {
	for i := fromObj; i <= maxObj; i++ {
		dn, err := os.readObject(i)
		if err != nil {
			continue
		}
		if dn.typ == typ {
			return i, nil
		}
	}
	return 0, fmt.Errorf("zfs: no object of type %d found in range [%d,%d]", typ, fromObj, maxObj)
}
