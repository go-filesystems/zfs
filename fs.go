package filesystem_zfs

// fs.go – ZFS filesystem operations (Stat, ListDir, ReadFile, ReadLink,
//         WriteFile, MkDir, DeleteFile, DeleteDir, Rename).
//
// Only pools created by Format() or structurally equivalent images support
// write operations.  Read operations work on any pool where the ZPL can be
// opened from the uberblock rootbp.

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"os"
	"sync"
	"time"

	filesystem "github.com/go-filesystems/interface"
)

// fsFields groups the additional fields added to FS for full filesystem access.
// These are embedded (by composition) in FS via the zfs.go struct definition.
type fsFields struct {
	zplDS  *zplDataset
	alloc  *allocator
	curTxg uint64
	mu     sync.Mutex
}

// ── Stat ─────────────────────────────────────────────────────────────────────

// Stat returns file metadata for path.
func (fs *zfsFS) Stat(path string) (filesystem.Stat, error) {
	path = cleanPath(path)

	// Fallback for bare uberblock images (no ZPL loaded): only root is known.
	if fs.zplDS == nil {
		if path == "/" {
			return filesystem.NewStat(0o040755, 0, fs.info.TransactionGroup), nil
		}
		return nil, &os.PathError{Op: "stat", Path: path, Err: errNotFound}
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	objNum, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, path)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: path, Err: errNotFound}
	}
	attrs, err := fs.zplDS.readAttrs(objNum)
	if err != nil {
		return nil, fmt.Errorf("zfs: Stat %q: %w", path, err)
	}
	return filesystem.NewStat(uint16(attrs.mode), attrs.size, objNum), nil
}

// ── ListDir ──────────────────────────────────────────────────────────────────

// ListDir returns the entries of the directory at path.
func (fs *zfsFS) ListDir(path string) ([]filesystem.DirEntry, error) {
	if fs.zplDS == nil {
		return nil, fmt.Errorf("zfs: ListDir: pool not fully opened")
	}
	path = cleanPath(path)
	fs.mu.Lock()
	defer fs.mu.Unlock()

	objNum, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, path)
	if err != nil {
		return nil, &os.PathError{Op: "listdir", Path: path, Err: errNotFound}
	}
	dirDN, err := fs.zplDS.zplOS.readObject(objNum)
	if err != nil {
		return nil, fmt.Errorf("zfs: ListDir %q: %w", path, err)
	}
	if dirDN.typ != dmotDirContents {
		return nil, &os.PathError{Op: "listdir", Path: path, Err: errNotDir}
	}
	entries, err := zapListAll(fs.f, fs.partOffset, dirDN)
	if err != nil {
		return nil, fmt.Errorf("zfs: ListDir %q: ZAP: %w", path, err)
	}

	result := make([]filesystem.DirEntry, 0, len(entries))
	for name, rawVal := range entries {
		childObjNum := rawVal & 0x0000FFFFFFFFFFFF
		fileTypeCode := uint8(rawVal >> 60)
		var mode uint16
		switch fileTypeCode {
		case 4: // DT_DIR
			mode = 0o040755
		case 10: // DT_LNK
			mode = 0o0120777
		default: // DT_REG or unknown
			mode = 0o0100644
		}
		_ = mode
		result = append(result, filesystem.NewDirEntry(childObjNum, name, fileTypeCode))
	}
	return result, nil
}

// ── ReadFile ─────────────────────────────────────────────────────────────────

// ReadFile returns the contents of the file at path.
func (fs *zfsFS) ReadFile(path string) ([]byte, error) {
	if fs.zplDS == nil {
		return nil, fmt.Errorf("zfs: ReadFile: pool not fully opened")
	}
	path = cleanPath(path)
	fs.mu.Lock()
	defer fs.mu.Unlock()

	objNum, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: errNotFound}
	}
	dn, err := fs.zplDS.zplOS.readObject(objNum)
	if err != nil {
		return nil, fmt.Errorf("zfs: ReadFile %q: %w", path, err)
	}
	if dn.typ != dmotPlainFileContents {
		return nil, fmt.Errorf("zfs: ReadFile %q: not a regular file (type %d)", path, dn.typ)
	}
	if dn.blkptrAt(0).isNull() {
		// Empty file
		return nil, nil
	}
	data, err := readDnodeData(fs.f, fs.partOffset, dn)
	if err != nil {
		return nil, fmt.Errorf("zfs: ReadFile %q: %w", path, err)
	}
	// Trim to actual size from SA attrs
	attrs, err := fs.zplDS.readAttrs(objNum)
	if err != nil {
		return nil, fmt.Errorf("zfs: ReadFile %q: readAttrs: %w", path, err)
	}
	if int(attrs.size) > len(data) {
		return nil, fmt.Errorf("zfs: ReadFile %q: SA size %d > data block %d", path, attrs.size, len(data))
	}
	return data[:attrs.size], nil
}

// ── ReadLink ─────────────────────────────────────────────────────────────────

// ReadLink returns the target of the symlink at path.
func (fs *zfsFS) ReadLink(path string) (string, error) {
	if fs.zplDS == nil {
		return "", fmt.Errorf("zfs: ReadLink: pool not fully opened")
	}
	path = cleanPath(path)
	fs.mu.Lock()
	defer fs.mu.Unlock()

	objNum, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, path)
	if err != nil {
		return "", &os.PathError{Op: "readlink", Path: path, Err: errNotFound}
	}
	dn, err := fs.zplDS.zplOS.readObject(objNum)
	if err != nil {
		return "", fmt.Errorf("zfs: ReadLink %q: %w", path, err)
	}
	// Symlink target is stored in data blocks (plain file contents)
	if dn.blkptrAt(0).isNull() {
		return "", nil
	}
	data, err := readDnodeData(fs.f, fs.partOffset, dn)
	if err != nil {
		return "", fmt.Errorf("zfs: ReadLink %q: %w", path, err)
	}
	// Trim to SA size
	attrs, err := fs.zplDS.readAttrs(objNum)
	if err == nil && int(attrs.size) <= len(data) {
		data = data[:attrs.size]
	}
	return string(data), nil
}

// ── WriteFile ────────────────────────────────────────────────────────────────

// WriteFile creates or overwrites the file at path with data.
func (fs *zfsFS) WriteFile(path string, data []byte, perm os.FileMode) error {
	if fs.zplDS == nil {
		return fmt.Errorf("zfs: WriteFile: pool not fully opened")
	}
	if fs.alloc == nil {
		return fmt.Errorf("zfs: WriteFile: no allocator (read-only pool?)")
	}
	path = cleanPath(path)
	parentPath, name := parentAndBase(path)
	if name == "/" {
		return fmt.Errorf("zfs: WriteFile: cannot write to /")
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()

	parentObjNum, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, parentPath)
	if err != nil {
		return &os.PathError{Op: "open", Path: parentPath, Err: errNotFound}
	}

	// Check if file already exists
	existingObjNum, _ := fs.zplDS.lookupEntry(fs.f, fs.partOffset, parentObjNum, name)

	now := uint64(time.Now().Unix())
	mode := uint64(0o0100000 | (uint16(perm) & 0o7777))

	// Build data block if non-empty
	var dataBP blkptr
	var dataOff int64
	if len(data) > 0 {
		// Align data to block size
		bsz := poolBlockSize
		paddedSize := int(alignUp(int64(len(data)), int64(bsz)))
		paddedData := make([]byte, paddedSize)
		copy(paddedData, data)
		var err2 error
		dataOff, err2 = fs.alloc.alloc(paddedSize)
		if err2 != nil {
			return fmt.Errorf("zfs: WriteFile: %w", err2)
		}
		if _, err2 = fs.f.WriteAt(paddedData, fs.partOffset+dataOff); err2 != nil {
			return fmt.Errorf("zfs: WriteFile: write data: %w", err2)
		}
		dataBP = makeBlkptr(dataOff, paddedSize, paddedSize, zcompressOff, dmotPlainFileContents, 0, fs.curTxg)
	}

	// Build dnode
	attrs := &saAttrs{
		mode: mode, size: uint64(len(data)),
		gen: 1, uid: 0, gid: 0,
		parent: parentObjNum, links: 1,
		atime: [2]uint64{now, 0}, mtime: [2]uint64{now, 0},
		ctime: [2]uint64{now, 0}, crtime: [2]uint64{now, 0},
	}
	saBonus := writeSABonus(attrs, fs.zplDS.saLayout)
	fileDN := newDnode(dmotPlainFileContents, 1, dmotSA, uint16(len(saBonus)))
	fileDN.datablkszsec = uint16(poolBlockSize / 512)
	if len(data) > 0 {
		fileDN.setBlkptrAt(0, dataBP)
		fileDN.maxblkid = 0
	}
	bonusStart := dnodeHdrSize + blkptrSize
	copy(fileDN.raw[bonusStart:], saBonus)
	fileDN.encode()

	// Allocate or reuse object number
	var objNum uint64
	if existingObjNum != 0 {
		objNum = existingObjNum
	} else {
		objNum, err = fs.allocObjectNum()
		if err != nil {
			return fmt.Errorf("zfs: WriteFile: allocate object: %w", err)
		}
	}

	// Write dnode to ZPL object array
	if err := fs.writeDnode(objNum, fileDN); err != nil {
		return fmt.Errorf("zfs: WriteFile: write dnode: %w", err)
	}

	// Update parent directory ZAP
	if existingObjNum == 0 {
		dirEntry := (uint64(8) << 60) | objNum // DT_REG=8
		if err := fs.updateDirZAP(parentObjNum, name, dirEntry, false); err != nil {
			return fmt.Errorf("zfs: WriteFile: update dir: %w", err)
		}
	}

	return fs.commitUberblock()
}

// ── MkDir ────────────────────────────────────────────────────────────────────

// MkDir creates the directory at path.
func (fs *zfsFS) MkDir(path string, perm os.FileMode) error {
	if fs.zplDS == nil {
		return fmt.Errorf("zfs: MkDir: pool not fully opened")
	}
	if fs.alloc == nil {
		return fmt.Errorf("zfs: MkDir: no allocator (read-only pool?)")
	}
	path = cleanPath(path)
	parentPath, name := parentAndBase(path)
	if name == "/" {
		return fmt.Errorf("zfs: MkDir: cannot create /")
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()

	parentObjNum, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, parentPath)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: parentPath, Err: errNotFound}
	}

	// Fail if already exists
	if ex, _ := fs.zplDS.lookupEntry(fs.f, fs.partOffset, parentObjNum, name); ex != 0 {
		return &os.PathError{Op: "mkdir", Path: path, Err: os.ErrExist}
	}

	// Allocate a ZAP block for the new directory
	zapOff, err := fs.alloc.alloc(poolBlockSize)
	if err != nil {
		return fmt.Errorf("zfs: MkDir: alloc ZAP: %w", err)
	}
	emptyZAP := newMicroZAPBlock(poolBlockSize)
	if _, err := fs.f.WriteAt(emptyZAP, fs.partOffset+zapOff); err != nil {
		return fmt.Errorf("zfs: MkDir: write ZAP: %w", err)
	}

	now := uint64(time.Now().Unix())
	mode := uint64(0o040000 | (uint16(perm) & 0o7777))
	objNum, err := fs.allocObjectNum()
	if err != nil {
		return fmt.Errorf("zfs: MkDir: allocate object: %w", err)
	}

	attrs := &saAttrs{
		mode: mode, size: 0,
		gen: 1, uid: 0, gid: 0,
		parent: parentObjNum, links: 2,
		atime: [2]uint64{now, 0}, mtime: [2]uint64{now, 0},
		ctime: [2]uint64{now, 0}, crtime: [2]uint64{now, 0},
	}
	saBonus := writeSABonus(attrs, fs.zplDS.saLayout)
	dirDN := newDnode(dmotDirContents, 1, dmotSA, uint16(len(saBonus)))
	dirDN.datablkszsec = uint16(poolBlockSize / 512)
	dirDN.setBlkptrAt(0, makeBlkptr(zapOff, poolBlockSize, poolBlockSize,
		zcompressOff, dmotDirContents, 0, fs.curTxg))
	bonusStart := dnodeHdrSize + blkptrSize
	copy(dirDN.raw[bonusStart:], saBonus)
	dirDN.encode()

	if err := fs.writeDnode(objNum, dirDN); err != nil {
		return fmt.Errorf("zfs: MkDir: write dnode: %w", err)
	}

	dirEntry := (uint64(4) << 60) | objNum // DT_DIR=4
	if err := fs.updateDirZAP(parentObjNum, name, dirEntry, false); err != nil {
		return fmt.Errorf("zfs: MkDir: update parent dir: %w", err)
	}

	return fs.commitUberblock()
}

// ── DeleteFile ───────────────────────────────────────────────────────────────

// DeleteFile removes the file at path.
func (fs *zfsFS) DeleteFile(path string) error {
	if fs.zplDS == nil {
		return fmt.Errorf("zfs: DeleteFile: pool not fully opened")
	}
	if fs.alloc == nil {
		return fmt.Errorf("zfs: DeleteFile: no allocator (read-only pool?)")
	}
	path = cleanPath(path)
	parentPath, name := parentAndBase(path)
	fs.mu.Lock()
	defer fs.mu.Unlock()

	parentObjNum, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, parentPath)
	if err != nil {
		return &os.PathError{Op: "remove", Path: path, Err: errNotFound}
	}
	objNum, err := fs.zplDS.lookupEntry(fs.f, fs.partOffset, parentObjNum, name)
	if err != nil {
		return &os.PathError{Op: "remove", Path: path, Err: errNotFound}
	}

	dn, err := fs.zplDS.zplOS.readObject(objNum)
	if err != nil {
		return fmt.Errorf("zfs: DeleteFile %q: %w", path, err)
	}
	if dn.typ == dmotDirContents {
		return fmt.Errorf("zfs: DeleteFile %q: is a directory", path)
	}

	// Zero out the dnode (marks it free)
	if err := fs.writeDnode(objNum, &dnode{raw: make([]byte, dnodeMinSize)}); err != nil {
		return fmt.Errorf("zfs: DeleteFile %q: zero dnode: %w", path, err)
	}

	// Remove from parent directory ZAP
	if err := fs.updateDirZAP(parentObjNum, name, 0, true); err != nil {
		return fmt.Errorf("zfs: DeleteFile %q: update dir: %w", path, err)
	}

	return fs.commitUberblock()
}

// ── DeleteDir ────────────────────────────────────────────────────────────────

// DeleteDir removes the empty directory at path.
func (fs *zfsFS) DeleteDir(path string) error {
	if fs.zplDS == nil {
		return fmt.Errorf("zfs: DeleteDir: pool not fully opened")
	}
	if fs.alloc == nil {
		return fmt.Errorf("zfs: DeleteDir: no allocator (read-only pool?)")
	}
	path = cleanPath(path)
	if path == "/" {
		return fmt.Errorf("zfs: DeleteDir: cannot remove root")
	}
	parentPath, name := parentAndBase(path)
	fs.mu.Lock()
	defer fs.mu.Unlock()

	parentObjNum, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, parentPath)
	if err != nil {
		return &os.PathError{Op: "rmdir", Path: path, Err: errNotFound}
	}
	objNum, err := fs.zplDS.lookupEntry(fs.f, fs.partOffset, parentObjNum, name)
	if err != nil {
		return &os.PathError{Op: "rmdir", Path: path, Err: errNotFound}
	}

	dn, err := fs.zplDS.zplOS.readObject(objNum)
	if err != nil {
		return fmt.Errorf("zfs: DeleteDir %q: %w", path, err)
	}
	if dn.typ != dmotDirContents {
		return fmt.Errorf("zfs: DeleteDir %q: not a directory", path)
	}

	// Check empty
	entries, err := zapListAll(fs.f, fs.partOffset, dn)
	if err != nil {
		return fmt.Errorf("zfs: DeleteDir %q: read entries: %w", path, err)
	}
	if len(entries) > 0 {
		return &os.PathError{Op: "rmdir", Path: path, Err: errNotEmpty}
	}

	if err := fs.writeDnode(objNum, &dnode{raw: make([]byte, dnodeMinSize)}); err != nil {
		return fmt.Errorf("zfs: DeleteDir %q: zero dnode: %w", path, err)
	}
	if err := fs.updateDirZAP(parentObjNum, name, 0, true); err != nil {
		return fmt.Errorf("zfs: DeleteDir %q: update parent dir: %w", path, err)
	}

	return fs.commitUberblock()
}

// ── Rename ───────────────────────────────────────────────────────────────────

// Rename moves oldPath to newPath.
func (fs *zfsFS) Rename(oldPath, newPath string) error {
	if fs.zplDS == nil {
		return fmt.Errorf("zfs: Rename: pool not fully opened")
	}
	if fs.alloc == nil {
		return fmt.Errorf("zfs: Rename: no allocator (read-only pool?)")
	}
	oldPath = cleanPath(oldPath)
	newPath = cleanPath(newPath)
	oldParent, oldName := parentAndBase(oldPath)
	newParent, newName := parentAndBase(newPath)
	fs.mu.Lock()
	defer fs.mu.Unlock()

	oldParentObj, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, oldParent)
	if err != nil {
		return &os.PathError{Op: "rename", Path: oldPath, Err: errNotFound}
	}
	newParentObj, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, newParent)
	if err != nil {
		return &os.PathError{Op: "rename", Path: newParent, Err: errNotFound}
	}

	// Find the source object
	oldObjRaw, err := fs.readDirEntryRaw(oldParentObj, oldName)
	if err != nil {
		return &os.PathError{Op: "rename", Path: oldPath, Err: errNotFound}
	}
	srcObjNum := oldObjRaw & 0x0000FFFFFFFFFFFF

	// If destination exists, remove it first (only for files)
	if dstObj, _ := fs.zplDS.lookupEntry(fs.f, fs.partOffset, newParentObj, newName); dstObj != 0 {
		dstDN, _ := fs.zplDS.zplOS.readObject(dstObj)
		if dstDN != nil && dstDN.typ == dmotDirContents {
			return fmt.Errorf("zfs: Rename: destination is a directory")
		}
		_ = fs.writeDnode(dstObj, &dnode{raw: make([]byte, dnodeMinSize)})
		_ = fs.updateDirZAP(newParentObj, newName, 0, true)
	}

	// Remove from old location and add to new location
	if err := fs.updateDirZAP(oldParentObj, oldName, 0, true); err != nil {
		return fmt.Errorf("zfs: Rename: remove old entry: %w", err)
	}
	if err := fs.updateDirZAP(newParentObj, newName, oldObjRaw, false); err != nil {
		// Try to put it back (best effort)
		_ = fs.updateDirZAP(oldParentObj, oldName, oldObjRaw, false)
		return fmt.Errorf("zfs: Rename: insert new entry: %w", err)
	}

	// Update parent reference in SA if it changed
	if oldParentObj != newParentObj {
		dn, err2 := fs.zplDS.zplOS.readObject(srcObjNum)
		if err2 == nil {
			attrs, err3 := parseDnodeSA(dn, fs.zplDS.saLayout)
			if err3 == nil {
				attrs.parent = newParentObj
				updateDnodeSA(dn, attrs, fs.zplDS.saLayout)
				_ = fs.writeDnode(srcObjNum, dn)
			}
		}
	}

	return fs.commitUberblock()
}

// ── Internal helpers ─────────────────────────────────────────────────────────

// allocObjectNum scans the ZPL object array to find a free slot (zeroed dnode).
func (fs *zfsFS) allocObjectNum() (uint64, error) {
	for i := uint64(4); i < fmtObjArrayObjs; i++ {
		dn, err := fs.zplDS.zplOS.readObject(i)
		if err != nil {
			continue
		}
		if dn.typ == dmotNone {
			return i, nil
		}
	}
	return 0, fmt.Errorf("zfs: no free object slot in ZPL (pool full)")
}

// writeDnode writes a dnode back to the ZPL object array at objNum.
func (fs *zfsFS) writeDnode(objNum uint64, dn *dnode) error {
	// Object array is at fmtZPLObjArrayOff; each dnode is 512 bytes.
	blkSz := uint64(fmtObjArraySize)
	byteOff := objNum * uint64(dnodeMinSize)
	blockID := byteOff / blkSz
	offsetInBlock := int(byteOff % blkSz)

	if blockID != 0 {
		return fmt.Errorf("zfs: writeDnode: object %d out of single-block array", objNum)
	}

	// Read the current object array block via the meta_dnode
	metaDN := fs.zplDS.zplOS.metaDnode
	bp := metaDN.blkptrAt(0)
	if bp.isNull() {
		return fmt.Errorf("zfs: writeDnode: ZPL meta_dnode has null BP")
	}

	blkData, err := readBlock(fs.f, fs.partOffset, bp)
	if err != nil {
		return fmt.Errorf("zfs: writeDnode: read object array: %w", err)
	}

	// Write the dnode into the block
	copy(blkData[offsetInBlock:], dn.raw[:dnodeMinSize])

	// Write the modified block back to its physical location
	physOff := fs.partOffset + bp.dvaOffset(0)
	if _, err := fs.f.WriteAt(blkData, physOff); err != nil {
		return fmt.Errorf("zfs: writeDnode: write object array: %w", err)
	}
	return nil
}

// updateDirZAP inserts (if delete=false) or deletes the entry for name in the
// directory dnode at dirObjNum.  For insert, rawVal is the full directory entry
// word ((type<<60)|objNum).
func (fs *zfsFS) updateDirZAP(dirObjNum uint64, name string, rawVal uint64, del bool) error {
	dirDN, err := fs.zplDS.zplOS.readObject(dirObjNum)
	if err != nil {
		return fmt.Errorf("zfs: updateDirZAP obj %d: %w", dirObjNum, err)
	}
	bp := dirDN.blkptrAt(0)
	if bp.isNull() {
		return fmt.Errorf("zfs: updateDirZAP obj %d: null BP", dirObjNum)
	}

	blkData, err := readBlock(fs.f, fs.partOffset, bp)
	if err != nil {
		return fmt.Errorf("zfs: updateDirZAP: read ZAP: %w", err)
	}

	blockType := binary.LittleEndian.Uint64(blkData[:8])
	if blockType != zbtMicro {
		return fmt.Errorf("zfs: updateDirZAP: unsupported ZAP type 0x%X for writes", blockType)
	}

	if del {
		mzapDelete(blkData, name)
	} else {
		if err := mzapInsert(blkData, name, rawVal); err != nil {
			return err
		}
	}

	// Write back to physical location
	physOff := fs.partOffset + bp.dvaOffset(0)
	if _, err := fs.f.WriteAt(blkData, physOff); err != nil {
		return fmt.Errorf("zfs: updateDirZAP: write back: %w", err)
	}
	return nil
}

// tryFatZAPInplace attempts to write the merged entries back into the
// existing fat-ZAP leaf blocks in-place. It requires that the pointer
// table already references leaf blocks (non-zero). If the existing leaf
// layout cannot accommodate the entries, an error is returned so the
// caller may fall back to a micro-ZAP conversion.
func (fs *zfsFS) tryFatZAPInplace(dirDN *dnode, hdrBlock []byte, entries map[string]uint64) error {
	le := binary.LittleEndian
	// Pointer table info
	ptrtblShift := le.Uint32(hdrBlock[zapHdrPtrtblOff+12:])
	numPtrs := uint64(1) << ptrtblShift
	ptrtblBlknum := le.Uint64(hdrBlock[zapHdrPtrtblOff:])

	// Read pointer table into slice
	leafNums := make([]uint64, numPtrs)
	if ptrtblBlknum == 0 {
		for i := uint64(0); i < numPtrs; i++ {
			off := 128 + i*8
			if int(off)+8 > len(hdrBlock) {
				break
			}
			leafNums[i] = le.Uint64(hdrBlock[off:])
		}
	} else {
		ptBlk, err := readDataBlock(fs.f, fs.partOffset, dirDN, ptrtblBlknum)
		if err != nil {
			return fmt.Errorf("zfs: tryFatZAPInplace: read ptrtbl: %w", err)
		}
		for i := uint64(0); i < numPtrs; i++ {
			ptrOff := i * 8
			if int(ptrOff)+8 > len(ptBlk) {
				break
			}
			leafNums[i] = le.Uint64(ptBlk[ptrOff:])
		}
	}

	// Collect non-zero leaf indices
	var nonZeroIdx []int
	var nonZeroLeafNums []uint64
	for i := 0; i < len(leafNums); i++ {
		if leafNums[i] != 0 {
			nonZeroIdx = append(nonZeroIdx, i)
			nonZeroLeafNums = append(nonZeroLeafNums, leafNums[i])
		}
	}
	if len(nonZeroLeafNums) == 0 {
		return fmt.Errorf("zfs: tryFatZAPInplace: no allocated leaf blocks to update")
	}

	// Distribute entries across the available leaf blocks using a hash.
	N := len(nonZeroLeafNums)
	entriesByLeaf := make([]map[string]uint64, N)
	for i := 0; i < N; i++ {
		entriesByLeaf[i] = make(map[string]uint64)
	}
	for k, v := range entries {
		h := fnv.New64a()
		h.Write([]byte(k))
		idx := int(h.Sum64() % uint64(N))
		entriesByLeaf[idx][k] = v
	}

	// For each leaf, build a new leaf block and write it to the leaf's
	// physical location (found via findDataBP).
	blockSize := dirDN.dataBlockSize()
	if blockSize == 0 {
		blockSize = poolBlockSize
	}
	for i, leafNum := range nonZeroLeafNums {
		// Read existing leaf to pick a reasonable prefix if possible
		prefix := 4
		if leafNum != 0 {
			if existing, err := readDataBlock(fs.f, fs.partOffset, dirDN, leafNum); err == nil && len(existing) >= 34 {
				prefix = int(binary.LittleEndian.Uint16(existing[32:]))
			}
		}
		newLeaf, err := buildFatZAPLeaf(blockSize, entriesByLeaf[i], prefix)
		if err != nil {
			return fmt.Errorf("zfs: tryFatZAPInplace: build leaf: %w", err)
		}
		bp, err := findDataBP(fs.f, fs.partOffset, dirDN, leafNum)
		if err != nil {
			return fmt.Errorf("zfs: tryFatZAPInplace: find leaf bp: %w", err)
		}
		phys := fs.partOffset + bp.dvaOffset(0)
		if _, err := fs.f.WriteAt(newLeaf, phys); err != nil {
			return fmt.Errorf("zfs: tryFatZAPInplace: write leaf at 0x%X: %w", phys, err)
		}
	}

	// Update entry count in header and write header back
	le.PutUint64(hdrBlock[zapHdrNumEntrOff:], uint64(len(entries)))
	hdrBP := dirDN.blkptrAt(0)
	hdrPhys := fs.partOffset + hdrBP.dvaOffset(0)
	if _, err := fs.f.WriteAt(hdrBlock, hdrPhys); err != nil {
		return fmt.Errorf("zfs: tryFatZAPInplace: write header: %w", err)
	}
	return nil
}

// readDirEntryRaw returns the raw uint64 directory entry for name in dirObjNum.
func (fs *zfsFS) readDirEntryRaw(dirObjNum uint64, name string) (uint64, error) {
	dirDN, err := fs.zplDS.zplOS.readObject(dirObjNum)
	if err != nil {
		return 0, err
	}
	entries, err := zapListAll(fs.f, fs.partOffset, dirDN)
	if err != nil {
		return 0, err
	}
	val, ok := entries[name]
	if !ok {
		return 0, errNotFound
	}
	return val, nil
}

// commitUberblock increments the txg and writes a new uberblock to label 0, slot 0
// and label 1, slot 0.  The rootbp is re-derived from the MOS meta_dnode.
func (fs *zfsFS) commitUberblock() error {
	fs.curTxg++

	// The rootbp points to the MOS objset itself; that block is unchanged.
	// Re-read its block pointer from the Open()-cached info.
	rootBPBuf := make([]byte, blkptrSize)
	if _, err := fs.f.ReadAt(rootBPBuf, fs.info.Offset+40); err != nil {
		return fmt.Errorf("zfs: commitUberblock: read rootbp: %w", err)
	}
	rootBP := parseBlkptr(rootBPBuf)
	// Update birth txg
	rootBP.birth = fs.curTxg
	rootBP.physBirth = fs.curTxg

	now := uint64(time.Now().Unix())
	ub := encodeUberblock(fs.info.Version, fs.curTxg, fs.info.GUIDSum, now, rootBP)

	slot := int(fs.curTxg % uberblockSlots)
	for label := 0; label < 2; label++ {
		// Uberblock ring lives inside the leading label area, NOT in the
		// data area — use labelOffset (raw partition start) here, not
		// partOffset (which is data-area-shifted by VDEV_LABEL_START_SIZE).
		ubOff := fs.labelOffset + int64(label)*vdevLabelSize +
			uberblockRegionOffset + int64(slot)*uberblockSize
		fs.f.WriteAt(ub, ubOff)
	}
	return nil
}

// initAllocator computes the next free offset by scanning ZPL block pointers.
func (fs *zfsFS) initAllocator(imageSize int64) {
	maxOff := int64(fmtInitialNextFree)
	if fs.zplDS != nil {
		// Quick scan: look at each ZPL object's data BP
		for i := uint64(1); i < fmtObjArrayObjs; i++ {
			dn, err := fs.zplDS.zplOS.readObject(i)
			if err != nil || dn == nil || dn.typ == dmotNone {
				continue
			}
			for j := 0; j < int(dn.nblkptr); j++ {
				bp := dn.blkptrAt(j)
				if bp.isNull() {
					continue
				}
				end := bp.dvaOffset(0) + bp.dvaAsize(0)
				if end > maxOff {
					maxOff = end
				}
			}
		}
	}
	next := alignUp(maxOff, int64(poolBlockSize))
	limit := imageSize - 2*vdevLabelSize
	if limit < next {
		limit = next
	}
	fs.alloc = newAllocator(next, limit, poolBlockSize)
}
