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

	// On overwrite, return the previous dnode's data extents to the
	// allocator before reallocating. Without this, every WriteFile to
	// an existing path leaks the old data block(s) — a problem for
	// long-running write loops with the same key set
	// (TestStress_ConcurrentRW exercises exactly this).
	if existingObjNum != 0 {
		if prev, err := fs.zplDS.zplOS.readObject(existingObjNum); err == nil {
			fs.freeDnodeData(prev)
		}
	}

	now := uint64(time.Now().Unix())
	mode := uint64(0o0100000 | (uint16(perm) & 0o7777))

	// Pick a per-file data block size. Small files keep the historic 4
	// KiB block (avoids wasting an entire 128 KiB record for a 32-byte
	// sentinel). Anything larger jumps to 128 KiB so we can address up
	// to several GiB through 1024-BP indirect blocks (indblkshift=17).
	const largeFileThreshold = 128 * 1024
	bsz := poolBlockSize
	if len(data) > largeFileThreshold {
		bsz = 128 * 1024
	}

	// Lay out the payload as N data blocks. The last block is padded
	// out to bsz; the read side trims back to attrs.size via ReadFile.
	nBlocks := 0
	if len(data) > 0 {
		nBlocks = int(alignUp(int64(len(data)), int64(bsz)) / int64(bsz))
	}
	dataBPs := make([]blkptr, nBlocks)
	for i := 0; i < nBlocks; i++ {
		// Slice this block's logical payload out of data.
		start := i * bsz
		end := start + bsz
		if end > len(data) {
			end = len(data)
		}
		block := make([]byte, bsz) // zero-padded tail
		copy(block, data[start:end])
		off, err := fs.alloc.alloc(bsz)
		if err != nil {
			// Roll back already-allocated blocks so a mid-allocation
			// failure doesn't permanently leak space.
			for j := 0; j < i; j++ {
				fs.alloc.free(dataBPs[j].dvaOffset(0), int(dataBPs[j].psize()))
			}
			return fmt.Errorf("zfs: WriteFile: alloc data block %d/%d: %w", i, nBlocks, err)
		}
		if _, err := fs.f.WriteAt(block, fs.partOffset+off); err != nil {
			return fmt.Errorf("zfs: WriteFile: write data block %d: %w", i, err)
		}
		// Emit a real fletcher4 block-pointer checksum over the exact
		// on-disk bytes. Earlier the writer left these as ZIO_CHECKSUM_OFF,
		// which made `zdb -e -bcc` fail on a written-to pool; the checksum
		// must be present and (per commitUberblock's recommitChain)
		// propagate up the whole BP chain.
		dbp := makeBlkptrCksum(off, bsz, bsz, zcompressOff, dmotPlainFileContents, 0, fs.curTxg, zioChecksumFletch4)
		setBPChecksum(&dbp, block)
		dataBPs[i] = dbp
	}

	// Build the dnode. nblkptr=1 by default — multi-block files route
	// through one or more indirect blocks (see writeBlockTree).
	saBonus := writeSABonus(&saAttrs{
		mode: mode, size: uint64(len(data)),
		gen: 1, uid: 0, gid: 0,
		parent: parentObjNum, links: 1,
		atime: [2]uint64{now, 0}, mtime: [2]uint64{now, 0},
		ctime: [2]uint64{now, 0}, crtime: [2]uint64{now, 0},
	}, fs.zplDS.saLayout)
	fileDN := newDnode(dmotPlainFileContents, 1, dmotSA, uint16(len(saBonus)))
	fileDN.datablkszsec = uint16(bsz / 512)
	fileDN.indblkshift = 17 // 128 KiB indirect blocks (1024 BPs each)
	if nBlocks > 0 {
		rootBP, nlevels, err := fs.writeBlockTree(dataBPs, bsz, 1<<17)
		if err != nil {
			return fmt.Errorf("zfs: WriteFile: build indirect tree: %w", err)
		}
		fileDN.setBlkptrAt(0, rootBP)
		fileDN.maxblkid = uint64(nBlocks - 1)
		fileDN.nlevels = uint8(nlevels)
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
	zbp := makeBlkptrCksum(zapOff, poolBlockSize, poolBlockSize,
		zcompressOff, dmotDirContents, 0, fs.curTxg, zioChecksumFletch4)
	setBPChecksum(&zbp, emptyZAP)
	dirDN.setBlkptrAt(0, zbp)
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

// writeBlockTree assembles an indirect-block tree above a slice of
// level-0 (data) block pointers and returns the root blkptr that the
// dnode's first slot should point at, together with the resulting
// `nlevels` value (1 if the tree fits in a single direct BP, 2 if it
// needs one indirect level, 3 for two levels, etc.).
//
// dataBlockSize is the level-0 data block size in bytes (e.g. 4 KiB or
// 128 KiB). indirBlockSize is the byte size of each non-leaf node
// (matches dn.indblkshift; the writer uses 128 KiB → 1024 BPs each).
// Each indirect block is written into the data area through the
// allocator so DeleteFile's freeDnodeData walker reclaims it.
//
// The on-disk shape exactly matches what findDataBP / readDataBlock
// already decode: an indirect block is a flat array of `blkptrSize`
// entries, padded with zero BPs at the tail to fill indirBlockSize.
//
// nlevels is capped at 6 (the OpenZFS hard limit, same as the
// reader's findDataBP). Files needing deeper trees are rejected.
func (fs *zfsFS) writeBlockTree(dataBPs []blkptr, dataBlockSize, indirBlockSize int) (blkptr, int, error) {
	if len(dataBPs) == 0 {
		return blkptr{}, 0, fmt.Errorf("zfs: writeBlockTree: no data blocks")
	}
	if len(dataBPs) == 1 {
		// Single block — no indirection needed.
		return dataBPs[0], 1, nil
	}
	bpsPerIndir := indirBlockSize / blkptrSize
	currentBPs := dataBPs
	nlevels := 1
	// indirLogicalSize: each indirect block at level L "covers" a
	// span of logical bytes equal to bpsPerIndir^L * dataBlockSize.
	// We record an indirect BP with lsize=psize=indirBlockSize.
	for len(currentBPs) > 1 {
		if nlevels >= 6 {
			return blkptr{}, 0, fmt.Errorf("zfs: writeBlockTree: tree exceeds 6 levels (got %d data blocks, bps/indir=%d)",
				len(dataBPs), bpsPerIndir)
		}
		// Group currentBPs into chunks of bpsPerIndir; each chunk
		// becomes one indirect block.
		nextBPs := make([]blkptr, 0, (len(currentBPs)+bpsPerIndir-1)/bpsPerIndir)
		for chunkStart := 0; chunkStart < len(currentBPs); chunkStart += bpsPerIndir {
			chunkEnd := chunkStart + bpsPerIndir
			if chunkEnd > len(currentBPs) {
				chunkEnd = len(currentBPs)
			}
			indirBuf := make([]byte, indirBlockSize)
			for i, bp := range currentBPs[chunkStart:chunkEnd] {
				encodeBlkptr(bp, indirBuf[i*blkptrSize:(i+1)*blkptrSize])
			}
			off, err := fs.alloc.alloc(indirBlockSize)
			if err != nil {
				return blkptr{}, 0, fmt.Errorf("zfs: writeBlockTree: alloc indirect: %w", err)
			}
			if _, err := fs.f.WriteAt(indirBuf, fs.partOffset+off); err != nil {
				return blkptr{}, 0, fmt.Errorf("zfs: writeBlockTree: write indirect: %w", err)
			}
			// Indirect BPs carry level = nlevels (so the immediate
			// parent of dataBPs is level=1, etc.). The fletcher4 checksum
			// covers the indirect block's on-disk bytes (the array of
			// child BPs, themselves already checksummed bottom-up).
			indirBP := makeBlkptrCksum(off, indirBlockSize, indirBlockSize,
				zcompressOff, dmotPlainFileContents, uint8(nlevels), fs.curTxg, zioChecksumFletch4)
			setBPChecksum(&indirBP, indirBuf)
			nextBPs = append(nextBPs, indirBP)
		}
		currentBPs = nextBPs
		nlevels++
	}
	return currentBPs[0], nlevels, nil
}

// freeDnodeData walks every non-null, non-embedded data extent and
// indirect-block extent reachable from the dnode's blkptrs and returns
// them to the allocator. Safe to call on dnodes with nlevels == 0 or
// nblkptr == 0 (no-op).
//
// Gang blocks are intentionally skipped (the read path also rejects
// them); they would need traversal of the gang header to enumerate
// their members, which the writer never emits.
func (fs *zfsFS) freeDnodeData(dn *dnode) {
	if fs.alloc == nil || dn == nil || dn.nblkptr == 0 {
		return
	}
	for i := 0; i < int(dn.nblkptr); i++ {
		fs.freeBlkptr(dn.blkptrAt(i))
	}
}

// freeBlkptr returns the extent covered by bp (and any indirect-block
// extents underneath it) to the allocator. Null / embedded / gang BPs
// are skipped.
func (fs *zfsFS) freeBlkptr(bp blkptr) {
	if bp.isNull() || bp.isEmbedded() {
		return
	}
	if bp.dvaGang(0) {
		return
	}
	off := bp.dvaOffset(0)
	psize := bp.psize()
	// If this BP points at an indirect block, recursively walk the
	// pointers it contains before freeing the indirect block itself.
	if bp.level() > 0 {
		raw, err := readBlock(fs.f, fs.partOffset, bp)
		if err == nil {
			for i := 0; i+blkptrSize <= len(raw); i += blkptrSize {
				child := parseBlkptr(raw[i : i+blkptrSize])
				fs.freeBlkptr(child)
			}
		}
	}
	fs.alloc.free(off, int(psize))
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

	// Reclaim every data / indirect extent referenced by the dnode
	// before zeroing it out. Without this the bump-pointer allocator
	// leaks pool space on every DeleteFile and long write/delete loops
	// (see TestStress_ManyFiles) exhaust the pool monotonically.
	fs.freeDnodeData(dn)

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

	// Reclaim the directory's ZAP block (and any indirect extents)
	// before zeroing the dnode.
	fs.freeDnodeData(dn)

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
		// Return the destination's data extents to the allocator
		// before zeroing the dnode; same reasoning as DeleteFile.
		fs.freeDnodeData(dstDN)
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
	// Objects 1..fmtZPLObjCount are reserved by Format() (master node,
	// unlinked set, root dir, SA master/registry/layouts). User files start
	// at the first slot after them; the dmotNone check below also skips any
	// already-allocated slot, so a low start bound is safe either way.
	for i := uint64(fmtZPLObjCount + 1); i < fmtObjArrayObjs; i++ {
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

	// The ZAP block's bytes changed, so the directory dnode's block
	// pointer checksum over it is now stale. Recompute it (matching the
	// dnode's configured checksum type, defaulting to fletcher4) and
	// rewrite the dnode into the object array so commitUberblock's
	// chain recompute carries the new checksum up to the uberblock.
	if !bp.isEmbedded() && bp.checksumType() != zioChecksumOff && bp.checksumType() != zioChecksumInherit {
		if bp.checksumType() == 0 {
			// Legacy dir dnodes written before this fix recorded
			// ZIO_CHECKSUM_INHERIT(0) on the ZAP BP; upgrade to fletcher4
			// so the block becomes zdb-verifiable.
			bp.prop = (bp.prop &^ (uint64(bpCksumBits) << bpCksumShift)) |
				(uint64(zioChecksumFletch4) << bpCksumShift)
		}
		setBPChecksum(&bp, blkData)
		bp.birth = fs.curTxg
		bp.physBirth = fs.curTxg
		dirDN.setBlkptrAt(0, bp)
		if err := fs.writeDnode(dirObjNum, dirDN); err != nil {
			return fmt.Errorf("zfs: updateDirZAP: rewrite dir dnode: %w", err)
		}
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
// and label 1, slot 0.  The rootbp is re-derived by recomputing the block-pointer
// checksum chain from the (just-rewritten) ZPL object array up to the uberblock.
func (fs *zfsFS) commitUberblock() error {
	fs.curTxg++

	// Re-emit metaslab 0's space_map so its claimed allocation matches the
	// blocks now live on disk. Block traversal (`zdb -e -bcc`, no -AAA)
	// cross-checks the space_map's smp_alloc against the bytes it finds
	// reachable from the rootbp; without this the writer's new data /
	// indirect / ZAP allocations show up as "size != alloc (leaked)". This
	// rewrites the space_map dnode INTO the on-disk MOS object array, so it
	// must run before recommitChain (which re-reads that array and
	// recomputes its checksum up the chain).
	if err := fs.updateSpaceMap(); err != nil {
		return fmt.Errorf("zfs: commitUberblock: update space_map: %w", err)
	}

	// Recompute the block-pointer checksum chain from the leaf metadata
	// blocks the mutation just rewrote, bottom-up to the rootbp. Without
	// this, every in-place metadata rewrite (writeDnode / updateDirZAP)
	// leaves a STALE fletcher4 up the chain, so `zdb -e -bcc` fails on a
	// written-to pool. recommitChain returns the fresh, fully-checksummed
	// rootbp to embed in the new uberblock.
	rootBP, err := fs.recommitChain()
	if err != nil {
		return fmt.Errorf("zfs: commitUberblock: recompute checksum chain: %w", err)
	}
	rootBP.birth = fs.curTxg
	rootBP.physBirth = fs.curTxg

	now := uint64(time.Now().Unix())
	ub := encodeUberblock(fs.info.Version, fs.curTxg, fs.info.GUIDSum, now, rootBP)

	// Uberblock ring slots are uberblockSlotSize (4 KiB for ashift=12);
	// the active slot is txg % nslots, matching OpenZFS and what zdb /
	// zpool import expect. Each slot carries a ZIO_CHECKSUM_LABEL
	// self-checksum seeded with the slot's absolute offset.
	nslots := uberblockRegionSize / uberblockSlotSize
	slot := int(fs.curTxg % uint64(nslots))
	for label := 0; label < 2; label++ {
		// Uberblock ring lives inside the leading label area, NOT in the
		// data area — use labelOffset (raw partition start) here, not
		// partOffset (which is data-area-shifted by VDEV_LABEL_START_SIZE).
		labelOff := fs.labelOffset + int64(label)*vdevLabelSize
		ubAt := uberblockRegionOffset + slot*uberblockSlotSize
		slotBuf := make([]byte, uberblockSlotSize)
		copy(slotBuf, ub)
		labelSelfChecksum(slotBuf, uint64(labelOff+int64(ubAt)))
		fs.f.WriteAt(slotBuf, labelOff+int64(ubAt))
	}
	return nil
}

// updateSpaceMap re-emits metaslab 0's on-disk space_map to match the set of
// blocks currently live on the vdev, so `zdb -e -bcc` block traversal balances
// against the space maps (no "size != alloc (leaked)"). It is a no-op on
// read-only / bare-uberblock pools.
//
// The allocator reports the live allocated set as [allocStart, nextFree) minus
// the free list (see allocatedExtents). All of Format()'s writes and the
// writer's runtime allocations are confined to metaslab 0 ([0, 2^msShift)), so
// the extents — already data-area-relative, which is exactly the metaslab-0
// offset basis — encode directly into the space-map log. smp_alloc is the sum
// of their lengths.
func (fs *zfsFS) updateSpaceMap() error {
	if fs.zplDS == nil || fs.alloc == nil {
		return nil
	}

	// Locate the on-disk MOS object array via the active rootbp.
	rootBPBuf := make([]byte, blkptrSize)
	if _, err := fs.f.ReadAt(rootBPBuf, fs.info.Offset+40); err != nil {
		return fmt.Errorf("read rootbp: %w", err)
	}
	rootBP := parseBlkptr(rootBPBuf)
	mosObjsetBlk := make([]byte, rootBP.psize())
	if _, err := fs.f.ReadAt(mosObjsetBlk, fs.partOffset+rootBP.dvaOffset(0)); err != nil {
		return fmt.Errorf("read MOS objset: %w", err)
	}
	mosMetaBP := parseBlkptr(mosObjsetBlk[dnodeHdrSize : dnodeHdrSize+blkptrSize])
	mosObjArray := make([]byte, mosMetaBP.psize())
	if _, err := fs.f.ReadAt(mosObjArray, fs.partOffset+mosMetaBP.dvaOffset(0)); err != nil {
		return fmt.Errorf("read MOS object array: %w", err)
	}

	// Parse the metaslab-0 space_map dnode (MOS object fmtMOSSpaceMap0Obj).
	smOff := fmtMOSSpaceMap0Obj * dnodeMinSize
	if smOff+dnodeMinSize > len(mosObjArray) {
		return fmt.Errorf("space_map object %d out of MOS array", fmtMOSSpaceMap0Obj)
	}
	smDN, err := parseDnode(mosObjArray[smOff : smOff+dnodeMinSize])
	if err != nil {
		return fmt.Errorf("parse space_map dnode: %w", err)
	}
	if smDN.typ != dmotSpaceMap {
		// Older / different layout without our metaslab space map — nothing
		// to maintain (the leak audit only applies when a space map exists).
		return nil
	}
	smBP := smDN.blkptrAt(0)
	if smBP.isNull() {
		return fmt.Errorf("space_map dnode has null data BP")
	}

	// Build the new space-map log from the live allocated set.
	extents := fs.alloc.allocatedExtents(int64(fmtMOSObjsetOff))
	metaslab0End := int64(1) << fmtMetaslabShift
	ranges := make([]smRange, 0, len(extents))
	var allocBytes int64
	for _, e := range extents {
		if e.off+e.size > metaslab0End {
			// The live set has grown past metaslab 0. Maintaining a
			// balanced multi-metaslab space_map at runtime (allocating new
			// space_map objects, growing the metaslab_array, adjusting the
			// spacemap_histogram feature refcount) is beyond this writer;
			// leave the space_map untouched rather than emit a wrong one.
			// The block-pointer checksum chain is still fully recomputed by
			// recommitChain, so the pool stays checksum-clean — only the
			// space-accounting leak audit (`zdb -bcc` without -AAA) would
			// flag such a >16 MiB pool. Smaller pools stay fully balanced.
			return nil
		}
		ranges = append(ranges, smRange{off: e.off, length: e.size, typ: smAlloc})
		allocBytes += e.size
	}
	smLog := encodeSpaceMapLog(ranges)

	smBlkSize := int(smBP.psize())
	if len(smLog) > smBlkSize {
		// Too many discontiguous live extents to fit the space-map log in
		// one block. Same rationale as the metaslab-0 overflow above: leave
		// the space_map as-is rather than truncate it.
		return nil
	}
	smBlock := make([]byte, smBlkSize)
	copy(smBlock, smLog)

	// Write the space-map data block and recompute its BP checksum.
	if _, err := fs.f.WriteAt(smBlock, fs.partOffset+smBP.dvaOffset(0)); err != nil {
		return fmt.Errorf("write space_map block: %w", err)
	}
	setBPChecksum(&smBP, smBlock)
	smBP.birth = fs.curTxg
	smBP.physBirth = fs.curTxg
	smDN.setBlkptrAt(0, smBP)

	// Update the space_map_phys_t bonus (smp_length, smp_alloc) in place.
	bonusBase := dnodeBonusOff(int(smDN.nblkptr))
	if bonusBase+smpAlloc+8 > len(smDN.raw) {
		return fmt.Errorf("space_map bonus out of dnode")
	}
	binary.LittleEndian.PutUint64(smDN.raw[bonusBase+smpLength:], uint64(len(smLog)))
	binary.LittleEndian.PutUint64(smDN.raw[bonusBase+smpAlloc:], uint64(allocBytes))

	// Write the updated space_map dnode back into the on-disk MOS object
	// array. recommitChain re-reads this array and recomputes its checksum
	// (and the whole chain above) on the next step.
	copy(mosObjArray[smOff:smOff+dnodeMinSize], smDN.raw[:dnodeMinSize])
	if _, err := fs.f.WriteAt(mosObjArray, fs.partOffset+mosMetaBP.dvaOffset(0)); err != nil {
		return fmt.Errorf("write MOS object array: %w", err)
	}
	return nil
}

// recommitChain recomputes the on-disk block-pointer checksum chain after a
// metadata mutation and returns the fresh rootbp that should go into the new
// uberblock. ZFS verifies every block by the fletcher4 checksum stored in the
// blkptr that POINTS AT it, so an in-place rewrite of any block (the ZPL object
// array via writeDnode, a directory ZAP via updateDirZAP, a file's data/indirect
// blocks) invalidates the checksum of EVERY block pointer from the uberblock
// down to it. recommitChain walks that path top-down and rewrites it bottom-up:
//
//	uberblock.rootbp        → MOS objset block
//	  MOS meta_dnode.bp[0]  → MOS object array      (holds the DSL dataset dnode)
//	    DSL dataset.ds_bp   → ZPL objset block
//	      ZPL meta_dnode.bp[0] → ZPL object array   (rewritten by writeDnode)
//
// Leaf BPs inside the ZPL object array (file data, indirect blocks, directory
// ZAP blocks) are already checksummed by the write path (WriteFile / MkDir /
// writeBlockTree / updateDirZAP) and rewritten into the object array before
// commit, so re-checksumming the object array here covers them too.
//
// All blocks are single-DVA, level-0 metadata at fixed physical offsets, so we
// read each block by its parent BP's DVA, patch the embedded child BP, write the
// block back, and recompute the parent's fletcher4 over the new bytes.
func (fs *zfsFS) recommitChain() (blkptr, error) {
	// Bare-uberblock image (no DSL/ZPL loaded): nothing to recompute —
	// fall back to bumping the existing rootbp's birth txg.
	if fs.zplDS == nil {
		rootBPBuf := make([]byte, blkptrSize)
		if _, err := fs.f.ReadAt(rootBPBuf, fs.info.Offset+40); err != nil {
			return blkptr{}, fmt.Errorf("read rootbp: %w", err)
		}
		return parseBlkptr(rootBPBuf), nil
	}

	// readPhys / writePhys operate on the data area (DVAs are relative to it).
	readPhys := func(bp blkptr) ([]byte, error) {
		buf := make([]byte, bp.psize())
		if _, err := fs.f.ReadAt(buf, fs.partOffset+bp.dvaOffset(0)); err != nil {
			return nil, err
		}
		return buf, nil
	}
	writePhys := func(bp blkptr, data []byte) error {
		_, err := fs.f.WriteAt(data, fs.partOffset+bp.dvaOffset(0))
		return err
	}

	// 1. Read the current rootbp (points at the MOS objset block).
	rootBPBuf := make([]byte, blkptrSize)
	if _, err := fs.f.ReadAt(rootBPBuf, fs.info.Offset+40); err != nil {
		return blkptr{}, fmt.Errorf("read rootbp: %w", err)
	}
	rootBP := parseBlkptr(rootBPBuf)

	mosObjsetBlk, err := readPhys(rootBP)
	if err != nil {
		return blkptr{}, fmt.Errorf("read MOS objset: %w", err)
	}
	mosMetaBP := parseBlkptr(mosObjsetBlk[dnodeHdrSize : dnodeHdrSize+blkptrSize])

	// 2. Read the MOS object array and locate the head DSL dataset dnode,
	//    whose bonus ds_bp points at the ZPL objset block.
	mosObjArray, err := readPhys(mosMetaBP)
	if err != nil {
		return blkptr{}, fmt.Errorf("read MOS object array: %w", err)
	}
	dsObjNum := fs.zplDS.headDSObjNum
	dsOff := int(dsObjNum) * dnodeMinSize
	if dsOff+dnodeMinSize > len(mosObjArray) {
		return blkptr{}, fmt.Errorf("DSL dataset object %d out of MOS array", dsObjNum)
	}
	dsDN, err := parseDnode(mosObjArray[dsOff : dsOff+dnodeMinSize])
	if err != nil {
		return blkptr{}, fmt.Errorf("parse DSL dataset dnode: %w", err)
	}
	bonusBase := dnodeHdrSize + int(dsDN.nblkptr)*blkptrSize
	zplBPOff := bonusBase + dsBP // ds_bp sits at offset dsBP within the bonus
	if zplBPOff+blkptrSize > len(mosObjArray[dsOff:dsOff+dnodeMinSize]) {
		return blkptr{}, fmt.Errorf("ds_bp out of DSL dataset dnode")
	}
	zplBP := parseBlkptr(mosObjArray[dsOff+zplBPOff : dsOff+zplBPOff+blkptrSize])

	// 3. Read the ZPL objset block; its meta_dnode bp[0] points at the ZPL
	//    object array (the block writeDnode rewrote in place).
	zplObjsetBlk, err := readPhys(zplBP)
	if err != nil {
		return blkptr{}, fmt.Errorf("read ZPL objset: %w", err)
	}
	zplMetaBP := parseBlkptr(zplObjsetBlk[dnodeHdrSize : dnodeHdrSize+blkptrSize])

	// ── Bottom-up recompute ──────────────────────────────────────────────

	// (a) ZPL object array → zplMetaBP checksum.
	zplObjArray, err := readPhys(zplMetaBP)
	if err != nil {
		return blkptr{}, fmt.Errorf("read ZPL object array: %w", err)
	}
	setBPChecksum(&zplMetaBP, zplObjArray)
	encodeBlkptr(zplMetaBP, zplObjsetBlk[dnodeHdrSize:dnodeHdrSize+blkptrSize])
	if err := writePhys(zplBP, zplObjsetBlk); err != nil {
		return blkptr{}, fmt.Errorf("write ZPL objset: %w", err)
	}

	// (b) ZPL objset block → zplBP checksum, stored in the DSL dataset's ds_bp.
	setBPChecksum(&zplBP, zplObjsetBlk)
	encodeBlkptr(zplBP, mosObjArray[dsOff+zplBPOff:dsOff+zplBPOff+blkptrSize])
	if err := writePhys(mosMetaBP, mosObjArray); err != nil {
		return blkptr{}, fmt.Errorf("write MOS object array: %w", err)
	}

	// (c) MOS object array → mosMetaBP checksum, stored in the MOS objset block.
	setBPChecksum(&mosMetaBP, mosObjArray)
	encodeBlkptr(mosMetaBP, mosObjsetBlk[dnodeHdrSize:dnodeHdrSize+blkptrSize])
	if err := writePhys(rootBP, mosObjsetBlk); err != nil {
		return blkptr{}, fmt.Errorf("write MOS objset: %w", err)
	}

	// (d) MOS objset block → rootbp checksum (returned for the uberblock).
	setBPChecksum(&rootBP, mosObjsetBlk)
	return rootBP, nil
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
