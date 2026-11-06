package filesystem_zfs

// openfile.go — filesystem.Opener: positional reads of a regular file. Each
// ReadAt reads only the data blocks of its own window (through the indirect
// blocks, which are cached for the handle), so a server answering a READ of a
// few bytes of a large file (NFS, SFTP) does not materialise the whole object
// through ReadFile for every request.

import (
	"fmt"
	"io"
	"os"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-volumes/safeio"
)

var _ filesystem.Opener = (*zfsFS)(nil)

// OpenFile opens the regular file at path for positional reads. Holes read as
// zeros. Nothing of the file is read here.
func (fs *zfsFS) OpenFile(path string) (filesystem.File, error) {
	if fs.zplDS == nil {
		return nil, fmt.Errorf("zfs: OpenFile: pool not fully opened")
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
		return nil, fmt.Errorf("zfs: OpenFile %q: %w", path, err)
	}
	if dn.typ != dmotPlainFileContents {
		return nil, fmt.Errorf("zfs: OpenFile %q: not a regular file (type %d)", path, dn.typ)
	}
	f := &zfsFile{fs: fs, dn: dn}
	if dn.blkptrAt(0).isNull() { // an empty file
		return f, nil
	}
	attrs, err := fs.zplDS.readAttrs(objNum)
	if err != nil {
		return nil, fmt.Errorf("zfs: OpenFile %q: readAttrs: %w", path, err)
	}
	f.size = attrs.size
	if f.size > 1<<62 { // a forged size is no size
		f.size = 1 << 62
	}
	if f.blkSz = dn.dataBlockSize(); f.blkSz == 0 || f.blkSz > spaMaxBlockSize {
		return nil, fmt.Errorf("zfs: OpenFile %q: data block size %d: %w", path, f.blkSz, safeio.ErrTooLarge)
	}
	return f, nil
}

type zfsFile struct {
	fs    *zfsFS
	dn    *dnode
	size  uint64
	blkSz int
	cache indirectCache // guarded by fs.mu
}

func (f *zfsFile) Size() int64 { return int64(f.size) }

func (f *zfsFile) Close() error { return nil }

// ReadAt fills p from off and says io.EOF with the bytes there are when the
// window runs past the end of the file.
func (f *zfsFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("zfs: negative offset %d", off)
	}
	if uint64(off) >= f.size {
		return 0, io.EOF
	}
	want := uint64(len(p))
	if uint64(off)+want > f.size {
		want = f.size - uint64(off)
	}
	dst := p[:want]
	clear(dst)
	if err := f.fill(dst, uint64(off)); err != nil {
		return 0, err
	}
	if want < uint64(len(p)) {
		return int(want), io.EOF
	}
	return int(want), nil
}

func (f *zfsFile) fill(dst []byte, off uint64) error {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	bs := uint64(f.blkSz)
	hi := off + uint64(len(dst))
	for blk := off / bs; blk*bs < hi; blk++ {
		if blk > f.dn.maxblkid { // past the last block the dnode has: zeros
			break
		}
		data, err := readDataBlockCached(f.fs.f, f.fs.partOffset, f.dn, blk, &f.cache)
		if err != nil {
			return err
		}
		start := blk * bs
		lo, top := max(start, off), min(start+uint64(len(data)), hi)
		if top <= lo {
			continue
		}
		copy(dst[lo-off:top-off], data[lo-start:top-start])
	}
	return nil
}
