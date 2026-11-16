package filesystem_zfs

import (
	"errors"
	"io"
	"os"
	"sync/atomic"
)

// Checksum verification is switched on for the duration of a READ operation
// (Open, Stat, ListDir, ReadFile, ReadLink, OpenFile and its ReadAt) and is off
// while the writer runs. The writer updates a block in place and only restores
// the checksum chain above it at the end of the operation (recommitChain), so a
// read it makes in the middle of an operation sees a block whose parent pointer
// is, for the moment, stale on purpose.

// verifyBackend is the blockBackend the filesystem reads through; its flag says
// whether readBlock checks block checksums.
type verifyBackend struct {
	blockBackend
	on atomic.Bool
}

// verifier is what readBlock asks of its reader.
type verifier interface{ verifying() bool }

func (v *verifyBackend) verifying() bool { return v.on.Load() }

// verifying forwards through the decrypting wrapper.
func (c *cryptingReader) verifying() bool { return readerVerifies(c.blockBackend) }

// readerVerifies reports whether reads through r must verify block checksums.
func readerVerifies(r io.ReaderAt) bool {
	v, ok := r.(verifier)
	return ok && v.verifying()
}

// verifyReads turns verification on until the returned function is called.
func (fs *zfsFS) verifyReads() func() {
	vb := fs.vb
	if vb == nil {
		return func() {}
	}
	was := vb.on.Swap(true)
	return func() { vb.on.Store(was) }
}

// lookupErr is what a read entry point returns when path resolution fails: a
// checksum error is reported as such (the data is damaged), anything else keeps
// meaning "not found".
func lookupErr(op, path string, err error) error {
	if errors.Is(err, ErrChecksum) {
		return err
	}
	return &os.PathError{Op: op, Path: path, Err: errNotFound}
}
