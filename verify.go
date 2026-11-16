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
	on   atomic.Bool
	salt atomic.Pointer[[32]byte] // the pool checksum salt, once read
}

// verifier is what readBlock asks of its reader.
type verifier interface{ verifying() bool }

func (v *verifyBackend) verifying() bool { return v.on.Load() }

// verifying forwards through the decrypting wrapper.
func (c *cryptingReader) verifying() bool { return readerVerifies(c.blockBackend) }

// salter carries the pool's checksum salt: the MOS pool directory entry
// "org.illumos:checksum_salt" keys the Skein, Edon-R and BLAKE3 checksums.
type salter interface {
	checksumSalt() *[32]byte
	setChecksumSalt(*[32]byte)
}

func (v *verifyBackend) checksumSalt() *[32]byte     { return v.salt.Load() }
func (v *verifyBackend) setChecksumSalt(s *[32]byte) { v.salt.Store(s) }

// The decrypting wrapper forwards both.
func (c *cryptingReader) checksumSalt() *[32]byte { return readerSalt(c.blockBackend) }
func (c *cryptingReader) setChecksumSalt(s *[32]byte) {
	if sl, ok := c.blockBackend.(salter); ok {
		sl.setChecksumSalt(s)
	}
}

// readerSalt returns the pool checksum salt known to r, nil if none.
func readerSalt(r io.ReaderAt) *[32]byte {
	if s, ok := r.(salter); ok {
		return s.checksumSalt()
	}
	return nil
}

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
