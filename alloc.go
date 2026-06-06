package filesystem_zfs

// alloc.go – Sequential block allocator for ZFS pools created by Format().
//
// The allocator tracks the next available byte offset in the pool.
// It does not implement full ZFS metaslab / space-map logic; it is only
// suitable for images created by Format() and subsequently written by this
// package's write operations.  Any image mounted by an external ZFS
// implementation must be reformatted before use.

import (
	"fmt"
)

const poolBlockSize = 4096 // default ZFS block size (ashift=12)

// allocator is a simple bump-pointer allocator for pool blocks.
type allocator struct {
	nextFree  int64 // next free byte offset (absolute, i.e. relative to file start)
	limitOff  int64 // exclusive upper bound; do not allocate at or above this offset
	blockSize int   // granularity of allocations
}

// newAllocator creates an allocator that can allocate blocks between
// startOff (inclusive) and limitOff (exclusive).
func newAllocator(startOff, limitOff int64, blockSize int) *allocator {
	if blockSize <= 0 {
		blockSize = poolBlockSize
	}
	return &allocator{
		nextFree:  alignUp(startOff, int64(blockSize)),
		limitOff:  limitOff,
		blockSize: blockSize,
	}
}

// alloc reserves size bytes (rounded up to blockSize) and returns the byte offset.
func (a *allocator) alloc(size int) (int64, error) {
	sz := int64(alignUp(int64(size), int64(a.blockSize)))
	if a.nextFree+sz > a.limitOff {
		return 0, fmt.Errorf("zfs: allocator: out of space (need %d, free %d)", sz, a.limitOff-a.nextFree)
	}
	off := a.nextFree
	a.nextFree += sz
	return off, nil
}

// freeSpace returns the available space in bytes.
func (a *allocator) freeSpace() int64 { return a.limitOff - a.nextFree }
