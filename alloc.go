package filesystem_zfs

// alloc.go – Block allocator for ZFS pools created by Format().
//
// The allocator combines two strategies:
//
//   1. A bump pointer that monotonically advances through the data area
//      for first-use allocations (cheap; no bookkeeping per block).
//
//   2. A per-size-class free list of (offset, size) extents reclaimed
//      via DeleteFile. The free list is consulted first on every
//      allocation so long-running write/delete cycles (e.g. the stress
//      tests' "many files" / "concurrent R/W" profiles) do not bleed
//      pool space monotonically.
//
// It does not implement full ZFS metaslab / space-map logic; the
// allocator state is in-memory only and is rebuilt on Open() from the
// uberblock's recorded next-free pointer (free-list contents are
// forgotten across reopens, which is safe because the on-disk dnodes
// still pin live extents — they just won't be reused until the writer
// learns to persist the free list).

import (
	"fmt"
	"sort"
	"sync"
)

const poolBlockSize = 4096 // default ZFS block size (ashift=12)

// freeExtent records a contiguous run of pool blocks reclaimed via
// free(). All fields are byte offsets / byte counts.
type freeExtent struct {
	off  int64
	size int64
}

// allocator is the per-pool block allocator. Allocations come from the
// free list (best-fit by aligned-up size, exact-class first) when
// possible, otherwise from a monotonically advancing bump pointer.
type allocator struct {
	mu        sync.Mutex
	nextFree  int64 // next free byte offset for the bump pointer
	limitOff  int64 // exclusive upper bound; do not allocate at or above this offset
	blockSize int   // granularity of allocations
	// freeBySize maps aligned-up extent size → list of free extents of
	// exactly that size. Same-size hits are O(1) pop; different-size
	// hits fall through to a linear scan over all classes.
	freeBySize map[int64][]freeExtent
}

// newAllocator creates an allocator that can allocate blocks between
// startOff (inclusive) and limitOff (exclusive).
func newAllocator(startOff, limitOff int64, blockSize int) *allocator {
	if blockSize <= 0 {
		blockSize = poolBlockSize
	}
	return &allocator{
		nextFree:   alignUp(startOff, int64(blockSize)),
		limitOff:   limitOff,
		blockSize:  blockSize,
		freeBySize: make(map[int64][]freeExtent),
	}
}

// alloc reserves size bytes (rounded up to blockSize) and returns the
// byte offset. Prefers free-list entries of the exact aligned size,
// then any larger-but-splittable free entry, before bumping.
func (a *allocator) alloc(size int) (int64, error) {
	sz := int64(alignUp(int64(size), int64(a.blockSize)))
	a.mu.Lock()
	defer a.mu.Unlock()

	// 1. Exact-size hit on the free list — O(1) pop.
	if extents, ok := a.freeBySize[sz]; ok && len(extents) > 0 {
		e := extents[len(extents)-1]
		a.freeBySize[sz] = extents[:len(extents)-1]
		if len(a.freeBySize[sz]) == 0 {
			delete(a.freeBySize, sz)
		}
		return e.off, nil
	}

	// 2. Best-fit on a larger free extent: scan sizes that are at least
	// sz, pick the smallest available, pop one entry from that class
	// and split the remainder back into the appropriate bucket.
	if bestSize, found := a.bestFitSize(sz); found {
		extents := a.freeBySize[bestSize]
		e := extents[len(extents)-1]
		a.freeBySize[bestSize] = extents[:len(extents)-1]
		if len(a.freeBySize[bestSize]) == 0 {
			delete(a.freeBySize, bestSize)
		}
		if remainder := e.size - sz; remainder > 0 {
			a.freeBySize[remainder] = append(a.freeBySize[remainder], freeExtent{
				off:  e.off + sz,
				size: remainder,
			})
		}
		return e.off, nil
	}

	// 3. Fall back to the bump pointer.
	if a.nextFree+sz > a.limitOff {
		return 0, fmt.Errorf("zfs: allocator: out of space (need %d, free %d)", sz, a.freeSpaceLocked())
	}
	off := a.nextFree
	a.nextFree += sz
	return off, nil
}

// free returns a previously-allocated extent to the free list. size is
// the raw byte count requested at alloc time; it is rounded up to the
// blockSize granularity to match the original reservation.
//
// free is a no-op if size <= 0 or off < 0, so callers can safely pass
// in BPs from null / embedded blocks without filtering.
func (a *allocator) free(off int64, size int) {
	if off < 0 || size <= 0 {
		return
	}
	sz := int64(alignUp(int64(size), int64(a.blockSize)))
	a.mu.Lock()
	defer a.mu.Unlock()
	a.freeBySize[sz] = append(a.freeBySize[sz], freeExtent{off: off, size: sz})
}

// freeSpace returns the available space in bytes (bump-pointer tail
// plus the sum of all free-list extents). Callers must not rely on a
// strict "this many bytes fit in one allocation" — coalescing is not
// performed, so the largest single-shot allocation may be smaller than
// freeSpace() reports.
func (a *allocator) freeSpace() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.freeSpaceLocked()
}

func (a *allocator) freeSpaceLocked() int64 {
	total := a.limitOff - a.nextFree
	for _, extents := range a.freeBySize {
		for _, e := range extents {
			total += e.size
		}
	}
	return total
}

// freeListBytes returns the total bytes currently parked on the free
// list (not including the bump tail). Test-only helper.
func (a *allocator) freeListBytes() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	var total int64
	for _, extents := range a.freeBySize {
		for _, e := range extents {
			total += e.size
		}
	}
	return total
}

// bestFitSize returns the smallest free-list bucket size that is
// strictly greater than need and has at least one extent available.
// Caller must hold a.mu.
func (a *allocator) bestFitSize(need int64) (int64, bool) {
	sizes := make([]int64, 0, len(a.freeBySize))
	for sz, extents := range a.freeBySize {
		if sz > need && len(extents) > 0 {
			sizes = append(sizes, sz)
		}
	}
	if len(sizes) == 0 {
		return 0, false
	}
	sort.Slice(sizes, func(i, j int) bool { return sizes[i] < sizes[j] })
	return sizes[0], true
}
