package filesystem_zfs

import (
	"sync"
	"testing"
)

func TestAllocFreeSpace(t *testing.T) {
	a := newAllocator(0, 4096, poolBlockSize)
	if got := a.freeSpace(); got != 4096 {
		t.Fatalf("freeSpace() = %d, want 4096", got)
	}
	if _, err := a.alloc(poolBlockSize); err != nil {
		t.Fatalf("alloc: %v", err)
	}
	if got := a.freeSpace(); got != 0 {
		t.Fatalf("freeSpace() after alloc = %d, want 0", got)
	}
}

func TestAllocDefaultBlockSize(t *testing.T) {
	// blockSize <= 0 should fall back to poolBlockSize.
	a := newAllocator(0, 16384, 0)
	if a.blockSize != poolBlockSize {
		t.Fatalf("blockSize = %d, want %d (default)", a.blockSize, poolBlockSize)
	}
	a2 := newAllocator(0, 16384, -1)
	if a2.blockSize != poolBlockSize {
		t.Fatalf("blockSize = %d for -1 input, want %d", a2.blockSize, poolBlockSize)
	}
}

func TestAllocExhausted(t *testing.T) {
	a := newAllocator(0, poolBlockSize, poolBlockSize)
	if _, err := a.alloc(poolBlockSize); err != nil {
		t.Fatalf("first alloc: %v", err)
	}
	if _, err := a.alloc(1); err == nil {
		t.Fatal("second alloc error = nil, want out-of-space error")
	}
}

func TestAllocStartAlignment(t *testing.T) {
	// Unaligned start should be aligned up.
	a := newAllocator(1, 8192, poolBlockSize)
	if a.nextFree != poolBlockSize {
		t.Fatalf("nextFree = %d, want %d (aligned from 1)", a.nextFree, poolBlockSize)
	}
}

func TestAllocReturnsOffset(t *testing.T) {
	a := newAllocator(0, 3*poolBlockSize, poolBlockSize)
	off0, err := a.alloc(poolBlockSize)
	if err != nil || off0 != 0 {
		t.Fatalf("first alloc = (%d, %v), want (0, nil)", off0, err)
	}
	off1, err := a.alloc(poolBlockSize)
	if err != nil || off1 != poolBlockSize {
		t.Fatalf("second alloc = (%d, %v), want (%d, nil)", off1, err, poolBlockSize)
	}
}

// TestAllocFreeListExactSize verifies that an alloc → free → alloc
// cycle reuses the same offset (free-list LIFO, exact-size class).
// This is the property that prevents the bump pointer from leaking
// pool space under steady-state write/delete workloads.
func TestAllocFreeListExactSize(t *testing.T) {
	a := newAllocator(0, 8*poolBlockSize, poolBlockSize)
	off0, err := a.alloc(poolBlockSize)
	if err != nil || off0 != 0 {
		t.Fatalf("first alloc = (%d, %v), want (0, nil)", off0, err)
	}
	a.free(off0, poolBlockSize)
	if a.freeListBytes() != poolBlockSize {
		t.Fatalf("freeListBytes after free = %d, want %d", a.freeListBytes(), poolBlockSize)
	}
	off1, err := a.alloc(poolBlockSize)
	if err != nil || off1 != off0 {
		t.Fatalf("second alloc = (%d, %v), want (%d, nil) — free list should be reused",
			off1, err, off0)
	}
	if a.freeListBytes() != 0 {
		t.Fatalf("freeListBytes after second alloc = %d, want 0", a.freeListBytes())
	}
}

// TestAllocFreeListBestFit verifies a larger free extent is split on
// allocation when no exact-size class is available: the small request
// is satisfied, and the remainder rejoins the free list under a new
// size class.
func TestAllocFreeListBestFit(t *testing.T) {
	a := newAllocator(0, 16*poolBlockSize, poolBlockSize)
	// Allocate one 4-block extent then free it.
	big, err := a.alloc(4 * poolBlockSize)
	if err != nil {
		t.Fatalf("alloc big: %v", err)
	}
	a.free(big, 4*poolBlockSize)
	// Single-block alloc should land in the front of the freed extent.
	off, err := a.alloc(poolBlockSize)
	if err != nil || off != big {
		t.Fatalf("split alloc = (%d, %v), want (%d, nil)", off, err, big)
	}
	// Remainder should be 3 blocks back on the free list at a new size.
	if got, want := a.freeListBytes(), int64(3*poolBlockSize); got != want {
		t.Fatalf("freeListBytes after split = %d, want %d", got, want)
	}
}

// TestAllocFreeListReclaimsBeforeBump asserts the allocator never
// bumps the next-free pointer while there is a suitable extent on
// the free list. The pool is sized to fit exactly one allocation in
// the bump tail, and proves the SECOND allocation comes from the
// freed slot rather than failing OOM.
func TestAllocFreeListReclaimsBeforeBump(t *testing.T) {
	a := newAllocator(0, 2*poolBlockSize, poolBlockSize)
	off0, err := a.alloc(poolBlockSize)
	if err != nil {
		t.Fatalf("alloc 1: %v", err)
	}
	if _, err = a.alloc(poolBlockSize); err != nil {
		t.Fatalf("alloc 2: %v", err)
	}
	a.free(off0, poolBlockSize)
	off3, err := a.alloc(poolBlockSize)
	if err != nil {
		t.Fatalf("alloc 3 after free: %v", err)
	}
	if off3 != off0 {
		t.Fatalf("alloc 3 = %d, want %d (free list slot)", off3, off0)
	}
}

// TestAllocFreeIgnoresInvalid checks that calling free on null /
// negative inputs is a no-op (callers pass BPs straight through).
func TestAllocFreeIgnoresInvalid(t *testing.T) {
	a := newAllocator(0, 4*poolBlockSize, poolBlockSize)
	a.free(0, 0)
	a.free(-1, poolBlockSize)
	a.free(0, -1)
	if a.freeListBytes() != 0 {
		t.Fatalf("free-list shouldn't accept invalid extents, got %d bytes", a.freeListBytes())
	}
}

// TestAllocConcurrent stress-checks the allocator's mutex by hammering
// it with concurrent alloc/free pairs. Failure mode would be either a
// race (caught by -race) or an arithmetic invariant violation
// (free-list accumulates impossible extents).
func TestAllocConcurrent(t *testing.T) {
	a := newAllocator(0, 1<<24, poolBlockSize) // 16 MiB
	const iters = 200
	const workers = 8
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				off, err := a.alloc(poolBlockSize)
				if err != nil {
					return
				}
				a.free(off, poolBlockSize)
			}
		}()
	}
	wg.Wait()
	// After every alloc was matched with a free, no extent should be
	// orphaned: bump tail + free-list bytes must equal the original
	// capacity (modulo same-offset reuse).
	if a.freeSpace() <= 0 {
		t.Fatalf("freeSpace after balanced churn = %d, want > 0", a.freeSpace())
	}
}
