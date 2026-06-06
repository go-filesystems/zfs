package filesystem_zfs

import "testing"

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
