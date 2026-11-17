package filesystem_zfs

import (
	"bytes"
	"math/rand/v2"
	"sync"
	"testing"
)

// countBackend counts the device reads per offset.
type countBackend struct {
	blockBackend
	mu sync.Mutex
	n  map[int64]int
}

func (c *countBackend) ReadAt(p []byte, off int64) (int, error) {
	c.mu.Lock()
	c.n[off]++
	c.mu.Unlock()
	return c.blockBackend.ReadAt(p, off)
}

// A file of two level-1 indirect blocks (more than 1024 records of 128 KiB) read
// at random alternates between them: each is read from the device and verified
// once, not every time the walk changes block (the one-entry-per-level cache
// alone re-read one on every other read). The kernel keeps indirect blocks in
// its dbuf cache (module/zfs/dbuf.c, dbuf_findbp -> dbuf_hold_impl -> dbuf_find).
func TestIndirectBlocksAreReadOnceAcrossARandomWalk(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a 132 MiB file")
	}
	const size = 132 << 20 // 1056 records of 128 KiB: two L1 blocks of 1024 pointers
	ifs, want := bigZFS(t, size)
	fs := ifs.(*zfsFS)
	cb := &countBackend{blockBackend: fs.vb.blockBackend, n: map[int64]int{}}
	fs.vb.blockBackend = cb
	of, err := fs.OpenFile("/big")
	if err != nil {
		t.Fatal(err)
	}
	f := of.(*zfsFile)
	buf := make([]byte, 4096)
	read := func(off int64) {
		t.Helper()
		if n, err := f.ReadAt(buf, off); err != nil || n != len(buf) || !bytes.Equal(buf, want[off:off+int64(n)]) {
			t.Fatalf("ReadAt(%d) = %d, %v", off, n, err)
		}
	}
	const rec = 128 << 10
	read(0)
	bpA := f.cache.ent[1].bp
	read(1050 * rec)
	bpB := f.cache.ent[1].bp
	if bpA == bpB {
		t.Fatalf("the file has one L1 block, the test needs two")
	}
	offA, offB := fs.partOffset+bpA.dvaOffset(0), fs.partOffset+bpB.dvaOffset(0)
	if cb.n[offA] != 1 || cb.n[offB] != 1 {
		t.Fatalf("setup: L1 reads %d and %d, want 1 and 1", cb.n[offA], cb.n[offB])
	}
	r := rand.New(rand.NewPCG(1, 2))
	for i := range 400 {
		read(int64(r.IntN(size/rec))*rec + int64(i%4096))
	}
	if cb.n[offA] != 1 || cb.n[offB] != 1 {
		t.Errorf("after 400 random reads the L1 blocks were read %d and %d times, want 1 and 1", cb.n[offA], cb.n[offB])
	}
	// A write to the pool empties the cache: the next read reads them again,
	// never a stale pointer.
	if err := fs.WriteFile("/other", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	read(0)
	if got := cb.n[offA]; got < 2 {
		t.Errorf("L1 block read %d times after a write, want it read again", got)
	}
}
