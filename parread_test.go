package filesystem_zfs

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"path/filepath"
	"sync"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

type parFS interface {
	filesystem.Filesystem
	filesystem.Opener
	SetReadParallelism(int)
	SetMaxDataCache(int64)
}

func asPar(t testing.TB, fs filesystem.Filesystem) parFS {
	t.Helper()
	p, ok := fs.(parFS)
	if !ok {
		t.Fatalf("%T has no SetReadParallelism / SetMaxDataCache", fs)
	}
	return p
}

// The result of every read entry point must not depend on the worker count.
func TestParallelReadsEqualSerial(t *testing.T) {
	const size = 6<<20 + 12345 // 49 records of 128 KiB, the last one short
	ifs, want := bigZFS(t, size)
	fs := asPar(t, ifs)
	for _, w := range []int{1, 2, 3, 8, 64} {
		fs.SetReadParallelism(w)
		got, err := fs.ReadFile("/big")
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("workers %d: ReadFile: %v (equal: %v)", w, err, bytes.Equal(got, want))
		}
		f, err := fs.OpenFile("/big")
		if err != nil {
			t.Fatal(err)
		}
		for _, chunk := range []int{4096, 128 << 10, 1 << 20, 5<<20 + 7} { // sequential, across and beyond a window
			buf := make([]byte, chunk)
			var off int64
			for off < size {
				n, err := f.ReadAt(buf, off)
				if err != nil && !errors.Is(err, io.EOF) {
					t.Fatalf("workers %d chunk %d at %d: %v", w, chunk, off, err)
				}
				if !bytes.Equal(buf[:n], want[off:off+int64(n)]) {
					t.Fatalf("workers %d chunk %d: wrong bytes at %d", w, chunk, off)
				}
				off += int64(n)
				if n == 0 {
					break
				}
			}
			if off != size {
				t.Fatalf("workers %d chunk %d: read %d of %d", w, chunk, off, size)
			}
		}
		r := rand.New(rand.NewPCG(uint64(w), 7))
		buf := make([]byte, 4096)
		for range 300 {
			off := int64(r.IntN(size - len(buf)))
			if n, err := f.ReadAt(buf, off); err != nil || n != len(buf) || !bytes.Equal(buf, want[off:off+int64(n)]) {
				t.Fatalf("workers %d: random read at %d: %d, %v", w, off, n, err)
			}
		}
		f.Close()
	}
}

func TestSetReadParallelismBounds(t *testing.T) {
	ifs, _ := bigZFS(t, 1<<20)
	fs := ifs.(*zfsFS)
	for _, c := range []struct{ set, want int }{{0, 1}, {-5, 1}, {1, 1}, {4, 4}, {1000, 64}} {
		fs.SetReadParallelism(c.set)
		if got := fs.readWorkers(); got != c.want {
			t.Errorf("SetReadParallelism(%d): %d workers, want %d", c.set, got, c.want)
		}
	}
	if w := (&zfsFS{}).readWorkers(); w < 1 || w > maxReadParallelism {
		t.Errorf("default workers %d outside [1,%d]", w, maxReadParallelism)
	}
}

// A sequential reader asking 4 KiB at a time finds its next records decoded; a
// random reader does not trigger a read-ahead.
func TestSequentialReaderGetsReadAhead(t *testing.T) {
	ifs, want := bigZFS(t, 4<<20)
	fs := ifs.(*zfsFS)
	fs.SetReadParallelism(4)
	f, _ := fs.OpenFile("/big")
	buf := make([]byte, 4096)
	f.ReadAt(buf, 1<<20) // random: one record
	if n := fs.dc.Load().Len(); n != 1 {
		t.Fatalf("a random read cached %d records, want 1", n)
	}
	for off := int64(0); off < 4<<20; off += 4096 {
		if _, err := f.ReadAt(buf, off); err != nil || !bytes.Equal(buf, want[off:off+4096]) {
			t.Fatalf("at %d: %v", off, err)
		}
		if off == 3*4096 { // the 4th sequential call: records beyond the first are decoded ahead
			if n := fs.dc.Load().Len(); n < 4 {
				t.Fatalf("after a sequential start the cache holds %d records", n)
			}
		}
	}
	// The whole file (32 records of 128 KiB = 4 MiB) fits the 8 MiB start.
	if n := fs.dc.Load().Len(); n != 32 {
		t.Errorf("cache holds %d records, want 32", n)
	}
}

// What the cache holds is dropped when the pool is written to.
func TestRecordCacheDroppedByAWrite(t *testing.T) {
	ifs, _ := bigZFS(t, 1<<20)
	fs := ifs.(*zfsFS)
	f, _ := fs.OpenFile("/big")
	buf := make([]byte, 4096)
	f.ReadAt(buf, 0)
	c1 := fs.dc.Load()
	if c1 == nil || c1.Len() == 0 {
		t.Fatal("nothing cached")
	}
	if err := fs.WriteFile("/other", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.ReadAt(buf, 0)
	if c2 := fs.dc.Load(); c2 == c1 {
		t.Error("the record cache survived a write to the pool")
	}
}

func TestMaxDataCacheIsHonoured(t *testing.T) {
	ifs, want := bigZFS(t, 4<<20)
	fs := ifs.(*zfsFS)
	fs.SetMaxDataCache(1) // below the 8 MiB start: the start
	f, _ := fs.OpenFile("/big")
	buf := make([]byte, 128<<10)
	for off := int64(0); off < 4<<20; off += int64(len(buf)) {
		if _, err := f.ReadAt(buf, off); err != nil || !bytes.Equal(buf, want[off:off+int64(len(buf))]) {
			t.Fatal(err)
		}
	}
	if c := fs.dc.Load().Cap(); c != startDataCacheBytes {
		t.Errorf("Cap = %d, want %d", c, startDataCacheBytes)
	}
}

// A damaged record is refused wherever it falls in a parallel window, the
// records before it are still returned in order, and a damaged record that is
// only READ AHEAD does not fail the read that triggered the read-ahead.
func TestDamagedRecordInAParallelWindow(t *testing.T) {
	const size, victim = 4 << 20, 20 // 32 records; the 21st is damaged
	img := filepath.Join(t.TempDir(), "pool.img")
	ifs, err := Format(img, size*2+64<<20, FormatConfig{PoolName: "parck"})
	if err != nil {
		t.Fatal(err)
	}
	want := offsetPattern(size)
	if err := ifs.WriteFile("/big", want, 0o644); err != nil {
		t.Fatal(err)
	}
	fs := ifs.(*zfsFS)
	obj, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, "/big")
	if err != nil {
		t.Fatal(err)
	}
	dn, err := fs.zplDS.zplOS.readObject(obj)
	if err != nil {
		t.Fatal(err)
	}
	bp, err := recordBP(fs.f, fs.partOffset, dn, victim, nil)
	if err != nil {
		t.Fatal(err)
	}
	off := fs.partOffset + bp.dvaOffset(0)
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
	flipByteAt(t, img, off+5)

	for _, w := range []int{1, 4, 8} {
		bad, err := Open(img, -1)
		if err != nil {
			t.Fatal(err)
		}
		p := asPar(t, bad)
		p.SetReadParallelism(w)
		if got, err := p.ReadFile("/big"); !errors.Is(err, ErrChecksum) || len(got) != 0 {
			t.Fatalf("workers %d: ReadFile of a damaged record: %d bytes, %v", w, len(got), err)
		}
		f, err := p.OpenFile("/big")
		if err != nil {
			t.Fatal(err)
		}
		// Sequential reads up to the record before the victim succeed, with the
		// read-ahead running into the victim (workers 4, 8: window 8, 16 records).
		chunk := make([]byte, 128<<10)
		for k := 0; k < victim; k++ {
			if _, err := f.ReadAt(chunk, int64(k)*(128<<10)); err != nil || !bytes.Equal(chunk, want[k*(128<<10):(k+1)*(128<<10)]) {
				t.Fatalf("workers %d: record %d before the damage: %v", w, k, err)
			}
		}
		if _, err := f.ReadAt(chunk, victim*(128<<10)); !errors.Is(err, ErrChecksum) {
			t.Fatalf("workers %d: the damaged record: err = %v, want ErrChecksum", w, err)
		}
		// A single read spanning the records before and the damaged one fails as a whole.
		span := make([]byte, 6*(128<<10))
		if _, err := f.ReadAt(span, (victim-3)*(128<<10)); !errors.Is(err, ErrChecksum) {
			t.Fatalf("workers %d: a read spanning the damage: err = %v", w, err)
		}
		bad.Close()
	}
}

// Every record keeps the kernel's fall-back to its other copies inside the
// parallel decode, and the first error in file order is the one reported.
func TestDecodeRecordsFallsBackAndReportsInOrder(t *testing.T) {
	const n, rec = 16, 512
	goods := make([][]byte, n)
	img := make([]byte, n*3*rec)
	jobs := make([]recordJob, n)
	for i := range goods {
		goods[i] = bytes.Repeat([]byte{byte('a' + i)}, rec)
		goods[i][3] = byte(i)
		bad := append([]byte(nil), goods[i]...)
		bad[7] ^= 1
		base := i * 3 * rec
		copy(img[base:], bad)          // DVA 0 damaged
		copy(img[base+rec:], goods[i]) // DVA 1 intact
		bp := makeBlkptrCksum(int64(base), rec, rec, zcompressOff, dmotPlainFileContents, 0, 1, zioChecksumFletch4)
		bp.dva[1] = makeDVA(int64(base+rec), rec)
		setBPChecksum(&bp, goods[i])
		jobs[i] = recordJob{uint64(i), bp}
	}
	r := checkedReader{bytes.NewReader(img)}
	for _, w := range []int{1, 2, 4, 8} {
		var order []int
		err := decodeRecords(r, 0, jobs, rec, w, n, func(k int, data []byte) error {
			order = append(order, k)
			if !bytes.Equal(data, goods[k]) {
				t.Errorf("workers %d: record %d decoded to the damaged copy", w, k)
			}
			return nil
		})
		if err != nil || len(order) != n {
			t.Fatalf("workers %d: %v, %d records", w, err, len(order))
		}
		for k, v := range order {
			if k != v {
				t.Fatalf("workers %d: emitted out of order: %v", w, order)
			}
		}
	}
	// Records 5 and 9 lose their second copy too: record 5 is the error, and
	// records 0..4 are emitted before it.
	for _, k := range []int{5, 9} {
		bad := append([]byte(nil), goods[k]...)
		bad[7] ^= 1
		copy(img[k*3*rec+rec:], bad)
	}
	for _, w := range []int{1, 4, 8} {
		var order []int
		err := decodeRecords(r, 0, jobs, rec, w, n, func(k int, _ []byte) error {
			order = append(order, k)
			return nil
		})
		if !errors.Is(err, ErrChecksum) || len(order) != 5 {
			t.Fatalf("workers %d: err %v, emitted %v; want ErrChecksum after records 0-4", w, err, order)
		}
	}
	// With the damaged records only soft (read-ahead), nothing fails.
	for _, w := range []int{1, 4} {
		emitted, nils := 0, 0
		err := decodeRecords(r, 0, jobs, rec, w, 5, func(k int, data []byte) error {
			emitted++
			if data == nil {
				nils++
			}
			return nil
		})
		if err != nil || emitted != n || nils != 2 {
			t.Fatalf("workers %d soft: err %v, %d emitted, %d nil", w, err, emitted, nils)
		}
	}
}

// Concurrent readers of one pool, parallel decode inside each: -race's case.
func TestConcurrentParallelReaders(t *testing.T) {
	ifs, want := bigZFS(t, 3<<20)
	fs := asPar(t, ifs)
	fs.SetReadParallelism(4)
	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := fs.OpenFile("/big")
			if err != nil {
				t.Error(err)
				return
			}
			r := rand.New(rand.NewPCG(uint64(g), 1))
			buf := make([]byte, 300<<10)
			for range 20 {
				off := int64(r.IntN(len(want) - len(buf)))
				if n, err := f.ReadAt(buf, off); err != nil || !bytes.Equal(buf[:n], want[off:off+int64(n)]) {
					t.Errorf("reader %d at %d: %v", g, off, err)
					return
				}
			}
			if got, err := fs.ReadFile("/big"); err != nil || !bytes.Equal(got, want) {
				t.Errorf("reader %d: ReadFile: %v", g, err)
			}
		}()
	}
	wg.Wait()
}

// BenchmarkRandomRead4KWarm is the warm random 4 KiB read of the judge's table:
// every record is cached after the first pass.
func BenchmarkRandomRead4KWarm(b *testing.B) {
	const size = 32 << 20
	ifs, _ := bigZFS(b, size)
	f, err := ifs.(filesystem.Opener).OpenFile("/big")
	if err != nil {
		b.Fatal(err)
	}
	r := rand.New(rand.NewPCG(9, 9))
	offs := make([]int64, 4096)
	for i := range offs {
		offs[i] = int64(r.IntN(size/4096)) * 4096
	}
	buf := make([]byte, 4096)
	for _, o := range offs {
		f.ReadAt(buf, o)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := f.ReadAt(buf, offs[i%len(offs)]); err != nil {
			b.Fatal(err)
		}
	}
}

// SetMaxDataCache(0) means the default, before and after the cache is rebuilt by a write.
func TestSetMaxDataCacheZeroIsTheDefault(t *testing.T) {
	ifs, _ := bigZFS(t, 1<<20)
	fs := ifs.(*zfsFS)
	f, _ := fs.OpenFile("/big")
	buf := make([]byte, 4096)
	f.ReadAt(buf, 0)
	fs.SetMaxDataCache(0)
	if err := fs.WriteFile("/w", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.ReadAt(buf, 0) // rebuilds the cache under the setting
	if got := fs.dcMax.Load(); got != DefaultMaxDataCacheBytes {
		t.Errorf("dcMax = %d, want the default %d", got, DefaultMaxDataCacheBytes)
	}
	if c := fs.dc.Load(); c == nil || c.Len() == 0 {
		t.Fatal("the rebuilt cache holds nothing")
	}
}
