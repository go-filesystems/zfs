package filesystem_zfs

import (
	"bytes"
	"errors"
	"testing"
)

// readBlockInto reads a stored block into the caller's buffer, verifies it like
// readBlock, and declines (reading nothing) a block it cannot read as it is.
func TestReadBlockInto(t *testing.T) {
	buf := make([]byte, 512)
	copy(buf, "hello, zfs")
	mk := func(comp uint8, psize, lsize int) blkptr {
		bp := makeBlkptrCksum(0, psize, lsize, comp, dmotPlainFileContents, 0, 1, zioChecksumFletch4)
		setBPChecksum(&bp, buf[:psize])
		return bp
	}
	rd := checkedReader{bytes.NewReader(buf)}

	dst := make([]byte, 512)
	if ok, err := readBlockInto(rd, 0, mk(zcompressOff, 512, 512), dst); !ok || err != nil || !bytes.Equal(dst, buf) {
		t.Fatalf("stored block: ok=%v err=%v equal=%v", ok, err, bytes.Equal(dst, buf))
	}

	bad := mk(zcompressOff, 512, 512)
	bad.cksum[0] ^= 1
	if ok, err := readBlockInto(rd, 0, bad, make([]byte, 512)); !ok || !errors.Is(err, ErrChecksum) {
		t.Fatalf("damaged block: ok=%v err=%v, want ErrChecksum", ok, err)
	}

	for name, c := range map[string]struct {
		bp  blkptr
		dst int
	}{
		"compressed":   {mk(zcompressLZ4, 256, 512), 512},
		"wrong buffer": {mk(zcompressOff, 512, 512), 100},
		"null":         {blkptr{}, 512},
	} {
		d := make([]byte, c.dst)
		if ok, err := readBlockInto(rd, 0, c.bp, d); ok || err != nil || !bytes.Equal(d, make([]byte, c.dst)) {
			t.Errorf("%s: ok=%v err=%v, want a decline that read nothing", name, ok, err)
		}
	}
}

// A read of whole records of a stored file goes straight into the caller's
// buffer: it caches nothing, and it still returns the file's bytes.
func TestWholeRecordReadsBypassTheCache(t *testing.T) {
	ifs, want := bigZFS(t, 4<<20)
	fs := ifs.(*zfsFS)
	fs.SetReadParallelism(4)
	f, _ := fs.OpenFile("/big")
	got := make([]byte, 1<<20)
	for off := int64(0); off < 4<<20; off += 1 << 20 {
		if n, err := f.ReadAt(got, off); err != nil || n != len(got) || !bytes.Equal(got, want[off:off+int64(n)]) {
			t.Fatalf("at %d: n=%d err=%v", off, n, err)
		}
	}
	if n := fs.dc.Load().Len(); n != 0 {
		t.Errorf("whole-record reads cached %d records, want 0", n)
	}
}

// A primary copy that fails its checksum falls back to the ditto copy on the
// readBlockInto path, at 1, 4 and 8 workers; with every copy damaged the
// buffer is left zero, not holding the last bad copy.
func TestReadBlockIntoDittoFallback(t *testing.T) {
	const rec = 512
	good := make([]byte, rec)
	copy(good, "good copy of the record")
	bad := bytes.Repeat([]byte{0xAA}, rec)
	mk := func(img []byte) blkptr {
		bp := makeBlkptrCksum(0, rec, rec, zcompressOff, dmotPlainFileContents, 0, 1, zioChecksumFletch4)
		setBPChecksum(&bp, good)
		bp.dva[1] = makeDVA(rec, rec)
		return bp
	}
	for _, w := range []int{1, 4, 8} {
		for _, c := range []struct {
			name       string
			img        []byte
			wantErr    bool
			wantRecord []byte
		}{
			{"primary bad, ditto good", append(append([]byte(nil), bad...), good...), false, good},
			{"primary good", append(append([]byte(nil), good...), bad...), false, good},
			{"both bad", append(append([]byte(nil), bad...), bad...), true, make([]byte, rec)},
		} {
			rd := checkedReader{bytes.NewReader(c.img)}
			jobs := make([]recordJob, 8)
			dst := make([]byte, 8*rec)
			for i := range jobs {
				jobs[i] = recordJob{blk: uint64(i), bp: mk(c.img), into: dst[i*rec : (i+1)*rec]}
			}
			err := decodeRecords(rd, 0, jobs, rec, w, len(jobs), func(int, []byte) error { return nil })
			if c.wantErr != (err != nil) || (c.wantErr && !errors.Is(err, ErrChecksum)) {
				t.Fatalf("workers %d, %s: err = %v", w, c.name, err)
			}
			if c.wantErr {
				for i := range jobs { // every record that failed is zero
					if !bytes.Equal(dst[i*rec:(i+1)*rec], c.wantRecord) {
						t.Fatalf("workers %d, %s: record %d unexpected", w, c.name, i)
					}
				}
				continue
			}
			for i := range jobs {
				if !bytes.Equal(dst[i*rec:(i+1)*rec], c.wantRecord) {
					t.Fatalf("workers %d, %s: record %d wrong", w, c.name, i)
				}
			}
		}
	}
	// The failed read zeroes its buffer (the serial path, record 0, is the first error).
	rd := checkedReader{bytes.NewReader(append(append([]byte(nil), bad...), bad...))}
	into := make([]byte, rec)
	if ok, err := readBlockInto(rd, 0, mk(nil), into); !ok || err == nil {
		t.Fatalf("both bad: ok=%v err=%v", ok, err)
	}
	if err := decodeRecords(rd, 0, []recordJob{{blk: 0, bp: mk(nil), into: into}}, rec, 1, 1, func(int, []byte) error { return nil }); err == nil {
		t.Fatal("both bad: no error")
	}
	if !bytes.Equal(into, make([]byte, rec)) {
		t.Fatal("a failed read left the last bad copy in the caller's buffer")
	}
}

// BenchmarkWarmWholeRecordReread: a 1 MiB ReadAt of a region read before (the
// pool's caches warm), the case the record cache serves and a direct read does
// not. 16 MiB file, uncompressed, GOMAXPROCS as set.
func BenchmarkWarmWholeRecordReread(b *testing.B) {
	ifs, _ := bigZFS(b, 16<<20)
	f, _ := ifs.(*zfsFS).OpenFile("/big")
	buf := make([]byte, 1<<20)
	for off := int64(0); off < 16<<20; off += 1 << 20 {
		f.ReadAt(buf, off)
	}
	b.SetBytes(16 << 20)
	b.ResetTimer()
	for b.Loop() {
		for off := int64(0); off < 16<<20; off += 1 << 20 {
			f.ReadAt(buf, off)
		}
	}
}
