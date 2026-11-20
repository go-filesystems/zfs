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
