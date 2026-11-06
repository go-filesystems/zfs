package filesystem_zfs

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

func offsetPattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>12)
	}
	return b
}

func bigZFS(t testing.TB, fileSize int) (filesystem.Filesystem, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "big.img")
	fs, err := Format(path, int64(fileSize)*2+64<<20, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	data := offsetPattern(fileSize)
	if err := fs.WriteFile("/big", data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.WriteFile("/small", []byte("hello world"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Cleanup(func() { fs.Close() })
	return fs, data
}

// A READ at an offset past 64 MiB must not need the file whole.
func TestOpenFileReadsARangePast64MiB(t *testing.T) {
	const fileSize = 72 << 20
	fs, want := bigZFS(t, fileSize)
	o, ok := fs.(filesystem.Opener)
	if !ok {
		t.Fatal("the driver is not a filesystem.Opener")
	}
	f, err := o.OpenFile("/big")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Size() != fileSize {
		t.Fatalf("Size = %d", f.Size())
	}
	for _, off := range []int64{0, 4095, 64 << 20, 66<<20 + 123, fileSize - 10} {
		buf := make([]byte, 4096)
		n, err := f.ReadAt(buf, off)
		wantN := min(int64(len(buf)), fileSize-off)
		if int64(n) != wantN || (n < len(buf)) != errors.Is(err, io.EOF) || (n == len(buf) && err != nil) {
			t.Fatalf("ReadAt(%d) = %d, %v; want %d", off, n, err, wantN)
		}
		if !bytes.Equal(buf[:n], want[off:off+int64(n)]) {
			t.Fatalf("ReadAt(%d): wrong bytes", off)
		}
	}
	span := make([]byte, 3<<20)
	if n, err := f.ReadAt(span, 10<<20+17); n != len(span) || err != nil || !bytes.Equal(span, want[10<<20+17:10<<20+17+len(span)]) {
		t.Fatalf("a spanning read = %d, %v", n, err)
	}
	if n, err := f.ReadAt(make([]byte, 8), fileSize); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("ReadAt at the end = %d, %v", n, err)
	}
	if _, err := f.ReadAt(make([]byte, 8), -1); err == nil {
		t.Error("a negative offset was read")
	}
	if err := f.Close(); err != nil {
		t.Error(err)
	}
}

func TestOpenFileSmallEmptyAndRefusals(t *testing.T) {
	fs, _ := bigZFS(t, 1<<20)
	o := fs.(filesystem.Opener)
	f, err := o.OpenFile("/small")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if n, err := f.ReadAt(buf, 6); n != 5 || err != nil || string(buf) != "world" {
		t.Errorf("small ReadAt = %d %v %q", n, err, buf)
	}
	if n, err := f.ReadAt(make([]byte, 20), 0); n != 11 || !errors.Is(err, io.EOF) {
		t.Errorf("small ReadAt past the end = %d %v", n, err)
	}
	if err := fs.WriteFile("/empty", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	e, err := o.OpenFile("/empty")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := e.ReadAt(make([]byte, 4), 0); n != 0 || !errors.Is(err, io.EOF) || e.Size() != 0 {
		t.Errorf("an empty file: %d %v size %d", n, err, e.Size())
	}
	if _, err := o.OpenFile("/nope"); err == nil {
		t.Error("a missing file was opened")
	}
	if _, err := o.OpenFile("/"); err == nil {
		t.Error("a directory was opened")
	}
}

// BenchmarkReadRangeOfBigFile: a 1 MiB read at 66 MiB of a 72 MiB file, through
// OpenFile/ReadAt and through ReadFile. Allocations are exact; times are not
// under load.
func BenchmarkReadRangeOfBigFile(b *testing.B) {
	fs, _ := bigZFS(b, 72<<20)
	b.Run("OpenFile-ReadAt", func(b *testing.B) {
		f, err := fs.(filesystem.Opener).OpenFile("/big")
		if err != nil {
			b.Fatal(err)
		}
		buf := make([]byte, 1<<20)
		b.SetBytes(int64(len(buf)))
		b.ReportAllocs()
		for b.Loop() {
			if _, err := f.ReadAt(buf, 66<<20); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("ReadFile-whole", func(b *testing.B) {
		b.SetBytes(1 << 20)
		b.ReportAllocs()
		for b.Loop() {
			data, err := fs.ReadFile("/big")
			if err != nil {
				b.Fatal(err)
			}
			_ = data[66<<20 : 67<<20]
		}
	})
}
