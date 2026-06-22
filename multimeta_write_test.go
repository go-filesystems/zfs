package filesystem_zfs

import (
	"bytes"
	"path/filepath"
	"testing"
)

// TestMultiMetaslabWritePath exercises the multi-metaslab write path that the
// small single-metaslab unit tests don't reach: a 64 MiB pool has asize ≈ 48
// MiB = 3 × 16 MiB metaslabs, and a 34 MiB file spans all three. This drives
// the allocator's metaslab-boundary skip (a block must not straddle a
// boundary) and updateSpaceMap's per-metaslab extent distribution, then
// confirms the data round-trips after a reopen.
func TestMultiMetaslabWritePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mm.img")
	const size = 64 * 1024 * 1024
	ifs, err := Format(path, size, FormatConfig{PoolName: "mm"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	fs := ifs.(*zfsFS)
	if fs.msCount < 2 {
		t.Fatalf("expected ≥2 metaslabs for a 64 MiB pool, got %d", fs.msCount)
	}

	// 34 MiB of non-trivial data — larger than two 16 MiB metaslabs.
	data := make([]byte, 34*1024*1024)
	for i := range data {
		data[i] = byte(i*1103515245 + 12345)
	}
	if err := fs.WriteFile("/big", data, 0o644); err != nil {
		t.Fatalf("WriteFile /big (%d bytes): %v", len(data), err)
	}
	if err := fs.WriteFile("/small", []byte("hi"), 0o644); err != nil {
		t.Fatalf("WriteFile /small: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	ifs2, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ifs2.Close()
	got, err := ifs2.ReadFile("/big")
	if err != nil {
		t.Fatalf("ReadFile /big after reopen: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("ReadFile /big: content mismatch (got %d bytes, want %d)", len(got), len(data))
	}
}
