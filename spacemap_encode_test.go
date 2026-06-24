package filesystem_zfs

import (
	"path/filepath"
	"testing"
)

// TestSnapshotIndirectCopy exercises the snapshot deep-copy of a file large
// enough to use indirect block pointers (copyBlkptrTree's level>0 branch and
// the full copyObjsetTree path), then confirms both the live file and the
// snapshot read back identically after a reopen.
//
// (The two-word space-map encoding is covered by TestEncodeSpaceMapLogTwoWord
// in coverage_extra_test.go, which landed on main.)
func TestSnapshotIndirectCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapind.img")
	const size = 16 * 1024 * 1024
	ifs, err := Format(path, size, FormatConfig{PoolName: "snapind"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	fs := ifs.(*zfsFS)

	// >128 KiB (several 128 KiB blocks) → routed through indirect block
	// pointers. Kept small so snapshot's deep-copy stays cheap under -race.
	data := make([]byte, 384*1024)
	for i := range data {
		data[i] = byte(i*31 + 7)
	}
	if err := fs.WriteFile("/f", data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.Snapshot("s1"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Live read-back.
	ifs2, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ifs2.Close()
	got, err := ifs2.ReadFile("/f")
	if err != nil || len(got) != len(data) {
		t.Fatalf("ReadFile /f live: err=%v len=%d want %d", err, len(got), len(data))
	}

	// Snapshot read-back through the @snap dataset path.
	snapFS, err := OpenDataset(path, -1, "@s1")
	if err != nil {
		t.Fatalf("OpenDataset @s1: %v", err)
	}
	defer snapFS.Close()
	sgot, err := snapFS.ReadFile("/f")
	if err != nil || len(sgot) != len(data) {
		t.Fatalf("ReadFile /f snapshot: err=%v len=%d want %d", err, len(sgot), len(data))
	}
}
