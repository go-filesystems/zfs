package filesystem_zfs

import (
	"path/filepath"
	"testing"
)

// formatPool creates a fresh pool image and returns its path plus the opened FS.
func formatPool(t *testing.T, sizeBytes int64) (string, FS) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pool.img")
	ifs, err := Format(path, sizeBytes, FormatConfig{PoolName: "snaptest"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	return path, ifs
}

// TestSnapshot_BasicRoundTrip is the headline verification: write a file,
// snapshot, then mutate the live dataset, and confirm the snapshot — reopened
// through the driver's OWN reader — still sees the original content while the
// live dataset reflects the mutations. Finally reopen the pool root and
// confirm it still reads cleanly.
func TestSnapshot_BasicRoundTrip(t *testing.T) {
	const size = 32 * 1024 * 1024
	path, ifs := formatPool(t, size)

	if err := ifs.WriteFile("/hello", []byte("original-contents"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ifs.WriteFile("/keep", []byte("stays"), 0o644); err != nil {
		t.Fatalf("WriteFile keep: %v", err)
	}

	if err := ifs.Snapshot("snap1"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Mutate the live dataset AFTER the snapshot: overwrite, delete, add.
	if err := ifs.WriteFile("/hello", []byte("CHANGED-after-snapshot"), 0o644); err != nil {
		t.Fatalf("WriteFile overwrite: %v", err)
	}
	if err := ifs.DeleteFile("/keep"); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}
	if err := ifs.WriteFile("/added", []byte("new file"), 0o644); err != nil {
		t.Fatalf("WriteFile added: %v", err)
	}

	// The LIVE dataset reflects every mutation.
	if got, err := ifs.ReadFile("/hello"); err != nil || string(got) != "CHANGED-after-snapshot" {
		t.Fatalf("live /hello = %q, err=%v; want %q", got, err, "CHANGED-after-snapshot")
	}
	if _, err := ifs.ReadFile("/keep"); err == nil {
		t.Fatal("live /keep still readable after delete")
	}
	if got, err := ifs.ReadFile("/added"); err != nil || string(got) != "new file" {
		t.Fatalf("live /added = %q, err=%v", got, err)
	}
	ifs.Close()

	// Reopen the SNAPSHOT through the driver's own reader and confirm it is
	// frozen at snapshot time.
	snap, err := OpenSnapshot(path, -1, "", "snap1")
	if err != nil {
		t.Fatalf("OpenSnapshot: %v", err)
	}
	defer snap.Close()

	if got, err := snap.ReadFile("/hello"); err != nil || string(got) != "original-contents" {
		t.Fatalf("snapshot /hello = %q, err=%v; want %q", got, err, "original-contents")
	}
	if got, err := snap.ReadFile("/keep"); err != nil || string(got) != "stays" {
		t.Fatalf("snapshot /keep = %q, err=%v; want %q (snapshot must be unaffected by live delete)", got, err, "stays")
	}
	if _, err := snap.ReadFile("/added"); err == nil {
		t.Fatal("snapshot sees /added, which was created AFTER the snapshot")
	}

	// Reopen the live pool root and confirm it still reads cleanly and
	// reflects the post-snapshot state.
	live, err := Open(path, -1)
	if err != nil {
		t.Fatalf("reopen live pool: %v", err)
	}
	defer live.Close()
	if got, err := live.ReadFile("/hello"); err != nil || string(got) != "CHANGED-after-snapshot" {
		t.Fatalf("reopened live /hello = %q, err=%v", got, err)
	}
	if _, err := live.ReadFile("/keep"); err == nil {
		t.Fatal("reopened live /keep still present after delete")
	}
}

// TestSnapshot_ListDirIsolation confirms directory contents (ZAP) are frozen:
// entries added/removed after the snapshot are invisible to the snapshot.
func TestSnapshot_ListDirIsolation(t *testing.T) {
	const size = 32 * 1024 * 1024
	path, ifs := formatPool(t, size)

	for _, n := range []string{"a", "b", "c"} {
		if err := ifs.WriteFile("/"+n, []byte(n), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", n, err)
		}
	}
	if err := ifs.Snapshot("s"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := ifs.DeleteFile("/b"); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}
	if err := ifs.WriteFile("/d", []byte("d"), 0o644); err != nil {
		t.Fatalf("WriteFile d: %v", err)
	}
	ifs.Close()

	snap, err := OpenSnapshot(path, -1, "", "s")
	if err != nil {
		t.Fatalf("OpenSnapshot: %v", err)
	}
	defer snap.Close()
	entries, err := snap.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name()] = true
	}
	for _, want := range []string{"a", "b", "c"} {
		if !names[want] {
			t.Errorf("snapshot dir missing %q (have %v)", want, names)
		}
	}
	if names["d"] {
		t.Errorf("snapshot dir contains %q created after snapshot (have %v)", "d", names)
	}
}

// TestSnapshot_MultipleSnapshots confirms two snapshots of the same dataset
// coexist, each frozen at its own point in time, sharing one snapnames ZAP.
func TestSnapshot_MultipleSnapshots(t *testing.T) {
	const size = 48 * 1024 * 1024
	path, ifs := formatPool(t, size)

	if err := ifs.WriteFile("/f", []byte("v1"), 0o644); err != nil {
		t.Fatalf("WriteFile v1: %v", err)
	}
	if err := ifs.Snapshot("snapA"); err != nil {
		t.Fatalf("Snapshot A: %v", err)
	}
	if err := ifs.WriteFile("/f", []byte("v2"), 0o644); err != nil {
		t.Fatalf("WriteFile v2: %v", err)
	}
	if err := ifs.Snapshot("snapB"); err != nil {
		t.Fatalf("Snapshot B: %v", err)
	}
	if err := ifs.WriteFile("/f", []byte("v3"), 0o644); err != nil {
		t.Fatalf("WriteFile v3: %v", err)
	}
	ifs.Close()

	for _, tc := range []struct{ snap, want string }{
		{"snapA", "v1"},
		{"snapB", "v2"},
	} {
		s, err := OpenSnapshot(path, -1, "", tc.snap)
		if err != nil {
			t.Fatalf("OpenSnapshot %s: %v", tc.snap, err)
		}
		got, err := s.ReadFile("/f")
		if err != nil || string(got) != tc.want {
			t.Errorf("%s /f = %q, err=%v; want %q", tc.snap, got, err, tc.want)
		}
		s.Close()
	}

	live, err := Open(path, -1)
	if err != nil {
		t.Fatalf("reopen live: %v", err)
	}
	defer live.Close()
	if got, err := live.ReadFile("/f"); err != nil || string(got) != "v3" {
		t.Errorf("live /f = %q, err=%v; want v3", got, err)
	}
}

// TestSnapshot_DuplicateNameRejected confirms a second snapshot with the same
// name fails rather than silently corrupting the ZAP.
func TestSnapshot_DuplicateNameRejected(t *testing.T) {
	const size = 16 * 1024 * 1024
	_, ifs := formatPool(t, size)
	defer ifs.Close()

	if err := ifs.WriteFile("/x", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ifs.Snapshot("dup"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := ifs.Snapshot("dup"); err == nil {
		t.Fatal("expected error creating duplicate snapshot name")
	}
}

// TestSnapshot_InvalidName rejects empty and separator-containing names.
func TestSnapshot_InvalidName(t *testing.T) {
	const size = 16 * 1024 * 1024
	_, ifs := formatPool(t, size)
	defer ifs.Close()
	for _, bad := range []string{"", "a@b", "a/b"} {
		if err := ifs.Snapshot(bad); err == nil {
			t.Errorf("Snapshot(%q) = nil, want error", bad)
		}
	}
}

// TestSnapshot_WriteAfterReopenIsolation guards the allocator high-water
// regression: after Close+reopen the live allocator must resume ABOVE the
// snapshot's deep-copied region, so heavy post-reopen writes cannot clobber
// the frozen snapshot. (Without snapshotHighWater() folded into
// initAllocator the snapshot's snap-ZAP block gets overwritten and OpenSnapshot
// fails.)
func TestSnapshot_WriteAfterReopenIsolation(t *testing.T) {
	const size = 32 * 1024 * 1024
	path, ifs := formatPool(t, size)
	if err := ifs.WriteFile("/hello", []byte("ORIGINAL"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ifs.Snapshot("s1"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	ifs.Close()

	live, err := Open(path, -1)
	if err != nil {
		t.Fatalf("reopen live: %v", err)
	}
	for i := 0; i < 40; i++ {
		if err := live.WriteFile("/spam", make([]byte, 4096), 0o644); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	live.Close()

	snap, err := OpenSnapshot(path, -1, "", "s1")
	if err != nil {
		t.Fatalf("OpenSnapshot after post-reopen writes: %v", err)
	}
	defer snap.Close()
	if got, err := snap.ReadFile("/hello"); err != nil || string(got) != "ORIGINAL" {
		t.Fatalf("snapshot corrupted by post-reopen writes: got %q err %v", got, err)
	}
}

// TestSnapshot_LargeFileIndirect exercises the indirect-block copy path: a
// file big enough to need an indirect tree is snapshotted, then the live copy
// is overwritten, and the snapshot must still return the original bytes.
func TestSnapshot_LargeFileIndirect(t *testing.T) {
	const size = 64 * 1024 * 1024
	path, ifs := formatPool(t, size)

	orig := make([]byte, 600*1024) // > 128 KiB block size → multi-block + indirect
	for i := range orig {
		orig[i] = byte(i*7 + 3)
	}
	if err := ifs.WriteFile("/big", orig, 0o644); err != nil {
		t.Fatalf("WriteFile big: %v", err)
	}
	if err := ifs.Snapshot("bsnap"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := ifs.WriteFile("/big", []byte("tiny"), 0o644); err != nil {
		t.Fatalf("overwrite big: %v", err)
	}
	ifs.Close()

	s, err := OpenSnapshot(path, -1, "", "bsnap")
	if err != nil {
		t.Fatalf("OpenSnapshot: %v", err)
	}
	defer s.Close()
	got, err := s.ReadFile("/big")
	if err != nil {
		t.Fatalf("snapshot ReadFile big: %v", err)
	}
	if len(got) != len(orig) {
		t.Fatalf("snapshot /big len = %d, want %d", len(got), len(orig))
	}
	for i := range orig {
		if got[i] != orig[i] {
			t.Fatalf("snapshot /big mismatch at byte %d: got %d want %d", i, got[i], orig[i])
		}
	}
}
