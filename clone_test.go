package filesystem_zfs

import (
	"errors"
	"strings"
	"testing"
)

// TestClone_BasicReadRoundTrip is the headline verification: snapshot a
// dataset, mutate the live dataset, clone the snapshot, then confirm the clone
// — reopened through the driver's OWN reader — reflects the snapshot-time
// content (not the later live mutations), while the live dataset keeps them.
func TestClone_BasicReadRoundTrip(t *testing.T) {
	const size = 48 * 1024 * 1024
	path, ifs := formatPool(t, size)

	if err := ifs.WriteFile("/hello", []byte("snapshot-time"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ifs.WriteFile("/keep", []byte("kept"), 0o644); err != nil {
		t.Fatalf("WriteFile keep: %v", err)
	}
	if err := ifs.Snapshot("s1"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	// Mutate the live dataset AFTER the snapshot.
	if err := ifs.WriteFile("/hello", []byte("LIVE-CHANGED"), 0o644); err != nil {
		t.Fatalf("WriteFile overwrite: %v", err)
	}
	if err := ifs.DeleteFile("/keep"); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}
	// Clone the snapshot into a new writable dataset.
	if err := ifs.Clone("s1", "myclone"); err != nil {
		t.Fatalf("Clone: %v", err)
	}
	ifs.Close()

	// Reopen the CLONE through the driver's own reader.
	clone, err := OpenDataset(path, -1, "myclone")
	if err != nil {
		t.Fatalf("OpenDataset(myclone): %v", err)
	}
	defer clone.Close()
	if got, err := clone.ReadFile("/hello"); err != nil || string(got) != "snapshot-time" {
		t.Fatalf("clone /hello = %q, err=%v; want %q", got, err, "snapshot-time")
	}
	if got, err := clone.ReadFile("/keep"); err != nil || string(got) != "kept" {
		t.Fatalf("clone /keep = %q, err=%v; want %q (clone must see the snapshot's copy)", got, err, "kept")
	}

	// The live pool root keeps its post-snapshot mutations.
	live, err := Open(path, -1)
	if err != nil {
		t.Fatalf("reopen live: %v", err)
	}
	defer live.Close()
	if got, err := live.ReadFile("/hello"); err != nil || string(got) != "LIVE-CHANGED" {
		t.Fatalf("live /hello = %q, err=%v; want LIVE-CHANGED", got, err)
	}
	if _, err := live.ReadFile("/keep"); err == nil {
		t.Fatal("live /keep still present after delete")
	}
}

// TestClone_Writable confirms a clone is INDEPENDENTLY writable: writing to the
// clone leaves both the origin snapshot and the live root dataset untouched,
// and the clone's own writes survive a Close+reopen (exercising the write-path
// recommitChain for a dataset that lives in an upper MOS array block).
func TestClone_Writable(t *testing.T) {
	const size = 64 * 1024 * 1024
	path, ifs := formatPool(t, size)

	if err := ifs.WriteFile("/base", []byte("base-v1"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ifs.Snapshot("s"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := ifs.Clone("s", "c"); err != nil {
		t.Fatalf("Clone: %v", err)
	}
	ifs.Close()

	// Write to the clone through a fresh handle.
	clone, err := OpenDataset(path, -1, "c")
	if err != nil {
		t.Fatalf("OpenDataset(c): %v", err)
	}
	if err := clone.WriteFile("/base", []byte("clone-modified"), 0o644); err != nil {
		t.Fatalf("clone WriteFile overwrite: %v", err)
	}
	if err := clone.WriteFile("/clone-only", []byte("only-in-clone"), 0o644); err != nil {
		t.Fatalf("clone WriteFile new: %v", err)
	}
	clone.Close()

	// Reopen the clone: its writes persisted.
	clone2, err := OpenDataset(path, -1, "c")
	if err != nil {
		t.Fatalf("reopen clone: %v", err)
	}
	defer clone2.Close()
	if got, err := clone2.ReadFile("/base"); err != nil || string(got) != "clone-modified" {
		t.Fatalf("clone /base = %q, err=%v; want clone-modified", got, err)
	}
	if got, err := clone2.ReadFile("/clone-only"); err != nil || string(got) != "only-in-clone" {
		t.Fatalf("clone /clone-only = %q, err=%v", got, err)
	}

	// The origin snapshot is untouched by the clone's writes.
	snap, err := OpenSnapshot(path, -1, "", "s")
	if err != nil {
		t.Fatalf("OpenSnapshot: %v", err)
	}
	defer snap.Close()
	if got, err := snap.ReadFile("/base"); err != nil || string(got) != "base-v1" {
		t.Fatalf("snapshot /base = %q, err=%v; want base-v1 (clone write leaked into snapshot)", got, err)
	}
	if _, err := snap.ReadFile("/clone-only"); err == nil {
		t.Fatal("snapshot sees /clone-only written only to the clone")
	}

	// The live root dataset is likewise untouched.
	live, err := Open(path, -1)
	if err != nil {
		t.Fatalf("reopen live: %v", err)
	}
	defer live.Close()
	if got, err := live.ReadFile("/base"); err != nil || string(got) != "base-v1" {
		t.Fatalf("live /base = %q, err=%v; want base-v1", got, err)
	}
	if _, err := live.ReadFile("/clone-only"); err == nil {
		t.Fatal("live root sees /clone-only written only to the clone")
	}
}

// TestClone_OriginProperty confirms `Origin()` reports "<pool>@<snap>" for a
// clone and "" for a non-clone (the pool root).
func TestClone_OriginProperty(t *testing.T) {
	const size = 48 * 1024 * 1024
	path, ifs := formatPool(t, size)

	if err := ifs.WriteFile("/f", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ifs.Snapshot("origin"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := ifs.Clone("origin", "child"); err != nil {
		t.Fatalf("Clone: %v", err)
	}
	// The root dataset is not a clone.
	if got, err := ifs.Origin(); err != nil || got != "" {
		t.Fatalf("root Origin() = %q, err=%v; want empty", got, err)
	}
	ifs.Close()

	clone, err := OpenDataset(path, -1, "child")
	if err != nil {
		t.Fatalf("OpenDataset(child): %v", err)
	}
	defer clone.Close()
	got, err := clone.Origin()
	if err != nil {
		t.Fatalf("clone Origin(): %v", err)
	}
	// formatPool names the pool "snaptest".
	if got != "snaptest@origin" {
		t.Fatalf("clone Origin() = %q; want %q", got, "snaptest@origin")
	}
}

// TestClone_DependentCloneBlocksDestroy confirms a snapshot that has a clone
// cannot be destroyed, and that destroying an unrelated (clone-free) snapshot
// still works.
func TestClone_DependentCloneBlocksDestroy(t *testing.T) {
	const size = 64 * 1024 * 1024
	path, ifs := formatPool(t, size)
	defer ifs.Close()

	if err := ifs.WriteFile("/f", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ifs.Snapshot("hasclone"); err != nil {
		t.Fatalf("Snapshot hasclone: %v", err)
	}
	if err := ifs.Snapshot("lonely"); err != nil {
		t.Fatalf("Snapshot lonely: %v", err)
	}
	if err := ifs.Clone("hasclone", "c"); err != nil {
		t.Fatalf("Clone: %v", err)
	}

	// The snapshot with a clone cannot be destroyed.
	err := ifs.DestroySnapshot("hasclone")
	if err == nil {
		t.Fatal("DestroySnapshot(hasclone) succeeded; want failure (dependent clone)")
	}
	if !errors.Is(err, errHasClones) {
		t.Fatalf("DestroySnapshot(hasclone) err = %v; want errHasClones", err)
	}
	// It is still resolvable after the refused destroy.
	if _, err := OpenSnapshot(path, -1, "", "hasclone"); err != nil {
		t.Fatalf("hasclone gone after refused destroy: %v", err)
	}

	// A clone-free snapshot destroys cleanly and is no longer resolvable.
	if err := ifs.DestroySnapshot("lonely"); err != nil {
		t.Fatalf("DestroySnapshot(lonely): %v", err)
	}
	if _, err := OpenSnapshot(path, -1, "", "lonely"); err == nil {
		t.Fatal("lonely still resolvable after destroy")
	}
	// The clone and the live root are unaffected by the destroy.
	if _, err := OpenDataset(path, -1, "c"); err != nil {
		t.Fatalf("clone unreadable after destroying lonely: %v", err)
	}
	if got, err := ifs.ReadFile("/f"); err != nil || string(got) != "x" {
		t.Fatalf("live /f = %q, err=%v after destroy", got, err)
	}
}

// TestClone_MultipleClonesOneSnapshot confirms a second clone of the same
// snapshot reuses the origin's existing ds_next_clones_obj ZAP (rather than
// creating a new one) and that both clones are independently reachable.
func TestClone_MultipleClonesOneSnapshot(t *testing.T) {
	const size = 96 * 1024 * 1024
	path, ifs := formatPool(t, size)

	if err := ifs.WriteFile("/f", []byte("shared"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ifs.Snapshot("s"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := ifs.Clone("s", "c1"); err != nil {
		t.Fatalf("Clone c1: %v", err)
	}
	if err := ifs.Clone("s", "c2"); err != nil {
		t.Fatalf("Clone c2: %v", err)
	}
	// The snapshot now has TWO dependent clones and still cannot be destroyed.
	if err := ifs.DestroySnapshot("s"); !errors.Is(err, errHasClones) {
		t.Fatalf("DestroySnapshot(s) with 2 clones err = %v; want errHasClones", err)
	}
	ifs.Close()

	for _, name := range []string{"c1", "c2"} {
		c, err := OpenDataset(path, -1, name)
		if err != nil {
			t.Fatalf("OpenDataset(%s): %v", name, err)
		}
		if got, err := c.ReadFile("/f"); err != nil || string(got) != "shared" {
			t.Errorf("%s /f = %q, err=%v; want shared", name, got, err)
		}
		origin, err := c.Origin()
		if err != nil || origin != "snaptest@s" {
			t.Errorf("%s Origin() = %q, err=%v; want snaptest@s", name, origin, err)
		}
		c.Close()
	}
}

// TestClone_DestroyMiddleOfChain destroys the OLDEST snapshot in a three-deep
// chain, exercising the prev-snap relink (repointPrevSnap rewrites the next
// snapshot's ds_prev_snap_obj) while the head's prev pointer is left untouched.
func TestClone_DestroyMiddleOfChain(t *testing.T) {
	const size = 96 * 1024 * 1024
	path, ifs := formatPool(t, size)
	defer ifs.Close()

	if err := ifs.WriteFile("/f", []byte("v1"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ifs.Snapshot("s1"); err != nil {
		t.Fatalf("Snapshot s1: %v", err)
	}
	if err := ifs.WriteFile("/f", []byte("v2"), 0o644); err != nil {
		t.Fatalf("WriteFile v2: %v", err)
	}
	if err := ifs.Snapshot("s2"); err != nil {
		t.Fatalf("Snapshot s2: %v", err)
	}
	if err := ifs.WriteFile("/f", []byte("v3"), 0o644); err != nil {
		t.Fatalf("WriteFile v3: %v", err)
	}
	if err := ifs.Snapshot("s3"); err != nil {
		t.Fatalf("Snapshot s3: %v", err)
	}

	// Destroy the oldest snapshot; the two newer ones stay intact.
	if err := ifs.DestroySnapshot("s1"); err != nil {
		t.Fatalf("DestroySnapshot(s1): %v", err)
	}
	if _, err := OpenSnapshot(path, -1, "", "s1"); err == nil {
		t.Fatal("s1 still resolvable after destroy")
	}
	for _, tc := range []struct{ snap, want string }{{"s2", "v2"}, {"s3", "v3"}} {
		s, err := OpenSnapshot(path, -1, "", tc.snap)
		if err != nil {
			t.Fatalf("OpenSnapshot(%s) after middle destroy: %v", tc.snap, err)
		}
		if got, err := s.ReadFile("/f"); err != nil || string(got) != tc.want {
			t.Errorf("%s /f = %q, err=%v; want %q", tc.snap, got, err, tc.want)
		}
		s.Close()
	}
}

// TestClone_InvalidArgs covers the argument-validation and not-found branches.
func TestClone_InvalidArgs(t *testing.T) {
	const size = 32 * 1024 * 1024
	path, ifs := formatPool(t, size)
	defer ifs.Close()

	if err := ifs.WriteFile("/f", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ifs.Snapshot("s"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	for _, tc := range []struct{ snap, clone string }{
		{"", "c"},         // empty snap
		{"a@b", "c"},      // snap with '@'
		{"a/b", "c"},      // snap with '/'
		{"s", ""},         // empty clone
		{"s", "a@b"},      // clone with '@'
		{"s", "a/b"},      // clone with '/'
		{"s", "$special"}, // clone with reserved '$' prefix
	} {
		if err := ifs.Clone(tc.snap, tc.clone); err == nil {
			t.Errorf("Clone(%q,%q) = nil, want error", tc.snap, tc.clone)
		}
	}

	// Snapshot that does not exist.
	if err := ifs.Clone("nope", "c"); err == nil {
		t.Error("Clone of nonexistent snapshot succeeded")
	}

	// Duplicate clone name.
	if err := ifs.Clone("s", "dup"); err != nil {
		t.Fatalf("Clone dup #1: %v", err)
	}
	if err := ifs.Clone("s", "dup"); err == nil {
		t.Error("second Clone with same name succeeded")
	}

	// DestroySnapshot argument validation + not-found.
	for _, bad := range []string{"", "a@b", "a/b"} {
		if err := ifs.DestroySnapshot(bad); err == nil {
			t.Errorf("DestroySnapshot(%q) = nil, want error", bad)
		}
	}
	if err := ifs.DestroySnapshot("nope"); err == nil {
		t.Error("DestroySnapshot of nonexistent snapshot succeeded")
	}
	_ = path
}

// TestClone_ReadOnlyAndClosedPools covers the guard branches on pools that are
// not writable or not fully opened.
func TestClone_ReadOnlyAndClosedPools(t *testing.T) {
	// A pool opened read-only (no allocator) rejects Clone/DestroySnapshot.
	// Construct a bare zfsFS with nil zplDS to hit the "not fully opened"
	// branch, and one with zplDS but nil alloc for the "no allocator" branch.
	bare := &zfsFS{}
	if err := bare.Clone("s", "c"); err == nil {
		t.Error("Clone on unopened pool succeeded")
	}
	if _, err := bare.Origin(); err == nil {
		t.Error("Origin on unopened pool succeeded")
	}
	if err := bare.DestroySnapshot("s"); err == nil {
		t.Error("DestroySnapshot on unopened pool succeeded")
	}

	noAlloc := &zfsFS{fsFields: fsFields{zplDS: &zplDataset{}}}
	if err := noAlloc.Clone("s", "c"); err == nil || !strings.Contains(err.Error(), "allocator") {
		t.Errorf("Clone on read-only pool err = %v; want allocator error", err)
	}
	if err := noAlloc.DestroySnapshot("s"); err == nil || !strings.Contains(err.Error(), "allocator") {
		t.Errorf("DestroySnapshot on read-only pool err = %v; want allocator error", err)
	}
}
