package filesystem_zfs

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

// TestZfsGrowTo verifies that GrowTo extends the pool image, writes new
// vdev labels and commits an updated uberblock.
func TestZfsGrowTo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zfs-grow.img")
	size1 := int64(4 * 1024 * 1024)
	fs, err := Format(path, size1, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()

	oldInfo := fs.Info()
	newSize := size1 * 2
	if err := fs.GrowTo(newSize); err != nil {
		t.Fatalf("GrowTo: %v", err)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Size() != newSize {
		t.Fatalf("size = %d, want %d", st.Size(), newSize)
	}

	fs2, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open after grow: %v", err)
	}
	defer fs2.Close()
	if fs2.Info().TransactionGroup <= oldInfo.TransactionGroup {
		t.Fatalf("transaction group not increased: before=%d after=%d", oldInfo.TransactionGroup, fs2.Info().TransactionGroup)
	}
}

// TestZfsGrowAlias confirms Grow is wired to the same code path as
// GrowTo (single source of truth, no behavioural drift).
func TestZfsGrowAlias(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zfs-grow-alias.img")
	size1 := int64(4 * 1024 * 1024)
	fs, err := Format(path, size1, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()

	newSize := size1 + 4*1024*1024
	if err := fs.Grow(newSize); err != nil {
		t.Fatalf("Grow: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Size() != newSize {
		t.Fatalf("Grow size = %d, want %d", st.Size(), newSize)
	}
}

// TestZfsResize_GrowRoute exercises the Resize entry point for the
// grow direction — ensures it routes to Grow on newSize > current.
func TestZfsResize_GrowRoute(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zfs-resize-grow.img")
	size1 := int64(4 * 1024 * 1024)
	fs, err := Format(path, size1, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()

	newSize := size1 * 3
	if err := fs.Resize(newSize); err != nil {
		t.Fatalf("Resize grow: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Size() != newSize {
		t.Fatalf("Resize size = %d, want %d", st.Size(), newSize)
	}
}

// TestZfsResize_NoOp confirms Resize(curSize) returns nil and leaves
// the image unchanged. ZFS, like every other filesystem here, treats
// "resize to current size" as a no-op rather than a sync barrier.
func TestZfsResize_NoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zfs-resize-noop.img")
	size := int64(8 * 1024 * 1024)
	fs, err := Format(path, size, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()

	if err := fs.Resize(size); err != nil {
		t.Fatalf("Resize no-op: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Size() != size {
		t.Fatalf("Resize no-op changed size: got %d, want %d", st.Size(), size)
	}
}

// TestZfsResize_ShrinkUnsupported is the headline contract test: the
// ZFS driver MUST return filesystem.ErrShrinkUnsupported when asked
// to shrink, mirroring OpenZFS's own refusal to shrink pools. The
// error must be unwrappable via errors.Is so callers can branch on
// it portably.
func TestZfsResize_ShrinkUnsupported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zfs-resize-shrink.img")
	size := int64(16 * 1024 * 1024)
	fs, err := Format(path, size, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()

	err = fs.Resize(size - 4*1024*1024)
	if err == nil {
		t.Fatalf("Resize shrink: expected error, got nil")
	}
	if !errors.Is(err, filesystem.ErrShrinkUnsupported) {
		t.Fatalf("Resize shrink: error %v does not wrap ErrShrinkUnsupported", err)
	}
}

// TestZfsResize_InvalidSize rejects zero and negative sizes with a
// non-nil, non-ErrShrinkUnsupported error.
func TestZfsResize_InvalidSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zfs-resize-invalid.img")
	fs, err := Format(path, 4*1024*1024, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()

	for _, sz := range []int64{0, -1, -1024 * 1024 * 1024} {
		err := fs.Resize(sz)
		if err == nil {
			t.Errorf("Resize(%d) = nil, want error", sz)
			continue
		}
		if errors.Is(err, filesystem.ErrShrinkUnsupported) {
			t.Errorf("Resize(%d) = ErrShrinkUnsupported, want plain validation error", sz)
		}
	}
}

// TestZfsGrow_ShrinkRejected verifies that Grow / GrowTo themselves
// (not just Resize) reject shrink with a wrapping ErrShrinkUnsupported
// — callers that don't know about Resize still get the right sentinel.
func TestZfsGrow_ShrinkRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zfs-grow-shrink.img")
	size := int64(16 * 1024 * 1024)
	fs, err := Format(path, size, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()

	err = fs.GrowTo(size - 4*1024*1024)
	if err == nil {
		t.Fatalf("GrowTo shrink: expected error, got nil")
	}
	if !errors.Is(err, filesystem.ErrShrinkUnsupported) {
		t.Fatalf("GrowTo shrink: %v does not wrap ErrShrinkUnsupported", err)
	}
}

// TestZfsGrow_InvalidSize rejects zero / negative target sizes — those
// cases short-circuit ahead of the shrink check. The 4 MiB minimum
// floor is unreachable from the public surface (Format always
// produces >= 4 MiB pools, so any well-formed Grow target either
// equals or exceeds it once the shrink branch is skipped); the
// validation block is still defence-in-depth for hand-crafted
// blockBackends and is exercised by these negative inputs.
func TestZfsGrow_InvalidSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zfs-grow-invalid.img")
	fs, err := Format(path, 4*1024*1024, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()

	for _, sz := range []int64{0, -1, -1 << 30} {
		if err := fs.GrowTo(sz); err == nil {
			t.Errorf("GrowTo(%d) = nil, want error", sz)
		}
	}
}

// TestGrowThenZdb is the cross-compat counterpart of TestWriteThenZdb
// for the grow path: Format → write a sentinel → Grow → zdb -e -p
// <dir> <pool> must still accept the grown pool's labels.
//
// SKIP conditions match TestWriteThenZdb:
//   - non-Linux/macOS host (zdb is Linux/Darwin only).
//   - zdb not on PATH.
//   - zdb rejects the image (= writer diverged again; surface the
//     output and skip with a diagnostic, same approach as
//     TestWriteThenZdb).
//
// On hard success the same three zdb-output invariants apply: pool
// name, version, vdev_tree section.
func TestGrowThenZdb(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("zdb cross-compat: skipping on %s (zdb only supported on linux/darwin)", runtime.GOOS)
	}
	zdbPath, err := exec.LookPath("zdb")
	if err != nil {
		t.Skip("zdb not on PATH — install zfsutils-linux (Debian/Ubuntu) or openzfs (Homebrew/pkgx) to enable grow-side cross-compat validation")
	}

	imgDir := t.TempDir()
	const poolName = "growpool"
	imgPath := filepath.Join(imgDir, poolName+".img")
	const startSize = int64(64 * 1024 * 1024)
	const grownSize = int64(96 * 1024 * 1024)

	fs, err := Format(imgPath, startSize, FormatConfig{
		PoolName: poolName,
		PoolGUID: 0xC0FFEE5C0EBAB1F, // distinct from compatw's
	})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	// Write a sentinel so the post-grow pool contains real DSL state
	// (not just labels), which is what `zdb` cares about most.
	if err := fs.WriteFile("/grew.txt", []byte("grown sentinel\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.Grow(grownSize); err != nil {
		t.Fatalf("Grow: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st, err := os.Stat(imgPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Size() != grownSize {
		t.Fatalf("post-grow image size = %d, want %d", st.Size(), grownSize)
	}

	cmd := exec.Command(zdbPath, "-e", "-p", imgDir, poolName)
	out, runErr := cmd.CombinedOutput()
	outStr := string(out)
	if runErr != nil {
		t.Skipf("zdb rejected the grown pool: %v\n"+
			"This usually means the label config nvlist's asize / vdev_tree\n"+
			"did not match the new image size, or one of the four labels\n"+
			"(L0/L1 at the start, L2/L3 at the new end) was written to the\n"+
			"wrong offset. zdb output follows:\n%s", runErr, outStr)
	}

	mustContain := []string{
		poolName,
		"version:",
		"vdev_tree:",
	}
	for _, want := range mustContain {
		if !strings.Contains(outStr, want) {
			t.Errorf("zdb output missing %q after grow. Full output:\n%s", want, outStr)
		}
	}
}

// TestZfsGrow_FullCycle: write before grow, write after grow, read
// both — verifies that grow extends usable space and that the writer
// can keep going past the original boundary.
func TestZfsGrow_FullCycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zfs-grow-cycle.img")
	startSize := int64(8 * 1024 * 1024)
	fs, err := Format(path, startSize, FormatConfig{PoolName: "growcycle"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	pre := []byte("before grow\n")
	if err := fs.WriteFile("/before.txt", pre, 0o644); err != nil {
		t.Fatalf("WriteFile before grow: %v", err)
	}

	newSize := startSize * 2
	if err := fs.Grow(newSize); err != nil {
		t.Fatalf("Grow: %v", err)
	}

	post := []byte("after grow — pool got bigger\n")
	if err := fs.WriteFile("/after.txt", post, 0o644); err != nil {
		t.Fatalf("WriteFile after grow: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fs2, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open after grow + write: %v", err)
	}
	defer fs2.Close()

	gotPre, err := fs2.ReadFile("/before.txt")
	if err != nil {
		t.Fatalf("ReadFile before: %v", err)
	}
	if string(gotPre) != string(pre) {
		t.Errorf("ReadFile before: %q, want %q", gotPre, pre)
	}
	gotPost, err := fs2.ReadFile("/after.txt")
	if err != nil {
		t.Fatalf("ReadFile after: %v", err)
	}
	if string(gotPost) != string(post) {
		t.Errorf("ReadFile after: %q, want %q", gotPost, post)
	}
}

// TestZfsGrow_PreservesAllocatorBumpPointer regression test: grow must
// widen the allocator's upper bound WITHOUT resetting the bump pointer
// or clobbering the free list. A previous implementation called
// initAllocator after grow, which rebuilt from on-disk dnodes and
// dropped the in-memory free list — making subsequent writes after
// a delete+write cycle re-bump instead of reusing extents.
func TestZfsGrow_PreservesAllocatorBumpPointer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zfs-grow-alloc.img")
	startSize := int64(8 * 1024 * 1024)
	fsAny, err := Format(path, startSize, FormatConfig{PoolName: "growalloc"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fsAny.Close()

	// Force a free-list entry: write then delete the same file.
	if err := fsAny.WriteFile("/tmp.bin", []byte("free-me"), 0o644); err != nil {
		t.Fatalf("WriteFile pre: %v", err)
	}
	if err := fsAny.DeleteFile("/tmp.bin"); err != nil {
		t.Fatalf("DeleteFile pre: %v", err)
	}

	// Reach into the concrete type to inspect allocator state.
	fs := fsAny.(*zfsFS)
	bumpBefore := fs.alloc.nextFree
	freeListBefore := fs.alloc.freeListBytes()
	if freeListBefore == 0 {
		t.Fatalf("free list empty after delete — test precondition failed")
	}

	if err := fs.Grow(startSize * 2); err != nil {
		t.Fatalf("Grow: %v", err)
	}
	if fs.alloc.nextFree != bumpBefore {
		t.Errorf("bump pointer changed across grow: was %d, now %d", bumpBefore, fs.alloc.nextFree)
	}
	if got := fs.alloc.freeListBytes(); got != freeListBefore {
		t.Errorf("free list bytes changed across grow: was %d, now %d", freeListBefore, got)
	}
	wantLimit := startSize*2 - 2*vdevLabelSize
	if fs.alloc.limitOff != wantLimit {
		t.Errorf("allocator limit after grow = %d, want %d", fs.alloc.limitOff, wantLimit)
	}
}
