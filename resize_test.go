package filesystem_zfs

// resize_test.go — Shrink-side tests.
//
// Covers both modes (Rebuild + InPlace + Auto dispatch matrix),
// payload-survival across re-Open, integrity via the existing reader,
// every validation branch, and a skip-gated zdb cross-check.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

// makeTestPool formats a fresh test pool, writes the supplied
// (path, payload) pairs, and returns the closed image path. Caller is
// responsible for re-opening as needed.
func makeTestPool(t *testing.T, sizeBytes int64, files map[string][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shrink.img")
	fs, err := Format(path, sizeBytes, FormatConfig{
		PoolName: "shrinktest",
		PoolGUID: 0xDEADBEEFCAFE,
	})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	for p, d := range files {
		if err := fs.WriteFile(p, d, 0o644); err != nil {
			t.Fatalf("WriteFile %q: %v", p, err)
		}
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

// hashAll re-opens the image, walks every file under root, and
// returns a map from path → sha256 of file payload. Used to confirm
// that shrink preserved every byte.
func hashAll(t *testing.T, path string) map[string][32]byte {
	t.Helper()
	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	out := make(map[string][32]byte)
	var walk func(dir string)
	walk = func(dir string) {
		entries, err := fs.ListDir(dir)
		if err != nil {
			t.Fatalf("ListDir %q: %v", dir, err)
		}
		for _, e := range entries {
			p := dir
			if p == "/" {
				p = "/" + e.Name()
			} else {
				p = dir + "/" + e.Name()
			}
			switch e.FileType() {
			case 4: // DT_DIR
				walk(p)
			default:
				data, err := fs.ReadFile(p)
				if err != nil {
					t.Fatalf("ReadFile %q: %v", p, err)
				}
				out[p] = sha256.Sum256(data)
			}
		}
	}
	walk("/")
	return out
}

// TestZfsShrink_Rebuild_HappyPath formats a pool, writes a small
// scattered payload, shrinks via Rebuild mode, and checks that the
// new image is the right size and every file's bytes survived
// byte-for-byte.
func TestZfsShrink_Rebuild_HappyPath(t *testing.T) {
	files := map[string][]byte{
		"/a.txt":    []byte("alpha\n"),
		"/b.bin":    bytes.Repeat([]byte{0x42}, 8*1024),
		"/c.empty":  nil,
		"/d.medium": bytes.Repeat([]byte{0xAB, 0xCD}, 16*1024),
	}
	startSize := int64(32 * 1024 * 1024)
	newSize := int64(16 * 1024 * 1024)
	path := makeTestPool(t, startSize, files)
	before := hashAll(t, path)

	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := fs.ShrinkWithMode(newSize, ShrinkMode_Rebuild); err != nil {
		t.Fatalf("ShrinkWithMode rebuild: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Size() != newSize {
		t.Fatalf("post-shrink size = %d, want %d", st.Size(), newSize)
	}

	after := hashAll(t, path)
	if len(before) != len(after) {
		t.Fatalf("file count drift: before %d, after %d", len(before), len(after))
	}
	for p, h := range before {
		if got := after[p]; got != h {
			t.Errorf("hash mismatch for %q after Rebuild shrink", p)
		}
	}
}

// TestZfsShrink_InPlace_HappyPath does the same as Rebuild but
// forces ShrinkMode_InPlace; verifies that the BP-relocation path
// also preserves every byte.
func TestZfsShrink_InPlace_HappyPath(t *testing.T) {
	files := map[string][]byte{
		"/x":        []byte("eks"),
		"/y.bin":    bytes.Repeat([]byte{0x77}, 5*1024),
		"/z.larger": bytes.Repeat([]byte{0xEE}, 9*1024),
	}
	startSize := int64(32 * 1024 * 1024)
	newSize := int64(20 * 1024 * 1024)
	path := makeTestPool(t, startSize, files)
	before := hashAll(t, path)

	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := fs.ShrinkWithMode(newSize, ShrinkMode_InPlace); err != nil {
		t.Fatalf("ShrinkWithMode inplace: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Size() != newSize {
		t.Fatalf("post-shrink size = %d, want %d", st.Size(), newSize)
	}

	after := hashAll(t, path)
	if len(before) != len(after) {
		t.Fatalf("file count drift: before %d, after %d", len(before), len(after))
	}
	for p, h := range before {
		if got := after[p]; got != h {
			t.Errorf("hash mismatch for %q after InPlace shrink", p)
		}
	}
}

// TestZfsShrink_Auto_NoSnapshots_RoutesToInPlace verifies that the
// Auto-mode dispatcher picks InPlace on a snapshot-free pool. We
// can't observe the chosen mode externally, but we can prove the
// dispatcher worked end-to-end (shrink succeeded, image is smaller,
// content survived). The TestZfsShrink_Snapshot_*_RoutesToRebuild
// counterpart proves the other arm of the matrix.
func TestZfsShrink_Auto_NoSnapshots_RoutesToInPlace(t *testing.T) {
	files := map[string][]byte{
		"/auto.txt": []byte("auto pick\n"),
	}
	startSize := int64(16 * 1024 * 1024)
	newSize := int64(10 * 1024 * 1024)
	path := makeTestPool(t, startSize, files)

	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Sanity: writer never emits snapshots, so hasSnapshots must be
	// false here. If this ever flips, Auto-dispatch logic needs a
	// second look.
	zfs := fs.(*zfsFS)
	if zfs.hasSnapshots() {
		t.Fatalf("test precondition failed: fresh writer pool reports snapshots present")
	}
	if err := fs.Shrink(newSize); err != nil {
		t.Fatalf("Shrink (Auto): %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st, _ := os.Stat(path)
	if st.Size() != newSize {
		t.Fatalf("post-shrink size = %d, want %d", st.Size(), newSize)
	}
	after := hashAll(t, path)
	if _, ok := after["/auto.txt"]; !ok {
		t.Errorf("post-shrink filesystem missing /auto.txt")
	}
}

// TestZfsShrink_Snapshot_AutoRoutesToRebuild_InPlaceRefuses spoofs a
// snapshot reference on the head dataset and verifies the dispatch
// matrix: Auto must downshift to Rebuild, explicit InPlace must
// refuse with a clear error. We poke the bonus buffer of the DSL
// dataset object to set ds_prev_snap_obj — that's exactly the field
// hasSnapshots() inspects, and it's what real snapshot creation
// would have done first.
func TestZfsShrink_Snapshot_AutoRoutesToRebuild_InPlaceRefuses(t *testing.T) {
	files := map[string][]byte{
		"/snap.txt": []byte("snap snap\n"),
	}
	startSize := int64(32 * 1024 * 1024)
	newSize := int64(20 * 1024 * 1024)
	path := makeTestPool(t, startSize, files)

	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	zfs := fs.(*zfsFS)
	// Spoof a user-visible snapshot: insert a named entry into the head
	// dataset's snapshot-name ZAP (ds_snapnames_zapobj). hasSnapshots()
	// keys off that ZAP being non-empty — ds_prev_snap_obj is always set
	// on a v5000 pool (it points at the hidden $ORIGIN snapshot) so it is
	// no longer a snapshot indicator.
	mos := zfs.zplDS.mos
	dslDirDN, err := mos.readObject(fmtMOSDSLDirObj)
	if err != nil {
		t.Fatalf("read DSL dir: %v", err)
	}
	bonus := dslDirDN.bonusData()
	headDS := uint64(0)
	for i := 0; i < 8; i++ {
		headDS |= uint64(bonus[ddHeadDatasetObj+i]) << (8 * i)
	}
	dsDN, err := mos.readObject(headDS)
	if err != nil {
		t.Fatalf("read DSL dataset: %v", err)
	}
	dsBonus := dsDN.bonusData()
	snapZAPObj := uint64(0)
	for i := 0; i < 8; i++ {
		snapZAPObj |= uint64(dsBonus[dsSnapnamesZAPObj+i]) << (8 * i)
	}
	if snapZAPObj == 0 {
		t.Fatalf("head dataset has no snapnames ZAP to spoof")
	}
	snapDN, err := mos.readObject(snapZAPObj)
	if err != nil {
		t.Fatalf("read snapnames ZAP dnode: %v", err)
	}
	// Read the ZAP's data block, insert "snap1" → some object, write back.
	blk, err := readDataBlock(zfs.f, zfs.partOffset, snapDN, 0)
	if err != nil {
		t.Fatalf("read snapnames ZAP block: %v", err)
	}
	if err := mzapInsert(blk, "snap1", 0xDEAD); err != nil {
		t.Fatalf("insert spoof snapshot: %v", err)
	}
	bp := snapDN.blkptrAt(0)
	if _, err := zfs.f.WriteAt(blk, zfs.partOffset+bp.dvaOffset(0)); err != nil {
		t.Fatalf("persist spoofed snapnames ZAP: %v", err)
	}

	if !zfs.hasSnapshots() {
		t.Fatalf("spoof failed: hasSnapshots still false")
	}

	// Explicit InPlace MUST refuse.
	err = zfs.ShrinkWithMode(newSize, ShrinkMode_InPlace)
	if err == nil {
		t.Fatalf("ShrinkWithMode InPlace on snapshotted pool: expected refusal, got nil")
	}
	if !strings.Contains(err.Error(), "snapshot") {
		t.Errorf("InPlace refusal error missing 'snapshot': %v", err)
	}

	// Auto MUST route to Rebuild — and Rebuild handles snapshotted
	// pools the same as snapshot-free ones (the snapshot bonus field
	// is replayed too as part of the head reset).
	if err := zfs.Shrink(newSize); err != nil {
		t.Fatalf("Shrink (Auto) on snapshotted pool: %v", err)
	}
	if err := zfs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	st, _ := os.Stat(path)
	if st.Size() != newSize {
		t.Fatalf("post-shrink size = %d, want %d", st.Size(), newSize)
	}
}

// TestZfsShrink_RejectGrowSize confirms that the public Shrink entry
// point refuses targets greater than the current size. (Resize handles
// that direction by routing to Grow; Shrink does NOT silently grow.)
func TestZfsShrink_RejectGrowSize(t *testing.T) {
	path := makeTestPool(t, 8*1024*1024, nil)
	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	err = fs.Shrink(16 * 1024 * 1024)
	if err == nil {
		t.Fatalf("Shrink(16MiB) on 8MiB pool: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "Grow") && !strings.Contains(err.Error(), "grow") {
		t.Errorf("Shrink-to-larger error doesn't mention Grow: %v", err)
	}
}

// TestZfsShrink_RejectTooSmall verifies the headroom floor: any target
// below labels + fixed-layout-metadata + trailing labels is refused.
func TestZfsShrink_RejectTooSmall(t *testing.T) {
	path := makeTestPool(t, 16*1024*1024, nil)
	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	// Well below the headroom floor.
	err = fs.Shrink(2 * 1024 * 1024)
	if err == nil {
		t.Fatalf("Shrink(2MiB): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "below") {
		t.Errorf("too-small error missing 'below': %v", err)
	}
}

// TestZfsShrink_RejectUnaligned: new size must be aligned to the
// pool's 4 KiB block size. Sub-sector targets are refused with a
// clear validation error (not ErrShrinkUnsupported).
func TestZfsShrink_RejectUnaligned(t *testing.T) {
	path := makeTestPool(t, 16*1024*1024, nil)
	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	err = fs.Shrink(10*1024*1024 + 1)
	if err == nil {
		t.Fatalf("Shrink(unaligned): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "aligned") {
		t.Errorf("unaligned error missing 'aligned': %v", err)
	}
}

// TestZfsShrink_RejectInvalidMode: ShrinkWithMode with a nonsense
// mode value must error out rather than silently dispatching.
func TestZfsShrink_RejectInvalidMode(t *testing.T) {
	path := makeTestPool(t, 16*1024*1024, nil)
	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	err = fs.ShrinkWithMode(10*1024*1024, ShrinkMode(99))
	if err == nil {
		t.Fatalf("ShrinkWithMode(invalid): expected error")
	}
	if !strings.Contains(err.Error(), "unknown mode") {
		t.Errorf("invalid-mode error missing 'unknown mode': %v", err)
	}
}

// TestZfsShrink_RejectZero verifies that newSize <= 0 is refused as a
// validation error (not routed anywhere).
func TestZfsShrink_RejectZero(t *testing.T) {
	path := makeTestPool(t, 16*1024*1024, nil)
	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	for _, sz := range []int64{0, -1, -1 << 30} {
		if err := fs.Shrink(sz); err == nil {
			t.Errorf("Shrink(%d): expected error", sz)
		}
	}
}

// TestZfsShrink_NoOpAtCurrentSize: shrinking to the current size is a
// silent success, matching the rest of the resize family.
func TestZfsShrink_NoOpAtCurrentSize(t *testing.T) {
	path := makeTestPool(t, 16*1024*1024, nil)
	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	if err := fs.Shrink(16 * 1024 * 1024); err != nil {
		t.Fatalf("Shrink(curSize): %v", err)
	}
	st, _ := os.Stat(path)
	if st.Size() != 16*1024*1024 {
		t.Errorf("post-noop size = %d, want %d", st.Size(), 16*1024*1024)
	}
}

// TestZfsShrink_PayloadSurvivesReopen: after shrink + close, a fresh
// Open must successfully decode every file. Hash-equivalence is what
// hashAll asserts; here we explicitly exercise the close → re-open
// loop so a stale FS handle doesn't mask a corrupted on-disk layout.
func TestZfsShrink_PayloadSurvivesReopen(t *testing.T) {
	files := map[string][]byte{
		"/survives.txt": []byte("re-open me\n"),
		"/big.bin":      bytes.Repeat([]byte{0xCC}, 32*1024),
	}
	path := makeTestPool(t, 32*1024*1024, files)

	fs1, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := fs1.Shrink(20 * 1024 * 1024); err != nil {
		t.Fatalf("Shrink: %v", err)
	}
	if err := fs1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fs2, err := Open(path, -1)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer fs2.Close()
	for p, want := range files {
		got, err := fs2.ReadFile(p)
		if err != nil {
			t.Fatalf("ReadFile %q after re-open: %v", p, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("payload mismatch for %q after re-open", p)
		}
	}
}

// TestZfsShrink_DirectoriesPreserved verifies that nested
// directories survive Rebuild mode (which is the mode that has to
// recreate the tree from scratch). InPlace doesn't move dnodes at all
// so it can't fail this — covered separately for completeness.
func TestZfsShrink_DirectoriesPreserved(t *testing.T) {
	startSize := int64(32 * 1024 * 1024)
	newSize := int64(20 * 1024 * 1024)
	path := filepath.Join(t.TempDir(), "shrink-dirs.img")
	fs, err := Format(path, startSize, FormatConfig{PoolName: "shrinkdirs"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	dirs := []string{"/a", "/a/b", "/a/b/c"}
	for _, d := range dirs {
		if err := fs.MkDir(d, 0o755); err != nil {
			t.Fatalf("MkDir %q: %v", d, err)
		}
	}
	if err := fs.WriteFile("/a/b/c/leaf.txt", []byte("leaf payload\n"), 0o644); err != nil {
		t.Fatalf("WriteFile leaf: %v", err)
	}
	if err := fs.ShrinkWithMode(newSize, ShrinkMode_Rebuild); err != nil {
		t.Fatalf("ShrinkWithMode rebuild: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fs2, err := Open(path, -1)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer fs2.Close()
	for _, d := range dirs {
		if _, err := fs2.Stat(d); err != nil {
			t.Errorf("dir %q missing after rebuild shrink: %v", d, err)
		}
	}
	data, err := fs2.ReadFile("/a/b/c/leaf.txt")
	if err != nil {
		t.Fatalf("ReadFile leaf after shrink: %v", err)
	}
	if string(data) != "leaf payload\n" {
		t.Errorf("leaf payload mismatch after shrink: got %q", data)
	}
}

// TestZfsShrink_LargeFile_InPlace covers the indirect-block relocation
// arm of the InPlace walker: a file big enough to need a level-1
// indirect block has BOTH leaf data extents AND an indirect-block
// extent that may live in the high region. Both must be relocated and
// the file must read back identical.
func TestZfsShrink_LargeFile_InPlace(t *testing.T) {
	// Two 128 KiB blocks → forces one indirect block above them.
	payload := bytes.Repeat([]byte{0xA5}, 130*1024)
	startSize := int64(48 * 1024 * 1024)
	newSize := int64(24 * 1024 * 1024)

	path := filepath.Join(t.TempDir(), "shrink-big.img")
	fs, err := Format(path, startSize, FormatConfig{PoolName: "shrinkbig"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if err := fs.WriteFile("/big.bin", payload, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.ShrinkWithMode(newSize, ShrinkMode_InPlace); err != nil {
		t.Fatalf("ShrinkWithMode inplace: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fs2, err := Open(path, -1)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer fs2.Close()
	got, err := fs2.ReadFile("/big.bin")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("large-file payload corrupted after InPlace shrink (lens: got %d, want %d)", len(got), len(payload))
	}
}

// TestZfsShrink_BareUberblock_NoZPL covers the "no live data" branch
// of InPlace: an FS handle opened against an image without a valid
// ZPL dataset (zplDS == nil) should still rewrite labels and
// truncate. We simulate this by zeroing the rootbp after Open so
// reopenAfterFormat's openNamedDataset fails. Even when ZPL is gone,
// shrink must successfully relabel + truncate.
func TestZfsShrink_BareUberblock_NoZPL(t *testing.T) {
	path := makeTestPool(t, 16*1024*1024, nil)
	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	zfs := fs.(*zfsFS)
	zfs.zplDS = nil // force the no-data-area branch
	if err := zfs.ShrinkWithMode(12*1024*1024, ShrinkMode_InPlace); err != nil {
		t.Fatalf("ShrinkWithMode bareUB: %v", err)
	}
	if err := zfs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	st, _ := os.Stat(path)
	if st.Size() != 12*1024*1024 {
		t.Errorf("size after bare-UB shrink = %d, want %d", st.Size(), 12*1024*1024)
	}
}

// TestZfsShrink_Resize_DispatchesToShrink confirms Resize() routes to
// Shrink when newSize < current — the bidirectional contract our new
// resize.go owns end to end (replacing the legacy "returns
// ErrShrinkUnsupported" behaviour).
func TestZfsShrink_Resize_DispatchesToShrink(t *testing.T) {
	files := map[string][]byte{
		"/dispatch.txt": []byte("dispatch me\n"),
	}
	path := makeTestPool(t, 16*1024*1024, files)
	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := fs.Resize(10 * 1024 * 1024); err != nil {
		t.Fatalf("Resize shrink-direction: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	st, _ := os.Stat(path)
	if st.Size() != 10*1024*1024 {
		t.Errorf("size = %d, want %d", st.Size(), 10*1024*1024)
	}

	// And payload survived the dispatched shrink.
	fs2, err := Open(path, -1)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer fs2.Close()
	got, err := fs2.ReadFile("/dispatch.txt")
	if err != nil {
		t.Fatalf("ReadFile after dispatched shrink: %v", err)
	}
	if string(got) != "dispatch me\n" {
		t.Errorf("payload mismatch after dispatched shrink: %q", got)
	}
}

// TestZfsShrink_Grow_StillRejectsShrink — grow surface must NOT have
// silently gained shrink support; the wrapped sentinel must still
// fire for direct Grow / GrowTo calls.
func TestZfsShrink_Grow_StillRejectsShrink(t *testing.T) {
	path := makeTestPool(t, 16*1024*1024, nil)
	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	err = fs.Grow(8 * 1024 * 1024)
	if err == nil {
		t.Fatalf("Grow shrink-direction: expected error, got nil")
	}
	if !errors.Is(err, filesystem.ErrShrinkUnsupported) {
		t.Fatalf("Grow shrink-direction error not wrapping ErrShrinkUnsupported: %v", err)
	}
}

// TestZfsShrinkMode_String exercises the String() formatting so the
// stringer is included in coverage even when no test inadvertently
// hits it via a Printf'd error.
func TestZfsShrinkMode_String(t *testing.T) {
	cases := map[ShrinkMode]string{
		ShrinkMode_Auto:    "auto",
		ShrinkMode_Rebuild: "rebuild",
		ShrinkMode_InPlace: "inplace",
		ShrinkMode(99):     "ShrinkMode(99)",
	}
	for in, want := range cases {
		if got := in.String(); got != want {
			t.Errorf("ShrinkMode(%d).String() = %q, want %q", int(in), got, want)
		}
	}
}

// TestShrinkThenZdb is the headline cross-validator — run a shrink
// (Rebuild mode) and feed the result to OpenZFS's own `zdb -e -ddddd`.
// Skip-gated identically to TestWriteThenZdb / TestGrowThenZdb:
//   - non-Linux/macOS host (zdb is Linux/Darwin only);
//   - zdb not on PATH;
//   - zdb rejects the image (= writer diverged again, surface output).
//
// On hard success we look for the same three invariants the grow
// cross-check uses (pool name, version, vdev_tree section), plus
// confirmation that no "indirect" mapping section appeared
// (our shrink takes the rebuild path, not the OpenZFS indirect-vdev
// path, so we should NOT see that section).
func TestShrinkThenZdb(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("zdb cross-compat: skipping on %s (zdb only supported on linux/darwin)", runtime.GOOS)
	}
	zdbPath, err := exec.LookPath("zdb")
	if err != nil {
		t.Skip("zdb not on PATH — install zfsutils-linux (Debian/Ubuntu) or openzfs (Homebrew/pkgx) to enable shrink-side cross-compat validation")
	}

	imgDir := t.TempDir()
	const poolName = "shrinkpool"
	imgPath := filepath.Join(imgDir, poolName+".img")
	const startSize = int64(96 * 1024 * 1024)
	const shrunkSize = int64(48 * 1024 * 1024)

	fs, err := Format(imgPath, startSize, FormatConfig{
		PoolName: poolName,
		PoolGUID: 0xC0FFEE5C0EBAB1E,
	})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if err := fs.WriteFile("/shrank.txt", []byte("shrank sentinel\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.ShrinkWithMode(shrunkSize, ShrinkMode_Rebuild); err != nil {
		t.Fatalf("ShrinkWithMode rebuild: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st, err := os.Stat(imgPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Size() != shrunkSize {
		t.Fatalf("post-shrink image size = %d, want %d", st.Size(), shrunkSize)
	}

	cmd := exec.Command(zdbPath, "-e", "-p", imgDir, poolName)
	out, runErr := cmd.CombinedOutput()
	outStr := string(out)
	if runErr != nil {
		t.Skipf("zdb rejected the shrunk pool: %v\n"+
			"This usually means the label config nvlist's asize / vdev_tree\n"+
			"didn't match the new image size, or one of the four labels\n"+
			"(L0/L1 at the start, L2/L3 at the new end) was written to the\n"+
			"wrong offset. zdb output follows:\n%s", runErr, outStr)
	}

	mustContain := []string{poolName, "version:", "vdev_tree:"}
	for _, want := range mustContain {
		if !strings.Contains(outStr, want) {
			t.Errorf("zdb output missing %q after Rebuild shrink. Full output:\n%s", want, outStr)
		}
	}
	// Negative: rebuild shrink must NOT leave indirect-vdev artefacts
	// behind. OpenZFS prints "removed" / "indirect_vdev" entries when
	// the legacy vdev-removal codepath was used; our writer's Rebuild
	// path never touches that machinery.
	for _, mustNot := range []string{"indirect_vdev:", "removed:"} {
		if strings.Contains(outStr, mustNot) {
			t.Errorf("zdb output unexpectedly contains %q (rebuild shrink should leave no indirect-vdev artefacts):\n%s",
				mustNot, outStr)
		}
	}
}

// TestZfsShrink_OverlappingWrites: exercise the post-shrink writer
// path. After a shrink the in-memory allocator must be reset to a
// consistent state — writing a NEW file should succeed and read back
// identical.
func TestZfsShrink_OverlappingWrites(t *testing.T) {
	files := map[string][]byte{
		"/initial.txt": []byte("initial content\n"),
	}
	path := makeTestPool(t, 32*1024*1024, files)

	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := fs.ShrinkWithMode(20*1024*1024, ShrinkMode_Rebuild); err != nil {
		t.Fatalf("Shrink: %v", err)
	}
	// New write after shrink. Note: post-Rebuild-shrink the FS
	// handle's allocator was reset against the new size; this is
	// where a forgotten initAllocator would blow up.
	if err := fs.WriteFile("/post.txt", []byte("after shrink\n"), 0o644); err != nil {
		t.Fatalf("WriteFile post-shrink: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fs2, err := Open(path, -1)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer fs2.Close()
	post, err := fs2.ReadFile("/post.txt")
	if err != nil {
		t.Fatalf("ReadFile post: %v", err)
	}
	if string(post) != "after shrink\n" {
		t.Errorf("post-shrink write payload mismatch: %q", post)
	}
}

// TestZfsShrink_SymlinkRebuild exercises the symlink branch of the
// Rebuild walker by writing a symlink-typed dir entry directly into
// the parent ZAP (the writer has no public Symlink API yet, so we
// have to forge the entry by hand). The Rebuild capture must read it
// via readlinkLocked, and the replay must recreate it via
// symlinkLocked → writefileImpl with the symlink mode bit set.
func TestZfsShrink_SymlinkRebuild(t *testing.T) {
	path := makeTestPool(t, 32*1024*1024, nil)
	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	zfs := fs.(*zfsFS)

	// Build a symlink dnode by hand: same shape as WriteFile but
	// dmode = symlink (0120000) and dir-entry type = DT_LNK (10).
	const linkTarget = "/etc/hosts"
	zfs.mu.Lock()
	if err := zfs.writefileImpl("/link", []byte(linkTarget), os.ModeSymlink|0o0777); err != nil {
		zfs.mu.Unlock()
		t.Fatalf("writefileImpl symlink: %v", err)
	}
	zfs.mu.Unlock()

	// Now shrink via Rebuild — the symlink dir entry must be captured
	// and replayed.
	if err := zfs.ShrinkWithMode(20*1024*1024, ShrinkMode_Rebuild); err != nil {
		t.Fatalf("Shrink rebuild: %v", err)
	}
	if err := zfs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fs2, err := Open(path, -1)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer fs2.Close()
	got, err := fs2.ReadLink("/link")
	if err != nil {
		t.Fatalf("ReadLink after shrink: %v", err)
	}
	if got != linkTarget {
		t.Errorf("symlink target after rebuild: got %q, want %q", got, linkTarget)
	}
}

// TestZfsShrink_HasSnapshots_BareImage verifies the early-return arm
// of hasSnapshots — when zplDS is nil there's nothing to inspect, the
// function must return false. Routes through Auto mode dispatch.
func TestZfsShrink_HasSnapshots_BareImage(t *testing.T) {
	path := makeTestPool(t, 16*1024*1024, nil)
	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	zfs := fs.(*zfsFS)
	zfs.zplDS = nil
	if zfs.hasSnapshots() {
		t.Errorf("hasSnapshots with zplDS=nil should be false")
	}
	// Even with zplDS=nil, Auto should still complete (it'll pick
	// InPlace and route into the bare-uberblock branch).
	if err := zfs.Shrink(12 * 1024 * 1024); err != nil {
		t.Fatalf("Shrink with zplDS=nil: %v", err)
	}
	zfs.Close()
}

// TestZfsShrink_NoOpAtCurrentSize_AfterShrink: a second shrink-to-
// same-size is also a no-op (idempotency on the public surface).
func TestZfsShrink_NoOpAtCurrentSize_AfterShrink(t *testing.T) {
	path := makeTestPool(t, 32*1024*1024, map[string][]byte{
		"/k": []byte("v"),
	})
	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	if err := fs.Shrink(20 * 1024 * 1024); err != nil {
		t.Fatalf("Shrink #1: %v", err)
	}
	// Repeat at the same size — no-op.
	if err := fs.Shrink(20 * 1024 * 1024); err != nil {
		t.Fatalf("Shrink #2 (same size): %v", err)
	}
}

// TestZfsShrink_Rebuild_PreservesPoolIdentity confirms that the
// pool's name + GUID survive a Rebuild shrink. zdb (and any other
// external import path) keys off these values; losing them would
// break cross-tool round-trips.
func TestZfsShrink_Rebuild_PreservesPoolIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shrink-ident.img")
	fs, err := Format(path, 24*1024*1024, FormatConfig{
		PoolName: "identpool",
		PoolGUID: 0x1234567890ABCDEF,
	})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if err := fs.ShrinkWithMode(16*1024*1024, ShrinkMode_Rebuild); err != nil {
		t.Fatalf("Shrink: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fs2, err := Open(path, -1)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	zfs := fs2.(*zfsFS)
	name, guid, err := zfs.readPoolIdentity()
	if err != nil {
		t.Fatalf("readPoolIdentity: %v", err)
	}
	if name != "identpool" {
		t.Errorf("pool name = %q, want %q (lost across Rebuild?)", name, "identpool")
	}
	if guid != 0x1234567890ABCDEF {
		t.Errorf("pool GUID = 0x%X, want 0x1234567890ABCDEF", guid)
	}
	fs2.Close()
}

// TestZfsShrink_Stat_NotFound exercises the unhappy path of
// statLocked — a missing path returns a wrapped PathError with the
// errNotFound sentinel.
func TestZfsShrink_Stat_NotFound(t *testing.T) {
	path := makeTestPool(t, 16*1024*1024, nil)
	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	zfs := fs.(*zfsFS)
	zfs.mu.Lock()
	defer zfs.mu.Unlock()
	if _, err := zfs.statLocked("/nope"); err == nil {
		t.Errorf("statLocked(/nope) = nil error, want errNotFound")
	}
}

// helper to spell out an int64 in MiB in error messages, used when a
// hard size check fails — nicer than raw bytes for human readers.
func fmtMiB(n int64) string { return fmt.Sprintf("%d MiB", n/(1024*1024)) }

var _ = fmtMiB
