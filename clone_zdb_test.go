package filesystem_zfs

// clone_zdb_test.go — WRITE-SIDE cross-compatibility audit for CLONES.
//
// Companion to compatw_test.go's TestWriteThenZdb: it produces a pool that has
// a snapshot, a clone of that snapshot, and data written INTO the clone, then
// validates the whole thing against the real OpenZFS userland `zdb`:
//
//   - `zdb -e -p <dir> -d <pool>` imports the pool and enumerates every dataset
//     (MOS + each ZPL objset). The clone must appear as "<pool>/<clone> [ZPL]",
//     proving the on-disk DSL wiring (dsl_dir dd_origin_obj, dsl_dataset
//     ds_prev_snap_obj, child-map registration) is spec-conformant enough for
//     OpenZFS to walk it. It must also print NO "leaked" line: every MOS object
//     the clone/snapshot creation allocated is properly referenced, and the
//     pool root DSL dir's own objects stay credited (which requires a snapshot's
//     ds_num_children == 1 and the head's == 0, exactly as OpenZFS does).
//
//   - `zdb -e -p <dir> -bcc <pool>` traverses every block verifying fletcher4
//     checksums and cross-checks the traversal byte-sum against the metaslab
//     space maps. A clean run ("No leaks (block sum matches space maps
//     exactly)") proves the clone's deep-copied blocks are checksum-correct up
//     the chain and that later writes into the clone did not clobber any pinned
//     metadata (the allocator high-water covers snapshot/clone aux objects).
//
// Skip-gated on `zdb` PATH availability (install zfsutils-linux on Debian/
// Ubuntu, or openzfs via Homebrew/pkgx) and on a Linux/Darwin host.

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCloneThenZdb(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("clone zdb cross-compat: skipping on %s (zdb is linux/darwin only)", runtime.GOOS)
	}
	zdbPath, err := exec.LookPath("zdb")
	if err != nil {
		t.Skip("zdb not on PATH — install zfsutils-linux (Debian/Ubuntu) or openzfs (Homebrew/pkgx) to enable clone cross-compat validation")
	}

	const pool = "clonezdbpool"
	imgDir := t.TempDir()
	imgPath := filepath.Join(imgDir, pool+".img")

	fs, err := Format(imgPath, 64*1024*1024, FormatConfig{
		PoolName: pool,
		PoolGUID: 0xC10E5C0FFEE1234,
	})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if err := fs.WriteFile("/alpha.txt", []byte("alpha in snapshot\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.MkDir("/dir1", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	if err := fs.WriteFile("/dir1/nested.txt", []byte("nested\n"), 0o644); err != nil {
		t.Fatalf("WriteFile nested: %v", err)
	}
	if err := fs.Snapshot("snap1"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := fs.Clone("snap1", "childfs"); err != nil {
		t.Fatalf("Clone: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Write INTO the clone through a fresh handle (exercises the write path for
	// a dataset that lives in an upper MOS array block + the aux-block
	// high-water protection).
	clone, err := OpenDataset(imgPath, -1, "childfs")
	if err != nil {
		t.Fatalf("OpenDataset(childfs): %v", err)
	}
	if err := clone.WriteFile("/clone-only.txt", []byte("only in clone\n"), 0o644); err != nil {
		t.Fatalf("clone WriteFile: %v", err)
	}
	if err := clone.Close(); err != nil {
		t.Fatalf("clone Close: %v", err)
	}

	// ── zdb -e -d: import + dataset enumeration, no MOS-object leaks ──────────
	dOut, dErr := exec.Command(zdbPath, "-e", "-p", imgDir, "-d", pool).CombinedOutput()
	dStr := string(dOut)
	if dErr != nil {
		t.Fatalf("zdb -e -d failed on a clone pool: %v\nOutput:\n%s", dErr, dStr)
	}
	for _, want := range []string{
		"Dataset " + pool + " [ZPL]",         // pool root
		"Dataset " + pool + "/childfs [ZPL]", // the clone
		"Dataset " + pool + "@snap1 [ZPL]",   // the origin snapshot
	} {
		if !strings.Contains(dStr, want) {
			t.Errorf("zdb -e -d output missing %q (clone/snapshot not walked).\nOutput:\n%s", want, dStr)
		}
	}
	if strings.Contains(dStr, "leaked") {
		t.Errorf("zdb -e -d reported a leaked MOS object on the clone pool — a\n"+
			"DSL object the clone allocated (or the root dir's) is not properly\n"+
			"referenced.\nOutput:\n%s", dStr)
	}

	// ── zdb -e -bcc: block checksums + space-map accounting balance ──────────
	bccOut, bccErr := exec.Command(zdbPath, "-e", "-p", imgDir, "-bcc", pool).CombinedOutput()
	bccStr := string(bccOut)
	if bccErr != nil {
		t.Fatalf("zdb -e -bcc failed on a clone pool: %v\nOutput:\n%s", bccErr, bccStr)
	}
	if strings.Contains(bccStr, "checksum error") || strings.Contains(bccStr, "bad checksum") {
		t.Errorf("zdb -e -bcc reported a block checksum error on the clone pool.\nOutput:\n%s", bccStr)
	}
	if strings.Contains(bccStr, "leaked space:") || strings.Contains(bccStr, "!= alloc") {
		t.Errorf("zdb -e -bcc reported a space-map leak on the clone pool.\nOutput:\n%s", bccStr)
	}
	if !strings.Contains(bccStr, "No leaks (block sum matches space maps exactly)") {
		t.Errorf("zdb -e -bcc did not confirm clean space accounting on the clone pool.\nOutput:\n%s", bccStr)
	}
}
