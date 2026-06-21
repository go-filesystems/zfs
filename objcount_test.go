package filesystem_zfs

import (
	"path/filepath"
	"testing"
)

// reopenObjCounts re-reads a Format()'d pool from disk and returns the two
// quantities zdb's dump_objset() asserts equal: usedobjs (BP_GET_FILL of the
// ZPL objset block pointer, i.e. the DSL dataset's ds_bp) and object_count
// (the number of allocated dnodes found by walking the meta_dnode's object
// array, object 0 excluded). It opens a fresh handle so the values come off
// disk, not from the writer's in-memory state.
func reopenObjCounts(t *testing.T, path string) (usedobjs, metaFill, objectCount uint64) {
	t.Helper()
	ifs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	fs, ok := ifs.(*zfsFS)
	if !ok {
		t.Fatalf("Open returned %T, want *zfsFS", ifs)
	}
	defer fs.Close()

	usedobjs = fs.zplDS.zplOS.bp.fill                    // ds_bp fill == zdb usedobjs
	metaFill = fs.zplDS.zplOS.metaDnode.blkptrAt(0).fill // meta_dnode data BP fill

	for i := uint64(1); i < fmtZPLObjArrayObjs; i++ {
		dn, err := fs.zplDS.zplOS.readObject(i)
		if err != nil || dn == nil {
			continue
		}
		if dn.typ != dmotNone {
			objectCount++
		}
	}
	return
}

// TestObjsetCountAfterWrites guards the objset object-count accounting that
// zdb's dump_objset() asserts: after WriteFile/MkDir/DeleteFile, the ds_bp
// fill (usedobjs) and the meta_dnode BP fill must both equal the live count
// of allocated dnodes in the ZPL object array (object_count). A stale fill is
// what made `zdb -e -dddd <pool>` SIGABRT with
// `object_count == usedobjs (0xN == 0xM)` on any written-to pool.
func TestObjsetCountAfterWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "objcount.img")
	const size = 16 * 1024 * 1024
	ifs, err := Format(path, size, FormatConfig{PoolName: "objcount"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	fs := ifs.(*zfsFS)

	// Baseline: a freshly Format()'d pool must already be self-consistent.
	used, meta, count := reopenObjCounts(t, path)
	if used != count || meta != count {
		t.Fatalf("after Format: usedobjs=%d metaFill=%d object_count=%d (all must match)", used, meta, count)
	}

	// Grow the object set: two files, a directory, a nested file.
	if err := fs.MkDir("/docs", 0o755); err != nil {
		t.Fatalf("MkDir /docs: %v", err)
	}
	if err := fs.WriteFile("/docs/hello.txt", []byte("hello world"), 0o644); err != nil {
		t.Fatalf("WriteFile /docs/hello.txt: %v", err)
	}
	if err := fs.WriteFile("/readme.txt", []byte("readme"), 0o644); err != nil {
		t.Fatalf("WriteFile /readme.txt: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close after writes: %v", err)
	}

	used, meta, count = reopenObjCounts(t, path)
	if used != count || meta != count {
		t.Fatalf("after writes: usedobjs=%d metaFill=%d object_count=%d (all must match)", used, meta, count)
	}
	if count <= baselineMin {
		t.Fatalf("after writes object_count=%d did not grow past baseline", count)
	}

	// Shrink it: deleting a file zeroes its dnode, so the count must drop
	// and the fills must follow.
	ifs2, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open for delete: %v", err)
	}
	fs2 := ifs2.(*zfsFS)
	if err := fs2.DeleteFile("/readme.txt"); err != nil {
		t.Fatalf("DeleteFile /readme.txt: %v", err)
	}
	if err := fs2.Close(); err != nil {
		t.Fatalf("Close after delete: %v", err)
	}

	usedAfterDel, metaAfterDel, countAfterDel := reopenObjCounts(t, path)
	if usedAfterDel != countAfterDel || metaAfterDel != countAfterDel {
		t.Fatalf("after delete: usedobjs=%d metaFill=%d object_count=%d (all must match)",
			usedAfterDel, metaAfterDel, countAfterDel)
	}
	if countAfterDel >= count {
		t.Fatalf("after delete object_count=%d did not drop below %d", countAfterDel, count)
	}
}

// baselineMin is a floor the post-write count must exceed; the Format()-time
// object count is small and writing three objects must push past it.
const baselineMin = fmtZPLObjCount
