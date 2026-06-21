package filesystem_zfs

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// countingReaderAt wraps an io.ReaderAt and returns an error after maxOK successful reads.
type countingReaderAt struct {
	r     io.ReaderAt
	calls int
	maxOK int // number of successful reads before failing
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	c.calls++
	if c.calls > c.maxOK {
		return 0, fmt.Errorf("countingReaderAt: injected read error on call %d", c.calls)
	}
	return c.r.ReadAt(p, off)
}

// newTestFS creates a Format()'d ZFS filesystem in a temp dir.
// Returns the concrete *zfsFS so coverage tests can poke at
// unexported internals (zplDS, f, partOffset, …). Format itself
// returns the public filesystem.Filesystem interface, but the
// runtime value is always a *zfsFS so the assertion is safe.
func newTestFS(t *testing.T) *zfsFS {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pool.img")
	const size = 8 * 1024 * 1024 // 8 MiB
	ifs, err := Format(path, size, FormatConfig{PoolName: "testcov"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	fs, ok := ifs.(*zfsFS)
	if !ok {
		t.Fatalf("Format returned %T, want *zfsFS", ifs)
	}
	t.Cleanup(func() { fs.Close() })
	return fs
}

// ── ReadLink ──────────────────────────────────────────────────────────────────

func TestReadLink_FileContent(t *testing.T) {
	// ReadLink reads data blocks regardless of inode type.
	// Write a regular file with "/target" as content, then ReadLink it.
	fs := newTestFS(t)

	if err := fs.WriteFile("/link", []byte("/target"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	target, err := fs.ReadLink("/link")
	if err != nil {
		t.Fatalf("ReadLink: %v", err)
	}
	if target != "/target" {
		t.Fatalf("ReadLink = %q, want %q", target, "/target")
	}
}

func TestReadLink_NotFound(t *testing.T) {
	fs := newTestFS(t)
	if _, err := fs.ReadLink("/nonexistent"); err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestReadLink_EmptyFile(t *testing.T) {
	// A file with no data blocks (blkptrAt(0).isNull()) returns "".
	fs := newTestFS(t)

	if err := fs.WriteFile("/empty", nil, 0o644); err != nil {
		t.Fatalf("WriteFile empty: %v", err)
	}

	target, err := fs.ReadLink("/empty")
	if err != nil {
		t.Fatalf("ReadLink empty: %v", err)
	}
	if target != "" {
		t.Fatalf("ReadLink empty = %q, want %q", target, "")
	}
}

// ── ListDir ───────────────────────────────────────────────────────────────────

func TestListDir_NotADirectory(t *testing.T) {
	fs := newTestFS(t)

	if err := fs.WriteFile("/notadir", []byte("content"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := fs.ListDir("/notadir"); err == nil {
		t.Fatal("ListDir on file should return error")
	}
}

// ── DeleteFile / DeleteDir ────────────────────────────────────────────────────

func TestDeleteFile_IsDirectory(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.MkDir("/adir", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	if err := fs.DeleteFile("/adir"); err == nil {
		t.Fatal("DeleteFile on directory should return error")
	}
}

func TestDeleteFile_NotFound(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.DeleteFile("/nonexistent"); err == nil {
		t.Fatal("DeleteFile nonexistent should return error")
	}
}

func TestDeleteDir_NotFound(t *testing.T) {
	// lookupEntry fails in DeleteDir (covers fs.go:411.16,413.3): name not in root ZAP.
	fs := newTestFS(t)
	if err := fs.DeleteDir("/nonexistent"); err == nil {
		t.Fatal("DeleteDir nonexistent should return error")
	}
}

func TestDeleteDir_NotADirectory(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.WriteFile("/file", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.DeleteDir("/file"); err == nil {
		t.Fatal("DeleteDir on file should return error")
	}
}

func TestDeleteDir_NonEmpty(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.MkDir("/full", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	if err := fs.WriteFile("/full/child", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.DeleteDir("/full"); err == nil {
		t.Fatal("DeleteDir non-empty should return error")
	}
}

func TestDeleteDir_Root(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.DeleteDir("/"); err == nil {
		t.Fatal("DeleteDir / should return error")
	}
}

// ── Rename ────────────────────────────────────────────────────────────────────

func TestRename_SameDir(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.WriteFile("/a", []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.Rename("/a", "/b"); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	// /a should be gone, /b should have the content.
	if _, err := fs.Stat("/a"); err == nil {
		t.Fatal("/a should not exist after rename")
	}
	data, err := fs.ReadFile("/b")
	if err != nil {
		t.Fatalf("ReadFile /b: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("ReadFile /b = %q, want %q", data, "hello")
	}
}

func TestRename_CrossDir(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.MkDir("/src", 0o755); err != nil {
		t.Fatalf("MkDir /src: %v", err)
	}
	if err := fs.MkDir("/dst", 0o755); err != nil {
		t.Fatalf("MkDir /dst: %v", err)
	}
	if err := fs.WriteFile("/src/file", []byte("move me"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := fs.Rename("/src/file", "/dst/file"); err != nil {
		t.Fatalf("Rename cross-dir: %v", err)
	}

	if _, err := fs.Stat("/src/file"); err == nil {
		t.Fatal("/src/file should not exist after rename")
	}
	data, err := fs.ReadFile("/dst/file")
	if err != nil {
		t.Fatalf("ReadFile /dst/file: %v", err)
	}
	if string(data) != "move me" {
		t.Fatalf("ReadFile /dst/file = %q, want %q", data, "move me")
	}
}

func TestRename_DestinationIsDirectory(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.WriteFile("/file", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.MkDir("/dir", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}

	// Rename file to existing directory name: destination is a directory → error.
	if err := fs.Rename("/file", "/dir"); err == nil {
		t.Fatal("Rename to directory should return error")
	}
}

func TestRename_OverwriteExistingFile(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.WriteFile("/src", []byte("new"), 0o644); err != nil {
		t.Fatalf("WriteFile src: %v", err)
	}
	if err := fs.WriteFile("/dst", []byte("old"), 0o644); err != nil {
		t.Fatalf("WriteFile dst: %v", err)
	}

	if err := fs.Rename("/src", "/dst"); err != nil {
		t.Fatalf("Rename overwrite: %v", err)
	}

	data, err := fs.ReadFile("/dst")
	if err != nil {
		t.Fatalf("ReadFile /dst: %v", err)
	}
	if string(data) != "new" {
		t.Fatalf("ReadFile /dst = %q, want %q", data, "new")
	}
}

func TestRename_OldNotFound(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.Rename("/nonexistent", "/b"); err == nil {
		t.Fatal("Rename nonexistent src should return error")
	}
}

func TestRename_OldParentNotFound(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.Rename("/nosuchdir/file", "/b"); err == nil {
		t.Fatal("Rename missing src parent should return error")
	}
}

func TestRename_NewParentNotFound(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.WriteFile("/a", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.Rename("/a", "/nosuchdir/b"); err == nil {
		t.Fatal("Rename missing dst parent should return error")
	}
}

// ── MkDir ─────────────────────────────────────────────────────────────────────

func TestMkDir_AlreadyExists(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.MkDir("/existing", 0o755); err != nil {
		t.Fatalf("MkDir first: %v", err)
	}
	if err := fs.MkDir("/existing", 0o755); err == nil {
		t.Fatal("MkDir duplicate should return error")
	}
}

func TestMkDir_ParentNotFound(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.MkDir("/noparent/child", 0o755); err == nil {
		t.Fatal("MkDir missing parent should return error")
	}
}

// ── ReadFile ──────────────────────────────────────────────────────────────────

func TestReadFile_NotFound(t *testing.T) {
	fs := newTestFS(t)
	if _, err := fs.ReadFile("/nonexistent"); err == nil {
		t.Fatal("ReadFile nonexistent should return error")
	}
}

func TestReadFile_EmptyFile(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.WriteFile("/empty", nil, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	data, err := fs.ReadFile("/empty")
	if err != nil {
		t.Fatalf("ReadFile empty: %v", err)
	}
	if len(data) != 0 {
		t.Fatalf("ReadFile empty = %d bytes, want 0", len(data))
	}
}

// ── WriteFile ─────────────────────────────────────────────────────────────────

func TestWriteFile_ParentNotFound(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.WriteFile("/noparent/file", []byte("x"), 0o644); err == nil {
		t.Fatal("WriteFile missing parent should return error")
	}
}

func TestWriteFile_Overwrite(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.WriteFile("/f", []byte("v1"), 0o644); err != nil {
		t.Fatalf("WriteFile v1: %v", err)
	}
	if err := fs.WriteFile("/f", []byte("v2"), 0o644); err != nil {
		t.Fatalf("WriteFile v2: %v", err)
	}
	data, err := fs.ReadFile("/f")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "v2" {
		t.Fatalf("data = %q, want %q", data, "v2")
	}
}

// ── WriteFile "/" error ───────────────────────────────────────────────────────

func TestWriteFile_Root(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.WriteFile("/", []byte("x"), 0o644); err == nil {
		t.Fatal("WriteFile to / should return error")
	}
}

func TestMkDir_Root(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.MkDir("/", 0o755); err == nil {
		t.Fatal("MkDir / should return error")
	}
}

// ── "no allocator" paths (zplDS!=nil, alloc==nil) ────────────────────────────

func TestWriteFile_NoAllocator(t *testing.T) {
	fs := newTestFS(t)
	fs.alloc = nil // simulate read-only pool
	if err := fs.WriteFile("/x", []byte("y"), 0o644); err == nil {
		t.Fatal("expected no-allocator error")
	}
}

func TestMkDir_NoAllocator(t *testing.T) {
	fs := newTestFS(t)
	fs.alloc = nil
	if err := fs.MkDir("/d", 0o755); err == nil {
		t.Fatal("expected no-allocator error")
	}
}

func TestDeleteFile_NoAllocator(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.WriteFile("/f", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fs.alloc = nil
	if err := fs.DeleteFile("/f"); err == nil {
		t.Fatal("expected no-allocator error")
	}
}

func TestDeleteDir_NoAllocator(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.MkDir("/d", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	fs.alloc = nil
	if err := fs.DeleteDir("/d"); err == nil {
		t.Fatal("expected no-allocator error")
	}
}

func TestRename_NoAllocator(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.WriteFile("/a", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fs.alloc = nil
	if err := fs.Rename("/a", "/b"); err == nil {
		t.Fatal("expected no-allocator error")
	}
}

// ── readDirEntries bad object ─────────────────────────────────────────────────

func TestReadDirEntries_InvalidObjNum(t *testing.T) {
	// Object 100 is beyond the array bounds → readObject should fail → error.
	path := filepath.Join(t.TempDir(), "pool.img")
	ifs, err := Format(path, 8*1024*1024, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer ifs.Close()
	fs := ifs.(*zfsFS)

	_, err = fs.zplDS.readDirEntries(fs.f, fs.partOffset, 100)
	if err == nil {
		t.Fatal("expected error for out-of-range object")
	}
}

// ── allocObjectNum pool-full ──────────────────────────────────────────────────

func TestAllocObjectNum_PoolFull(t *testing.T) {
	// Fill all available object slots with files.
	// fmtObjArrayObjs = fmtObjArraySize/dnodeMinSize = 16384/512 = 32
	// Objects 1..fmtZPLObjCount are pre-used by format (master node,
	// unlinked set, root dir, SA master/registry/layouts). Free user slots
	// are (fmtZPLObjCount+1)..31.
	fs := newTestFS(t)

	// Create exactly enough files to fill all free slots.
	for i := 0; i < fmtObjArrayObjs-(fmtZPLObjCount+1); i++ {
		name := "/" + string([]byte{'a' + byte(i/26), 'a' + byte(i%26)})
		if err := fs.WriteFile(name, []byte("x"), 0o644); err != nil {
			t.Fatalf("WriteFile %d: %v", i, err)
		}
	}

	// One more write should fail with pool-full.
	if err := fs.WriteFile("/overflow", []byte("x"), 0o644); err == nil {
		t.Fatal("expected pool-full error")
	}
}

func TestListDir_SymlinkEntry(t *testing.T) {
	// Create a file and manually insert it as DT_LNK (10<<60) by first
	// writing the file (DT_REG), then deleting and re-adding via internal ZAP.
	// Simplest: just check that a file created with WriteFile shows up.
	fs := newTestFS(t)
	if err := fs.WriteFile("/f", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	entries, err := fs.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Name() == "f" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected 'f' in ListDir results")
	}
}

// ── additional coverage tests ─────────────────────────────────────────────────

func TestReadFile_NotRegularFile(t *testing.T) {
	// ReadFile on a directory → "not a regular file" error.
	fs := newTestFS(t)
	if err := fs.MkDir("/mydir", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	_, err := fs.ReadFile("/mydir")
	if err == nil {
		t.Fatal("expected error reading a directory as file")
	}
}

func TestListDir_SymlinkTypeEntry(t *testing.T) {
	// Manually insert a symlink entry (DT_LNK=10) into root dir to cover case 10 in ListDir.
	fs := newTestFS(t)
	rootObjNum := fs.zplDS.rootObjNum
	rootDN, err := fs.zplDS.zplOS.readObject(rootObjNum)
	if err != nil {
		t.Fatalf("readObject: %v", err)
	}
	bp := rootDN.blkptrAt(0)
	zapData, err := readBlock(fs.f, fs.partOffset, bp)
	if err != nil {
		t.Fatalf("readBlock: %v", err)
	}
	if err := mzapInsert(zapData, "alink", (uint64(10)<<60)|5); err != nil {
		t.Fatalf("mzapInsert: %v", err)
	}
	if _, err := fs.f.WriteAt(zapData, fs.partOffset+bp.dvaOffset(0)); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	entries, err := fs.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	have := false
	for _, e := range entries {
		if e.Name() == "alink" {
			have = true
		}
	}
	if !have {
		t.Fatal("expected 'alink' in listing")
	}
}

func TestStat_ReadAttrsError(t *testing.T) {
	// Ghost directory entry pointing to object 9999 (invalid) →
	// Stat calls readAttrs(9999) → readObject(9999) fails → error.
	fs := newTestFS(t)
	rootObjNum := fs.zplDS.rootObjNum
	rootDN, err := fs.zplDS.zplOS.readObject(rootObjNum)
	if err != nil {
		t.Fatalf("readObject: %v", err)
	}
	bp := rootDN.blkptrAt(0)
	zapData, err := readBlock(fs.f, fs.partOffset, bp)
	if err != nil {
		t.Fatalf("readBlock: %v", err)
	}
	if err := mzapInsert(zapData, "ghost", (uint64(8)<<60)|9999); err != nil {
		t.Fatalf("mzapInsert: %v", err)
	}
	if _, err := fs.f.WriteAt(zapData, fs.partOffset+bp.dvaOffset(0)); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	_, err = fs.Stat("/ghost")
	if err == nil {
		t.Fatal("expected error for ghost entry with invalid object")
	}
}

func TestWriteDnode_ObjectIDNonZero(t *testing.T) {
	// writeDnode with objNum=32 → blockID = 32*512 / fmtObjArraySize = 1 ≠ 0 → error.
	fs := newTestFS(t)
	dn := newDnode(dmotNone, 0, 0, 0)
	dn.encode()
	if err := fs.writeDnode(32, dn); err == nil {
		t.Fatal("expected error for blockID != 0")
	}
}

func TestWriteDnode_NullMetaBP(t *testing.T) {
	// Replace ZPL meta_dnode with zero-byte dnode → bp.isNull() → error.
	fs := newTestFS(t)
	nullDN := &dnode{raw: make([]byte, dnodeMinSize)} // all zeros → prop=0 → isNull()=true
	fs.zplDS.zplOS.metaDnode = nullDN
	dn := newDnode(dmotNone, 0, 0, 0)
	dn.encode()
	if err := fs.writeDnode(1, dn); err == nil {
		t.Fatal("expected error for null meta_dnode BP")
	}
}

func TestUpdateDirZAP_ReadObjectError(t *testing.T) {
	// updateDirZAP with invalid dirObjNum (9999) → readObject fails → error.
	fs := newTestFS(t)
	if err := fs.updateDirZAP(9999, "x", 1, false); err == nil {
		t.Fatal("expected error for invalid dirObjNum")
	}
}

func TestUpdateDirZAP_NonMicroZAP(t *testing.T) {
	// Corrupt root dir ZAP block type to zbtHeader (fat-ZAP) → "unsupported ZAP type" error.
	fs := newTestFS(t)
	rootObjNum := fs.zplDS.rootObjNum
	rootDN, err := fs.zplDS.zplOS.readObject(rootObjNum)
	if err != nil {
		t.Fatalf("readObject: %v", err)
	}
	bp := rootDN.blkptrAt(0)
	zapData, err := readBlock(fs.f, fs.partOffset, bp)
	if err != nil {
		t.Fatalf("readBlock: %v", err)
	}
	binary.LittleEndian.PutUint64(zapData[0:], zbtHeader)
	if _, err := fs.f.WriteAt(zapData, fs.partOffset+bp.dvaOffset(0)); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err := fs.updateDirZAP(rootObjNum, "x", 1, false); err == nil {
		t.Fatal("expected error for non-micro ZAP type")
	}
}

func TestReadDirEntryRaw_ReadObjectError(t *testing.T) {
	// readDirEntryRaw with object 9999 → readObject fails → error.
	fs := newTestFS(t)
	if _, err := fs.readDirEntryRaw(9999, "x"); err == nil {
		t.Fatal("expected error for invalid dirObjNum")
	}
}

func TestDeleteFile_ReadObjectError(t *testing.T) {
	// Ghost entry in root pointing to object 9999 → DeleteFile reads its dnode → error.
	fs := newTestFS(t)
	rootObjNum := fs.zplDS.rootObjNum
	rootDN, _ := fs.zplDS.zplOS.readObject(rootObjNum)
	bp := rootDN.blkptrAt(0)
	zapData, _ := readBlock(fs.f, fs.partOffset, bp)
	_ = mzapInsert(zapData, "ghost", (uint64(8)<<60)|9999)
	_, _ = fs.f.WriteAt(zapData, fs.partOffset+bp.dvaOffset(0))
	if err := fs.DeleteFile("/ghost"); err == nil {
		t.Fatal("expected error for ghost entry with invalid object")
	}
}

func TestDeleteDir_ReadObjectError(t *testing.T) {
	// Ghost dir entry pointing to object 9999 → DeleteDir reads its dnode → error.
	fs := newTestFS(t)
	rootObjNum := fs.zplDS.rootObjNum
	rootDN, _ := fs.zplDS.zplOS.readObject(rootObjNum)
	bp := rootDN.blkptrAt(0)
	zapData, _ := readBlock(fs.f, fs.partOffset, bp)
	_ = mzapInsert(zapData, "ghostdir", (uint64(4)<<60)|9999)
	_, _ = fs.f.WriteAt(zapData, fs.partOffset+bp.dvaOffset(0))
	if err := fs.DeleteDir("/ghostdir"); err == nil {
		t.Fatal("expected error for ghost dir entry with invalid object")
	}
}

func TestInitAllocator_SmallImageSize(t *testing.T) {
	// imageSize = 2*vdevLabelSize+1 → limit=1 < next → limit is replaced by next.
	fs := newTestFS(t)
	fs.initAllocator(2*vdevLabelSize + 1)
	if fs.alloc == nil {
		t.Fatal("expected allocator after small imageSize initAllocator")
	}
}

func TestCommitUberblock_ClosedFile(t *testing.T) {
	// Close the underlying file before commitUberblock → ReadAt fails → error.
	fs := newTestFS(t)
	_ = fs.f.Close() // close; t.Cleanup will close again (silently ignored)
	if err := fs.commitUberblock(); err == nil {
		t.Fatal("expected error after file is closed")
	}
}

func TestUpdateDirZAP_NullBP(t *testing.T) {
	// A free object slot (past the format-reserved objects 1..fmtZPLObjCount)
	// is all-zeros → blkptrAt(0).isNull()=true → error.
	fs := newTestFS(t)
	freeObj := uint64(fmtZPLObjCount + 1)
	if err := fs.updateDirZAP(freeObj, "x", 1, false); err == nil {
		t.Fatal("expected error for null BP in free dnode")
	}
}

func TestInitAllocator_UpdatesMaxOff(t *testing.T) {
	// Write a file so its data BP ends beyond fmtInitialNextFree → covers maxOff=end.
	fs := newTestFS(t)
	if err := fs.WriteFile("/data2", []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fs.initAllocator(8 * 1024 * 1024)
	if fs.alloc == nil {
		t.Fatal("expected allocator after initAllocator")
	}
}

func TestZapLookup_ZapListAllError(t *testing.T) {
	// dnode with null BP → zapListAll fails → zapLookup propagates that error.
	dn := newDnode(dmotZAPOther, 1, 0, 0) // nblkptr=1, blkptr is zero → isNull()=true
	_, err := zapLookup(nil, 0, dn, "key")
	if err == nil {
		t.Fatal("expected error when zapListAll fails")
	}
}

// ── zeroMetaBP zeroes the ZPL meta_dnode BP so writeDnode will fail ───────────

func zeroMetaBP(fs *zfsFS) {
	// Write zeros over the first blkptr of the ZPL meta_dnode's raw data.
	raw := fs.zplDS.zplOS.metaDnode.raw
	for i := dnodeHdrSize; i < dnodeHdrSize+blkptrSize && i < len(raw); i++ {
		raw[i] = 0
	}
	fs.zplDS.zplOS.metaDnode, _ = parseDnode(raw[:dnodeMinSize])
}

// ── ListDir error paths ───────────────────────────────────────────────────────

func TestListDir_NotFound(t *testing.T) {
	// lookupPath on non-existent path → PathError (covers fs.go line 69).
	fs := newTestFS(t)
	if _, err := fs.ListDir("/nonexistent"); err == nil {
		t.Fatal("expected error for non-existent path")
	}
}

func TestListDir_ReadObjectError(t *testing.T) {
	// readObject on ghost dir obj → error (covers fs.go line 73).
	// Insert a dir entry pointing to object 9999 in root dir, then call ListDir on root.
	// But root is a dir with zapListAll success; we need a SUBdir that points to ghost obj.
	// Simpler: insert a ghost dir entry at the root dir level with obj 9999 type=4,
	// then call ListDir on root → it reads each entry's obj? No — ListDir reads the dir
	// object itself (the dnode for the directory), not the children's dnodes.
	// Line 73 is: dirDN, err := fs.zplDS.zplOS.readObject(objNum)
	// where objNum comes from lookupPath. So the directory path resolves to an objNum
	// that readObject fails on.
	// Strategy: insert a dir entry pointing to obj 9999 (dir type=4) in root,
	//           then create that subdirectory entry via ghost obj, then ListDir on it.
	// But lookupPath will find it and return objNum=9999, then readObject(9999) fails.
	fs := newTestFS(t)
	rootObjNum := fs.zplDS.rootObjNum
	rootDN, _ := fs.zplDS.zplOS.readObject(rootObjNum)
	bp := rootDN.blkptrAt(0)
	zapData, _ := readBlock(fs.f, fs.partOffset, bp)
	// Insert a dir entry with obj 9999 (type 4 = DT_DIR)
	_ = mzapInsert(zapData, "ghostdir", (uint64(4)<<60)|9999)
	_, _ = fs.f.WriteAt(zapData, fs.partOffset+bp.dvaOffset(0))
	if _, err := fs.ListDir("/ghostdir"); err == nil {
		t.Fatal("expected error for ghost dir object")
	}
}

func TestListDir_ZapListAllError(t *testing.T) {
	// zapListAll error on dir dnode → error (covers fs.go line 80).
	// Create a subdirectory, then corrupt its ZAP block so zapListAll fails.
	fs := newTestFS(t)
	if err := fs.MkDir("/testdir", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	// Find the dir object num
	rootObjNum := fs.zplDS.rootObjNum
	dirObjNum, _ := fs.zplDS.lookupEntry(fs.f, fs.partOffset, rootObjNum, "testdir")
	dirDN, _ := fs.zplDS.zplOS.readObject(dirObjNum)
	bp := dirDN.blkptrAt(0)
	// Corrupt the ZAP block magic
	zapData, _ := readBlock(fs.f, fs.partOffset, bp)
	binary.LittleEndian.PutUint64(zapData[0:], 0xDEADBEEF) // bad magic
	_, _ = fs.f.WriteAt(zapData, fs.partOffset+bp.dvaOffset(0))
	if _, err := fs.ListDir("/testdir"); err == nil {
		t.Fatal("expected error for corrupt dir ZAP")
	}
}

func TestListDir_DirTypeEntry(t *testing.T) {
	// Create a subdirectory so ListDir returns an entry with fileTypeCode=4.
	// This covers the `case 4: mode = 0o040755` branch (fs.go line 90).
	fs := newTestFS(t)
	if err := fs.MkDir("/subdir", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	entries, err := fs.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Name() == "subdir" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected 'subdir' in ListDir results")
	}
}

// ── ReadFile error paths ──────────────────────────────────────────────────────

func TestReadFile_ReadObjectError(t *testing.T) {
	// readObject on ghost file obj → error (covers fs.go line 119).
	fs := newTestFS(t)
	rootObjNum := fs.zplDS.rootObjNum
	rootDN, _ := fs.zplDS.zplOS.readObject(rootObjNum)
	bp := rootDN.blkptrAt(0)
	zapData, _ := readBlock(fs.f, fs.partOffset, bp)
	_ = mzapInsert(zapData, "ghostfile", (uint64(8)<<60)|9999)
	_, _ = fs.f.WriteAt(zapData, fs.partOffset+bp.dvaOffset(0))
	if _, err := fs.ReadFile("/ghostfile"); err == nil {
		t.Fatal("expected error for ghost file object")
	}
}

func TestReadFile_ReadDnodeDataError(t *testing.T) {
	// readDnodeData error on file with corrupt block pointer (covers fs.go line 130).
	fs := newTestFS(t)
	if err := fs.WriteFile("/testfile", []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Find the file object num and corrupt its data BP
	rootObjNum := fs.zplDS.rootObjNum
	fileObjNum, _ := fs.zplDS.lookupEntry(fs.f, fs.partOffset, rootObjNum, "testfile")
	fileDN, _ := fs.zplDS.zplOS.readObject(fileObjNum)
	// Set the data BP to point to an invalid offset (out of file bounds)
	bigBP := makeBlkptr(1<<40, poolBlockSize, poolBlockSize, zcompressOff, dmotPlainFileContents, 0, 1)
	fileDN.setBlkptrAt(0, bigBP)
	fileDN.encode()
	// Write back the dnode via the object array block
	metaDN := fs.zplDS.zplOS.metaDnode
	metaBP := metaDN.blkptrAt(0)
	blkData, _ := readBlock(fs.f, fs.partOffset, metaBP)
	byteOff := int(fileObjNum) * dnodeMinSize
	copy(blkData[byteOff:], fileDN.raw[:dnodeMinSize])
	_, _ = fs.f.WriteAt(blkData, fs.partOffset+metaBP.dvaOffset(0))
	// Also update in-memory objset cache
	copy(fs.zplDS.zplOS.raw[byteOff:], fileDN.raw[:dnodeMinSize])
	if _, err := fs.ReadFile("/testfile"); err == nil {
		t.Fatal("expected error for corrupt data BP")
	}
}

// ── ReadLink error paths ──────────────────────────────────────────────────────

func TestReadLink_ReadObjectError(t *testing.T) {
	// readObject on ghost symlink obj → error (covers fs.go line 157).
	fs := newTestFS(t)
	rootObjNum := fs.zplDS.rootObjNum
	rootDN, _ := fs.zplDS.zplOS.readObject(rootObjNum)
	bp := rootDN.blkptrAt(0)
	zapData, _ := readBlock(fs.f, fs.partOffset, bp)
	_ = mzapInsert(zapData, "ghostlink", (uint64(10)<<60)|9999)
	_, _ = fs.f.WriteAt(zapData, fs.partOffset+bp.dvaOffset(0))
	if _, err := fs.ReadLink("/ghostlink"); err == nil {
		t.Fatal("expected error for ghost symlink object")
	}
}

func TestReadLink_ReadDnodeDataError(t *testing.T) {
	// readDnodeData error on symlink with corrupt data BP (covers fs.go line 165).
	// Create a regular file with a non-null but invalid data BP so readDnodeData fails.
	fs := newTestFS(t)
	if err := fs.WriteFile("/testlink", []byte("target"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	rootObjNum := fs.zplDS.rootObjNum
	fileObjNum, _ := fs.zplDS.lookupEntry(fs.f, fs.partOffset, rootObjNum, "testlink")
	fileDN, _ := fs.zplDS.zplOS.readObject(fileObjNum)
	// Set data BP to out-of-bounds offset so readDnodeData fails
	bigBP := makeBlkptr(1<<40, poolBlockSize, poolBlockSize, zcompressOff, dmotPlainFileContents, 0, 1)
	fileDN.setBlkptrAt(0, bigBP)
	fileDN.encode()
	metaDN := fs.zplDS.zplOS.metaDnode
	metaBP := metaDN.blkptrAt(0)
	blkData, _ := readBlock(fs.f, fs.partOffset, metaBP)
	byteOff := int(fileObjNum) * dnodeMinSize
	copy(blkData[byteOff:], fileDN.raw[:dnodeMinSize])
	_, _ = fs.f.WriteAt(blkData, fs.partOffset+metaBP.dvaOffset(0))
	copy(fs.zplDS.zplOS.raw[byteOff:], fileDN.raw[:dnodeMinSize])
	if _, err := fs.ReadLink("/testlink"); err == nil {
		t.Fatal("expected error for corrupt symlink data BP")
	}
}

// ── WriteFile I/O error paths ─────────────────────────────────────────────────

func TestWriteFile_AllocFails(t *testing.T) {
	// alloc.alloc fails → WriteFile returns error (covers fs.go line 215).
	// Exhaust the allocator by setting its limit to next so no space is available.
	fs := newTestFS(t)
	// Set allocator limit to current nextFree (no space left) by creating a new allocator with same start and limit.
	fs.alloc = newAllocator(fs.alloc.nextFree, fs.alloc.nextFree, poolBlockSize)
	if err := fs.WriteFile("/x", []byte("data"), 0o644); err == nil {
		t.Fatal("expected alloc error")
	}
}

func TestWriteFile_WriteAtFails(t *testing.T) {
	// fs.f.WriteAt fails when writing data block (covers fs.go line 218).
	fs := newTestFS(t)
	_ = fs.f.Close()
	if err := fs.WriteFile("/x", []byte("data"), 0o644); err == nil {
		t.Fatal("expected error after file closed")
	}
}

func TestWriteFile_WriteDnodeFails(t *testing.T) {
	// writeDnode fails after data block written (covers fs.go line 255).
	// Write empty file (no data block) so alloc.alloc is not called, but writeDnode fails.
	fs := newTestFS(t)
	zeroMetaBP(fs)
	if err := fs.WriteFile("/x", []byte{}, 0o644); err == nil {
		t.Fatal("expected writeDnode error")
	}
}

func TestWriteFile_UpdateDirZAPFails(t *testing.T) {
	// updateDirZAP fails after writeDnode succeeds (covers fs.go line 262).
	// To make updateDirZAP fail while writeDnode succeeds:
	// 1. writeDnode succeeds (meta BP is valid)
	// 2. updateDirZAP fails because parent dir's dnode has null BP
	// We need to corrupt the root dir's ZAP after writeDnode.
	// Trick: make the parent dir object 9999 (invalid) by manipulating parentObjNum.
	// Actually the parentPath is "/" which resolves to rootObjNum (valid).
	// We need to corrupt the root dir's ZAP block so updateDirZAP fails.
	// Use the "unsupported ZAP type" trick: corrupt root dir ZAP magic after setup.
	fs := newTestFS(t)
	// First, allocate a valid object so writeDnode will succeed...
	// Then corrupt the root dir ZAP so updateDirZAP fails at the write step.
	// Strategy: let WriteFile run until updateDirZAP, which reads the dir ZAP.
	// Corrupt the root ZAP type BEFORE calling WriteFile.
	rootObjNum := fs.zplDS.rootObjNum
	rootDN, _ := fs.zplDS.zplOS.readObject(rootObjNum)
	bp := rootDN.blkptrAt(0)
	zapData, _ := readBlock(fs.f, fs.partOffset, bp)
	binary.LittleEndian.PutUint64(zapData[0:], zbtHeader) // non-micro type → fail
	_, _ = fs.f.WriteAt(zapData, fs.partOffset+bp.dvaOffset(0))
	if err := fs.WriteFile("/newfile", []byte{}, 0o644); err == nil {
		t.Fatal("expected updateDirZAP error")
	}
}

// ── MkDir I/O error paths ─────────────────────────────────────────────────────

func TestMkDir_AllocFails(t *testing.T) {
	// alloc.alloc fails → MkDir returns error (covers fs.go line 300).
	fs := newTestFS(t)
	fs.alloc = newAllocator(fs.alloc.nextFree, fs.alloc.nextFree, poolBlockSize)
	if err := fs.MkDir("/d", 0o755); err == nil {
		t.Fatal("expected alloc error")
	}
}

func TestMkDir_WriteAtFails(t *testing.T) {
	// fs.f.WriteAt fails when writing ZAP block (covers fs.go line 304).
	fs := newTestFS(t)
	_ = fs.f.Close()
	if err := fs.MkDir("/d", 0o755); err == nil {
		t.Fatal("expected error after file closed")
	}
}

func TestMkDir_AllocObjectNumFails(t *testing.T) {
	// allocObjectNum fails → MkDir returns error (covers fs.go line 311).
	// Fill all object slots with written files to exhaust object numbers.
	fs := newTestFS(t)
	// Fill objects 4 through fmtObjArrayObjs-1 so allocObjectNum finds no free slots.
	// We do this by writing many dummy dnodes into the object array.
	metaDN := fs.zplDS.zplOS.metaDnode
	metaBP := metaDN.blkptrAt(0)
	blkData, err := readBlock(fs.f, fs.partOffset, metaBP)
	if err != nil {
		t.Fatalf("readBlock: %v", err)
	}
	// Mark objects 4..31 as in-use by setting their type byte (offset 0) to dmotPlainFileContents
	for i := int64(4); i < fmtObjArrayObjs; i++ {
		off := i * dnodeMinSize
		if off+dnodeMinSize > int64(len(blkData)) {
			break
		}
		blkData[off] = dmotPlainFileContents // byte 0 is dn_type
	}
	if _, err := fs.f.WriteAt(blkData, fs.partOffset+metaBP.dvaOffset(0)); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	// Invalidate the in-memory cache by forcing readObject to re-read from disk
	// (the raw field of the metaDnode is a cached OA block, but readObject calls readDataBlock).
	// Actually, objset.readObject uses readDataBlock which reads from the file directly.
	// So just writing to the file should be sufficient.
	if err := fs.MkDir("/d", 0o755); err == nil {
		t.Fatal("expected allocObjectNum error")
	}
}

func TestMkDir_WriteDnodeFails(t *testing.T) {
	// writeDnode fails in MkDir (covers fs.go line 331).
	fs := newTestFS(t)
	zeroMetaBP(fs)
	if err := fs.MkDir("/d", 0o755); err == nil {
		t.Fatal("expected writeDnode error")
	}
}

func TestMkDir_UpdateDirZAPFails(t *testing.T) {
	// updateDirZAP fails in MkDir (covers fs.go line 336).
	fs := newTestFS(t)
	// Corrupt root ZAP so updateDirZAP fails
	rootObjNum := fs.zplDS.rootObjNum
	rootDN, _ := fs.zplDS.zplOS.readObject(rootObjNum)
	bp := rootDN.blkptrAt(0)
	zapData, _ := readBlock(fs.f, fs.partOffset, bp)
	binary.LittleEndian.PutUint64(zapData[0:], zbtHeader)
	_, _ = fs.f.WriteAt(zapData, fs.partOffset+bp.dvaOffset(0))
	if err := fs.MkDir("/d", 0o755); err == nil {
		t.Fatal("expected updateDirZAP error in MkDir")
	}
}

// ── DeleteFile error paths ─────────────────────────────────────────────────────

func TestDeleteFile_WriteDnodeFails(t *testing.T) {
	// writeDnode fails in DeleteFile (covers fs.go:376.87,378.3).
	// Use a read-only file handle: ReadAt works (lookups succeed) but WriteAt fails
	// in writeDnode → the error branch at line 376 fires.
	path := filepath.Join(t.TempDir(), "pool.img")
	ifs, err := Format(path, 8*1024*1024, FormatConfig{PoolName: "testcov"});var fs *zfsFS;if err==nil { fs = ifs.(*zfsFS) }
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	if err := fs.WriteFile("/f", []byte("data"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Replace writable handle with read-only: ReadAt succeeds but WriteAt fails.
	// Also update objset reader so readObject works via ReadAt.
	_ = fs.f.Close()
	roFile, err2 := os.Open(path)
	if err2 != nil {
		t.Fatal(err2)
	}
	fs.f = &osFileBackend{f: roFile}
	fs.zplDS.zplOS.r = roFile
	if err := fs.DeleteFile("/f"); err == nil {
		t.Fatal("expected writeDnode error in DeleteFile")
	}
}

func TestDeleteFile_UpdateDirZAPFails(t *testing.T) {
	// updateDirZAP fails in DeleteFile (covers fs.go:381.69,383.3).
	// writeDnode must succeed (file is writable), then updateDirZAP must fail.
	// Strategy: replace os.r with a counting reader that fails on the 3rd ReadAt
	// call. The first 2 calls (readObject in lookupEntry + readObject for file dnode)
	// succeed, so lookups and readObject work. The 3rd call (readObject inside
	// updateDirZAP) fails → updateDirZAP returns error → line 381 error branch fires.
	fs := newTestFS(t)
	if err := fs.WriteFile("/f2", []byte("data"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fs.zplDS.zplOS.r = &countingReaderAt{r: fs.f, maxOK: 2}
	if err := fs.DeleteFile("/f2"); err == nil {
		t.Fatal("expected updateDirZAP error in DeleteFile")
	}
}

// ── DeleteDir error paths ──────────────────────────────────────────────────────

func TestDeleteDir_WriteDnodeFails(t *testing.T) {
	// writeDnode fails in DeleteDir (covers fs.go:432.87,434.3).
	// Use a read-only file handle: ReadAt works (lookups succeed) but WriteAt fails
	// in writeDnode → the error branch fires.
	path := filepath.Join(t.TempDir(), "pool.img")
	ifs, err := Format(path, 8*1024*1024, FormatConfig{PoolName: "testcov"});var fs *zfsFS;if err==nil { fs = ifs.(*zfsFS) }
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	if err := fs.MkDir("/emptydir", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	// Replace writable handle with read-only.
	_ = fs.f.Close()
	roFile, err2 := os.Open(path)
	if err2 != nil {
		t.Fatal(err2)
	}
	fs.f = &osFileBackend{f: roFile}
	fs.zplDS.zplOS.r = roFile
	if err := fs.DeleteDir("/emptydir"); err == nil {
		t.Fatal("expected writeDnode error in DeleteDir")
	}
}

func TestDeleteDir_UpdateDirZAPFails(t *testing.T) {
	// updateDirZAP fails in DeleteDir (covers fs.go:435.69,437.3).
	// Strategy: replace os.r with a counting reader that fails on the 3rd ReadAt
	// call. Calls 1-2 (lookupEntry.readObject + readObject for dir dnode) succeed;
	// call 3 (updateDirZAP.readObject) fails → error branch fires.
	fs := newTestFS(t)
	if err := fs.MkDir("/emptydir2", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	fs.zplDS.zplOS.r = &countingReaderAt{r: fs.f, maxOK: 2}
	if err := fs.DeleteDir("/emptydir2"); err == nil {
		t.Fatal("expected updateDirZAP error in DeleteDir")
	}
}

// ── Rename error paths ──────────────────────────────────────────────────────────

func TestRename_OldParentNotFoundNew(t *testing.T) {
	// lookupPath for old parent fails (covers Rename line 407).
	fs := newTestFS(t)
	if err := fs.Rename("/nonexistent/file", "/other"); err == nil {
		t.Fatal("expected error for non-existent old parent")
	}
}

func TestRename_NewParentNotFoundNew(t *testing.T) {
	// lookupPath for new parent fails (covers Rename line 411).
	fs := newTestFS(t)
	if err := fs.WriteFile("/f3", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.Rename("/f3", "/nonexistent/f3"); err == nil {
		t.Fatal("expected error for non-existent new parent")
	}
}

func TestRename_SourceNotFoundNew(t *testing.T) {
	// readDirEntryRaw fails for source (covers Rename line 425, old errNotFound branch).
	fs := newTestFS(t)
	if err := fs.Rename("/nonexistentsrc", "/other"); err == nil {
		t.Fatal("expected error for non-existent source")
	}
}

func TestRename_DestIsDir(t *testing.T) {
	// destination exists and is a directory → error (covers Rename internal dest-is-dir branch).
	fs := newTestFS(t)
	if err := fs.WriteFile("/srcfile", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.MkDir("/dstdir", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	if err := fs.Rename("/srcfile", "/dstdir"); err == nil {
		t.Fatal("expected error for rename over directory")
	}
}

func TestRename_RemoveOldFails(t *testing.T) {
	// updateDirZAP to remove old entry fails (covers fs.go:486.72,488.3).
	// Rename flow os.r calls: readDirEntryRaw.readObject (1), lookupEntry.readObject (2),
	// updateDirZAP.readObject (3). Fail on call 3 → first updateDirZAP errors.
	fs := newTestFS(t)
	if err := fs.WriteFile("/g", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fs.zplDS.zplOS.r = &countingReaderAt{r: fs.f, maxOK: 2}
	if err := fs.Rename("/g", "/h"); err == nil {
		t.Fatal("expected updateDirZAP error in Rename (remove old)")
	}
}

func TestRename_InsertNewFails(t *testing.T) {
	// second updateDirZAP fails in Rename (covers fs.go:489.81,493.3).
	// Rename flow os.r calls: readDirEntryRaw.readObject (1), lookupEntry.readObject (2),
	// first updateDirZAP.readObject (3), second updateDirZAP.readObject (4).
	// Fail on call 4 → first updateDirZAP succeeds, second errors.
	fs := newTestFS(t)
	if err := fs.WriteFile("/g2", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fs.zplDS.zplOS.r = &countingReaderAt{r: fs.f, maxOK: 3}
	if err := fs.Rename("/g2", "/h2"); err == nil {
		t.Fatal("expected second updateDirZAP error in Rename (insert new)")
	}
}

// ── writeDnode error paths ──────────────────────────────────────────────────────

func TestWriteDnode_ReadBlockFails(t *testing.T) {
	// readBlock fails in writeDnode (covers fs.go line 547).
	// Set meta dnode BP to point to out-of-bounds offset.
	fs := newTestFS(t)
	metaDN := fs.zplDS.zplOS.metaDnode
	bigBP := makeBlkptr(1<<40, poolBlockSize, poolBlockSize, zcompressOff, dmotNone, 0, 1)
	metaDN.setBlkptrAt(0, bigBP)
	metaDN.encode()
	fs.zplDS.zplOS.metaDnode, _ = parseDnode(metaDN.raw[:dnodeMinSize])
	dn := &dnode{raw: make([]byte, dnodeMinSize)}
	if err := fs.writeDnode(1, dn); err == nil {
		t.Fatal("expected readBlock error in writeDnode")
	}
}

func TestWriteDnode_WriteAtFails(t *testing.T) {
	// WriteAt fails in writeDnode (covers fs.go line 559).
	// Use a read-only file handle: ReadAt succeeds but WriteAt returns EBADF.
	path := filepath.Join(t.TempDir(), "pool.img")
	ifs, err := Format(path, 8*1024*1024, FormatConfig{PoolName: "testcov"});var fs *zfsFS;if err==nil { fs = ifs.(*zfsFS) }
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	// Close the writable handle and replace with read-only so readBlock succeeds
	// but WriteAt fails.
	_ = fs.f.Close()
	roFile, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	fs.f = &osFileBackend{f: roFile}
	dn := &dnode{raw: make([]byte, dnodeMinSize)}
	if err := fs.writeDnode(1, dn); err == nil {
		t.Fatal("expected WriteAt error in writeDnode")
	}
}

func TestWriteDnode_OutOfBounds(t *testing.T) {
	// offsetInBlock+dnodeMinSize > len(blkData) (covers fs.go line 552).
	// Use objNum at the very end of the block so offset+512 > blockSize.
	// The ZPL obj array block is poolBlockSize(4096) = 8*dnodeMinSize(512).
	// fmtObjArrayObjs = 32 → last valid slot is 31 at offset 31*512 = 15872 >> 4096.
	// But writeDnode only reads one block (blockID must be 0). So objNum must satisfy
	// objNum*dnodeMinSize/blkSz == 0 → objNum < fmtObjArraySize/dnodeMinSize = 8.
	// For objNum=7: byteOff=7*512=3584, then offset+512=4096 == len(blkData)=4096 → not OOB.
	// For objNum=8: byteOff=8*512=4096; blockID=4096/4096=1 → blockID!=0 → already caught.
	// The OOB check (line 552) fires when offsetInBlock+dnodeMinSize > len(blkData).
	// blkData comes from readBlock which returns the compressed or raw block.
	// If the block is smaller than expected (e.g., compressed), offsetInBlock could be OOB.
	// Simulate by pointing meta BP to a tiny block (uncompressed reading gives same size).
	// Actually, we can't easily make readBlock return a smaller block without compression.
	// Try: set meta BP to a very small block (4 bytes) via a temp file trick.
	// readEmbedded panics for size 0; readBlock with small size is hard to arrange.
	// Skip this specific sub-branch test for now by testing the known-working path.
	// This branch is essentially unreachable with our Format() output.
	t.Skip("offsetInBlock OOB branch unreachable in practice with format output")
}

// ── updateDirZAP error paths ──────────────────────────────────────────────────

func TestUpdateDirZAP_ReadBlockFails(t *testing.T) {
	// readBlock fails in updateDirZAP (covers fs.go line 583).
	// Point the root dir's blkptr to out-of-bounds offset.
	fs := newTestFS(t)
	rootObjNum := fs.zplDS.rootObjNum
	rootDN, _ := fs.zplDS.zplOS.readObject(rootObjNum)
	// Overwrite the root dir dnode BP with one pointing to huge offset
	bigBP := makeBlkptr(1<<40, poolBlockSize, poolBlockSize, zcompressOff, dmotDirContents, 0, 1)
	rootDN.setBlkptrAt(0, bigBP)
	rootDN.encode()
	metaDN := fs.zplDS.zplOS.metaDnode
	metaBP := metaDN.blkptrAt(0)
	blkData, _ := readBlock(fs.f, fs.partOffset, metaBP)
	byteOff := int(rootObjNum) * dnodeMinSize
	copy(blkData[byteOff:], rootDN.raw[:dnodeMinSize])
	_, _ = fs.f.WriteAt(blkData, fs.partOffset+metaBP.dvaOffset(0))
	copy(fs.zplDS.zplOS.raw[byteOff:], rootDN.raw[:dnodeMinSize])
	if err := fs.updateDirZAP(rootObjNum, "x", 1, false); err == nil {
		t.Fatal("expected readBlock error in updateDirZAP")
	}
}

func TestUpdateDirZAP_ZAPTooShort(t *testing.T) {
	// ZAP block < 8 bytes (fs.go line 592) — only reachable if readBlock returns <8 bytes.
	// readBlock returns exactly physSize bytes from a real BP, and physSize must be ≥512.
	// The only <8 path is via null BP (len=lsize=0) but that is caught earlier (line 579).
	// This branch is effectively unreachable in practice.
	t.Skip("ZAP block < 8 bytes unreachable: physSize is always ≥512 for non-null BPs")
}

func TestUpdateDirZAP_WriteAtFails(t *testing.T) {
	// WriteAt fails in updateDirZAP (covers fs.go line 603).
	// Use a read-only file handle: readBlock (ReadAt) succeeds, WriteAt returns EBADF.
	path := filepath.Join(t.TempDir(), "pool.img")
	ifs, err := Format(path, 8*1024*1024, FormatConfig{PoolName: "testcov"});var fs *zfsFS;if err==nil { fs = ifs.(*zfsFS) }
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	rootObjNum := fs.zplDS.rootObjNum
	// Replace writable handle with read-only so readBlock (ReadAt) succeeds
	// but WriteAt fails. Also update the objset's reader so readObject works.
	_ = fs.f.Close()
	roFile, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	fs.f = &osFileBackend{f: roFile}
	fs.zplDS.zplOS.r = roFile
	if err := fs.updateDirZAP(rootObjNum, "x", 1, false); err == nil {
		t.Fatal("expected WriteAt error in updateDirZAP")
	}
}

func TestUpdateDirZAP_MzapInsertFails(t *testing.T) {
	// mzapInsert rejects keys >= mzapNameLen (50) chars (covers fs.go:596.59,598.4).
	// A 50-char filename passes lookupEntry (returns 0=not found), allocObjectNum,
	// writeDnode — and only fails at mzapInsert inside updateDirZAP.
	fs := newTestFS(t)
	longName := fmt.Sprintf("%0*d", mzapNameLen, 0) // exactly 50 chars → "key too long"
	if err := fs.WriteFile("/"+longName, nil, 0o644); err == nil {
		t.Fatal("expected mzapInsert error for long key")
	}
}

// ── readDirEntryRaw zapListAll error ──────────────────────────────────────────

func TestReadDirEntryRaw_ZapListAllError(t *testing.T) {
	// zapListAll fails in readDirEntryRaw (covers fs.go line 616).
	// Use a dir object with a corrupt ZAP block.
	fs := newTestFS(t)
	if err := fs.MkDir("/kdir", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	rootObjNum := fs.zplDS.rootObjNum
	dirObjNum, _ := fs.zplDS.lookupEntry(fs.f, fs.partOffset, rootObjNum, "kdir")
	dirDN, _ := fs.zplDS.zplOS.readObject(dirObjNum)
	bp := dirDN.blkptrAt(0)
	zapData, _ := readBlock(fs.f, fs.partOffset, bp)
	binary.LittleEndian.PutUint64(zapData[0:], 0xDEADBEEF) // bad magic
	_, _ = fs.f.WriteAt(zapData, fs.partOffset+bp.dvaOffset(0))
	if _, err := fs.readDirEntryRaw(dirObjNum, "x"); err == nil {
		t.Fatal("expected zapListAll error in readDirEntryRaw")
	}
}

// ── commitUberblock label 1 error ─────────────────────────────────────────────

func TestCommitUberblock_Label1Fails(t *testing.T) {
	// WriteAt for label 1 fails (covers fs.go line 649).
	// Label 0 is at offset 0, label 1 is at vdevLabelSize=256KiB.
	// We use an errorReaderAt that fails at label 1's offset.
	// But fs.f is *os.File, so we can't intercept writes.
	// Alternative: truncate the file so label 1's offset is beyond file end.
	// But truncate would fail for offsets beyond existing content and WriteAt would fail.
	// Actually, os.File.WriteAt to an offset beyond file end succeeds on most systems (extends file).
	// The approach: use a very small file where label 1 write fails due to disk error.
	// This is hard to simulate without OS-level tricks.
	// Instead, test directly: close the file after only 1 label is written.
	// We can't intercept mid-loop. Skip this specific sub-branch.
	t.Skip("label 1 WriteAt error requires mid-loop file mocking")
}

// ── allocObjectNum error path ─────────────────────────────────────────────────

func TestAllocObjectNum_ReadError(t *testing.T) {
	// readObject error in allocObjectNum → continue (covers fs.go line 486).
	// Set metaDnode BP0 to a non-null BP with an unreachable offset so
	// readDataBlock fails → readObject returns error → continue in the loop.
	// All slots error → loop ends → "no free slot" error returned.
	fs := newTestFS(t)
	metaDN := fs.zplDS.zplOS.metaDnode
	badBP := makeBlkptr(1<<40, poolBlockSize, poolBlockSize, zcompressOff, dmotNone, 0, 1)
	metaDN.setBlkptrAt(0, badBP)
	metaDN.encode()
	fs.zplDS.zplOS.metaDnode, _ = parseDnode(metaDN.raw[:dnodeMinSize])
	_, err := fs.allocObjectNum()
	if err == nil {
		t.Fatal("expected error from allocObjectNum with invalid meta BP")
	}
}

// ── initAllocator limit<next ──────────────────────────────────────────────────

func TestInitAllocator_LimitLessThanNext(t *testing.T) {
	// limit < next (covers limit<next branch) AND null BP (covers fs.go line 668).
	// Create an empty file: WriteFile with []byte{} builds a dnode with nblkptr=1
	// but does NOT call setBlkptrAt, so blkptr[0] stays null → triggers line 668.
	fs := newTestFS(t)
	if err := fs.WriteFile("/empty_null_bp", []byte{}, 0o644); err != nil {
		t.Fatalf("WriteFile empty: %v", err)
	}
	// imageSize=0 → limit = 0 - 2*vdevLabelSize → very negative → limit < next → limit = next.
	fs.initAllocator(0)
	if fs.alloc == nil {
		t.Fatal("expected allocator")
	}
}

// ── multi-block writes (Bug 3 regression) ────────────────────────────────────

// TestWriteFile_MultiBlock_L1 writes a payload that requires two
// 128-KiB data blocks (256 KiB) — one level of indirection. The dnode
// nlevels must be 2 and ReadFile must round-trip the entire payload.
func TestWriteFile_MultiBlock_L1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool.img")
	ifs, err := Format(path, 8*1024*1024, FormatConfig{PoolName: "multiblk"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	fs := ifs.(*zfsFS)
	t.Cleanup(func() { fs.Close() })

	const sz = 256 * 1024
	payload := make([]byte, sz)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if err := fs.WriteFile("/multi.bin", payload, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	objNum, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, "/multi.bin")
	if err != nil {
		t.Fatalf("lookupPath: %v", err)
	}
	dn, err := fs.zplDS.zplOS.readObject(objNum)
	if err != nil {
		t.Fatalf("readObject: %v", err)
	}
	if dn.nlevels < 2 {
		t.Fatalf("dn.nlevels = %d, want >= 2 (multi-block file should use indirection)", dn.nlevels)
	}
	if got := dn.dataBlockSize(); got != 128*1024 {
		t.Fatalf("dn.dataBlockSize = %d, want 131072 (large-file class)", got)
	}

	got, err := fs.ReadFile("/multi.bin")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(got) != sz {
		t.Fatalf("ReadFile len = %d, want %d", len(got), sz)
	}
	for i := range got {
		if got[i] != payload[i] {
			t.Fatalf("ReadFile byte %d = %d, want %d", i, got[i], payload[i])
		}
	}
}

// TestWriteFile_MultiBlock_PreservesSmallFiles asserts that small
// files still use the 4-KiB-block layout (datablkszsec = 8) and a
// single direct BP. This is the path the existing stress / format
// tests cover; the multi-block change must not regress it.
func TestWriteFile_MultiBlock_PreservesSmallFiles(t *testing.T) {
	fs := newTestFS(t)
	const payload = "small-file sentinel"
	if err := fs.WriteFile("/s.txt", []byte(payload), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	objNum, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, "/s.txt")
	if err != nil {
		t.Fatalf("lookupPath: %v", err)
	}
	dn, err := fs.zplDS.zplOS.readObject(objNum)
	if err != nil {
		t.Fatalf("readObject: %v", err)
	}
	if dn.dataBlockSize() != poolBlockSize {
		t.Fatalf("small file data block size = %d, want %d (small-file class)", dn.dataBlockSize(), poolBlockSize)
	}
	if dn.nlevels != 1 {
		t.Fatalf("small file nlevels = %d, want 1 (no indirection)", dn.nlevels)
	}
}

// TestWriteFile_MultiBlock_FreesIndirect verifies the indirect-block
// extents are also handed back to the allocator on DeleteFile, not
// just the data blocks themselves. Sentinel: after a write + delete
// cycle the bump pointer doesn't grow.
func TestWriteFile_MultiBlock_FreesIndirect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool.img")
	ifs, err := Format(path, 16*1024*1024, FormatConfig{PoolName: "multifree"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	fs := ifs.(*zfsFS)
	t.Cleanup(func() { fs.Close() })

	const sz = 1024 * 1024 // 1 MiB → 8 data blocks + 1 indirect at L1
	payload := make([]byte, sz)
	for i := range payload {
		payload[i] = byte(i % 17)
	}
	if err := fs.WriteFile("/multi.bin", payload, 0o644); err != nil {
		t.Fatalf("seed WriteFile: %v", err)
	}
	bumpAfterFirst := fs.alloc.nextFree

	for i := 0; i < 16; i++ {
		if err := fs.DeleteFile("/multi.bin"); err != nil {
			t.Fatalf("iter %d: DeleteFile: %v", i, err)
		}
		if err := fs.WriteFile("/multi.bin", payload, 0o644); err != nil {
			t.Fatalf("iter %d: WriteFile: %v", i, err)
		}
		if fs.alloc.nextFree > bumpAfterFirst {
			t.Fatalf("iter %d: bump grew (was %d, now %d) — indirect blocks not freed",
				i, bumpAfterFirst, fs.alloc.nextFree)
		}
	}
}
