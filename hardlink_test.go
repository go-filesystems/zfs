package filesystem_zfs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

// TestLink_BasicAndNlinkAwareDelete exercises the full hard-link
// lifecycle in a single freshly Format()'d pool:
//
//   - Create a file, Link a second name to it.
//   - Both names resolve to the SAME inode (object number).
//   - The source inode's SA links count is 2.
//   - Both names read back identical content.
//   - Deleting one name leaves the inode live: the other name still
//     reads its content and the object is NOT freed (links back to 1).
//   - Deleting the second (last) name removes the file for good.
func TestLink_BasicAndNlinkAwareDelete(t *testing.T) {
	fs := newTestFS(t)

	content := []byte("hard-linked payload")
	if err := fs.WriteFile("/a", content, 0o644); err != nil {
		t.Fatalf("WriteFile /a: %v", err)
	}
	if err := fs.Link("/a", "/b"); err != nil {
		t.Fatalf("Link /a -> /b: %v", err)
	}

	// Both names resolve to the same inode.
	stA, err := fs.Stat("/a")
	if err != nil {
		t.Fatalf("Stat /a: %v", err)
	}
	stB, err := fs.Stat("/b")
	if err != nil {
		t.Fatalf("Stat /b: %v", err)
	}
	if stA.Inode() != stB.Inode() {
		t.Fatalf("hard link inode mismatch: /a=%d /b=%d", stA.Inode(), stB.Inode())
	}
	objNum := stA.Inode()

	// SA links count is 2.
	attrs, err := fs.zplDS.readAttrs(objNum)
	if err != nil {
		t.Fatalf("readAttrs after Link: %v", err)
	}
	if attrs.links != 2 {
		t.Fatalf("links after Link = %d, want 2", attrs.links)
	}

	// Identical content via both names.
	gotA, err := fs.ReadFile("/a")
	if err != nil {
		t.Fatalf("ReadFile /a: %v", err)
	}
	gotB, err := fs.ReadFile("/b")
	if err != nil {
		t.Fatalf("ReadFile /b: %v", err)
	}
	if !bytes.Equal(gotA, content) || !bytes.Equal(gotB, content) {
		t.Fatalf("content mismatch: /a=%q /b=%q want %q", gotA, gotB, content)
	}

	// Delete one name — the inode must survive (links 2 -> 1, object
	// NOT freed) and the surviving name must still read its content.
	if err := fs.DeleteFile("/a"); err != nil {
		t.Fatalf("DeleteFile /a: %v", err)
	}
	if _, err := fs.Stat("/a"); err == nil {
		t.Fatalf("Stat /a should fail after delete")
	}
	stB2, err := fs.Stat("/b")
	if err != nil {
		t.Fatalf("Stat /b after deleting /a: %v", err)
	}
	if stB2.Inode() != objNum {
		t.Fatalf("/b inode changed after deleting /a: got %d want %d", stB2.Inode(), objNum)
	}
	attrs, err = fs.zplDS.readAttrs(objNum)
	if err != nil {
		t.Fatalf("readAttrs after first delete: %v", err)
	}
	if attrs.links != 1 {
		t.Fatalf("links after first delete = %d, want 1", attrs.links)
	}
	gotB, err = fs.ReadFile("/b")
	if err != nil {
		t.Fatalf("ReadFile /b after deleting /a: %v", err)
	}
	if !bytes.Equal(gotB, content) {
		t.Fatalf("/b content after deleting /a = %q, want %q", gotB, content)
	}

	// The dnode must still be a live regular file (not zeroed/freed).
	dn, err := fs.zplDS.zplOS.readObject(objNum)
	if err != nil {
		t.Fatalf("readObject after first delete: %v", err)
	}
	if dn.typ != dmotPlainFileContents {
		t.Fatalf("inode type after first delete = %d, want %d (object was freed!)",
			dn.typ, dmotPlainFileContents)
	}

	// Delete the second (last) name — file is gone for good.
	if err := fs.DeleteFile("/b"); err != nil {
		t.Fatalf("DeleteFile /b: %v", err)
	}
	if _, err := fs.Stat("/b"); err == nil {
		t.Fatalf("Stat /b should fail after deleting last link")
	}
}

// TestLink_RejectsDirectoriesAndExisting checks the error paths that
// POSIX link(2) requires.
func TestLink_RejectsDirectoriesAndExisting(t *testing.T) {
	fs := newTestFS(t)

	if err := fs.MkDir("/d", 0o755); err != nil {
		t.Fatalf("MkDir /d: %v", err)
	}
	if err := fs.Link("/d", "/d2"); err == nil {
		t.Fatalf("Link of a directory should fail")
	}

	if err := fs.WriteFile("/f", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile /f: %v", err)
	}
	if err := fs.WriteFile("/g", []byte("y"), 0o644); err != nil {
		t.Fatalf("WriteFile /g: %v", err)
	}
	if err := fs.Link("/f", "/g"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("Link onto existing path = %v, want os.ErrExist", err)
	}

	if err := fs.Link("/missing", "/h"); err == nil {
		t.Fatalf("Link of missing source should fail")
	}
}

// TestLink_SurvivesReopen verifies a hard link persists across a
// close + fresh Open, using the same Format(...compatw...)+Open dance
// the rest of the zfs write tests use.
func TestLink_SurvivesReopen(t *testing.T) {
	imgPath := filepath.Join(t.TempDir(), compatwPoolName+".img")
	ifs, err := Format(imgPath, compatwPoolSize, FormatConfig{PoolName: compatwPoolName})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	content := []byte("persist me")
	if err := ifs.WriteFile("/orig", content, 0o644); err != nil {
		t.Fatalf("WriteFile /orig: %v", err)
	}
	hl, ok := ifs.(filesystem.HardLinker)
	if !ok {
		t.Fatalf("Format returned %T, which is not a filesystem.HardLinker", ifs)
	}
	if err := hl.Link("/orig", "/alias"); err != nil {
		t.Fatalf("Link /orig -> /alias: %v", err)
	}
	if err := ifs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(imgPath, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer reopened.Close()

	stO, err := reopened.Stat("/orig")
	if err != nil {
		t.Fatalf("Stat /orig after reopen: %v", err)
	}
	stA, err := reopened.Stat("/alias")
	if err != nil {
		t.Fatalf("Stat /alias after reopen: %v", err)
	}
	if stO.Inode() != stA.Inode() {
		t.Fatalf("after reopen, link inode mismatch: /orig=%d /alias=%d",
			stO.Inode(), stA.Inode())
	}

	fs, ok := reopened.(*zfsFS)
	if !ok {
		t.Fatalf("Open returned %T, want *zfsFS", reopened)
	}
	attrs, err := fs.zplDS.readAttrs(stO.Inode())
	if err != nil {
		t.Fatalf("readAttrs after reopen: %v", err)
	}
	if attrs.links != 2 {
		t.Fatalf("links after reopen = %d, want 2", attrs.links)
	}

	got, err := reopened.ReadFile("/alias")
	if err != nil {
		t.Fatalf("ReadFile /alias after reopen: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("/alias content after reopen = %q, want %q", got, content)
	}
}
