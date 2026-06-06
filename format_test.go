package filesystem_zfs

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestFormatAndRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool.img")
	const size = 8 * 1024 * 1024 // 8 MiB

	// ── Format ────────────────────────────────────────────────────────────────
	ifs, err := Format(path, size, FormatConfig{PoolName: "testpool"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer ifs.Close()
	fs := ifs.(*zfsFS)

	if fs.zplDS == nil {
		t.Fatal("Format: ZPL dataset not opened after format")
	}

	// ── Stat root ─────────────────────────────────────────────────────────────
	st, err := fs.Stat("/")
	if err != nil {
		t.Fatalf("Stat(/): %v", err)
	}
	if st.Mode()&0o170000 != 0o040000 {
		t.Fatalf("Stat(/).Mode() = 0o%o, want directory", st.Mode())
	}

	// ── ListDir empty root ────────────────────────────────────────────────────
	entries, err := fs.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir(/): %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("ListDir(/) = %d entries, want 0", len(entries))
	}

	// ── WriteFile and ReadFile ────────────────────────────────────────────────
	data := []byte("hello, ZFS world!\n")
	if err := fs.WriteFile("/hello.txt", data, 0o644); err != nil {
		t.Fatalf("WriteFile(/hello.txt): %v", err)
	}

	got, err := fs.ReadFile("/hello.txt")
	if err != nil {
		t.Fatalf("ReadFile(/hello.txt): %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("ReadFile(/hello.txt) = %q, want %q", got, data)
	}

	// ── Stat file ─────────────────────────────────────────────────────────────
	st, err = fs.Stat("/hello.txt")
	if err != nil {
		t.Fatalf("Stat(/hello.txt): %v", err)
	}
	if st.Size() != uint64(len(data)) {
		t.Fatalf("Stat(/hello.txt).Size() = %d, want %d", st.Size(), len(data))
	}
	if st.Mode()&0o170000 != 0o0100000 {
		t.Fatalf("Stat(/hello.txt).Mode() = 0o%o, want regular file", st.Mode())
	}

	// ── ListDir shows new file ─────────────────────────────────────────────────
	entries, err = fs.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir(/) after write: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("ListDir(/) = %d entries, want 1", len(entries))
	}
	if entries[0].Name() != "hello.txt" {
		t.Fatalf("ListDir(/) entry = %q, want hello.txt", entries[0].Name())
	}

	// ── MkDir ────────────────────────────────────────────────────────────────
	if err := fs.MkDir("/subdir", 0o755); err != nil {
		t.Fatalf("MkDir(/subdir): %v", err)
	}

	st, err = fs.Stat("/subdir")
	if err != nil {
		t.Fatalf("Stat(/subdir): %v", err)
	}
	if st.Mode()&0o170000 != 0o040000 {
		t.Fatalf("Stat(/subdir).Mode() = 0o%o, want directory", st.Mode())
	}

	// ── Write file inside subdir ───────────────────────────────────────────────
	nested := []byte("nested content")
	if err := fs.WriteFile("/subdir/nested.txt", nested, 0o644); err != nil {
		t.Fatalf("WriteFile(/subdir/nested.txt): %v", err)
	}
	gotNested, err := fs.ReadFile("/subdir/nested.txt")
	if err != nil {
		t.Fatalf("ReadFile(/subdir/nested.txt): %v", err)
	}
	if !bytes.Equal(gotNested, nested) {
		t.Fatalf("ReadFile(/subdir/nested.txt) mismatch")
	}

	// ── Rename file ────────────────────────────────────────────────────────────
	if err := fs.Rename("/hello.txt", "/renamed.txt"); err != nil {
		t.Fatalf("Rename(/hello.txt, /renamed.txt): %v", err)
	}
	if _, err := fs.Stat("/hello.txt"); err == nil {
		t.Fatal("Stat(/hello.txt) after rename: expected error, got nil")
	}
	renamedData, err := fs.ReadFile("/renamed.txt")
	if err != nil {
		t.Fatalf("ReadFile(/renamed.txt) after rename: %v", err)
	}
	if !bytes.Equal(renamedData, data) {
		t.Fatalf("ReadFile(/renamed.txt) = %q, want %q", renamedData, data)
	}

	// ── DeleteFile ─────────────────────────────────────────────────────────────
	if err := fs.DeleteFile("/renamed.txt"); err != nil {
		t.Fatalf("DeleteFile(/renamed.txt): %v", err)
	}
	if _, err := fs.Stat("/renamed.txt"); err == nil {
		t.Fatal("Stat(/renamed.txt) after delete: expected error, got nil")
	}

	// ── DeleteDir ──────────────────────────────────────────────────────────────
	// Must fail on non-empty dir.
	if err := fs.DeleteDir("/subdir"); err == nil {
		t.Fatal("DeleteDir(/subdir): expected error on non-empty dir, got nil")
	}
	// Delete the file inside first.
	if err := fs.DeleteFile("/subdir/nested.txt"); err != nil {
		t.Fatalf("DeleteFile(/subdir/nested.txt): %v", err)
	}
	if err := fs.DeleteDir("/subdir"); err != nil {
		t.Fatalf("DeleteDir(/subdir): %v", err)
	}
	if _, err := fs.Stat("/subdir"); err == nil {
		t.Fatal("Stat(/subdir) after delete: expected error, got nil")
	}

	// ── Close and reopen: verify persistence ──────────────────────────────────
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	fs2, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open after format: %v", err)
	}
	defer fs2.Close()

	// Root should still be a directory.
	st2, err := fs2.Stat("/")
	if err != nil {
		t.Fatalf("Stat(/) after reopen: %v", err)
	}
	if st2.Mode()&0o170000 != 0o040000 {
		t.Fatalf("Stat(/).Mode() after reopen = 0o%o, want directory", st2.Mode())
	}
}

func TestFormatTooSmall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tiny.img")
	if _, err := Format(path, 1024*1024, FormatConfig{}); err == nil {
		t.Fatal("Format(too small): expected error, got nil")
	}
}

func TestFormatDefaultPoolName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool.img")
	ifs, err := Format(path, 4*1024*1024, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer ifs.Close()
	fs := ifs.(*zfsFS)
	if fs.zplDS == nil {
		t.Fatal("Format: ZPL dataset not opened with default pool name")
	}
}

func TestWriteAndOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool.img")
	fs, err := Format(path, 8*1024*1024, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()

	v1 := []byte("version 1")
	v2 := []byte("version 2 – updated content")
	if err := fs.WriteFile("/data.txt", v1, 0o644); err != nil {
		t.Fatalf("WriteFile v1: %v", err)
	}
	got, _ := fs.ReadFile("/data.txt")
	if !bytes.Equal(got, v1) {
		t.Fatalf("ReadFile v1 mismatch")
	}

	// Overwrite
	if err := fs.WriteFile("/data.txt", v2, 0o644); err != nil {
		t.Fatalf("WriteFile v2: %v", err)
	}
	got2, err := fs.ReadFile("/data.txt")
	if err != nil {
		t.Fatalf("ReadFile v2: %v", err)
	}
	if !bytes.Equal(got2, v2) {
		t.Fatalf("ReadFile v2 = %q, want %q", got2, v2)
	}
}

func TestBuildLabel_TruncatesLargeInputs(t *testing.T) {
	// nvBuf > 112*1024 bytes → truncated to 112KiB; ub > uberblockSize → truncated.
	nvBuf := make([]byte, 113*1024)
	ub := make([]byte, uberblockSize+100)
	label := buildLabel(nvBuf, ub)
	if len(label) != vdevLabelSize {
		t.Fatalf("buildLabel len = %d, want %d", len(label), vdevLabelSize)
	}
}
