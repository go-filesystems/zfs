package filesystem_zfs

import (
	"path/filepath"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

// TestSymlinkRoundTrip verifies the driver now exposes filesystem.Symlinker
// and that a created symlink reads back through the standard ReadLink path,
// including after a close + re-open (the on-disk shape must persist).
func TestSymlinkRoundTrip(t *testing.T) {
	imgPath := filepath.Join(t.TempDir(), "symlink.img")
	fs, err := Format(imgPath, compatwPoolSize, FormatConfig{PoolName: compatwPoolName})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	sl, ok := fs.(filesystem.Symlinker)
	if !ok {
		fs.Close()
		t.Fatal("zfs FS does not satisfy filesystem.Symlinker")
	}
	const target = "/some/target/path"
	if err := sl.Symlink(target, "/link"); err != nil {
		fs.Close()
		t.Fatalf("Symlink: %v", err)
	}
	got, err := fs.ReadLink("/link")
	if err != nil {
		fs.Close()
		t.Fatalf("ReadLink: %v", err)
	}
	if got != target {
		fs.Close()
		t.Fatalf("ReadLink = %q, want %q", got, target)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Re-open and confirm the symlink target survives a round-trip to disk.
	fs2, err := Open(imgPath, -1)
	if err != nil {
		t.Fatalf("Open(reopen): %v", err)
	}
	defer fs2.Close()
	if got, err := fs2.ReadLink("/link"); err != nil || got != target {
		t.Fatalf("post-reopen ReadLink = %q, %v; want %q", got, err, target)
	}
}
