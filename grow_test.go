package filesystem_zfs

import (
	"os"
	"path/filepath"
	"testing"
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
