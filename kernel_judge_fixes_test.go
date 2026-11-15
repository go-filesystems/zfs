package filesystem_zfs

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// The pool label Format writes must say EXPORTED, or zpool import refuses the
// image without -f ("previously in use from another system", #52). The state is
// an XDR uint64 nvpair: name length, name padded to 4, type, nelems, value.
func TestFormatMarksThePoolExported(t *testing.T) {
	img := filepath.Join(t.TempDir(), "z.img")
	f, err := Format(img, 256<<20, FormatConfig{PoolName: "kjz"})
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	b, err := os.ReadFile(img)
	if err != nil {
		t.Fatal(err)
	}
	label := b[16<<10 : 128<<10] // the vdev nvlist area of label 0
	i := bytes.Index(label, []byte("state"))
	if i < 0 {
		t.Fatal("no state pair in label 0")
	}
	// "state" is 5 bytes: padded to 8 in XDR; then type (4), nelems (4), value (8).
	if got := binary.BigEndian.Uint64(label[i+8+8:]); got != 1 {
		t.Fatalf("pool state %d, want 1 (POOL_STATE_EXPORTED)", got)
	}
}
