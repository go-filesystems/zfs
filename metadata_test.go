package filesystem_zfs

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
)

// TestMetadataSetter sets mode/owner/times on a file and verifies the SA
// attributes round-trip (including across a close/re-open), without disturbing
// the file's data.
func TestMetadataSetter(t *testing.T) {
	imgPath := filepath.Join(t.TempDir(), "meta.img")
	fs, err := Format(imgPath, compatwPoolSize, FormatConfig{PoolName: compatwPoolName})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	ms, ok := fs.(filesystem.MetadataSetter)
	if !ok {
		fs.Close()
		t.Fatal("zfs FS does not satisfy filesystem.MetadataSetter")
	}
	if err := fs.WriteFile("/f", []byte("payload"), 0o644); err != nil {
		fs.Close()
		t.Fatalf("WriteFile: %v", err)
	}
	before := uint64(time.Now().Unix()) - 1

	if err := ms.Chmod("/f", 0o600|os.ModeSetuid); err != nil {
		fs.Close()
		t.Fatalf("Chmod: %v", err)
	}
	const wantUID, wantGID = uint32(0x12345), uint32(0x6789A)
	if err := ms.Chown("/f", wantUID, wantGID); err != nil {
		fs.Close()
		t.Fatalf("Chown: %v", err)
	}
	at := time.Unix(1_000_000_000, 0)
	mt := time.Unix(1_500_000_000, 0)
	if err := ms.Chtimes("/f", at, mt); err != nil {
		fs.Close()
		t.Fatalf("Chtimes: %v", err)
	}

	// Verify the SA attributes directly.
	zfs := fs.(*zfsFS)
	objNum, err := zfs.zplDS.lookupPath(zfs.f, zfs.partOffset, "/f")
	if err != nil {
		fs.Close()
		t.Fatalf("lookupPath: %v", err)
	}
	attrs, err := zfs.zplDS.readAttrs(objNum)
	if err != nil {
		fs.Close()
		t.Fatalf("readAttrs: %v", err)
	}
	if attrs.mode&0o170000 != 0o100000 {
		t.Fatalf("type bits clobbered: mode=0o%o", attrs.mode)
	}
	if attrs.mode&0o7777 != 0o4600 {
		t.Fatalf("mode perm = 0o%o, want 0o4600", attrs.mode&0o7777)
	}
	if attrs.uid != uint64(wantUID) || attrs.gid != uint64(wantGID) {
		t.Fatalf("uid/gid = %#x/%#x, want %#x/%#x", attrs.uid, attrs.gid, wantUID, wantGID)
	}
	if attrs.atime[0] != uint64(at.Unix()) || attrs.mtime[0] != uint64(mt.Unix()) {
		t.Fatalf("atime/mtime = %d/%d, want %d/%d", attrs.atime[0], attrs.mtime[0], at.Unix(), mt.Unix())
	}
	if attrs.ctime[0] < before {
		t.Fatalf("ctime %d not refreshed (>= %d expected)", attrs.ctime[0], before)
	}

	// Data must be untouched, and the mode must persist across a re-open.
	if got, err := fs.ReadFile("/f"); err != nil || string(got) != "payload" {
		t.Fatalf("ReadFile after setattr = %q, %v; want payload", got, err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	fs2, err := Open(imgPath, -1)
	if err != nil {
		t.Fatalf("Open(reopen): %v", err)
	}
	defer fs2.Close()
	st, err := fs2.Stat("/f")
	if err != nil {
		t.Fatalf("Stat after reopen: %v", err)
	}
	if st.Mode()&0o7777 != 0o4600 {
		t.Fatalf("post-reopen mode = 0o%o, want 0o4600", st.Mode()&0o7777)
	}
}
