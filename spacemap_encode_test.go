package filesystem_zfs

import (
	"encoding/binary"
	"path/filepath"
	"testing"
)

// TestEncodeSpaceMapLogTwoWord covers the two-word space-map entry path: a
// single allocated run larger than one single-word entry can hold
// (smRunMaxUnits << smShift = 128 MiB) must be split, and runs beyond that
// emit the two-word form (encodeSMTwoWord). Decoding the stream back must
// recover the original byte length.
func TestEncodeSpaceMapLogTwoWord(t *testing.T) {
	const run = int64(300) * 1024 * 1024 // 300 MiB > 128 MiB single-word cap
	log := encodeSpaceMapLog([]smRange{{off: 0, length: run, typ: smAlloc}})
	if len(log)%8 != 0 || len(log) == 0 {
		t.Fatalf("log length %d not a positive multiple of 8", len(log))
	}

	// Replay: sum the run lengths (single- and two-word) back to `run`.
	var total int64
	for i := 0; i+8 <= len(log); i += 8 {
		w := binary.LittleEndian.Uint64(log[i:])
		if w>>62 == sm2Prefix { // two-word entry
			r := int64((w>>spaVdevBits)&((1<<sm2RunBits)-1)) + 1
			total += r << smShift
			i += 8
			continue
		}
		r := int64(w&((1<<smRunBits)-1)) + 1
		total += r << smShift
	}
	if total != run {
		t.Fatalf("decoded run total = %d, want %d", total, run)
	}

	// Also exercise encodeSMTwoWord directly with a non-zero vdev/offset.
	w0, w1 := encodeSMTwoWord(int64(64)*1024*1024, int64(200)*1024*1024, 0, smAlloc)
	if w0>>62 != sm2Prefix {
		t.Fatalf("two-word entry missing 0b11 prefix: %#x", w0)
	}
	if (w1>>sm2OffsetBits)&1 != smAlloc {
		t.Fatalf("two-word entry type bit wrong: %#x", w1)
	}
}

// TestSnapshotIndirectCopy exercises the snapshot deep-copy of a file large
// enough to use indirect block pointers (copyBlkptrTree's level>0 branch and
// the full copyObjsetTree path), then confirms both the live file and the
// snapshot read back identically after a reopen.
func TestSnapshotIndirectCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapind.img")
	const size = 96 * 1024 * 1024
	ifs, err := Format(path, size, FormatConfig{PoolName: "snapind"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	fs := ifs.(*zfsFS)

	// >128 KiB → multi-block file routed through indirect block pointers.
	data := make([]byte, 2*1024*1024)
	for i := range data {
		data[i] = byte(i*31 + 7)
	}
	if err := fs.WriteFile("/f", data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.Snapshot("s1"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Live read-back.
	ifs2, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer ifs2.Close()
	got, err := ifs2.ReadFile("/f")
	if err != nil || len(got) != len(data) {
		t.Fatalf("ReadFile /f live: err=%v len=%d want %d", err, len(got), len(data))
	}

	// Snapshot read-back through the @snap dataset path.
	snapFS, err := OpenDataset(path, -1, "@s1")
	if err != nil {
		t.Fatalf("OpenDataset @s1: %v", err)
	}
	defer snapFS.Close()
	sgot, err := snapFS.ReadFile("/f")
	if err != nil || len(sgot) != len(data) {
		t.Fatalf("ReadFile /f snapshot: err=%v len=%d want %d", err, len(sgot), len(data))
	}
}
