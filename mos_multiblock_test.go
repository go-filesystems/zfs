package filesystem_zfs

import (
	"path/filepath"
	"testing"
)

// TestMOSMultiBlock checks that the MOS object array is laid out as a
// multi-block meta_dnode (fmtMOSObjArrayBlocks dnode blocks of the fixed
// 16 KiB ZFS dnode-block size), so it has room for both the per-metaslab
// space_maps and runtime snapshot objects without a too-large dnode block
// (which aborts zdb at dnode_slots_hold). It also confirms objects beyond
// the first block are reachable through the read path.
func TestMOSMultiBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mb.img")
	const size = 256 * 1024 * 1024
	ifs, err := Format(path, size, FormatConfig{PoolName: "mb"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	ifs.Close()

	ifs2, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	fs := ifs2.(*zfsFS)
	defer fs.Close()

	meta := fs.zplDS.mos.metaDnode
	if int(meta.nblkptr) != fmtMOSObjArrayBlocks {
		t.Errorf("MOS meta_dnode nblkptr = %d, want %d", meta.nblkptr, fmtMOSObjArrayBlocks)
	}
	if got := meta.dataBlockSize(); got != fmtDnodeBlkSize {
		t.Errorf("MOS dnode block size = %d, want %d (fixed ZFS dnode block)", got, fmtDnodeBlkSize)
	}
	if int(meta.maxblkid) != fmtMOSObjArrayBlocks-1 {
		t.Errorf("MOS meta_dnode maxblkid = %d, want %d", meta.maxblkid, fmtMOSObjArrayBlocks-1)
	}

	// An object number in the second block must be readable (empty slots come
	// back as DMU_OT_NONE, not an out-of-bounds error).
	secondBlockObj := uint64(fmtDnodeBlkSize / dnodeMinSize) // first slot of block 1
	if secondBlockObj >= fmtMOSObjArrayObjs {
		t.Fatalf("test assumption broken: second-block object %d >= %d", secondBlockObj, fmtMOSObjArrayObjs)
	}
	if _, err := fs.zplDS.mos.readObject(secondBlockObj); err != nil {
		t.Fatalf("readObject(%d) in second MOS block: %v", secondBlockObj, err)
	}
}
