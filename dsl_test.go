package filesystem_zfs

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"testing"
)

// buildFakeMOS constructs a minimal 4096-byte buffer that looks like a
// 1024-byte MOS objset block, with osType set to the given value.
// Returns (buf, bp) where bp points into buf at offset 0.
func buildFakeMOSBuf(osType uint64) ([]byte, blkptr) {
	buf := make([]byte, 4096)
	// osType at offset 704 inside the 1024-byte objset block.
	binary.LittleEndian.PutUint64(buf[objsetTypeOff:], osType)
	bp := makeBlkptr(0, 1024, 1024, zcompressOff, dmotObjset, 0, 1)
	return buf, bp
}

// ── openRootDataset error paths ───────────────────────────────────────────────

func TestOpenRootDataset_MOSNullBP(t *testing.T) {
	var bp blkptr // null
	if _, err := openRootDataset(bytes.NewReader(nil), 0, bp); err == nil {
		t.Fatal("expected error for null rootBP")
	}
}

func TestOpenRootDataset_MOSWrongType(t *testing.T) {
	// MOS osType == dmuOSTZFS (not dmuOSTMeta).
	buf, bp := buildFakeMOSBuf(dmuOSTZFS)
	if _, err := openRootDataset(bytes.NewReader(buf), 0, bp); err == nil {
		t.Fatal("expected error for wrong MOS type")
	}
}

func TestOpenRootDataset_PoolDirMissingRootDataset(t *testing.T) {
	// MOS with correct type but pool directory ZAP has no "root_dataset" key.
	const blkSz = 4096
	buf := make([]byte, 4*blkSz)

	// MOS objset block at offset 0 (1024 bytes):
	binary.LittleEndian.PutUint64(buf[objsetTypeOff:], dmuOSTMeta) // correct type

	// MOS meta_dnode (object 0) with datablkszsec=8 pointing to objArray at blkSz:
	mosMeta := newDnode(dmotDnode, 1, 0, 0)
	mosMeta.datablkszsec = 8
	mosMeta.setBlkptrAt(0, makeBlkptr(int64(blkSz), blkSz, blkSz, zcompressOff, dmotDnode, 0, 1))
	mosMeta.encode()
	copy(buf[0:], mosMeta.raw)

	// Object array at offset blkSz (4096 bytes):
	// Object 1 = pool dir ZAP dnode (empty ZAP, missing "root_dataset")
	emptyZAP := newMicroZAPBlock(blkSz) // empty, no "root_dataset"
	copy(buf[2*blkSz:], emptyZAP)

	poolDirDN := newDnode(dmotObjectDirectory, 1, 0, 0)
	poolDirDN.datablkszsec = 8
	poolDirDN.setBlkptrAt(0, makeBlkptr(int64(2*blkSz), blkSz, blkSz, zcompressOff, dmotObjectDirectory, 0, 1))
	poolDirDN.encode()
	copy(buf[blkSz+dnodeMinSize:], poolDirDN.raw) // object 1

	bp := makeBlkptr(0, 1024, 1024, zcompressOff, dmotObjset, 0, 1)
	_, err := openRootDataset(bytes.NewReader(buf), 0, bp)
	if err == nil {
		t.Fatal("expected error for missing root_dataset key")
	}
}

// ── readDirEntries (non-dir type) ─────────────────────────────────────────────

func TestReadDirEntries_WrongType(t *testing.T) {
	// Create a real FS and use readDirEntries on a non-directory object.
	path := filepath.Join(t.TempDir(), "pool.img")
	const size = 8 * 1024 * 1024
	ifs, err := Format(path, size, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer ifs.Close()
	fs := ifs.(*zfsFS)

	// Write a regular file (type=dmotPlainFileContents).
	if err := fs.WriteFile("/afile", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Look up the object number of /afile.
	objNum, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, "/afile")
	if err != nil {
		t.Fatalf("lookupPath: %v", err)
	}

	// readDirEntries should fail because the object is a file, not a dir.
	_, err = fs.zplDS.readDirEntries(fs.f, fs.partOffset, objNum)
	if err == nil {
		t.Fatal("expected error for non-directory in readDirEntries")
	}
}

// ── parseDnode / bonusData edge cases ─────────────────────────────────────────

func TestParseDnode_TooShort(t *testing.T) {
	if _, err := parseDnode(make([]byte, 100)); err == nil {
		t.Fatal("expected error for too-short buffer")
	}
}

func TestParseDnode_ExtraSlotsShortBuf(t *testing.T) {
	// extraSlots=1 → size=1024, but buf is only 512 bytes.
	// parseDnode should clip size to len(b)=512 and succeed.
	b := make([]byte, dnodeMinSize)
	b[0] = dmotPlainFileContents // typ
	b[1] = 17                    // indblkshift
	b[2] = 1                     // nlevels
	b[3] = 1                     // nblkptr
	b[12] = 1                    // extraSlots=1 → wants 1024 bytes
	dn, err := parseDnode(b)
	if err != nil {
		t.Fatalf("parseDnode with short extraSlots buf: %v", err)
	}
	// Should have clipped raw to 512 bytes.
	if len(dn.raw) != dnodeMinSize {
		t.Errorf("raw len = %d, want %d", len(dn.raw), dnodeMinSize)
	}
}

func TestBonusData_EndBeyondRaw(t *testing.T) {
	// bonusLen larger than available space in raw → should be clipped to len(raw).
	dn := newDnode(dmotPlainFileContents, 1, 0, 300) // bonusLen=300, space=512-192=320
	// Manually set bonuslen larger than remaining space.
	dn.bonuslen = 500
	dn.encode()
	bonus := dn.bonusData()
	// end = 192 + 500 = 692 > 512 → clipped to 512-192 = 320 bytes.
	if len(bonus) != dnodeMinSize-dnodeHdrSize-blkptrSize {
		t.Errorf("bonusData len = %d, want %d", len(bonus), dnodeMinSize-dnodeHdrSize-blkptrSize)
	}
}

// ── additional openRootDataset error paths ────────────────────────────────────

func TestOpenRootDataset_PoolDirZAPError(t *testing.T) {
	// MOS object 1 has nblkptr=0 → zapListAll fails with null BP.
	const blkSz = 4096
	buf := make([]byte, 3*blkSz)
	binary.LittleEndian.PutUint64(buf[objsetTypeOff:], dmuOSTMeta)
	mosMeta := newDnode(dmotDnode, 1, 0, 0)
	mosMeta.datablkszsec = 8
	mosMeta.setBlkptrAt(0, makeBlkptr(int64(blkSz), blkSz, blkSz, zcompressOff, dmotDnode, 0, 1))
	mosMeta.encode()
	copy(buf[0:], mosMeta.raw)
	// Object 1: pool dir dnode with nblkptr=0 → null BP → zapListAll fails.
	poolDirDN := newDnode(dmotObjectDirectory, 0, 0, 0)
	poolDirDN.encode()
	copy(buf[blkSz+dnodeMinSize:], poolDirDN.raw)
	bp := makeBlkptr(0, 1024, 1024, zcompressOff, dmotObjset, 0, 1)
	_, err := openRootDataset(bytes.NewReader(buf), 0, bp)
	if err == nil {
		t.Fatal("expected error when pool dir ZAP has null BP")
	}
}

func TestOpenRootDataset_DSLDirBonusTooShort(t *testing.T) {
	// DSL dir object (obj 2) has bonusLen=0 → dslDirBonus too short error.
	const blkSz = 4096
	buf := make([]byte, 4*blkSz)
	binary.LittleEndian.PutUint64(buf[objsetTypeOff:], dmuOSTMeta)
	mosMeta := newDnode(dmotDnode, 1, 0, 0)
	mosMeta.datablkszsec = 8
	mosMeta.setBlkptrAt(0, makeBlkptr(int64(blkSz), blkSz, blkSz, zcompressOff, dmotDnode, 0, 1))
	mosMeta.encode()
	copy(buf[0:], mosMeta.raw)
	poolDirZAP := newMicroZAPBlock(blkSz)
	_ = mzapInsert(poolDirZAP, dmuPoolRootDataset, 2)
	copy(buf[2*blkSz:], poolDirZAP)
	poolDirDN := newDnode(dmotObjectDirectory, 1, 0, 0)
	poolDirDN.datablkszsec = 8
	poolDirDN.setBlkptrAt(0, makeBlkptr(int64(2*blkSz), blkSz, blkSz, zcompressOff, dmotObjectDirectory, 0, 1))
	poolDirDN.encode()
	copy(buf[blkSz+dnodeMinSize:], poolDirDN.raw)
	// obj 2: DSL dir with bonusLen=0 → bonusData() is empty → too short.
	dslDirDN := newDnode(dmotDSLDir, 1, dmotDSLDir, 0)
	dslDirDN.encode()
	copy(buf[blkSz+2*dnodeMinSize:], dslDirDN.raw)
	bp := makeBlkptr(0, 1024, 1024, zcompressOff, dmotObjset, 0, 1)
	_, err := openRootDataset(bytes.NewReader(buf), 0, bp)
	if err == nil {
		t.Fatal("expected error for too-short DSL dir bonus")
	}
}

func TestOpenRootDataset_HeadDatasetObjNumZero(t *testing.T) {
	// DSL dir bonus has ddHeadDatasetObj=0 → headDatasetObjNum=0 → error.
	const blkSz = 4096
	buf := make([]byte, 4*blkSz)
	binary.LittleEndian.PutUint64(buf[objsetTypeOff:], dmuOSTMeta)
	mosMeta := newDnode(dmotDnode, 1, 0, 0)
	mosMeta.datablkszsec = 8
	mosMeta.setBlkptrAt(0, makeBlkptr(int64(blkSz), blkSz, blkSz, zcompressOff, dmotDnode, 0, 1))
	mosMeta.encode()
	copy(buf[0:], mosMeta.raw)
	poolDirZAP := newMicroZAPBlock(blkSz)
	_ = mzapInsert(poolDirZAP, dmuPoolRootDataset, 2)
	copy(buf[2*blkSz:], poolDirZAP)
	poolDirDN := newDnode(dmotObjectDirectory, 1, 0, 0)
	poolDirDN.datablkszsec = 8
	poolDirDN.setBlkptrAt(0, makeBlkptr(int64(2*blkSz), blkSz, blkSz, zcompressOff, dmotObjectDirectory, 0, 1))
	poolDirDN.encode()
	copy(buf[blkSz+dnodeMinSize:], poolDirDN.raw)
	// obj 2: DSL dir with 16-byte bonus (all zeros) → headDatasetObjNum=0.
	dslDirDN := newDnode(dmotDSLDir, 1, dmotDSLDir, 16)
	dslDirDN.encode()
	copy(buf[blkSz+2*dnodeMinSize:], dslDirDN.raw)
	bp := makeBlkptr(0, 1024, 1024, zcompressOff, dmotObjset, 0, 1)
	_, err := openRootDataset(bytes.NewReader(buf), 0, bp)
	if err == nil {
		t.Fatal("expected error for headDatasetObjNum=0")
	}
}

func TestLookupEntry_ThroughFileFails(t *testing.T) {
	// lookupPath through a file (not a directory) triggers readDirEntries failure
	// → lookupEntry returns error from readDirEntries (stmt 3 coverage).
	fs := newTestFS(t)
	if err := fs.WriteFile("/notadir", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := fs.ReadFile("/notadir/child")
	if err == nil {
		t.Fatal("expected error when traversing through a file")
	}
}

// buildDeepMOSBuf constructs a 5-block buffer for testing openRootDataset deep paths.
// obj 1 → pool dir ZAP (with "root_dataset"=2)
// obj 2 → DSL dir (bonus with ddHeadDatasetObj=3)
// obj 3 → DSL dataset (controlled bonus)
func buildDeepMOSBuf(dslDSBonusLen uint16, setNullZPLBP bool) ([]byte, blkptr) {
	const blkSz = 4096
	buf := make([]byte, 6*blkSz)

	binary.LittleEndian.PutUint64(buf[objsetTypeOff:], dmuOSTMeta)

	// MOS meta-dnode → object array at blkSz
	mosMeta := newDnode(dmotDnode, 1, 0, 0)
	mosMeta.datablkszsec = 8
	mosMeta.setBlkptrAt(0, makeBlkptr(int64(blkSz), blkSz, blkSz, zcompressOff, dmotDnode, 0, 1))
	mosMeta.encode()
	copy(buf[0:], mosMeta.raw)

	// Pool dir ZAP block at 2*blkSz: {"root_dataset": 2}
	poolDirZAP := newMicroZAPBlock(blkSz)
	_ = mzapInsert(poolDirZAP, dmuPoolRootDataset, 2)
	copy(buf[2*blkSz:], poolDirZAP)

	// obj 1: pool dir dnode → ZAP at 2*blkSz
	poolDirDN := newDnode(dmotObjectDirectory, 1, 0, 0)
	poolDirDN.datablkszsec = 8
	poolDirDN.setBlkptrAt(0, makeBlkptr(int64(2*blkSz), blkSz, blkSz, zcompressOff, dmotObjectDirectory, 0, 1))
	poolDirDN.encode()
	copy(buf[blkSz+dnodeMinSize:], poolDirDN.raw)

	// obj 2: DSL dir dnode with headDatasetObj=3 in bonus
	dslDirBonus := make([]byte, ddHeadDatasetObj+8+8)                // ensure ddHeadDatasetObj+8 bytes
	binary.LittleEndian.PutUint64(dslDirBonus[ddHeadDatasetObj:], 3) // headDatasetObj=3
	dslDirDN := newDnode(dmotDSLDir, 1, dmotDSLDir, uint16(len(dslDirBonus)))
	dslDirDN.encode()
	copy(dslDirDN.raw[dnodeHdrSize+blkptrSize:], dslDirBonus)
	copy(buf[blkSz+2*dnodeMinSize:], dslDirDN.raw)

	// obj 3: DSL dataset dnode
	var dslDSBonus []byte
	if setNullZPLBP {
		// Full size bonus with null ZPL BP (all zeros at dsBP offset)
		dslDSBonus = make([]byte, dsBP+blkptrSize)
		// dsBP is at offset 128; all zeros → null blkptr
	} else {
		// Short bonus to trigger "DSL dataset bonus too short"
		dslDSBonus = make([]byte, dslDSBonusLen)
	}
	dslDSDN := newDnode(dmotDSLDataset, 1, dmotDSLDataset, uint16(len(dslDSBonus)))
	dslDSDN.encode()
	if setNullZPLBP {
		copy(dslDSDN.raw[dnodeHdrSize+blkptrSize:], dslDSBonus)
	} else {
		copy(dslDSDN.raw[dnodeHdrSize+blkptrSize:], dslDSBonus)
	}
	copy(buf[blkSz+3*dnodeMinSize:], dslDSDN.raw)

	bp := makeBlkptr(0, 1024, 1024, zcompressOff, dmotObjset, 0, 1)
	return buf, bp
}

func TestOpenRootDataset_DSLDatasetBonusTooShort(t *testing.T) {
	// DSL dataset dnode has a bonus shorter than dsBP+blkptrSize=256 → error.
	buf, bp := buildDeepMOSBuf(100, false) // bonusLen=100 < 256
	_, err := openRootDataset(bytes.NewReader(buf), 0, bp)
	if err == nil {
		t.Fatal("expected error for too-short DSL dataset bonus")
	}
}

func TestOpenRootDataset_ZPLBPNull(t *testing.T) {
	// DSL dataset has null ZPL block pointer → "DSL dataset has null ZPL BP" error.
	buf, bp := buildDeepMOSBuf(0, true) // full bonus, null ZPL BP
	_, err := openRootDataset(bytes.NewReader(buf), 0, bp)
	if err == nil {
		t.Fatal("expected error for null ZPL BP")
	}
}
