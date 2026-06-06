package filesystem_zfs

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ── saLayout0Size / saBonusSize ───────────────────────────────────────────────

func TestSALayout0Size(t *testing.T) {
	sz := saLayout0Size()
	// 10 fixed-8-byte attrs + 4 fixed-16-byte attrs = 80 + 64 = 144
	const want = 144
	if sz != want {
		t.Fatalf("saLayout0Size() = %d, want %d", sz, want)
	}
}

func TestSABonusSize(t *testing.T) {
	sz := saBonusSize()
	// 4 (magic) + 2 (layout_info) + 144 (attrs) = 150
	const want = 150
	if sz != want {
		t.Fatalf("saBonusSize() = %d, want %d", sz, want)
	}
}

// ── updateDnodeSA / parseDnodeSA ─────────────────────────────────────────────

func TestUpdateDnodeSA_RoundTrip(t *testing.T) {
	layout := defaultSALayout()
	dn := newDnode(dmotPlainFileContents, 1, dmotSA, uint16(saBonusSize()))

	attrs := &saAttrs{
		mode:   0o100644,
		size:   9876,
		gen:    3,
		uid:    1001,
		gid:    1001,
		parent: 7,
		links:  1,
		xattr:  0,
		rdev:   0,
		flags:  0,
		atime:  [2]uint64{1000, 0},
		mtime:  [2]uint64{2000, 0},
		ctime:  [2]uint64{3000, 0},
		crtime: [2]uint64{500, 0},
	}

	updateDnodeSA(dn, attrs, layout)

	// Verify by reading back via parseDnodeSA.
	got, err := parseDnodeSA(dn, layout)
	if err != nil {
		t.Fatalf("parseDnodeSA after update: %v", err)
	}
	if got.mode != attrs.mode {
		t.Errorf("mode: got 0o%o, want 0o%o", got.mode, attrs.mode)
	}
	if got.size != attrs.size {
		t.Errorf("size: got %d, want %d", got.size, attrs.size)
	}
	if got.uid != attrs.uid {
		t.Errorf("uid: got %d, want %d", got.uid, attrs.uid)
	}
	if got.gid != attrs.gid {
		t.Errorf("gid: got %d, want %d", got.gid, attrs.gid)
	}
	if got.parent != attrs.parent {
		t.Errorf("parent: got %d, want %d", got.parent, attrs.parent)
	}
	if got.atime[0] != attrs.atime[0] {
		t.Errorf("atime: got %d, want %d", got.atime[0], attrs.atime[0])
	}
}

func TestParseDnodeSA_WrongBonusType(t *testing.T) {
	layout := defaultSALayout()
	dn := newDnode(dmotPlainFileContents, 1, dmotNone, 10) // bonusType=0 ≠ dmotSA=44
	if _, err := parseDnodeSA(dn, layout); err == nil {
		t.Fatal("expected error for wrong bonus type")
	}
}

// ── readSALayoutFromZAP ───────────────────────────────────────────────────────

func TestReadSALayoutFromZAP_MicroZAP(t *testing.T) {
	// micro-ZAP → returns defaultSALayout() without error
	blk := newMicroZAPBlock(4096)
	dn := dnodeForFatZAP(1) // reuses helper from zap_test.go; block 0 is the micro-ZAP

	got, err := readSALayoutFromZAP(bytes.NewReader(blk), 0, dn, "0")
	if err != nil {
		t.Fatalf("readSALayoutFromZAP micro: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("readSALayoutFromZAP returned empty layout")
	}
}

func TestReadSALayoutFromZAP_FatZAP(t *testing.T) {
	// fat-ZAP → also returns defaultSALayout() (current implementation falls through)
	data := buildFatZAPBlocks("0", 0) // key "0" → val 0
	dn := dnodeForFatZAP(2)

	got, err := readSALayoutFromZAP(bytes.NewReader(data), 0, dn, "0")
	if err != nil {
		t.Fatalf("readSALayoutFromZAP fat-ZAP: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("readSALayoutFromZAP returned empty layout")
	}
}

// ── loadSAMasterNode (error paths) ────────────────────────────────────────────

// buildSAMasterNodeTestBuf constructs an in-memory buffer with:
//
//	offset 0: meta_dnode data block (4096 B)
//	  - obj 0 at byte 0:   placeholder dnode
//	  - obj 1 at byte 512: SA master node dnode (typ=dmotSAMasterNode, ZAP at +4096)
//	  - obj 2 at byte 1024: layouts ZAP dnode (typ=dmotZAPOther, ZAP at +8192)
//	offset 4096: SA master node ZAP (micro-ZAP with {"LAYOUTS": 2})
//	offset 8192: layouts ZAP (micro-ZAP with {"0": 0})
//
// Returns (buf, fake_objset).
func buildSAMasterNodeTestBuf() ([]byte, *objset) {
	const (
		metaBlockOff   = 0
		saMasterZAPOff = 4096
		layoutsZAPOff  = 8192
		totalSize      = 12288
	)
	buf := make([]byte, totalSize)

	// Dnode 1: SA master node (typ=45, blkptr→ saMasterZAPOff)
	saMasterDN := newDnode(dmotSAMasterNode, 1, 0, 0)
	saMasterDN.datablkszsec = 8
	saMasterDN.setBlkptrAt(0, makeBlkptr(saMasterZAPOff, 4096, 4096, zcompressOff, dmotSAMasterNode, 0, 1))
	saMasterDN.encode()
	copy(buf[512:], saMasterDN.raw)

	// Dnode 2: layouts ZAP dnode (blkptr→ layoutsZAPOff)
	layoutsDN := newDnode(dmotZAPOther, 1, 0, 0)
	layoutsDN.datablkszsec = 8
	layoutsDN.setBlkptrAt(0, makeBlkptr(layoutsZAPOff, 4096, 4096, zcompressOff, dmotZAPOther, 0, 1))
	layoutsDN.encode()
	copy(buf[1024:], layoutsDN.raw)

	// SA master node ZAP block: {"LAYOUTS": 2}
	saMasterZAP := newMicroZAPBlock(4096)
	_ = mzapInsert(saMasterZAP, "LAYOUTS", 2)
	copy(buf[saMasterZAPOff:], saMasterZAP)

	// Layouts ZAP block: {"0": 0}
	layoutsZAP := newMicroZAPBlock(4096)
	_ = mzapInsert(layoutsZAP, "0", 0)
	copy(buf[layoutsZAPOff:], layoutsZAP)

	// meta_dnode pointing to the object array at offset 0
	metaDN := newDnode(dmotDnode, 1, 0, 0)
	metaDN.datablkszsec = 8
	metaDN.setBlkptrAt(0, makeBlkptr(metaBlockOff, 4096, 4096, zcompressOff, dmotDnode, 0, 1))
	metaDN.encode()

	fakeOS := &objset{
		r:         bytes.NewReader(buf),
		partOff:   0,
		metaDnode: metaDN,
	}
	return buf, fakeOS
}

func TestLoadSAMasterNode_Success(t *testing.T) {
	buf, fakeOS := buildSAMasterNodeTestBuf()
	r := bytes.NewReader(buf)

	mn, err := loadSAMasterNode(r, 0, fakeOS, 1 /*masterNodeObjNum*/)
	if err != nil {
		t.Fatalf("loadSAMasterNode: %v", err)
	}
	if len(mn.layouts) == 0 {
		t.Fatal("loadSAMasterNode returned empty layouts")
	}
}

func TestLoadSAMasterNode_WrongType(t *testing.T) {
	// Dnode 1 has wrong type (not dmotSAMasterNode).
	buf := make([]byte, 4096)
	wrongDN := newDnode(dmotPlainFileContents, 1, 0, 0) // wrong type
	copy(buf[512:], wrongDN.raw)

	metaDN := newDnode(dmotDnode, 1, 0, 0)
	metaDN.datablkszsec = 8
	metaDN.setBlkptrAt(0, makeBlkptr(0, 4096, 4096, zcompressOff, dmotDnode, 0, 1))
	metaDN.encode()

	fakeOS := &objset{
		r:         bytes.NewReader(buf),
		partOff:   0,
		metaDnode: metaDN,
	}

	_, err := loadSAMasterNode(bytes.NewReader(buf), 0, fakeOS, 1)
	if err == nil {
		t.Fatal("expected error for wrong SA master node type")
	}
}

func TestLoadSAMasterNode_MissingLAYOUTSKey(t *testing.T) {
	// Dnode 1 has correct type but the ZAP has no "LAYOUTS" key.
	const saMasterZAPOff = 4096
	const totalSize = 8192
	buf := make([]byte, totalSize)

	// Dnode 1: SA master node, ZAP at saMasterZAPOff
	saMasterDN := newDnode(dmotSAMasterNode, 1, 0, 0)
	saMasterDN.datablkszsec = 8
	saMasterDN.setBlkptrAt(0, makeBlkptr(saMasterZAPOff, 4096, 4096, zcompressOff, dmotSAMasterNode, 0, 1))
	saMasterDN.encode()
	copy(buf[512:], saMasterDN.raw)

	// SA master node ZAP: empty (no "LAYOUTS" key)
	saMasterZAP := newMicroZAPBlock(4096)
	copy(buf[saMasterZAPOff:], saMasterZAP)

	metaDN := newDnode(dmotDnode, 1, 0, 0)
	metaDN.datablkszsec = 8
	metaDN.setBlkptrAt(0, makeBlkptr(0, 4096, 4096, zcompressOff, dmotDnode, 0, 1))
	metaDN.encode()

	fakeOS := &objset{
		r:         bytes.NewReader(buf),
		partOff:   0,
		metaDnode: metaDN,
	}

	_, err := loadSAMasterNode(bytes.NewReader(buf), 0, fakeOS, 1)
	if err == nil {
		t.Fatal("expected error for missing LAYOUTS key")
	}
}

// ── additional coverage tests ─────────────────────────────────────────────────

func TestParseSABonus_VarSizeAttr(t *testing.T) {
	// Layout containing zplSymlink (sz=0) → sz==0 → continue, no error.
	layout := []uint16{zplMode, zplSymlink, zplSize}
	bonus := writeSABonus(&saAttrs{mode: 0o0100644, size: 100}, []uint16{zplMode, zplSize})
	result, err := parseSABonus(bonus, layout)
	if err != nil {
		t.Fatalf("parseSABonus with var-size attr: %v", err)
	}
	if result.mode != 0o0100644 {
		t.Errorf("mode = 0o%o, want 0o%o", result.mode, 0o0100644)
	}
}

func TestParseSABonus_UnknownAttrID(t *testing.T) {
	// Layout containing attribute ID 9999 (not in saAttrSize) → !ok → continue.
	layout := []uint16{zplMode, 9999, zplSize}
	bonus := writeSABonus(&saAttrs{mode: 0o0100755, size: 200}, []uint16{zplMode, zplSize})
	result, err := parseSABonus(bonus, layout)
	if err != nil {
		t.Fatalf("parseSABonus with unknown attr: %v", err)
	}
	if result.size != 200 {
		t.Errorf("size = %d, want 200", result.size)
	}
}

func TestParseSABonus_ShortBuffer(t *testing.T) {
	// Buffer only contains mode+size; atime would exceed bounds → off+sz>len(buf) → break.
	layout := []uint16{zplMode, zplSize, zplAtime}
	bonus := writeSABonus(&saAttrs{mode: 0o0644, size: 50}, []uint16{zplMode, zplSize})
	result, err := parseSABonus(bonus, layout)
	if err != nil {
		t.Fatalf("parseSABonus short buffer: %v", err)
	}
	if result.mode != 0o0644 {
		t.Errorf("mode = 0o%o, want 0o%o", result.mode, 0o0644)
	}
}

func TestWriteSABonus_VarSizeAttr(t *testing.T) {
	// Layout with zplSymlink (sz=0) → !ok||sz==0 → continue (not written to buffer).
	layout := []uint16{zplMode, zplSymlink, zplSize}
	bonus := writeSABonus(&saAttrs{mode: 0o0644, size: 10}, layout)
	// Only mode(8) and size(8) written → header(6)+16 = 22 bytes.
	const wantLen = 22
	if len(bonus) != wantLen {
		t.Errorf("len(bonus) = %d, want %d", len(bonus), wantLen)
	}
}

func TestReadSALayoutFromZAP_ShortBlock(t *testing.T) {
	// dnode with nblkptr=0 and datablkszsec=0 → readDataBlock returns 0-byte slice → len<8 → error.
	raw := make([]byte, 512) // all zeros: nlevels=0, nblkptr=0, datablkszsec=0
	dn, _ := parseDnode(raw)
	_, err := readSALayoutFromZAP(bytes.NewReader(nil), 0, dn, "0")
	if err == nil {
		t.Fatal("expected error for short ZAP block")
	}
}

func TestReadSALayoutFromZAP_ReadError(t *testing.T) {
	// dnode with nblkptr=1 and non-null BP but empty reader → ReadAt fails → error.
	dn := newDnode(dmotNone, 1, 0, 0)
	bp := makeBlkptr(0, 4096, 4096, zcompressOff, dmotNone, 0, 1)
	dn.setBlkptrAt(0, bp)
	dn.encode()
	_, err := readSALayoutFromZAP(bytes.NewReader(nil), 0, dn, "0")
	if err == nil {
		t.Fatal("expected error when reader fails")
	}
}

func TestLoadSAMasterNode_NonNumericKey(t *testing.T) {
	// Layouts ZAP has a non-numeric key → fmt.Sscan fails → continue.
	buf, fakeOS := buildSAMasterNodeTestBuf()
	_ = mzapInsert(buf[8192:], "bad_key", 1) // add non-numeric key to layouts ZAP
	r := bytes.NewReader(buf)
	mn, err := loadSAMasterNode(r, 0, fakeOS, 1)
	if err != nil {
		t.Fatalf("loadSAMasterNode with non-numeric key: %v", err)
	}
	_ = mn
}

func TestLoadSAMasterNode_LayoutsObjReadError(t *testing.T) {
	// SA master node ZAP returns layoutsObjNum=9999 which doesn't exist → readObject fails.
	const (
		saMasterZAPOff2 = 4096
		totalSize2      = 8192
	)
	buf2 := make([]byte, totalSize2)
	saMasterDN := newDnode(dmotSAMasterNode, 1, 0, 0)
	saMasterDN.datablkszsec = 8
	saMasterDN.setBlkptrAt(0, makeBlkptr(saMasterZAPOff2, 4096, 4096, zcompressOff, dmotSAMasterNode, 0, 1))
	saMasterDN.encode()
	copy(buf2[512:], saMasterDN.raw)
	saMasterZAP := newMicroZAPBlock(4096)
	_ = mzapInsert(saMasterZAP, "LAYOUTS", 9999) // layouts obj 9999 does not exist
	copy(buf2[saMasterZAPOff2:], saMasterZAP)
	metaDN := newDnode(dmotDnode, 1, 0, 0)
	metaDN.datablkszsec = 8
	metaDN.setBlkptrAt(0, makeBlkptr(0, 4096, 4096, zcompressOff, dmotDnode, 0, 1))
	metaDN.encode()
	fakeOS2 := &objset{
		r:         bytes.NewReader(buf2),
		partOff:   0,
		metaDnode: metaDN,
	}
	_, err := loadSAMasterNode(bytes.NewReader(buf2), 0, fakeOS2, 1)
	if err == nil {
		t.Fatal("expected error for non-existent layouts object")
	}
}

func TestParseSABonus_DataStartClip(t *testing.T) {
	// layoutInfo has hdrSize=1 → dataStart=8 > len(buf)=6 → clipped to len(buf).
	buf := make([]byte, 6)
	binary.LittleEndian.PutUint32(buf[0:], saMagic)
	binary.LittleEndian.PutUint16(buf[4:], 1<<10) // layoutInfo: hdrSize=1, layoutIdx=0
	result, err := parseSABonus(buf, defaultSALayout())
	if err != nil {
		t.Fatalf("parseSABonus with clipped dataStart: %v", err)
	}
	_ = result
}

func TestLoadSAMasterNode_LayoutReadSAFails(t *testing.T) {
	// Covers sa.go:139 — readSALayoutFromZAP fails → fallback to defaultSALayout.
	// Strategy: use a countingReaderAt that allows calls 1-2 (SA master node ZAP +
	// layouts ZAP) but fails on call 3 (readSALayoutFromZAP reading the layouts block).
	const blkSz = 4096
	buf := make([]byte, 3*blkSz)

	// Block blkSz: SA master node micro-ZAP with LAYOUTS=2.
	saMasterZAP := newMicroZAPBlock(blkSz)
	_ = mzapInsert(saMasterZAP, "LAYOUTS", 2)
	copy(buf[blkSz:], saMasterZAP)

	// Block 2*blkSz: layouts micro-ZAP with one numeric key "0".
	layoutsZAP := newMicroZAPBlock(blkSz)
	_ = mzapInsert(layoutsZAP, "0", 99)
	copy(buf[2*blkSz:], layoutsZAP)

	// Object 1: SA master node dnode pointing to SA master node ZAP.
	saMasterDN := newDnode(dmotSAMasterNode, 1, 0, 0)
	saMasterDN.datablkszsec = uint16(blkSz / 512)
	saMasterDN.setBlkptrAt(0, makeBlkptr(int64(blkSz), blkSz, blkSz, zcompressOff, dmotSAMasterNode, 0, 1))
	saMasterDN.encode()
	copy(buf[dnodeMinSize:], saMasterDN.raw) // object 1 at byte offset 512

	// Object 2: layouts dnode pointing to layouts ZAP.
	layoutsDN := newDnode(dmotSAAttrLayouts, 1, 0, 0)
	layoutsDN.datablkszsec = uint16(blkSz / 512)
	layoutsDN.setBlkptrAt(0, makeBlkptr(int64(2*blkSz), blkSz, blkSz, zcompressOff, dmotSAAttrLayouts, 0, 1))
	layoutsDN.encode()
	copy(buf[2*dnodeMinSize:], layoutsDN.raw) // object 2 at byte offset 1024

	metaDN := newDnode(dmotDnode, 1, 0, 0)
	metaDN.datablkszsec = uint16(blkSz / 512)
	metaDN.setBlkptrAt(0, makeBlkptr(0, blkSz, blkSz, zcompressOff, dmotDnode, 0, 1))
	metaDN.encode()
	fakeOS := &objset{
		r:         bytes.NewReader(buf),
		partOff:   0,
		metaDnode: metaDN,
	}

	// r calls: 1=zapListAll(mn), 2=zapListAll(layoutsDN), 3=readSALayoutFromZAP(layoutsDN,"0")
	// Fail on call 3 → readSALayoutFromZAP errors → sa.go:139 fallback fires.
	cr := &countingReaderAt{r: bytes.NewReader(buf), maxOK: 2}
	mn, err := loadSAMasterNode(cr, 0, fakeOS, 1)
	if err != nil {
		t.Fatalf("loadSAMasterNode: %v", err)
	}
	if mn == nil {
		t.Fatal("expected non-nil master node")
	}
}
