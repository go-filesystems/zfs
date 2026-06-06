package filesystem_zfs

import (
	"bytes"
	"os"
	"testing"
)

// ── writeObject(0, dn) ────────────────────────────────────────────────────────

func TestWriteObject_Zero(t *testing.T) {
	// writeObject(0, dn) updates metaDnode in-place without I/O.
	orig := newDnode(dmotNone, 1, 0, 0)
	os := &objset{
		raw:       make([]byte, objsetHdrSize),
		metaDnode: orig,
	}
	updated := newDnode(dmotDirContents, 1, 0, 0)
	if err := os.writeObject(0, updated); err != nil {
		t.Fatalf("writeObject(0): %v", err)
	}
	if os.metaDnode.typ != dmotDirContents {
		t.Errorf("metaDnode.typ = %d, want %d", os.metaDnode.typ, dmotDirContents)
	}
	// Should also be reflected in raw.
	if os.raw[objsetMetaDnodeOff] != dmotDirContents {
		t.Errorf("raw[0] = %d, want %d", os.raw[0], dmotDirContents)
	}
}

// ── writeObjectBlock (error paths) ───────────────────────────────────────────

func TestWriteObjectBlock_OutOfBounds(t *testing.T) {
	// blockID >= nblkptr → error.
	metaDN := newDnode(dmotDnode, 1, 0, 0) // nblkptr=1
	os := &objset{
		r:         bytes.NewReader(nil),
		partOff:   0,
		metaDnode: metaDN,
	}
	err := os.writeObjectBlock(1 /*blockID=1 >= nblkptr=1*/, make([]byte, 512))
	if err == nil {
		t.Fatal("expected out-of-bounds error")
	}
}

func TestWriteObjectBlock_NullBP(t *testing.T) {
	// blockID within range but blkptr is null → error.
	metaDN := newDnode(dmotDnode, 1, 0, 0) // nblkptr=1, blkptr[0] is null (zeros)
	os := &objset{
		r:         bytes.NewReader(nil),
		partOff:   0,
		metaDnode: metaDN,
	}
	err := os.writeObjectBlock(0, make([]byte, 512))
	if err == nil {
		t.Fatal("expected null-BP error")
	}
}

func TestWriteObjectBlock_NotWritable(t *testing.T) {
	// Reader implements io.ReaderAt but not io.WriterAt → "not writable" error.
	metaDN := newDnode(dmotDnode, 1, 0, 0)
	metaDN.setBlkptrAt(0, makeBlkptr(0, 4096, 4096, zcompressOff, dmotDnode, 0, 1))
	metaDN.encode()

	os := &objset{
		r:         bytes.NewReader(make([]byte, 4096)), // read-only
		partOff:   0,
		metaDnode: metaDN,
	}
	err := os.writeObjectBlock(0, make([]byte, 4096))
	if err == nil {
		t.Fatal("expected 'not writable' error")
	}
}

// ── findObjectByType ──────────────────────────────────────────────────────────

func TestFindObjectByType_Found(t *testing.T) {
	// Build an object array block: objects 0–3 with different types.
	objBlock := make([]byte, 4096)
	dn1 := newDnode(dmotPlainFileContents, 1, 0, 0)
	dn2 := newDnode(dmotDirContents, 1, 0, 0)
	dn3 := newDnode(dmotMasterNode, 1, 0, 0)
	copy(objBlock[1*dnodeMinSize:], dn1.raw)
	copy(objBlock[2*dnodeMinSize:], dn2.raw)
	copy(objBlock[3*dnodeMinSize:], dn3.raw)

	metaDN := newDnode(dmotDnode, 1, 0, 0)
	metaDN.datablkszsec = 8 // 4096-byte data blocks
	metaDN.setBlkptrAt(0, makeBlkptr(0, 4096, 4096, zcompressOff, dmotDnode, 0, 1))
	metaDN.encode()

	os := &objset{
		r:         bytes.NewReader(objBlock),
		partOff:   0,
		metaDnode: metaDN,
	}

	objNum, err := os.findObjectByType(1, 3, dmotDirContents)
	if err != nil {
		t.Fatalf("findObjectByType: %v", err)
	}
	if objNum != 2 {
		t.Fatalf("objNum = %d, want 2", objNum)
	}
}

func TestFindObjectByType_NotFound(t *testing.T) {
	objBlock := make([]byte, 4096)
	dn1 := newDnode(dmotPlainFileContents, 1, 0, 0)
	copy(objBlock[1*dnodeMinSize:], dn1.raw)

	metaDN := newDnode(dmotDnode, 1, 0, 0)
	metaDN.datablkszsec = 8
	metaDN.setBlkptrAt(0, makeBlkptr(0, 4096, 4096, zcompressOff, dmotDnode, 0, 1))
	metaDN.encode()

	os := &objset{
		r:         bytes.NewReader(objBlock),
		partOff:   0,
		metaDnode: metaDN,
	}
	_, err := os.findObjectByType(1, 1, dmotDirContents)
	if err == nil {
		t.Fatal("expected not-found error")
	}
}

// ── openObjset (error paths) ──────────────────────────────────────────────────

func TestOpenObjset_NullBP(t *testing.T) {
	var bp blkptr // all zeros = null
	if _, err := openObjset(bytes.NewReader(nil), 0, bp); err == nil {
		t.Fatal("expected null-BP error")
	}
}

func TestOpenObjset_BlockTooSmall(t *testing.T) {
	// Block is smaller than objsetHdrSize (1024 bytes).
	buf := make([]byte, 512)
	bp := makeBlkptr(0, 512, 512, zcompressOff, dmotObjset, 0, 1)
	if _, err := openObjset(bytes.NewReader(buf), 0, bp); err == nil {
		t.Fatal("expected too-small-block error")
	}
}

// ── readObject (edge cases) ───────────────────────────────────────────────────

func TestReadObject_ObjectZero(t *testing.T) {
	meta := newDnode(dmotDnode, 1, 0, 0)
	os := &objset{
		r:         bytes.NewReader(nil),
		partOff:   0,
		metaDnode: meta,
	}
	dn, err := os.readObject(0)
	if err != nil {
		t.Fatalf("readObject(0): %v", err)
	}
	if dn != meta {
		t.Fatal("readObject(0) should return metaDnode")
	}
}

// ── writeObject (non-zero objNum) ─────────────────────────────────────────────

func TestWriteObject_NonZero(t *testing.T) {
	// Write object 1 via a real writable temp file.
	tmp, err := os.CreateTemp(t.TempDir(), "objset*.img")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer tmp.Close()

	// Create a 4096-byte object-array block with a dummy dnode at slot 1 (offset 512).
	objBlock := make([]byte, 4096)
	origDN := newDnode(dmotPlainFileContents, 1, 0, 0)
	copy(objBlock[dnodeMinSize:], origDN.raw) // position 1

	if _, err := tmp.WriteAt(objBlock, 0); err != nil {
		t.Fatalf("WriteAt init: %v", err)
	}

	// meta_dnode: datablkszsec=8 (4096B), blkptr[0] → offset 0, size 4096
	metaDN := newDnode(dmotDnode, 1, 0, 0)
	metaDN.datablkszsec = 8
	metaDN.setBlkptrAt(0, makeBlkptr(0, 4096, 4096, zcompressOff, dmotDnode, 0, 1))
	metaDN.encode()

	fakeOS := &objset{
		r:         tmp,
		partOff:   0,
		metaDnode: metaDN,
	}

	// Overwrite object 1 with a dir-contents dnode.
	newDN := newDnode(dmotDirContents, 1, 0, 0)
	if err := fakeOS.writeObject(1, newDN); err != nil {
		t.Fatalf("writeObject(1): %v", err)
	}

	// Read back and verify.
	readDN, err := fakeOS.readObject(1)
	if err != nil {
		t.Fatalf("readObject(1) after write: %v", err)
	}
	if readDN.typ != dmotDirContents {
		t.Errorf("typ = %d, want %d", readDN.typ, dmotDirContents)
	}
}

// ── additional coverage tests ─────────────────────────────────────────────────

func TestOpenObjset_ReadBlockError(t *testing.T) {
	// Non-null BP but reader fails at that offset → readBlock error → return nil, error.
	bp := makeBlkptr(0, 4096, 4096, zcompressOff, dmotObjset, 0, 1)
	r := errorReaderAt{data: nil, failOffset: 0} // always fails at offset 0
	_, err := openObjset(r, 0, bp)
	if err == nil {
		t.Fatal("expected error when ReadAt fails")
	}
}

func TestReadObject_OffsetOutOfBounds(t *testing.T) {
	// datablkszsec=2 → logical blkSz=1024; object 1 has byteOff=512, blockID=0,
	// offsetInBlock=512; physical block is only 512 bytes → 512+512>512 → error.
	const psize = 512
	data := make([]byte, psize)
	metaDN := newDnode(dmotDnode, 1, 0, 0)
	metaDN.datablkszsec = 2 // logical 1024-byte blocks
	metaDN.setBlkptrAt(0, makeBlkptr(0, psize, psize, zcompressOff, dmotDnode, 0, 1))
	metaDN.encode()
	os2 := &objset{
		r:         bytes.NewReader(data),
		partOff:   0,
		metaDnode: metaDN,
	}
	_, err := os2.readObject(1)
	if err == nil {
		t.Fatal("expected out-of-bounds error")
	}
}

func TestFindObjectByType_ReadObjectErrorContinue(t *testing.T) {
	// findObjectByType with range including objects whose readObject fails →
	// err != nil → continue (covers the error-continue branch).
	objBlock := make([]byte, 4096)
	metaDN := newDnode(dmotDnode, 1, 0, 0)
	metaDN.datablkszsec = 8 // blkSz=4096 → max 8 objects (0-7) per block
	metaDN.setBlkptrAt(0, makeBlkptr(0, 4096, 4096, zcompressOff, dmotDnode, 0, 1))
	metaDN.encode()
	os3 := &objset{
		r:         bytes.NewReader(objBlock),
		partOff:   0,
		metaDnode: metaDN,
	}
	// Objects 8-10: byteOff=8*512=4096, blockID=1 >= nblkptr=1 → error → continue
	_, err := os3.findObjectByType(8, 10, dmotPlainFileContents)
	if err == nil {
		t.Fatal("expected not-found error")
	}
}
