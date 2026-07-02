package filesystem_zfs

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ── zapListAllRaw dispatch + micro path ────────────────────────────────────────

func TestZapListAllRaw_Micro(t *testing.T) {
	blk := newMicroZAPBlock(4096)
	if err := mzapInsert(blk, "answer", 42); err != nil {
		t.Fatalf("mzapInsert: %v", err)
	}
	dn := dnodeForFatZAP(1)
	got, err := zapListAllRaw(bytes.NewReader(blk), 0, dn)
	if err != nil {
		t.Fatalf("zapListAllRaw micro: %v", err)
	}
	want := make([]byte, 8)
	binary.LittleEndian.PutUint64(want, 42)
	if !bytes.Equal(got["answer"], want) {
		t.Errorf("micro raw value = %x, want %x", got["answer"], want)
	}
}

func TestZapListAllRaw_NullBP(t *testing.T) {
	dn := newDnode(dmotZAPOther, 1, 0, 0)
	if _, err := zapListAllRaw(bytes.NewReader(nil), 0, dn); err == nil {
		t.Fatal("expected null-BP error")
	}
}

func TestZapListAllRaw_BlockTooSmall(t *testing.T) {
	dn := dnodeForFatZAP(1)
	dn.datablkszsec = 1
	dn.setBlkptrAt(0, makeBlkptr(0, 512, 512, zcompressOff, dmotZAPOther, 0, 1))
	dn.encode()
	if _, err := zapListAllRaw(bytes.NewReader(make([]byte, 4)), 0, dn); err == nil {
		t.Fatal("expected block-too-small error")
	}
}

func TestZapListAllRaw_UnknownType(t *testing.T) {
	buf := make([]byte, 4096)
	binary.LittleEndian.PutUint64(buf[:8], 0xBADC0FFEE)
	dn := dnodeForFatZAP(1)
	if _, err := zapListAllRaw(bytes.NewReader(buf), 0, dn); err == nil {
		t.Fatal("expected unknown-type error")
	}
}

func TestParseMicroZAPRaw_SkipsFreeSlots(t *testing.T) {
	blk := newMicroZAPBlock(4096)
	_ = mzapInsert(blk, "k1", 1)
	_ = mzapInsert(blk, "k2", 2)
	m := parseMicroZAPRaw(blk)
	if len(m) != 2 {
		t.Fatalf("parseMicroZAPRaw entries = %d, want 2", len(m))
	}
	if binary.LittleEndian.Uint64(m["k2"]) != 2 {
		t.Errorf("k2 = %x", m["k2"])
	}
}

// ── readZAPLeafRawValue ────────────────────────────────────────────────────────

// buildLeafRawByteValue builds a one-block fat-ZAP leaf whose single entry
// stores a byte-array (intLen=1) value spanning as many array chunks as
// needed, and returns the leaf block plus the entry's chunk indices.
func buildLeafByteValueLeaf(t *testing.T, key string, value []byte) []byte {
	t.Helper()
	const blkSz = 4096
	le := binary.LittleEndian
	leaf := make([]byte, blkSz)
	le.PutUint64(leaf[0:], zbtLeaf)
	le.PutUint32(leaf[24:], zapLeafMagic)
	le.PutUint16(leaf[30:], 1)
	le.PutUint16(leaf[32:], 0)
	hashTabSz := blkSz / 16
	chunksStart := 48 + hashTabSz

	// chunk 0: entry; chunk 1: name; chunks 2.. : value array chain.
	name := append([]byte(key), 0)
	nameChunks := (len(name) + 20) / 21
	valChunks := (len(value) + 20) / 21

	// entry
	setEntryChunk(leaf, chunksStart, 0, 1 /*nameChunk*/, len(name), 1+nameChunks /*valChunk*/, len(value) /*numInts*/, 1 /*intLen*/)
	// name chunks
	writeChain(leaf, chunksStart, 1, name)
	// value chunks
	writeChain(leaf, chunksStart, 1+nameChunks, value)
	_ = valChunks
	return leaf
}

// writeChain writes data across consecutive array chunks starting at
// startChunk, linking each to the next and terminating with 0xFFFF.
func writeChain(blk []byte, chunksStart, startChunk int, data []byte) {
	le := binary.LittleEndian
	idx := startChunk
	for off := 0; off < len(data) || (len(data) == 0 && off == 0); off += 21 {
		coff := chunksStart + idx*zapLeafChunkSize
		blk[coff] = 251
		n := 21
		if off+n > len(data) {
			n = len(data) - off
		}
		copy(blk[coff+1:], data[off:off+n])
		if off+21 < len(data) {
			le.PutUint16(blk[coff+22:], uint16(idx+1))
		} else {
			le.PutUint16(blk[coff+22:], 0xFFFF)
		}
		idx++
	}
}

func TestReadZAPLeafRawValue_ByteArrayMultiChunk(t *testing.T) {
	// A 40-byte value spans two array chunks (21 + 19).
	val := make([]byte, 40)
	for i := range val {
		val[i] = byte(i + 1)
	}
	leaf := buildLeafByteValueLeaf(t, "blob", val)
	got, err := parseFatZAPLeafRaw(leaf)
	if err != nil {
		t.Fatalf("parseFatZAPLeafRaw: %v", err)
	}
	if !bytes.Equal(got["blob"], val) {
		t.Errorf("byte-array value = %x, want %x", got["blob"], val)
	}
}

func TestReadZAPLeafRawValue_IntNormalisation(t *testing.T) {
	// Store a big-endian 8-byte integer (intLen=8) and confirm the raw
	// reader re-emits it little-endian.
	const blkSz = 4096
	le := binary.LittleEndian
	leaf := make([]byte, blkSz)
	le.PutUint64(leaf[0:], zbtLeaf)
	le.PutUint32(leaf[24:], zapLeafMagic)
	le.PutUint16(leaf[30:], 1)
	hashTabSz := blkSz / 16
	chunksStart := 48 + hashTabSz
	name := append([]byte("n"), 0)
	setEntryChunk(leaf, chunksStart, 0, 1, len(name), 2, 1 /*numInts*/, 8 /*intLen*/)
	writeChain(leaf, chunksStart, 1, name)
	// value: big-endian 0x0102030405060708
	beVal := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	writeChain(leaf, chunksStart, 2, beVal)

	got, err := parseFatZAPLeafRaw(leaf)
	if err != nil {
		t.Fatalf("parseFatZAPLeafRaw: %v", err)
	}
	if v := le.Uint64(got["n"]); v != 0x0102030405060708 {
		t.Errorf("normalised int = %#x, want 0x0102030405060708", v)
	}
}

func TestReadZAPLeafRawValue_Guards(t *testing.T) {
	if readZAPLeafRawValue(nil, 0, 0, 0, 0, 8) != nil {
		t.Error("numInts=0 must yield nil")
	}
	if readZAPLeafRawValue(nil, 0, 0, 0, 1, 0) != nil {
		t.Error("intLen=0 must yield nil")
	}
}

func TestParseFatZAPLeafRaw_BadBlock(t *testing.T) {
	if _, err := parseFatZAPLeafRaw(make([]byte, 10)); err == nil {
		t.Fatal("expected too-short error")
	}
	blk := make([]byte, 4096)
	binary.LittleEndian.PutUint64(blk[0:], 0xdead) // wrong block type
	if _, err := parseFatZAPLeafRaw(blk); err == nil {
		t.Fatal("expected bad-block-type error")
	}
}

func TestParseFatZAPRaw_BadMagic(t *testing.T) {
	hdr := make([]byte, 4096)
	binary.LittleEndian.PutUint64(hdr[0:], zbtHeader)
	binary.LittleEndian.PutUint64(hdr[8:], 0xbad) // wrong magic
	dn := dnodeForFatZAP(1)
	if _, err := parseFatZAPRaw(bytes.NewReader(hdr), 0, dn, hdr); err == nil {
		t.Fatal("expected bad-magic error")
	}
}
