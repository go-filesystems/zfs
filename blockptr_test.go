package filesystem_zfs

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// ── helper ───────────────────────────────────────────────────────────────────

// makeTestBP builds a blkptr that points to a block of data stored in buf at byteOff.
func makeTestBP(byteOff int64, physSize, logicalSize int, compress uint8, dtype uint8) blkptr {
	return makeBlkptr(byteOff, physSize, logicalSize, compress, dtype, 0, 1)
}

// ── readBlock (null BP) ───────────────────────────────────────────────────────

func TestReadBlock_NullBP(t *testing.T) {
	// A null BP returns a zero-block of lsize bytes (lsize = 512 for prop=0).
	var bp blkptr // all zeros = null
	got, err := readBlock(bytes.NewReader(nil), 0, bp)
	if err != nil {
		t.Fatalf("readBlock null: %v", err)
	}
	if len(got) != 512 {
		t.Fatalf("len(got) = %d, want 512", len(got))
	}
}

// ── blkptr field accessors ────────────────────────────────────────────────────

func TestBlkptrDmuType(t *testing.T) {
	bp := blkptr{}
	bp.prop = makeProp(zcompressOff, 512, 512, dmotPlainFileContents, 0)
	if got := bp.dmuType(); got != dmotPlainFileContents {
		t.Fatalf("dmuType() = %d, want %d", got, dmotPlainFileContents)
	}
}

func TestBlkptrLevel(t *testing.T) {
	bp := blkptr{}
	bp.prop = makeProp(zcompressOff, 512, 512, dmotDirContents, 2)
	if got := bp.level(); got != 2 {
		t.Fatalf("level() = %d, want 2", got)
	}
}

func TestBlkptrDvasValid(t *testing.T) {
	bp := blkptr{}
	// No DVAs set → dvasValid = 0.
	if n := bp.dvasValid(); n != 0 {
		t.Fatalf("dvasValid() = %d, want 0", n)
	}
	// Set DVA 0 with asize512 = 8.
	bp.dva[0][0] = 8 // asize512 in bits 23:0
	if n := bp.dvasValid(); n != 1 {
		t.Fatalf("dvasValid() = %d, want 1", n)
	}
	// Set DVA 1 as well.
	bp.dva[1][0] = 8
	if n := bp.dvasValid(); n != 2 {
		t.Fatalf("dvasValid() = %d, want 2", n)
	}
}

// ── readBlock ─────────────────────────────────────────────────────────────────

func TestReadBlock_GangBlock(t *testing.T) {
	var bp blkptr
	bp.dva[0][1] = 1 << 63 // gang bit
	bp.dva[0][0] = 8       // asize
	bp.prop = makeProp(zcompressOff, 512, 512, dmotPlainFileContents, 0)
	if _, err := readBlock(bytes.NewReader(nil), 0, bp); err == nil {
		t.Fatal("expected gang block error")
	}
}

func TestReadBlock_ReadError(t *testing.T) {
	bp := makeTestBP(0, 512, 512, zcompressOff, dmotPlainFileContents)
	// Use a reader that fails.
	r := &limitedReader{data: make([]byte, 256)} // too short
	if _, err := readBlock(r, 0, bp); err == nil {
		t.Fatal("expected read error on short data")
	}
}

func TestReadBlock_LZ4Compression(t *testing.T) {
	// Build a tiny valid LZ4-encoded block stored in memory.
	raw := append([]byte{0x50}, []byte("hello")...)
	lz4Src := make([]byte, 4+len(raw))
	binary.BigEndian.PutUint32(lz4Src[:4], uint32(len(raw)))
	copy(lz4Src[4:], raw)

	// Store at offset 0 in a padded 512-byte buffer (psize = 512).
	buf := make([]byte, 512)
	copy(buf, lz4Src)

	// psize=512, lsize=1024: psize != lsize triggers the LZ4 decompression path.
	// makeProp requires lsize >= 512; use lsize=1024, psize=512.
	bp := blkptr{}
	bp.dva[0] = makeDVA(0, 512)
	bp.prop = makeProp(zcompressLZ4, 1024, 512, dmotPlainFileContents, 0)
	bp.birth = 1

	got, err := readBlock(bytes.NewReader(buf), 0, bp)
	if err != nil {
		t.Fatalf("readBlock LZ4: %v", err)
	}
	// lz4DecodeBlock pads to dstSize=1024; "hello" is in first 5 bytes.
	if len(got) != 1024 || !bytes.HasPrefix(got, []byte("hello")) {
		t.Fatalf("got len=%d prefix=%q, want len=1024 prefix=hello", len(got), got[:5])
	}
}

func TestReadBlock_LZJBCompression(t *testing.T) {
	// Build valid LZJB-encoded data (8 literals "abcdefgh").
	src := append([]byte{0x00}, []byte("abcdefgh")...)
	buf := make([]byte, 512)
	copy(buf, src)

	bp := blkptr{}
	bp.dva[0] = makeDVA(0, 512)
	bp.prop = makeProp(zcompressLZJB, 1024, 512, dmotPlainFileContents, 0)
	bp.birth = 1

	got, err := readBlock(bytes.NewReader(buf), 0, bp)
	if err != nil {
		t.Fatalf("readBlock LZJB: %v", err)
	}
	// lzjbDecompress pads to dstSize=1024; "abcdefgh" is in the first 8 bytes.
	if len(got) != 1024 || !bytes.HasPrefix(got, []byte("abcdefgh")) {
		t.Fatalf("got len=%d prefix=%q, want len=1024 prefix=abcdefgh", len(got), got[:8])
	}
}

func TestReadBlock_ZLECompression(t *testing.T) {
	// Build valid OpenZFS ZLE-encoded data (n=64): control 0x04 => 5 literal
	// bytes "hello", then zero runs filling the rest of the 1024-byte logical
	// block. dstSize is 1024, so 1019 zeros remain after "hello": encode them
	// as ff,ff,ff,ff,ff (5*192 = 960) + 0x82 (= 67-64? no): 1019 = 192*5 + 59,
	// 59 zeros => control 64+59-1 = 122 = 0x7a.
	src := append([]byte{0x04}, []byte("hello")...)
	src = append(src, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7a)
	buf := make([]byte, 512)
	copy(buf, src)

	bp := blkptr{}
	bp.dva[0] = makeDVA(0, 512)
	bp.prop = makeProp(zcompressZLE, 1024, 512, dmotPlainFileContents, 0)
	bp.birth = 1

	got, err := readBlock(bytes.NewReader(buf), 0, bp)
	if err != nil {
		t.Fatalf("readBlock ZLE: %v", err)
	}
	// Decompresses to dstSize=1024; "hello" is in first 5 bytes, rest zeros.
	if len(got) != 1024 || !bytes.HasPrefix(got, []byte("hello")) {
		t.Fatalf("got len=%d prefix=%q, want len=1024 prefix=hello", len(got), got[:5])
	}
	for i := 5; i < len(got); i++ {
		if got[i] != 0 {
			t.Fatalf("byte %d = %#x, want 0", i, got[i])
		}
	}
}

func TestReadBlock_UnsupportedCompression(t *testing.T) {
	buf := make([]byte, 512)
	bp := blkptr{}
	bp.dva[0] = makeDVA(0, 512)
	// Use zcompressGZIP1 (not handled) — need psize != lsize to reach the switch.
	bp.prop = makeProp(zcompressGZIP1, 1024, 512, dmotPlainFileContents, 0)
	bp.birth = 1

	if _, err := readBlock(bytes.NewReader(buf), 0, bp); err == nil {
		t.Fatal("expected unsupported compression error")
	}
}

func TestReadBlock_CompressEmptyPsizeLtLsize(t *testing.T) {
	// compress=zcompressEmpty, psize != lsize: should reach the outer `return raw, nil`
	// (the inner `if psize == lsize` branch is false).
	buf := make([]byte, 512)
	bp := blkptr{}
	bp.dva[0] = makeDVA(0, 512)
	bp.prop = makeProp(zcompressEmpty, 1024, 512, dmotPlainFileContents, 0)
	bp.birth = 1

	got, err := readBlock(bytes.NewReader(buf), 0, bp)
	if err != nil {
		t.Fatalf("readBlock zcompressEmpty: %v", err)
	}
	// Returns the raw 512-byte block (psize), not the full lsize.
	if len(got) != 512 {
		t.Fatalf("len(got) = %d, want 512", len(got))
	}
}

func TestReadEmbedded_PsizeLargerThanRaw(t *testing.T) {
	t.Skip("validates lib-internal (pre-2026-05-22) ZAP/EBP layout that's been corrected to match real OpenZFS — rewrite against real fixtures, see TestRAIDFixture_Single")
	// psize > 112 (len(raw)) triggers the guard `if psize > len(raw) { psize = len(raw) }`
	var bp blkptr
	// bits 24:0 = 200 → psize = 201 > 112; bits 47:40 = 4 → lsize = 5
	bp.prop = bpEmbeddedBit | (uint64(4) << 40) | uint64(200) | bpLEBit
	bp.dva[0][0] = 0xABCDEF0102030405
	data, _ := readEmbedded(bp)
	if len(data) != 5 {
		t.Fatalf("readEmbedded len = %d, want 5", len(data))
	}
}

// ── readEmbedded ──────────────────────────────────────────────────────────────

func TestReadEmbedded(t *testing.T) {
	t.Skip("validates lib-internal (pre-2026-05-22) ZAP/EBP layout that's been corrected to match real OpenZFS — rewrite against real fixtures, see TestRAIDFixture_Single")
	// Craft an embedded BP via readBlock.
	var bp blkptr
	// Set the embedded bit (bit 39), lsize in bits 47:40 = 4 (→ 5 bytes), psize bits 24:0 = 4 (→ 5 bytes).
	// Bits 15:0 can be anything since readEmbedded now reads from bits 47:40.
	bp.prop = bpEmbeddedBit | (uint64(4) << 40) | uint64(4) | bpLEBit
	// Store 5 known bytes in dva[0][0] (first 8 bytes of raw[]).
	bp.dva[0][0] = 0x0102030405060708
	// The first 5 bytes from raw should be the LE encoding of dva[0][0].
	data, _ := readEmbedded(bp)
	if len(data) != 5 {
		t.Fatalf("readEmbedded len = %d, want 5", len(data))
	}
	// raw[0..4] = LE bytes of 0x0102030405060708 = {0x08, 0x07, 0x06, 0x05, 0x04}
	if data[0] != 0x08 || data[1] != 0x07 || data[2] != 0x06 {
		t.Fatalf("readEmbedded data = %v, unexpected bytes", data)
	}
}

func TestReadBlock_EmbeddedPath(t *testing.T) {
	t.Skip("validates lib-internal (pre-2026-05-22) ZAP/EBP layout that's been corrected to match real OpenZFS — rewrite against real fixtures, see TestRAIDFixture_Single")
	var bp blkptr
	// lsize in bits 47:40 = 2 → 3 bytes; embedded bit set.
	bp.prop = bpEmbeddedBit | (uint64(2) << 40) | bpLEBit
	bp.dva[0][0] = 0xAABBCC // first 3 bytes are CC BB AA in LE -> wait...
	// We just verify no error and length is correct.
	data, err := readBlock(nil, 0, bp)
	if err != nil {
		t.Fatalf("readBlock embedded: %v", err)
	}
	if len(data) != 3 {
		t.Fatalf("readBlock embedded len = %d, want 3", len(data))
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// limitedReader is an io.ReaderAt backed by a short buffer (produces EOF on overrun).
type limitedReader struct {
	data []byte
}

func (lr *limitedReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(lr.data)) {
		return 0, io.EOF
	}
	n := copy(p, lr.data[off:])
	if n < len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
