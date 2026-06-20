package filesystem_zfs

import (
	"encoding/binary"
	"testing"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// makeLZ4Source builds a ZFS-envelope LZ4 source from a pre-built raw LZ4 block.
func makeLZ4Source(raw []byte) []byte {
	src := make([]byte, 4+len(raw))
	binary.BigEndian.PutUint32(src[:4], uint32(len(raw)))
	copy(src[4:], raw)
	return src
}

// ── lz4Decompress ─────────────────────────────────────────────────────────────

func TestLZ4Decompress_TooShort(t *testing.T) {
	if _, err := lz4Decompress([]byte("ab"), 4); err == nil {
		t.Fatal("expected error for src < 4 bytes")
	}
}

func TestLZ4Decompress_BadCompSize(t *testing.T) {
	// Declare a compSize larger than the remaining data.
	src := []byte{0x00, 0x00, 0x01, 0x00} // compSize=256, but data is 0 bytes after header
	if _, err := lz4Decompress(src, 1); err == nil {
		t.Fatal("expected error for compSize > available data")
	}
}

func TestLZ4Decompress_OnlyLiterals(t *testing.T) {
	// token = 0x50 → litLen=5, no match section (last sequence)
	raw := append([]byte{0x50}, []byte("hello")...)
	got, err := lz4Decompress(makeLZ4Source(raw), 5)
	if err != nil {
		t.Fatalf("lz4Decompress: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

func TestLZ4Decompress_WithMatch(t *testing.T) {
	// Sequence: litLen=4 literals "abcd", then match offset=1 matchLen=4 (→ "dddd")
	// token = 0x40 (litLen=4, lower=0 → matchLen=4)
	raw := []byte{0x40, 'a', 'b', 'c', 'd', 0x01, 0x00}
	got, err := lz4Decompress(makeLZ4Source(raw), 8)
	if err != nil {
		t.Fatalf("lz4Decompress with match: %v", err)
	}
	if string(got) != "abcddddd" {
		t.Fatalf("got %q, want %q", got, "abcddddd")
	}
}

func TestLZ4DecodeBlock_ExtendedLiteralLength(t *testing.T) {
	// litLen = 15 + 1 = 16 (extra byte = 1 ≠ 255 terminates extension)
	raw := append([]byte{0xF0, 0x01}, make([]byte, 16)...) // token, extra, 16 zeros
	got, err := lz4DecodeBlock(raw, 16)
	if err != nil {
		t.Fatalf("extended literal length: %v", err)
	}
	if len(got) != 16 {
		t.Fatalf("len = %d, want 16", len(got))
	}
}

func TestLZ4DecodeBlock_ExtendedMatchLength(t *testing.T) {
	// After literals "abcd", a match with extended matchLen:
	// token = 0x4F → litLen=4, lower=15 → matchLen base=19; extra=1 → matchLen=20
	// offset=1, so copies last char 20 times
	raw := []byte{0x4F, 'a', 'b', 'c', 'd', 0x01, 0x00, 0x01}
	dstSize := 4 + 20 // = 24
	got, err := lz4DecodeBlock(raw, dstSize)
	if err != nil {
		t.Fatalf("extended match length: %v", err)
	}
	if len(got) != dstSize {
		t.Fatalf("len = %d, want %d", len(got), dstSize)
	}
}

func TestLZ4DecodeBlock_TruncatedMatchOffset(t *testing.T) {
	// Only 1 byte after literals → falls into `len(src)-si < 2` branch
	raw := []byte{0x10, 'x', 0x01} // litLen=1, then 1 byte remaining → no offset
	// This path breaks out of loop, returns padded result
	got, err := lz4DecodeBlock(raw, 5)
	if err != nil {
		t.Fatalf("short match offset: %v", err)
	}
	if got[0] != 'x' {
		t.Fatalf("got[0] = %q, want 'x'", got[0])
	}
}

func TestLZ4DecodeBlock_ZeroMatchOffset(t *testing.T) {
	// litLen=0, then offset=0 → error
	raw := []byte{0x00, 0x00, 0x00}
	if _, err := lz4DecodeBlock(raw, 4); err == nil {
		t.Fatal("expected zero-offset error")
	}
}

func TestLZ4DecodeBlock_InvalidMatchOffset(t *testing.T) {
	// "x" as single literal, then match offset=5 (beyond current output) → error
	raw := []byte{0x10, 'x', 0x05, 0x00}
	if _, err := lz4DecodeBlock(raw, 5); err == nil {
		t.Fatal("expected invalid-offset error")
	}
}

func TestLZ4DecodeBlock_LiteralOverflow(t *testing.T) {
	// token says 5 literals but only 3 bytes available
	raw := []byte{0x50, 'a', 'b', 'c'} // litLen=5 but only 3 available
	if _, err := lz4DecodeBlock(raw, 5); err == nil {
		t.Fatal("expected literal overflow error")
	}
}

func TestLZ4DecodeBlock_DstSizeExact(t *testing.T) {
	// result exactly fills dstSize — tests the `len(dst) >= dstSize` break path
	raw := []byte{0x20, 'a', 'b', 0x01, 0x00} // litLen=2 + match offset=1 matchLen=4
	got, err := lz4DecodeBlock(raw, 6)
	if err != nil {
		t.Fatalf("lz4DecodeBlock: %v", err)
	}
	if len(got) != 6 {
		t.Fatalf("len = %d, want 6", len(got))
	}
}

// ── lzjbDecompress ────────────────────────────────────────────────────────────

func TestLZJBDecompress_Literals(t *testing.T) {
	// Control byte = 0x00 → all 8 tokens are literals.
	src := append([]byte{0x00}, []byte("abcdefgh")...)
	got, err := lzjbDecompress(src, 8)
	if err != nil {
		t.Fatalf("lzjbDecompress: %v", err)
	}
	if string(got) != "abcdefgh" {
		t.Fatalf("got %q, want %q", got, "abcdefgh")
	}
}

func TestLZJBDecompress_BackRef(t *testing.T) {
	// ctrl=0x02 → bit0=literal, bit1=back-ref
	// literal 'a'; back-ref offset=1 copyLen=3 → copies dst[0]='a' 3 times → "aaaa"
	src := []byte{0x02, 'a', 0x00, 0x01}
	got, err := lzjbDecompress(src, 4)
	if err != nil {
		t.Fatalf("lzjbDecompress back-ref: %v", err)
	}
	if string(got) != "aaaa" {
		t.Fatalf("got %q, want %q", got, "aaaa")
	}
}

func TestLZJBDecompress_BackRefPastStart(t *testing.T) {
	// Back-ref with offset > current di → src2 < 0 → zero fill
	// ctrl=0x02: literal 'a', then back-ref with offset=2 (past start) → zero fill
	src := []byte{0x02, 'a', 0x00, 0x02}
	got, err := lzjbDecompress(src, 4)
	if err != nil {
		t.Fatalf("lzjbDecompress past-start: %v", err)
	}
	if got[0] != 'a' {
		t.Fatalf("got[0] = %q, want 'a'", got[0])
	}
	if got[1] != 0 || got[2] != 0 || got[3] != 0 {
		t.Fatalf("zeros not filled correctly: %v", got)
	}
}

func TestLZJBDecompress_TruncatedBackRef(t *testing.T) {
	// Control bit says back-ref but only 1 byte remains → no-op, break inner loop.
	src := []byte{0x02, 'a', 0x01} // back-ref needs 2 bytes but only 1 available
	got, err := lzjbDecompress(src, 4)
	if err != nil {
		t.Fatalf("lzjbDecompress truncated: %v", err)
	}
	if got[0] != 'a' {
		t.Fatalf("got[0] = %q, want 'a'", got[0])
	}
}

func TestLZJBDecompress_ZeroOffset(t *testing.T) {
	// Back-ref with offset=0 → break (the `if offset == 0 { break }` guard).
	// ctrl=0x02: literal 'a', back-ref hi=0x00 lo=0x00 (offset=0)
	src := []byte{0x02, 'a', 0x00, 0x00}
	got, err := lzjbDecompress(src, 4)
	if err != nil {
		t.Fatalf("lzjbDecompress zero-offset: %v", err)
	}
	// Only the first literal should be written; rest stays zero.
	if got[0] != 'a' {
		t.Fatalf("got[0] = %q, want 'a'", got[0])
	}
}

// ── zleDecompress ─────────────────────────────────────────────────────────────

func TestZLEDecompress_Literals(t *testing.T) {
	got, err := zleDecompress([]byte("hello"), 5)
	if err != nil {
		t.Fatalf("zleDecompress: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

func TestZLEDecompress_ZeroRun(t *testing.T) {
	// 'a' [0x00, 0x02] 'b' → "a\x00\x00\x00b" (n = 0x02+1 = 3 zeros)
	src := []byte{'a', 0x00, 0x02, 'b'}
	got, err := zleDecompress(src, 5)
	if err != nil {
		t.Fatalf("zleDecompress zero-run: %v", err)
	}
	if got[0] != 'a' || got[1] != 0 || got[2] != 0 || got[3] != 0 || got[4] != 'b' {
		t.Fatalf("got %v, want a\\x00\\x00\\x00b", got)
	}
}

func TestZLEDecompress_ZeroAtEnd(t *testing.T) {
	// [0x00] alone at end of src → `si >= len(src)` after reading the zero → di++
	src := []byte{0x00}
	got, err := zleDecompress(src, 1)
	if err != nil {
		t.Fatalf("zleDecompress zero-at-end: %v", err)
	}
	if got[0] != 0 {
		t.Fatalf("got %v, want [0]", got)
	}
}

func TestLZ4DecodeBlock_EmptySrc(t *testing.T) {
	// si=0 >= len(src)=0 → break at line 32; returns zero-padded dst.
	got, err := lz4DecodeBlock([]byte{}, 4)
	if err != nil {
		t.Fatalf("EmptySrc: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("len=%d want 4", len(got))
	}
}

func TestLZ4DecodeBlock_MatchLengthExt255(t *testing.T) {
	// Match length extension where first extra byte is 255 (loop continues once),
	// followed by a terminating byte. Covers the `extra != 255` false branch.
	//
	// Sequence 1: litLen=5 "abcde", match offset=1 matchLen=4 → "abcdeeee" (9 bytes)
	// Sequence 2: litLen=0, match offset=1, ext=[255,1] → matchLen=19+255+1=275
	raw := []byte{
		0x50, 'a', 'b', 'c', 'd', 'e', 0x01, 0x00, // seq1
		0x0F, 0x01, 0x00, 0xFF, 0x01, // seq2: token, offset lo/hi, ext1=255, ext2=1
	}
	dstSize := 9 + 275 // = 284
	got, err := lz4DecodeBlock(raw, dstSize)
	if err != nil {
		t.Fatalf("MatchLengthExt255: %v", err)
	}
	if len(got) != dstSize {
		t.Fatalf("len = %d, want %d", len(got), dstSize)
	}
	if got[0] != 'a' || got[8] != 'e' {
		t.Fatalf("unexpected content at [0]=%q [8]=%q", got[0], got[8])
	}
}
