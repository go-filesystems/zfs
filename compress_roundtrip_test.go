package filesystem_zfs

// compress_roundtrip_test.go – End-to-end validation of the compressed
// data-block read path against REAL (spec-compliant) compressed payloads.
//
// The existing compress_test.go feeds hand-crafted byte sequences that exercise
// individual decoder branches. This file complements it by compressing real
// data with independent, spec-compliant reference encoders (implemented here,
// NOT reusing the production decoder) and asserting that the production
// decoders round-trip it exactly. It also drives the actual block read path
// (readEmbedded, keyed on the block pointer's compression type) so the wiring
// — not just the raw codec — is covered. No external tools, zpool, or kernel
// modules are required.

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ── reference LZ4 block encoder ───────────────────────────────────────────────
//
// A minimal but spec-compliant LZ4 block encoder. It emits standard LZ4
// sequences (token, optional extended literal length, literals, 16-bit LE match
// offset, optional extended match length) and honours the LZ4 end-of-block
// rules: the last sequence is literals-only and the last 5 bytes are always
// literals. This is intentionally independent of the production decoder so a
// round-trip exercises the decoder against externally-valid input.
func refLZ4Encode(in []byte) []byte {
	const (
		minMatch     = 4
		lastLiterals = 5 // last 5 bytes must be literals
		mfLimit      = 12
		hashLog      = 12
		hashSize     = 1 << hashLog
	)
	var out []byte
	var table [hashSize]int
	for i := range table {
		table[i] = -1
	}
	hash := func(p int) uint32 {
		v := binary.LittleEndian.Uint32(in[p:])
		return (v * 2654435761) >> (32 - hashLog)
	}
	emitLen := func(n int) {
		for n >= 255 {
			out = append(out, 255)
			n -= 255
		}
		out = append(out, byte(n))
	}

	n := len(in)
	anchor := 0
	i := 0
	// Need at least mfLimit bytes of look-ahead to attempt a match.
	matchEnd := n - mfLimit
	for i < matchEnd {
		h := hash(i)
		ref := table[h]
		table[h] = i
		if ref < 0 || ref < i-65535 ||
			binary.LittleEndian.Uint32(in[ref:]) != binary.LittleEndian.Uint32(in[i:]) {
			i++
			continue
		}
		// Extend the match.
		mlen := minMatch
		for i+mlen < n-lastLiterals && in[ref+mlen] == in[i+mlen] {
			mlen++
		}
		litLen := i - anchor
		token := byte(0)
		if litLen >= 15 {
			token |= 0xF0
		} else {
			token |= byte(litLen) << 4
		}
		extMatch := mlen - minMatch
		if extMatch >= 15 {
			token |= 0x0F
		} else {
			token |= byte(extMatch)
		}
		out = append(out, token)
		if litLen >= 15 {
			emitLen(litLen - 15)
		}
		out = append(out, in[anchor:anchor+litLen]...)
		offset := i - ref
		out = append(out, byte(offset), byte(offset>>8))
		if extMatch >= 15 {
			emitLen(extMatch - 15)
		}
		i += mlen
		anchor = i
	}
	// Final literal-only sequence covering the remaining bytes.
	litLen := n - anchor
	token := byte(0)
	if litLen >= 15 {
		token |= 0xF0
	} else {
		token |= byte(litLen) << 4
	}
	out = append(out, token)
	if litLen >= 15 {
		emitLen(litLen - 15)
	}
	out = append(out, in[anchor:]...)
	return out
}

// zfsFrameLZ4 wraps a raw LZ4 block in ZFS's 4-byte big-endian length envelope.
func zfsFrameLZ4(raw []byte) []byte {
	src := make([]byte, 4+len(raw))
	binary.BigEndian.PutUint32(src[:4], uint32(len(raw)))
	copy(src[4:], raw)
	return src
}

// refZLEEncode is a spec-compliant OpenZFS ZLE encoder (n=64), mirroring
// module/zfs/zle.c:zfs_zle_compress_buf. It is INDEPENDENT of the production
// decoder (zleDecompress): it does not call it nor share its loop.
//
// Encoding (n=64):
//   - a run of L non-zero (literal) bytes is emitted as control byte (L-1)
//     followed by the L bytes, with L capped at n per chunk;
//   - a run of Z zero bytes is emitted as control byte (n + Z - 1) with no
//     following data, with Z capped at (256 - n) per chunk.
func refZLEEncode(in []byte) []byte {
	const n = 64
	var out []byte
	i := 0
	for i < len(in) {
		if in[i] == 0 {
			// Zero run, capped at (256-n) per control byte.
			run := 0
			for i < len(in) && in[i] == 0 && run < (256-n) {
				run++
				i++
			}
			out = append(out, byte(n+run-1))
		} else {
			// Literal run, capped at n per control byte.
			start := i
			cnt := 0
			for i < len(in) && in[i] != 0 && cnt < n {
				cnt++
				i++
			}
			out = append(out, byte(cnt-1))
			out = append(out, in[start:start+cnt]...)
		}
	}
	return out
}

// ── round-trip tests ──────────────────────────────────────────────────────────

// lz4Payloads returns a spread of inputs that exercise literals-only,
// short matches, long (extended) matches, and extended literal runs.
func lz4Payloads() map[string][]byte {
	rep := bytes.Repeat([]byte("ABCD"), 300)                  // 1200 bytes, long matches
	mixed := append([]byte("the quick brown fox "), rep...)   // literals then matches
	zeros := make([]byte, 777)                                // long zero run -> big match
	textRun := bytes.Repeat([]byte("xyz123"), 64)             // extended-length matches
	literals := []byte("abcdefghijklmnopqrstuvwxyz0123456789") // all-literal (incompressible-ish)
	return map[string][]byte{
		"repetitive":  rep,
		"mixed":       mixed,
		"zeros":       zeros,
		"textRun":     textRun,
		"literals":    literals,
		"single":      {0x42},
		"empty":       {},
	}
}

func TestLZ4Decompress_RoundTripRealData(t *testing.T) {
	for name, want := range lz4Payloads() {
		t.Run(name, func(t *testing.T) {
			framed := zfsFrameLZ4(refLZ4Encode(want))
			got, err := lz4Decompress(framed, len(want))
			if err != nil {
				t.Fatalf("lz4Decompress(%s): %v", name, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s round-trip mismatch:\n got len=%d\nwant len=%d\nfirst diff at %d",
					name, len(got), len(want), firstDiff(got, want))
			}
		})
	}
}

func TestZLEDecompress_RoundTripRealData(t *testing.T) {
	cases := map[string][]byte{
		"sparse":   append(append([]byte("head"), make([]byte, 500)...), []byte("tail")...),
		"allZero":  make([]byte, 333),
		"noZero":   []byte("dense data with no zero bytes at all"),
		"altZero":  {1, 0, 2, 0, 0, 3, 0, 0, 0, 4},
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := zleDecompress(refZLEEncode(want), len(want))
			if err != nil {
				t.Fatalf("zleDecompress(%s): %v", name, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s round-trip mismatch at byte %d", name, firstDiff(got, want))
			}
		})
	}
}

// TestZLEDecompress_RealOpenZFSBlocks asserts zleDecompress against GOLDEN ZLE
// payloads extracted from a real OpenZFS pool (zpool create + compression=zle),
// not against this file's own reference encoder. These are the exact on-disk
// physical (psize) bytes of L0 EMBEDDED blkptrs, captured via:
//
//	zpool create -o ashift=12 zletest <img>; zfs set compression=zle zletest
//	printf 'small zle file\n' > /zletest/small.txt      # 15 bytes
//	dd if=/dev/zero bs=4096 count=1 of=/zletest/sparse.bin; printf HEADER | dd conv=notrunc ...
//	zdb -ddddd zletest/ <obj>   # shows the L0 EMBEDDED blkptr + 200L/13P, 1000L/1dP
//	zdb -R zletest <dva>:<size>:dr  # raw decompressed block holding the embedded payload
//
// OpenZFS uses the ZLE level n=64 (module/zfs/zio_compress.c: {"zle", 64, ...}).
// If zleDecompress regresses to the old non-spec format these will FAIL.
func TestZLEDecompress_RealOpenZFSBlocks(t *testing.T) {
	type vec struct {
		name  string
		psize []byte // exact on-disk ZLE physical payload
		lsize int    // logical (decompressed) block size
		want  []byte // expected decompressed prefix (rest is zeros up to lsize)
	}
	vecs := []vec{
		{
			// /zletest/small.txt: "small zle file\n" (15 bytes) in a 512-byte
			// logical block. blkptr: 200L/13P (psize=0x13=19). Control 0x0e =>
			// 15 literals; then ff,ff,b0 => 192+192+113 = 497 zeros.
			name:  "small.txt",
			psize: []byte{0x0e, 's', 'm', 'a', 'l', 'l', ' ', 'z', 'l', 'e', ' ', 'f', 'i', 'l', 'e', '\n', 0xff, 0xff, 0xb0},
			lsize: 512,
			want:  []byte("small zle file\n"),
		},
		{
			// /zletest/sparse.bin: "HEADER" (6 bytes) in a 4096-byte logical
			// block. blkptr: 1000L/1dP (psize=0x1d=29). Control 0x05 => 6
			// literals; then ff*21 (=4032 zeros) + 0x79 (=58 zeros) = 4090 zeros.
			name: "sparse.bin",
			psize: append(append([]byte{0x05}, []byte("HEADER")...),
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x79),
			lsize: 4096,
			want:  []byte("HEADER"),
		},
	}
	for _, v := range vecs {
		t.Run(v.name, func(t *testing.T) {
			got, err := zleDecompress(v.psize, v.lsize)
			if err != nil {
				t.Fatalf("zleDecompress(%s): %v", v.name, err)
			}
			if len(got) != v.lsize {
				t.Fatalf("%s: got len %d, want %d", v.name, len(got), v.lsize)
			}
			if !bytes.HasPrefix(got, v.want) {
				t.Fatalf("%s: prefix mismatch: got %q want %q", v.name, got[:len(v.want)], v.want)
			}
			// Everything after the literal prefix must be zero.
			for i := len(v.want); i < len(got); i++ {
				if got[i] != 0 {
					t.Fatalf("%s: byte %d = %#x, want 0", v.name, i, got[i])
				}
			}
		})
	}
}

// TestReadEmbedded_LZ4CompressedBlock drives the real block read path: it builds
// an embedded block pointer carrying an LZ4-compressed payload (keyed on
// zcompressLZ4) and asserts readEmbedded decompresses it transparently.
func TestReadEmbedded_LZ4CompressedBlock(t *testing.T) {
	// Payload small enough to fit in the 112-byte embedded payload region
	// after compression.
	want := bytes.Repeat([]byte("zfs-embedded-"), 8) // 104 bytes, highly compressible
	raw := refLZ4Encode(want)
	framed := zfsFrameLZ4(raw)
	if len(framed) > 112 {
		t.Fatalf("framed payload %d does not fit embedded region", len(framed))
	}

	bp := buildEmbeddedBP(t, framed, len(want), zcompressLZ4)
	got, err := readEmbedded(bp)
	if err != nil {
		t.Fatalf("readEmbedded: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("embedded LZ4 mismatch at byte %d: got %q want %q",
			firstDiff(got, want), got, want)
	}
}

// TestReadEmbedded_ZLECompressedBlock does the same for ZLE compression.
func TestReadEmbedded_ZLECompressedBlock(t *testing.T) {
	want := append([]byte("zle"), make([]byte, 90)...) // mostly zeros, compresses tiny
	enc := refZLEEncode(want)
	if len(enc) > 112 {
		t.Fatalf("ZLE payload %d does not fit embedded region", len(enc))
	}
	bp := buildEmbeddedBP(t, enc, len(want), zcompressZLE)
	got, err := readEmbedded(bp)
	if err != nil {
		t.Fatalf("readEmbedded: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("embedded ZLE mismatch at byte %d", firstDiff(got, want))
	}
}

// buildEmbeddedBP packs a compressed payload into the 112-byte payload region of
// an embedded block pointer, mirroring readEmbedded's word layout, and sets the
// embedded flag, lsize, psize, and compression type in prop.
func buildEmbeddedBP(t *testing.T, payload []byte, lsize int, comp uint8) blkptr {
	t.Helper()
	if len(payload) > 112 {
		t.Fatalf("payload %d exceeds 112-byte embedded region", len(payload))
	}
	var raw [112]byte
	copy(raw[:], payload)
	le := binary.LittleEndian

	var bp blkptr
	for i := 0; i < 3; i++ {
		bp.dva[i][0] = le.Uint64(raw[i*16:])
		bp.dva[i][1] = le.Uint64(raw[i*16+8:])
	}
	bp.pad[0] = le.Uint64(raw[48:])
	bp.pad[1] = le.Uint64(raw[56:])
	bp.physBirth = le.Uint64(raw[64:])
	bp.fill = le.Uint64(raw[72:])
	for i := 0; i < 4; i++ {
		bp.cksum[i] = le.Uint64(raw[80+i*8:])
	}

	// prop: lsize-1 (25 bits), psize-1 (7 bits @25), comp (7 bits @32), embedded bit @39.
	prop := uint64(lsize-1) & 0x1FFFFFF
	prop |= (uint64(len(payload)-1) & 0x7F) << 25
	prop |= (uint64(comp) & 0x7F) << 32
	prop |= bpEmbeddedBit
	bp.prop = prop
	return bp
}

func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return n
	}
	return -1
}
