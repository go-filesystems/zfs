package filesystem_zfs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// ── GZIP (raw zlib stream) ─────────────────────────────────────────────────────

// makeZFSGzip builds a ZFS GZIP block: a raw zlib stream of `payload`.
// OpenZFS stores GZIP-compressed data as a bare zlib stream with no extra
// framing (module/zfs/gzip.c uses zlib compress2()/uncompress() directly).
func makeZFSGzip(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

func TestGzipDecompress_RoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog\n"), 64)
	src := makeZFSGzip(t, payload)
	got, err := gzipDecompress(src, len(payload))
	if err != nil {
		t.Fatalf("gzipDecompress: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

// TestGzipDecompress_PhysicalSlack mirrors the on-disk case where the physical
// buffer (psize) is rounded up and padded with zeros past the end of the zlib
// stream. The zlib trailer terminates the stream, so the slack is ignored.
func TestGzipDecompress_PhysicalSlack(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB, 0xCD, 0x00, 0x11}, 200)
	stream := makeZFSGzip(t, payload)
	// Pad to a 512-byte boundary the way a real psize buffer would be.
	padded := make([]byte, (len(stream)+511)/512*512)
	copy(padded, stream)
	got, err := gzipDecompress(padded, len(payload))
	if err != nil {
		t.Fatalf("gzipDecompress (padded): %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("padded round-trip mismatch")
	}
}

func TestGzipDecompress_Garbage(t *testing.T) {
	if _, err := gzipDecompress([]byte{0x00, 0x01, 0x02, 0x03}, 16); err == nil {
		t.Fatal("expected error for non-zlib input")
	}
}

func TestGzipDecompress_WrongSize(t *testing.T) {
	payload := []byte("hello world")
	src := makeZFSGzip(t, payload)
	if _, err := gzipDecompress(src, len(payload)+5); err == nil {
		t.Fatal("expected size-mismatch error")
	}
}

// ── ZSTD (zfs_zstdhdr_t + zstd frame) ──────────────────────────────────────────

// makeZFSZstd builds a ZFS ZSTD block: an 8-byte header (4-byte BE c_len,
// 4-byte BE raw_version_level) followed by a MAGICLESS zstd frame of `payload`.
// OpenZFS compresses with ZSTD_f_zstd1_magicless, which omits the 4-byte
// 0x28B52FFD magic; we replicate that by stripping it from a standard frame.
func makeZFSZstd(t *testing.T, payload []byte, level uint8) []byte {
	t.Helper()
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	std := enc.EncodeAll(payload, nil)
	enc.Close()
	if len(std) < 4 || !bytes.Equal(std[:4], []byte{0x28, 0xB5, 0x2F, 0xFD}) {
		t.Fatalf("expected standard zstd magic prefix, got %x", std[:min(4, len(std))])
	}
	frame := std[4:] // strip magic -> magicless, as ZFS stores it

	hdr := make([]byte, zstdHeaderSize)
	binary.BigEndian.PutUint32(hdr[:4], uint32(len(frame)))
	// raw_version_level: real ZFS packs version+level here. Decompression only
	// reads c_len and the frame, so the exact packing does not matter for the
	// read path. Encode a plausible value (version 1.4.5 = 10405, level in low
	// byte) so the field is non-trivial.
	binary.BigEndian.PutUint32(hdr[4:8], (10405<<8)|uint32(level))
	return append(hdr, frame...)
}

func TestZstdDecompress_RoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte("zstandard compresses ZFS data blocks well. "), 100)
	src := makeZFSZstd(t, payload, 3)
	got, err := zstdDecompress(src, len(payload))
	if err != nil {
		t.Fatalf("zstdDecompress: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

// TestZstdDecompress_PhysicalSlack pads the buffer past c_len to mimic the
// rounded-up psize buffer on disk. The header's c_len bounds the frame, so the
// slack is ignored.
func TestZstdDecompress_PhysicalSlack(t *testing.T) {
	payload := bytes.Repeat([]byte{0x01, 0x02, 0x03, 0x04, 0x00, 0x00}, 256)
	src := makeZFSZstd(t, payload, 1)
	padded := make([]byte, (len(src)+511)/512*512)
	copy(padded, src)
	got, err := zstdDecompress(padded, len(payload))
	if err != nil {
		t.Fatalf("zstdDecompress (padded): %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("padded round-trip mismatch")
	}
}

func TestZstdDecompress_TooShort(t *testing.T) {
	if _, err := zstdDecompress([]byte{0x00, 0x01, 0x02}, 16); err == nil {
		t.Fatal("expected error for src shorter than header")
	}
}

func TestZstdDecompress_BadCLen(t *testing.T) {
	// c_len declares more than the buffer holds.
	src := make([]byte, zstdHeaderSize+4)
	binary.BigEndian.PutUint32(src[:4], 1000)
	if _, err := zstdDecompress(src, 16); err == nil {
		t.Fatal("expected error for c_len > buffer")
	}
}

func TestZstdDecompress_BadFrame(t *testing.T) {
	// Valid header length but garbage frame bytes.
	src := make([]byte, zstdHeaderSize+4)
	binary.BigEndian.PutUint32(src[:4], 4)
	copy(src[zstdHeaderSize:], []byte{0xDE, 0xAD, 0xBE, 0xEF})
	if _, err := zstdDecompress(src, 16); err == nil {
		t.Fatal("expected error for invalid zstd frame")
	}
}

func TestZstdDecompress_WrongSize(t *testing.T) {
	payload := []byte("short")
	src := makeZFSZstd(t, payload, 3)
	if _, err := zstdDecompress(src, len(payload)+10); err == nil {
		t.Fatal("expected size-mismatch error")
	}
}

// TestZstdDecompress_RealOpenZFSBlock asserts zstdDecompress against the EXACT
// on-disk physical (psize) bytes of an L0 EMBEDDED blkptr captured from a real
// OpenZFS pool (zfs-2.3.2, compression=zstd). Capture procedure:
//
//	truncate -s 256M zstd.img
//	zpool create -o ashift=12 t_zstd zstd.img; zfs set compression=zstd t_zstd
//	printf 'small zstd file\n' > /t_zstd/small.txt   # 16 bytes
//	zpool export t_zstd
//	# read the L0 EMBEDDED blkptr (200L/25P) for /small.txt via the driver and
//	# dump the 37-byte embedded payload that feeds zstdDecompress.
//
// The payload is: 4-byte BE c_len (=0x1d=29), 4-byte BE raw_version_level
// (0x030028a5), then a 29-byte MAGICLESS zstd frame. If the magicless framing
// or header parsing regresses, this FAILS with a magic-number mismatch.
func TestZstdDecompress_RealOpenZFSBlock(t *testing.T) {
	// 37-byte embedded payload of /t_zstd/small.txt.
	src := mustHex(t, "0000001d030028a50000c5000088736d616c6c207a7374642066696c650a000100d955b004")
	const lsize = 512
	got, err := zstdDecompress(src, lsize)
	if err != nil {
		t.Fatalf("zstdDecompress(real block): %v", err)
	}
	want := []byte("small zstd file\n")
	if !bytes.HasPrefix(got, want) {
		t.Fatalf("prefix mismatch: got %q want %q", got[:len(want)], want)
	}
	for i := len(want); i < len(got); i++ {
		if got[i] != 0 {
			t.Fatalf("byte %d = %#x, want 0 (tail must be zero-filled)", i, got[i])
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}
