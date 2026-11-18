//go:build libzstd

package filesystem_zfs

// Reference measurement of the zstd record decode against libzstd, one core,
// on the 128 KiB records of the read-path harness's word-like text compressed
// at the OpenZFS default (zstd-3, magicless frames, zfs_zstdhdr_t header). See
// libzstd_ref_cgo.go for the command.

import (
	"bytes"
	"encoding/binary"
	"testing"
)

const lzRecord = 128 << 10

type lzFixture struct {
	plain [][]byte
	zfs   [][]byte // 8-byte header + magicless frame
	raw   [][]byte // magicless frames
	ratio float64
}

var lzCached *lzFixture

func lzBuild(b *testing.B, level int) *lzFixture {
	if lzCached == nil {
		lzCached = lzBuild1(b, level)
	}
	return lzCached
}

func lzBuild1(b *testing.B, level int) *lzFixture {
	var buf bytes.Buffer
	if err := rpGen(&buf); err != nil {
		b.Fatal(err)
	}
	data := buf.Bytes()[:64<<20]
	f := &lzFixture{}
	var cs, ps int
	for off := 0; off < len(data); off += lzRecord {
		rec := data[off : off+lzRecord]
		frame := refCompress(rec, level)
		hdr := make([]byte, 8, 8+len(frame))
		binary.BigEndian.PutUint32(hdr, uint32(len(frame)))
		binary.BigEndian.PutUint32(hdr[4:], 0x030028a5)
		f.plain = append(f.plain, rec)
		f.raw = append(f.raw, frame)
		f.zfs = append(f.zfs, append(hdr, frame...))
		cs += len(frame)
		ps += len(rec)
	}
	f.ratio = float64(ps) / float64(cs)
	return f
}

func BenchmarkZstdRecordGo(b *testing.B) {
	f := lzBuild(b, 3)
	for k := range f.zfs {
		out, err := zstdDecompress(f.zfs[k], lzRecord)
		if err != nil || !bytes.Equal(out, f.plain[k]) {
			b.Fatal("mismatch", k, err)
		}
	}
	b.SetBytes(lzRecord)
	b.ReportMetric(f.ratio, "ratio")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := zstdDecompress(f.zfs[i%len(f.zfs)], lzRecord); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkZstdRecordGoExactDst is the control: the destination sized exactly
// to the record, as zstdDecompress did before the slack was added.
func BenchmarkZstdRecordGoExactDst(b *testing.B) {
	f := lzBuild(b, 3)
	b.SetBytes(lzRecord)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := f.zfs[i%len(f.zfs)]
		frame := append(append(make([]byte, 0, len(src)-4), zstdMagic...), src[8:]...)
		if out, err := zstdDecoder.DecodeAll(frame, make([]byte, 0, lzRecord)); err != nil || len(out) != lzRecord {
			b.Fatal(err)
		}
	}
}

func BenchmarkZstdRecordLibzstd(b *testing.B) {
	f := lzBuild(b, 3)
	d := newRefDecoder()
	dst := make([]byte, lzRecord)
	b.SetBytes(lzRecord)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if d.decode(dst, f.raw[i%len(f.raw)]) != lzRecord {
			b.Fatal("decompress")
		}
	}
}
