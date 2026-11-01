package filesystem_zfs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"testing"

	"github.com/go-volumes/safeio"
)

// Memory-bomb regression tests: every input-driven allocation must be refused
// or bounded BEFORE it happens. Each asserts the error and that the whole call
// allocated little (runtime.MemStats.TotalAlloc is cumulative: an allocation
// that is freed afterwards still shows).

const bombAllocLimit = 1 << 20

func allocDelta(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// embeddedBP builds an embedded block pointer: lsize and psize in bytes, comp
// the compression code.
func embeddedBP(lsize, psize uint64, comp uint8) blkptr {
	return blkptr{prop: bpEmbeddedBit | (lsize - 1) | (psize-1)<<25 | uint64(comp)<<32}
}

// A 128-byte embedded block pointer declaring a 16 MiB logical size allocated
// 16 MiB even though its payload is at most 112 bytes.
func TestBomb_EmbeddedLsize(t *testing.T) {
	for _, comp := range []uint8{zcompressOff, zcompressLZ4, zcompressLZJB, zcompressZLE, zcompressGZIP1} {
		var err error
		got := allocDelta(func() { _, err = readEmbedded(embeddedBP(16<<20, 1, comp)) })
		t.Logf("comp %d: allocated %d bytes, err=%v", comp, got, err)
		if err == nil {
			t.Errorf("comp %d: 16 MiB from 1 byte accepted", comp)
		}
		if got > bombAllocLimit {
			t.Errorf("comp %d: allocated %d bytes before refusing", comp, got)
		}
	}
}

// LZ4 match lengths are extended by 255-valued bytes with no limit in the
// format; the decoder appended every byte of the match before comparing with
// the destination size.
func TestBomb_LZ4MatchLength(t *testing.T) {
	src := []byte{0x1F, 'a', 0x01, 0x00}
	src = append(src, bytes.Repeat([]byte{0xFF}, 1<<20)...)
	src = append(src, 0x00)
	var out []byte
	var err error
	got := allocDelta(func() { out, err = lz4DecodeBlock(src, 4096) })
	t.Logf("allocated %d bytes, err=%v", got, err)
	// The block is decoded up to the destination, as before; it just no longer
	// generates the 267 MB it would then have thrown away.
	if err != nil || len(out) != 4096 {
		t.Fatalf("len=%d err=%v", len(out), err)
	}
	if got > bombAllocLimit {
		t.Fatalf("allocated %d bytes for a %d-byte block", got, len(src))
	}
}

// Same for literal runs.
func TestBomb_LZ4LiteralLength(t *testing.T) {
	src := []byte{0xF0}
	src = append(src, bytes.Repeat([]byte{0xFF}, 64)...)
	src = append(src, 0x00)
	src = append(src, make([]byte, 255*64+15)...)
	got := allocDelta(func() { _, _ = lz4DecodeBlock(src, 4096) })
	if got > bombAllocLimit {
		t.Fatalf("allocated %d bytes", got)
	}
}

// The expansion gate is exact: a destination the input can produce is decoded
// (255 x 16 input bytes), one byte more is refused.
func TestBomb_ExpansionBoundExact(t *testing.T) {
	if err := checkExpansion("lz4", 16, 255*16+expansionSlack, lz4MaxExpansion); err != nil {
		t.Fatalf("at the bound: %v", err)
	}
	if err := checkExpansion("lz4", 16, 255*16+expansionSlack+1, lz4MaxExpansion); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("one over: err = %v", err)
	}
	if err := checkExpansion("lz4", 0, 4, lz4MaxExpansion); err != nil {
		t.Fatalf("empty stream into a small zero-padded block: %v", err)
	}
	if err := checkExpansion("lz4", 16, -1, lz4MaxExpansion); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("negative: err = %v", err)
	}
	// Through the codecs: 8 source bytes cannot make 8*8+1 LZJB bytes.
	if _, err := lzjbDecompress(make([]byte, 8), 8*lzjbMaxExpansion+expansionSlack+1); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("lzjb one over: err = %v", err)
	}
	if _, err := zleDecompress(make([]byte, 8), 8*zleMaxExpansion+expansionSlack+1); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("zle one over: err = %v", err)
	}
}

// A real, maximal LZ4 stream still round-trips through the gate: a 1 MiB block
// of one repeated byte is a handful of 255-valued length bytes.
func TestBomb_LZ4MaximalRatioStillDecodes(t *testing.T) {
	const want = 1 << 20
	// token: 1 literal, match nibble 15; literal 'z'; offset 1; length bytes
	// 255 x n to reach want-1 match bytes (19 + 255n + r).
	body := []byte{0x1F, 'z', 0x01, 0x00}
	rem := want - 1 - 19
	for rem >= 255 {
		body = append(body, 0xFF)
		rem -= 255
	}
	body = append(body, byte(rem))
	// ZFS framing: 4-byte big-endian length, then the block.
	src := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	src = append(src, body...)
	out, err := lz4Decompress(src, want)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != want || out[0] != 'z' || out[want-1] != 'z' {
		t.Fatalf("len=%d", len(out))
	}
}

// Block pointer sizes: the kernel refuses LSIZE/PSIZE above SPA_MAXBLOCKSIZE
// (16 MiB), the fields reach 32 MiB; the bound is exact.
func TestBomb_BlkptrSizesExact(t *testing.T) {
	mk := func(lsize, psize int) blkptr {
		bp := blkptr{prop: uint64(lsize/512-1) | uint64(psize/512-1)<<16}
		bp.dva[0] = [2]uint64{1, 1}
		return bp
	}
	if err := verifyBlkptrSizes(mk(spaMaxBlockSize, spaMaxBlockSize)); err != nil {
		t.Fatalf("at the bound: %v", err)
	}
	if err := verifyBlkptrSizes(mk(spaMaxBlockSize+512, 512)); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("lsize one sector over: err = %v", err)
	}
	if err := verifyBlkptrSizes(mk(512, spaMaxBlockSize+512)); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("psize one sector over: err = %v", err)
	}
	var err error
	got := allocDelta(func() { _, err = readBlock(&bombReaderAt{b: make([]byte, 4096)}, 0, mk(32<<20, 32<<20)) })
	if !errors.Is(err, safeio.ErrTooLarge) || got > bombAllocLimit {
		t.Fatalf("32 MiB psize: err=%v allocated %d", err, got)
	}
	// A hole (no DVAs) declaring 32 MiB is refused too, not zero-filled.
	hole := blkptr{prop: uint64(32<<20/512 - 1)}
	got = allocDelta(func() { _, err = readBlock(&bombReaderAt{}, 0, hole) })
	if !errors.Is(err, safeio.ErrTooLarge) || got > bombAllocLimit {
		t.Fatalf("32 MiB hole: err=%v allocated %d", err, got)
	}
	// Embedded: lsize bound exact, and uncompressed lsize may not exceed the payload.
	if _, err := readEmbedded(embeddedBP(spaMaxBlockSize+1, 1, zcompressOff)); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("embedded lsize over: err = %v", err)
	}
	if _, err := readEmbedded(embeddedBP(bpePayloadSize, bpePayloadSize, zcompressOff)); err != nil {
		t.Fatalf("embedded full payload: %v", err)
	}
	if _, err := readEmbedded(embeddedBP(bpePayloadSize+1, bpePayloadSize, zcompressOff)); err == nil {
		t.Fatal("embedded lsize 113 from a 112-byte payload accepted")
	}
}

// The read limit is exact: an object of 1 block of 128 KiB reads at a 128 KiB
// limit and is refused at 128 KiB - 1; SetMaxReadSize drives it.
func TestBomb_MaxReadSizeExact(t *testing.T) {
	dn := newDnode(dmotPlainFileContents, 1, 0, 0)
	dn.maxblkid = 1 // two 128 KiB blocks
	// Blocks 0 and 1: block 1 is past nblkptr, so a read that passes the limit
	// fails on it with a non-limit error; what is asserted is the limit's side.
	r := &bombReaderAt{b: make([]byte, 4096)}
	if _, err := readDnodeDataMax(r, 0, dn, 2*131072); errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("at the limit refused: %v", err)
	}
	if _, err := readDnodeDataMax(r, 0, dn, 2*131072-1); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("one byte under: err = %v, want ErrTooLarge", err)
	}
	fs := &zfsFS{}
	if fs.MaxReadSize() != DefaultMaxReadSize {
		t.Fatalf("default = %d", fs.MaxReadSize())
	}
	fs.SetMaxReadSize(4096)
	if fs.MaxReadSize() != 4096 {
		t.Fatalf("MaxReadSize = %d", fs.MaxReadSize())
	}
	fs.SetMaxReadSize(-1)
	if fs.MaxReadSize() != DefaultMaxReadSize {
		t.Fatalf("not restored: %d", fs.MaxReadSize())
	}
	// A data block size above SPA_MAXBLOCKSIZE is refused before anything is sized from it.
	big := newDnode(dmotPlainFileContents, 1, 0, 0)
	big.datablkszsec = 0xFFFF
	big.maxblkid = 1
	if _, err := readDnodeData(r, 0, big); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("32 MiB data blocks: err = %v", err)
	}
}

// zstd: a frame declaring a 256 MiB window must not make the shared decoder
// allocate it (a negative control: DecodeAll never did, the option now makes
// the limit explicit and 16 MiB is the ceiling).
func TestBomb_ZstdDeclaredWindow(t *testing.T) {
	frame := []byte{0x00, 0x40, 0x01, 0x00, 0x00} // FHD=0, window descriptor 2^28, empty last raw block
	src := make([]byte, 8, 8+len(frame))
	binary.BigEndian.PutUint32(src[0:], uint32(len(frame)))
	src = append(src, frame...)
	var err error
	got := allocDelta(func() { _, err = zstdDecompress(src, 0) })
	t.Logf("allocated %d bytes, err=%v", got, err)
	if got > bombAllocLimit {
		t.Fatalf("allocated %d bytes for a %d-byte block", got, len(src))
	}
}

// zstd frame whose header declares a 3 GiB content size.
func TestBomb_ZstdContentSize(t *testing.T) {
	frame := []byte{0xE0, 0, 0, 0, 0xC0, 0, 0, 0, 0x01, 0x00, 0x00} // FCS = 3<<30, one empty last raw block
	src := make([]byte, 8, 8+len(frame))
	binary.BigEndian.PutUint32(src[0:], uint32(len(frame)))
	src = append(src, frame...)
	var err error
	got := allocDelta(func() { _, err = zstdDecompress(src, 4096) })
	t.Logf("allocated %d bytes, err=%v", got, err)
	if err == nil {
		t.Fatal("3 GiB content size accepted for a 4096-byte block")
	}
	if got > bombAllocLimit {
		t.Fatalf("allocated %d bytes for a %d-byte block", got, len(src))
	}
}

// gzip allocated the destination before decoding a byte.
func TestBomb_GzipPreallocation(t *testing.T) {
	var zb bytes.Buffer
	zw := zlib.NewWriter(&zb)
	zw.Write([]byte("tiny"))
	zw.Close()
	var err error
	got := allocDelta(func() { _, err = gzipDecompress(zb.Bytes(), 16<<20) })
	t.Logf("allocated %d bytes, err=%v", got, err)
	if err == nil {
		t.Fatal("4 bytes accepted as 16 MiB")
	}
	if got > bombAllocLimit {
		t.Fatalf("allocated %d bytes", got)
	}
}

// dn_maxblkid is attacker-controlled; readDnodeData reserved total bytes
// (up to maxDnodeDataBytes = 4 GiB) before reading the first block.
func TestBomb_DnodeMaxBlkidPrealloc(t *testing.T) {
	dn := newDnode(dmotPlainFileContents, 1, 0, 0)
	dn.maxblkid = 8191 // 8192 x 128 KiB = 1 GiB
	var err error
	got := allocDelta(func() { _, err = readDnodeData(&bombReaderAt{b: make([]byte, 4096)}, 0, dn) })
	t.Logf("allocated %d bytes, err=%v", got, err)
	if err == nil {
		t.Fatal("expected the second block (past nblkptr) to fail")
	}
	if got > bombAllocLimit {
		t.Fatalf("allocated %d bytes before reading the first block", got)
	}
}

// An nvlist-array pair reserved nelem (an int32 of the image) slots before
// looking at the data it has: 16M slots is 400 MB, and a negative nelem
// panicked in make.
func TestBomb_NVListArrayCount(t *testing.T) {
	for _, nelem := range []int32{1 << 24, -1, 1<<31 - 1} {
		p := &parsedNVPair{name: "children", typ: nvDataTypeNVListArray, nelem: nelem, data: make([]byte, 64)}
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("nelem %d: panic %v", nelem, r)
				}
			}()
			got := allocDelta(func() { _, err = p.nvlistArrayValue() })
			t.Logf("nelem %d: allocated %d bytes, err=%v", nelem, got, err)
			if got > bombAllocLimit {
				t.Errorf("nelem %d: allocated %d bytes for 64 bytes of data", nelem, got)
			}
		}()
		if err == nil {
			t.Errorf("nelem %d accepted", nelem)
		}
	}
}

// ashift comes from the vdev_tree nvlist of the image; 1<<ashift with ashift
// >= 64 is 0 and the alignment checks divide by it. OpenZFS accepts ASHIFT_MIN
// (9) to ASHIFT_MAX (16) (include/sys/spa.h).
func TestBomb_RaidzAshift(t *testing.T) {
	kids := []io.ReaderAt{&bombReaderAt{b: make([]byte, 1<<16)}, &bombReaderAt{b: make([]byte, 1<<16)}, &bombReaderAt{b: make([]byte, 1<<16)}}
	for _, ashift := range []uint{0, 8, 17, 31, 63, 64, 200} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("ashift %d: panic %v", ashift, r)
				}
			}()
			if _, err := raidzRead(kids, 0, 0, 4096, 1, ashift); err == nil {
				t.Errorf("ashift %d accepted", ashift)
			}
		}()
	}
	for _, ashift := range []uint{ashiftMin, ashiftMax} {
		if _, err := raidzRead(kids, 0, 0, int64(1)<<ashift*2, 1, ashift); err != nil && errors.Is(err, safeio.ErrOutOfBounds) {
			t.Errorf("ashift %d refused: %v", ashift, err)
		}
	}
}

type bombReaderAt struct{ b []byte }

func (m *bombReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(m.b)) {
		return 0, errors.New("EOF")
	}
	n := copy(p, m.b[off:])
	if n < len(p) {
		return n, errors.New("short")
	}
	return n, nil
}

var _ = safeio.ErrTooLarge

// zapBombLeaf builds a 128 KiB fat-ZAP leaf in which nEntries entry chunks all
// name and value the same long array chain. Every claim is within the leaf's
// capacity on its own (the per-entry clamp), but together they claim
// nEntries x capacity.
func zapBombLeaf(nEntries int) []byte {
	const size = 128 << 10
	blk := make([]byte, size)
	le := binary.LittleEndian
	le.PutUint64(blk[0:], zbtLeaf)
	le.PutUint32(blk[24:], zapLeafMagic)
	chunksStart := 48 + size/16
	chunkCount := (size - chunksStart) / zapLeafChunkSize
	chain := nEntries // first array chunk
	for i := chain; i < chunkCount; i++ {
		off := chunksStart + i*zapLeafChunkSize
		blk[off] = 251
		for j := 1; j <= 21; j++ {
			blk[off+j] = 'a'
		}
		next := i + 1
		if next >= chunkCount {
			next = 0xFFFF
		}
		le.PutUint16(blk[off+22:], uint16(next))
	}
	for i := 0; i < nEntries; i++ {
		off := chunksStart + i*zapLeafChunkSize
		blk[off] = 252
		blk[off+1] = 1 // value int length
		le.PutUint16(blk[off+4:], uint16(chain))
		le.PutUint16(blk[off+6:], 65535) // name length, clamped to the leaf's capacity
		le.PutUint16(blk[off+8:], uint16(chain))
		le.PutUint16(blk[off+10:], 65535) // value ints
	}
	return blk
}

// Each entry of a fat-ZAP leaf was allowed the leaf's whole array capacity for
// its name and its value, so a 128 KiB leaf of 1000 entries made 1000 x ~170 KB
// of name and value buffers (and kept the values in the result map).
func TestBomb_ZAPLeafEntryAmplification(t *testing.T) {
	blk := zapBombLeaf(1000)
	var raw map[string][]byte
	var u map[string]uint64
	gotRaw := allocDelta(func() { raw, _ = parseFatZAPLeafRaw(blk) })
	gotU := allocDelta(func() { u, _ = parseFatZAPLeaf(blk) })
	t.Logf("raw: %d bytes (%d entries); uint64: %d bytes (%d entries)", gotRaw, len(raw), gotU, len(u))
	if gotRaw > bombAllocLimit || gotU > bombAllocLimit {
		t.Fatalf("a %d-byte leaf cost %d / %d bytes", len(blk), gotRaw, gotU)
	}
}

// The per-leaf chunk budget is exact: one entry using every chunk of the leaf
// (1 entry chunk + k name chunks + the rest for its value) is read, one more
// value byte than the leaf holds is refused.
func TestBomb_ZAPLeafBudgetExact(t *testing.T) {
	const size = 128 << 10
	const k = 3
	patch := func(valBytes int) map[string][]byte {
		blk := zapBombLeaf(1)
		off := 48 + size/16
		binary.LittleEndian.PutUint16(blk[off+6:], k*zapLeafArrayBytes)
		binary.LittleEndian.PutUint16(blk[off+10:], uint16(valBytes))
		m, err := parseFatZAPLeafRaw(blk)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	// An entry that needs 1 + 3 + ceil(65535/21) chunks fits in the leaf's 5118.
	if m := patch(65535); len(m) != 1 {
		t.Fatalf("an entry within the leaf's chunks was dropped: %d entries", len(m))
	}
	// Two entries that together need more chunks than the leaf has: the second
	// is not read.
	blk := zapBombLeaf(2)
	off := 48 + size/16
	for e := 0; e < 2; e++ {
		o := off + e*zapLeafChunkSize
		binary.LittleEndian.PutUint16(blk[o+6:], 21)
		binary.LittleEndian.PutUint16(blk[o+10:], 65535)
	}
	got := allocDelta(func() { _, _ = parseFatZAPLeafRaw(blk) })
	// 1 + 1 + ceil(65535/21) = 3123 chunks per entry; the leaf has 5118, so one
	// entry is read (about 215 KB with the visited-set) and the second is not.
	if got > 300<<10 {
		t.Fatalf("second overdrawing entry was read: %d bytes", got)
	}
}

// nestedVdevLabel encodes a label nvlist whose vdev_tree nests `depth`
// single-child levels, as large as fits the 112 KiB label region.
func nestedVdevLabel(depth int) []byte {
	cur := nvList{nvString("type", "mirror")}
	for i := 0; i < depth; i++ {
		cur = nvList{nvString("type", "mirror"), nvNVListArray("children", []nvList{cur})}
	}
	return encodeNVListFull(nvList{nvNVList("vdev_tree", cur)})
}

// A label of nested vdev_tree levels: every level copied the whole remainder
// of the label (quadratic, and every copy live down the recursion), and the
// recursion depth was the label's size / the size of a level. libnvpair
// refuses nesting beyond nvpair_max_recursion = 100 (module/nvpair/nvpair.c).
func TestBomb_NestedVdevTree(t *testing.T) {
	enc := nestedVdevLabel(800)
	if len(enc) > 112*1024 {
		t.Fatalf("label does not fit its region: %d", len(enc))
	}
	buf := make([]byte, 112*1024)
	copy(buf, enc)
	var err error
	got := allocDelta(func() {
		var top parsedNVList
		top, err = decodeNVList(buf)
		if err != nil {
			return
		}
		var tree parsedNVList
		tree, err = top.findByName("vdev_tree").nvlistValue()
		if err != nil {
			return
		}
		_, err = parseVdevTree(tree)
	})
	t.Logf("%d-byte label, depth 800: allocated %d bytes, refused=%v", len(enc), got, err != nil)
	if err == nil {
		t.Error("nesting of 800 accepted")
	}
	if got > 4*uint64(len(buf)) {
		t.Errorf("allocated %d bytes for a %d-byte label", got, len(buf))
	}
}

// The nesting bound is exact: 99 nested levels (100 vdevs deep) parse, 100 do not.
func TestBomb_VdevNestingExact(t *testing.T) {
	parse := func(depth int) error {
		top, err := decodeNVList(nestedVdevLabel(depth))
		if err != nil {
			t.Fatal(err)
		}
		tree, err := top.findByName("vdev_tree").nvlistValue()
		if err != nil {
			t.Fatal(err)
		}
		_, err = parseVdevTree(tree)
		return err
	}
	if err := parse(maxNVNesting - 1); err != nil {
		t.Fatalf("at the bound: %v", err)
	}
	if err := parse(maxNVNesting); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("one over: %v", err)
	}
}

// bombCountingReader counts the bytes asked of the device.
type bombCountingReader struct {
	b    []byte
	read int64
}

func (c *bombCountingReader) ReadAt(p []byte, off int64) (int, error) {
	if len(p) > 1 { // not readBlock's one-byte "does the block exist" probe
		c.read += int64(len(p))
	}
	if off < 0 || off+int64(len(p)) > int64(len(c.b)) {
		return 0, errors.New("EOF")
	}
	return copy(p, c.b[off:]), nil
}

// plainBP is a block pointer to size bytes at byte offset off, uncompressed.
func plainBP(off, size int64) blkptr {
	s := uint64(size/512) - 1
	return blkptr{
		dva:  [3][2]uint64{{uint64(size / 512), uint64(off / 512)}},
		prop: s | s<<bpPsizeShift | uint64(zcompressOff)<<bpCompressShift,
	}
}

// indirectBomb: a 3-level dnode of 512-byte blocks whose 1024 pointers at each
// level all name the same block: 264 KiB of device for `blocks` data blocks.
func indirectBomb(blocks int) (*bombCountingReader, *dnode) {
	const ind = 128 << 10
	dev := make([]byte, 2*ind+512)
	l1, data := plainBP(ind, ind), plainBP(2*ind, 512)
	for i := 0; i < ind/blkptrSize; i++ {
		encodeBlkptr(l1, dev[i*blkptrSize:])
		encodeBlkptr(data, dev[ind+i*blkptrSize:])
	}
	dn := newDnode(dmotPlainFileContents, 1, 0, 0)
	dn.nlevels, dn.indblkshift, dn.datablkszsec = 3, 17, 1
	dn.maxblkid = uint64(blocks - 1)
	dn.setBlkptrAt(0, plainBP(0, ind))
	return &bombCountingReader{b: dev}, dn
}

// Every data block walked its indirect blocks again from the root: 8192 blocks
// of 512 bytes read 2 x 128 KiB each, 2 GiB of device reads for a 4 MiB file
// held by 264 KiB of image.
func TestBomb_IndirectBlockRereads(t *testing.T) {
	const blocks = 8192
	r, dn := indirectBomb(blocks)
	var data []byte
	var err error
	got := allocDelta(func() { data, err = readDnodeDataMax(r, 0, dn, 0) })
	t.Logf("read %d bytes of device, allocated %d bytes, len=%d err=%v", r.read, got, len(data), err)
	if err != nil || len(data) != blocks*512 {
		t.Fatalf("len=%d err=%v", len(data), err)
	}
	// The three distinct blocks once each, plus the data blocks themselves.
	if want := int64(2*(128<<10) + blocks*512); r.read > want {
		t.Fatalf("device read %d bytes, want at most %d", r.read, want)
	}
	// Proportional to the 4 MiB result (block buffers + append growth), not to
	// blocks x indirect-block size.
	if got > 8*uint64(len(data)) {
		t.Fatalf("allocated %d bytes", got)
	}
}

// Block pointers claiming more than the dnode's block size: n blocks of 16 MiB
// were appended to a result the dnode says is n x 512 bytes, so the ceiling on
// the object did not bound the result. The walk now stops at the ceiling: with
// a 20 MiB ceiling the second 16 MiB block is refused and the third never read.
func TestBomb_DataBlockLargerThanDnodeBlock(t *testing.T) {
	dev := make([]byte, 16<<20)
	dn := newDnode(dmotPlainFileContents, 3, 0, 0)
	dn.datablkszsec = 1
	dn.maxblkid = 2
	for i := 0; i < 3; i++ {
		dn.setBlkptrAt(i, plainBP(0, 16<<20))
	}
	r := &bombCountingReader{b: dev}
	var err error
	_, err = readDnodeDataMax(r, 0, dn, 20<<20)
	if !errors.Is(err, safeio.ErrTooLarge) || r.read != 2*(16<<20) {
		t.Fatalf("16 MiB blocks under a 20 MiB ceiling: err=%v, device read %d", err, r.read)
	}
	// Exact: a ceiling of exactly two blocks reads both and refuses the third.
	r.read = 0
	_, err = readDnodeDataMax(r, 0, dn, 32<<20)
	if !errors.Is(err, safeio.ErrTooLarge) || r.read != 3*(16<<20) {
		t.Fatalf("32 MiB ceiling: err=%v, device read %d", err, r.read)
	}
	r.read = 0
	if b, err := readDnodeDataMax(r, 0, dn, 48<<20); err != nil || len(b) != 48<<20 {
		t.Fatalf("48 MiB ceiling: len=%d err=%v", len(b), err)
	}
}

// readBlock sized its buffer from the pointer's PSIZE (up to 16 MiB) before
// asking the device whether those bytes exist. Callers that walk many pointers
// and skip the ones that fail (the fat-ZAP leaf walk reads every pointer of
// its table) paid 16 MiB of allocation per pointer to a block past the end of
// a 4 KiB device.
func TestBomb_BlockPastTheDevice(t *testing.T) {
	dev := &bombCountingReader{b: make([]byte, 4096)}
	bp := plainBP(1<<20, 16<<20)
	var err error
	got := allocDelta(func() {
		for i := 0; i < 50; i++ {
			_, err = readBlock(dev, 0, bp)
		}
	})
	if err == nil {
		t.Fatal("a block past the end of the device was read")
	}
	if got > bombAllocLimit {
		t.Fatalf("50 failed reads of a 16 MiB block allocated %d bytes", got)
	}
	// Inside the device a large block still reads whole.
	big := &bombCountingReader{b: make([]byte, 2<<20)}
	if b, err := readBlock(big, 0, plainBP(0, 2<<20)); err != nil || len(b) != 2<<20 {
		t.Fatalf("2 MiB block: len=%d err=%v", len(b), err)
	}
	// And the very last byte of the device is still reachable.
	if b, err := readBlock(big, 0, plainBP(2<<20-64<<10, 64<<10)); err != nil || len(b) != 64<<10 {
		t.Fatalf("block ending at the device end: len=%d err=%v", len(b), err)
	}
}
