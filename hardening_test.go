package filesystem_zfs

// hardening_test.go — security-hardening regression + fuzz tests.
//
// THREAT MODEL: an untrusted ZFS pool image must NEVER panic the host,
// read out of bounds, integer-overflow into a bad alloc/slice, loop
// forever, or OOM. Every test below feeds a hostile on-disk structure to
// one of the hardened parsers and asserts a graceful error (or empty
// result) instead of a crash.
//
// The exact attack vectors from the hardening review are encoded as both
// f.Add fuzz seeds (so they run under plain `go test`) and as explicit
// regression assertions.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/go-volumes/safeio"
)

// sizedReaderAt is an io.ReaderAt over a byte slice that also exposes Size(),
// so deviceSizeOf can bound gpt parsing. It never panics on OOB reads.
type sizedReaderAt struct{ b []byte }

func (m *sizedReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(m.b)) {
		return 0, errReadEOF
	}
	n := copy(p, m.b[off:])
	if n < len(p) {
		return n, errReadEOF
	}
	return n, nil
}
func (m *sizedReaderAt) Size() (int64, error) { return int64(len(m.b)), nil }

var errReadEOF = errors.New("eof")

// makeDnodeRaw builds a 512-byte dnode header with the supplied fields and
// a single non-null block pointer at index 0 (so isNull() is false). The
// blkptr is left mostly zero except a sentinel to defeat isNull.
func makeDnodeRaw(typ, indblkshift, nlevels, nblkptr uint8, datablkszsec uint16, maxblkid uint64) []byte {
	b := make([]byte, dnodeMinSize)
	b[0] = typ
	b[1] = indblkshift
	b[2] = nlevels
	b[3] = nblkptr
	binary.LittleEndian.PutUint16(b[8:], datablkszsec)
	binary.LittleEndian.PutUint64(b[16:], maxblkid)
	// Make blkptr[0] non-null by setting a byte in its DVA word.
	b[dnodeHdrSize+0] = 0x01
	return b
}

// ── C1: readDnodeData with a hostile dn_maxblkid ─────────────────────────────

func TestHarden_C1_ReadDnodeData_HugeMaxblkid(t *testing.T) {
	// maxblkid = 2^60 with a tiny block size would, naively, allocate
	// ~2^60 * blkSz bytes (OOM / cap-out-of-range panic). Must error.
	raw := makeDnodeRaw(dmotPlainFileContents, 17, 1, 1, 1 /*512B blocks*/, 1<<60)
	dn, err := parseDnode(raw)
	if err != nil {
		t.Fatalf("parseDnode: %v", err)
	}
	r := &sizedReaderAt{b: make([]byte, 1<<16)}
	_, err = readDnodeData(r, 0, dn)
	if err == nil {
		t.Fatal("readDnodeData with maxblkid=2^60: error = nil, want ceiling error")
	}
}

func TestHarden_C1_ReadDnodeData_MaxblkidOverflow(t *testing.T) {
	// maxblkid = MaxUint64 → n = maxblkid+1 wraps to 0; must error cleanly.
	raw := makeDnodeRaw(dmotPlainFileContents, 17, 1, 1, 1, ^uint64(0))
	dn, err := parseDnode(raw)
	if err != nil {
		t.Fatalf("parseDnode: %v", err)
	}
	r := &sizedReaderAt{b: make([]byte, 1<<16)}
	if _, err := readDnodeData(r, 0, dn); err == nil {
		t.Fatal("readDnodeData with maxblkid=MaxUint64: error = nil, want overflow error")
	}
}

// ── H2: findDataBP with hostile indblkshift / nlevels ────────────────────────

func TestHarden_H2_FindDataBP_BadIndblkshift(t *testing.T) {
	// indblkshift = 0 (< minIndblkshift) with nlevels > 1 would make
	// bpsPerBlock = 0 and divide by zero. Must error.
	raw := makeDnodeRaw(dmotPlainFileContents, 0 /*indblkshift*/, 2 /*nlevels*/, 1, 256, 0)
	dn, err := parseDnode(raw)
	if err != nil {
		t.Fatalf("parseDnode: %v", err)
	}
	r := &sizedReaderAt{b: make([]byte, 1<<16)}
	if _, err := findDataBP(r, 0, dn, 0); err == nil {
		t.Fatal("findDataBP with indblkshift=0: error = nil, want range error")
	}
}

func TestHarden_H2_FindDataBP_HugeNlevels(t *testing.T) {
	// nlevels = 255 → fan-out amplification. Must error (> maxNlevels).
	raw := makeDnodeRaw(dmotPlainFileContents, 17, 255 /*nlevels*/, 1, 256, 0)
	dn, err := parseDnode(raw)
	if err != nil {
		t.Fatalf("parseDnode: %v", err)
	}
	r := &sizedReaderAt{b: make([]byte, 1<<16)}
	if _, err := findDataBP(r, 0, dn, 0); err == nil {
		t.Fatal("findDataBP with nlevels=255: error = nil, want nlevels error")
	}
}

func TestHarden_H2_FindDataBP_IndirectIdxOOB(t *testing.T) {
	// A 2-level dnode whose root blkptr points at a SHORT indirect block
	// (smaller than the geometry implies): the derived idx slices past the
	// block. CheckBounds must catch it (H2b) rather than panicking.
	blockSize := 4096
	// Indirect block of only 16 bytes — far too short to hold a blkptr at
	// the computed idx. Place it at data-area offset 0.
	indir := make([]byte, 16)
	img := make([]byte, blockSize+(1<<16))
	copy(img, indir)
	dnRaw := makeDnodeRaw(dmotPlainFileContents, 12 /*indblkshift: 4096B*/, 2 /*nlevels*/, 1, 2 /*1KB blocks*/, 1<<20)
	dn, err := parseDnode(dnRaw)
	if err != nil {
		t.Fatalf("parseDnode: %v", err)
	}
	// Root blkptr[0] points (uncompressed) at the 16-byte "indirect" block.
	dn.setBlkptrAt(0, makeBlkptr(0, 16, 16, zcompressOff, 0, 1, 0))
	r := &sizedReaderAt{b: img}
	// blockID large enough that idx>0 inside the (too-short) indirect block.
	if _, err := findDataBP(r, 0, dn, 1<<19); err == nil {
		t.Fatal("findDataBP with short indirect block: error = nil, want bounds error")
	}
}

// ── H1: raidz geometry with nparity >= dcols ─────────────────────────────────

func TestHarden_H1_ParseVdevTree_BadRaidz(t *testing.T) {
	// A vdev_tree nvlist describing a raidz with nparity >= dcols must be
	// rejected at parse time (H1). Build the nvlist with the real encoder
	// and decode it back so parseVdevTree sees a faithful structure.
	leaf := nvList{nvString("type", string(vdevTypeDisk))}
	root := nvList{
		nvString("type", string(vdevTypeRAIDZ)),
		nvUint64("nparity", 3), // nparity 3 with only 2 children → invalid
		nvNVListArray("children", []nvList{leaf, leaf}),
	}
	decoded, err := decodeNVList(encodeNVListFull(root))
	if err != nil {
		t.Fatalf("decodeNVList: %v", err)
	}
	if _, err := parseVdevTree(decoded); err == nil {
		t.Fatal("parseVdevTree with nparity>=dcols: error = nil, want geometry error")
	}

	// A valid raidz1 (nparity 1, 3 children) must parse cleanly.
	good := nvList{
		nvString("type", string(vdevTypeRAIDZ)),
		nvUint64("nparity", 1),
		nvNVListArray("children", []nvList{leaf, leaf, leaf}),
	}
	gd, err := decodeNVList(encodeNVListFull(good))
	if err != nil {
		t.Fatalf("decodeNVList: %v", err)
	}
	if _, err := parseVdevTree(gd); err != nil {
		t.Fatalf("parseVdevTree valid raidz1: %v", err)
	}
}

func TestHarden_DeviceSizeOf(t *testing.T) {
	// int64-returning Size() path.
	if got := deviceSizeOf(int64SizedReader{n: 42}); got != 42 {
		t.Fatalf("deviceSizeOf(int64 Size) = %d, want 42", got)
	}
	// (int64,error)-returning Size() path (sizedReaderAt).
	if got := deviceSizeOf(&sizedReaderAt{b: make([]byte, 17)}); got != 17 {
		t.Fatalf("deviceSizeOf(Size err) = %d, want 17", got)
	}
	// Unknown reader → 0.
	if got := deviceSizeOf(readerAtFunc(func([]byte, int64) (int, error) { return 0, errReadEOF })); got != 0 {
		t.Fatalf("deviceSizeOf(unknown) = %d, want 0", got)
	}
}

type int64SizedReader struct{ n int64 }

func (r int64SizedReader) ReadAt(p []byte, off int64) (int, error) { return 0, errReadEOF }
func (r int64SizedReader) Size() int64                             { return r.n }

func TestHarden_H1_RaidzGeometry(t *testing.T) {
	cases := []struct {
		dcols, nparity int
		ok             bool
	}{
		{0, 0, false},
		{1, 1, false}, // dcols < 2
		{2, 2, false}, // nparity == dcols → dataCols 0
		{3, 3, false}, // nparity == dcols
		{3, 4, false}, // nparity > dcols → negative dataCols
		{2, 0, false}, // nparity 0
		{2, 1, true},  // raidz1
		{4, 2, true},  // raidz2
		{5, 3, true},  // raidz3
	}
	for _, c := range cases {
		if got := validRaidzGeom(c.dcols, c.nparity); got != c.ok {
			t.Errorf("validRaidzGeom(%d,%d) = %v, want %v", c.dcols, c.nparity, got, c.ok)
		}
		// raidzMapAlloc must return nil (not panic) for an invalid geometry.
		rm := raidzMapAlloc(0, 8, c.dcols, c.nparity, 9)
		if c.ok && rm == nil {
			t.Errorf("raidzMapAlloc(%d,%d) = nil for valid geometry", c.dcols, c.nparity)
		}
		if !c.ok && rm != nil {
			t.Errorf("raidzMapAlloc(%d,%d) != nil for invalid geometry", c.dcols, c.nparity)
		}
	}
}

func TestHarden_H1_RaidzRead_BadGeometry(t *testing.T) {
	// nparity >= len(children) must error, not divide-by-zero / makeslice panic.
	ok := func(p []byte, off int64) (int, error) { return len(p), nil }
	children := []io.ReaderAt{readerAtFunc(ok), readerAtFunc(ok)}
	if _, err := raidzRead(children, 0, 0, 512, 2 /*nparity == dcols*/, 9); err == nil {
		t.Fatal("raidzRead with nparity==dcols: error = nil, want geometry error")
	}
}

// ── H4 + H3: hostile fat-ZAP header and leaf ─────────────────────────────────

func TestHarden_H4_ParseFatZAP_HugeShiftAndLeafs(t *testing.T) {
	// Build a dnode whose only data block is a fat-ZAP header with a hostile
	// zt_shift (63) and zap_num_leafs (2^63). The pointer-table walk must
	// terminate (bounded by storage), not loop ~2^63 times.
	blockSize := 4096
	hdr := make([]byte, blockSize)
	le := binary.LittleEndian
	le.PutUint64(hdr[0:], zbtHeader)
	le.PutUint64(hdr[8:], zapMagic)
	le.PutUint64(hdr[zapHdrPtrtblShift:], 63)    // zt_shift = 63
	le.PutUint64(hdr[zapHdrNumLeafsOff:], 1<<63) // numLeafs huge
	le.PutUint64(hdr[zapHdrPtrtblOff:], 0)       // embedded ptrtbl

	dn, r := blkptrToBlock(t, hdr, blockSize)
	// Must return (possibly empty) without hanging or panicking.
	entries, err := parseFatZAP(r, 0, dn, hdr)
	if err != nil {
		t.Fatalf("parseFatZAP: unexpected error %v", err)
	}
	_ = entries
}

func TestHarden_H3_FatZAPLeaf_CyclicChunkChain(t *testing.T) {
	// A leaf with an entry whose name array chunk chain forms a cycle
	// (chunk points back to itself). The reader must break the cycle.
	blockSize := 4096
	blk := make([]byte, blockSize)
	le := binary.LittleEndian
	le.PutUint64(blk[0:], zbtLeaf)
	le.PutUint32(blk[24:], zapLeafMagic)

	hashTabSz := blockSize / 16
	chunksStart := 48 + hashTabSz
	// Entry chunk at chunk index 0.
	entOff := chunksStart + 0*zapLeafChunkSize
	blk[entOff] = 252                     // ZAP_CHUNK_ENTRY
	blk[entOff+1] = 8                     // value intlen
	le.PutUint16(blk[entOff+4:], 1)       // name chunk = 1
	le.PutUint16(blk[entOff+6:], 0xFFFF)  // huge name length
	le.PutUint16(blk[entOff+8:], 2)       // value chunk = 2
	le.PutUint16(blk[entOff+10:], 0xFFFF) // huge value numints
	// Array chunk 1: cycles to itself.
	arrOff := chunksStart + 1*zapLeafChunkSize
	blk[arrOff] = 251 // ZAP_CHUNK_ARRAY
	blk[arrOff+1] = 'A'
	le.PutUint16(blk[arrOff+22:], 1) // next = self → cycle
	// Array chunk 2 (value): cycles to itself too.
	valOff := chunksStart + 2*zapLeafChunkSize
	blk[valOff] = 251
	le.PutUint16(blk[valOff+22:], 2) // next = self

	// Must not hang / OOM despite the 0xFFFF lengths and self-cycles.
	res, err := parseFatZAPLeaf(blk)
	if err != nil {
		t.Fatalf("parseFatZAPLeaf: %v", err)
	}
	_ = res
}

func TestHarden_H3_ReadZAPLeafString_Cycle(t *testing.T) {
	// Direct unit test of the chunk-chain cycle guard.
	blockSize := 4096
	blk := make([]byte, blockSize)
	le := binary.LittleEndian
	chunksStart := 48
	nchunks := (blockSize - chunksStart) / zapLeafChunkSize
	off := chunksStart + 0*zapLeafChunkSize
	blk[off] = 251
	for i := 0; i < 21; i++ {
		blk[off+1+i] = 'x'
	}
	le.PutUint16(blk[off+22:], 0) // next = 0 → cycle back to start
	// Request a very long name; the cycle guard must stop it.
	s := readZAPLeafString(blk, chunksStart, nchunks, 0, 1<<20)
	if len(s) > 21*nchunks {
		t.Fatalf("readZAPLeafString returned %d bytes, cycle guard failed", len(s))
	}
}

func TestHarden_H3_ReadZAPLeafValue_NegativeAndCycle(t *testing.T) {
	// numInts*intLen would overflow / be negative — must return 0, not panic.
	if v := readZAPLeafValue(nil, 0, 0, 0, 0, 0); v != 0 {
		t.Fatalf("readZAPLeafValue(zero) = %d, want 0", v)
	}
	blockSize := 4096
	blk := make([]byte, blockSize)
	le := binary.LittleEndian
	chunksStart := 48
	nchunks := (blockSize - chunksStart) / zapLeafChunkSize
	off := chunksStart
	blk[off] = 251
	le.PutUint16(blk[off+22:], 0) // cycle
	v := readZAPLeafValue(blk, chunksStart, nchunks, 0, 4, 8)
	_ = v // just must not hang / panic
}

// ── M3: objNum overflow ──────────────────────────────────────────────────────

func TestHarden_M3_ReadObject_Overflow(t *testing.T) {
	// objNum so large that objNum*dnodeMinSize overflows uint64.
	metaRaw := makeDnodeRaw(dmotDnode, 17, 1, 1, 256, 0)
	meta, err := parseDnode(metaRaw)
	if err != nil {
		t.Fatalf("parseDnode: %v", err)
	}
	os := &objset{r: &sizedReaderAt{b: make([]byte, 1<<16)}, metaDnode: meta}
	if _, err := os.readObject(^uint64(0) - 1); err == nil {
		t.Fatal("readObject(huge): error = nil, want overflow error")
	}
}

// ── safeio sentinel smoke (ensures the right error family is used) ────────────

func TestHarden_SafeioSentinels(t *testing.T) {
	if _, err := safeio.MakeBytes(10, 5); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("MakeBytes ceiling: want ErrTooLarge, got %v", err)
	}
	if err := safeio.CheckBounds(8, 4, 8); !errors.Is(err, safeio.ErrOutOfBounds) {
		t.Fatalf("CheckBounds OOB: want ErrOutOfBounds, got %v", err)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

type readerAtFunc func(p []byte, off int64) (int, error)

func (f readerAtFunc) ReadAt(p []byte, off int64) (int, error) { return f(p, off) }

// blkptrToBlock builds a dnode whose data block 0 contains `blk` and returns
// the dnode plus a reader so that readDataBlock(...,0) returns blk. The
// block pointer is uncompressed with DVA offset 0, and partOff is 0, so the
// data area starts at image offset 0.
func blkptrToBlock(t *testing.T, blk []byte, blockSize int) (*dnode, *sizedReaderAt) {
	t.Helper()
	img := make([]byte, blockSize+(1<<16))
	copy(img, blk)
	dnRaw := makeDnodeRaw(dmotDirContents, 17, 1, 1, uint16(blockSize/512), 0)
	dn, err := parseDnode(dnRaw)
	if err != nil {
		t.Fatalf("parseDnode: %v", err)
	}
	bp := makeBlkptr(0, blockSize, blockSize, zcompressOff, 0, 0, 0)
	dn.setBlkptrAt(0, bp)
	return dn, &sizedReaderAt{b: img}
}

// ── Fuzz targets ──────────────────────────────────────────────────────────────

// FuzzParseFatZAPLeaf feeds arbitrary bytes to the fat-ZAP leaf parser; it
// must never panic, OOB-read, or hang (H3).
func FuzzParseFatZAPLeaf(f *testing.F) {
	// Seed: cyclic chunk chain with huge declared lengths (H3 vector).
	blockSize := 4096
	seed := make([]byte, blockSize)
	le := binary.LittleEndian
	le.PutUint64(seed[0:], zbtLeaf)
	le.PutUint32(seed[24:], zapLeafMagic)
	hashTabSz := blockSize / 16
	chunksStart := 48 + hashTabSz
	entOff := chunksStart
	seed[entOff] = 252
	seed[entOff+1] = 8
	le.PutUint16(seed[entOff+4:], 1)
	le.PutUint16(seed[entOff+6:], 0xFFFF)
	le.PutUint16(seed[entOff+8:], 1)
	le.PutUint16(seed[entOff+10:], 0xFFFF)
	arrOff := chunksStart + zapLeafChunkSize
	seed[arrOff] = 251
	le.PutUint16(seed[arrOff+22:], 1) // self-cycle
	f.Add(seed)
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 48))
	f.Add(make([]byte, 4096))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseFatZAPLeaf(data) // must not panic / hang
	})
}

// FuzzParseFatZAP feeds arbitrary header blocks (with a benign backing
// reader) to the fat-ZAP walker (H4). It must terminate without OOM/hang.
func FuzzParseFatZAP(f *testing.F) {
	blockSize := 4096
	hdr := make([]byte, blockSize)
	le := binary.LittleEndian
	le.PutUint64(hdr[0:], zbtHeader)
	le.PutUint64(hdr[8:], zapMagic)
	le.PutUint64(hdr[zapHdrPtrtblShift:], 63)    // zt_shift = 63 (H4)
	le.PutUint64(hdr[zapHdrNumLeafsOff:], 1<<63) // numLeafs huge (H4)
	f.Add(hdr)
	f.Add(make([]byte, 128))
	f.Add(make([]byte, 4096))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 128 {
			return
		}
		blkSize := (len(data) / 512) * 512
		if blkSize == 0 {
			return
		}
		dnRaw := makeDnodeRaw(dmotDirContents, 17, 1, 1, uint16(blkSize/512), 0)
		dn, err := parseDnode(dnRaw)
		if err != nil {
			return
		}
		bp := makeBlkptr(0, blkSize, blkSize, zcompressOff, 0, 0, 0)
		dn.setBlkptrAt(0, bp)
		img := make([]byte, len(data)+(1<<16))
		copy(img, data)
		r := &sizedReaderAt{b: img}
		_, _ = parseFatZAP(r, 0, dn, data) // must not panic / hang
	})
}

// FuzzReadDnodeData drives readDnodeData with arbitrary dnode headers,
// including the maxblkid=2^60 vector (C1). It must never OOM/panic.
func FuzzReadDnodeData(f *testing.F) {
	f.Add(makeDnodeRaw(dmotPlainFileContents, 17, 1, 1, 1, 1<<60)) // C1
	f.Add(makeDnodeRaw(dmotPlainFileContents, 0, 2, 1, 256, 0))    // H2 indblkshift=0
	f.Add(makeDnodeRaw(dmotPlainFileContents, 17, 255, 1, 256, 0)) // H2 nlevels=255
	f.Add(makeDnodeRaw(dmotPlainFileContents, 17, 1, 1, 1, ^uint64(0)))

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) < dnodeMinSize {
			return
		}
		dn, err := parseDnode(raw)
		if err != nil {
			return
		}
		r := &sizedReaderAt{b: make([]byte, 1<<16)}
		_, _ = readDnodeData(r, 0, dn) // must not panic / OOM
		_, _ = findDataBP(r, 0, dn, 0) // must not panic / divide-by-zero
	})
}

// FuzzPartitionOffset drives the gpt-backed partition locator with arbitrary
// images (M1). It must never panic.
func FuzzPartitionOffset(f *testing.F) {
	img := make([]byte, 64*sectorSize)
	copy(img[sectorSize:], []byte("EFI PART"))
	f.Add(img, -1)
	f.Add(img, 0)
	f.Add([]byte("EFI PART"), -1)
	f.Add(make([]byte, 512), 1)

	f.Fuzz(func(t *testing.T, data []byte, idx int) {
		if len(data) == 0 {
			return
		}
		_, _ = partitionOffset(bytes.NewReader(data), idx) // must not panic
	})
}
