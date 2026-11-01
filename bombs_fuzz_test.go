package filesystem_zfs

import "testing"

// fuzzAllocBudget is what one fuzz iteration may allocate: a fixed allowance
// plus a multiple of the input. The multiple is the largest expansion any codec
// is allowed (LZ4's 255:1) plus headroom; a bomb is an iteration whose
// allocation has no relation to the input's size.
func fuzzAllocBudget(inputLen int) uint64 { return 1<<20 + 300*uint64(inputLen) }

// FuzzDecompressBlock decodes arbitrary bytes with every codec and an
// arbitrary logical size.
func FuzzDecompressBlock(f *testing.F) {
	f.Add(uint8(0), uint32(4096), []byte{0, 0, 0, 3, 0x30, 'a', 'b', 'c'})
	f.Add(uint8(1), uint32(1<<24), []byte{1})
	f.Add(uint8(3), uint32(100), []byte{0x1F, 'a', 1, 0, 0xFF, 0xFF, 0})
	f.Fuzz(func(t *testing.T, codec uint8, lsize uint32, src []byte) {
		dst := int(lsize % (spaMaxBlockSize + 1))
		got := allocDelta(func() {
			switch codec % 5 {
			case 0:
				_, _ = lz4Decompress(src, dst)
			case 1:
				_, _ = lzjbDecompress(src, dst)
			case 2:
				_, _ = zleDecompress(src, dst)
			case 3:
				_, _ = gzipDecompress(src, dst)
			case 4:
				_, _ = zstdDecompress(src, dst)
			}
		})
		if got > fuzzAllocBudget(len(src)) {
			t.Fatalf("codec %d: allocated %d bytes for a %d-byte block declaring %d", codec%5, got, len(src), dst)
		}
	})
}

// FuzzReadEmbedded decodes an arbitrary 128-byte block pointer as an embedded
// one: at most 112 bytes of payload and an lsize of its choosing.
func FuzzReadEmbedded(f *testing.F) {
	f.Add(make([]byte, blkptrSize))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) < blkptrSize {
			return
		}
		bp := parseBlkptr(raw[:blkptrSize])
		bp.prop |= bpEmbeddedBit
		got := allocDelta(func() { _, _ = readEmbedded(bp) })
		if got > fuzzAllocBudget(bpePayloadSize) {
			t.Fatalf("allocated %d bytes for prop %#x", got, bp.prop)
		}
	})
}

// FuzzNVList decodes arbitrary bytes as an nvlist and walks every nested list
// and array it names.
func FuzzNVList(f *testing.F) {
	f.Add([]byte{1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		got := allocDelta(func() {
			l, err := decodeNVList(b)
			if err != nil {
				return
			}
			for i := range l {
				_, _ = l[i].nvlistValue()
				_, _ = l[i].nvlistArrayValue()
			}
		})
		if got > fuzzAllocBudget(len(b))*4 {
			t.Fatalf("allocated %d bytes for a %d-byte nvlist", got, len(b))
		}
	})
}

// FuzzZAPLeaf parses an arbitrary leaf block, both decoders. The entries of a
// leaf are charged against its chunk count, so what the decoders allocate is
// proportional to the block, not to entries x block.
func FuzzZAPLeaf(f *testing.F) {
	f.Add(zapBombLeaf(10))
	f.Add(zapBombLeaf(1000))
	f.Fuzz(func(t *testing.T, blk []byte) {
		got := allocDelta(func() {
			_, _ = parseFatZAPLeaf(blk)
			_, _ = parseFatZAPLeafRaw(blk)
		})
		if got > 1<<20+64*uint64(len(blk)) {
			t.Fatalf("allocated %d bytes for a %d-byte leaf", got, len(blk))
		}
	})
}

// FuzzDnodeWalk reads a whole object whose dnode header fields and root block
// pointer come from the input, over a device that is the rest of the input.
// A 1 MiB ceiling bounds the result; the walk must not allocate or read in
// proportion to anything else.
func FuzzDnodeWalk(f *testing.F) {
	_, dn := indirectBomb(64)
	seed := append([]byte(nil), dn.raw[dnodeHdrSize:dnodeHdrSize+blkptrSize]...)
	f.Add(uint8(3), uint8(17), uint16(1), uint16(63), uint8(1), seed)
	f.Fuzz(func(t *testing.T, nlevels, indblkshift uint8, blksz, maxblkid uint16, nblkptr uint8, dev []byte) {
		if len(dev) < blkptrSize {
			return
		}
		dn := newDnode(dmotPlainFileContents, 1+nblkptr%3, 0, 0)
		dn.nlevels, dn.indblkshift, dn.datablkszsec, dn.maxblkid = nlevels, indblkshift, blksz, uint64(maxblkid)
		for i := 0; i < int(dn.nblkptr) && (i+1)*blkptrSize <= len(dev); i++ {
			dn.setBlkptrAt(i, parseBlkptr(dev[i*blkptrSize:(i+1)*blkptrSize]))
		}
		r := &bombCountingReader{b: dev}
		got := allocDelta(func() { _, _ = readDnodeDataMax(r, 0, dn, 1<<20) })
		if got > 64<<20+300*uint64(len(dev)) {
			t.Fatalf("allocated %d bytes (device read %d) for a %d-byte device", got, r.read, len(dev))
		}
	})
}

// FuzzVdevLabel decodes an arbitrary label nvlist down to the vdev tree.
func FuzzVdevLabel(f *testing.F) {
	f.Add(nestedVdevLabel(3))
	f.Add(nestedVdevLabel(200))
	f.Fuzz(func(t *testing.T, b []byte) {
		got := allocDelta(func() {
			top, err := decodeNVList(b)
			if err != nil {
				return
			}
			vp := top.findByName("vdev_tree")
			if vp == nil {
				return
			}
			if tree, err := vp.nvlistValue(); err == nil {
				_, _ = parseVdevTree(tree)
			}
		})
		if got > 4<<20+64*uint64(len(b)) {
			t.Fatalf("allocated %d bytes for a %d-byte label", got, len(b))
		}
	})
}
