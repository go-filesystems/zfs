package filesystem_zfs

// blockptr.go – ZFS block pointer (blkptr_t) parsing and physical I/O.
//
// A block pointer is 128 bytes:
//   [0..47]   dva[0..2]     3 × DVA (16 bytes each)
//   [48..55]  blk_prop      properties field
//   [56..71]  blk_pad[0..1] padding
//   [72..79]  blk_phys_birth
//   [80..87]  blk_birth
//   [88..95]  blk_fill
//   [96..127] blk_cksum[0..3]
//
// blk_prop field (LE uint64 for LE pools):
//   bits 15:0   lsize−1 in 512B sectors
//   bits 31:16  psize−1 in 512B sectors
//   bits 38:32  compress type (7 bits)
//   bit  39     embedded
//   bits 47:40  checksum type (8 bits)
//   bits 55:48  DMU object type (8 bits)
//   bits 60:56  indirect level (5 bits)
//   bit  62     dedup
//   bit  63     byte order (1 = LE)
//
// DVA word layout (LE pool):
//   word[0]: bits 63:32 = vdev id, bits 31:24 = grid, bits 23:0 = asize in 512B sectors
//   word[1]: bit 63 = gang, bits 62:0 = offset in 512B sectors

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	blkptrSize = 128 // sizeof(blkptr_t)

	// blk_prop bits
	bpLsizeBits     = 0xFFFF // bits 15:0 (lsize - 1 in 512B sectors)
	bpPsizeShift    = 16     // bits 31:16
	bpPsizeBits     = 0xFFFF
	bpCompressShift = 32 // bits 38:32
	bpCompressBits  = 0x7F
	bpEmbeddedBit   = uint64(1) << 39
	bpTypeShift     = 48 // bits 55:48
	bpTypeBits      = 0xFF
	bpLevelShift    = 56 // bits 60:56
	bpLevelBits     = 0x1F
	bpDedupBit      = uint64(1) << 62
	bpLEBit         = uint64(1) << 63

	// Compression types (zio_compress_t)
	zcompressInherit = 0
	zcompressOn      = 1
	zcompressOff     = 2
	zcompressLZJB    = 3
	zcompressEmpty   = 4
	zcompressGZIP1   = 5
	zcompressGZIP9   = 13
	zcompressZLE     = 14
	zcompressLZ4     = 15
	zcompressZSTD    = 16
)

// blkptr is a parsed ZFS block pointer.
type blkptr struct {
	dva       [3][2]uint64 // [i][0]=word0, [i][1]=word1
	prop      uint64
	pad       [2]uint64 // bytes 56..71 — payload region for embedded BPs
	physBirth uint64
	birth     uint64
	fill      uint64
	cksum     [4]uint64
}

// isNull returns true if all DVAs are empty (unallocated block).
func (bp blkptr) isNull() bool {
	return bp.dva[0][0] == 0 && bp.dva[0][1] == 0 &&
		bp.dva[1][0] == 0 && bp.dva[1][1] == 0 &&
		bp.dva[2][0] == 0 && bp.dva[2][1] == 0
}

// isEmbedded returns true when data is stored inside the BP itself.
func (bp blkptr) isEmbedded() bool { return bp.prop&bpEmbeddedBit != 0 }

// lsize returns the logical (decompressed) size in bytes.
func (bp blkptr) lsize() int64 {
	return int64(((bp.prop & bpLsizeBits) + 1) * 512)
}

// psize returns the physical (compressed) size in bytes.
func (bp blkptr) psize() int64 {
	return int64((((bp.prop >> bpPsizeShift) & bpPsizeBits) + 1) * 512)
}

// compress returns the compression algorithm byte.
func (bp blkptr) compress() uint8 { return uint8((bp.prop >> bpCompressShift) & bpCompressBits) }

// dmuType returns the DMU object type.
func (bp blkptr) dmuType() uint8 { return uint8((bp.prop >> bpTypeShift) & bpTypeBits) }

// level returns the indirect level (0 = data).
func (bp blkptr) level() uint8 { return uint8((bp.prop >> bpLevelShift) & bpLevelBits) }

// dvaOffset returns the byte offset of DVA i RELATIVE TO THE START OF
// THE DATA AREA. ZFS stores DVAs as 512-byte-sector counts measured
// from VDEV_LABEL_START_SIZE (= 4 MiB) past the partition start; the
// caller must add `vdevLabelStartSize` once when computing a file-
// absolute offset (see openObjset / readBlock — they go through
// blockBackend.ReadAt which expects file-absolute offsets).
func (bp blkptr) dvaOffset(i int) int64 {
	// word[1] bits 62:0 = offset in 512B sectors (relative to data area).
	off512 := bp.dva[i][1] & 0x7FFFFFFFFFFFFFFF
	return int64(off512 << 9)
}

// dvaAsize returns the allocated byte size for DVA i.
func (bp blkptr) dvaAsize(i int) int64 {
	// word[0] bits 23:0 = asize in 512B sectors
	asize512 := bp.dva[i][0] & 0xFFFFFF
	return int64(asize512 << 9)
}

// dvaGang returns true if DVA i is a gang block.
func (bp blkptr) dvaGang(i int) bool { return (bp.dva[i][1]>>63)&1 != 0 }

// dvaNvalid returns the number of populated DVAs (non-zero asize).
func (bp blkptr) dvasValid() int {
	n := 0
	for i := 0; i < 3; i++ {
		if bp.dva[i][0]&0xFFFFFF != 0 {
			n++
		}
	}
	return n
}

// parseBlkptr parses a 128-byte slice into a blkptr.
func parseBlkptr(b []byte) blkptr {
	le := binary.LittleEndian
	var bp blkptr
	for i := 0; i < 3; i++ {
		bp.dva[i][0] = le.Uint64(b[i*16:])
		bp.dva[i][1] = le.Uint64(b[i*16+8:])
	}
	bp.prop = le.Uint64(b[48:])
	bp.pad[0] = le.Uint64(b[56:])
	bp.pad[1] = le.Uint64(b[64:])
	bp.physBirth = le.Uint64(b[72:])
	bp.birth = le.Uint64(b[80:])
	bp.fill = le.Uint64(b[88:])
	for i := 0; i < 4; i++ {
		bp.cksum[i] = le.Uint64(b[96+i*8:])
	}
	return bp
}

// encodeBlkptr writes a blkptr into a 128-byte slice b.
func encodeBlkptr(bp blkptr, b []byte) {
	le := binary.LittleEndian
	for i := 0; i < 3; i++ {
		le.PutUint64(b[i*16:], bp.dva[i][0])
		le.PutUint64(b[i*16+8:], bp.dva[i][1])
	}
	le.PutUint64(b[48:], bp.prop)
	le.PutUint64(b[56:], 0) // pad0
	le.PutUint64(b[64:], 0) // pad1
	le.PutUint64(b[72:], bp.physBirth)
	le.PutUint64(b[80:], bp.birth)
	le.PutUint64(b[88:], bp.fill)
	for i := 0; i < 4; i++ {
		le.PutUint64(b[96+i*8:], bp.cksum[i])
	}
}

// makeProp builds a blk_prop value for a data block.
// lsize and psize are in bytes (must be multiples of 512).
// Checksum is always set to ZIO_CHECKSUM_OFF (2) so that readers skip verification.
func makeProp(compress uint8, lsize, psize int, dtype uint8, level uint8) uint64 {
	ls := uint64(lsize/512 - 1)
	ps := uint64(psize/512 - 1)
	const checksumOff = uint64(2) << 40 // ZIO_CHECKSUM_OFF at bits 47:40
	return ls |
		(ps << 16) |
		(uint64(compress) << bpCompressShift) |
		checksumOff |
		(uint64(dtype) << bpTypeShift) |
		(uint64(level&bpLevelBits) << bpLevelShift) |
		bpLEBit
}

// makeDVA builds the two DVA words for a block at byteOff with physSize bytes on vdev 0.
func makeDVA(byteOff int64, physSize int) [2]uint64 {
	offset512 := uint64(byteOff >> 9)
	asize512 := uint64(physSize >> 9)
	w0 := asize512 & 0xFFFFFF // vdev=0, grid=0, asize
	w1 := offset512 & 0x7FFFFFFFFFFFFFFF
	return [2]uint64{w0, w1}
}

// makeBlkptr constructs a block pointer for a single-copy, uncompressed block.
func makeBlkptr(byteOff int64, physSize, logicalSize int, compress uint8, dtype uint8, level uint8, txg uint64) blkptr {
	var bp blkptr
	bp.dva[0] = makeDVA(byteOff, physSize)
	bp.prop = makeProp(compress, logicalSize, physSize, dtype, level)
	bp.birth = txg
	bp.physBirth = txg
	bp.fill = 1
	return bp
}

// readBlock reads the logical content of a block pointer from r.
// r is the underlying device file, partOff is the partition byte offset.
// Returns the decompressed lsize bytes.
//
// When the block is encrypted (bp.isEncrypted()) readBlock looks
// for a *cryptingReader wrapping `r` to source the decryption
// context. Callers obtain that wrapper by opening the FS via
// OpenFromDeviceDatasetWithKey, which stores a cryptingReader as
// the FS's backing reader.
func readBlock(r io.ReaderAt, partOff int64, bp blkptr) ([]byte, error) {
	if bp.isNull() {
		// Return a zero block of lsize bytes.
		return make([]byte, bp.lsize()), nil
	}
	if bp.isEmbedded() {
		return readEmbedded(bp)
	}
	if bp.dvaGang(0) {
		return nil, fmt.Errorf("zfs: gang blocks not supported")
	}

	offset := partOff + bp.dvaOffset(0)
	psize := bp.psize()
	lsize := bp.lsize()

	raw := make([]byte, psize)
	if _, err := r.ReadAt(raw, offset); err != nil {
		return nil, fmt.Errorf("zfs: readBlock at 0x%X psize=%d: %w", offset, psize, err)
	}

	if bp.isEncrypted() {
		cr, ok := r.(*cryptingReader)
		if !ok {
			return nil, fmt.Errorf("zfs: encrypted block read against an unwrapped reader — open with OpenFromDeviceDatasetWithKey")
		}
		dec, err := decryptBlockPayload(cr.crypt, bp, raw)
		if err != nil {
			return nil, err
		}
		raw = dec
	}

	comp := bp.compress()
	if comp == zcompressOff || comp == zcompressEmpty || comp == zcompressInherit || psize == lsize {
		if psize == lsize {
			return raw, nil
		}
		return raw, nil
	}

	switch {
	case comp == zcompressLZ4:
		return lz4Decompress(raw, int(lsize))
	case comp == zcompressLZJB:
		return lzjbDecompress(raw, int(lsize))
	case comp == zcompressZLE:
		return zleDecompress(raw, int(lsize))
	case comp >= zcompressGZIP1 && comp <= zcompressGZIP9:
		return gzipDecompress(raw, int(lsize))
	case comp == zcompressZSTD:
		return zstdDecompress(raw, int(lsize))
	default:
		return nil, fmt.Errorf("zfs: unsupported compression %d", comp)
	}
}

// readEmbedded extracts inline data from an embedded block pointer per
// OpenZFS module/zfs/blkptr.c:decode_embedded_bp_compressed. Embedded BPs
// (BPE) carry up to 112 bytes of payload spread across the blkptr struct,
// skipping ONLY the prop and (logical) birth fields. Per OpenZFS:
//
//	#define BPE_IS_PAYLOADWORD(bp, wp)  \
//	    ((wp) != &(bp)->blk_prop && (wp) != &(bp)->blk_birth)
//	#define BPE_NUM_WORDS              14
//	#define BPE_PAYLOAD_SIZE           (14 * 8) = 112
//
// On-disk layout (sizeof(blkptr_t) = 128 bytes / 16 uint64 words):
//
//	word  0..5    dva[0..2]            payload  (48 bytes)
//	word     6    prop                 SKIP
//	word  7..8    pad[0..1]            payload  (16 bytes)
//	word     9    phys_birth           payload  (8 bytes)  <-- previously skipped
//	word    10    birth                SKIP
//	word    11    fill                 payload  (8 bytes)  <-- previously skipped
//	word 12..15   cksum[0..3]          payload  (32 bytes)
//
// Total payload = 6 + 2 + 1 + 1 + 4 = 14 words = 112 bytes.
//
// prop field for BPEs:
//
//	bits  0..24  LSIZE  (decompressed size in bytes, biased by 1)
//	bits 25..31  PSIZE  (compressed size in bytes, biased by 1; up to 112)
//	bits 32..38  compress algorithm
//	bit  39      embedded flag (always set here)
//	bits 40..47  etype (BP_EMBEDDED_TYPE_*)
//
// Returns the LSIZE-byte decompressed payload.
func readEmbedded(bp blkptr) ([]byte, error) {
	const bpeLsizeMask = uint64(0x1FFFFFF) // 25 bits
	const bpePsizeMask = uint64(0x7F)      // 7 bits
	lsize := int((bp.prop & bpeLsizeMask) + 1)
	psize := int(((bp.prop >> 25) & bpePsizeMask) + 1)
	comp := uint8((bp.prop >> 32) & 0x7F)

	const payloadCap = 112
	var raw [payloadCap]byte
	le := binary.LittleEndian
	// dva[0..2] = raw[0..48]
	for i := 0; i < 3; i++ {
		le.PutUint64(raw[i*16:], bp.dva[i][0])
		le.PutUint64(raw[i*16+8:], bp.dva[i][1])
	}
	// pad[0..1] (bytes 56..71) = raw[48..64]
	le.PutUint64(raw[48:], bp.pad[0])
	le.PutUint64(raw[56:], bp.pad[1])
	// phys_birth (bytes 72..79) = raw[64..72]
	le.PutUint64(raw[64:], bp.physBirth)
	// birth (bytes 80..87) is SKIPPED — not payload.
	// fill (bytes 88..95) = raw[72..80]
	le.PutUint64(raw[72:], bp.fill)
	// cksum[0..3] (bytes 96..127) = raw[80..112]
	for i := 0; i < 4; i++ {
		le.PutUint64(raw[80+i*8:], bp.cksum[i])
	}

	if psize > payloadCap {
		return nil, fmt.Errorf("zfs: embedded BP psize %d exceeds payload capacity %d", psize, payloadCap)
	}
	compressed := raw[:psize]

	switch comp {
	case zcompressOff, zcompressEmpty, zcompressInherit:
		// Uncompressed; psize == lsize is expected.
		out := make([]byte, lsize)
		copy(out, compressed)
		return out, nil
	case zcompressLZ4:
		return lz4Decompress(compressed, lsize)
	case zcompressLZJB:
		return lzjbDecompress(compressed, lsize)
	case zcompressZLE:
		return zleDecompress(compressed, lsize)
	default:
		if comp >= zcompressGZIP1 && comp <= zcompressGZIP9 {
			return gzipDecompress(compressed, lsize)
		}
		if comp == zcompressZSTD {
			return zstdDecompress(compressed, lsize)
		}
		return nil, fmt.Errorf("zfs: embedded BP unsupported compress %d", comp)
	}
}
