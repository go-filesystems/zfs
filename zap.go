package filesystem_zfs

// zap.go – ZAP (ZFS Attribute Processor) parsing.
//
// ZAP stores key→value mappings. There are two kinds:
//   Micro-ZAP: single block, ≤63 entries, keys ≤50 chars, values are uint64.
//   Fat-ZAP:   multi-block hash table, variable key/value sizes.
//
// Identifying the kind: first 8 bytes of the block:
//   ZBT_MICRO  = (1<<63)|3  → micro-ZAP
//   ZBT_HEADER = (1<<63)|1  → fat-ZAP header block
//   ZBT_LEAF   = (1<<63)|0  → fat-ZAP leaf block

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"strings"

	"github.com/go-volumes/safeio"
)

const (
	zbtLeaf   = uint64(1) << 63
	zbtHeader = (uint64(1) << 63) | 1
	zbtMicro  = (uint64(1) << 63) | 3

	mzapHdrSize = 64
	mzapEntSize = 64
	mzapNameLen = 50 // MZAP_NAME_LEN = MZAP_ENT_LEN - 8 - 4 - 2

	// Fat-ZAP constants
	zapLeafHashShift   = 16
	zapLeafHashTabSize = 1 << zapLeafHashShift // entries in leaf hash table
	zapLeafChunkSize   = 24                    // sizeof(struct zap_leaf_chunk)

	// maxZapPtrtblShift caps zt_shift (log2 of the number of pointer-table
	// entries). OpenZFS zap_ptrtbl never exceeds a few million entries; 24
	// (=16M pointers) is already far past any real ZAP and keeps 1<<shift
	// from overflowing or producing a multi-exabyte loop bound.
	maxZapPtrtblShift = 24
	// maxZapLeafs caps zap_num_leafs, used only to bound the leaf-walk
	// early-exit; the per-iteration storage bound is the real safety net.
	maxZapLeafs = 1 << 24
)

// zapLookup looks up key in the ZAP dnode and returns its uint64 value.
func zapLookup(r io.ReaderAt, partOff int64, dn *dnode, key string) (uint64, error) {
	entries, err := zapListAll(r, partOff, dn)
	if err != nil {
		return 0, err
	}
	val, ok := entries[key]
	if !ok {
		return 0, fmt.Errorf("zfs: zap: key %q not found", key)
	}
	return val, nil
}

// zapListAll returns all key→uint64 entries in the ZAP dnode.
func zapListAll(r io.ReaderAt, partOff int64, dn *dnode) (map[string]uint64, error) {
	if dn.nblkptr == 0 || dn.blkptrAt(0).isNull() {
		return nil, fmt.Errorf("zfs: zap: null block pointer")
	}
	// Read the first block to determine ZAP type.
	blk0, err := readDataBlock(r, partOff, dn, 0)
	if err != nil {
		return nil, fmt.Errorf("zfs: zap: read block 0: %w", err)
	}
	if len(blk0) < 8 {
		return nil, fmt.Errorf("zfs: zap: block too small")
	}
	blockType := binary.LittleEndian.Uint64(blk0[:8])
	switch blockType {
	case zbtMicro:
		return parseMicroZAP(blk0)
	case zbtHeader:
		return parseFatZAP(r, partOff, dn, blk0)
	default:
		return nil, fmt.Errorf("zfs: zap: unknown block type 0x%X", blockType)
	}
}

// ── Micro-ZAP ───────────────────────────────────────────────────────────────

// parseMicroZAP parses a micro-ZAP block.
// Layout: 64-byte header, then entries of 64 bytes each:
//
//	[0..7]  value (uint64 LE)
//	[8..11] cd (uint32 LE, collision differentiator)
//	[12..13] pad
//	[14..63] name (50 bytes, null-terminated)
func parseMicroZAP(blk []byte) (map[string]uint64, error) {
	result := make(map[string]uint64)
	n := (len(blk) - mzapHdrSize) / mzapEntSize
	for i := 0; i < n; i++ {
		base := mzapHdrSize + i*mzapEntSize
		ent := blk[base : base+mzapEntSize]
		// First byte of name is 0 → free entry
		if ent[14] == 0 {
			continue
		}
		val := binary.LittleEndian.Uint64(ent[0:8])
		name := nullTerminated(ent[14 : 14+mzapNameLen])
		result[name] = val
	}
	return result, nil
}

// ── Micro-ZAP write ──────────────────────────────────────────────────────────

// mzapInsert adds or updates key=value in a micro-ZAP block.
// Returns the modified block (same underlying slice).
func mzapInsert(blk []byte, key string, value uint64) error {
	if len(key) >= mzapNameLen {
		return fmt.Errorf("zfs: mzap: key %q too long (max %d)", key, mzapNameLen-1)
	}
	n := (len(blk) - mzapHdrSize) / mzapEntSize
	// First pass: update existing
	for i := 0; i < n; i++ {
		base := mzapHdrSize + i*mzapEntSize
		ent := blk[base : base+mzapEntSize]
		if ent[14] == 0 {
			continue
		}
		name := nullTerminated(ent[14 : 14+mzapNameLen])
		if name == key {
			binary.LittleEndian.PutUint64(ent[0:8], value)
			return nil
		}
	}
	// Second pass: find free slot
	for i := 0; i < n; i++ {
		base := mzapHdrSize + i*mzapEntSize
		ent := blk[base : base+mzapEntSize]
		if ent[14] == 0 {
			binary.LittleEndian.PutUint64(ent[0:8], value)
			copy(ent[14:14+mzapNameLen], append([]byte(key), 0))
			return nil
		}
	}
	return fmt.Errorf("zfs: mzap: no free slot (max %d entries)", n)
}

// mzapDelete removes key from a micro-ZAP block.
func mzapDelete(blk []byte, key string) error {
	n := (len(blk) - mzapHdrSize) / mzapEntSize
	for i := 0; i < n; i++ {
		base := mzapHdrSize + i*mzapEntSize
		ent := blk[base : base+mzapEntSize]
		if ent[14] == 0 {
			continue
		}
		name := nullTerminated(ent[14 : 14+mzapNameLen])
		if name == key {
			for j := range ent {
				ent[j] = 0
			}
			return nil
		}
	}
	return fmt.Errorf("zfs: mzap: key %q not found", key)
}

// mzapDefaultSalt is the per-ZAP hash salt written into mz_salt. OpenZFS
// asserts (zap_micro.c:zap_hash) that the salt is non-zero — a zero salt
// crashes any consumer that performs a zap_lookup (e.g. `zdb -e -p`
// walking the MOS pool directory). Real ZFS picks a random salt per
// objset; microZAP lookup recomputes the hash from salt+name and matches
// on the stored name, so any fixed non-zero value is correct and keeps
// Format() reproducible. The value is the constant OpenZFS uses to seed
// zap_create's salt before randomisation (spa_get_random fallback) and is
// a convenient distinctive non-zero marker.
const mzapDefaultSalt = uint64(0x0123456789abcdef)

// newMicroZAPBlock creates a new 4096-byte micro-ZAP block.
func newMicroZAPBlock(blockSize int) []byte {
	blk := make([]byte, blockSize)
	binary.LittleEndian.PutUint64(blk[0:8], zbtMicro)
	// mz_salt (bytes 8:16) must be non-zero; mz_normflags (16:24) = 0.
	binary.LittleEndian.PutUint64(blk[8:16], mzapDefaultSalt)
	return blk
}

// ── Fat-ZAP ─────────────────────────────────────────────────────────────────

// Fat-ZAP header (zap_phys_t):
//   [0..7]    zap_block_type   ZBT_HEADER
//   [8..15]   zap_magic        ZAP_MAGIC (0x2F5AB2AB)
//   [16..23]  zap_ptrtbl
//     [16..23]  zt_blk         (pointer table block number; 0 = embedded in hdr block)
//     [24..27]  zt_numblks     (number of pointer table blocks; 0 = embedded)
//     [28..31]  zt_shift       (number of bits = log2(number of pointers in the table))
//     [32..39]  zt_nextblk     (next block to allocate)
//     [40..47]  zt_blks_copied (reserved)
//   [48..55]  zap_freeblk      (next free block)
//   [56..63]  zap_num_leafs
//   [64..71]  zap_num_entries
//   [72..79]  zap_salt
//   [80..87]  zap_normflags
//   [88..95]  zap_flags
//   (then embedded pointer table starting at offset 128, if zt_numblks=0)

const (
	// ZAP_MAGIC from OpenZFS sys/zap_impl.h. Note the embedded "2" mid-
	// value (0x2F52AB2AB, not 0x2F5AB2AB) — the previous constant had a
	// typo'd digit and rejected every real ZAP block.
	zapMagic = uint64(0x2F52AB2AB)
	// zap_phys_t layout (OpenZFS sys/zap_impl.h):
	//   0x00  zap_block_type        ZBT_HEADER
	//   0x08  zap_magic
	//   0x10  zap_ptrtbl            (zap_table_phys_t, 5 × uint64 = 40 bytes)
	//         +0x00  zt_blk         block# of external ptrtbl, 0 = embedded
	//         +0x08  zt_numblks
	//         +0x10  zt_shift       log2(num entries) — pre-2026 lib read this from +0x0C (inside zt_numblks!)
	//         +0x18  zt_nextblk
	//         +0x20  zt_blks_copied
	//   0x38  zap_freeblk
	//   0x40  zap_num_leafs
	//   0x48  zap_num_entries
	//   0x50  zap_salt
	//   0x58  zap_normflags
	//   0x60  zap_flags
	//   then the embedded pointer table at offset 0x80 when zt_blk == 0
	zapHdrPtrtblOff   = 0x10
	zapHdrPtrtblShift = 0x20 // = 16 + 16 (offset 16 inside zap_table_phys_t)
	zapHdrFreeblkOff  = 0x38
	zapHdrNumLeafsOff = 0x40
	zapHdrNumEntrOff  = 0x48
	zapHdrPtrtblSize  = 128 // size of header before embedded ptrtbl
)

// parseFatZAP reads all entries from a fat-ZAP object.
func parseFatZAP(r io.ReaderAt, partOff int64, dn *dnode, hdrBlock []byte) (map[string]uint64, error) {
	le := binary.LittleEndian
	if len(hdrBlock) < 128 {
		return nil, fmt.Errorf("zfs: fat-zap: header block too small")
	}
	magic := le.Uint64(hdrBlock[8:])
	if magic != zapMagic {
		return nil, fmt.Errorf("zfs: fat-zap: bad magic 0x%X", magic)
	}

	// Pointer table info — zt_shift is a uint64 (not uint32) at the new
	// offset zapHdrPtrtblShift; reading it as uint32 happened to work
	// only when the shift fit in 32 bits, which is always — but the
	// offset was wrong (28 instead of 32), so we'd read inside
	// zt_numblks and get nonsense.
	ptrtblShift := le.Uint64(hdrBlock[zapHdrPtrtblShift:])
	numLeafs := le.Uint64(hdrBlock[zapHdrNumLeafsOff:])

	// H4: zt_shift and zap_num_leafs come straight off disk. A hostile
	// zt_shift (e.g. 63) makes numPtrs = 1<<63 and a hostile numLeafs makes
	// the "stop after numLeafs+1 leaves" condition useless, so the pointer-
	// table loop would re-read leaf blocks up to 2^63 times → effectively a
	// hang. Cap the pointer count to what the pointer table storage can
	// actually address, and cap numLeafs the same way. The embedded table
	// occupies the back half of the header block (8 bytes per pointer); an
	// external table is at most one data block of the dnode. Either way the
	// true upper bound on distinct leaf pointers is far below 2^63.
	if ptrtblShift > maxZapPtrtblShift {
		ptrtblShift = maxZapPtrtblShift
	}
	if numLeafs > maxZapLeafs {
		numLeafs = maxZapLeafs
	}

	result := make(map[string]uint64)
	var visited safeio.VisitSet

	// Walk pointer table to enumerate leaf blocks (avoiding duplicates)
	numPtrs := uint64(1) << ptrtblShift
	ptrtblBlknum := le.Uint64(hdrBlock[zapHdrPtrtblOff:]) // zt_blk (0 = embedded)

	// Hard cap on pointer-table iterations: a pointer table can hold at most
	// (block size / 8) pointers. For the embedded case it is the header
	// block; for the external case it is one data block. Bound the loop by
	// numPtrs but never more than the storage can hold.
	maxPtrs := uint64(len(hdrBlock) / 8)
	if ptrtblBlknum == 0 {
		// embedded table lives in the back half only
		maxPtrs = uint64(len(hdrBlock)/2) / 8
	}
	if numPtrs > maxPtrs {
		numPtrs = maxPtrs
	}

	// Embedded ptrtbl lives in the SECOND HALF of the header block
	// (OpenZFS ZAP_EMBEDDED_PTRTBL_SHIFT = block_shift - 3 - 1; ptrtbl
	// occupies the back half of the block). The previous offset 128
	// only worked when zap_phys_t was treated as a flat 128-byte
	// header — which was never true on real ZFS.
	embeddedPtrtblOff := len(hdrBlock) / 2

	// Read the external pointer table once (not per-iteration) when present.
	var extPtBlk []byte
	if ptrtblBlknum != 0 {
		if blk, err := readDataBlock(r, partOff, dn, ptrtblBlknum); err == nil {
			extPtBlk = blk
		}
	}

	for i := uint64(0); i < numPtrs && uint64(visited.Len()) < numLeafs+1; i++ {
		var leafBlkNum uint64
		if ptrtblBlknum == 0 {
			ptrOff := embeddedPtrtblOff + int(i)*8
			if ptrOff+8 > len(hdrBlock) {
				break
			}
			leafBlkNum = le.Uint64(hdrBlock[ptrOff:])
		} else {
			// External pointer table — bound the loop by the table's
			// actual byte length so a hostile numPtrs cannot run past it.
			ptrOff := i * 8
			if extPtBlk == nil || int(ptrOff)+8 > len(extPtBlk) {
				break
			}
			leafBlkNum = le.Uint64(extPtBlk[ptrOff:])
		}
		// safeio.VisitSet breaks cycles and de-dups: a pointer table that
		// repeatedly references the same leaf (or forms a loop) is visited
		// at most once per distinct block number.
		if leafBlkNum == 0 || !visited.Add(leafBlkNum) {
			continue
		}

		leafBlk, err := readDataBlock(r, partOff, dn, leafBlkNum)
		if err != nil {
			continue
		}
		entries, err := parseFatZAPLeaf(leafBlk)
		if err != nil {
			continue
		}
		for k, v := range entries {
			result[k] = v
		}
	}
	return result, nil
}

// Fat-ZAP leaf block (zap_leaf_phys_t):
//   [0..7]   l_hdr.lh_block_type  ZBT_LEAF
//   [8..15]  l_hdr.lh_pad1
//   [16..23] l_hdr.lh_prefix
//   [24..27] l_hdr.lh_magic  ZAP_LEAF_MAGIC (0x2AB1EAF)
//   (more header fields…)
// The entries are in two sections: hash table and chunk array.
// Chunks start at offset 48 + 2*(1<<lh_prefix_len) (hash table size).
// Actually leaf chunks start at a fixed offset for a leaf that fills one block.

const zapLeafMagic = uint32(0x2AB1EAF)

func parseFatZAPLeaf(blk []byte) (map[string]uint64, error) {
	le := binary.LittleEndian
	if len(blk) < 48 {
		return nil, fmt.Errorf("zfs: fat-zap leaf: too short")
	}
	blockType := le.Uint64(blk[0:])
	if blockType != zbtLeaf {
		return nil, fmt.Errorf("zfs: fat-zap leaf: bad block type 0x%X", blockType)
	}
	lhMagic := le.Uint32(blk[24:])
	if lhMagic != zapLeafMagic {
		return nil, fmt.Errorf("zfs: fat-zap leaf: bad magic 0x%X", lhMagic)
	}

	// lh_nfree + lh_nentries at offsets 28 and 30 (uint16)
	lhNfatries := int(le.Uint16(blk[30:]))
	// lh_prefix_len (uint16 at offset 32) = number of bits in hash prefix
	prefixLen := int(le.Uint16(blk[32:]))
	// lh_freelist (uint16 at offset 34)
	// Block-table starts at 48 (header is 48 bytes)
	// Hash table: 2^(16 - prefix_len) uint16 entries ? Actually the hash table size is:
	// ZAP_LEAF_HASH_NUMENTRIES = ZAP_LEAF_HASH_SIZE(bs) = (bs - sizeof(zap_leaf_phys_t)) / 3 / ...
	// This is getting complex. Let me use an approximate approach:
	// Collect chunks from the block, ignoring the hash table.

	_ = lhNfatries
	_ = prefixLen // suppress unused

	// OpenZFS ZAP_LEAF_HASH_NUMENTRIES = 1 << (block_shift - 5), and
	// hash table = NUMENTRIES * sizeof(uint16) = blockSize/16. The
	// previous code used lh_prefix_len (hash prefix bit count) which
	// for a single-leaf fat-zap is 0, giving a 2-byte table — wrong by
	// ~512×.
	_ = prefixLen
	hashTabSz := len(blk) / 16
	chunksStart := 48 + hashTabSz
	chunkCount := (len(blk) - chunksStart) / zapLeafChunkSize

	result := make(map[string]uint64, lhNfatries)
	// Walk chunks looking for entry chunks (type 252 = ZAP_CHUNK_ENTRY).
	// ZAP_CHUNK_ENTRY = 252, ZAP_CHUNK_ARRAY = 251, ZAP_CHUNK_FREE = 253
	const (
		chunkTypeEntry = 252
		chunkTypeArray = 251
		chunkTypeFree  = 253
	)
	for i := 0; i < chunkCount; i++ {
		off := chunksStart + i*zapLeafChunkSize
		chunkType := blk[off]
		if chunkType != chunkTypeEntry {
			continue
		}
		// Entry chunk layout (24 bytes):
		//   [0]     le_type (252)
		//   [1]     le_value_intlen (bytes per value int: 1, 2, 4, 8)
		//   [2..3]  le_next (uint16)  next entry with same hash
		//   [4..5]  le_name_chunk (uint16)  first name array chunk
		//   [6..7]  le_name_numints (uint16)  chars in name on this
		//   [8..9]  le_value_chunk (uint16)
		//   [10..11] le_value_numints (uint16)
		//   [12..15] le_cd (uint32)
		//   [16..23] le_hash (uint64)
		nameChunk := int(le.Uint16(blk[off+4:]))
		nameLen := int(le.Uint16(blk[off+6:]))
		valChunk := int(le.Uint16(blk[off+8:]))
		valIntLen := int(blk[off+1])
		valNumInts := int(le.Uint16(blk[off+10:]))

		// H3: nameLen and numInts*intLen are attacker-controlled uint16s.
		// They can never legitimately exceed the bytes the leaf block's
		// array chunks can hold (chunkCount * 21). Clamp both to that
		// bound so a hostile value cannot drive an oversized allocation in
		// readZAPLeafValue or an unbounded builder in readZAPLeafString.
		maxArrayBytes := chunkCount * 21
		if maxArrayBytes < 0 {
			maxArrayBytes = 0
		}
		if nameLen > maxArrayBytes {
			nameLen = maxArrayBytes
		}

		// Read name from chained array chunks
		name := readZAPLeafString(blk, chunksStart, chunkCount, nameChunk, nameLen)
		if name == "" {
			continue
		}

		// Read value (uint64 or smaller ints, all assembled into uint64).
		// Clamp valNumInts so numInts*intLen cannot exceed the leaf's array
		// capacity (H3); valIntLen is a single byte (<=255) so the product
		// is then safely bounded.
		if valIntLen > 0 && valNumInts > maxArrayBytes/valIntLen {
			valNumInts = maxArrayBytes / valIntLen
		}
		val := readZAPLeafValue(blk, chunksStart, chunkCount, valChunk, valNumInts, valIntLen)
		result[name] = val
	}
	return result, nil
}

// readZAPLeafString reads a string stored in chained array chunks.
func readZAPLeafString(blk []byte, chunksStart, nchunks, startChunk, nameLen int) string {
	var sb strings.Builder
	chunkIdx := startChunk
	remaining := nameLen
	// H3: the le_next chain can form a cycle (A→B→A). VisitSet stops the
	// walk the moment a chunk index repeats, so a malicious chain cannot
	// loop even if the per-byte progress invariant were ever defeated.
	var visited safeio.VisitSet
	for remaining > 0 && chunkIdx >= 0 && chunkIdx < nchunks {
		if !visited.Add(uint64(chunkIdx)) {
			break
		}
		off := chunksStart + chunkIdx*zapLeafChunkSize
		if off+zapLeafChunkSize > len(blk) {
			break
		}
		if blk[off] != 251 { // ZAP_CHUNK_ARRAY
			break
		}
		// Array chunk: [0] type, [1..21] data (21 bytes), [22..23] next chunk
		dataOff := off + 1
		copyLen := 21
		if copyLen > remaining {
			copyLen = remaining
		}
		for i := 0; i < copyLen; i++ {
			sb.WriteByte(blk[dataOff+i])
		}
		remaining -= copyLen
		// next chunk at [22..23]
		chunkIdx = int(binary.LittleEndian.Uint16(blk[off+22:]))
		if chunkIdx == 0xFFFF {
			break
		}
	}
	s := sb.String()
	// Strip null terminator
	s = strings.TrimRight(s, "\x00")
	return s
}

// readZAPLeafValue reads a value (1..8 bytes per int) from array chunks.
func readZAPLeafValue(blk []byte, chunksStart, nchunks, startChunk, numInts, intLen int) uint64 {
	if intLen == 0 || numInts == 0 {
		return 0
	}
	totalBytes := numInts * intLen
	// H3: numInts*intLen is bounded by the caller against the leaf's array
	// capacity, but guard the allocation defensively against a negative or
	// overflowing product here too.
	if totalBytes < 0 {
		return 0
	}
	buf := make([]byte, totalBytes)
	chunkIdx := startChunk
	copied := 0
	// VisitSet breaks a cyclic le_next chain (H3).
	var visited safeio.VisitSet
	for copied < totalBytes && chunkIdx >= 0 && chunkIdx < nchunks {
		if !visited.Add(uint64(chunkIdx)) {
			break
		}
		off := chunksStart + chunkIdx*zapLeafChunkSize
		if off+zapLeafChunkSize > len(blk) {
			break
		}
		if blk[off] != 251 {
			break
		}
		dataOff := off + 1
		copyLen := 21
		if copyLen > totalBytes-copied {
			copyLen = totalBytes - copied
		}
		copy(buf[copied:], blk[dataOff:dataOff+copyLen])
		copied += copyLen
		chunkIdx = int(binary.LittleEndian.Uint16(blk[off+22:]))
		if chunkIdx == 0xFFFF {
			break
		}
	}
	if intLen > 8 {
		intLen = 8
	}
	// ZAP integer values are BIG-ENDIAN on disk (zap_leaf.c stores
	// them via explicit byte-shift unrolling regardless of machine
	// endianness). The previous LittleEndian decode swapped every
	// uint64 ZAP value, yielding garbage like 0x2000000000000000
	// instead of the actual 32.
	var val uint64
	for i := 0; i < numInts && i < 8/intLen; i++ {
		switch intLen {
		case 1:
			val = uint64(buf[0])
		case 2:
			val = uint64(binary.BigEndian.Uint16(buf[:2]))
		case 4:
			val = uint64(binary.BigEndian.Uint32(buf[:4]))
		case 8:
			if len(buf) >= 8 {
				val = binary.BigEndian.Uint64(buf[:8])
			}
		}
	}
	return val
}

// ── helpers ──────────────────────────────────────────────────────────────────

func nullTerminated(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// buildFatZAPLeaf constructs a fat-ZAP leaf block containing the provided
// entries. It returns a block-sized byte slice ready to be written to disk.
// The function uses array chunks (21 bytes/data) and entry chunks (24 bytes)
// as expected by the reader.
func buildFatZAPLeaf(blockSize int, entries map[string]uint64, prefPrefix int) ([]byte, error) {
	le := binary.LittleEndian
	// Choose a prefix that keeps the hash table small enough to fit.
	prefix := prefPrefix
	if prefix < 0 {
		prefix = 4
	}
	// Ensure hash table fits in the block with header
	for {
		hashTabSz := 2 * (1 << prefix)
		if 48+hashTabSz < blockSize {
			break
		}
		prefix--
		if prefix < 0 {
			return nil, fmt.Errorf("zfs: buildFatZAPLeaf: cannot choose prefix for blockSize=%d", blockSize)
		}
	}
	hashTabSz := 2 * (1 << prefix)
	chunksStart := 48 + hashTabSz
	chunkCount := (blockSize - chunksStart) / zapLeafChunkSize
	if chunkCount <= 0 {
		return nil, fmt.Errorf("zfs: buildFatZAPLeaf: not enough room for chunks (blockSize=%d)", blockSize)
	}

	// Estimate required chunks
	need := 0
	for name := range entries {
		nameLen := len(name) + 1
		nameChunks := (nameLen + 20) / 21
		need += nameChunks // name array chunks
		need += 1          // value (8 bytes) fits in one chunk
		need += 1          // entry chunk
	}
	if need > chunkCount {
		return nil, fmt.Errorf("zfs: buildFatZAPLeaf: leaf capacity exceeded (need %d chunks, have %d)", need, chunkCount)
	}

	blk := make([]byte, blockSize)
	le.PutUint64(blk[0:], zbtLeaf)
	le.PutUint32(blk[24:], zapLeafMagic)
	le.PutUint16(blk[30:], uint16(len(entries)))
	le.PutUint16(blk[32:], uint16(prefix))

	// Fill chunks
	chunkIdx := 0
	for name, val := range entries {
		// name array chunks
		nameBytes := append([]byte(name), 0)
		nameLen := len(nameBytes)
		nameChunks := (nameLen + 20) / 21
		nameChunkStart := chunkIdx
		copied := 0
		for j := 0; j < nameChunks; j++ {
			if chunkIdx >= chunkCount {
				return nil, fmt.Errorf("zfs: buildFatZAPLeaf: out of chunk space")
			}
			off := chunksStart + chunkIdx*zapLeafChunkSize
			blk[off] = 251 // ZAP_CHUNK_ARRAY
			toCopy := 21
			if nameLen-copied < toCopy {
				toCopy = nameLen - copied
			}
			copy(blk[off+1:off+1+toCopy], nameBytes[copied:copied+toCopy])
			// next chunk pointer
			if j < nameChunks-1 {
				le.PutUint16(blk[off+22:], uint16(chunkIdx+1))
			} else {
				le.PutUint16(blk[off+22:], 0xFFFF)
			}
			copied += toCopy
			chunkIdx++
		}

		// value chunk (store as single 8-byte little-endian int)
		if chunkIdx >= chunkCount {
			return nil, fmt.Errorf("zfs: buildFatZAPLeaf: out of chunk space for value")
		}
		offVal := chunksStart + chunkIdx*zapLeafChunkSize
		blk[offVal] = 251
		le.PutUint64(blk[offVal+1:offVal+1+8], val)
		le.PutUint16(blk[offVal+22:], 0xFFFF)
		valChunkStart := chunkIdx
		chunkIdx++

		// entry chunk
		if chunkIdx >= chunkCount {
			return nil, fmt.Errorf("zfs: buildFatZAPLeaf: out of chunk space for entry")
		}
		offEnt := chunksStart + chunkIdx*zapLeafChunkSize
		blk[offEnt] = 252                    // ZAP_CHUNK_ENTRY
		blk[offEnt+1] = 8                    // le_value_intlen = 8 bytes
		le.PutUint16(blk[offEnt+2:], 0xFFFF) // le_next
		le.PutUint16(blk[offEnt+4:], uint16(nameChunkStart))
		le.PutUint16(blk[offEnt+6:], uint16(nameLen))
		le.PutUint16(blk[offEnt+8:], uint16(valChunkStart))
		le.PutUint16(blk[offEnt+10:], uint16(1)) // val num ints
		le.PutUint32(blk[offEnt+12:], 0)         // le_cd
		// le_hash
		h := fnv.New64a()
		h.Write([]byte(name))
		le.PutUint64(blk[offEnt+16:], h.Sum64())
		chunkIdx++
	}
	return blk, nil
}
