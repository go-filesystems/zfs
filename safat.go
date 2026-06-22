package filesystem_zfs

// safat.go — kernel-compatible System Attributes (SA) infrastructure and
// the minimal fat-ZAP writer needed to make Format()'d ZPL datasets
// MOUNTABLE by the OpenZFS kernel (not merely parseable by zdb).
//
// Background — why this exists
// ----------------------------
// A ZPL (filesystem) dataset stores each inode's attributes (mode, size,
// uid/gid, timestamps, …) in the dnode bonus buffer using the SA layer.
// The bonus carries an sa_hdr_phys_t whose sa_layout_info names a *layout
// number*; the kernel resolves that number to an ordered attribute list it
// reads from the per-objset SA registry:
//
//	ZPL master node (obj 1) ── "SA_ATTRS" ──▶ SA master node (DMU_OT_SA_MASTER_NODE)
//	                                              ├── "REGISTRY" ─▶ attr registry ZAP
//	                                              └── "LAYOUTS"  ─▶ layouts ZAP
//
// Two OpenZFS facts make the SA infrastructure mandatory for mount:
//
//  1. SA_LAYOUT_NUM() (sys/sa_impl.h) REMAPS an on-disk layout number of 0
//     to 1. Layout 1 is the kernel's built-in "dummy/empty" layout, and
//     layout 0 is the built-in legacy ZPL layout (16 attrs incl. an
//     embedded ACL). A freshly written znode therefore cannot use layout 0
//     or 1 to describe a custom attribute packing; it must reference a
//     registered layout numbered >= 2, which only exists if we emit the
//     LAYOUTS ZAP on disk.
//
//  2. sa_setup() reads every layout out of the LAYOUTS ZAP with
//     zap_lookup(..., integer_size=2, num=za_num_integers, attrs), i.e. the
//     layout value is a uint16 ARRAY. A microZAP can only hold a single
//     uint64 value, so LAYOUTS must be a fat-ZAP.
//
// The REGISTRY and SA master node values are single uint64s and so remain
// microZAPs; only LAYOUTS needs the fat-ZAP path implemented here.
//
// fat-ZAP correctness — the kernel navigates by hash
// ---------------------------------------------------
// Unlike this library's own reader (which linear-scans leaf chunks), the
// kernel locates an entry by zap_hash(name): it indexes the leaf hash
// table by the high hash bits and walks the le_hash chain. So the leaf we
// write must (a) compute le_hash with the exact OpenZFS CRC64+salt hash and
// (b) seat the entry in the correct l_hash[] bucket. ZAP integer values are
// stored BIG-ENDIAN on disk (matching readZAPLeafValue in zap.go).

import (
	"encoding/binary"
	"fmt"
)

// ── OpenZFS CRC64 (reflected, poly 0xC96C5795D7870F42) ───────────────────────
//
// zfs_crc64_table is built exactly as module/zfs/spa_misc.c builds it, and
// zap_hash (module/zfs/zap_micro.c) folds a name into the salt with it. The
// known invariant zfs_crc64_table[128] == ZFS_CRC64_POLY is asserted in the
// unit test.

const zfsCRC64Poly = uint64(0xC96C5795D7870F42)

var zfsCRC64Table = func() [256]uint64 {
	var t [256]uint64
	for i := 0; i < 256; i++ {
		crc := uint64(i)
		for j := 0; j < 8; j++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ zfsCRC64Poly
			} else {
				crc >>= 1
			}
		}
		t[i] = crc
	}
	return t
}()

// zapHashbits is the number of high hash bits a non-HASH64 ZAP keeps:
// zap_hashbits() (module/zfs/zap_micro.c) returns 28 unless ZAP_FLAG_HASH64 is
// set (which our string-keyed ZAPs never set).
const zapHashbits = 28

// zapHashName reproduces zap_hash() (module/zfs/zap_micro.c) for a string
// (non-binary) key. It folds every byte of the name EXCEPT the terminating
// null into the per-ZAP salt with the OpenZFS CRC64, then applies the SAME
// final mask the kernel does:
//
//	h &= ~((1ULL << (64 - zap_hashbits(zap))) - 1)
//
// i.e. it keeps only the top zap_hashbits (=28) bits and zeroes the low 36.
// This is essential: the kernel STORES this masked value in le_hash and, at
// lookup, recomputes the same masked hash and chain-compares le_hash == h. If
// we stored the full (unmasked) hash, fzap_lookup's equality test would never
// match and sa_setup's per-layout zap_lookup would return ENOENT — even though
// a linear zap_cursor scan still "sees" the entry. The leaf hash-table bucket
// ZAP_LEAF_HASH(h) slices bits below bit 28, so masking does not perturb it.
// Verified byte-for-byte against a real `zpool create` LAYOUTS dump: for
// salt 0x14312d9, name "2" hashes to 0xe6e6c3c000000000, matching the on-disk
// le_hash exactly.
func zapHashName(salt uint64, name string) uint64 {
	h := salt
	for i := 0; i < len(name); i++ { // name has no embedded null; null not hashed
		h = (h >> 8) ^ zfsCRC64Table[(h^uint64(name[i]))&0xFF]
	}
	h &^= (uint64(1) << (64 - zapHashbits)) - 1
	return h
}

// ── SA attribute registry (zfs_attr_table, module/zfs/zfs_sa.c) ──────────────
//
// Each entry: name, byte length (0 = variable), byteswap class, attr number.
// The values are encoded into the REGISTRY ZAP via ATTR_ENCODE.

type saAttrReg struct {
	name   string
	length uint16
	bswap  uint8
	attr   uint16
}

const (
	saUint64Array = 0
	saUint8Array  = 3
	saACL         = 4
)

// zfsAttrTable mirrors zfs_attr_table[] for the attributes a normal,
// non-xattr=sa, FUID-ACL znode uses. We register the full standard set so
// the kernel's sa_attr_table_setup() sees a consistent registry; only the
// attributes named by a layout are ever packed.
var zfsAttrTable = []saAttrReg{
	{"ZPL_ATIME", 16, saUint64Array, zplAtime},
	{"ZPL_MTIME", 16, saUint64Array, zplMtime},
	{"ZPL_CTIME", 16, saUint64Array, zplCtime},
	{"ZPL_CRTIME", 16, saUint64Array, zplCrtime},
	{"ZPL_GEN", 8, saUint64Array, zplGen},
	{"ZPL_MODE", 8, saUint64Array, zplMode},
	{"ZPL_SIZE", 8, saUint64Array, zplSize},
	{"ZPL_PARENT", 8, saUint64Array, zplParent},
	{"ZPL_LINKS", 8, saUint64Array, zplLinks},
	{"ZPL_XATTR", 8, saUint64Array, zplXattr},
	{"ZPL_RDEV", 8, saUint64Array, zplRdev},
	{"ZPL_FLAGS", 8, saUint64Array, zplFlags},
	{"ZPL_UID", 8, saUint64Array, zplUID},
	{"ZPL_GID", 8, saUint64Array, zplGID},
	{"ZPL_PAD", 32, saUint64Array, zplPad},
	{"ZPL_ZNODE_ACL", 88, saUint8Array, 15},
	{"ZPL_DACL_COUNT", 8, saUint64Array, zplDACLCount},
	{"ZPL_SYMLINK", 0, saUint8Array, zplSymlink},
	{"ZPL_SCANSTAMP", 32, saUint8Array, zplScanstamp},
	{"ZPL_DACL_ACES", 0, saACL, zplDACLAces},
	// ZPL_DXATTR and ZPL_PROJID complete the v2.2 zfs_attr_table the kernel's
	// sa_setup() expects to find in the REGISTRY (a real `zpool create` dump
	// registers both). Encodings copied from that dump: DXATTR = [0:3:20]
	// (variable, uint8 byteswap), PROJID = [8:0:21] (uint64).
	{"ZPL_DXATTR", 0, saUint8Array, zplDXattr},
	{"ZPL_PROJID", 8, saUint64Array, zplProjid},
}

// attrEncode reproduces ATTR_ENCODE (sys/sa_impl.h):
//
//	ATTR_NUM    = bits 0..15
//	ATTR_BSWAP  = bits 16..23
//	ATTR_LENGTH = bits 24..39
func attrEncode(attr, length uint16, bswap uint8) uint64 {
	return uint64(attr) | (uint64(bswap) << 16) | (uint64(length) << 24)
}

// ── SA layout used by Format()'d znodes ──────────────────────────────────────
//
// saZnodeLayoutNum is the on-disk layout number for the attributes our
// writer packs. It must be >= 2 (0 → legacy, and SA_LAYOUT_NUM remaps 0→1).
const saZnodeLayoutNum = 2

// zplDACLCount, zplDACLAces, zplScanstamp are attribute numbers used by the
// modern FUID-ACL znode form. zplPad/zplSymlink already exist in sa.go.
const (
	zplDACLCount = 16
	zplScanstamp = 18 // unused by our layout; registered for completeness
	zplDACLAces  = 19
	zplDXattr    = 20 // ZPL_DXATTR: system-attr xattr (variable, byteswap=uint8)
	zplProjid    = 21 // ZPL_PROJID: project quota id
)

// saZnodeLayout is the ordered attribute list our writer packs into a
// znode bonus, registered on disk as layout saZnodeLayoutNum. It carries
// every fixed-size attribute the kernel reads at znode load
// (zfs_znode_alloc in zfs_znode_os.c: MODE, GEN, SIZE, LINKS, FLAGS,
// PARENT, UID, GID, ATIME, MTIME, CTIME, CRTIME), plus DACL_COUNT (read by
// the ACL layer). All entries are fixed-size, so the bonus has no
// variable-length size table.
func saZnodeLayout() []uint16 {
	return []uint16{
		zplMode, zplSize, zplGen, zplUID, zplGID,
		zplParent, zplFlags, zplAtime, zplMtime, zplCtime,
		zplCrtime, zplLinks, zplDACLCount,
	}
}

// saZnodeLayoutSize is the packed fixed-attribute byte size for the layout.
func saZnodeLayoutSize() int {
	total := 0
	for _, a := range saZnodeLayout() {
		total += saAttrSize[a]
	}
	return total
}

// ── fat-ZAP object builder (single-block header + single leaf) ───────────────
//
// We build the smallest valid fat-ZAP: a header block (zap_phys_t with an
// embedded pointer table) whose every pointer references leaf block 1, plus
// one leaf block holding all entries. This is the shape a freshly upgraded
// microZAP takes and is fully navigable by the kernel.
//
// Layout for a `bs`-byte block (bs = log2(blockSize)):
//   header block 0: zap_phys_t, embedded ptrtbl in the back half
//   leaf   block 1: zap_leaf_phys_t (48-byte hdr, l_hash[NUMENTRIES], chunks)

// fatZAPEntry is one key→uint16-array entry (the only value shape LAYOUTS
// needs). For REGISTRY-style uint64 entries use intLen=8 with a 1-element
// values slice.
type fatZAPEntry struct {
	name   string
	intLen int      // 2 for uint16 arrays, 8 for uint64 scalars
	values []uint64 // each stored big-endian, truncated to intLen bytes
}

// buildFatZAPObject returns the header block and the leaf block for a fat-ZAP
// holding entries. blockSize must be a power of two (4096 here). salt is the
// per-ZAP hash salt (any non-zero value; we reuse mzapDefaultSalt for
// reproducibility, matching newMicroZAPBlock).
func buildFatZAPObject(blockSize int, salt uint64, entries []fatZAPEntry) (hdr, leaf []byte, err error) {
	bs := 0
	for (1 << bs) < blockSize {
		bs++
	}
	if 1<<bs != blockSize {
		return nil, nil, fmt.Errorf("zfs: fat-zap: blockSize %d not a power of two", blockSize)
	}

	// ── header block ─────────────────────────────────────────────────────
	// Embedded pointer table occupies the back half of the header block:
	// ZAP_EMBEDDED_PTRTBL_SHIFT(zap) = bs - 3 - 1, i.e. (blockSize/2)/8
	// uint64 pointers. zt_shift records log2 of that count. Every pointer
	// references leaf block 1 (a single leaf holds all entries).
	hdr = make([]byte, blockSize)
	le := binary.LittleEndian
	le.PutUint64(hdr[0:], zbtHeader)
	le.PutUint64(hdr[8:], zapMagic)
	// zap_ptrtbl (zap_table_phys_t at 0x10): zt_blk=0 (embedded),
	// zt_numblks=0, zt_shift = embedded ptrtbl shift.
	embedShift := bs - 3 - 1
	le.PutUint64(hdr[zapHdrPtrtblShift:], uint64(embedShift))
	le.PutUint64(hdr[zapHdrFreeblkOff:], 2)  // next free block (0,1 used)
	le.PutUint64(hdr[zapHdrNumLeafsOff:], 1) // one leaf
	le.PutUint64(hdr[zapHdrNumEntrOff:], uint64(len(entries)))
	le.PutUint64(hdr[0x50:], salt) // zap_salt
	// Embedded pointer table: (1<<embedShift) uint64 slots in the back half,
	// each pointing at leaf block 1.
	embeddedOff := blockSize / 2
	numPtrs := 1 << embedShift
	for i := 0; i < numPtrs; i++ {
		le.PutUint64(hdr[embeddedOff+i*8:], 1)
	}

	// ── leaf block ───────────────────────────────────────────────────────
	// Hash table size = NUMENTRIES uint16 = (1<<(bs-5)) * 2 bytes = blockSize/16.
	// Chunks follow the hash table.
	//
	// CRITICAL — lh_prefix / lh_prefix_len for a single all-covering leaf:
	// zap_deref_leaf() (module/zfs/zap.c) walks the pointer table to a leaf and
	// then ASSERTs
	//	ZAP_HASH_IDX(h, lh_prefix_len) == lh_prefix
	// for every looked-up hash h, where ZAP_HASH_IDX(h, n) is the top n bits of
	// h (0 when n == 0). A single leaf that every pointer-table slot references
	// must therefore match ALL hash prefixes, which only holds for a zero-length
	// prefix: lh_prefix_len = 0 and lh_prefix = 0. (Verified against a real
	// `zpool create` LAYOUTS dump: lh_prefix=0, lh_prefix_len=0.) The earlier
	// code set lh_prefix_len = zt_shift, which made the assert demand the top
	// zt_shift hash bits be zero — false for our keys — so libzpool/the kernel
	// aborted in fzap_lookup before ever reaching the leaf hash table.
	leaf = make([]byte, blockSize)
	le.PutUint64(leaf[0:], zbtLeaf)       // lh_block_type
	le.PutUint64(leaf[16:], 0)            // lh_prefix = 0 (covers all prefixes)
	le.PutUint32(leaf[24:], zapLeafMagic) // lh_magic
	le.PutUint16(leaf[32:], 0)            // lh_prefix_len = 0 (single leaf)

	hashShift := bs - 5
	hashNumEnt := 1 << hashShift
	hashTabSz := hashNumEnt * 2
	chunksStart := 48 + hashTabSz

	// The leaf hash table (l_hash[]) must start fully empty = CHAIN_END (0xffff)
	// in every slot. A zero-filled slot points at chunk 0, so the kernel's
	// fzap_cursor_retrieve / zap_leaf_lookup_closest would dereference chunk 0
	// as an entry and abort on `le_type == ZAP_CHUNK_ENTRY` (it is an ARRAY
	// chunk). Real leaves are memset to 0xff, matching the reference dump.
	for i := 48; i < chunksStart; i += 2 {
		le.PutUint16(leaf[i:], chainEnd)
	}
	chunkCount := (blockSize - chunksStart) / zapLeafChunkSize

	nextChunk := 0
	alloc := func() (int, error) {
		if nextChunk >= chunkCount {
			return 0, fmt.Errorf("zfs: fat-zap leaf: out of chunks")
		}
		c := nextChunk
		nextChunk++
		return c, nil
	}

	nentries := 0
	for _, e := range entries {
		// Name array chunks (name + trailing null).
		nameBytes := append([]byte(e.name), 0)
		nameInts := len(nameBytes)
		firstNameChunk, err := alloc()
		if err != nil {
			return nil, nil, err
		}
		copied := 0
		cur := firstNameChunk
		for copied < nameInts {
			off := chunksStart + cur*zapLeafChunkSize
			leaf[off] = 251 // ZAP_CHUNK_ARRAY
			n := zapLeafArrayBytes
			if nameInts-copied < n {
				n = nameInts - copied
			}
			copy(leaf[off+1:off+1+n], nameBytes[copied:copied+n])
			copied += n
			if copied < nameInts {
				nxt, err := alloc()
				if err != nil {
					return nil, nil, err
				}
				le.PutUint16(leaf[off+1+zapLeafArrayBytes:], uint16(nxt))
				cur = nxt
			} else {
				le.PutUint16(leaf[off+1+zapLeafArrayBytes:], chainEnd)
			}
		}

		// Value array chunks: values are intLen-byte BIG-ENDIAN integers,
		// concatenated, then chunked.
		valBytes := make([]byte, len(e.values)*e.intLen)
		for i, v := range e.values {
			putBigUint(valBytes[i*e.intLen:(i+1)*e.intLen], v, e.intLen)
		}
		firstValChunk, err := alloc()
		if err != nil {
			return nil, nil, err
		}
		copied = 0
		cur = firstValChunk
		for {
			off := chunksStart + cur*zapLeafChunkSize
			leaf[off] = 251
			n := zapLeafArrayBytes
			if len(valBytes)-copied < n {
				n = len(valBytes) - copied
			}
			if n > 0 {
				copy(leaf[off+1:off+1+n], valBytes[copied:copied+n])
			}
			copied += n
			if copied < len(valBytes) {
				nxt, err := alloc()
				if err != nil {
					return nil, nil, err
				}
				le.PutUint16(leaf[off+1+zapLeafArrayBytes:], uint16(nxt))
				cur = nxt
			} else {
				le.PutUint16(leaf[off+1+zapLeafArrayBytes:], chainEnd)
				break
			}
		}

		// Entry chunk.
		entChunk, err := alloc()
		if err != nil {
			return nil, nil, err
		}
		// le_hash is the FULL (unmasked) zap_hash: the kernel recomputes the
		// hash on lookup and chain-compares it against le_hash, so a masked
		// value would never match and the entry would be reported missing.
		h := zapHashName(salt, e.name)
		off := chunksStart + entChunk*zapLeafChunkSize
		leaf[off] = 252 // ZAP_CHUNK_ENTRY
		leaf[off+1] = byte(e.intLen)
		le.PutUint16(leaf[off+2:], chainEnd) // le_next
		le.PutUint16(leaf[off+4:], uint16(firstNameChunk))
		le.PutUint16(leaf[off+6:], uint16(nameInts))
		le.PutUint16(leaf[off+8:], uint16(firstValChunk))
		le.PutUint16(leaf[off+10:], uint16(len(e.values)))
		le.PutUint32(leaf[off+12:], 0) // le_cd
		le.PutUint64(leaf[off+16:], h) // le_hash

		// Seat the entry in the leaf hash table: ZAP_LEAF_HASH(l, h) =
		// (h >> (64 - ZAP_LEAF_HASH_SHIFT - lh_prefix_len)) & (NUMENT-1).
		// lh_prefix_len is 0 for our single all-covering leaf.
		idx := leafHashIdx(h, hashShift, 0)
		le.PutUint16(leaf[48+idx*2:], uint16(entChunk))
		nentries++
	}

	// lh_nfree / lh_nentries / lh_freelist.
	le.PutUint16(leaf[28:], uint16(chunkCount-nextChunk)) // lh_nfree
	le.PutUint16(leaf[30:], uint16(nentries))             // lh_nentries
	le.PutUint16(leaf[34:], uint16(nextChunk))            // lh_freelist head

	// Thread remaining chunks onto the free list as ZAP_CHUNK_FREE.
	for c := nextChunk; c < chunkCount; c++ {
		off := chunksStart + c*zapLeafChunkSize
		leaf[off] = 253 // ZAP_CHUNK_FREE
		if c+1 < chunkCount {
			le.PutUint16(leaf[off+1+zapLeafArrayBytes:], uint16(c+1))
		} else {
			le.PutUint16(leaf[off+1+zapLeafArrayBytes:], chainEnd)
		}
	}

	return hdr, leaf, nil
}

const (
	zapLeafArrayBytes = zapLeafChunkSize - 3 // 21
	chainEnd          = uint16(0xFFFF)       // CHAIN_END
)

// leafHashIdx reproduces ZAP_LEAF_HASH(l, h) (sys/zap_leaf.h):
//
//	(h >> (64 - ZAP_LEAF_HASH_SHIFT(l) - lh_prefix_len)) & (NUMENTRIES - 1)
func leafHashIdx(h uint64, hashShift, prefixLen int) int {
	shift := 64 - hashShift - prefixLen
	if shift < 0 {
		shift = 0
	}
	return int((h >> uint(shift)) & uint64((1<<hashShift)-1))
}

// putBigUint writes v as an n-byte big-endian integer into b.
func putBigUint(b []byte, v uint64, n int) {
	for i := 0; i < n; i++ {
		b[n-1-i] = byte(v >> (8 * uint(i)))
	}
}
