package filesystem_zfs

import (
	"fmt"
	"math/rand"
	"testing"
)

// TestCRC64TableInvariant checks the documented OpenZFS invariant
// zfs_crc64_table[128] == ZFS_CRC64_POLY (asserted in zap_hash,
// module/zfs/zap_micro.c). If this holds, the reference stdlib table was built
// with the correct reflected polynomial (ECMA-182 == ZFS_CRC64_POLY).
func TestCRC64TableInvariant(t *testing.T) {
	if zfsCRC64Table[128] != zfsCRC64Poly {
		t.Fatalf("zfsCRC64Table[128] = %#x, want ZFS_CRC64_POLY %#x",
			zfsCRC64Table[128], zfsCRC64Poly)
	}
}

// goldenCRC64Table and zapHashNameGolden are a VERBATIM copy of the original,
// hand-rolled OpenZFS CRC-64 table + zap_hash fold that safat.go carried before
// it was migrated onto the hash/crc64 (ECMA-182) reference implementation. They
// exist ONLY to prove — bit for bit — that the migration preserves the exact
// on-disk le_hash value the kernel recomputes and chain-compares at lookup.
// Do NOT wire these into production code.
var goldenCRC64Table = func() [256]uint64 {
	var tbl [256]uint64
	for i := 0; i < 256; i++ {
		crc := uint64(i)
		for j := 0; j < 8; j++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ zfsCRC64Poly
			} else {
				crc >>= 1
			}
		}
		tbl[i] = crc
	}
	return tbl
}()

func zapHashNameGolden(salt uint64, name string) uint64 {
	h := salt
	for i := 0; i < len(name); i++ {
		h = (h >> 8) ^ goldenCRC64Table[(h^uint64(name[i]))&0xFF]
	}
	h &^= (uint64(1) << (64 - zapHashbits)) - 1
	return h
}

// TestCRC64TableParityVsGolden proves the stdlib crc64.ECMA table is
// byte-for-byte identical to the old hand-rolled zfs_crc64_table across all
// 256 entries (not merely at index 128).
func TestCRC64TableParityVsGolden(t *testing.T) {
	for i := 0; i < 256; i++ {
		if zfsCRC64Table[i] != goldenCRC64Table[i] {
			t.Fatalf("table entry %d: stdlib %#x != golden %#x",
				i, zfsCRC64Table[i], goldenCRC64Table[i])
		}
	}
}

// TestZapHashNameKnownVector pins the single on-disk vector documented in
// safat.go: for the ZAP salt 0x14312d9, the LAYOUTS name "2" hashes to
// 0xe6e6c3c000000000 (matching a real `zpool create` LAYOUTS dump's le_hash).
func TestZapHashNameKnownVector(t *testing.T) {
	const salt = uint64(0x14312d9)
	const want = uint64(0xe6e6c3c000000000)
	if got := zapHashName(salt, "2"); got != want {
		t.Fatalf("zapHashName(0x14312d9, %q) = %#016x, want %#016x", "2", got, want)
	}
	if got := zapHashNameGolden(salt, "2"); got != want {
		t.Fatalf("golden mismatch on known vector: %#016x", got)
	}
}

// TestZapHashNameParityVsGolden proves the migrated, hash/crc64-based
// zapHashName reproduces the old hand-rolled fold EXACTLY — including the
// effect of the per-ZAP salt — over real format names, edge cases and a large
// random fuzz sample. Parity here is what guarantees the kernel finds every
// entry we seat in a leaf hash bucket.
func TestZapHashNameParityVsGolden(t *testing.T) {
	names := []string{
		"", "0", "1", "2", "10", "42", "255", "1000000",
		"ZPL_MODE", "ZPL_SIZE", "ZPL_ATIME", "ZPL_MTIME", "ZPL_CTIME",
		"ZPL_CRTIME", "ZPL_GEN", "ZPL_LINKS", "ZPL_FLAGS", "ZPL_PARENT",
		"ZPL_UID", "ZPL_GID", "ZPL_DACL_COUNT", "ZPL_DACL_ACES",
		"ZPL_DXATTR", "ZPL_PROJID", "SA_ATTRS", "REGISTRY", "LAYOUTS",
		"VERSION", "DELETE_QUEUE", "ROOT",
		"\x01", "\xff\xfe\x00\x7f",
		"a", "aa", "aaa", "aaaa", "aaaaa", "aaaaaa", "aaaaaaa",
		"aaaaaaaa", "aaaaaaaaa", // 8 & 9 bytes: cross the slicing-by-8 boundary
		"the quick brown fox jumps over the lazy dog 0123456789",
	}
	// Curated salts include 0, the documented on-disk salt, the default mzap
	// salt, all-ones, high bit set, and assorted patterns.
	salts := []uint64{
		0, 1, 0x14312d9, mzapDefaultSalt, 0xffffffffffffffff,
		0x8000000000000000, 0x0123456789abcdef, 0xdeadbeefcafebabe,
		0x00000000ffffffff,
	}
	for _, s := range salts {
		for _, n := range names {
			if got, want := zapHashName(s, n), zapHashNameGolden(s, n); got != want {
				t.Fatalf("parity mismatch salt=%#x name=%q: new=%#016x golden=%#016x",
					s, n, got, want)
			}
		}
	}

	// Large random fuzz: random salts and random-length random-byte names.
	rng := rand.New(rand.NewSource(1))
	const iters = 500000
	for i := 0; i < iters; i++ {
		salt := rng.Uint64()
		b := make([]byte, rng.Intn(40))
		for j := range b {
			b[j] = byte(rng.Intn(256))
		}
		n := string(b)
		if got, want := zapHashName(salt, n), zapHashNameGolden(salt, n); got != want {
			t.Fatalf("random parity mismatch salt=%#x name=%x: new=%#016x golden=%#016x",
				salt, b, got, want)
		}
	}
}

// TestFatZAPRoundTrip builds a LAYOUTS-shaped fat-ZAP (a uint16 array
// value) and a REGISTRY-shaped one (uint64 scalar values), then reads
// them back through the library's own fat-ZAP reader to confirm the
// header + leaf are structurally valid and the entries are found. The
// reader collapses array values to a single uint64, so for the uint16
// array we only assert the entry is present (the kernel reads the full
// array; structural validity is what this test guards).
func TestFatZAPRoundTrip(t *testing.T) {
	// REGISTRY-style: a handful of attr-name → uint64 entries.
	regEntries := []fatZAPEntry{
		{name: "ZPL_MODE", intLen: 8, values: []uint64{attrEncode(zplMode, 8, saUint64Array)}},
		{name: "ZPL_SIZE", intLen: 8, values: []uint64{attrEncode(zplSize, 8, saUint64Array)}},
		{name: "ZPL_ATIME", intLen: 8, values: []uint64{attrEncode(zplAtime, 16, saUint64Array)}},
	}
	hdr, leaf, err := buildFatZAPObject(poolBlockSize, mzapDefaultSalt, regEntries)
	if err != nil {
		t.Fatalf("buildFatZAPObject(registry): %v", err)
	}
	got := readFatZAPViaMemBackend(t, hdr, leaf)
	for _, e := range regEntries {
		v, ok := got[e.name]
		if !ok {
			t.Errorf("registry entry %q missing", e.name)
			continue
		}
		if v != e.values[0] {
			t.Errorf("registry %q = %#x, want %#x", e.name, v, e.values[0])
		}
	}

	// LAYOUTS-style: one entry keyed by the decimal layout number, value is
	// a uint16 array of attribute numbers.
	layoutAttrs := saZnodeLayout()
	vals := make([]uint64, len(layoutAttrs))
	for i, a := range layoutAttrs {
		vals[i] = uint64(a)
	}
	hdr2, leaf2, err := buildFatZAPObject(poolBlockSize, mzapDefaultSalt, []fatZAPEntry{
		{name: fmt.Sprintf("%d", saZnodeLayoutNum), intLen: 2, values: vals},
	})
	if err != nil {
		t.Fatalf("buildFatZAPObject(layouts): %v", err)
	}
	got2 := readFatZAPViaMemBackend(t, hdr2, leaf2)
	if _, ok := got2[fmt.Sprintf("%d", saZnodeLayoutNum)]; !ok {
		t.Errorf("layouts entry %q missing", fmt.Sprintf("%d", saZnodeLayoutNum))
	}
}

// readFatZAPViaMemBackend wires the header + leaf blocks behind an
// in-memory dnode (header = blkid 0, leaf = blkid 1) and runs the
// library's parseFatZAP over it.
func readFatZAPViaMemBackend(t *testing.T, hdr, leaf []byte) map[string]uint64 {
	t.Helper()
	// Two 4 KiB logical blocks reached through one L1 indirect block.
	ind := make([]byte, poolBlockSize)
	hdrBP := makeBlkptrCksum(0, poolBlockSize, poolBlockSize, zcompressOff, dmotSAAttrLayouts, 0, fmtPoolTXG, zioChecksumOff)
	leafBP := makeBlkptrCksum(int64(poolBlockSize), poolBlockSize, poolBlockSize, zcompressOff, dmotSAAttrLayouts, 0, fmtPoolTXG, zioChecksumOff)
	encodeBlkptr(hdrBP, ind[0:blkptrSize])
	encodeBlkptr(leafBP, ind[blkptrSize:2*blkptrSize])

	// Backing store: [0]=hdr, [4K]=leaf, [8K]=indirect.
	buf := make([]byte, 3*poolBlockSize)
	copy(buf[0:], hdr)
	copy(buf[poolBlockSize:], leaf)
	copy(buf[2*poolBlockSize:], ind)
	r := memReaderAt(buf)

	indBP := makeBlkptrCksum(int64(2*poolBlockSize), poolBlockSize, poolBlockSize, zcompressOff, dmotSAAttrLayouts, 1, fmtPoolTXG, zioChecksumOff)
	dn := newDnode(dmotSAAttrLayouts, 1, dmotNone, 0)
	dn.datablkszsec = uint16(poolBlockSize / 512)
	dn.indblkshift = 12
	dn.nlevels = 2
	dn.maxblkid = 1
	dn.setBlkptrAt(0, indBP)
	dn.encode()
	pdn, err := parseDnode(dn.raw)
	if err != nil {
		t.Fatalf("parseDnode: %v", err)
	}

	out, err := parseFatZAP(r, 0, pdn, hdr)
	if err != nil {
		t.Fatalf("parseFatZAP: %v", err)
	}
	return out
}

// memReaderAt is a tiny io.ReaderAt over a byte slice (partOff is 0 in the
// test, so DVA offsets index directly into buf).
type memReaderAt []byte

func (m memReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(m)) {
		return 0, fmt.Errorf("out of range")
	}
	n := copy(p, m[off:])
	return n, nil
}
