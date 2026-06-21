package filesystem_zfs

import (
	"fmt"
	"testing"
)

// TestCRC64TableInvariant checks the documented OpenZFS invariant
// zfs_crc64_table[128] == ZFS_CRC64_POLY (asserted in zap_hash,
// module/zfs/zap_micro.c). If this holds, the table was built with the
// correct reflected polynomial.
func TestCRC64TableInvariant(t *testing.T) {
	if zfsCRC64Table[128] != zfsCRC64Poly {
		t.Fatalf("zfsCRC64Table[128] = %#x, want ZFS_CRC64_POLY %#x",
			zfsCRC64Table[128], zfsCRC64Poly)
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
