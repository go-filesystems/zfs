package filesystem_zfs

import (
	"encoding/binary"
	"testing"
)

// decodeSMDebug decodes a v1 space-map debug entry word
// (the high bit is set). It returns the action, syncpass and txg fields.
func decodeSMDebug(w uint64) (action, syncpass, txg uint64) {
	action = (w >> 60) & 0x3
	syncpass = (w >> 50) & 0x3ff
	txg = w & ((uint64(1) << 50) - 1)
	return
}

// decodeSMRange decodes a v1 space-map range entry word (high bit clear)
// into (free, offsetSectors, runSectors).
func decodeSMRange(w uint64) (free bool, offSec, runSec uint64) {
	runSec = (w & ((uint64(1) << smRunBits) - 1)) + 1
	free = (w>>smTypeShift)&1 == 1
	offSec = (w >> smOffsetShift) & ((uint64(1) << 47) - 1)
	return
}

// TestSpaceMapEntryEncoding verifies the v1 space-map entry encoding
// against the byte-level format OpenZFS reads: a leading ALLOC debug
// marker, then range entries whose decoded (offset, run) reproduce the
// input extents. The decode mirror is the same bit layout observed in a
// real `zpool create` space map dumped with `zdb -R ...:dr`.
func TestSpaceMapEntryEncoding(t *testing.T) {
	const ashift = 12
	const txg = 1
	// Two extents: a 128 KiB run at offset 0x80000 and a 16 KiB run right
	// after it. Both are multiples of the sector size (1<<ashift).
	ranges := [][2]uint64{
		{0x80000, 0x20000},
		{0xA0000, 0x4000},
	}
	buf, objsize := encodeSpaceMapEntries(ranges, ashift, txg)
	if objsize != uint64(len(buf)) {
		t.Fatalf("objsize %d != len(buf) %d", objsize, len(buf))
	}
	if len(buf)%8 != 0 || len(buf) == 0 {
		t.Fatalf("encoded length %d not a non-zero multiple of 8", len(buf))
	}

	words := make([]uint64, len(buf)/8)
	for i := range words {
		words[i] = binary.LittleEndian.Uint64(buf[i*8:])
	}

	// First word must be the ALLOC debug marker (syncpass 1, txg).
	if words[0]>>63 != 1 {
		t.Fatalf("first word %#x is not a debug entry", words[0])
	}
	action, syncpass, dtxg := decodeSMDebug(words[0])
	if action != smAllocAction || syncpass != 1 || dtxg != txg {
		t.Fatalf("debug marker decode: action=%d syncpass=%d txg=%d, want 0/1/%d",
			action, syncpass, dtxg, txg)
	}

	// Remaining words are ALLOC range entries reproducing the extents.
	var got [][2]uint64
	for _, w := range words[1:] {
		if w>>63 == 1 {
			t.Fatalf("unexpected debug entry %#x among range entries", w)
		}
		free, offSec, runSec := decodeSMRange(w)
		if free {
			t.Errorf("range entry %#x decoded as FREE, want ALLOC", w)
		}
		got = append(got, [2]uint64{offSec << ashift, runSec << ashift})
	}
	if len(got) != len(ranges) {
		t.Fatalf("decoded %d range entries, want %d", len(got), len(ranges))
	}
	for i, r := range ranges {
		if got[i] != r {
			t.Errorf("extent %d decoded %v, want %v", i, got[i], r)
		}
	}
}

// TestSpaceMapEntrySplitsLongRun verifies that an extent longer than a
// single 15-bit run field is split into multiple range entries whose
// offsets and lengths are contiguous and sum to the original extent.
func TestSpaceMapEntrySplitsLongRun(t *testing.T) {
	const ashift = 12
	sector := uint64(1) << ashift
	maxRun := uint64(1) << smRunBits // sectors per entry
	// One extent of (maxRun + 5) sectors => must split into two entries.
	extentSectors := maxRun + 5
	ranges := [][2]uint64{{0, extentSectors * sector}}
	buf, _ := encodeSpaceMapEntries(ranges, ashift, 1)
	words := make([]uint64, len(buf)/8)
	for i := range words {
		words[i] = binary.LittleEndian.Uint64(buf[i*8:])
	}
	// words[0] is the debug marker; words[1:] are range entries.
	rangeWords := words[1:]
	if len(rangeWords) != 2 {
		t.Fatalf("long run split into %d entries, want 2", len(rangeWords))
	}
	var nextOff, total uint64
	for i, w := range rangeWords {
		_, offSec, runSec := decodeSMRange(w)
		if offSec != nextOff {
			t.Errorf("entry %d offset %d not contiguous (want %d)", i, offSec, nextOff)
		}
		if runSec > maxRun {
			t.Errorf("entry %d run %d exceeds max %d", i, runSec, maxRun)
		}
		nextOff += runSec
		total += runSec
	}
	if total != extentSectors {
		t.Errorf("split run total %d sectors != original %d", total, extentSectors)
	}
}

// TestChooseMetaslabShift checks the metaslab geometry chooser: small
// vdevs get 16 MiB metaslabs, the count never exceeds maxMetaslabs, the
// aligned asize equals count<<shift, and a sub-metaslab area yields no
// metaslabs.
func TestChooseMetaslabShift(t *testing.T) {
	const ashift = 12
	cases := []struct {
		name        string
		rawAsize    uint64
		wantNonzero bool // expect at least one metaslab
		wantFloor   bool // expect the 16 MiB floor shift (small vdev)
	}{
		{"48MiB-3-metaslabs", 48 << 20, true, true},  // 48/16 = 3 == cap, floor shift
		{"64MiB-capped", 64 << 20, true, false},      // 64/16=4 > cap => shift grows
		{"4GiB-capped", 4 << 30, true, false},        // large vdev: shift grows, count <= cap
		{"sub-sector-no-metaslab", 1 << 10, false, false}, // 1 KiB < one ashift block
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			shift, msSize, count, asize := chooseMetaslabShift(c.rawAsize, ashift)
			if count > maxMetaslabs {
				t.Errorf("count %d exceeds cap %d", count, maxMetaslabs)
			}
			if c.wantNonzero && count == 0 {
				t.Errorf("count = 0, want >= 1 (shift %d)", shift)
			}
			if !c.wantNonzero && count != 0 {
				t.Errorf("count = %d, want 0", count)
			}
			if c.wantFloor && shift != minMetaslabShift {
				t.Errorf("shift = %d, want floor %d", shift, minMetaslabShift)
			}
			if count > 0 {
				if msSize != uint64(1)<<shift {
					t.Errorf("msSize %d != 1<<%d", msSize, shift)
				}
				if asize != count<<shift {
					t.Errorf("asize %d != count<<shift (%d)", asize, count<<shift)
				}
				if shift < ashift {
					t.Errorf("shift %d below ashift %d", shift, ashift)
				}
			} else if asize != 0 {
				t.Errorf("zero-count layout has asize %d, want 0", asize)
			}
		})
	}
}

// TestSpaceMapPhysBonus verifies the 24-byte space_map_phys_t bonus
// layout: smp_object, smp_objsize (length), smp_alloc, little-endian.
func TestSpaceMapPhysBonus(t *testing.T) {
	b := spaceMapPhysBonus(29, 0x118, 0x42000)
	if len(b) != spaceMapPhysSize {
		t.Fatalf("bonus len %d, want %d", len(b), spaceMapPhysSize)
	}
	if got := binary.LittleEndian.Uint64(b[0:]); got != 29 {
		t.Errorf("smp_object = %#x, want 0x1d", got)
	}
	if got := binary.LittleEndian.Uint64(b[8:]); got != 0x118 {
		t.Errorf("smp_objsize = %#x, want 0x118", got)
	}
	if got := binary.LittleEndian.Uint64(b[16:]); got != 0x42000 {
		t.Errorf("smp_alloc = %#x, want 0x42000", got)
	}
}

// TestMetaslabRegionEnd checks that the data-area offset past the
// space-map region stays within the image's usable bounds and past the
// fixed layout, so the runtime allocator starts clear of the space maps.
func TestMetaslabRegionEnd(t *testing.T) {
	const total = 64 << 20
	end := metaslabRegionEnd(total)
	if end <= fmtInitialNextFree {
		t.Errorf("region end %#x not past fixed layout %#x", end, fmtInitialNextFree)
	}
	// Must leave room before the two trailing labels.
	limit := uint64(total) - 2*vdevLabelSize
	if end >= limit {
		t.Errorf("region end %#x overruns usable limit %#x", end, limit)
	}
}
