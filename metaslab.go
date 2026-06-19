package filesystem_zfs

// metaslab.go – Metaslab / space-map emission for Format().
//
// OpenZFS divides every top-level vdev's data area into fixed-size
// metaslabs (each 2^ms_shift bytes). The set of metaslabs is named by a
// single "metaslab array" MOS object (DMU_OT_OBJECT_ARRAY): a flat
// uint64[] whose i-th element is the MOS object number of metaslab i's
// space-map object. Each space-map object (DMU_OT_SPACE_MAP) carries a
// space_map_phys_t bonus and a data block of variable-length entries that
// record the ALLOC / FREE history of that metaslab's segments.
//
// On import, spa_load replays each space map to reconstruct the vdev's
// allocated space; `zdb -bcc` (without -AAA) then asserts that the bytes
// reachable by block-pointer traversal exactly equal the bytes the space
// maps mark allocated (otherwise it reports "leaked" / "size != alloc").
//
// Our writer lays every pool block down contiguously in the first
// metaslab, so only metaslab 0 has a non-empty space map; the rest are
// empty (objsize = 0, alloc = 0). The single ALLOC extent for metaslab 0
// covers exactly the contiguous region the writer fills, so the alloc
// total reconciles with block traversal.
//
// References: OpenZFS module/zfs/space_map.c (entry encoding) and
// include/sys/spa.h / space_map.h (space_map_phys_t, SM_* bit macros).

import "encoding/binary"

const (
	// space_map_phys_t prefix that real `zpool create` writes as the
	// space-map object's bonus: smp_object, smp_objsize (== on-disk
	// length in bytes), smp_alloc (signed). The histogram/pad that
	// follow in the in-core struct are not part of the persisted bonus
	// for a freshly created pool (zdb dumps "24 bonus" bytes).
	spaceMapPhysSize = 24

	// Space-map data-block size. Real pools use 16 KiB (datablkszsec =
	// 32); our handful of entries fit comfortably and we keep the same
	// block size so the dnode geometry matches.
	spaceMapBlockSize = 16 * 1024

	// smRunBits is the width of the SM_RUN field in a v1 (single-word)
	// space-map entry; the encoded run length is (run_sectors - 1), so
	// the maximum run is 2^smRunBits sectors.
	smRunBits   = 15
	smOffsetShift = 16 // SM_OFFSET starts at bit 16
	smTypeShift   = 15 // SM_TYPE is bit 15

	// SM debug-entry action codes.
	smAllocAction = 0
	smFreeAction  = 1

	// smDebugBit marks a debug (non-range) entry: the top bit of the word.
	smDebugBit = uint64(1) << 63
)

// smDebugEntry builds a v1 space-map debug entry word. Debug entries are
// markers (not range data) that record which sync pass and txg the
// following range entries were written in; OpenZFS emits one before each
// batch. Layout: [63]=1, [61:60]=action, [59:50]=syncpass, [49:0]=txg.
func smDebugEntry(action, syncpass, txg uint64) uint64 {
	return smDebugBit |
		((action & 0x3) << 60) |
		((syncpass & 0x3ff) << 50) |
		(txg & ((uint64(1) << 50) - 1))
}

// smRangeEntry builds a v1 (single-word) space-map range entry.
//   - offsetSectors: the segment start relative to the metaslab start, in
//     ashift units (offset >> ashift).
//   - runSectors: the segment length in ashift units (must be 1..2^15).
//   - free: true for a FREE record, false for ALLOC.
//
// Layout: [62:16]=SM_OFFSET, [15]=SM_TYPE (1=free), [14:0]=SM_RUN-1, [63]=0.
func smRangeEntry(offsetSectors, runSectors uint64, free bool) uint64 {
	typ := uint64(0)
	if free {
		typ = 1
	}
	return (offsetSectors << smOffsetShift) |
		(typ << smTypeShift) |
		((runSectors - 1) & ((uint64(1) << smRunBits) - 1))
}

// encodeSpaceMapEntries encodes a list of allocated byte ranges (relative
// to the metaslab start) into the v1 space-map entry stream OpenZFS reads.
// It emits a single ALLOC debug marker for syncpass=1/txg, then one or
// more range entries per extent (splitting extents longer than the 15-bit
// run field allows). ashift is the vdev's allocation shift. The returned
// bytes are the raw little-endian entry words; the caller pads to the
// data-block size. The second return value is the encoded length in bytes
// (smp_objsize).
func encodeSpaceMapEntries(allocRanges [][2]uint64, ashift uint, txg uint64) ([]byte, uint64) {
	if len(allocRanges) == 0 {
		return nil, 0
	}
	sector := uint64(1) << ashift
	maxRun := uint64(1) << smRunBits // sectors per single range entry
	var words []uint64
	// One ALLOC debug marker (syncpass 1) precedes the range entries,
	// mirroring what space_map_write() emits on the first sync pass.
	words = append(words, smDebugEntry(smAllocAction, 1, txg))
	for _, r := range allocRanges {
		off := r[0]
		length := r[1]
		offSec := off / sector
		runSec := length / sector
		for runSec > 0 {
			chunk := runSec
			if chunk > maxRun {
				chunk = maxRun
			}
			words = append(words, smRangeEntry(offSec, chunk, false))
			offSec += chunk
			runSec -= chunk
		}
	}
	buf := make([]byte, len(words)*8)
	for i, w := range words {
		binary.LittleEndian.PutUint64(buf[i*8:], w)
	}
	return buf, uint64(len(buf))
}

// spaceMapPhysBonus builds the 24-byte space_map_phys_t bonus.
//   - object: this space-map object's own MOS object number.
//   - objsize: the on-disk entry length in bytes (smp_objsize / smp_length).
//   - alloc: bytes currently allocated in this metaslab (signed smp_alloc).
func spaceMapPhysBonus(object, objsize uint64, alloc int64) []byte {
	b := make([]byte, spaceMapPhysSize)
	le := binary.LittleEndian
	le.PutUint64(b[0:], object)
	le.PutUint64(b[8:], objsize)
	le.PutUint64(b[16:], uint64(alloc))
	return b
}

const (
	// minMetaslabShift is the floor for metaslab_shift: 16 MiB metaslabs,
	// the OpenZFS default granularity for small vdevs.
	minMetaslabShift = 24

	// maxMetaslabs caps the metaslab count so the metaslab array object
	// plus one space-map object per metaslab fit in the free slots of
	// Format()'s single 16 KiB MOS object array. Objects 1..27 are taken
	// by the pool/DSL hierarchy, leaving slots 28..31 — four objects, so
	// one array object + up to three space maps. OpenZFS likewise raises
	// metaslab_shift to bound the metaslab count for large vdevs (just to
	// ~200 rather than 3); a larger metaslab is fully spec-legal.
	maxMetaslabs = 3
)

// chooseMetaslabShift picks metaslab_shift and the resulting whole-metaslab
// count for a vdev whose usable data area is asizeRaw bytes. It returns the
// shift, the per-metaslab size (1<<shift), the metaslab count, and the
// asize aligned down to a whole metaslab boundary (the value that must go
// in the vdev nvlist so asize == count<<shift exactly).
//
// The shift starts at minMetaslabShift (16 MiB) and grows until the count
// fits within maxMetaslabs. For a data area too small to hold even one
// 16 MiB metaslab, the shift is lowered (but never below ashift) so the
// vdev still has at least one metaslab; if it cannot hold even one
// ashift-sized metaslab the count is zero and the caller emits no
// metaslab layout (metaslab_array = 0).
func chooseMetaslabShift(asizeRaw uint64, ashift uint) (shift uint, msSize, count, asizeAligned uint64) {
	if asizeRaw == 0 {
		return 0, 0, 0, 0
	}
	shift = uint(minMetaslabShift)
	// Grow the shift to cap the count for large vdevs.
	for asizeRaw>>shift > maxMetaslabs {
		shift++
	}
	// Shrink the shift (down to ashift) when the area is too small for a
	// single 16 MiB metaslab, so small pools still get one metaslab.
	for shift > ashift && asizeRaw>>shift == 0 {
		shift--
	}
	count = asizeRaw >> shift
	if count == 0 {
		return shift, uint64(1) << shift, 0, 0
	}
	msSize = uint64(1) << shift
	asizeAligned = count << shift
	return shift, msSize, count, asizeAligned
}

// metaslabRegionEnd returns the first data-area byte offset past every
// block Format() lays down for a pool image of totalBytes: the fixed
// layout end (fmtInitialNextFree) plus the metaslab array block (one pool
// block) and one space-map data block (spaceMapBlockSize) per metaslab.
// It mirrors the placement in Format()'s step 4b and is used by
// initAllocator so runtime writes start past the space maps.
func metaslabRegionEnd(totalBytes uint64) uint64 {
	ml := computeMetaslabLayout(rawVdevAsize(totalBytes))
	if ml.count == 0 {
		return uint64(fmtInitialNextFree)
	}
	return uint64(fmtInitialNextFree) + poolBlockSize + ml.count*spaceMapBlockSize
}
