package filesystem_zfs

// metaslab.go – metaslab / space_map on-disk encoding for Format().
//
// A ZFS top-level vdev divides its allocatable space (asize) into
// fixed-size metaslabs of 2^ms_shift bytes each. The MOS holds:
//
//   - one "metaslab_array" object (DMU_OT_OBJECT_ARRAY) whose data block
//     is an array of uint64: array[ms_id] = the MOS object number of that
//     metaslab's space_map (0 = never allocated). The leaf vdev's nvlist
//     records this object number in "metaslab_array" and 2^ms_shift in
//     "metaslab_shift".
//
//   - one space_map object (DMU_OT_SPACE_MAP) per metaslab that has had
//     any allocation. Its bonus is a space_map_phys_t; its data block is
//     the space-map log: a sequence of 8-byte little-endian entries, each
//     recording an ALLOC or FREE run within the metaslab.
//
// OpenZFS's metaslab loader sums smp_alloc across all space maps to get
// the vdev's allocated byte count; `zdb -bcc` (without -AAA) compares that
// against what block traversal actually finds and reports "size != alloc
// (leaked)" if they differ. Format() therefore records every block it
// writes as ALLOC in the appropriate metaslab's space map, leaving the
// rest free.
//
// Encoding reference (OpenZFS 2.3 include/sys/space_map.h):
//
//	space_map_phys_t (320 bytes):
//	  0   uint64 smp_object       this SM's own MOS object number
//	  8   uint64 smp_length       valid log bytes (= nentries * 8)
//	  16  int64  smp_alloc        net allocated bytes in this metaslab
//	  24  uint64 smp_pad[5]
//	  64  uint64 smp_histogram[32]
//
//	single-word log entry (bit63 == 0):
//	  [62:16] offset  (47 bits, in 2^sm_shift units, relative to ms start)
//	  [15]    type    (SM_ALLOC=0, SM_FREE=1)
//	  [14:0]  run-1   (15 bits, in 2^sm_shift units; run = field+1)
//
//	two-word log entry (bits[63:62] == 0b11):
//	  word0: 0b11<<62 | (run-1)<<SPA_VDEVBITS | vdev
//	  word1: type<<SM2_OFFSET_BITS | offset
//
// The entry offsets/runs are in units of 2^sm_shift, where sm_shift for a
// metaslab space map equals the vdev ashift (12 here), NOT ms_shift.

import "encoding/binary"

const (
	// spaceMapPhysSize is sizeof(space_map_phys_t): smp_object, smp_length,
	// smp_alloc (3×8) + smp_pad[5] (5×8) + smp_histogram[32] (32×8) = 320.
	spaceMapPhysSize = (3 + 5 + 32) * 8

	// space_map_phys_t bonus field offsets.
	smpObject    = 0
	smpLength    = 8
	smpAlloc     = 16
	smpHistogram = 64

	// Space-map entry type values (enum sm_lookup_type).
	smAlloc = 0
	smFree  = 1

	// Single-word entry bit widths.
	smOffsetBits = 47
	smRunBits    = 15
	// smRunMaxUnits is the largest run (in sm_shift units) a single-word
	// entry can hold: SM_RUN_DECODE(~0) = (2^15 - 1) + 1 = 32768.
	smRunMaxUnits = 1 << smRunBits

	// Two-word entry widths.
	spaVdevBits   = 24
	sm2OffsetBits = 63
	sm2RunBits    = 36
	sm2Prefix     = 3 // 0b11 at bits [63:62]
)

// smShift is the space-map shift: the vdev ashift. All Format() pools are
// ashift=12, and metaslab space maps decode their offsets/runs in 2^ashift
// units (zdb sets sm->sm_shift = vd->vdev_ashift).
const smShift = 12

// encodeSMSingle builds a single-word space-map log entry. offBytes and
// runBytes are byte values relative to the metaslab start; both must be
// multiples of 2^smShift. typ is smAlloc or smFree. The caller guarantees
// the run fits a single word (runBytes>>smShift <= smRunMaxUnits and
// offBytes>>smShift < 2^smOffsetBits).
func encodeSMSingle(offBytes, runBytes int64, typ uint64) uint64 {
	off := uint64(offBytes>>smShift) & ((1 << smOffsetBits) - 1)
	run := uint64(runBytes >> smShift) // run >= 1
	var w uint64
	// prefix bits [63:62] = 0 for a single-word entry.
	w |= off << 16
	w |= (typ & 1) << 15
	w |= (run - 1) & ((1 << smRunBits) - 1)
	return w
}

// encodeSMTwoWord builds a two-word space-map log entry for runs larger
// than a single word can hold. vdev is the leaf vdev id (0). Returns the
// two LE words (word0, word1).
func encodeSMTwoWord(offBytes, runBytes int64, vdev uint64, typ uint64) (uint64, uint64) {
	run := uint64(runBytes >> smShift) // run >= 1
	off := uint64(offBytes >> smShift)
	w0 := uint64(sm2Prefix) << 62
	w0 |= ((run - 1) & ((1 << sm2RunBits) - 1)) << spaVdevBits
	w0 |= vdev & ((1 << spaVdevBits) - 1)
	w1 := (typ & 1) << sm2OffsetBits
	w1 |= off & ((1 << sm2OffsetBits) - 1)
	return w0, w1
}

// smRange is one allocated (or freed) byte range within a metaslab,
// expressed relative to the metaslab's start. off and length are byte
// counts and must be 2^smShift-aligned.
type smRange struct {
	off    int64
	length int64
	typ    uint64 // smAlloc or smFree
}

// encodeSpaceMapLog serialises ranges into the on-disk space-map log
// (a sequence of 8-byte LE entries), splitting any run that overflows a
// single-word entry into a two-word entry. Returns the packed log bytes;
// len(log) == smp_length.
func encodeSpaceMapLog(ranges []smRange) []byte {
	var out []byte
	var word [8]byte
	emit := func(w uint64) {
		binary.LittleEndian.PutUint64(word[:], w)
		out = append(out, word[:]...)
	}
	for _, r := range ranges {
		remaining := r.length
		off := r.off
		for remaining > 0 {
			chunk := remaining
			maxSingle := int64(smRunMaxUnits) << smShift
			if chunk <= maxSingle {
				emit(encodeSMSingle(off, chunk, r.typ))
				off += chunk
				remaining -= chunk
				continue
			}
			// Run too large for a single word: emit a two-word entry
			// (handles up to 2^36 sm_shift units, far beyond any small
			// image, but kept correct for completeness).
			w0, w1 := encodeSMTwoWord(off, chunk, 0, r.typ)
			emit(w0)
			emit(w1)
			off += chunk
			remaining -= chunk
		}
	}
	return out
}

// makeSpaceMapPhys builds the 320-byte space_map_phys_t bonus for a space
// map: its own object number, the valid-log byte length, and the net
// allocated bytes. The histogram is left zero (zdb tolerates a zero
// histogram; it is advisory free-region bucketing only).
func makeSpaceMapPhys(smObj uint64, logLen int, allocBytes int64) []byte {
	b := make([]byte, spaceMapPhysSize)
	le := binary.LittleEndian
	le.PutUint64(b[smpObject:], smObj)
	le.PutUint64(b[smpLength:], uint64(logLen))
	le.PutUint64(b[smpAlloc:], uint64(allocBytes))
	return b
}

// metaslabLayout describes the metaslab geometry chosen for a vdev asize.
type metaslabLayout struct {
	msShift int   // log2 of metaslab size
	msSize  int64 // 1 << msShift
	count   int   // number of metaslabs covering asize
}

// chooseMetaslabLayout picks a metaslab geometry for the given asize. We
// keep the writer's existing 2^24 (16 MiB) metaslab size — OpenZFS uses a
// 16 MiB floor for small vdevs — which yields a handful of metaslabs for a
// test image and stays consistent with the metaslab_shift already written
// to the label nvlist. count is asize/msSize (asize is already aligned to
// msSize by the nvlist builders).
func chooseMetaslabLayout(asize int64, msShift int) metaslabLayout {
	msSize := int64(1) << msShift
	count := int(asize / msSize)
	if count < 1 {
		count = 1
	}
	return metaslabLayout{msShift: msShift, msSize: msSize, count: count}
}
