package filesystem_zfs

// metaslab_test.go – unit tests for the space_map / metaslab encoding.
//
// These tests are VM-independent: they assert that the bytes Format()
// emits for the metaslab_array and metaslab-0 space_map decode back to the
// exact OpenZFS on-disk layout (include/sys/space_map.h), and that the
// recorded smp_alloc equals the contiguous data span Format() writes — the
// invariant `zdb -bcc` checks (block traversal size == metaslab alloc).

import (
	"encoding/binary"
	"testing"
)

// decodeSMSingle reverses encodeSMSingle using the OpenZFS macros:
// offset = BF64_DECODE(x,16,47), type = BF64_DECODE(x,15,1),
// run = BF64_DECODE(x,0,15)+1. Returns byte offset, byte run, type.
func decodeSMSingle(w uint64) (offBytes, runBytes int64, typ uint64) {
	off := (w >> 16) & ((1 << smOffsetBits) - 1)
	typ = (w >> 15) & 1
	run := (w & ((1 << smRunBits) - 1)) + 1
	return int64(off) << smShift, int64(run) << smShift, typ
}

func TestEncodeSMSingleRoundTrip(t *testing.T) {
	cases := []struct {
		off, run int64
		typ      uint64
	}{
		{0, 4096, smAlloc},
		{4096, 4096, smFree},
		{512 * 1024, 144 * 1024, smAlloc},
		{0, int64(smRunMaxUnits) << smShift, smAlloc}, // max single-word run
	}
	for _, c := range cases {
		w := encodeSMSingle(c.off, c.run, c.typ)
		// A single-word entry must have prefix bits [63:62] == 0.
		if (w >> 62) != 0 {
			t.Fatalf("off=%#x run=%#x: prefix bits not zero (w=%#x)", c.off, c.run, w)
		}
		gotOff, gotRun, gotTyp := decodeSMSingle(w)
		if gotOff != c.off || gotRun != c.run || gotTyp != c.typ {
			t.Errorf("roundtrip off=%#x run=%#x typ=%d -> off=%#x run=%#x typ=%d",
				c.off, c.run, c.typ, gotOff, gotRun, gotTyp)
		}
	}
}

func TestEncodeSpaceMapLogAllocRun(t *testing.T) {
	// The contiguous data span Format() writes for metaslab 0.
	allocStart := int64(fmtMOSObjsetOff)
	allocEnd := int64(fmtInitialNextFree)
	allocBytes := allocEnd - allocStart

	log := encodeSpaceMapLog([]smRange{{off: allocStart, length: allocBytes, typ: smAlloc}})
	if len(log)%8 != 0 {
		t.Fatalf("space-map log not a whole number of 8-byte words: %d", len(log))
	}

	// Decode every entry and confirm it sums back to allocBytes, all ALLOC,
	// covering [allocStart, allocEnd) contiguously.
	var covered int64
	cursor := allocStart
	for i := 0; i+8 <= len(log); i += 8 {
		w := binary.LittleEndian.Uint64(log[i:])
		if (w >> 62) == sm2Prefix {
			t.Fatalf("unexpected two-word entry for a %d-byte run", allocBytes)
		}
		off, run, typ := decodeSMSingle(w)
		if typ != smAlloc {
			t.Errorf("entry %d: type=%d, want ALLOC", i/8, typ)
		}
		if off != cursor {
			t.Errorf("entry %d: off=%#x, want %#x (non-contiguous)", i/8, off, cursor)
		}
		cursor += run
		covered += run
	}
	if covered != allocBytes {
		t.Errorf("covered %d bytes, want %d", covered, allocBytes)
	}
	if cursor != allocEnd {
		t.Errorf("log ends at %#x, want %#x", cursor, allocEnd)
	}
}

func TestMakeSpaceMapPhysFields(t *testing.T) {
	const obj = 29
	const logLen = 8
	const alloc = 144 * 1024
	b := makeSpaceMapPhys(obj, logLen, alloc)
	if len(b) != spaceMapPhysSize {
		t.Fatalf("space_map_phys size = %d, want %d", len(b), spaceMapPhysSize)
	}
	le := binary.LittleEndian
	if got := le.Uint64(b[smpObject:]); got != obj {
		t.Errorf("smp_object = %d, want %d", got, obj)
	}
	if got := le.Uint64(b[smpLength:]); got != logLen {
		t.Errorf("smp_length = %d, want %d", got, logLen)
	}
	if got := int64(le.Uint64(b[smpAlloc:])); got != alloc {
		t.Errorf("smp_alloc = %d, want %d", got, alloc)
	}
	// Histogram region must exist and start at offset 64.
	if smpHistogram != 64 {
		t.Errorf("smp_histogram offset = %d, want 64", smpHistogram)
	}
}

func TestChooseMetaslabLayout(t *testing.T) {
	// 128 MiB device: asize = 128 - 4 (reserve) - 0.5 (two trailing
	// labels) MiB, aligned down to 16 MiB = 112 MiB => 7 metaslabs.
	asize := vdevAsize(128 * 1024 * 1024)
	ml := chooseMetaslabLayout(asize, fmtMetaslabShift)
	if ml.msShift != fmtMetaslabShift {
		t.Errorf("msShift = %d, want %d", ml.msShift, fmtMetaslabShift)
	}
	if ml.msSize != 1<<fmtMetaslabShift {
		t.Errorf("msSize = %d, want %d", ml.msSize, int64(1)<<fmtMetaslabShift)
	}
	wantCount := int(asize / (1 << fmtMetaslabShift))
	if ml.count != wantCount {
		t.Errorf("count = %d, want %d", ml.count, wantCount)
	}
	// All of Format()'s data must fit inside metaslab 0.
	if int64(fmtInitialNextFree) > ml.msSize {
		t.Errorf("Format data span ends at %#x, exceeds metaslab 0 size %#x — "+
			"allocation accounting assumes everything fits metaslab 0",
			fmtInitialNextFree, ml.msSize)
	}
}
