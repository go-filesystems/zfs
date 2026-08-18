package filesystem_zfs

import "testing"

// A dnode's dn_nblkptr is a single byte read off the disk, so a malformed image
// can claim up to 255 block pointers in a dnode with room for 3. Before this was
// rejected at parse time, the claim reached two different slice expressions and
// panicked in the caller's process:
//
//	blkptrAt:   raw[64+i*128 : 64+i*128+128] → "slice bounds out of range [:576]
//	            with capacity 512" (found by FuzzReadDnodeData)
//	bonusData:  base past len(raw) with end clamped to it → low > high
//
// A parser handed hostile bytes must return an error, not take the process down,
// so both are asserted here rather than left to the fuzz corpus.
func TestParseDnodeRejectsImpossibleNblkptr(t *testing.T) {
	for _, tc := range []struct {
		name     string
		size     int
		nblkptr  byte
		wantFail bool
	}{
		{"512-byte dnode, 3 pointers is the maximum", dnodeMinSize, 3, false},
		{"512-byte dnode, 4 does not fit", dnodeMinSize, 4, true},
		{"512-byte dnode, a hostile 255", dnodeMinSize, 255, true},
		{"512-byte dnode, zero is fine", dnodeMinSize, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := make([]byte, tc.size)
			b[3] = tc.nblkptr
			dn, err := parseDnode(b)
			if tc.wantFail {
				if err == nil {
					t.Fatalf("nblkptr=%d accepted in a %d-byte dnode; only %d pointers fit",
						tc.nblkptr, tc.size, (tc.size-dnodeHdrSize)/blkptrSize)
				}
				return
			}
			if err != nil {
				t.Fatalf("nblkptr=%d rejected but it fits: %v", tc.nblkptr, err)
			}
			// Every pointer the dnode admits to must be readable without panicking.
			for i := 0; i < int(dn.nblkptr); i++ {
				dn.blkptrAt(i)
			}
			dn.bonusData()
		})
	}
}

// bonusData computes its base from nblkptr, so a dnode assembled inside the
// package (clone.go builds one directly) can still reach it with a base past the
// buffer even though parseDnode would have rejected the same values.
func TestBonusDataSurvivesAnOutOfRangeBase(t *testing.T) {
	dn := &dnode{raw: make([]byte, dnodeMinSize), nblkptr: 255, bonuslen: 64}
	if got := dn.bonusData(); got != nil {
		t.Fatalf("expected no bonus data when the base is past the buffer, got %d bytes", len(got))
	}
}
