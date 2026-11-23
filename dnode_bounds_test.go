package filesystem_zfs

import "testing"

// zfs#82: dn_nblkptr is untrusted. A header whose block-pointer array (plus
// the spill pointer, when DNODE_FLAG_SPILL_BLKPTR is set) overruns the dnode
// must be refused by parseDnode, never panic in blkptrAt/bonusData.
func TestParseDnode_NblkptrBound(t *testing.T) {
	cases := []struct {
		name    string
		nblkptr uint8
		flags   uint8
		extra   uint8
		ok      bool
	}{
		{"1", 1, 0, 0, true},
		{"max 3", 3, 0, 0, true}, // DN_MAX_NBLKPTR for a 512-byte dnode
		{"4 overruns", 4, 0, 0, false},
		{"48 (fuzz crasher)", 48, 0, 0, false},
		{"255", 255, 0, 0, false},
		{"3 + spill overruns", 3, dnodeFlagSpillBlkptr, 0, false},
		{"2 + spill", 2, dnodeFlagSpillBlkptr, 0, true},
		{"4 in a 1024-byte dnode", 4, 0, 1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := make([]byte, dnodeMinSize*(1+int(c.extra)))
			b[3], b[7], b[12] = c.nblkptr, c.flags, c.extra
			dn, err := parseDnode(b)
			if (err == nil) != c.ok {
				t.Fatalf("parseDnode err=%v, want ok=%v", err, c.ok)
			}
			if err == nil {
				for i := 0; i < int(dn.nblkptr); i++ {
					_ = dn.blkptrAt(i)
				}
				_ = dn.bonusData()
			}
		})
	}
}
