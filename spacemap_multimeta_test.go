package filesystem_zfs

import "testing"

// TestVdevGeometry checks the metaslab geometry chooser: count is capped at
// fmtMaxMetaslabs, asize = count<<shift never exceeds the raw allocatable
// span, and the chosen (shift,count) maximises asize within the cap (no
// other valid shift yields a larger usable area).
func TestVdevGeometry(t *testing.T) {
	sizes := []int64{
		8 * 1024 * 1024,
		16 * 1024 * 1024,
		64 * 1024 * 1024,
		256 * 1024 * 1024,
		512 * 1024 * 1024,
		1024 * 1024 * 1024,
		4 * 1024 * 1024 * 1024,
	}
	for _, total := range sizes {
		asize, shift, count := vdevGeometry(total)
		raw := total - vdevLabelStartSize - 2*vdevLabelSize
		if count < 1 || count > fmtMaxMetaslabs {
			t.Errorf("total=%d: count=%d out of [1,%d]", total, count, fmtMaxMetaslabs)
		}
		if asize != int64(count)<<shift {
			t.Errorf("total=%d: asize=%d != count<<shift=%d", total, asize, int64(count)<<shift)
		}
		if asize > raw {
			t.Errorf("total=%d: asize=%d exceeds raw=%d", total, asize, raw)
		}
		// Maximality: no shift with count<=fmtMaxMetaslabs beats the choice.
		var best int64
		for s := fmtMinMetaslabShift; s <= 40; s++ {
			c := raw / (int64(1) << s)
			if c < 1 {
				break
			}
			if c > fmtMaxMetaslabs {
				continue
			}
			if u := c << s; u > best {
				best = u
			}
		}
		if asize != best {
			t.Errorf("total=%d: asize=%d not maximal (best=%d)", total, asize, best)
		}
	}
}

// TestAllocatorMetaslabBoundary verifies the bump allocator never hands out
// an extent that straddles a metaslab boundary (ZFS claims each block within
// a single metaslab, so a straddling block fails `zdb -bcc`). It allocates a
// run of mixed-size blocks across several metaslabs and asserts each returned
// extent lies wholly inside one metaslab.
func TestAllocatorMetaslabBoundary(t *testing.T) {
	const msSize = int64(1) << 20 // 1 MiB metaslabs
	a := newAllocator(0, 8*msSize, poolBlockSize, msSize)

	sizes := []int{poolBlockSize, 128 * 1024, 64 * 1024, 128 * 1024, 4096, 128 * 1024}
	for round := 0; round < 40; round++ {
		sz := sizes[round%len(sizes)]
		off, err := a.alloc(sz)
		if err != nil {
			break // pool full — fine, we tested enough
		}
		end := off + int64(alignUp(int64(sz), int64(poolBlockSize)))
		if off/msSize != (end-1)/msSize {
			t.Fatalf("alloc(%d)=[%d,%d) straddles metaslab boundary (msSize=%d)", sz, off, end, msSize)
		}
	}
}
