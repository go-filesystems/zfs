package filesystem_zfs

// raidz.go — healthy-path RAID-Z1/Z2/Z3 read geometry.
//
// Algorithm reference: OpenZFS module/zfs/vdev_raidz.c:vdev_raidz_map_alloc.
//
// Given a logical IO (offset O sectors, size S sectors) against a
// RAID-Z vdev with `dcols` children and `nparity` parity columns:
//
//	data_cols = dcols - nparity
//	q  = S / data_cols                    (full rows)
//	r  = S % data_cols                    (remainder)
//	bc = r==0 ? 0 : r + nparity            ("big" columns in partial row)
//	acols = q==0 ? bc : dcols              (accessed columns)
//
// For column c in [0, acols):
//
//	col   = (O + c) mod dcols              (physical child index)
//	coff  = (O / dcols) << ashift
//	if col < (O mod dcols): coff += sector_size
//	rc_size = (c < bc ? q+1 : q) << ashift
//
// Columns c=0..nparity-1 are PARITY; columns c=nparity..acols-1
// hold DATA in column order. The output buffer is the concatenation
// of all data-column reads, in increasing column index.
//
// For healthy reads we skip the parity columns and read only the data
// columns. The OUTPUT data column ordering matters: ZFS lays out the
// logical data with column 0 (= column c=nparity in the raidz_map)
// being the first data column, and so on.

import (
	"fmt"
	"io"
)

// raidzCol describes one accessed column of a RAID-Z IO.
type raidzCol struct {
	childIdx int   // index into the raidz vdev's children
	offset   int64 // byte offset within that child's data area
	size     int   // bytes to read from this column
}

// raidzMap holds the per-IO layout: parity columns + data columns
// (in order). For healthy reads only `data` is used.
type raidzMap struct {
	nparity int
	dcols   int
	parity  []raidzCol // length == nparity
	data    []raidzCol // length == acols - nparity
}

// raidzMapAlloc computes the column layout for a logical IO at sector
// offset b with size s sectors, on a RAID-Z vdev with `dcols` children
// and `nparity` parity columns. Sector size = 1 << ashift.
func raidzMapAlloc(b, s uint64, dcols, nparity int, ashift uint) *raidzMap {
	dataCols := dcols - nparity
	q := s / uint64(dataCols)
	r := s % uint64(dataCols)
	bc := uint64(0)
	if r != 0 {
		bc = r + uint64(nparity)
	}
	acols := bc
	if q != 0 {
		acols = uint64(dcols)
	}

	rm := &raidzMap{
		nparity: nparity,
		dcols:   dcols,
		parity:  make([]raidzCol, nparity),
		data:    make([]raidzCol, int(acols)-nparity),
	}
	sectorSize := int64(1) << ashift

	for c := uint64(0); c < acols; c++ {
		col := (b + c) % uint64(dcols)
		coff := int64((b / uint64(dcols)) << ashift)
		if col < (b % uint64(dcols)) {
			coff += sectorSize
		}
		var size int
		if c < bc {
			size = int((q + 1) << ashift)
		} else {
			size = int(q << ashift)
		}
		rc := raidzCol{childIdx: int(col), offset: coff, size: size}
		if int(c) < nparity {
			rm.parity[c] = rc
		} else {
			rm.data[int(c)-nparity] = rc
		}
	}
	return rm
}

// raidzRead performs a healthy-path RAID-Z read. `children` is the
// ordered slice of leaf backends matching the raidz vdev's children
// (one per child, by id). `dataArea` is the byte offset within each
// child where DVA offset 0 maps (= partOff + VDEV_LABEL_START_SIZE);
// children may have different partition offsets in general but in
// practice they share the same layout, so a single value works for
// homogeneous test fixtures.
//
// `offset` and `size` are the BYTE values from the DVA (already
// in absolute byte units, not sectors), measured from data-area
// start of the vdev. The function returns `size` bytes of decoded
// data — the concatenation of each data column read in column
// order.
func raidzRead(children []io.ReaderAt, dataArea int64, offset, size int64, nparity int, ashift uint) ([]byte, error) {
	sectorSize := int64(1) << ashift
	if offset%sectorSize != 0 || size%sectorSize != 0 {
		return nil, fmt.Errorf("zfs: raidz read: offset/size %d/%d not aligned to sector %d", offset, size, sectorSize)
	}
	b := uint64(offset / sectorSize)
	s := uint64(size / sectorSize)
	rm := raidzMapAlloc(b, s, len(children), nparity, ashift)

	out := make([]byte, 0, size)
	for _, dc := range rm.data {
		if dc.childIdx >= len(children) {
			return nil, fmt.Errorf("zfs: raidz read: childIdx %d out of range (have %d)", dc.childIdx, len(children))
		}
		if dc.size == 0 {
			continue
		}
		buf := make([]byte, dc.size)
		if _, err := children[dc.childIdx].ReadAt(buf, dataArea+dc.offset); err != nil {
			return nil, fmt.Errorf("zfs: raidz read child %d at %#x: %w", dc.childIdx, dataArea+dc.offset, err)
		}
		out = append(out, buf...)
	}
	return out, nil
}
