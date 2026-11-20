package filesystem_zfs

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// failingCopies is an in-memory device whose reads fail with err for any
// request that touches one of the [lo, hi) ranges in bad.
type failingCopies struct {
	checkedReader
	bad [][2]int64
	err error
}

func (f failingCopies) ReadAt(p []byte, off int64) (int, error) {
	for _, b := range f.bad {
		if off < b[1] && off+int64(len(p)) > b[0] {
			return 0, f.err
		}
	}
	return f.checkedReader.ReadAt(p, off)
}

// A device read error on one copy is treated like a checksum failure on it:
// the next DVA is tried, on the readBlockInto path and on the readBlock path,
// at 1 and 4 workers. The error is reported, wrapping the device's, only when
// every copy failed, and the first one in DVA order; a failed direct read
// leaves its buffer zero.
func TestDittoFallbackOnDeviceReadError(t *testing.T) {
	const rec = 512
	errDev := errors.New("device: EIO")
	good := make([]byte, rec)
	copy(good, "good copy of the record")
	bad := bytes.Repeat([]byte{0xAA}, rec)
	bp := makeBlkptrCksum(0, rec, rec, zcompressOff, dmotPlainFileContents, 0, 1, zioChecksumFletch4)
	setBPChecksum(&bp, good)
	bp.dva[1] = makeDVA(rec, rec)
	cp0, cp1 := [2]int64{0, rec}, [2]int64{rec, 2 * rec}

	for _, direct := range []bool{true, false} {
		for _, w := range []int{1, 4} {
			for _, c := range []struct {
				name    string
				img     []byte
				bad     [][2]int64
				wantErr error // nil: the record must read as good
			}{
				{"first copy EIO, second good", append(append([]byte(nil), bad...), good...), [][2]int64{cp0}, nil},
				{"first copy EIO, second damaged", append(append([]byte(nil), bad...), bad...), [][2]int64{cp0}, errDev},
				{"first damaged, second EIO", append(append([]byte(nil), bad...), good...), [][2]int64{cp1}, ErrChecksum},
				{"both EIO", append(append([]byte(nil), good...), good...), [][2]int64{cp0, cp1}, errDev},
				{"first good, second EIO", append(append([]byte(nil), good...), bad...), [][2]int64{cp1}, nil},
			} {
				name := fmt.Sprintf("direct=%v workers=%d %s", direct, w, c.name)
				rd := failingCopies{checkedReader{bytes.NewReader(c.img)}, c.bad, errDev}
				jobs := make([]recordJob, 8)
				dst := make([]byte, 8*rec)
				for i := range jobs {
					jobs[i] = recordJob{blk: uint64(i), bp: bp}
					if direct {
						jobs[i].into = dst[i*rec : (i+1)*rec]
					}
				}
				got := make([][]byte, len(jobs))
				err := decodeRecords(rd, 0, jobs, rec, w, len(jobs), func(k int, d []byte) error {
					got[k] = d
					return nil
				})
				if (err != nil) != (c.wantErr != nil) || (err != nil && !errors.Is(err, c.wantErr)) {
					t.Fatalf("%s: err = %v, want %v", name, err, c.wantErr)
				}
				for i := range jobs {
					r := got[i]
					if direct {
						r = dst[i*rec : (i+1)*rec]
					}
					switch {
					case c.wantErr == nil && !bytes.Equal(r, good):
						t.Fatalf("%s: record %d is not the good copy", name, i)
					case c.wantErr != nil && direct && !bytes.Equal(r, make([]byte, rec)):
						t.Fatalf("%s: record %d: a failed direct read left bytes in the buffer", name, i)
					}
				}
			}
		}
	}
}
