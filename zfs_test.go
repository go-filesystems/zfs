package filesystem_zfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type errorReaderAt struct {
	data       []byte
	failOffset int64
}

func (reader errorReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off == reader.failOffset {
		return 0, io.ErrUnexpectedEOF
	}
	if off >= int64(len(reader.data)) {
		return 0, io.EOF
	}
	n := copy(p, reader.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func TestParseUberblock(t *testing.T) {
	if _, err := parseUberblock([]byte("short"), 0, 0, 0); err == nil {
		t.Fatal("parseUberblock() error = nil, want short-buffer error")
	}

	if _, err := parseUberblock(make([]byte, uberblockSize), 0, 0, 0); err == nil {
		t.Fatal("parseUberblock() error = nil, want bad-magic error")
	}

	little, err := parseUberblock(makeUberblock(binary.LittleEndian, 1, 2, 3, 4), 100, 0, 1)
	if err != nil {
		t.Fatalf("parseUberblock(little): %v", err)
	}
	if little.Endian != "little" || little.TransactionGroup != 2 || little.TimestampUnix() != 4 {
		t.Fatalf("little = %+v, want decoded little-endian uberblock", little)
	}

	big, err := parseUberblock(makeUberblock(binary.BigEndian, 5, 6, 7, 8), 200, 1, 2)
	if err != nil {
		t.Fatalf("parseUberblock(big): %v", err)
	}
	if big.Endian != "big" || big.Version != 5 || !big.Timestamp.Equal(time.Unix(8, 0).UTC()) {
		t.Fatalf("big = %+v, want decoded big-endian uberblock", big)
	}
}

func TestReadInfoSelectsFreshestUberblock(t *testing.T) {
	image := make([]byte, 2*vdevLabelSize+uberblockRegionOffset+4*uberblockSize)
	writeUberblock(image, 0, 0, makeUberblock(binary.LittleEndian, 1, 5, 11, 20))
	writeUberblock(image, 0, 1, makeUberblock(binary.BigEndian, 1, 7, 12, 25))
	writeUberblock(image, 1, 2, makeUberblock(binary.LittleEndian, 1, 7, 13, 30))

	info, err := readInfo(bytes.NewReader(image), 0)
	if err != nil {
		t.Fatalf("readInfo: %v", err)
	}
	if info.Label != 1 || info.Slot != 2 || info.TransactionGroup != 7 || info.RawTimestamp != 30 {
		t.Fatalf("info = %+v, want label 1 slot 2 txg 7 timestamp 30", info)
	}
	if got, want := info.LabelOffset(0), int64(vdevLabelSize); got != want {
		t.Fatalf("LabelOffset() = %d, want %d", got, want)
	}
	if got, want := info.UberblockRegionOffset(0), int64(vdevLabelSize+uberblockRegionOffset); got != want {
		t.Fatalf("UberblockRegionOffset() = %d, want %d", got, want)
	}
}

func TestReadInfoSkipsBrokenFirstLabel(t *testing.T) {
	image := make([]byte, 2*vdevLabelSize+uberblockRegionOffset+2*uberblockSize)
	writeUberblock(image, 1, 0, makeUberblock(binary.LittleEndian, 1, 9, 10, 11))

	info, err := readInfo(errorReaderAt{data: image, failOffset: uberblockRegionOffset}, 0)
	if err != nil {
		t.Fatalf("readInfo: %v", err)
	}
	if info.Label != 1 || info.TransactionGroup != 9 {
		t.Fatalf("info = %+v, want label 1 txg 9", info)
	}
}

func TestReadInfoNoValidUberblock(t *testing.T) {
	if _, err := readInfo(bytes.NewReader(make([]byte, uberblockRegionOffset+uberblockSize)), 0); err == nil {
		t.Fatal("readInfo() error = nil, want missing uberblock error")
	}
}

func TestOpenBareImageAndInfoHelpers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zfs.img")
	image := make([]byte, 2*vdevLabelSize+uberblockRegionOffset+uberblockSize)
	writeUberblock(image, 0, 0, makeUberblock(binary.LittleEndian, 1, 2, 3, 4))
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	info := fs.Info()
	if fs.PartitionOffset() != 0 {
		t.Fatalf("PartitionOffset() = %d, want 0", fs.PartitionOffset())
	}
	if info.Endian != "little" || info.TimestampUnix() != 4 {
		t.Fatalf("info = %+v, want little-endian timestamp 4", info)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestOpenWithMBRPartition(t *testing.T) {
	partOffset := int64(1024 * sectorSize)
	image := make([]byte, partOffset+2*vdevLabelSize+uberblockRegionOffset+uberblockSize)
	writeMBRPartition(image, 0, 1024)
	writeUberblock(image[int(partOffset):], 0, 0, makeUberblock(binary.LittleEndian, 1, 4, 5, 6))

	path := filepath.Join(t.TempDir(), "zfs-mbr.img")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()

	if got := fs.PartitionOffset(); got != partOffset {
		t.Fatalf("PartitionOffset() = %d, want %d", got, partOffset)
	}
}

func TestOpenErrorPaths(t *testing.T) {
	origOpenFile := openFile
	origOpenPartitionOffset := openPartitionOffset
	origOpenReadInfo := openReadInfo
	t.Cleanup(func() {
		openFile = origOpenFile
		openPartitionOffset = origOpenPartitionOffset
		openReadInfo = origOpenReadInfo
	})

	openFile = func(string, int, os.FileMode) (*os.File, error) {
		return nil, errors.New("boom")
	}
	if _, err := Open("missing.img", -1); err == nil {
		t.Fatal("Open() error = nil, want error")
	}

	path := filepath.Join(t.TempDir(), "zfs.img")
	image := make([]byte, 2*vdevLabelSize+uberblockRegionOffset+uberblockSize)
	writeUberblock(image, 0, 0, makeUberblock(binary.LittleEndian, 1, 2, 3, 4))
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	openFile = origOpenFile
	openPartitionOffset = func(io.ReaderAt, int) (int64, error) {
		return 0, errors.New("partition")
	}
	if _, err := Open(path, -1); err == nil {
		t.Fatal("Open() error = nil, want partition error")
	}

	openPartitionOffset = origOpenPartitionOffset
	openReadInfo = func(io.ReaderAt, int64) (Info, error) {
		return Info{}, errors.New("read")
	}
	if _, err := Open(path, -1); err == nil {
		t.Fatal("Open() error = nil, want read error")
	}
}

func TestPartitionOffsetVariants(t *testing.T) {
	// partitionOffset now delegates to the hardened go-volumes/gpt parser,
	// which validates every partition against the device size. Fixtures use
	// LBAs that fit inside the image, and deviceSizeOf reads the size from
	// the *bytes.Reader (which exposes Size()).
	t.Run("bare image", func(t *testing.T) {
		off, err := partitionOffset(bytes.NewReader(make([]byte, sectorSize)), -1)
		if err != nil {
			t.Fatalf("partitionOffset: %v", err)
		}
		if off != 0 {
			t.Fatalf("partitionOffset() = %d, want 0", off)
		}
	})

	t.Run("no size: whole-image fallback", func(t *testing.T) {
		// A reader without Size()/Stat() cannot bound the table, so
		// partitionOffset falls back to whole-image mode (offset 0).
		image := make([]byte, 64*sectorSize)
		writeGPT(image, 2, []uint64{4, 8})
		off, err := partitionOffset(errorReaderAt{data: image, failOffset: -1}, -1)
		if err != nil || off != 0 {
			t.Fatalf("partitionOffset(no-size) = (%d, %v), want (0, nil)", off, err)
		}
	})

	t.Run("gpt auto and index", func(t *testing.T) {
		image := make([]byte, 64*sectorSize)
		writeGPT(image, 2, []uint64{4, 8})
		if off, err := partitionOffset(bytes.NewReader(image), -1); err != nil || off != int64(4*sectorSize) {
			t.Fatalf("partitionOffset(auto) = (%d, %v), want (%d, nil)", off, err, 4*sectorSize)
		}
		if off, err := partitionOffset(bytes.NewReader(image), 1); err != nil || off != int64(8*sectorSize) {
			t.Fatalf("partitionOffset(index) = (%d, %v), want (%d, nil)", off, err, 8*sectorSize)
		}
	})

	t.Run("gpt errors", func(t *testing.T) {
		// Bad (too-small) entry size is rejected by the gpt parser.
		badEntrySize := make([]byte, 64*sectorSize)
		writeGPTHeaderOnly(badEntrySize, 2, 64, 1)
		if _, err := partitionOffset(bytes.NewReader(badEntrySize), -1); err == nil {
			t.Fatal("partitionOffset() error = nil, want GPT entry-size error")
		}

		// A header with no populated entries: auto-select and explicit
		// index both fail to find a partition.
		empty := make([]byte, 64*sectorSize)
		writeGPTHeaderOnly(empty, 2, 4, 128)
		if _, err := partitionOffset(bytes.NewReader(empty), -1); err == nil {
			t.Fatal("partitionOffset() error = nil, want missing GPT partition error")
		}
		if _, err := partitionOffset(bytes.NewReader(empty), 0); err == nil {
			t.Fatal("partitionOffset() error = nil, want missing GPT index error")
		}
		if _, err := partitionOffset(bytes.NewReader(empty), 3); err == nil {
			t.Fatal("partitionOffset() error = nil, want out-of-range GPT index error")
		}
	})

	t.Run("mbr auto and index", func(t *testing.T) {
		image := make([]byte, 64*sectorSize)
		writeMBRPartition(image, 1, 8)
		if off, err := partitionOffset(bytes.NewReader(image), -1); err != nil || off != int64(8*sectorSize) {
			t.Fatalf("partitionOffset(auto) = (%d, %v), want (%d, nil)", off, err, 8*sectorSize)
		}
		if off, err := partitionOffset(bytes.NewReader(image), 1); err != nil || off != int64(8*sectorSize) {
			t.Fatalf("partitionOffset(index) = (%d, %v), want (%d, nil)", off, err, 8*sectorSize)
		}
	})

	t.Run("mbr errors", func(t *testing.T) {
		// A protective/empty MBR (signature only, no entries) has no
		// populated partition: auto-select returns ErrNoTable → offset 0,
		// while an explicit out-of-range index errors.
		image := make([]byte, 64*sectorSize)
		image[510] = 0x55
		image[511] = 0xAA
		if off, err := partitionOffset(bytes.NewReader(image), -1); err != nil || off != 0 {
			t.Fatalf("partitionOffset() = (%d, %v), want (0, nil)", off, err)
		}
		if _, err := partitionOffset(bytes.NewReader(image), 0); err == nil {
			t.Fatal("partitionOffset() error = nil, want missing MBR index error")
		}
		if _, err := partitionOffset(bytes.NewReader(image), 5); err == nil {
			t.Fatal("partitionOffset() error = nil, want out-of-range MBR index error")
		}
	})
}

func makeUberblock(order binary.ByteOrder, version uint64, txg uint64, guidSum uint64, timestamp uint64) []byte {
	buf := make([]byte, uberblockSize)
	order.PutUint64(buf[0:8], uberblockMagic)
	order.PutUint64(buf[8:16], version)
	order.PutUint64(buf[16:24], txg)
	order.PutUint64(buf[24:32], guidSum)
	order.PutUint64(buf[32:40], timestamp)
	return buf
}

func writeUberblock(image []byte, label int, slot int, uberblock []byte) {
	off := label*vdevLabelSize + uberblockRegionOffset + slot*uberblockSize
	copy(image[off:], uberblock)
}

func writeMBRPartition(image []byte, index int, startLBA uint32) {
	image[510] = 0x55
	image[511] = 0xAA
	entry := image[446+index*16:]
	binary.LittleEndian.PutUint32(entry[8:], startLBA)
	entry[4] = 0xBF
}

func writeGPT(image []byte, entryLBA uint64, starts []uint64) {
	writeGPTHeaderOnly(image, entryLBA, 128, uint32(len(starts)))
	for index, start := range starts {
		entry := image[int(entryLBA)*sectorSize+index*128:]
		entry[0] = byte(index + 1)
		binary.LittleEndian.PutUint64(entry[32:], start)
	}
}

func writeGPTHeaderOnly(image []byte, entryLBA uint64, entrySize uint32, numParts uint32) {
	copy(image[sectorSize:], []byte("EFI PART"))
	binary.LittleEndian.PutUint64(image[sectorSize+72:], entryLBA)
	binary.LittleEndian.PutUint32(image[sectorSize+80:], numParts)
	binary.LittleEndian.PutUint32(image[sectorSize+84:], entrySize)
}

func TestInterfaceStubs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zfs.img")
	image := make([]byte, 2*vdevLabelSize+uberblockRegionOffset+uberblockSize)
	writeUberblock(image, 0, 0, makeUberblock(binary.LittleEndian, 1, 2, 3, 4))
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	fs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()

	if _, err := fs.ReadFile("/"); err == nil {
		t.Fatal("ReadFile error = nil, want error")
	}
	if _, err := fs.ListDir("/"); err == nil {
		t.Fatal("ListDir error = nil, want error")
	}
	st, err := fs.Stat("/")
	if err != nil {
		t.Fatalf("Stat(root) error = %v, want nil", err)
	}
	if st.Inode() != fs.Info().TransactionGroup {
		t.Fatalf("Stat(root).Inode() = %d, want %d", st.Inode(), fs.Info().TransactionGroup)
	}
	if _, err := fs.Stat("/nonroot"); err == nil {
		t.Fatal("Stat non-root error = nil, want error")
	}
	if err := fs.WriteFile("/", nil, 0o644); err == nil {
		t.Fatal("WriteFile error = nil, want error")
	}
	if _, err := fs.ReadLink("/"); err == nil {
		t.Fatal("ReadLink error = nil, want error")
	}
	if err := fs.MkDir("/", 0o755); err == nil {
		t.Fatal("MkDir error = nil, want error")
	}
	if err := fs.DeleteFile("/"); err == nil {
		t.Fatal("DeleteFile error = nil, want error")
	}
	if err := fs.DeleteDir("/"); err == nil {
		t.Fatal("DeleteDir error = nil, want error")
	}
	if err := fs.Rename("/a", "/b"); err == nil {
		t.Fatal("Rename error = nil, want error")
	}
}
