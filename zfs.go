package filesystem_zfs

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	filesystem "github.com/go-filesystems/interface"
)

// Verify FS implements the common filesystem interface.

const (
	sectorSize            = 512
	vdevLabelSize         = 256 * 1024
	uberblockRegionOffset = 128 * 1024
	uberblockSize         = 1024
	uberblockSlots        = 128
	uberblockMagic        = 0x00bab10c

	// vdevLabelStartSize matches OpenZFS's VDEV_LABEL_START_SIZE: two
	// labels at the start (2 × 256 KiB) + VDEV_BOOT_SIZE (3.5 MiB) =
	// 4 MiB. DVA offsets in block pointers are byte offsets relative
	// to the start of the data area, which begins at vdevLabelStartSize
	// inside the partition. Without this shift the reader misses every
	// block written by real `zpool create` (the lib's own Format()
	// previously wrote MOS at byte offset 0x80000 which is inside the
	// boot pad region; we now align with real OpenZFS layout).
	vdevLabelStartSize = 4 << 20 // 4 MiB
)

// Info holds the fields decoded from a ZFS uberblock.
type Info struct {
	Version          uint64
	TransactionGroup uint64
	GUIDSum          uint64
	RawTimestamp     uint64
	Timestamp        time.Time
	Label            int
	Slot             int
	Offset           int64
	Endian           string
}

// TimestampUnix returns the raw uberblock timestamp in seconds since the Unix epoch.
func (info Info) TimestampUnix() uint64 { return info.RawTimestamp }

// LabelOffset returns the absolute offset of the label that contained the uberblock.
func (info Info) LabelOffset(partOffset int64) int64 {
	return partOffset + int64(info.Label)*vdevLabelSize
}

// UberblockRegionOffset returns the absolute offset of the uberblock ring.
func (info Info) UberblockRegionOffset(partOffset int64) int64 {
	return info.LabelOffset(partOffset) + uberblockRegionOffset
}

// zfsFS represents an opened ZFS image (unexported concrete type).
type zfsFS struct {
	f          blockBackend
	partOffset int64     // DATA AREA start in `f` (= raw partition start + VDEV_LABEL_START_SIZE)
	labelOffset int64    // raw partition start in `f` — for label / uberblock / grow operations
	info       Info
	crypt      *cryptCtx // non-nil only when opened via OpenFromDeviceDatasetWithKey
	fsFields   // extra fields defined in fs.go
}

// blockBackend is the interface backing zfsFS. The read path uses
// only ReadAt — already satisfied by io.ReaderAt-style sources.
// The write/grow path additionally needs WriteAt + Sync + Size +
// Truncate, mirroring ext4.BlockDevice. Any layered block source
// (LUKS Device, qcow2 wrapper, in-memory test fixture) implements
// this interface to feed ZFS without an *os.File-backed image.
type blockBackend interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
	Size() (int64, error)
	Truncate(size int64) error
	io.Closer
}

// BlockBackend is the exported alias of blockBackend — lets
// external packages satisfy the interface and pass instances to
// OpenFromDevice / OpenFromDeviceDataset.
type BlockBackend = blockBackend

// osFileBackend wraps an *os.File so the read+write+grow paths
// can talk to a plain disk file through the blockBackend
// interface. Open / OpenDataset use this; layered callers
// (LUKS, qcow2, …) supply their own implementations.
type osFileBackend struct{ f *os.File }

func (o *osFileBackend) ReadAt(p []byte, off int64) (int, error)  { return o.f.ReadAt(p, off) }
func (o *osFileBackend) WriteAt(p []byte, off int64) (int, error) { return o.f.WriteAt(p, off) }
func (o *osFileBackend) Sync() error                              { return o.f.Sync() }
func (o *osFileBackend) Truncate(size int64) error                { return o.f.Truncate(size) }
func (o *osFileBackend) Close() error                             { return o.f.Close() }
func (o *osFileBackend) Size() (int64, error) {
	fi, err := o.f.Stat()
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// Verify implementation of the common filesystem interface + every
// capability interface zfsFS supports.
var (
	_ filesystem.Filesystem = (*zfsFS)(nil)
	_ filesystem.Grower     = (*zfsFS)(nil)
	_ filesystem.Resizer    = (*zfsFS)(nil)
)

var (
	openFile            = os.OpenFile
	openPartitionOffset = partitionOffset
	openReadInfo        = readInfo
)

// FS is the public interface returned by Open. Extends
// filesystem.Filesystem with ZFS-specific operations (Info,
// PartitionOffset, GrowTo / Grow / Resize).
//
// GrowTo, Grow and Resize all map to the same on-disk operation; the
// three spellings exist so callers using the historical Grower
// interface, the newer filesystem.Resizer, or the bare verb all reach
// the same code path. Resize is the only entry point that returns
// filesystem.ErrShrinkUnsupported for shrink attempts — Grow / GrowTo
// reject shrink with a wrapped error too, so errors.Is is reliable in
// either direction.
type FS interface {
	filesystem.Filesystem
	Info() Info
	PartitionOffset() int64
	GrowTo(newSizeBytes int64) error
	Grow(newSizeBytes int64) error
	Resize(newSize int64) error
}

// Open opens imagePath, optionally selecting a partition, and scans for the freshest uberblock.
// If the pool contains a valid ZPL object set it is opened; otherwise only uberblock metadata
// is available and read/write operations will return errors.
func Open(imagePath string, partIndex int) (FS, error) {
	return openInternal(imagePath, partIndex, "")
}

// OpenDataset is like Open but navigates to a NESTED dataset rather
// than the pool's root DSL dir. datasetPath is the dataset name
// minus the pool prefix — e.g. for "rpool/ROOT/pve-1", pass
// "ROOT/pve-1". The pool prefix is implicit (every pool has
// exactly one root_dataset and we always start there).
//
// Use case: chaining into a Proxmox VE or Ubuntu Server ZSYS
// install whose / lives on a non-root dataset. The pool root
// itself is typically empty in those layouts; the bootloader
// needs the leaf dataset's filesystem to find /boot/vmlinuz.
//
// datasetPath="" is equivalent to Open() — the pool root dataset
// is opened.
func OpenDataset(imagePath string, partIndex int, datasetPath string) (FS, error) {
	return openInternal(imagePath, partIndex, datasetPath)
}

// OpenFromDevice opens a ZFS pool backed by an arbitrary
// blockBackend (LUKS plaintext, qcow2 unpacked view, in-memory
// fixture, …) and lands on the pool's root dataset.
//
// partIndex is honoured the same way as Open: -1 for whole-image
// mode, >= 0 to select a partition from a GPT/MBR-partitioned
// backing store.
func OpenFromDevice(dev BlockBackend, partIndex int) (FS, error) {
	return openFromDevice(dev, partIndex, "")
}

// OpenFromDeviceDataset is OpenFromDevice + dataset navigation.
// Use to open "<pool>/<dataset>/<…>" against a layered block
// source; datasetPath has the same semantics as OpenDataset
// (pool name implicit, "" for the pool root).
func OpenFromDeviceDataset(dev BlockBackend, partIndex int, datasetPath string) (FS, error) {
	return openFromDevice(dev, partIndex, datasetPath)
}

// OpenFromDevices opens a multi-vdev pool. The first device is the
// "primary" — its label 0 is read to discover the vdev tree
// (mirror / raidz / disk) and the GUIDs of every leaf in declaration
// order. `devs` must contain one backend per leaf, in the SAME id
// order as the on-disk vdev_tree.children array (= zpool-create
// argument order). Mismatches are detected via dev_item.guid check.
//
// For a SINGLE-vdev pool the slice has 1 element and the call is
// equivalent to OpenFromDeviceDataset. For mirror / raidz the
// additional legs are required: mirror uses any leg, raidz needs
// ALL data legs present for healthy reads (one missing leg falls
// back to the parity reconstruction path, which is not yet
// implemented — see memory:userland-fs-drivers).
func OpenFromDevices(devs []BlockBackend, partIndex int, datasetPath string) (FS, error) {
	if len(devs) == 0 {
		return nil, fmt.Errorf("zfs: OpenFromDevices: empty device slice")
	}
	primary := devs[0]
	off, err := openPartitionOffset(primary, partIndex)
	if err != nil {
		for _, d := range devs {
			d.Close()
		}
		return nil, err
	}
	tree, err := readVdevTree(primary, off)
	if err != nil {
		for _, d := range devs {
			d.Close()
		}
		return nil, fmt.Errorf("zfs: vdev tree: %w", err)
	}
	leafGUIDs := tree.leafGUIDs()
	if len(devs) != len(leafGUIDs) {
		for _, d := range devs {
			d.Close()
		}
		return nil, fmt.Errorf("zfs: device count %d != vdev leaf count %d (pool has %s vdev with %d leaves)",
			len(devs), len(leafGUIDs), tree.typ, len(leafGUIDs))
	}

	// Build the multi-vdev pool that routes reads per topology.
	pool := newMultiVdevPool(primary, devs, tree, off)

	info, err := openReadInfo(pool, off)
	if err != nil {
		pool.Close()
		return nil, err
	}
	fs := &zfsFS{f: pool, partOffset: off + vdevLabelStartSize, info: info, labelOffset: off}
	fs.curTxg = info.TransactionGroup

	rootBPBuf := make([]byte, blkptrSize)
	if _, e2 := pool.ReadAt(rootBPBuf, info.Offset+40); e2 == nil {
		rootBP := parseBlkptr(rootBPBuf)
		if !rootBP.isNull() {
			if ds, e3 := openNamedDataset(pool, fs.partOffset, rootBP, datasetPath); e3 == nil {
				fs.zplDS = ds
				if sz, e4 := pool.Size(); e4 == nil {
					fs.initAllocator(sz)
				}
			} else if datasetPath != "" {
				pool.Close()
				return nil, fmt.Errorf("zfs: open dataset %q: %w", datasetPath, e3)
			}
		}
	}
	return fs, nil
}

// openFromDevice is the shared implementation for the
// device-backed open paths. Mirrors openInternal but takes a
// pre-opened blockBackend rather than an imagePath.
func openFromDevice(dev BlockBackend, partIndex int, datasetPath string) (FS, error) {
	off, err := openPartitionOffset(dev, partIndex)
	if err != nil {
		dev.Close()
		return nil, err
	}
	info, err := openReadInfo(dev, off)
	if err != nil {
		dev.Close()
		return nil, err
	}
	// fs.partOffset stores the DATA AREA start (= raw partition start +
	// VDEV_LABEL_START_SIZE). DVA-based reads everywhere in the codebase
	// use this as the base; label/uberblock reads use info.Offset which
	// was computed pre-shift by openReadInfo and is still raw-partition-
	// relative.
	fs := &zfsFS{f: dev, partOffset: off + vdevLabelStartSize, info: info, labelOffset: off}
	fs.curTxg = info.TransactionGroup

	rootBPBuf := make([]byte, blkptrSize)
	if _, e2 := dev.ReadAt(rootBPBuf, info.Offset+40); e2 == nil {
		rootBP := parseBlkptr(rootBPBuf)
		if !rootBP.isNull() {
			if ds, e3 := openNamedDataset(dev, fs.partOffset, rootBP, datasetPath); e3 == nil {
				fs.zplDS = ds
				if sz, e4 := dev.Size(); e4 == nil {
					fs.initAllocator(sz)
				}
			} else if datasetPath != "" {
				dev.Close()
				return nil, fmt.Errorf("zfs: open dataset %q: %w", datasetPath, e3)
			}
		}
	}
	return fs, nil
}

func openInternal(imagePath string, partIndex int, datasetPath string) (FS, error) {
	f, err := openFile(imagePath, os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("zfs: open %s: %w", imagePath, err)
	}
	// Wrap the *os.File in the blockBackend interface so the rest
	// of the FS code (which now stores blockBackend, not *os.File)
	// can talk to it uniformly with layered backends like LUKS.
	return openFromDevice(&osFileBackend{f: f}, partIndex, datasetPath)
}

// Close releases the underlying file handle.
func (fs *zfsFS) Close() error { return fs.f.Close() }

// Info returns the decoded uberblock metadata.
func (fs *zfsFS) Info() Info { return fs.info }

// PartitionOffset returns the byte offset of the selected partition.
// PartitionOffset returns the raw byte offset of the partition (NOT
// the data area) within the underlying device. External callers care
// about where ZFS lives on the disk, not where DVAs are based —
// fs.partOffset internally is the data-area start (= raw + 4 MiB), so
// we expose the raw value via fs.labelOffset.
func (fs *zfsFS) PartitionOffset() int64 { return fs.labelOffset }

func readInfo(r io.ReaderAt, partOffset int64) (Info, error) {
	buf := make([]byte, uberblockSize)
	var best Info
	found := false

	for label := 0; label < 2; label++ {
		base := partOffset + int64(label)*vdevLabelSize + uberblockRegionOffset
		for slot := 0; slot < uberblockSlots; slot++ {
			off := base + int64(slot)*uberblockSize
			if _, err := r.ReadAt(buf, off); err != nil {
				break
			}
			info, err := parseUberblock(buf, off, label, slot)
			if err != nil {
				continue
			}
			if !found || info.TransactionGroup > best.TransactionGroup ||
				(info.TransactionGroup == best.TransactionGroup && info.RawTimestamp > best.RawTimestamp) {
				best = info
				found = true
			}
		}
	}

	if !found {
		return Info{}, fmt.Errorf("zfs: no valid uberblock found")
	}
	return best, nil
}

func parseUberblock(buf []byte, off int64, label int, slot int) (Info, error) {
	if len(buf) < 40 {
		return Info{}, fmt.Errorf("zfs: uberblock too short")
	}

	var order binary.ByteOrder
	endian := ""
	switch {
	case binary.LittleEndian.Uint64(buf[:8]) == uberblockMagic:
		order = binary.LittleEndian
		endian = "little"
	case binary.BigEndian.Uint64(buf[:8]) == uberblockMagic:
		order = binary.BigEndian
		endian = "big"
	default:
		return Info{}, fmt.Errorf("zfs: invalid uberblock magic")
	}

	rawTimestamp := order.Uint64(buf[32:40])
	return Info{
		Version:          order.Uint64(buf[8:16]),
		TransactionGroup: order.Uint64(buf[16:24]),
		GUIDSum:          order.Uint64(buf[24:32]),
		RawTimestamp:     rawTimestamp,
		Timestamp:        time.Unix(int64(rawTimestamp), 0).UTC(),
		Label:            label,
		Slot:             slot,
		Offset:           off,
		Endian:           endian,
	}, nil
}

func partitionOffset(r io.ReaderAt, partIndex int) (int64, error) {
	var sig [8]byte
	if _, err := r.ReadAt(sig[:], sectorSize); err == nil && string(sig[:]) == "EFI PART" {
		return gptPartOffset(r, partIndex)
	}

	var magic [2]byte
	if _, err := r.ReadAt(magic[:], 510); err == nil && magic[0] == 0x55 && magic[1] == 0xAA {
		return mbrPartOffset(r, partIndex)
	}

	return 0, nil
}

func gptPartOffset(r io.ReaderAt, partIndex int) (int64, error) {
	hdr := make([]byte, 92)
	if _, err := r.ReadAt(hdr, sectorSize); err != nil {
		return 0, fmt.Errorf("zfs: read GPT header: %w", err)
	}
	le := binary.LittleEndian
	partEntryLBA := le.Uint64(hdr[72:])
	numParts := le.Uint32(hdr[80:])
	entrySize := le.Uint32(hdr[84:])
	if entrySize < 128 {
		return 0, fmt.Errorf("zfs: unexpected GPT entry size %d", entrySize)
	}

	tableOff := int64(partEntryLBA) * sectorSize
	buf := make([]byte, entrySize)
	for index := uint32(0); index < numParts; index++ {
		if _, err := r.ReadAt(buf, tableOff+int64(index)*int64(entrySize)); err != nil {
			break
		}
		var typeGUID [16]byte
		copy(typeGUID[:], buf[:16])
		startLBA := le.Uint64(buf[32:])

		if partIndex >= 0 {
			if int(index) != partIndex {
				continue
			}
			if typeGUID == [16]byte{} || startLBA == 0 {
				return 0, fmt.Errorf("zfs: GPT partition index %d not found", partIndex)
			}
			return int64(startLBA) * sectorSize, nil
		}

		if typeGUID != [16]byte{} && startLBA != 0 {
			return int64(startLBA) * sectorSize, nil
		}
	}

	if partIndex >= 0 {
		return 0, fmt.Errorf("zfs: GPT partition index %d not found", partIndex)
	}
	return 0, fmt.Errorf("zfs: no populated GPT partition found")
}

func mbrPartOffset(r io.ReaderAt, partIndex int) (int64, error) {
	table := make([]byte, 64)
	if _, err := r.ReadAt(table, 446); err != nil {
		return 0, fmt.Errorf("zfs: read MBR partition table: %w", err)
	}
	for index := 0; index < 4; index++ {
		entry := table[index*16:]
		startLBA := binary.LittleEndian.Uint32(entry[8:])

		if partIndex >= 0 {
			if index != partIndex {
				continue
			}
			if startLBA == 0 {
				return 0, fmt.Errorf("zfs: MBR partition index %d not found", partIndex)
			}
			return int64(startLBA) * sectorSize, nil
		}

		if startLBA != 0 {
			return int64(startLBA) * sectorSize, nil
		}
	}

	if partIndex >= 0 {
		return 0, fmt.Errorf("zfs: MBR partition index %d not found", partIndex)
	}
	return 0, nil
}
