package filesystem_zfs

import (
	"fmt"
	"time"
)

// GrowTo expands the pool image to newSizeBytes, rewrites vdev labels and
// commits an uberblock. Shrinking is not supported.
func (fs *zfsFS) GrowTo(newSizeBytes int64) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if newSizeBytes <= 0 {
		return fmt.Errorf("zfs: grow: invalid size %d", newSizeBytes)
	}

	curSize, err := fs.f.Size()
	if err != nil {
		return fmt.Errorf("zfs: grow: size: %w", err)
	}
	if newSizeBytes == curSize {
		return nil
	}
	if newSizeBytes < curSize {
		return fmt.Errorf("zfs: shrinking filesystem not supported")
	}

	const minSize = 4 * 1024 * 1024
	if newSizeBytes < minSize {
		return fmt.Errorf("zfs: grow: size %d below minimum %d bytes", newSizeBytes, minSize)
	}

	if err := fs.f.Truncate(newSizeBytes); err != nil {
		return fmt.Errorf("zfs: grow: truncate: %w", err)
	}

	// Best-effort: derive pool GUID from the opened uberblock. Use a
	// default pool name when not readily available.
	poolGUID := fs.info.GUIDSum
	poolName := "data"

	now := uint64(time.Now().Unix())
	nvBuf := buildLabelNVList(poolName, poolGUID, poolGUID, uint64(newSizeBytes), now)

	// Re-derive rootBP for embedding into the label's uberblock slot.
	rootBPBuf := make([]byte, blkptrSize)
	if _, err := fs.f.ReadAt(rootBPBuf, fs.info.Offset+40); err != nil {
		return fmt.Errorf("zfs: grow: read rootbp: %w", err)
	}
	rootBP := parseBlkptr(rootBPBuf)
	ub := encodeUberblock(fs.info.Version, fs.curTxg, fs.info.GUIDSum, now, rootBP)

	// Write the four vdev labels at the canonical offsets.
	labelOffsets := []int64{
		fs.labelOffset + 0*vdevLabelSize,
		fs.labelOffset + vdevLabelSize,
		fs.labelOffset + newSizeBytes - 2*vdevLabelSize,
		fs.labelOffset + newSizeBytes - vdevLabelSize,
	}
	label := buildLabel(nvBuf, ub)
	for _, off := range labelOffsets {
		if _, err := fs.f.WriteAt(label, off); err != nil {
			return fmt.Errorf("zfs: grow: write label at %d: %w", off, err)
		}
	}
	if err := fs.f.Sync(); err != nil {
		return fmt.Errorf("zfs: grow: sync: %w", err)
	}

	// Update allocator limit and commit an uberblock to record the change.
	fs.initAllocator(newSizeBytes)
	if err := fs.commitUberblock(); err != nil {
		return fmt.Errorf("zfs: grow: commit uberblock: %w", err)
	}
	return nil
}
