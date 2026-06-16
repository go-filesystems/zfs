package filesystem_zfs

import (
	"fmt"
	"time"

	filesystem "github.com/go-filesystems/interface"
)

// GrowTo expands the pool image to newSizeBytes, rewrites vdev labels and
// commits an uberblock. Shrinking is not supported.
//
// ZFS pool-grow semantics mirror OpenZFS's `zpool online -e` /
// `autoexpand=on` behaviour for a single-vdev pool: the four leaf vdev
// labels (L0, L1 at the start; L2, L3 at the end) are re-emitted with
// the new asize in the label config nvlist, then a new uberblock is
// committed to the ring so the on-disk state advertises the larger
// capacity. The bump-pointer allocator's upper bound is widened so
// subsequent writes can populate the new tail of the image.
//
// What this does NOT do (intentionally — these are no-ops in our
// writer's mode and pose no risk on grow):
//
//   - Touch metaslabs: the writer's bump-pointer allocator does not yet
//     consume metaslab arrays, so there is no metaslab_array accounting
//     to grow. When a future change wires up real metaslabs, this is
//     the place that will need to extend their coverage.
//   - Update ub_rootbp accounting: rootbp points at the MOS objset, an
//     unchanged 4 KiB block in the data area; grow does not move or
//     resize it.
//
// Concurrency: grow takes the per-FS mutex (same lock that gates every
// other writer), so an in-flight WriteFile / DeleteFile / Rename
// blocks grow and vice versa.
func (fs *zfsFS) GrowTo(newSizeBytes int64) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.growLocked(newSizeBytes)
}

// Grow is the spelling required by the filesystem.Resizer-adjacent
// grow API. It is a thin alias of GrowTo so callers that already
// branch on Resize / Grow / GrowTo all reach the same code path.
func (fs *zfsFS) Grow(newSizeBytes int64) error { return fs.GrowTo(newSizeBytes) }

// Resize routes to Grow when newSize > current size, is a no-op when
// equal, and dispatches to Shrink (in Auto mode) when newSize <
// current size. The shrink path is now implemented end-to-end in
// resize.go — see ShrinkMode and ShrinkWithMode for the mode contract.
// OpenZFS itself does not support pool shrink (vdev_removal builds a
// permanent indirect-mapping table that adds per-pool overhead
// forever), but our writer has no such constraint, so Resize is
// genuinely bidirectional.
func (fs *zfsFS) Resize(newSize int64) error {
	return fs.resizeOnce(newSize)
}

// growLocked is the lock-already-held implementation shared by GrowTo
// and by future callers that need to compose grow with other label /
// uberblock work without re-entering the FS mutex.
func (fs *zfsFS) growLocked(newSizeBytes int64) error {
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
		return fmt.Errorf("zfs: grow: cannot shrink from %d to %d: %w",
			curSize, newSizeBytes, filesystem.ErrShrinkUnsupported)
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
	for _, off := range labelOffsets {
		// Each label's self-checksums are seeded with that label's own
		// absolute offset, so rebuild per offset rather than reusing one
		// buffer across all four.
		label := buildLabel(nvBuf, ub, off, fs.curTxg)
		if _, err := fs.f.WriteAt(label, off); err != nil {
			return fmt.Errorf("zfs: grow: write label at %d: %w", off, err)
		}
	}
	if err := fs.f.Sync(); err != nil {
		return fmt.Errorf("zfs: grow: sync: %w", err)
	}

	// Extend the allocator's upper bound without resetting the
	// bump-pointer. initAllocator would walk every dnode again and
	// rebuild allocator state from scratch — that is correct on Open
	// but on grow we want to PRESERVE the in-memory free list and the
	// current bump-pointer, only widening the limit so newly-grown
	// space becomes available. Falls back to a full re-init if the
	// allocator hasn't been wired up yet (e.g. label-only image).
	newLimit := newSizeBytes - 2*vdevLabelSize
	if fs.alloc != nil {
		fs.alloc.mu.Lock()
		if newLimit > fs.alloc.limitOff {
			fs.alloc.limitOff = newLimit
		}
		fs.alloc.mu.Unlock()
	} else {
		fs.initAllocator(newSizeBytes)
	}

	// Rewriting the four labels above clears every uberblock ring slot
	// except the active one (buildLabel emits a fresh, mostly-zero
	// label that populates only slot txg%nslots with a valid rootbp).
	// The cached fs.info.Offset may now point at a wiped slot, so re-
	// read the freshest uberblock BEFORE commitUberblock — otherwise
	// commitUberblock would read a NULL rootbp from the stale offset.
	info, err := openReadInfo(fs.f, fs.labelOffset)
	if err != nil {
		return fmt.Errorf("zfs: grow: refresh uberblock info: %w", err)
	}
	fs.info = info

	if err := fs.commitUberblock(); err != nil {
		return fmt.Errorf("zfs: grow: commit uberblock: %w", err)
	}
	return nil
}
