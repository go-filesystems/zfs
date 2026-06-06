package filesystem_zfs

// multidev.go — Multi-vdev block backend that intercepts ReadAt to
// route per the vdev tree topology. For mirror reads: serve from
// leg 0. For raidz reads: use raidz_map_alloc to compute (child,
// child_offset, child_size) per data column and concatenate.
//
// The pool exposes a single `blockBackend` to the rest of the lib so
// the existing read paths (readBlock / readDataBlock / etc.) work
// unchanged on top of it. The Open path is the one that has to know
// about multi-vdev: it reads label 0 of the primary device, parses
// the vdev_tree, opens all leaf children, and builds the pool.

import (
	"fmt"
	"io"
	"sync"
)

// multiVdevPool wraps a slice of leaf-vdev backends and implements
// blockBackend by routing each ReadAt through the vdev tree.
type multiVdevPool struct {
	primary  blockBackend  // for Sync/Size/Truncate/Close passthrough
	leaves   []blockBackend // ordered by vdev id
	tree     *vdev          // root of the vdev tree
	partOff  int64          // partition offset (raw, same on every leaf)

	mu sync.Mutex
}

func newMultiVdevPool(primary blockBackend, leaves []blockBackend, tree *vdev, partOff int64) *multiVdevPool {
	return &multiVdevPool{
		primary: primary,
		leaves:  leaves,
		tree:    tree,
		partOff: partOff,
	}
}

// Sync / Size / Truncate / Close delegate to the primary (leaf 0).
func (m *multiVdevPool) Sync() error            { return m.primary.Sync() }
func (m *multiVdevPool) Size() (int64, error)   { return m.primary.Size() }
func (m *multiVdevPool) Truncate(s int64) error { return m.primary.Truncate(s) }
func (m *multiVdevPool) Close() error {
	var firstErr error
	seen := make(map[blockBackend]struct{}, len(m.leaves))
	for _, b := range m.leaves {
		if _, dup := seen[b]; dup {
			continue
		}
		seen[b] = struct{}{}
		if err := b.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// WriteAt is not supported for multi-vdev pools (cloud-boot read-only).
func (m *multiVdevPool) WriteAt(p []byte, off int64) (int, error) {
	return 0, fmt.Errorf("zfs: multi-vdev pool is read-only")
}

// ReadAt routes the read based on the root vdev type. The offset is
// the partition-absolute byte offset; we subtract partOffset+vdev-
// label-start to derive the data-area offset, then route.
func (m *multiVdevPool) ReadAt(p []byte, off int64) (int, error) {
	dataAreaStart := m.partOff + vdevLabelStartSize
	if off < dataAreaStart {
		// Label / uberblock reads. Route to leaf 0 (label 0 has the
		// same on every mirror leg; for raidz we read labels from
		// leaf 0 of the data-bearing children too).
		return m.primary.ReadAt(p, off)
	}
	logical := off - dataAreaStart

	switch m.tree.typ {
	case vdevTypeMirror:
		// All legs hold identical data — serve from leaf 0 (with
		// fallback to other legs on read error).
		var lastErr error
		for _, leg := range m.leaves {
			n, err := leg.ReadAt(p, off)
			if err == nil {
				return n, nil
			}
			lastErr = err
		}
		return 0, lastErr
	case vdevTypeRAIDZ:
		nparity := int(m.tree.nparity)
		ashift := uint(m.tree.ashift)
		children := make([]io.ReaderAt, len(m.leaves))
		for i, leg := range m.leaves {
			children[i] = leg
		}
		// Convert dataArea offset for raidz_map: the children share
		// the same VDEV_LABEL_START_SIZE shift, so we pass it via
		// `dataArea` to raidzRead.
		out, err := raidzRead(children, dataAreaStart, logical, int64(len(p)), nparity, ashift)
		if err != nil {
			return 0, err
		}
		copy(p, out)
		return len(p), nil
	case vdevTypeFile, vdevTypeDisk:
		// Single-leaf root (single-vdev pool) — passthrough.
		return m.primary.ReadAt(p, off)
	default:
		return 0, fmt.Errorf("zfs: multi-vdev pool: unsupported root vdev type %q", m.tree.typ)
	}
}

// Compile-time check.
var _ blockBackend = (*multiVdevPool)(nil)
