package filesystem_zfs

// probe.go — public helpers for label-only discovery (no FS open).
// Used by cloud-boot-init's findZFSVdevs to group attached devices
// by pool and assemble the correct leaf-id ordering before calling
// OpenFromDevices.

import (
	"fmt"
	"io"
)

// LabelInfo is the subset of a vdev label's top-level NVList that
// cloud-boot needs to assemble a multi-vdev pool: pool identity,
// this-leaf identity, top-vdev topology, and the leaf-guid list of
// the top vdev's children in vdev-id order.
type LabelInfo struct {
	PoolName     string
	PoolGUID     uint64
	TopGUID      uint64 // GUID of the top-level vdev (mirror/raidz parent)
	ThisGUID     uint64 // GUID of THIS device (this leaf)
	VdevChildren uint64 // number of top-level vdevs in the pool
	Type         string // "file"/"disk" for single-vdev, "mirror"/"raidz"/... for multi-vdev
	NParity      uint64 // raidz nparity (0 for non-raidz)
	Ashift       uint64
	// LeafGUIDs is the ordered list of guids from vdev_tree.children
	// (matching vdev id order, which is the order OpenFromDevices
	// requires for its devs slice). For single-vdev pools the slice
	// is empty (the pool root IS a leaf).
	LeafGUIDs []uint64
}

// ProbeLabel reads label 0 from `r` (positioned at partition start)
// and decodes the subset of fields LabelInfo describes. No data
// blocks are read; this is purely a label/NVList parse and is safe
// to call against random devices (returns an error for non-ZFS
// media without side effects).
func ProbeLabel(r io.ReaderAt, partOff int64) (*LabelInfo, error) {
	buf := make([]byte, 112*1024)
	if _, err := r.ReadAt(buf, partOff+0x4000); err != nil {
		return nil, fmt.Errorf("probe label: read nv region: %w", err)
	}
	top, err := decodeNVList(buf)
	if err != nil {
		return nil, fmt.Errorf("probe label: decode nv: %w", err)
	}
	out := &LabelInfo{}
	if p := top.findByName("name"); p != nil {
		out.PoolName, _ = p.stringValue()
	}
	if p := top.findByName("pool_guid"); p != nil {
		out.PoolGUID, _ = p.uint64Value()
	}
	if p := top.findByName("guid"); p != nil {
		out.ThisGUID, _ = p.uint64Value()
	}
	if p := top.findByName("top_guid"); p != nil {
		out.TopGUID, _ = p.uint64Value()
	}
	if p := top.findByName("vdev_children"); p != nil {
		out.VdevChildren, _ = p.uint64Value()
	}
	vp := top.findByName("vdev_tree")
	if vp == nil {
		return nil, fmt.Errorf("probe label: no vdev_tree")
	}
	tree, err := parseVdevTree(mustNVListValue(vp))
	if err != nil {
		return nil, fmt.Errorf("probe label: vdev_tree: %w", err)
	}
	out.Type = string(tree.typ)
	out.NParity = tree.nparity
	out.Ashift = tree.ashift
	if !tree.isLeaf() {
		out.LeafGUIDs = make([]uint64, 0, len(tree.children))
		for _, c := range tree.children {
			out.LeafGUIDs = append(out.LeafGUIDs, c.guid)
		}
	}
	return out, nil
}

func mustNVListValue(p *parsedNVPair) parsedNVList {
	v, _ := p.nvlistValue()
	return v
}
