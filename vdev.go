package filesystem_zfs

// vdev.go — vdev tree types and routing for multi-vdev pools
// (mirror / RAID-Z1/Z2/Z3). The tree is parsed from the NVList
// stored in each leaf's vdev label (vdev_tree key); a multi-vdev
// pool's root vdev is non-leaf (type=mirror or raidz), with leaf
// children pointing at backing devices.
//
// Backed READS go through devicePool.ReadAt, which:
//   - For mirror: tries each leg in turn (data is identical)
//   - For raidz: computes per-IO (child, offset, size) via the
//     raidz_map_alloc-equivalent in raidz.go and reads only the
//     data columns (parity is healthy-skipped)
//
// Writes are not supported on multi-vdev opens — cloud-boot opens
// FS images read-only.

import (
	"fmt"
	"io"
)

// vdevType is the string in the vdev_tree.type nvpair.
type vdevType string

const (
	vdevTypeFile      vdevType = "file"
	vdevTypeDisk      vdevType = "disk"
	vdevTypeMirror    vdevType = "mirror"
	vdevTypeRAIDZ     vdevType = "raidz"
	vdevTypeReplacing vdevType = "replacing"
	vdevTypeIndirect  vdevType = "indirect"
	vdevTypeRoot      vdevType = "root"
)

// vdev is one node in the parsed vdev tree.
type vdev struct {
	typ      vdevType
	id       uint64
	guid     uint64
	ashift   uint64
	nparity  uint64 // raidz1/2/3
	path     string // leaf "file" / "disk" only
	children []*vdev
}

// isLeaf returns true for "file" / "disk" leaf vdevs.
func (v *vdev) isLeaf() bool { return v.typ == vdevTypeFile || v.typ == vdevTypeDisk }

// dataChildren returns just the leaf vdevs holding data (skips spares,
// caches, etc. — but those aren't in this tree's vdev_tree).
func (v *vdev) leafGUIDs() []uint64 {
	var out []uint64
	var walk func(*vdev)
	walk = func(n *vdev) {
		if n.isLeaf() {
			out = append(out, n.guid)
			return
		}
		for _, c := range n.children {
			walk(c)
		}
	}
	walk(v)
	return out
}

// parseVdevTree decodes a vdev_tree NVList into a vdev tree.
func parseVdevTree(nv parsedNVList) (*vdev, error) {
	v := &vdev{}
	if p := nv.findByName("type"); p != nil {
		if s, err := p.stringValue(); err == nil {
			v.typ = vdevType(s)
		}
	}
	for _, p := range nv {
		switch p.name {
		case "id":
			v.id, _ = p.uint64Value()
		case "guid":
			v.guid, _ = p.uint64Value()
		case "ashift":
			v.ashift, _ = p.uint64Value()
		case "nparity":
			v.nparity, _ = p.uint64Value()
		case "path":
			v.path, _ = p.stringValue()
		case "children":
			kids, err := p.nvlistArrayValue()
			if err != nil {
				return nil, fmt.Errorf("vdev children: %w", err)
			}
			v.children = make([]*vdev, 0, len(kids))
			for i, k := range kids {
				c, err := parseVdevTree(k)
				if err != nil {
					return nil, fmt.Errorf("vdev child %d: %w", i, err)
				}
				v.children = append(v.children, c)
			}
		}
	}
	return v, nil
}

// readVdevTree reads label 0 from `r` (already positioned at the
// partition start) and returns the parsed vdev_tree.
func readVdevTree(r io.ReaderAt, partOff int64) (*vdev, error) {
	// NVList region: label_start + 0x4000 .. + 0x20000 (112 KiB).
	buf := make([]byte, 112*1024)
	if _, err := r.ReadAt(buf, partOff+0x4000); err != nil {
		return nil, fmt.Errorf("read label0 nv: %w", err)
	}
	top, err := decodeNVList(buf)
	if err != nil {
		return nil, fmt.Errorf("decode label nv: %w", err)
	}
	vp := top.findByName("vdev_tree")
	if vp == nil {
		return nil, fmt.Errorf("label has no vdev_tree")
	}
	tree, err := vp.nvlistValue()
	if err != nil {
		return nil, fmt.Errorf("vdev_tree nvlist: %w", err)
	}
	return parseVdevTree(tree)
}
