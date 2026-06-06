package filesystem_zfs

// dsl.go – ZFS DSL (Dataset and Snapshot Layer) traversal.
//
// Navigation path from uberblock to ZPL filesystem:
//   uberblock.rootbp
//     → MOS object set (type DMU_OST_META)
//       object 1 = pool directory ZAP
//         "root_dataset" → DSL dir object num
//           dsl_dir_phys_t bonus: dd_head_dataset_obj → DSL dataset object num
//             dsl_dataset_phys_t bonus: ds_bp → ZPL object set BP
//
// ZPL object set:
//   object 1 = master node ZAP (has "ROOT" → root dir object num)
//   SA master node object (type=45) somewhere nearby
//   root dir object = ZAP of directory entries

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// Fixed object numbers in the MOS
	mosPoolDirObj = 1 // DMU_POOL_DIRECTORY_OBJECT = 1

	// Keys in the pool directory ZAP
	dmuPoolRootDataset = "root_dataset"

	// dsl_dir_phys_t field offsets in bonus (uint64 LE, dnode has bonustype=DMU_OT_DSL_DIR)
	ddCreationTime      = 0  // uint64
	ddHeadDatasetObj    = 8  // uint64 – points to the DSL dataset
	ddParentObj         = 16 // uint64
	ddCloneParentObj    = 24 // uint64
	ddChildDirZAPObj    = 32 // uint64
	ddUsedBytes         = 40 // uint64
	ddCompressedBytes   = 48 // uint64
	ddUncompressedBytes = 56 // uint64

	// dsl_dataset_phys_t field offsets in bonus (bonustype=DMU_OT_DSL_DATASET)
	dsDirObj            = 0   // uint64
	dsPrevSnapObj       = 8   // uint64
	dsPrevSnapTxg       = 16  // uint64
	dsNextSnapObj       = 24  // uint64
	dsSnapnamesZAPObj   = 32  // uint64
	dsNumChildren       = 40  // uint64
	dsCreationTime      = 48  // uint64
	dsCreationTxg       = 56  // uint64
	dsDeadlistObj       = 64  // uint64
	dsUsedBytes         = 72  // uint64
	dsCompressedBytes   = 80  // uint64
	dsUncompressedBytes = 88  // uint64
	dsUniqueBytes       = 96  // uint64
	dsFsidGUID          = 104 // uint64
	dsGUID              = 112 // uint64
	dsFlags             = 120 // uint64
	dsBP                = 128 // blkptr_t (128 bytes) = the ZPL object set block pointer

	// ZPL master node keys
	zplKeyRoot    = "ROOT"
	zplKeyVersion = "VERSION"

	// Fixed object numbers in ZPL object set
	zplMasterNodeObjNum = 1
)

// zplDataset holds the resolved ZPL layer for a dataset.
type zplDataset struct {
	mos        *objset  // MOS object set
	zplOS      *objset  // ZPL object set
	rootObjNum uint64   // root directory object number in zplOS
	saLayout   []uint16 // SA attribute layout to use
}

// openRootDataset navigates from the MOS to the root ZPL dataset.
//
// Equivalent to openNamedDataset(r, partOff, rootBP, "") — kept as a
// thin wrapper for backward compatibility.
func openRootDataset(r io.ReaderAt, partOff int64, rootBP blkptr) (*zplDataset, error) {
	return openNamedDataset(r, partOff, rootBP, "")
}

// openNamedDataset navigates from the MOS to a NAMED ZPL dataset,
// walking the DSL child-directory chain to reach a non-root dataset
// such as "ROOT/pve-1" inside a Proxmox-style pool. childPath is
// a "/"-separated path relative to the pool's root DSL dir. An
// empty childPath is equivalent to openRootDataset.
//
// Why we needed this. The cloud-boot bootloader chains into an
// existing distro install (Proxmox VE / Ubuntu Server ZSYS) whose
// kernel + initrd live inside a NESTED ZFS dataset:
//
//	rpool                  ← pool root DSL dir (no FS content)
//	    ROOT               ← child DSL dir (no FS content)
//	        pve-1          ← leaf DSL dataset with the real /
//
// Walking only to the pool root (the existing openRootDataset
// path) lands us on an empty filesystem and the bootloader can't
// find /boot/vmlinuz. With childPath="ROOT/pve-1" we descend two
// levels via each DSL dir's ddChildDirZAPObj and open the leaf
// dataset's ZPL.
func openNamedDataset(r io.ReaderAt, partOff int64, rootBP blkptr, childPath string) (*zplDataset, error) {
	// Step 1: Open the MOS
	mos, err := openObjset(r, partOff, rootBP)
	if err != nil {
		return nil, fmt.Errorf("zfs: open MOS: %w", err)
	}
	if mos.osType != dmuOSTMeta {
		return nil, fmt.Errorf("zfs: MOS has unexpected type %d", mos.osType)
	}

	// Step 2: Read pool directory ZAP (object 1) for the root DSL
	// dir's object number.
	poolDirDN, err := mos.readObject(mosPoolDirObj)
	if err != nil {
		return nil, fmt.Errorf("zfs: read pool dir object: %w", err)
	}
	poolDirEntries, err := zapListAll(r, partOff, poolDirDN)
	if err != nil {
		return nil, fmt.Errorf("zfs: pool dir ZAP: %w", err)
	}
	currentDirObjNum, ok := poolDirEntries[dmuPoolRootDataset]
	if !ok {
		return nil, fmt.Errorf("zfs: pool dir missing 'root_dataset' key")
	}

	// Step 2.5: Walk the child-dir chain to the requested dataset.
	// childPath="ROOT/pve-1" iterates {"ROOT", "pve-1"} and at each
	// step reads the current DSL dir's ddChildDirZAPObj to find the
	// child by name. childPath="" is a zero-iteration loop and we
	// stay on the pool root DSL dir, preserving the legacy
	// openRootDataset contract.
	for _, segment := range splitPath(childPath) {
		// Read current DSL dir's bonus to get its ddChildDirZAPObj.
		dslDirDN, err := mos.readObject(currentDirObjNum)
		if err != nil {
			return nil, fmt.Errorf("zfs: read DSL dir %d on the way to %q: %w", currentDirObjNum, childPath, err)
		}
		bonus := dslDirDN.bonusData()
		if len(bonus) < ddChildDirZAPObj+8 {
			return nil, fmt.Errorf("zfs: DSL dir %d bonus too short for childDirZAP", currentDirObjNum)
		}
		childZAPObj := binary.LittleEndian.Uint64(bonus[ddChildDirZAPObj:])
		if childZAPObj == 0 {
			return nil, fmt.Errorf("zfs: DSL dir %d has no children, cannot resolve %q in %q", currentDirObjNum, segment, childPath)
		}
		// Read the children ZAP and look up the segment.
		childDN, err := mos.readObject(childZAPObj)
		if err != nil {
			return nil, fmt.Errorf("zfs: read child-dir ZAP %d: %w", childZAPObj, err)
		}
		children, err := zapListAll(r, partOff, childDN)
		if err != nil {
			return nil, fmt.Errorf("zfs: parse child-dir ZAP %d: %w", childZAPObj, err)
		}
		next, ok := children[segment]
		if !ok {
			return nil, fmt.Errorf("zfs: dataset segment %q not found under DSL dir %d (have: %v)", segment, currentDirObjNum, childKeys(children))
		}
		currentDirObjNum = next
	}

	// Step 3: Read DSL dir object to get head dataset object num
	dslDirDN, err := mos.readObject(currentDirObjNum)
	if err != nil {
		return nil, fmt.Errorf("zfs: read DSL dir: %w", err)
	}
	dslDirBonus := dslDirDN.bonusData()
	if len(dslDirBonus) < ddHeadDatasetObj+8 {
		return nil, fmt.Errorf("zfs: DSL dir bonus too short")
	}
	headDatasetObjNum := binary.LittleEndian.Uint64(dslDirBonus[ddHeadDatasetObj:])
	if headDatasetObjNum == 0 {
		return nil, fmt.Errorf("zfs: DSL dir has no head dataset")
	}

	// Step 4: Read DSL dataset object to get ZPL objset BP
	dslDatasetDN, err := mos.readObject(headDatasetObjNum)
	if err != nil {
		return nil, fmt.Errorf("zfs: read DSL dataset: %w", err)
	}
	dslDSBonus := dslDatasetDN.bonusData()
	if len(dslDSBonus) < dsBP+blkptrSize {
		return nil, fmt.Errorf("zfs: DSL dataset bonus too short")
	}
	zplBP := parseBlkptr(dslDSBonus[dsBP : dsBP+blkptrSize])
	if zplBP.isNull() {
		return nil, fmt.Errorf("zfs: DSL dataset has null ZPL BP")
	}

	// Step 5: Open ZPL object set
	zplOS, err := openObjset(r, partOff, zplBP)
	if err != nil {
		return nil, fmt.Errorf("zfs: open ZPL objset: %w", err)
	}

	// Step 6: Read master node ZAP (object 1) to find root dir
	masterNodeDN, err := zplOS.readObject(zplMasterNodeObjNum)
	if err != nil {
		return nil, fmt.Errorf("zfs: read ZPL master node: %w", err)
	}
	masterEntries, err := zapListAll(r, partOff, masterNodeDN)
	if err != nil {
		return nil, fmt.Errorf("zfs: ZPL master node ZAP: %w", err)
	}
	rootObjNum, ok := masterEntries[zplKeyRoot]
	if !ok {
		return nil, fmt.Errorf("zfs: ZPL master node missing 'ROOT' key")
	}

	// Use default SA layout (our Format() hardcodes layout 0)
	saLayout := defaultSALayout()

	return &zplDataset{
		mos:        mos,
		zplOS:      zplOS,
		rootObjNum: rootObjNum,
		saLayout:   saLayout,
	}, nil
}

// readDirEntries returns the object number → name mapping for a directory.
func (ds *zplDataset) readDirEntries(r io.ReaderAt, partOff int64, dirObjNum uint64) (map[string]uint64, error) {
	dirDN, err := ds.zplOS.readObject(dirObjNum)
	if err != nil {
		return nil, fmt.Errorf("zfs: read dir dnode %d: %w", dirObjNum, err)
	}
	if dirDN.typ != dmotDirContents {
		return nil, fmt.Errorf("zfs: object %d is not a directory (type %d)", dirObjNum, dirDN.typ)
	}
	return zapListAll(r, partOff, dirDN)
}

// lookupEntry looks up one path component within directory dirObjNum.
// Returns child object number.
func (ds *zplDataset) lookupEntry(r io.ReaderAt, partOff int64, dirObjNum uint64, name string) (uint64, error) {
	entries, err := ds.readDirEntries(r, partOff, dirObjNum)
	if err != nil {
		return 0, err
	}
	objNum, ok := entries[name]
	if !ok {
		return 0, fmt.Errorf("zfs: %q not found: %w", name, errNotFound)
	}
	// In ZFS, the directory ZAP stores (lower 48 bits = object num, upper 16 = ftype).
	return objNum & 0x0000FFFFFFFFFFFF, nil
}

// lookupPath resolves an absolute path to its object number in the ZPL object set.
func (ds *zplDataset) lookupPath(r io.ReaderAt, partOff int64, path string) (uint64, error) {
	path = cleanPath(path)
	if path == "/" {
		return ds.rootObjNum, nil
	}
	parts := splitPath(path)
	cur := ds.rootObjNum
	for _, part := range parts {
		next, err := ds.lookupEntry(r, partOff, cur, part)
		if err != nil {
			return 0, fmt.Errorf("zfs: lookup %q: %w", path, err)
		}
		cur = next
	}
	return cur, nil
}

// childKeys returns the keys of a children ZAP map in a stable
// order, for inclusion in "dataset not found" error messages so
// the operator can see what siblings actually exist.
func childKeys(m map[string]uint64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// readAttrs reads SA attributes from an object.
func (ds *zplDataset) readAttrs(objNum uint64) (*saAttrs, error) {
	dn, err := ds.zplOS.readObject(objNum)
	if err != nil {
		return nil, err
	}
	return parseDnodeSA(dn, ds.saLayout)
}
