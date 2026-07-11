package filesystem_zfs

// clone.go – ZFS CLONE creation, the `origin` property, and snapshot
// destruction with dependent-clone tracking, for pools created by Format().
//
// A clone is a WRITABLE dataset created from a snapshot. On disk (OpenZFS
// dsl_dataset_create_sync) a clone is:
//
//   - a NEW dsl_dir whose dd_origin_obj points at the origin snapshot's
//     dsl_dataset, plus its own (empty) child-dir map and props ZAP;
//   - a NEW dsl_dataset whose ds_prev_snap_obj / ds_prev_snap_txg reference
//     the origin snapshot, with its own snapnames ZAP and deadlist;
//   - registered by name under the parent DSL dir's child map, so the reader's
//     dataset-path navigation (OpenDataset "<clone>") reaches it;
//   - tracked on the origin snapshot via ds_next_clones_obj (a DMU_OT_DSL_CLONES
//     ZAP keyed by each clone dataset's object number) and ds_num_children, so
//     the snapshot cannot be destroyed while a clone depends on it.
//
// Where THIS driver differs from OpenZFS. Real ZFS clones are O(1): the clone
// SHARES every block with the origin snapshot and only copies-on-write the
// blocks it later modifies. This driver is NOT copy-on-write — its write path
// (fs.go) mutates blocks in place — so a clone that merely re-pointed at the
// snapshot's blocks would be clobbered by the first WriteFile, and would in
// turn corrupt the frozen snapshot. To keep both the clone writable AND the
// snapshot frozen without rewriting the driver to be CoW, the clone is created
// EAGERLY: the snapshot's ZPL object-set tree is deep-copied into fresh
// bump-allocated blocks (exactly as snapshot.go copies the live head), and the
// clone's ds_bp points at that independent copy. This is O(dataset size)
// rather than O(1), but the on-disk DSL *structures* (dd_origin_obj,
// ds_prev_snap_obj, ds_next_clones_obj) are faithful to OpenZFS; only the
// block-sharing optimisation is replaced by the driver's existing eager-copy
// invariant.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

// errHasClones is returned by DestroySnapshot when the snapshot still has
// dependent clones recorded in its ds_next_clones_obj ZAP.
var errHasClones = errors.New("snapshot has dependent clones")

// Clone creates a writable dataset named cloneName from the snapshot snapName
// of the pool's root dataset. After a successful Clone the new dataset is
// reachable through the driver's own reader via OpenDataset(image, part,
// cloneName) (or the device-backed equivalents) and is independently writable:
// writes to the clone do not affect the origin snapshot, and vice-versa.
//
// snapName must name an existing snapshot of the currently-open dataset.
// cloneName must be non-empty, must not contain '@' or '/', must not begin with
// '$' (reserved for the special $MOS/$FREE/$ORIGIN dirs), and must not collide
// with an existing child dataset.
func (fs *zfsFS) Clone(snapName, cloneName string) error {
	if fs.zplDS == nil {
		return fmt.Errorf("zfs: Clone: pool not fully opened")
	}
	if fs.alloc == nil {
		return fmt.Errorf("zfs: Clone: no allocator (read-only pool?)")
	}
	if snapName == "" || strings.ContainsAny(snapName, "@/") {
		return fmt.Errorf("zfs: Clone: invalid snapshot name %q", snapName)
	}
	if cloneName == "" || strings.ContainsAny(cloneName, "@/") || cloneName[0] == '$' {
		return fmt.Errorf("zfs: Clone: invalid clone name %q", cloneName)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.cloneFromSnapshot(snapName, cloneName)
}

// cloneFromSnapshot performs the actual clone. Caller holds fs.mu.
func (fs *zfsFS) cloneFromSnapshot(snapName, cloneName string) error {
	mos := fs.zplDS.mos
	le := binary.LittleEndian

	// 1. Resolve the pool root DSL dir, its head dataset, and its child map.
	rootDirObj, err := fs.headDSLDirObj()
	if err != nil {
		return err
	}
	rootDirDN, err := mos.readObject(rootDirObj)
	if err != nil {
		return fmt.Errorf("zfs: Clone: read root DSL dir: %w", err)
	}
	rootDirBonus := append([]byte(nil), rootDirDN.bonusData()...)
	if len(rootDirBonus) < ddChildDirZAPObj+8 {
		return fmt.Errorf("zfs: Clone: root DSL dir bonus too short")
	}
	headDSObj := le.Uint64(rootDirBonus[ddHeadDatasetObj:])
	if headDSObj == 0 {
		return fmt.Errorf("zfs: Clone: root DSL dir has no head dataset")
	}
	rootChildZAPObj := le.Uint64(rootDirBonus[ddChildDirZAPObj:])
	if rootChildZAPObj == 0 {
		return fmt.Errorf("zfs: Clone: root DSL dir has no child map")
	}

	// 2. Reject a clone name that collides with an existing child dataset.
	childDN, err := mos.readObject(rootChildZAPObj)
	if err != nil {
		return fmt.Errorf("zfs: Clone: read root child map: %w", err)
	}
	children, err := zapListAll(fs.f, fs.partOffset, childDN)
	if err != nil {
		return fmt.Errorf("zfs: Clone: list root child map: %w", err)
	}
	if _, dup := children[cloneName]; dup {
		return fmt.Errorf("zfs: Clone: dataset %q already exists", cloneName)
	}

	// 3. Resolve the origin snapshot dataset + its frozen ZPL objset BP.
	snapDSObj, err := resolveSnapshot(fs.f, fs.partOffset, mos, headDSObj, snapName)
	if err != nil {
		return err
	}
	snapDN, err := mos.readObject(snapDSObj)
	if err != nil {
		return fmt.Errorf("zfs: Clone: read origin snapshot: %w", err)
	}
	snapBonus := append([]byte(nil), snapDN.bonusData()...)
	if len(snapBonus) < dslDatasetPhysSize {
		return fmt.Errorf("zfs: Clone: origin snapshot bonus too short")
	}
	snapZPLBP := parseBlkptr(snapBonus[dsBP : dsBP+blkptrSize])
	if snapZPLBP.isNull() {
		return fmt.Errorf("zfs: Clone: origin snapshot has null ZPL BP")
	}
	snapCreationTxg := le.Uint64(snapBonus[dsCreationTxg:])

	now := uint64(time.Now().Unix())

	// 4. Deep-copy the snapshot's frozen ZPL objset into fresh blocks so the
	// clone is independently writable (see the file header for why an eager
	// copy replaces real ZFS's O(1) block-sharing in this non-CoW driver).
	cloneZPLBP, err := fs.copyObjsetTree(snapZPLBP)
	if err != nil {
		return fmt.Errorf("zfs: Clone: copy objset tree: %w", err)
	}

	// 5. Allocate the clone's MOS objects: its own deadlist, an (empty) child
	// map, an (empty) props ZAP, an (empty) snapnames ZAP, then the DSL dir and
	// DSL dataset dnodes themselves.
	cloneDLObj, err := fs.allocDeadlist()
	if err != nil {
		return fmt.Errorf("zfs: Clone: %w", err)
	}
	cloneChildZAPObj, err := fs.newEmptyMOSZAP(dmotDSLDirChildMap)
	if err != nil {
		return fmt.Errorf("zfs: Clone: child map: %w", err)
	}
	clonePropsZAPObj, err := fs.newEmptyMOSZAP(dmotDSLProps)
	if err != nil {
		return fmt.Errorf("zfs: Clone: props ZAP: %w", err)
	}
	cloneSnapNamesObj, err := fs.newEmptyMOSZAP(dmotDSLDSSnapMap)
	if err != nil {
		return fmt.Errorf("zfs: Clone: snapnames ZAP: %w", err)
	}
	cloneDirObj, err := fs.allocMOSObjectNum()
	if err != nil {
		return fmt.Errorf("zfs: Clone: alloc DSL dir obj: %w", err)
	}
	if err := fs.reserveMOSObject(cloneDirObj); err != nil {
		return fmt.Errorf("zfs: Clone: reserve DSL dir obj: %w", err)
	}
	cloneDSObj, err := fs.allocMOSObjectNum()
	if err != nil {
		return fmt.Errorf("zfs: Clone: alloc DSL dataset obj: %w", err)
	}
	if err := fs.reserveMOSObject(cloneDSObj); err != nil {
		return fmt.Errorf("zfs: Clone: reserve DSL dataset obj: %w", err)
	}

	// 6. Build the clone DSL dir. dd_origin_obj (== ddCloneParentObj) points at
	// the origin snapshot — this is what `zfs get origin` reports and what
	// dsl_dir_hold_obj follows to find the clone's parent snapshot.
	dirBonus := make([]byte, dslDirPhysSize)
	le.PutUint64(dirBonus[ddCreationTime:], now)
	le.PutUint64(dirBonus[ddHeadDatasetObj:], cloneDSObj)
	le.PutUint64(dirBonus[ddParentObj:], rootDirObj)
	le.PutUint64(dirBonus[ddCloneParentObj:], snapDSObj)
	le.PutUint64(dirBonus[ddChildDirZAPObj:], cloneChildZAPObj)
	le.PutUint64(dirBonus[ddPropsZAPObj:], clonePropsZAPObj)
	le.PutUint64(dirBonus[ddFlags:], dsFlagUsedBreakdown)
	dirDN := newDnode(dmotDSLDir, 1, dmotDSLDir, uint16(len(dirBonus)))
	copy(dirDN.raw[dnodeBonusOff(1):], dirBonus)
	dirDN.encode()
	if err := fs.writeMOSObject(cloneDirObj, dirDN); err != nil {
		return fmt.Errorf("zfs: Clone: write DSL dir dnode: %w", err)
	}

	// 7. Build the clone DSL dataset. ds_prev_snap_obj / ds_prev_snap_txg
	// reference the origin snapshot; ds_bp points at the private writable copy.
	dsBonus := make([]byte, dslDatasetPhysSize)
	le.PutUint64(dsBonus[dsDirObj:], cloneDirObj)
	le.PutUint64(dsBonus[dsPrevSnapObj:], snapDSObj)
	le.PutUint64(dsBonus[dsPrevSnapTxg:], snapCreationTxg)
	le.PutUint64(dsBonus[dsSnapnamesZAPObj:], cloneSnapNamesObj)
	le.PutUint64(dsBonus[dsCreationTime:], now)
	le.PutUint64(dsBonus[dsCreationTxg:], fs.curTxg)
	le.PutUint64(dsBonus[dsDeadlistObj:], cloneDLObj)
	// Carry the origin snapshot's space accounting; exact CoW-shared unique
	// bytes are not meaningful in this eager-copy driver.
	le.PutUint64(dsBonus[dsUsedBytes:], le.Uint64(snapBonus[dsUsedBytes:]))
	le.PutUint64(dsBonus[dsCompressedBytes:], le.Uint64(snapBonus[dsCompressedBytes:]))
	le.PutUint64(dsBonus[dsUncompressedBytes:], le.Uint64(snapBonus[dsUncompressedBytes:]))
	le.PutUint64(dsBonus[dsFlags:], dsFlagUniqueAccurate)
	encodeBlkptr(cloneZPLBP, dsBonus[dsBP:dsBP+blkptrSize])
	dsDN := newDnode(dmotDSLDataset, 1, dmotDSLDataset, uint16(len(dsBonus)))
	copy(dsDN.raw[dnodeBonusOff(1):], dsBonus)
	dsDN.encode()
	if err := fs.writeMOSObject(cloneDSObj, dsDN); err != nil {
		return fmt.Errorf("zfs: Clone: write DSL dataset dnode: %w", err)
	}

	// 8. Register the clone under the pool root DSL dir's child map so the
	// reader's dataset-path navigation can reach it.
	if err := fs.mutateMOSZAP(rootChildZAPObj, cloneName, cloneDirObj, false); err != nil {
		return fmt.Errorf("zfs: Clone: register clone %q: %w", cloneName, err)
	}

	// 9. Dependent-clone tracking on the origin snapshot: record the clone
	// dataset in ds_next_clones_obj (create the DMU_OT_DSL_CLONES ZAP on first
	// clone) and bump ds_num_children.
	nextClonesObj := le.Uint64(snapBonus[dsNextClonesObj:])
	if nextClonesObj == 0 {
		nextClonesObj, err = fs.newEmptyMOSZAP(dmotDSLClones)
		if err != nil {
			return fmt.Errorf("zfs: Clone: create clones ZAP: %w", err)
		}
		le.PutUint64(snapBonus[dsNextClonesObj:], nextClonesObj)
	}
	// OpenZFS keys the clones ZAP by the clone dataset's object number
	// formatted as lowercase hex (zap_add_int), value = the same object number.
	if err := fs.mutateMOSZAP(nextClonesObj, fmt.Sprintf("%x", cloneDSObj), cloneDSObj, false); err != nil {
		return fmt.Errorf("zfs: Clone: record dependent clone: %w", err)
	}
	le.PutUint64(snapBonus[dsNumChildren:], le.Uint64(snapBonus[dsNumChildren:])+1)
	// Rewrite the origin snapshot dnode in place with the updated bonus.
	copy(snapDN.raw[dnodeBonusOff(int(snapDN.nblkptr)):], snapBonus)
	snapDN.encode()
	if err := fs.writeMOSObject(snapDSObj, snapDN); err != nil {
		return fmt.Errorf("zfs: Clone: update origin snapshot: %w", err)
	}

	// 9b. Record the clone on the ORIGIN DIR's dd_clones ZAP too. OpenZFS's
	// dsl_dataset_create_sync populates dd_clones on the dir that owns the
	// origin snapshot (here the pool root DSL dir), and zdb's
	// count_dir_mos_objects marks dd_clones referenced — without it zdb reports
	// the origin dir's own MOS objects as leaked.
	if len(rootDirBonus) >= ddClonesObj+8 {
		ddClones := le.Uint64(rootDirBonus[ddClonesObj:])
		if ddClones == 0 {
			ddClones, err = fs.newEmptyMOSZAP(dmotDSLClones)
			if err != nil {
				return fmt.Errorf("zfs: Clone: create dd_clones ZAP: %w", err)
			}
			le.PutUint64(rootDirBonus[ddClonesObj:], ddClones)
		}
		if err := fs.mutateMOSZAP(ddClones, fmt.Sprintf("%x", cloneDSObj), cloneDSObj, false); err != nil {
			return fmt.Errorf("zfs: Clone: record clone in dd_clones: %w", err)
		}
		copy(rootDirDN.raw[dnodeBonusOff(int(rootDirDN.nblkptr)):], rootDirBonus)
		rootDirDN.encode()
		if err := fs.writeMOSObject(rootDirObj, rootDirDN); err != nil {
			return fmt.Errorf("zfs: Clone: update origin dir dd_clones: %w", err)
		}
	}

	// 10. Commit a fresh uberblock so the clone's MOS objects survive reopen.
	return fs.commitUberblock()
}

// Origin returns the full name ("<pool>@<snapshot>") of the snapshot this
// dataset was cloned from, or "" if the currently-open dataset is not a clone
// (mirroring `zfs get origin`, which reports "-" for a non-clone). It reads the
// open dataset's DSL dir dd_origin_obj and resolves the referenced snapshot's
// name.
func (fs *zfsFS) Origin() (string, error) {
	if fs.zplDS == nil {
		return "", fmt.Errorf("zfs: Origin: pool not fully opened")
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	mos := fs.zplDS.mos

	dsDN, err := mos.readObject(fs.zplDS.headDSObjNum)
	if err != nil {
		return "", fmt.Errorf("zfs: Origin: read dataset: %w", err)
	}
	dsBonus := dsDN.bonusData()
	if len(dsBonus) < dsDirObj+8 {
		return "", fmt.Errorf("zfs: Origin: dataset bonus too short")
	}
	dirObj := binary.LittleEndian.Uint64(dsBonus[dsDirObj:])
	dirDN, err := mos.readObject(dirObj)
	if err != nil {
		return "", fmt.Errorf("zfs: Origin: read DSL dir: %w", err)
	}
	dirBonus := dirDN.bonusData()
	if len(dirBonus) < ddCloneParentObj+8 {
		return "", nil // too short to carry an origin → treat as non-clone
	}
	originSnapObj := binary.LittleEndian.Uint64(dirBonus[ddCloneParentObj:])
	if originSnapObj == 0 {
		return "", nil // not a clone
	}
	return fs.snapshotFullName(originSnapObj)
}

// snapshotFullName resolves a snapshot dataset object to "<pool>@<snapname>".
// The snapshot's name is found by reverse-lookup in its owning head dataset's
// snapnames ZAP (matching OpenZFS dsl_dataset_get_snapname's zap_value_search).
func (fs *zfsFS) snapshotFullName(snapObj uint64) (string, error) {
	mos := fs.zplDS.mos
	le := binary.LittleEndian

	snapDN, err := mos.readObject(snapObj)
	if err != nil {
		return "", fmt.Errorf("zfs: Origin: read origin snapshot: %w", err)
	}
	snapBonus := snapDN.bonusData()
	if len(snapBonus) < dsSnapnamesZAPObj+8 {
		return "", fmt.Errorf("zfs: Origin: origin snapshot bonus too short")
	}
	dirObj := le.Uint64(snapBonus[dsDirObj:])
	dirDN, err := mos.readObject(dirObj)
	if err != nil {
		return "", fmt.Errorf("zfs: Origin: read origin DSL dir: %w", err)
	}
	dirBonus := dirDN.bonusData()
	if len(dirBonus) < ddHeadDatasetObj+8 {
		return "", fmt.Errorf("zfs: Origin: origin DSL dir bonus too short")
	}
	headObj := le.Uint64(dirBonus[ddHeadDatasetObj:])
	headDN, err := mos.readObject(headObj)
	if err != nil {
		return "", fmt.Errorf("zfs: Origin: read origin head dataset: %w", err)
	}
	headBonus := headDN.bonusData()
	if len(headBonus) < dsSnapnamesZAPObj+8 {
		return "", fmt.Errorf("zfs: Origin: origin head bonus too short")
	}
	name := ""
	if snapZAPObj := le.Uint64(headBonus[dsSnapnamesZAPObj:]); snapZAPObj != 0 {
		zapDN, err := mos.readObject(snapZAPObj)
		if err != nil {
			return "", fmt.Errorf("zfs: Origin: read snapnames ZAP: %w", err)
		}
		entries, err := zapListAll(fs.f, fs.partOffset, zapDN)
		if err != nil {
			return "", fmt.Errorf("zfs: Origin: list snapnames ZAP: %w", err)
		}
		for k, v := range entries {
			if v == snapObj {
				name = k
				break
			}
		}
	}
	return fs.poolName() + "@" + name, nil
}

// poolName returns the pool's name from its vdev label, or "" if it cannot be
// read (Origin falls back to a bare "@<snap>" in that case).
func (fs *zfsFS) poolName() string {
	li, err := ProbeLabel(fs.f, fs.labelOffset)
	if err != nil {
		return ""
	}
	return li.PoolName
}

// DestroySnapshot removes snapshot snapName of the pool's root dataset. It
// FAILS with a wrapped errHasClones if the snapshot still has dependent clones
// (recorded in its ds_next_clones_obj ZAP) — matching OpenZFS, which rejects
// destroying a snapshot whose blocks a clone still descends from. Destroy the
// clone(s) first.
//
// The snapshot is unlinked from the head dataset's snapnames ZAP and prev-snap
// chain and its MOS objects are freed. Consistent with this driver's non-CoW,
// non-reclaiming snapshot model, the snapshot's eagerly-copied data blocks are
// left in place (a bounded space leak) rather than returned to the allocator.
func (fs *zfsFS) DestroySnapshot(snapName string) error {
	if fs.zplDS == nil {
		return fmt.Errorf("zfs: DestroySnapshot: pool not fully opened")
	}
	if fs.alloc == nil {
		return fmt.Errorf("zfs: DestroySnapshot: no allocator (read-only pool?)")
	}
	if snapName == "" || strings.ContainsAny(snapName, "@/") {
		return fmt.Errorf("zfs: DestroySnapshot: invalid snapshot name %q", snapName)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.destroySnapshot(snapName)
}

// destroySnapshot performs the actual destroy. Caller holds fs.mu.
func (fs *zfsFS) destroySnapshot(snapName string) error {
	mos := fs.zplDS.mos
	le := binary.LittleEndian

	headDirObj, err := fs.headDSLDirObj()
	if err != nil {
		return err
	}
	headDirDN, err := mos.readObject(headDirObj)
	if err != nil {
		return fmt.Errorf("zfs: DestroySnapshot: read head DSL dir: %w", err)
	}
	headDirBonus := headDirDN.bonusData()
	if len(headDirBonus) < ddHeadDatasetObj+8 {
		return fmt.Errorf("zfs: DestroySnapshot: head DSL dir bonus too short")
	}
	headDSObj := le.Uint64(headDirBonus[ddHeadDatasetObj:])

	snapDSObj, err := resolveSnapshot(fs.f, fs.partOffset, mos, headDSObj, snapName)
	if err != nil {
		return err
	}
	snapDN, err := mos.readObject(snapDSObj)
	if err != nil {
		return fmt.Errorf("zfs: DestroySnapshot: read snapshot: %w", err)
	}
	snapBonus := append([]byte(nil), snapDN.bonusData()...)
	if len(snapBonus) < dslDatasetPhysSize {
		return fmt.Errorf("zfs: DestroySnapshot: snapshot bonus too short")
	}

	// Guard: refuse if the snapshot has dependent clones.
	nextClonesObj := le.Uint64(snapBonus[dsNextClonesObj:])
	if nextClonesObj != 0 {
		zapDN, err := mos.readObject(nextClonesObj)
		if err != nil {
			return fmt.Errorf("zfs: DestroySnapshot: read clones ZAP: %w", err)
		}
		clones, err := zapListAll(fs.f, fs.partOffset, zapDN)
		if err != nil {
			return fmt.Errorf("zfs: DestroySnapshot: list clones ZAP: %w", err)
		}
		if len(clones) > 0 {
			return fmt.Errorf("zfs: DestroySnapshot: %q has %d dependent clone(s): %w",
				snapName, len(clones), errHasClones)
		}
	}

	// Unlink "<snapName>" from the head dataset's snapnames ZAP.
	headDN, err := mos.readObject(headDSObj)
	if err != nil {
		return fmt.Errorf("zfs: DestroySnapshot: read head dataset: %w", err)
	}
	headBonus := append([]byte(nil), headDN.bonusData()...)
	if len(headBonus) < dslDatasetPhysSize {
		return fmt.Errorf("zfs: DestroySnapshot: head dataset bonus too short")
	}
	snapZAPObj := le.Uint64(headBonus[dsSnapnamesZAPObj:])
	if snapZAPObj == 0 {
		return fmt.Errorf("zfs: DestroySnapshot: dataset has no snapshots")
	}
	if err := fs.mutateMOSZAP(snapZAPObj, snapName, 0, true); err != nil {
		return fmt.Errorf("zfs: DestroySnapshot: remove snapname: %w", err)
	}

	// Relink the prev-snap chain around the destroyed snapshot. If the head
	// pointed at it, advance the head to the destroyed snapshot's own previous
	// snapshot; repoint any snapshot whose prev is the destroyed one likewise.
	// A HEAD dataset keeps ds_num_children = 0 (the snapshot carries the count),
	// so only the prev-snap chain needs fixing here.
	snapPrev := le.Uint64(snapBonus[dsPrevSnapObj:])
	if le.Uint64(headBonus[dsPrevSnapObj:]) == snapDSObj {
		le.PutUint64(headBonus[dsPrevSnapObj:], snapPrev)
	}
	copy(headDN.raw[dnodeBonusOff(int(headDN.nblkptr)):], headBonus)
	headDN.encode()
	if err := fs.writeMOSObject(headDSObj, headDN); err != nil {
		return fmt.Errorf("zfs: DestroySnapshot: rewrite head dataset: %w", err)
	}
	if err := fs.repointPrevSnap(snapDSObj, snapPrev); err != nil {
		return err
	}

	// Free the snapshot's own MOS objects. Its eagerly-copied data blocks are
	// intentionally not reclaimed (see the doc comment).
	if err := fs.freeMOSObject(snapDSObj); err != nil {
		return fmt.Errorf("zfs: DestroySnapshot: free snapshot dnode: %w", err)
	}
	if dl := le.Uint64(snapBonus[dsDeadlistObj:]); dl != 0 {
		if err := fs.freeMOSObject(dl); err != nil {
			return fmt.Errorf("zfs: DestroySnapshot: free deadlist: %w", err)
		}
	}
	if nextClonesObj != 0 {
		if err := fs.freeMOSObject(nextClonesObj); err != nil {
			return fmt.Errorf("zfs: DestroySnapshot: free clones ZAP: %w", err)
		}
	}
	return fs.commitUberblock()
}

// repointPrevSnap rewrites every DSL dataset whose ds_prev_snap_obj equals
// oldPrev to point at newPrev, keeping the snapshot chain consistent after a
// snapshot in the middle of the chain is destroyed.
func (fs *zfsFS) repointPrevSnap(oldPrev, newPrev uint64) error {
	mos := fs.zplDS.mos
	le := binary.LittleEndian
	for i := uint64(1); i < fmtMOSObjArrayObjs; i++ {
		if i == oldPrev {
			continue
		}
		dn, err := mos.readObject(i)
		if err != nil || dn == nil || dn.typ != dmotDSLDataset {
			continue
		}
		bonus := append([]byte(nil), dn.bonusData()...)
		if len(bonus) < dsPrevSnapObj+8 {
			continue
		}
		if le.Uint64(bonus[dsPrevSnapObj:]) != oldPrev {
			continue
		}
		le.PutUint64(bonus[dsPrevSnapObj:], newPrev)
		copy(dn.raw[dnodeBonusOff(int(dn.nblkptr)):], bonus)
		dn.encode()
		if err := fs.writeMOSObject(i, dn); err != nil {
			return fmt.Errorf("zfs: DestroySnapshot: repoint prev-snap of object %d: %w", i, err)
		}
	}
	return nil
}

// ── MOS ZAP / object helpers ────────────────────────────────────────────────

// newEmptyMOSZAP allocates a fresh MOS object holding an empty single-block
// micro-ZAP of DMU type dtype, and returns its object number. Mirrors
// allocDeadlist but for a plain ZAP (child map / props / snapnames / clones).
// The block pointer is checksummed here because recommitChain re-checksums the
// MOS object array dnodes but not the data blocks those dnodes point at.
func (fs *zfsFS) newEmptyMOSZAP(dtype uint8) (uint64, error) {
	obj, err := fs.allocMOSObjectNum()
	if err != nil {
		return 0, fmt.Errorf("alloc ZAP obj: %w", err)
	}
	if err := fs.reserveMOSObject(obj); err != nil {
		return 0, fmt.Errorf("reserve ZAP obj: %w", err)
	}
	off, err := fs.alloc.alloc(poolBlockSize)
	if err != nil {
		return 0, fmt.Errorf("alloc ZAP block: %w", err)
	}
	blk := newMicroZAPBlock(poolBlockSize)
	if _, err := fs.f.WriteAt(blk, fs.partOffset+off); err != nil {
		return 0, fmt.Errorf("write ZAP block: %w", err)
	}
	bp := makeBlkptr(off, poolBlockSize, poolBlockSize, zcompressOff, dtype, 0, fs.curTxg)
	setBPChecksum(&bp, blk)
	dn := newDnode(dtype, 1, dmotNone, 0)
	dn.datablkszsec = uint16(poolBlockSize / 512)
	dn.setBlkptrAt(0, bp)
	dn.encode()
	if err := fs.writeMOSObject(obj, dn); err != nil {
		return 0, fmt.Errorf("write ZAP dnode: %w", err)
	}
	return obj, nil
}

// mutateMOSZAP inserts (del=false) or removes (del=true) key in the single-block
// micro-ZAP MOS object obj, then rewrites the object's data block and refreshes
// its dnode's block-pointer checksum. Like updateDirZAP, the BP checksum must be
// recomputed here: recommitChain re-checksums the MOS object array (the dnodes)
// but not the ZAP data blocks the dnodes point at.
func (fs *zfsFS) mutateMOSZAP(obj uint64, key string, val uint64, del bool) error {
	dn, err := fs.zplDS.mos.readObject(obj)
	if err != nil {
		return fmt.Errorf("read ZAP dnode %d: %w", obj, err)
	}
	bp := dn.blkptrAt(0)
	if bp.isNull() {
		return fmt.Errorf("ZAP object %d has null BP", obj)
	}
	blk, err := readBlock(fs.f, fs.partOffset, bp)
	if err != nil {
		return fmt.Errorf("read ZAP block %d: %w", obj, err)
	}
	if del {
		if err := mzapDelete(blk, key); err != nil {
			return fmt.Errorf("delete %q from ZAP %d: %w", key, obj, err)
		}
	} else {
		if err := mzapInsert(blk, key, val); err != nil {
			return fmt.Errorf("insert %q into ZAP %d: %w", key, obj, err)
		}
	}
	if _, err := fs.f.WriteAt(blk, fs.partOffset+bp.dvaOffset(0)); err != nil {
		return fmt.Errorf("write ZAP block %d: %w", obj, err)
	}
	setBPChecksum(&bp, blk)
	bp.birth = fs.curTxg
	bp.physBirth = fs.curTxg
	dn.setBlkptrAt(0, bp)
	dn.encode()
	return fs.writeMOSObject(obj, dn)
}

// freeMOSObject marks the MOS object slot objNum free by writing a zeroed
// (dmotNone) dnode over it, so allocMOSObjectNum can reuse the slot.
func (fs *zfsFS) freeMOSObject(objNum uint64) error {
	empty := &dnode{raw: make([]byte, dnodeMinSize)}
	return fs.writeMOSObject(objNum, empty)
}
