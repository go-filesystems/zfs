package filesystem_zfs

// snapshot.go – ZFS snapshot CREATION for pools created by Format().
//
// Background. ZFS snapshots are normally cheap: the live dataset and the
// snapshot SHARE every block, and copy-on-write keeps the snapshot's view
// frozen because the live writer never overwrites a shared block in place —
// it allocates a fresh block and re-points the parent, leaving the old block
// (which the snapshot still references) untouched. The DSL's dead-list /
// birth-txg machinery then tracks which blocks become exclusive to the
// snapshot so they can be freed when the snapshot is destroyed.
//
// THIS driver, however, is NOT copy-on-write. Format() lays the filesystem
// out at fixed physical offsets and the write path (fs.go) mutates blocks IN
// PLACE: writeDnode rewrites the ZPL object-array block at its original
// offset, updateDirZAP rewrites a directory ZAP block at its original offset,
// and overwritten file data blocks are freed and may be reused. A snapshot
// that merely recorded the live ds_bp would therefore NOT be isolated — a
// later WriteFile / DeleteFile would clobber the very blocks the snapshot
// points at, corrupting the frozen view.
//
// To get a SOUND snapshot without rewriting the whole driver to be CoW, we
// take the snapshot EAGERLY: at snapshot time we deep-copy the entire block
// tree reachable from the live ZPL object set into FRESH bump-allocated
// blocks, and record the snapshot dataset's ds_bp pointing at that private
// copy. Because:
//
//   - the copy only READS live blocks and WRITES to freshly allocated offsets,
//     the live pool is never mutated (its ds_bp is unchanged → it still reads
//     back cleanly);
//   - the copied blocks are never handed to the allocator's free list, so the
//     live writer's bump pointer / free list never reuses them → the snapshot
//     stays frozen no matter what the live dataset does afterwards.
//
// This is "clone-on-snapshot": more expensive than real ZFS (O(dataset size)
// rather than O(1)), but correct and non-destructive, which is what matters
// for a userland reader/writer whose own reader must be able to open the
// snapshot back.
//
// On-disk wiring (all new objects go into FREE slots; nothing existing moves):
//
//   MOS object array (16 KiB, 32 slots; Format uses 1..3, leaving 4..31 free)
//     obj 2  = head DSL dir         (unchanged except first-snapshot ZAP link)
//     obj 3  = head DSL dataset     (ds_prev_snap_obj / ds_num_children bumped)
//     obj S  = snapshot DSL dataset (NEW: ds_bp → deep-copied ZPL objset)
//     obj Z  = snapnames ZAP        (NEW, shared by all snaps of this dataset)
//
//   head dataset bonus: ds_snapnames_zapobj → obj Z (created on first snap)
//   snap ZAP: "<snapname>" → obj S
//
// Reader side: OpenSnapshot / dataset paths of the form "@snap" or
// "child/path@snap" resolve the head dataset, read ds_snapnames_zapobj, look
// up the snap name, and open the snapshot dataset's ds_bp instead of the
// head's. See openNamedDatasetSnap below.

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Snapshot creates a snapshot named snapName of the pool's root dataset.
//
// The snapshot is a frozen, isolated copy: it is unaffected by subsequent
// writes/deletes to the live dataset, survives a Close + reopen, and is
// itself readable through the driver via OpenSnapshot (or by opening a
// dataset path ending in "@<snapName>").
//
// snapName must be non-empty and must not contain '@' or '/'. Creating two
// snapshots with the same name returns an error.
func (fs *zfsFS) Snapshot(snapName string) error {
	if fs.zplDS == nil {
		return fmt.Errorf("zfs: Snapshot: pool not fully opened")
	}
	if fs.alloc == nil {
		return fmt.Errorf("zfs: Snapshot: no allocator (read-only pool?)")
	}
	if snapName == "" || strings.ContainsAny(snapName, "@/") {
		return fmt.Errorf("zfs: Snapshot: invalid snapshot name %q", snapName)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.snapshotHeadDataset(snapName)
}

// snapshotHeadDataset performs the actual snapshot of the currently-open
// (head) dataset. Caller holds fs.mu.
func (fs *zfsFS) snapshotHeadDataset(snapName string) error {
	mos := fs.zplDS.mos

	// 1. Resolve the head DSL dir + head DSL dataset object numbers.
	headDirObj, err := fs.headDSLDirObj()
	if err != nil {
		return err
	}
	headDirDN, err := mos.readObject(headDirObj)
	if err != nil {
		return fmt.Errorf("zfs: Snapshot: read head DSL dir: %w", err)
	}
	headDirBonus := append([]byte(nil), headDirDN.bonusData()...)
	if len(headDirBonus) < ddHeadDatasetObj+8 {
		return fmt.Errorf("zfs: Snapshot: head DSL dir bonus too short")
	}
	headDSObj := binary.LittleEndian.Uint64(headDirBonus[ddHeadDatasetObj:])
	if headDSObj == 0 {
		return fmt.Errorf("zfs: Snapshot: head DSL dir has no head dataset")
	}
	headDSDN, err := mos.readObject(headDSObj)
	if err != nil {
		return fmt.Errorf("zfs: Snapshot: read head DSL dataset: %w", err)
	}
	headDSBonus := append([]byte(nil), headDSDN.bonusData()...)
	if len(headDSBonus) < dsBP+blkptrSize {
		return fmt.Errorf("zfs: Snapshot: head DSL dataset bonus too short")
	}

	// 2. Find / create the snapnames ZAP for the head dataset.
	snapZAPObj := binary.LittleEndian.Uint64(headDSBonus[dsSnapnamesZAPObj:])
	var snapZAPBlk []byte
	var snapZAPBP blkptr
	createdZAP := false
	if snapZAPObj == 0 {
		// First snapshot of this dataset: allocate a fresh micro-ZAP block
		// and a MOS dnode to describe it.
		off, err := fs.alloc.alloc(poolBlockSize)
		if err != nil {
			return fmt.Errorf("zfs: Snapshot: alloc snap ZAP: %w", err)
		}
		snapZAPBlk = newMicroZAPBlock(poolBlockSize)
		snapZAPBP = makeBlkptr(off, poolBlockSize, poolBlockSize, zcompressOff, dmotDSLDSSnapMap, 0, fs.curTxg)
		createdZAP = true
	} else {
		zapDN, err := mos.readObject(snapZAPObj)
		if err != nil {
			return fmt.Errorf("zfs: Snapshot: read snap ZAP dnode: %w", err)
		}
		snapZAPBP = zapDN.blkptrAt(0)
		if snapZAPBP.isNull() {
			return fmt.Errorf("zfs: Snapshot: snap ZAP has null BP")
		}
		snapZAPBlk, err = readBlock(fs.f, fs.partOffset, snapZAPBP)
		if err != nil {
			return fmt.Errorf("zfs: Snapshot: read snap ZAP block: %w", err)
		}
		// Reject duplicate snapshot names.
		existing, err := zapListAll(fs.f, fs.partOffset, zapDN)
		if err != nil {
			return fmt.Errorf("zfs: Snapshot: list snap ZAP: %w", err)
		}
		if _, dup := existing[snapName]; dup {
			return fmt.Errorf("zfs: Snapshot: snapshot %q already exists", snapName)
		}
	}

	// 3. Deep-copy the live ZPL object set into fresh blocks. zplBP points
	// at the live objset; copyObjsetTree returns a BP for an independent,
	// frozen copy.
	liveZPLBP := parseBlkptr(headDSBonus[dsBP : dsBP+blkptrSize])
	if liveZPLBP.isNull() {
		return fmt.Errorf("zfs: Snapshot: head dataset has null ZPL BP")
	}
	snapZPLBP, err := fs.copyObjsetTree(liveZPLBP)
	if err != nil {
		return fmt.Errorf("zfs: Snapshot: copy objset tree: %w", err)
	}

	// 4. Allocate MOS object numbers for the snapshot dataset (and the snap
	// ZAP, if newly created).
	snapDSObj, err := fs.allocMOSObjectNum()
	if err != nil {
		return fmt.Errorf("zfs: Snapshot: alloc snap dataset obj: %w", err)
	}
	// Reserve the dataset slot before allocating the ZAP slot so the two
	// don't collide (allocMOSObjectNum scans for the first dmotNone slot).
	if err := fs.reserveMOSObject(snapDSObj); err != nil {
		return fmt.Errorf("zfs: Snapshot: reserve snap dataset obj: %w", err)
	}
	if createdZAP {
		snapZAPObj, err = fs.allocMOSObjectNum()
		if err != nil {
			return fmt.Errorf("zfs: Snapshot: alloc snap ZAP obj: %w", err)
		}
		if err := fs.reserveMOSObject(snapZAPObj); err != nil {
			return fmt.Errorf("zfs: Snapshot: reserve snap ZAP obj: %w", err)
		}
	}

	now := uint64(time.Now().Unix())

	// 5. Build the snapshot DSL dataset dnode. It mirrors the head dataset
	// but: ds_bp → frozen copy, ds_next_snap_obj → head dataset (the snap's
	// "next" in the chain is the live head), ds_num_children = 0,
	// ds_snapnames_zapobj = 0 (snapshots have no snapshots of their own).
	prevSnapObj := binary.LittleEndian.Uint64(headDSBonus[dsPrevSnapObj:])
	prevSnapTxg := binary.LittleEndian.Uint64(headDSBonus[dsPrevSnapTxg:])

	snapBonus := make([]byte, len(headDSBonus))
	copy(snapBonus, headDSBonus)
	le := binary.LittleEndian
	le.PutUint64(snapBonus[dsDirObj:], headDirObj)
	le.PutUint64(snapBonus[dsPrevSnapObj:], prevSnapObj)
	le.PutUint64(snapBonus[dsPrevSnapTxg:], prevSnapTxg)
	le.PutUint64(snapBonus[dsNextSnapObj:], headDSObj) // next in chain = the live head
	le.PutUint64(snapBonus[dsSnapnamesZAPObj:], 0)
	le.PutUint64(snapBonus[dsNumChildren:], 0)
	le.PutUint64(snapBonus[dsCreationTime:], now)
	le.PutUint64(snapBonus[dsCreationTxg:], fs.curTxg)
	encodeBlkptr(snapZPLBP, snapBonus[dsBP:dsBP+blkptrSize])
	// Give the snapshot its OWN deadlist (the bonus was copied from the head,
	// which points ds_deadlist_obj at the head's deadlist — sharing it makes
	// zdb's dataset walk panic on a duplicate deadlist object).
	snapDLObj, err := fs.allocDeadlist()
	if err != nil {
		return fmt.Errorf("zfs: Snapshot: %w", err)
	}
	le.PutUint64(snapBonus[dsDeadlistObj:], snapDLObj)

	snapDSDN := newDnode(dmotDSLDataset, 1, dmotDSLDataset, uint16(len(snapBonus)))
	copy(snapDSDN.raw[dnodeHdrSize+blkptrSize:], snapBonus)
	snapDSDN.encode()
	if err := fs.writeMOSObject(snapDSObj, snapDSDN); err != nil {
		return fmt.Errorf("zfs: Snapshot: write snap dataset dnode: %w", err)
	}

	// 6. Insert "<snapName>" → snapDSObj into the snap ZAP and persist it.
	if err := mzapInsert(snapZAPBlk, snapName, snapDSObj); err != nil {
		return fmt.Errorf("zfs: Snapshot: insert into snap ZAP: %w", err)
	}
	if _, err := fs.f.WriteAt(snapZAPBlk, fs.partOffset+snapZAPBP.dvaOffset(0)); err != nil {
		return fmt.Errorf("zfs: Snapshot: write snap ZAP block: %w", err)
	}
	// The ZAP block's contents changed (a name was inserted), so its dnode's
	// BP must carry a fresh fletcher4 over the new bytes — whether the ZAP
	// object is brand new (createdZAP) or pre-existing (e.g. the root
	// dataset's Format-time snapnames ZAP). Without this zdb fails to read it
	// (ECKSUM). recommitChain re-checksums the MOS object array (the dnodes),
	// but not the data blocks those dnodes point at, so we update the BP here.
	setBPChecksum(&snapZAPBP, snapZAPBlk)
	snapZAPBP.birth = fs.curTxg
	snapZAPBP.physBirth = fs.curTxg
	zapDN := newDnode(dmotDSLDSSnapMap, 1, dmotNone, 0)
	zapDN.datablkszsec = uint16(poolBlockSize / 512)
	zapDN.setBlkptrAt(0, snapZAPBP)
	zapDN.encode()
	if err := fs.writeMOSObject(snapZAPObj, zapDN); err != nil {
		return fmt.Errorf("zfs: Snapshot: write snap ZAP dnode: %w", err)
	}

	// 7. Update the head DSL dataset: link the snapshot into the chain
	// (ds_prev_snap_obj) and bump num_children / ds_snapnames_zapobj.
	//
	// Do NOT advance ds_prev_snap_txg. zdb's space audit (`zdb -bcc`) charges
	// blocks with birth <= ds_prev_snap_txg to the previous snapshot instead
	// of the head. Real ZFS snapshots SHARE the head's old blocks, so that
	// snapshot then traverses (and accounts) them. Our snapshot is an eager
	// CLONE — it points at a private copy, not the head's live blocks — so if
	// we advanced ds_prev_snap_txg to the snapshot txg, every live block
	// (born at Format/earlier write txgs) would be charged to a snapshot that
	// never references it, and zdb would report it leaked. Leaving
	// ds_prev_snap_txg at its prior value keeps the head owning its full live
	// tree; the snapshot independently owns its copied tree (born this txg).
	// Link the snapshot into the head's chain so zdb's dataset walk
	// (dsl_dataset_hold_obj requires a valid chain), BUT do NOT advance
	// ds_prev_snap_txg: our snapshot is an eager copy that shares no blocks
	// with the head, so the head must keep owning (and zdb keep traversing)
	// all its live blocks — advancing the txg would charge them to a snapshot
	// that never references them and `zdb -bcc` would report them leaked.
	le.PutUint64(headDSBonus[dsPrevSnapObj:], snapDSObj)
	numChildren := le.Uint64(headDSBonus[dsNumChildren:])
	le.PutUint64(headDSBonus[dsNumChildren:], numChildren+1)
	le.PutUint64(headDSBonus[dsSnapnamesZAPObj:], snapZAPObj)
	// Re-encode the head dataset dnode in place (same object slot/offset).
	newHeadDN := newDnode(dmotDSLDataset, 1, dmotDSLDataset, uint16(len(headDSBonus)))
	copy(newHeadDN.raw[dnodeHdrSize+blkptrSize:], headDSBonus)
	newHeadDN.encode()
	if err := fs.writeMOSObject(headDSObj, newHeadDN); err != nil {
		return fmt.Errorf("zfs: Snapshot: rewrite head dataset dnode: %w", err)
	}

	// 8. Commit a fresh uberblock so the new MOS objects survive reopen.
	return fs.commitUberblock()
}

// allocDeadlist creates a fresh, empty deadlist MOS object (a DMU_OT_DEADLIST
// dnode over an empty micro-ZAP) and returns its object number. Every dataset
// — head and each snapshot — must own a DISTINCT deadlist object: zdb's
// dmu_objset_find walk builds a range tree of the deadlist objects it visits
// and panics ("adding existent segment to range tree") if two datasets name
// the same one. The snapshot bonus is copied from the head, which would
// otherwise make every snapshot share the head's deadlist (object
// fmtMOSRootDLObj). The block pointer is checksummed here because recommitChain
// re-checksums the MOS object array but not the data blocks its dnodes point at.
func (fs *zfsFS) allocDeadlist() (uint64, error) {
	obj, err := fs.allocMOSObjectNum()
	if err != nil {
		return 0, fmt.Errorf("alloc deadlist obj: %w", err)
	}
	if err := fs.reserveMOSObject(obj); err != nil {
		return 0, fmt.Errorf("reserve deadlist obj: %w", err)
	}
	off, err := fs.alloc.alloc(poolBlockSize)
	if err != nil {
		return 0, fmt.Errorf("alloc deadlist block: %w", err)
	}
	zap := newMicroZAPBlock(poolBlockSize)
	if _, err := fs.f.WriteAt(zap, fs.partOffset+off); err != nil {
		return 0, fmt.Errorf("write deadlist block: %w", err)
	}
	bp := makeBlkptr(off, poolBlockSize, poolBlockSize, zcompressOff, dmotDeadlist, 0, fs.curTxg)
	setBPChecksum(&bp, zap)
	bonus := make([]byte, dslDeadlistPhysSize)
	dn := newDnode(dmotDeadlist, 1, dmotDeadlistHdr, uint16(len(bonus)))
	dn.datablkszsec = uint16(poolBlockSize / 512)
	dn.flags = dnodeFlagUsedBytes
	dn.setBlkptrAt(0, bp)
	copy(dn.raw[dnodeBonusOff(1):], bonus)
	dn.encode()
	if err := fs.writeMOSObject(obj, dn); err != nil {
		return 0, fmt.Errorf("write deadlist dnode: %w", err)
	}
	return obj, nil
}

// headDSLDirObj returns the MOS object number of the pool's root DSL dir
// (the "root_dataset" entry in the pool directory ZAP). Snapshots in this
// implementation always target the root dataset that the FS was opened on,
// which for Open() (datasetPath="") is this root DSL dir.
func (fs *zfsFS) headDSLDirObj() (uint64, error) {
	mos := fs.zplDS.mos
	poolDirDN, err := mos.readObject(mosPoolDirObj)
	if err != nil {
		return 0, fmt.Errorf("zfs: read pool dir object: %w", err)
	}
	entries, err := zapListAll(fs.f, fs.partOffset, poolDirDN)
	if err != nil {
		return 0, fmt.Errorf("zfs: pool dir ZAP: %w", err)
	}
	obj, ok := entries[dmuPoolRootDataset]
	if !ok {
		return 0, fmt.Errorf("zfs: pool dir missing 'root_dataset' key")
	}
	return obj, nil
}

// copyObjsetTree deep-copies the object set referenced by srcBP — the objset
// block, its object-array data blocks, and every block tree reachable from
// each object dnode — into fresh bump-allocated blocks. It returns a block
// pointer to the independent copy.
//
// The copy is frozen: none of the new offsets are ever returned to the
// allocator, so the live writer can never reuse them. After this call the
// snapshot's view is fully isolated from later in-place mutations of the live
// objset.
func (fs *zfsFS) copyObjsetTree(srcBP blkptr) (blkptr, error) {
	objsetBlk, err := readBlock(fs.f, fs.partOffset, srcBP)
	if err != nil {
		return blkptr{}, fmt.Errorf("read objset block: %w", err)
	}
	if len(objsetBlk) < objsetHdrSize {
		return blkptr{}, fmt.Errorf("objset block too small: %d", len(objsetBlk))
	}
	dst := append([]byte(nil), objsetBlk...)

	// The meta_dnode (object 0) sits at the front of the objset block and
	// describes the object array. Copy its whole block tree and re-point it.
	metaDN, err := parseDnode(dst[objsetMetaDnodeOff : objsetMetaDnodeOff+dnodeMinSize])
	if err != nil {
		return blkptr{}, fmt.Errorf("parse meta_dnode: %w", err)
	}
	if err := fs.copyDnodeBlockTree(metaDN, true); err != nil {
		return blkptr{}, fmt.Errorf("copy object array: %w", err)
	}
	copy(dst[objsetMetaDnodeOff:], metaDN.raw[:dnodeMinSize])

	// Write the copied objset block to a fresh location.
	off, err := fs.alloc.alloc(len(dst))
	if err != nil {
		return blkptr{}, fmt.Errorf("alloc objset copy: %w", err)
	}
	if _, err := fs.f.WriteAt(dst, fs.partOffset+off); err != nil {
		return blkptr{}, fmt.Errorf("write objset copy: %w", err)
	}
	newBP := makeBlkptr(off, int(srcBP.psize()), int(srcBP.lsize()), zcompressOff, dmotObjset, srcBP.level(), fs.curTxg)
	// The copy occupies a fresh DVA, so its BP needs a fresh fletcher4 over
	// the copied bytes; without it zdb fails to verify the snapshot objset,
	// abandons the subtree, and reports its blocks as leaked. Carry the
	// source fill (object count) up unchanged.
	setBPChecksum(&newBP, dst)
	newBP.fill = srcBP.fill
	return newBP, nil
}

// copyDnodeBlockTree deep-copies every data / indirect block reachable from
// dn into fresh blocks, rewriting dn's block pointers in place to reference
// the copies. When isObjectArray is true, the dnode's data blocks are object
// arrays (arrays of dnode_phys_t); each contained dnode's OWN block tree is
// copied recursively so directory ZAPs, file data, and indirect blocks become
// private to the snapshot too.
func (fs *zfsFS) copyDnodeBlockTree(dn *dnode, isObjectArray bool) error {
	for i := 0; i < int(dn.nblkptr); i++ {
		bp := dn.blkptrAt(i)
		newBP, err := fs.copyBlkptrTree(bp, isObjectArray, dn.dataBlockSize())
		if err != nil {
			return err
		}
		dn.setBlkptrAt(i, newBP)
	}
	dn.encode()
	return nil
}

// copyBlkptrTree copies the block referenced by bp (and, recursively, every
// block beneath it) into fresh allocations, returning a BP for the copy. Null
// / embedded / gang BPs are returned unchanged (embedded data already lives in
// the BP; gang blocks are never produced by this writer).
//
// When objectArrayLevel0 is true and bp is a level-0 block, the block is an
// array of dnode_phys_t: each non-empty dnode's block tree is copied too.
func (fs *zfsFS) copyBlkptrTree(bp blkptr, objectArrayLevel0 bool, leafBlockSize int) (blkptr, error) {
	if bp.isNull() || bp.isEmbedded() {
		return bp, nil
	}
	if bp.dvaGang(0) {
		return blkptr{}, fmt.Errorf("zfs: snapshot: gang blocks not supported")
	}

	raw, err := readBlock(fs.f, fs.partOffset, bp)
	if err != nil {
		return blkptr{}, fmt.Errorf("read block at 0x%X: %w", bp.dvaOffset(0), err)
	}
	dst := append([]byte(nil), raw...)

	if bp.level() > 0 {
		// Indirect block: an array of child BPs. Copy each child subtree,
		// then this indirect block.
		for off := 0; off+blkptrSize <= len(dst); off += blkptrSize {
			child := parseBlkptr(dst[off : off+blkptrSize])
			if child.isNull() {
				continue
			}
			newChild, err := fs.copyBlkptrTree(child, objectArrayLevel0, leafBlockSize)
			if err != nil {
				return blkptr{}, err
			}
			encodeBlkptr(newChild, dst[off:off+blkptrSize])
		}
	} else if objectArrayLevel0 {
		// Level-0 object-array block: copy each contained dnode's subtree.
		for off := 0; off+dnodeMinSize <= len(dst); off += dnodeMinSize {
			child, err := parseDnode(dst[off : off+dnodeMinSize])
			if err != nil || child.typ == dmotNone || child.nblkptr == 0 {
				continue
			}
			// The meta-dnode (object 0) of a ZPL objset is itself NOT in the
			// object array; here every entry is a regular object. Copy its
			// block tree (its own data is plain data, never object arrays).
			if err := fs.copyDnodeBlockTree(child, false); err != nil {
				return blkptr{}, err
			}
			copy(dst[off:off+dnodeMinSize], child.raw[:dnodeMinSize])
		}
	}

	// Write the (possibly rewritten) block to a fresh location.
	newOff, err := fs.alloc.alloc(len(dst))
	if err != nil {
		return blkptr{}, fmt.Errorf("alloc block copy: %w", err)
	}
	if _, err := fs.f.WriteAt(dst, fs.partOffset+newOff); err != nil {
		return blkptr{}, fmt.Errorf("write block copy: %w", err)
	}
	newBP := makeBlkptr(newOff, int(bp.psize()), int(bp.lsize()), zcompressOff, bp.dmuType(), bp.level(), fs.curTxg)
	// Re-checksum over the copied bytes (the copy lives at a new DVA) and
	// preserve the source fill — indirect / object-array BPs carry the count
	// of blocks / dnodes beneath them, which zdb's leak audit relies on.
	setBPChecksum(&newBP, dst)
	newBP.fill = bp.fill
	return newBP, nil
}

// snapshotHighWater returns the highest byte offset (exclusive) occupied by
// any snapshot dataset's deep-copied block tree, so the allocator can resume
// above it after a reopen. It walks every DSL dataset object in the MOS whose
// ds_bp differs from the live head dataset's, recursing through the snapshot's
// ZPL objset, object array, and each object's data/indirect extents.
//
// Returns 0 if no snapshots exist or the MOS cannot be scanned. Best-effort:
// unreadable objects are skipped (they cannot pin live space the writer would
// hand out, since the writer only ever appends).
func (fs *zfsFS) snapshotHighWater() int64 {
	mos := fs.zplDS.mos
	var maxEnd int64
	bump := func(bp blkptr) {
		if bp.isNull() || bp.isEmbedded() || bp.dvaGang(0) {
			return
		}
		if end := bp.dvaOffset(0) + bp.dvaAsize(0); end > maxEnd {
			maxEnd = end
		}
	}
	for i := uint64(1); i < fmtMOSObjArrayObjs; i++ {
		dn, err := mos.readObject(i)
		if err != nil || dn == nil || dn.typ != dmotDSLDataset {
			continue
		}
		bonus := dn.bonusData()
		if len(bonus) < dsBP+blkptrSize {
			continue
		}
		zplBP := parseBlkptr(bonus[dsBP : dsBP+blkptrSize])
		fs.walkBlockTreeExtents(zplBP, true, bump)
	}
	return maxEnd
}

// walkBlockTreeExtents visits every extent reachable from bp (the block
// itself, its indirect children, and — when objsetRoot is set — the dnodes
// inside an object set / object array) and reports each via visit. It mirrors
// copyBlkptrTree's traversal but read-only.
func (fs *zfsFS) walkBlockTreeExtents(bp blkptr, objsetRoot bool, visit func(blkptr)) {
	if bp.isNull() || bp.isEmbedded() || bp.dvaGang(0) {
		return
	}
	visit(bp)
	raw, err := readBlock(fs.f, fs.partOffset, bp)
	if err != nil {
		return
	}
	if objsetRoot && bp.dmuType() == dmotObjset {
		// Objset block: meta_dnode at the front describes the object array.
		metaDN, err := parseDnode(raw[objsetMetaDnodeOff : objsetMetaDnodeOff+dnodeMinSize])
		if err == nil {
			for j := 0; j < int(metaDN.nblkptr); j++ {
				fs.walkBlockTreeExtents(metaDN.blkptrAt(j), false, visit)
				// The object array's level-0 blocks hold dnodes; recurse.
				fs.walkObjectArray(metaDN.blkptrAt(j), visit)
			}
		}
		return
	}
	if bp.level() > 0 {
		for off := 0; off+blkptrSize <= len(raw); off += blkptrSize {
			child := parseBlkptr(raw[off : off+blkptrSize])
			fs.walkBlockTreeExtents(child, false, visit)
		}
	}
}

// walkObjectArray descends an object-array BP (possibly indirect), visiting
// every contained dnode's data/indirect extents.
func (fs *zfsFS) walkObjectArray(bp blkptr, visit func(blkptr)) {
	if bp.isNull() || bp.isEmbedded() || bp.dvaGang(0) {
		return
	}
	raw, err := readBlock(fs.f, fs.partOffset, bp)
	if err != nil {
		return
	}
	if bp.level() > 0 {
		for off := 0; off+blkptrSize <= len(raw); off += blkptrSize {
			child := parseBlkptr(raw[off : off+blkptrSize])
			fs.walkObjectArray(child, visit)
		}
		return
	}
	for off := 0; off+dnodeMinSize <= len(raw); off += dnodeMinSize {
		child, err := parseDnode(raw[off : off+dnodeMinSize])
		if err != nil || child.typ == dmotNone || child.nblkptr == 0 {
			continue
		}
		for j := 0; j < int(child.nblkptr); j++ {
			fs.walkBlockTreeExtents(child.blkptrAt(j), false, visit)
		}
	}
}

// ── MOS object-array write helpers ─────────────────────────────────────────
//
// These mirror writeDnode / allocObjectNum (which target the ZPL object array)
// but operate on the MOS object array, which Format places in a single 16 KiB
// block described by the MOS meta_dnode. Format uses MOS objects 1..3, leaving
// 4..(fmtMOSObjArrayObjs-1) free for snapshot datasets and their snap ZAPs.

// allocMOSObjectNum returns the first free (dmotNone) MOS object slot.
func (fs *zfsFS) allocMOSObjectNum() (uint64, error) {
	mos := fs.zplDS.mos
	for i := uint64(4); i < fmtMOSObjArrayObjs; i++ {
		dn, err := mos.readObject(i)
		if err != nil {
			continue
		}
		if dn.typ == dmotNone {
			return i, nil
		}
	}
	return 0, fmt.Errorf("zfs: no free MOS object slot (pool metadata full)")
}

// reserveMOSObject writes a placeholder dnode so a slot stops reading as free
// before the caller fills it in (lets two allocMOSObjectNum calls return
// distinct slots within one snapshot).
func (fs *zfsFS) reserveMOSObject(objNum uint64) error {
	placeholder := &dnode{raw: make([]byte, dnodeMinSize)}
	placeholder.raw[0] = dmotObjectArray // any non-zero type marks it busy
	return fs.writeMOSObject(objNum, placeholder)
}

// writeMOSObject writes dn into the MOS object array at objNum, in place,
// exactly like writeDnode does for the ZPL object array. The MOS object array
// is a single block addressed by the MOS meta_dnode's first BP.
func (fs *zfsFS) writeMOSObject(objNum uint64, dn *dnode) error {
	metaDN := fs.zplDS.mos.metaDnode
	blkSz := uint64(metaDN.dataBlockSize())
	if blkSz == 0 {
		blkSz = fmtDnodeBlkSize
	}
	byteOff := objNum * uint64(dnodeMinSize)
	blockID := byteOff / blkSz
	offsetInBlock := int(byteOff % blkSz)
	// The MOS object array spans multiple 16 KiB dnode blocks; object objNum
	// lives in block blockID, addressed by the meta_dnode's BP[blockID].
	if blockID >= uint64(metaDN.nblkptr) {
		return fmt.Errorf("zfs: writeMOSObject: object %d beyond MOS array (%d blocks)", objNum, metaDN.nblkptr)
	}
	bp := metaDN.blkptrAt(int(blockID))
	if bp.isNull() {
		return fmt.Errorf("zfs: writeMOSObject: MOS meta_dnode BP[%d] is null", blockID)
	}
	if blockID >= 1 {
		// recommitChain reuses the upper blocks' on-disk fills and skips
		// re-checksumming them unless flagged dirty; this write changes one.
		fs.mosUpperDirty = true
	}
	blkData, err := readBlock(fs.f, fs.partOffset, bp)
	if err != nil {
		return fmt.Errorf("zfs: writeMOSObject: read MOS object array: %w", err)
	}
	if offsetInBlock+dnodeMinSize > len(blkData) {
		return fmt.Errorf("zfs: writeMOSObject: object %d out of block bounds", objNum)
	}
	copy(blkData[offsetInBlock:], dn.raw[:dnodeMinSize])
	physOff := fs.partOffset + bp.dvaOffset(0)
	if _, err := fs.f.WriteAt(blkData, physOff); err != nil {
		return fmt.Errorf("zfs: writeMOSObject: write MOS object array: %w", err)
	}
	return nil
}
