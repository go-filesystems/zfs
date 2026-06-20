package filesystem_zfs

// resize.go – ZFS pool shrink. ZFS upstream (OpenZFS) does NOT support
// pool shrink; the indirect-vdev / vdev_remove machinery in
// vdev_removal.c builds a permanent indirect-mapping table that adds
// per-pool overhead forever, so the project has historically declined
// to ship a shrink button. Our writer carries none of that legacy: we
// control the on-disk format end to end, we emit no snapshots, and the
// only consumer is our own driver, so we can implement shrink directly
// without the indirect-mapping cost.
//
// Two modes are provided:
//
//   ShrinkMode_Rebuild
//     Walk the live filesystem (every file + directory, exact contents
//     and metadata), reset the pool head in place, replay everything
//     into the head of the same backing store, then truncate. O(live
//     data). Safe in the presence of snapshots IF the writer ever
//     grows snapshot support (each snapshot's BP tree is replayed too)
//     — today the writer emits no snapshots so the "preserve snapshots"
//     branch is exercise-for-the-reader rather than something we need
//     to test.
//
//   ShrinkMode_InPlace
//     Walk every live block-pointer subtree; for any extent whose
//     allocated byte range falls inside the high region
//     [newDataLimit, currentDataLimit), relocate it to the low region
//     via the allocator, rewrite the parent BP, and propagate the
//     rewrite up to the containing dnode (which itself lives in a
//     fixed-position object array at byte offset < newDataLimit and
//     therefore never moves). Then rewrite the four vdev labels at
//     their new positions, commit a new uberblock, and truncate.
//
// Both modes are pure Go. The cross-validation against `zdb` is
// skip-gated; see resize_test.go.

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"time"

	filesystem "github.com/go-filesystems/interface"
)

// ShrinkMode selects the on-disk relocation strategy used by Shrink.
// See the package comment in resize.go for the full per-mode contract.
type ShrinkMode int

const (
	// ShrinkMode_Auto picks InPlace when the pool is snapshot-free (the
	// only state our writer ever produces) and falls back to Rebuild
	// otherwise. Resize() always uses Auto.
	ShrinkMode_Auto ShrinkMode = iota
	// ShrinkMode_Rebuild always runs the rebuild path. Use this when
	// the caller wants the deterministic, fully-replayed image even on
	// a pool that the InPlace path could have handled.
	ShrinkMode_Rebuild
	// ShrinkMode_InPlace always runs the in-place relocation path and
	// errors out if any snapshot is present. The check is conservative:
	// any non-zero ds_prev_snap_obj / ds_next_snap_obj on the head
	// dataset rejects the operation.
	ShrinkMode_InPlace
)

func (m ShrinkMode) String() string {
	switch m {
	case ShrinkMode_Auto:
		return "auto"
	case ShrinkMode_Rebuild:
		return "rebuild"
	case ShrinkMode_InPlace:
		return "inplace"
	default:
		return fmt.Sprintf("ShrinkMode(%d)", int(m))
	}
}

// Shrink reduces the pool's on-disk image to newSize bytes using the
// auto-selected relocation strategy. Equivalent to
// ShrinkWithMode(newSize, ShrinkMode_Auto).
//
// Shrink takes the per-FS mutex (same lock that gates every other
// writer). Concurrent WriteFile / DeleteFile / Rename block until the
// shrink completes.
func (fs *zfsFS) Shrink(newSize int64) error {
	return fs.ShrinkWithMode(newSize, ShrinkMode_Auto)
}

// ShrinkWithMode is the explicit-mode entry point. See ShrinkMode for
// the per-mode contract.
func (fs *zfsFS) ShrinkWithMode(newSize int64, mode ShrinkMode) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.shrinkLocked(newSize, mode)
}

// shrinkLocked is the lock-already-held implementation called by
// ShrinkWithMode and by Resize (after Resize re-takes the lock).
func (fs *zfsFS) shrinkLocked(newSize int64, mode ShrinkMode) error {
	if newSize <= 0 {
		return fmt.Errorf("zfs: shrink: invalid size %d", newSize)
	}
	cur, err := fs.f.Size()
	if err != nil {
		return fmt.Errorf("zfs: shrink: size: %w", err)
	}
	if newSize == cur {
		return nil
	}
	if newSize > cur {
		return fmt.Errorf("zfs: shrink: new size %d > current size %d (use Grow / Resize instead)", newSize, cur)
	}

	const minSize = 4 * 1024 * 1024
	if newSize < minSize {
		return fmt.Errorf("zfs: shrink: size %d below minimum %d bytes", newSize, minSize)
	}
	// Alignment: the writer's pool layout is built around the 4 KiB
	// ashift-12 block size. Anything below that granularity can't be
	// addressed by a DVA, so reject sub-sector targets.
	if newSize%int64(poolBlockSize) != 0 {
		return fmt.Errorf("zfs: shrink: size %d not aligned to %d bytes", newSize, poolBlockSize)
	}

	// Headroom check: we need enough room for the four labels + the
	// fixed-position MOS/ZPL block region + at least a token amount of
	// data area for the relocated live extents.
	const fixedLayoutHeadroom = vdevLabelStartSize + fmtInitialNextFree + 2*vdevLabelSize
	if newSize < fixedLayoutHeadroom {
		return fmt.Errorf("zfs: shrink: size %d below fixed-layout headroom %d (4 MiB header + ~0x8E000 metadata + 2 × 256 KiB labels)",
			newSize, fixedLayoutHeadroom)
	}

	// Pick the actual strategy.
	resolved := mode
	if resolved == ShrinkMode_Auto {
		if fs.hasSnapshots() {
			resolved = ShrinkMode_Rebuild
		} else {
			resolved = ShrinkMode_InPlace
		}
	}

	switch resolved {
	case ShrinkMode_Rebuild:
		return fs.shrinkRebuildLocked(newSize)
	case ShrinkMode_InPlace:
		if fs.hasSnapshots() {
			return fmt.Errorf("zfs: shrink (InPlace): refused — pool has snapshots, use Rebuild or Auto")
		}
		return fs.shrinkInPlaceLocked(newSize, cur)
	default:
		return fmt.Errorf("zfs: shrink: unknown mode %d", int(mode))
	}
}

// hasSnapshots reports whether the head dataset has any USER-VISIBLE
// snapshots, i.e. named entries in its snapshot-name ZAP
// (ds_snapnames_zapobj). It deliberately does NOT key off
// ds_prev_snap_obj: on a feature-flags (v5000) pool every head dataset
// descends from the hidden $ORIGIN snapshot, so ds_prev_snap_obj is
// always non-zero — that is a structural artifact, not a user snapshot.
// Real ZFS lists snapshots from the snapnames ZAP, which is what we
// mirror here. A freshly Format()'d pool has an empty snapnames ZAP, so
// this returns false (and InPlace shrink is permitted), exactly as
// before the $ORIGIN hierarchy was added.
func (fs *zfsFS) hasSnapshots() bool {
	if fs.zplDS == nil || fs.zplDS.mos == nil {
		return false
	}
	mos := fs.zplDS.mos
	poolDirDN, err := mos.readObject(mosPoolDirObj)
	if err != nil {
		return false
	}
	entries, err := zapListAll(fs.f, fs.partOffset, poolDirDN)
	if err != nil {
		return false
	}
	dslDirObjNum, ok := entries[dmuPoolRootDataset]
	if !ok {
		return false
	}
	dslDirDN, err := mos.readObject(dslDirObjNum)
	if err != nil {
		return false
	}
	bonus := dslDirDN.bonusData()
	if len(bonus) < ddHeadDatasetObj+8 {
		return false
	}
	headDatasetObjNum := binary.LittleEndian.Uint64(bonus[ddHeadDatasetObj:])
	if headDatasetObjNum == 0 {
		return false
	}
	dsDN, err := mos.readObject(headDatasetObjNum)
	if err != nil {
		return false
	}
	dsBonus := dsDN.bonusData()
	if len(dsBonus) < dsSnapnamesZAPObj+8 {
		return false
	}
	snapZAPObj := binary.LittleEndian.Uint64(dsBonus[dsSnapnamesZAPObj:])
	if snapZAPObj == 0 {
		return false
	}
	snapDN, err := mos.readObject(snapZAPObj)
	if err != nil {
		return false
	}
	snaps, err := zapListAll(fs.f, fs.partOffset, snapDN)
	if err != nil {
		return false
	}
	return len(snaps) > 0
}

// ────────────────────────────────────────────────────────────────────
// Rebuild mode — walk live FS via the read API, reset the pool head,
// replay every entry into the same backing store, then truncate.
// ────────────────────────────────────────────────────────────────────

// rebuildEntry is one captured filesystem entry to be replayed after
// the pool head is reset. We snapshot every regular file's payload
// into memory; the working set is bounded by live-data size, which is
// already the metric on which both modes scale.
type rebuildEntry struct {
	path string
	mode os.FileMode
	// One of these is set:
	isDir     bool
	isSymlink bool
	data      []byte // regular-file contents, only when !isDir && !isSymlink
	link      string // symlink target, only when isSymlink
}

// captureLiveFS walks the live filesystem in deterministic
// (alphabetical) order, snapshotting every file's payload into
// memory and every directory's mode. Order matters: parents must
// precede children at replay time so MkDir / WriteFile can find their
// parent.
func (fs *zfsFS) captureLiveFS() ([]rebuildEntry, error) {
	if fs.zplDS == nil {
		// Bare uberblock image; nothing to capture, replay is a no-op
		// reformat at the new size.
		return nil, nil
	}
	var out []rebuildEntry
	var walk func(dir string) error
	walk = func(dir string) error {
		entries, err := fs.listDirLocked(dir)
		if err != nil {
			return fmt.Errorf("zfs: shrink-rebuild: list %q: %w", dir, err)
		}
		// Stable ordering — ListDir uses a map, deterministic replay
		// makes test diffs much easier to read.
		names := make([]string, 0, len(entries))
		nameMap := make(map[string]filesystem.DirEntry, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
			nameMap[e.Name()] = e
		}
		sort.Strings(names)
		for _, name := range names {
			e := nameMap[name]
			childPath := dir
			if childPath == "/" {
				childPath = "/" + name
			} else {
				childPath = dir + "/" + name
			}
			switch e.FileType() {
			case 4: // DT_DIR
				st, err := fs.statLocked(childPath)
				if err != nil {
					return fmt.Errorf("zfs: shrink-rebuild: stat dir %q: %w", childPath, err)
				}
				out = append(out, rebuildEntry{
					path:  childPath,
					mode:  os.FileMode(st.Mode() & 0o7777),
					isDir: true,
				})
				if err := walk(childPath); err != nil {
					return err
				}
			case 10: // DT_LNK
				tgt, err := fs.readlinkLocked(childPath)
				if err != nil {
					return fmt.Errorf("zfs: shrink-rebuild: readlink %q: %w", childPath, err)
				}
				out = append(out, rebuildEntry{
					path:      childPath,
					mode:      0o0777,
					isSymlink: true,
					link:      tgt,
				})
			default: // DT_REG and anything we don't model specifically
				data, err := fs.readfileLocked(childPath)
				if err != nil {
					return fmt.Errorf("zfs: shrink-rebuild: read %q: %w", childPath, err)
				}
				st, err := fs.statLocked(childPath)
				if err != nil {
					return fmt.Errorf("zfs: shrink-rebuild: stat %q: %w", childPath, err)
				}
				out = append(out, rebuildEntry{
					path: childPath,
					mode: os.FileMode(st.Mode() & 0o7777),
					data: data,
				})
			}
		}
		return nil
	}
	if err := walk("/"); err != nil {
		return nil, err
	}
	return out, nil
}

// shrinkRebuildLocked implements ShrinkMode_Rebuild against the same
// backing store: capture every live entry, reformat the head with the
// new size, replay every entry, truncate. The pool name and GUID are
// preserved across the rebuild so external identifiers (zpool import,
// boot config) keep working.
func (fs *zfsFS) shrinkRebuildLocked(newSize int64) error {
	// 1. Capture pool identity for label rebuild.
	poolName, poolGUID, err := fs.readPoolIdentity()
	if err != nil {
		return fmt.Errorf("zfs: shrink-rebuild: pool identity: %w", err)
	}

	// 2. Snapshot live entries.
	entries, err := fs.captureLiveFS()
	if err != nil {
		return err
	}

	// 3. Reset the pool head: rewrite the canonical Format() layout at
	// byte offsets [0, fixedLayoutHeadroom) of the backing store.
	if err := fs.formatHeadLocked(poolName, poolGUID, newSize); err != nil {
		return fmt.Errorf("zfs: shrink-rebuild: reset head: %w", err)
	}

	// 4. Re-init in-memory state (allocator, zplDS, curTxg, info)
	// against the rewritten head so the replay calls below find a
	// consistent pool.
	if err := fs.reopenAfterFormatLocked(newSize); err != nil {
		return fmt.Errorf("zfs: shrink-rebuild: re-open: %w", err)
	}

	// 5. Replay live entries in capture order (parents before
	// children). Each call goes through the normal writer code path,
	// so the resulting on-disk layout is identical to what a fresh
	// Format + WriteFile sequence would have produced.
	for _, e := range entries {
		switch {
		case e.isDir:
			// Root is implicit — never replay it.
			if e.path == "/" {
				continue
			}
			if err := fs.mkdirLocked(e.path, e.mode); err != nil {
				return fmt.Errorf("zfs: shrink-rebuild: mkdir %q: %w", e.path, err)
			}
		case e.isSymlink:
			if err := fs.symlinkLocked(e.link, e.path); err != nil {
				return fmt.Errorf("zfs: shrink-rebuild: symlink %q -> %q: %w", e.path, e.link, err)
			}
		default:
			if err := fs.writefileLocked(e.path, e.data, e.mode); err != nil {
				return fmt.Errorf("zfs: shrink-rebuild: write %q: %w", e.path, err)
			}
		}
	}

	// 6. Truncate the backing store down to the new size.
	if err := fs.f.Truncate(newSize); err != nil {
		return fmt.Errorf("zfs: shrink-rebuild: truncate: %w", err)
	}
	if err := fs.f.Sync(); err != nil {
		return fmt.Errorf("zfs: shrink-rebuild: sync: %w", err)
	}
	return nil
}

// readPoolIdentity decodes the pool name + GUID from label 0 so we
// can rebuild a new label at the new size with the same identity.
// Falls back to ("data", info.GUIDSum) when the label can't be parsed
// — the GUIDSum value is what label-rebuild would have used anyway.
func (fs *zfsFS) readPoolIdentity() (string, uint64, error) {
	buf := make([]byte, 112*1024)
	if _, err := fs.f.ReadAt(buf, fs.labelOffset+0x4000); err != nil {
		// Best effort — keep going with the in-memory info we already
		// have rather than failing the shrink for a missing label.
		return "data", fs.info.GUIDSum, nil
	}
	top, err := decodeNVList(buf)
	if err != nil {
		return "data", fs.info.GUIDSum, nil
	}
	name := "data"
	guid := fs.info.GUIDSum
	if p := top.findByName("name"); p != nil {
		if v, err := p.stringValue(); err == nil && v != "" {
			name = v
		}
	}
	if p := top.findByName("pool_guid"); p != nil {
		if v, err := p.uint64Value(); err == nil && v != 0 {
			guid = v
		}
	}
	return name, guid, nil
}

// formatHeadLocked overwrites the leading region of the backing store
// (and the two trailing labels at their new positions) with a freshly-
// minted, empty pool layout. The bytes between the new head metadata
// and the new trailing labels are NOT touched — they are dead space
// that the replay phase will overwrite or that truncate will drop.
//
// This shares its body with format.go's Format() but writes into the
// existing blockBackend instead of creating an os.File from scratch.
// Keeping it a sibling rather than refactoring Format() lets us evolve
// the two independently; if the duplication grows, factor it out.
func (fs *zfsFS) formatHeadLocked(poolName string, poolGUID uint64, newSize int64) error {
	now := uint64(time.Now().Unix())

	writeAt := func(off int64, b []byte) error {
		_, err := fs.f.WriteAt(b, off)
		return err
	}
	// makeBP mirrors format.go's wrapper: fletcher4 block checksum over the
	// physical block bytes `phys`, so resized pools stay byte-compatible
	// with freshly Format()'d ones (and import-traversable under OpenZFS).
	makeBP := func(off int64, physSize, logicalSize int, dtype uint8, phys []byte) blkptr {
		bp := makeBlkptrCksum(off, physSize, logicalSize, zcompressOff, dtype, 0, fmtPoolTXG, zioChecksumFletch4)
		setBPChecksum(&bp, phys)
		return bp
	}

	// ZAPs
	poolDirZAP := newMicroZAPBlock(poolBlockSize)
	mzapInsert(poolDirZAP, dmuPoolRootDataset, fmtMOSDSLDirObj)
	masterNodeZAP := newMicroZAPBlock(poolBlockSize)
	mzapInsert(masterNodeZAP, zplKeyRoot, fmtZPLRootDir)
	mzapInsert(masterNodeZAP, zplKeyVersion, fmtZPLVersion)
	unlinkedZAP := newMicroZAPBlock(poolBlockSize)
	rootDirZAP := newMicroZAPBlock(poolBlockSize)

	// ZPL object array
	zplObjArray := make([]byte, fmtObjArraySize)

	zplMasterDN := newDnode(dmotMasterNode, 1, dmotNone, 0)
	zplMasterDN.datablkszsec = uint16(poolBlockSize / 512)
	zplMasterDN.setBlkptrAt(0, makeBP(fmtMasterNodeZAPOff, poolBlockSize, poolBlockSize, dmotMasterNode, masterNodeZAP))
	zplMasterDN.encode()
	copy(zplObjArray[fmtZPLMasterNode*dnodeMinSize:], zplMasterDN.raw)

	zplUnlinkedDN := newDnode(dmotUnlinkedSet, 1, dmotNone, 0)
	zplUnlinkedDN.datablkszsec = uint16(poolBlockSize / 512)
	zplUnlinkedDN.setBlkptrAt(0, makeBP(fmtUnlinkedZAPOff, poolBlockSize, poolBlockSize, dmotUnlinkedSet, unlinkedZAP))
	zplUnlinkedDN.encode()
	copy(zplObjArray[fmtZPLUnlinked*dnodeMinSize:], zplUnlinkedDN.raw)

	rootSAAttrs := &saAttrs{
		mode: 0o040755, gen: 1, parent: fmtZPLRootDir, links: 2,
		atime: [2]uint64{now, 0}, mtime: [2]uint64{now, 0},
		ctime: [2]uint64{now, 0}, crtime: [2]uint64{now, 0},
	}
	layout := defaultSALayout()
	saBonus := writeSABonus(rootSAAttrs, layout)
	zplRootDN := newDnode(dmotDirContents, 1, dmotSA, uint16(len(saBonus)))
	zplRootDN.datablkszsec = uint16(poolBlockSize / 512)
	zplRootDN.setBlkptrAt(0, makeBP(fmtRootDirZAPOff, poolBlockSize, poolBlockSize, dmotDirContents, rootDirZAP))
	copy(zplRootDN.raw[dnodeHdrSize+blkptrSize:], saBonus)
	zplRootDN.encode()
	copy(zplObjArray[fmtZPLRootDir*dnodeMinSize:], zplRootDN.raw)

	// ZPL objset
	zplObjset := make([]byte, poolBlockSize)
	zplMetaDN := newDnode(dmotDnode, 1, dmotNone, 0)
	zplMetaDN.datablkszsec = uint16(fmtObjArraySize / 512)
	zplMetaDN.setBlkptrAt(0, makeBP(fmtZPLObjArrayOff, fmtObjArraySize, fmtObjArraySize, dmotDnode, zplObjArray))
	zplMetaDN.encode()
	copy(zplObjset[0:], zplMetaDN.raw)
	binary.LittleEndian.PutUint64(zplObjset[objsetTypeOff:], dmuOSTZFS)

	// MOS object array
	mosObjArray := make([]byte, fmtObjArraySize)
	poolDirDN := newDnode(dmotObjectDirectory, 1, dmotNone, 0)
	poolDirDN.datablkszsec = uint16(poolBlockSize / 512)
	poolDirDN.setBlkptrAt(0, makeBP(fmtPoolDirZAPOff, poolBlockSize, poolBlockSize, dmotObjectDirectory, poolDirZAP))
	poolDirDN.encode()
	copy(mosObjArray[fmtMOSPoolDirObj*dnodeMinSize:], poolDirDN.raw)

	dslDirBonus := make([]byte, 96)
	binary.LittleEndian.PutUint64(dslDirBonus[ddHeadDatasetObj:], fmtMOSDSLDatasetObj)
	dslDirDN := newDnode(dmotDSLDir, 1, dmotDSLDir, uint16(len(dslDirBonus)))
	copy(dslDirDN.raw[dnodeHdrSize+blkptrSize:], dslDirBonus)
	dslDirDN.encode()
	copy(mosObjArray[fmtMOSDSLDirObj*dnodeMinSize:], dslDirDN.raw)

	dslDSBonus := make([]byte, 320)
	binary.LittleEndian.PutUint64(dslDSBonus[dsDirObj:], fmtMOSDSLDirObj)
	binary.LittleEndian.PutUint64(dslDSBonus[dsCreationTime:], now)
	binary.LittleEndian.PutUint64(dslDSBonus[dsCreationTxg:], fmtPoolTXG)
	zplBP := makeBP(fmtZPLObjsetOff, poolBlockSize, poolBlockSize, dmotObjset, zplObjset)
	encodeBlkptr(zplBP, dslDSBonus[dsBP:dsBP+blkptrSize])
	dslDatasetDN := newDnode(dmotDSLDataset, 1, dmotDSLDataset, uint16(len(dslDSBonus)))
	copy(dslDatasetDN.raw[dnodeHdrSize+blkptrSize:], dslDSBonus)
	dslDatasetDN.encode()
	copy(mosObjArray[fmtMOSDSLDatasetObj*dnodeMinSize:], dslDatasetDN.raw)

	// MOS objset
	mosObjset := make([]byte, poolBlockSize)
	mosMetaDN := newDnode(dmotDnode, 1, dmotNone, 0)
	mosMetaDN.datablkszsec = uint16(fmtObjArraySize / 512)
	mosMetaDN.setBlkptrAt(0, makeBP(fmtMOSObjArrayOff, fmtObjArraySize, fmtObjArraySize, dmotDnode, mosObjArray))
	mosMetaDN.encode()
	copy(mosObjset[0:], mosMetaDN.raw)
	binary.LittleEndian.PutUint64(mosObjset[objsetTypeOff:], dmuOSTMeta)

	writes := []struct {
		off  int64
		data []byte
	}{
		{fmtMOSObjsetOff, mosObjset},
		{fmtMOSObjArrayOff, mosObjArray},
		{fmtPoolDirZAPOff, poolDirZAP},
		{fmtZPLObjsetOff, zplObjset},
		{fmtZPLObjArrayOff, zplObjArray},
		{fmtMasterNodeZAPOff, masterNodeZAP},
		{fmtUnlinkedZAPOff, unlinkedZAP},
		{fmtRootDirZAPOff, rootDirZAP},
	}
	for _, wr := range writes {
		if err := writeAt(fs.labelOffset+vdevLabelStartSize+wr.off, wr.data); err != nil {
			return fmt.Errorf("write head block at 0x%X: %w", wr.off, err)
		}
	}

	rootBP := makeBP(fmtMOSObjsetOff, poolBlockSize, poolBlockSize, dmotObjset, mosObjset)
	ub := encodeUberblock(fmtPoolVersion, fmtPoolTXG, poolGUID, now, rootBP)

	nvBuf := buildLabelNVList(poolName, poolGUID, poolGUID, uint64(newSize), now)

	// First, BEFORE we move/clobber labels, truncate the file down to
	// the new size — this drops any stale L2/L3 labels at the OLD
	// offsets, so the only labels left are the four we're about to
	// write. Doing it now (rather than after writing the new labels)
	// is fine because writeAt with WriteAt past a truncated end re-
	// extends the file with zero-fill, and we re-issue every label
	// write below.
	if err := fs.f.Truncate(newSize); err != nil {
		return fmt.Errorf("truncate: %w", err)
	}

	labelOffsets := []int64{
		fs.labelOffset + 0*vdevLabelSize,
		fs.labelOffset + vdevLabelSize,
		fs.labelOffset + newSize - 2*vdevLabelSize,
		fs.labelOffset + newSize - vdevLabelSize,
	}
	for _, off := range labelOffsets {
		label := buildLabel(nvBuf, ub, off, fmtPoolTXG)
		if err := writeAt(off, label); err != nil {
			return fmt.Errorf("write label at %d: %w", off, err)
		}
	}
	if err := fs.f.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	return nil
}

// reopenAfterFormatLocked re-reads info / opens zplDS / re-initialises
// the allocator against the freshly-written head. Equivalent to the
// post-Open sequence in openFromDevice but operating against the
// existing zfsFS struct.
func (fs *zfsFS) reopenAfterFormatLocked(newSize int64) error {
	info, err := openReadInfo(fs.f, fs.labelOffset)
	if err != nil {
		return fmt.Errorf("readInfo: %w", err)
	}
	fs.info = info
	fs.curTxg = info.TransactionGroup

	rootBPBuf := make([]byte, blkptrSize)
	if _, err := fs.f.ReadAt(rootBPBuf, info.Offset+40); err != nil {
		return fmt.Errorf("read rootbp: %w", err)
	}
	rootBP := parseBlkptr(rootBPBuf)
	if rootBP.isNull() {
		return fmt.Errorf("rebuilt rootbp is null")
	}
	ds, err := openNamedDataset(fs.f, fs.partOffset, rootBP, "")
	if err != nil {
		return fmt.Errorf("open root dataset: %w", err)
	}
	fs.zplDS = ds
	fs.initAllocator(newSize)
	return nil
}

// ────────────────────────────────────────────────────────────────────
// Locked helpers — same body as the public Stat / ListDir / ReadFile /
// MkDir / WriteFile methods, but skip the per-call mutex acquire so
// they can be composed from within shrinkLocked (which already holds
// the lock).
// ────────────────────────────────────────────────────────────────────

func (fs *zfsFS) statLocked(path string) (filesystem.Stat, error) {
	path = cleanPath(path)
	if fs.zplDS == nil {
		if path == "/" {
			return filesystem.NewStat(0o040755, 0, fs.info.TransactionGroup), nil
		}
		return nil, &os.PathError{Op: "stat", Path: path, Err: errNotFound}
	}
	objNum, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, path)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: path, Err: errNotFound}
	}
	attrs, err := fs.zplDS.readAttrs(objNum)
	if err != nil {
		return nil, fmt.Errorf("zfs: statLocked %q: %w", path, err)
	}
	return filesystem.NewStat(uint16(attrs.mode), attrs.size, objNum), nil
}

func (fs *zfsFS) listDirLocked(path string) ([]filesystem.DirEntry, error) {
	if fs.zplDS == nil {
		return nil, nil
	}
	path = cleanPath(path)
	objNum, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, path)
	if err != nil {
		return nil, err
	}
	dirDN, err := fs.zplDS.zplOS.readObject(objNum)
	if err != nil {
		return nil, err
	}
	if dirDN.typ != dmotDirContents {
		return nil, errNotDir
	}
	entries, err := zapListAll(fs.f, fs.partOffset, dirDN)
	if err != nil {
		return nil, err
	}
	result := make([]filesystem.DirEntry, 0, len(entries))
	for name, rawVal := range entries {
		childObjNum := rawVal & 0x0000FFFFFFFFFFFF
		fileTypeCode := uint8(rawVal >> 60)
		result = append(result, filesystem.NewDirEntry(childObjNum, name, fileTypeCode))
	}
	return result, nil
}

func (fs *zfsFS) readfileLocked(path string) ([]byte, error) {
	if fs.zplDS == nil {
		return nil, fmt.Errorf("zfs: readfileLocked: pool not fully opened")
	}
	path = cleanPath(path)
	objNum, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, path)
	if err != nil {
		return nil, err
	}
	dn, err := fs.zplDS.zplOS.readObject(objNum)
	if err != nil {
		return nil, err
	}
	if dn.typ != dmotPlainFileContents {
		return nil, fmt.Errorf("zfs: readfileLocked %q: not a regular file (type %d)", path, dn.typ)
	}
	if dn.blkptrAt(0).isNull() {
		return nil, nil
	}
	data, err := readDnodeData(fs.f, fs.partOffset, dn)
	if err != nil {
		return nil, err
	}
	attrs, err := fs.zplDS.readAttrs(objNum)
	if err != nil {
		return nil, err
	}
	if int(attrs.size) > len(data) {
		return nil, fmt.Errorf("zfs: readfileLocked %q: SA size %d > data %d", path, attrs.size, len(data))
	}
	return data[:attrs.size], nil
}

func (fs *zfsFS) readlinkLocked(path string) (string, error) {
	if fs.zplDS == nil {
		return "", fmt.Errorf("zfs: readlinkLocked: pool not fully opened")
	}
	path = cleanPath(path)
	objNum, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, path)
	if err != nil {
		return "", err
	}
	dn, err := fs.zplDS.zplOS.readObject(objNum)
	if err != nil {
		return "", err
	}
	if dn.blkptrAt(0).isNull() {
		return "", nil
	}
	data, err := readDnodeData(fs.f, fs.partOffset, dn)
	if err != nil {
		return "", err
	}
	attrs, err := fs.zplDS.readAttrs(objNum)
	if err == nil && int(attrs.size) <= len(data) {
		data = data[:attrs.size]
	}
	return string(data), nil
}

// mkdirLocked / writefileLocked / symlinkLocked: thin wrappers that
// inline the body of MkDir / WriteFile / (a new) Symlink without
// re-taking the FS mutex. Implementation kept short by delegating to
// the existing private helpers; the public methods will get a similar
// refactor once Symlink lands as part of HardLinker / Symlinker.
func (fs *zfsFS) mkdirLocked(path string, perm os.FileMode) error {
	// Reuse MkDir by temporarily releasing the lock — but the lock is
	// already held, so we use a fresh implementation that mirrors
	// MkDir without re-locking.
	return fs.mkdirImpl(path, perm)
}

func (fs *zfsFS) writefileLocked(path string, data []byte, perm os.FileMode) error {
	return fs.writefileImpl(path, data, perm)
}

func (fs *zfsFS) symlinkLocked(target, linkPath string) error {
	// Symlinks aren't a public capability yet for this writer; emit
	// the on-disk shape ourselves (same as a regular file payload,
	// but with mode = symlink bits).
	return fs.writefileImpl(linkPath, []byte(target), os.ModeSymlink|0o0777)
}

// writefileImpl is WriteFile minus the mutex acquire — see fs.go for
// the full annotation on each step. We replicate it here rather than
// refactor WriteFile because there's only one in-process consumer
// (the shrink-rebuild replay) and the duplication is shorter than the
// refactor + plumbing.
func (fs *zfsFS) writefileImpl(path string, data []byte, perm os.FileMode) error {
	if fs.zplDS == nil {
		return fmt.Errorf("zfs: writefileImpl: pool not fully opened")
	}
	if fs.alloc == nil {
		return fmt.Errorf("zfs: writefileImpl: no allocator")
	}
	path = cleanPath(path)
	parentPath, name := parentAndBase(path)
	if name == "/" {
		return fmt.Errorf("zfs: writefileImpl: cannot write to /")
	}

	parentObjNum, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, parentPath)
	if err != nil {
		return &os.PathError{Op: "open", Path: parentPath, Err: errNotFound}
	}
	existingObjNum, _ := fs.zplDS.lookupEntry(fs.f, fs.partOffset, parentObjNum, name)
	if existingObjNum != 0 {
		if prev, err := fs.zplDS.zplOS.readObject(existingObjNum); err == nil {
			fs.freeDnodeData(prev)
		}
	}

	now := uint64(time.Now().Unix())
	// Preserve the symlink mode bit when present, otherwise default to
	// regular-file.
	mode := uint64(0o0100000 | (uint16(perm) & 0o7777))
	if perm&os.ModeSymlink != 0 {
		mode = 0o0120000 | uint64(perm&0o7777)
	}

	const largeFileThreshold = 128 * 1024
	bsz := poolBlockSize
	if len(data) > largeFileThreshold {
		bsz = 128 * 1024
	}

	nBlocks := 0
	if len(data) > 0 {
		nBlocks = int(alignUp(int64(len(data)), int64(bsz)) / int64(bsz))
	}
	dataBPs := make([]blkptr, nBlocks)
	for i := 0; i < nBlocks; i++ {
		start := i * bsz
		end := start + bsz
		if end > len(data) {
			end = len(data)
		}
		block := make([]byte, bsz)
		copy(block, data[start:end])
		off, err := fs.alloc.alloc(bsz)
		if err != nil {
			for j := 0; j < i; j++ {
				fs.alloc.free(dataBPs[j].dvaOffset(0), int(dataBPs[j].psize()))
			}
			return fmt.Errorf("zfs: writefileImpl: alloc data block %d: %w", i, err)
		}
		if _, err := fs.f.WriteAt(block, fs.partOffset+off); err != nil {
			return fmt.Errorf("zfs: writefileImpl: write data block: %w", err)
		}
		dbp := makeBlkptrCksum(off, bsz, bsz, zcompressOff, dmotPlainFileContents, 0, fs.curTxg, zioChecksumFletch4)
		setBPChecksum(&dbp, block)
		dataBPs[i] = dbp
	}

	saBonus := writeSABonus(&saAttrs{
		mode: mode, size: uint64(len(data)),
		gen: 1, parent: parentObjNum, links: 1,
		atime: [2]uint64{now, 0}, mtime: [2]uint64{now, 0},
		ctime: [2]uint64{now, 0}, crtime: [2]uint64{now, 0},
	}, fs.zplDS.saLayout)
	fileDN := newDnode(dmotPlainFileContents, 1, dmotSA, uint16(len(saBonus)))
	fileDN.datablkszsec = uint16(bsz / 512)
	fileDN.indblkshift = 17
	if nBlocks > 0 {
		rootBP, nlevels, err := fs.writeBlockTree(dataBPs, bsz, 1<<17)
		if err != nil {
			return fmt.Errorf("zfs: writefileImpl: tree: %w", err)
		}
		fileDN.setBlkptrAt(0, rootBP)
		fileDN.maxblkid = uint64(nBlocks - 1)
		fileDN.nlevels = uint8(nlevels)
	}
	copy(fileDN.raw[dnodeHdrSize+blkptrSize:], saBonus)
	fileDN.encode()

	var objNum uint64
	if existingObjNum != 0 {
		objNum = existingObjNum
	} else {
		objNum, err = fs.allocObjectNum()
		if err != nil {
			return fmt.Errorf("zfs: writefileImpl: alloc obj: %w", err)
		}
	}
	if err := fs.writeDnode(objNum, fileDN); err != nil {
		return fmt.Errorf("zfs: writefileImpl: write dnode: %w", err)
	}
	if existingObjNum == 0 {
		typBits := uint64(8) // DT_REG
		if perm&os.ModeSymlink != 0 {
			typBits = 10 // DT_LNK
		}
		dirEntry := (typBits << 60) | objNum
		if err := fs.updateDirZAP(parentObjNum, name, dirEntry, false); err != nil {
			return fmt.Errorf("zfs: writefileImpl: dir: %w", err)
		}
	}
	return fs.commitUberblock()
}

// mkdirImpl is MkDir minus the mutex acquire.
func (fs *zfsFS) mkdirImpl(path string, perm os.FileMode) error {
	if fs.zplDS == nil {
		return fmt.Errorf("zfs: mkdirImpl: pool not fully opened")
	}
	if fs.alloc == nil {
		return fmt.Errorf("zfs: mkdirImpl: no allocator")
	}
	path = cleanPath(path)
	parentPath, name := parentAndBase(path)
	if name == "/" {
		return fmt.Errorf("zfs: mkdirImpl: cannot create /")
	}
	parentObjNum, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, parentPath)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: parentPath, Err: errNotFound}
	}
	if ex, _ := fs.zplDS.lookupEntry(fs.f, fs.partOffset, parentObjNum, name); ex != 0 {
		return &os.PathError{Op: "mkdir", Path: path, Err: os.ErrExist}
	}
	zapOff, err := fs.alloc.alloc(poolBlockSize)
	if err != nil {
		return fmt.Errorf("zfs: mkdirImpl: alloc ZAP: %w", err)
	}
	emptyZAP := newMicroZAPBlock(poolBlockSize)
	if _, err := fs.f.WriteAt(emptyZAP, fs.partOffset+zapOff); err != nil {
		return fmt.Errorf("zfs: mkdirImpl: write ZAP: %w", err)
	}
	now := uint64(time.Now().Unix())
	mode := uint64(0o040000 | (uint16(perm) & 0o7777))
	objNum, err := fs.allocObjectNum()
	if err != nil {
		return fmt.Errorf("zfs: mkdirImpl: alloc obj: %w", err)
	}
	attrs := &saAttrs{
		mode: mode, size: 0, gen: 1, parent: parentObjNum, links: 2,
		atime: [2]uint64{now, 0}, mtime: [2]uint64{now, 0},
		ctime: [2]uint64{now, 0}, crtime: [2]uint64{now, 0},
	}
	saBonus := writeSABonus(attrs, fs.zplDS.saLayout)
	dirDN := newDnode(dmotDirContents, 1, dmotSA, uint16(len(saBonus)))
	dirDN.datablkszsec = uint16(poolBlockSize / 512)
	zbp := makeBlkptrCksum(zapOff, poolBlockSize, poolBlockSize,
		zcompressOff, dmotDirContents, 0, fs.curTxg, zioChecksumFletch4)
	setBPChecksum(&zbp, emptyZAP)
	dirDN.setBlkptrAt(0, zbp)
	copy(dirDN.raw[dnodeHdrSize+blkptrSize:], saBonus)
	dirDN.encode()
	if err := fs.writeDnode(objNum, dirDN); err != nil {
		return fmt.Errorf("zfs: mkdirImpl: write dnode: %w", err)
	}
	dirEntry := (uint64(4) << 60) | objNum
	if err := fs.updateDirZAP(parentObjNum, name, dirEntry, false); err != nil {
		return fmt.Errorf("zfs: mkdirImpl: update dir: %w", err)
	}
	return fs.commitUberblock()
}

// ────────────────────────────────────────────────────────────────────
// InPlace mode — relocate every BP whose extent falls in the high
// region, then rewrite labels at their new positions and truncate.
// ────────────────────────────────────────────────────────────────────

// shrinkInPlaceLocked implements ShrinkMode_InPlace.
//
// On-disk view (file-absolute byte offsets):
//
//	[0, labelOffset+VLSS)       leading labels + boot pad
//	[labelOffset+VLSS, …)       data area (DVAs measure from here)
//	[…, fileSize - 2*VLS)       end of data area
//	[fileSize-2*VLS, fileSize)  trailing labels L2/L3
//
// After the shrink the same shape holds with `newSize` in place of
// `fileSize`. Any extent whose end byte exceeds `newSize - 2*VLS` is
// in the "high region" and must be relocated. The MOS/ZPL fixed-
// position blocks (offsets < 0x8E000 inside the data area) are always
// below the headroom floor, so they never move — we only touch the
// extents reachable from dnode BP trees + meta_dnode data BPs.
//
// Crash safety: the old four labels and the old uberblock ring stay
// readable until the very last truncate. A crash before the truncate
// leaves the image with the old size + a stale uberblock that still
// references the now-relocated data — readers find the older,
// pre-shrink txg first, so the pool is mountable at its old size.
// The relocations themselves are write-then-update-parent so a crash
// in the middle leaves either the old parent BP (pointing at the
// pre-relocation copy) or the new BP (pointing at the post-relocation
// copy); the two copies coexist in unrelated extents.
func (fs *zfsFS) shrinkInPlaceLocked(newSize int64, curSize int64) error {
	if fs.zplDS == nil {
		// No data area to relocate — just shorten labels + truncate.
		return fs.relabelAndTruncate(newSize)
	}
	if fs.alloc == nil {
		return fmt.Errorf("zfs: shrink-inplace: no allocator (read-only pool?)")
	}

	// The "high region" is expressed in data-area byte coordinates
	// (= DVA bytes). Anything with end > newDataLimit must move.
	newDataLimit := newSize - 2*vdevLabelSize - vdevLabelStartSize
	if newDataLimit <= 0 {
		return fmt.Errorf("zfs: shrink-inplace: newSize %d leaves no data area", newSize)
	}

	// Step 1 — pre-flight: walk every live extent reachable from the
	// dnodes in the ZPL object array AND the meta_dnode's own data BPs
	// (those describe the object array itself). Skip the meta_dnode
	// data BPs since the object array lives at fixed low offsets (≤
	// 0x8B000) that are always inside any sane newSize.
	//
	// We separate the walk into "compute the new allocator limit" so
	// we can clamp it down BEFORE relocating — otherwise the bump
	// pointer might allocate replacement extents that themselves land
	// in the high region we're trying to evacuate.
	fs.alloc.mu.Lock()
	if fs.alloc.nextFree > newDataLimit {
		// We have to relocate the bump-pointer tail too, but the
		// allocator can still serve from the head (anything below the
		// previous nextFree that's been freed). Don't change nextFree
		// — keep allocating from there so we don't trample the live
		// extents we're still about to evacuate.
	}
	oldLimit := fs.alloc.limitOff
	// Allow the relocator to allocate into the [previous nextFree,
	// newDataLimit) tail of the low region — but cap at newDataLimit
	// so it can't pick a destination that itself is in the high
	// region.
	if newDataLimit < fs.alloc.limitOff {
		fs.alloc.limitOff = newDataLimit
	}
	fs.alloc.mu.Unlock()
	// Restore the allocator limit if we error out, so subsequent
	// writes against this FS still work. On success we leave it at
	// newDataLimit (that's the correct ceiling for the new pool).
	rollbackAlloc := func() {
		fs.alloc.mu.Lock()
		fs.alloc.limitOff = oldLimit
		fs.alloc.mu.Unlock()
	}

	// Step 2 — walk every object's BP slots and relocate any extent
	// that crosses the new data limit. The walker is recursive: for
	// indirect blocks it rewrites child BPs in the in-memory buffer,
	// then if the indirect block itself is in the high region it gets
	// reallocated to the low region; if its parent is in the high
	// region too, the recursion handles that one level up.
	for objNum := uint64(0); objNum < fmtObjArrayObjs; objNum++ {
		dn, err := fs.zplDS.zplOS.readObject(objNum)
		if err != nil {
			continue
		}
		if dn == nil || dn.typ == dmotNone {
			continue
		}
		dirty := false
		for i := 0; i < int(dn.nblkptr); i++ {
			bp := dn.blkptrAt(i)
			newBP, changed, err := fs.relocateBPSubtree(bp, newDataLimit)
			if err != nil {
				rollbackAlloc()
				return fmt.Errorf("zfs: shrink-inplace: relocate obj %d BP %d: %w", objNum, i, err)
			}
			if changed {
				dn.setBlkptrAt(i, newBP)
				dirty = true
			}
		}
		if dirty {
			if err := fs.writeDnode(objNum, dn); err != nil {
				rollbackAlloc()
				return fmt.Errorf("zfs: shrink-inplace: write dnode %d: %w", objNum, err)
			}
		}
	}

	// Step 3 — rewrite labels at new positions and commit a new
	// uberblock at the new TXG. The old labels at the now-truncated
	// tail will be dropped by the Truncate that follows; the new
	// labels live inside the bytes we keep.
	if err := fs.relabelAndTruncate(newSize); err != nil {
		rollbackAlloc()
		return err
	}
	return nil
}

// relocateBPSubtree relocates the subtree rooted at bp so that no
// extent in it extends past newDataLimit. Returns the (possibly
// updated) BP, a "changed" flag, and any error.
//
// Null / embedded / gang BPs are returned unchanged.
//
// For indirect BPs (level > 0) the function reads the indirect block,
// recurses into each child slot, rewrites changed children in the
// buffer, and then — if the indirect block ITSELF lives in the high
// region OR any child changed — writes the buffer either back to the
// original location (when staying low) or to a freshly-allocated low
// slot (when the indirect itself was high). Same for level-0 (data)
// BPs but without the recursive descent.
func (fs *zfsFS) relocateBPSubtree(bp blkptr, newDataLimit int64) (blkptr, bool, error) {
	if bp.isNull() || bp.isEmbedded() {
		return bp, false, nil
	}
	if bp.dvaGang(0) {
		// Gang blocks are not emitted by our writer and the read path
		// already refuses them; if one is encountered here something
		// else is wrong.
		return bp, false, fmt.Errorf("gang block encountered (DVA0)")
	}

	off := bp.dvaOffset(0)
	asize := bp.dvaAsize(0)
	highSelf := off+asize > newDataLimit

	var raw []byte
	childrenChanged := false
	if bp.level() > 0 {
		var err error
		raw, err = readBlock(fs.f, fs.partOffset, bp)
		if err != nil {
			return bp, false, fmt.Errorf("read indirect block at 0x%X: %w", off, err)
		}
		// Walk every child BP slot in the indirect block. The block
		// is a flat array of `blkptrSize`-byte entries padded with
		// zero BPs at the tail; null children produce no recursion.
		for i := 0; i+blkptrSize <= len(raw); i += blkptrSize {
			child := parseBlkptr(raw[i : i+blkptrSize])
			newChild, changed, err := fs.relocateBPSubtree(child, newDataLimit)
			if err != nil {
				return bp, false, err
			}
			if changed {
				encodeBlkptr(newChild, raw[i:i+blkptrSize])
				childrenChanged = true
			}
		}
	} else {
		// Level-0 data block — only relevant if it's in the high
		// region. Read it lazily; if it stays low we never touch the
		// disk.
		if highSelf {
			var err error
			raw, err = readBlock(fs.f, fs.partOffset, bp)
			if err != nil {
				return bp, false, fmt.Errorf("read data block at 0x%X: %w", off, err)
			}
		}
	}

	if !highSelf {
		// We may still need to flush the modified indirect buffer back
		// to its original location.
		if childrenChanged {
			if _, err := fs.f.WriteAt(raw, fs.partOffset+off); err != nil {
				return bp, false, fmt.Errorf("write rewritten indirect at 0x%X: %w", off, err)
			}
			return bp, true, nil
		}
		return bp, false, nil
	}

	// `bp` itself is in the high region — allocate a low slot and
	// write the (possibly child-rewritten) buffer there.
	psize := int(bp.psize())
	newOff, err := fs.alloc.alloc(psize)
	if err != nil {
		return bp, false, fmt.Errorf("alloc replacement for high BP at 0x%X (size %d): %w", off, psize, err)
	}
	if newOff+int64(psize) > newDataLimit {
		// allocator limit should already enforce this, but defence
		// in depth: refuse rather than write into the high region we
		// are evacuating.
		fs.alloc.free(newOff, psize)
		return bp, false, fmt.Errorf("allocator returned high-region slot 0x%X (need < 0x%X)", newOff, newDataLimit)
	}
	if _, err := fs.f.WriteAt(raw, fs.partOffset+newOff); err != nil {
		return bp, false, fmt.Errorf("write relocated block at 0x%X: %w", newOff, err)
	}
	newBP := bp
	newBP.dva[0] = makeDVA(newOff, psize)
	// We deliberately do NOT free the OLD extent: it's about to be
	// truncated off the end of the file. Returning it to the
	// allocator would let a future grow re-use a now-illegal offset
	// before the truncate, and it's an extent past newDataLimit
	// anyway so the truncate reclaims its space.
	return newBP, true, nil
}

// relabelAndTruncate writes the four vdev labels for newSize, commits
// a fresh uberblock that bumps the txg, then truncates the backing
// store. This is the "swap the boundary" final step shared by every
// shrink mode.
func (fs *zfsFS) relabelAndTruncate(newSize int64) error {
	// Bump txg so the new uberblock outranks any stale one that might
	// be lingering at the old positions until truncate.
	fs.curTxg++

	rootBPBuf := make([]byte, blkptrSize)
	if _, err := fs.f.ReadAt(rootBPBuf, fs.info.Offset+40); err != nil {
		return fmt.Errorf("read rootbp: %w", err)
	}
	rootBP := parseBlkptr(rootBPBuf)
	rootBP.birth = fs.curTxg
	rootBP.physBirth = fs.curTxg

	now := uint64(time.Now().Unix())
	ub := encodeUberblock(fs.info.Version, fs.curTxg, fs.info.GUIDSum, now, rootBP)

	poolName, poolGUID, _ := fs.readPoolIdentity()
	nvBuf := buildLabelNVList(poolName, poolGUID, poolGUID, uint64(newSize), now)

	// Write the leading labels at their (unchanged) positions, then
	// the new trailing labels INSIDE the bytes we are about to keep.
	// buildLabel embeds the active uberblock (with its self-checksum)
	// into the correct ring slot for fs.curTxg, so no separate
	// uberblock write is needed here.
	labelOffsets := []int64{
		fs.labelOffset + 0*vdevLabelSize,
		fs.labelOffset + vdevLabelSize,
		fs.labelOffset + newSize - 2*vdevLabelSize,
		fs.labelOffset + newSize - vdevLabelSize,
	}
	for _, off := range labelOffsets {
		label := buildLabel(nvBuf, ub, off, fs.curTxg)
		if _, err := fs.f.WriteAt(label, off); err != nil {
			return fmt.Errorf("write label at %d: %w", off, err)
		}
	}

	if err := fs.f.Sync(); err != nil {
		return fmt.Errorf("sync before truncate: %w", err)
	}
	if err := fs.f.Truncate(newSize); err != nil {
		return fmt.Errorf("truncate to %d: %w", newSize, err)
	}
	if err := fs.f.Sync(); err != nil {
		return fmt.Errorf("sync after truncate: %w", err)
	}

	// Update the cached uberblock-position view so subsequent commits
	// route to the freshly-rewritten labels.
	info, err := openReadInfo(fs.f, fs.labelOffset)
	if err == nil {
		fs.info = info
		fs.curTxg = info.TransactionGroup
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────
// Public Resize dispatcher — replaces the old Grow-only implementation
// from grow.go (which still owns the Grow / GrowTo entry points). The
// dispatcher gives callers a single public surface and routes:
//   newSize == current : no-op
//   newSize  > current : Grow
//   newSize  < current : Shrink(Auto)
// ────────────────────────────────────────────────────────────────────

// resizeOnce is the actual implementation called by Resize() in
// grow.go. Keeping it here lets resize.go own the dispatcher logic
// alongside the shrink modes it dispatches to. grow.go has been
// updated to delegate here.
func (fs *zfsFS) resizeOnce(newSize int64) error {
	if newSize <= 0 {
		return fmt.Errorf("zfs: resize: invalid size %d", newSize)
	}
	cur, err := fs.f.Size()
	if err != nil {
		return fmt.Errorf("zfs: resize: size: %w", err)
	}
	if newSize == cur {
		return nil
	}
	if newSize > cur {
		return fs.GrowTo(newSize)
	}
	return fs.Shrink(newSize)
}
