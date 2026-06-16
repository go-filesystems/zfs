package filesystem_zfs

// metadata.go — POSIX metadata mutators (chmod / chown / chtimes), bundled as
// filesystem.MetadataSetter. ZFS stores these in the dnode's SA bonus; each
// mutator reads the object's dnode and current attributes, edits the relevant
// fields, refreshes ctime, re-encodes the SA bonus in place (the layout is
// fixed, so the length is unchanged and the data block pointers are untouched),
// rewrites the dnode and commits a new uberblock.

import (
	"fmt"
	"os"
	"time"

	filesystem "github.com/go-filesystems/interface"
)

var _ filesystem.MetadataSetter = (*zfsFS)(nil)

// updateObjAttrs resolves path to its object, applies edit to the decoded SA
// attributes, refreshes ctime, and writes the dnode back under a new uberblock.
// Mutating calls require a writable pool.
func (fs *zfsFS) updateObjAttrs(path string, edit func(a *saAttrs)) error {
	if fs.zplDS == nil {
		return fmt.Errorf("zfs: pool not fully opened")
	}
	if fs.alloc == nil {
		return fmt.Errorf("zfs: read-only pool")
	}
	path = cleanPath(path)
	fs.mu.Lock()
	defer fs.mu.Unlock()

	objNum, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, path)
	if err != nil {
		return &os.PathError{Op: "setattr", Path: path, Err: errNotFound}
	}
	dn, err := fs.zplDS.zplOS.readObject(objNum)
	if err != nil {
		return fmt.Errorf("zfs: setattr %q: read object: %w", path, err)
	}
	attrs, err := fs.zplDS.readAttrs(objNum)
	if err != nil {
		return fmt.Errorf("zfs: setattr %q: read attrs: %w", path, err)
	}

	edit(attrs)
	attrs.ctime = [2]uint64{uint64(time.Now().Unix()), 0}

	saBonus := writeSABonus(attrs, fs.zplDS.saLayout)
	bonus := dn.bonusData()
	if len(saBonus) > len(bonus) {
		// The layout is fixed, so this should never happen; guard rather than
		// overrun the dnode's bonus region.
		return fmt.Errorf("zfs: setattr %q: SA bonus %d exceeds dnode bonus %d", path, len(saBonus), len(bonus))
	}
	copy(bonus, saBonus)
	dn.encode() // rewrites only the dnode header; blkptrs + bonus are preserved
	if err := fs.writeDnode(objNum, dn); err != nil {
		return fmt.Errorf("zfs: setattr %q: write dnode: %w", path, err)
	}
	return fs.commitUberblock()
}

// Chmod replaces the permission + setuid/setgid/sticky bits at path, preserving
// the file-type bits. ctime is refreshed.
func (fs *zfsFS) Chmod(path string, perm os.FileMode) error {
	return fs.updateObjAttrs(path, func(a *saAttrs) {
		bits := uint64(perm & 0o777)
		if perm&os.ModeSetuid != 0 {
			bits |= 0o4000
		}
		if perm&os.ModeSetgid != 0 {
			bits |= 0o2000
		}
		if perm&os.ModeSticky != 0 {
			bits |= 0o1000
		}
		a.mode = (a.mode &^ 0o7777) | bits
	})
}

// Chown updates uid/gid at path. ctime is refreshed; mode, body and the other
// timestamps are left alone.
func (fs *zfsFS) Chown(path string, uid, gid uint32) error {
	return fs.updateObjAttrs(path, func(a *saAttrs) {
		a.uid = uint64(uid)
		a.gid = uint64(gid)
	})
}

// Chtimes sets atime and mtime at path. ctime is refreshed to now per POSIX;
// crtime (birth time) is left untouched.
func (fs *zfsFS) Chtimes(path string, atime, mtime time.Time) error {
	return fs.updateObjAttrs(path, func(a *saAttrs) {
		a.atime = [2]uint64{uint64(atime.Unix()), 0}
		a.mtime = [2]uint64{uint64(mtime.Unix()), 0}
	})
}
