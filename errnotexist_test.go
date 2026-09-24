// SPDX-License-Identifier: BSD-3-Clause

package filesystem_zfs

import (
	"errors"
	iofs "io/fs"
	"path/filepath"
	"testing"
)

// ⛔ The error contract from go-filesystems/interface: a path that is not
// there must satisfy errors.Is(err, fs.ErrNotExist).
//
// zfs needed one line, and the reason is worth recording because the other
// three drivers left out of this contract did not.
//
// btrfs and xfs raise ONE sentinel from two unrelated places -- a name missing
// from a directory, and a B-tree or directory-format failure that means the
// image is broken -- so marking the sentinel there would make a server answer
// 404 for corruption. Each needed the marking placed by hand at the path
// boundary.
//
// zfs never mixed them. errNotFound is raised at twenty-six sites and every
// one is a named thing that is not there: stat, listdir, open, readlink,
// mkdir, remove, link, rmdir, rename, setattr, a dataset name, a snapshot
// name, a directory entry. ZAP failures -- a null block pointer, a block too
// small, an unknown block type -- return their own unclassified errors and
// always did. So the sentinel could simply say what it means.
func TestMissingPathsSatisfyErrNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool.img")
	fsys, err := Format(path, 256<<20, FormatConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()

	for _, tc := range []struct {
		what string
		err  error
	}{
		{"Stat", func() error { _, e := fsys.Stat("/nope.txt"); return e }()},
		{"ReadFile", func() error { _, e := fsys.ReadFile("/nope.txt"); return e }()},
		{"ListDir", func() error { _, e := fsys.ListDir("/nope"); return e }()},
		{"ReadLink", func() error { _, e := fsys.ReadLink("/nope"); return e }()},
		{"DeleteFile", fsys.DeleteFile("/nope.txt")},
		{"DeleteDir", fsys.DeleteDir("/nope")},
		{"Rename", fsys.Rename("/nope.txt", "/other.txt")},
		{"MkDir under a missing parent", fsys.MkDir("/nope/child", 0o755)},
		{"WriteFile under a missing parent", fsys.WriteFile("/nope/child", []byte("x"), 0o644)},
	} {
		if tc.err == nil {
			t.Errorf("%s on a missing path returned no error at all", tc.what)
			continue
		}
		if !errors.Is(tc.err, iofs.ErrNotExist) {
			t.Errorf("%s: errors.Is(err, fs.ErrNotExist) is false for %q", tc.what, tc.err)
		}
	}
}

// TestAZapFailureIsNotA404 is the guard that keeps the line above honest. A
// ZAP block that cannot be read means the pool is damaged, not that a file is
// absent; if it ever starts satisfying fs.ErrNotExist, every server in this
// family will report a broken pool as "not found".
func TestAZapFailureIsNotA404(t *testing.T) {
	// A dnode with no block pointers is the shape a truncated or corrupt
	// object takes: zapListAll refuses it before any key is considered.
	_, err := zapLookup(nil, 0, &dnode{}, "anything")
	if err == nil {
		t.Fatal("a ZAP lookup on a dnode with no block pointers returned no error")
	}
	if errors.Is(err, iofs.ErrNotExist) {
		t.Fatalf("a damaged ZAP now reads as fs.ErrNotExist (%v): "+
			"a server will answer 404 for a corrupt pool", err)
	}
}
