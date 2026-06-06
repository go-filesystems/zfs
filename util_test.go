package filesystem_zfs

import (
	"errors"
	"io/fs"
	"testing"
)

func TestFsErrNotFound(t *testing.T) {
	err := fsErrNotFound("stat", "/missing")
	if err == nil {
		t.Fatal("fsErrNotFound returned nil")
	}
	var pe *fs.PathError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *fs.PathError, got %T", err)
	}
	if pe.Op != "stat" || pe.Path != "/missing" {
		t.Fatalf("PathError = %+v, want op=stat path=/missing", pe)
	}
	if !errors.Is(err, errNotFound) {
		t.Fatalf("errors.Is(err, errNotFound) = false, want true")
	}
}

func TestFsErrNotDir(t *testing.T) {
	err := fsErrNotDir("listdir", "/file.txt")
	if err == nil {
		t.Fatal("fsErrNotDir returned nil")
	}
	var pe *fs.PathError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *fs.PathError, got %T", err)
	}
	if !errors.Is(err, errNotDir) {
		t.Fatalf("errors.Is(err, errNotDir) = false, want true")
	}
}

func TestCleanPath(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", "/"},
		{".", "/"},
		{"/", "/"},
		{"/a/b/c", "/a/b/c"},
		{"a/b/c", "/a/b/c"}, // no leading slash → prepend /
		{"/a//b", "/a/b"},
		{"/a/./b", "/a/b"},
		{"/a/b/.", "/a/b"},
	}
	for _, tc := range tests {
		if got := cleanPath(tc.in); got != tc.want {
			t.Errorf("cleanPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSplitPath(t *testing.T) {
	if parts := splitPath("/"); len(parts) != 0 {
		t.Fatalf("splitPath('/') = %v, want []", parts)
	}
	parts := splitPath("/a/b/c")
	if len(parts) != 3 || parts[0] != "a" || parts[1] != "b" || parts[2] != "c" {
		t.Fatalf("splitPath('/a/b/c') = %v, want [a b c]", parts)
	}
}

func TestParentAndBase(t *testing.T) {
	tests := []struct {
		in, wantParent, wantBase string
	}{
		{"/", "", "/"},
		{"/a", "/", "a"},
		{"/a/b", "/a", "b"},
		{"/a/b/c", "/a/b", "c"},
	}
	for _, tc := range tests {
		p, b := parentAndBase(tc.in)
		if p != tc.wantParent || b != tc.wantBase {
			t.Errorf("parentAndBase(%q) = (%q, %q), want (%q, %q)",
				tc.in, p, b, tc.wantParent, tc.wantBase)
		}
	}
}

func TestAlignUp(t *testing.T) {
	tests := []struct {
		n, align, want int64
	}{
		{0, 4096, 0},
		{1, 4096, 4096},
		{4096, 4096, 4096},
		{4097, 4096, 8192},
	}
	for _, tc := range tests {
		if got := alignUp(tc.n, tc.align); got != tc.want {
			t.Errorf("alignUp(%d, %d) = %d, want %d", tc.n, tc.align, got, tc.want)
		}
	}
}
