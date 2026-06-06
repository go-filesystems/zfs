package filesystem_zfs

// util.go – Utility helpers: path manipulation, shared errors.

import (
	"errors"
	"io/fs"
	"path"
	"strings"
)

// errNotFound is returned when a ZFS object or path component is not found.
var errNotFound = errors.New("not found")

// errNotDir is returned when the path component is not a directory.
var errNotDir = errors.New("not a directory")

// errNotEmpty is returned when the directory is not empty.
var errNotEmpty = errors.New("directory not empty")

// errReadOnly is returned when the image was opened without write intent.
var errReadOnly = errors.New("read-only")

// fsErrNotFound wraps errNotFound as an *fs.PathError for the given path.
func fsErrNotFound(op, p string) error {
	return &fs.PathError{Op: op, Path: p, Err: errNotFound}
}

// fsErrNotDir wraps errNotDir as an *fs.PathError for the given path.
func fsErrNotDir(op, p string) error {
	return &fs.PathError{Op: op, Path: p, Err: errNotDir}
}

// cleanPath normalises a POSIX path:
//   - empty → "/"
//   - collapses // and ./ components
//   - ensures leading /
func cleanPath(p string) string {
	if p == "" || p == "." {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	cleaned := path.Clean(p)
	return cleaned
}

// splitPath splits an absolute path into its non-empty components.
// "/" → []
// "/a/b/c" → ["a", "b", "c"]
func splitPath(p string) []string {
	p = cleanPath(p)
	if p == "/" {
		return nil
	}
	parts := strings.Split(p, "/")
	var result []string
	for _, part := range parts {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// parentAndBase splits a path into parent dir and base name.
// "/" → ("", "/"), "/a" → ("/", "a"), "/a/b" → ("/a", "b")
func parentAndBase(p string) (parent, base string) {
	p = cleanPath(p)
	if p == "/" {
		return "", "/"
	}
	i := strings.LastIndex(p, "/")
	if i == 0 {
		return "/", p[1:]
	}
	return p[:i], p[i+1:]
}

// alignUp rounds n up to the nearest multiple of align.
func alignUp(n, align int64) int64 {
	if n%align == 0 {
		return n
	}
	return n + align - n%align
}
