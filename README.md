<p align="center"><img src="https://raw.githubusercontent.com/go-filesystems/brand/main/social/go-filesystems-zfs.png" alt="go-filesystems/zfs" width="720"></p>

# zfs

[![Go Reference](https://pkg.go.dev/badge/github.com/go-filesystems/zfs.svg)](https://pkg.go.dev/github.com/go-filesystems/zfs)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![CI](https://github.com/go-filesystems/zfs/actions/workflows/ci.yml/badge.svg)](https://github.com/go-filesystems/zfs/actions/workflows/ci.yml)

A read/write ZFS implementation for bare disk images, supporting a single
pool with a single ZPL dataset. Designed for embedded tooling that needs to
create, inspect, and modify ZFS filesystems programmatically.

## Support summary

| Feature | Status | Notes |
|---|---:|---|
| Open / Close | ✅ | Opens single-pool images |
| Format | ✅ | Creates new pool images via `Format` |
| ReadFile / WriteFile | ✅ | Basic file I/O supported (ZPL dataset) |
| MkDir / Delete / Rename | ✅ | Directory operations supported |
| Snapshots / Clones | ⚠️ No | Not implemented (test-oriented subset) |
| Compression / Checksums | ⚠️ No | Not implemented on data blocks |


## Module

```text
github.com/go-filesystems/zfs
```

## API

### Opening / creating

```go
// Open opens an existing ZFS image. partIndex=-1 uses the whole image.
func Open(imagePath string, partIndex int) (*FS, error)

// Format creates a new ZFS image of sizeBytes at path and opens it.
func Format(path string, sizeBytes int64, cfg FormatConfig) (*FS, error)
```

### Metadata

```go
func (fs *FS) Info() Info   // pool name, GUID, version, TXG, timestamp
```

### File operations

```go
func (fs *FS) ReadFile(path string) ([]byte, error)
func (fs *FS) WriteFile(path string, data []byte, perm os.FileMode) error
func (fs *FS) DeleteFile(path string) error
```

### Directory operations

```go
func (fs *FS) ListDir(path string) ([]filesystem.DirEntry, error)
func (fs *FS) MkDir(path string, perm os.FileMode) error
func (fs *FS) DeleteDir(path string) error
```

### Rename

```go
func (fs *FS) Rename(oldPath, newPath string) error
```

### Closing

```go
func (fs *FS) Close() error
```

## Implements

This package implements the `filesystem.Filesystem` interface defined in
`github.com/go-filesystems/interface`. Example usage:

```go
import (
	filesystem "github.com/go-filesystems/interface"
	fsz "github.com/go-filesystems/zfs"
)

f, _ := fsz.Open("pool.img", -1)
defer f.Close()
var fs filesystem.Filesystem = f
_, _ = fs.ReadFile("/hello.txt")
```

## Image layout

| Offset | Size | Content |
|---|---|---|
| 0 | 256 KiB | Vdev label L0 |
| 256 KiB | 256 KiB | Vdev label L1 |
| 512 KiB | varies | Pool data (MOS, ZPL objset, object arrays, ZAP blocks) |
| end−512 KiB | 256 KiB | Vdev label L2 |
| end−256 KiB | 256 KiB | Vdev label L3 |

Pool data starts at offset `0x080000`. The ZPL object array has 32 slots
(objects 0–31), giving a maximum of 28 user files/directories per pool image.

## Supported ZAP type

Only **micro-ZAP** is supported for directory writes. Directory entries use a
4 KiB block with 63 name slots of up to 49 bytes each.

## Limitations

- Single vdev, single pool, single dataset
- No compression or checksums on data blocks
- No snapshots, clones, or ACLs
- Maximum 28 objects (files + directories) per pool image
- Directory names limited to 49 bytes

## Test coverage

100% statement coverage.
