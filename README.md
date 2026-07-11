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
| Snapshots | ✅ | Create via `FS.Snapshot`, read via `OpenSnapshot`, remove via `FS.DestroySnapshot` |
| Clones | ✅ | Create writable dataset from a snapshot via `FS.Clone`; `FS.Origin` reports the origin; dependent-clone tracking blocks snapshot destroy |
| Compression | ✅ Read | Transparent decompress on read (lz4 / gzip / zstd / lzjb / zle) |
| Native encryption | ✅ Read | AES-CCM/GCM datasets via `OpenFromDeviceDatasetWithKey` (passphrase or raw wrapping key) |


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

### Snapshots and clones

```go
// Snapshot freezes the currently-open dataset; read it back via OpenSnapshot.
func (fs *FS) Snapshot(snapName string) error

// Clone creates a writable dataset from a snapshot. Reach it via OpenDataset.
func (fs *FS) Clone(snapName, cloneName string) error

// Origin returns "<pool>@<snapshot>" for a clone, or "" for a non-clone.
func (fs *FS) Origin() (string, error)

// DestroySnapshot removes a snapshot; it fails if the snapshot has dependent
// clones (a snapshot with clones cannot be destroyed).
func (fs *FS) DestroySnapshot(snapName string) error
```

A clone is created with a faithful on-disk DSL layout: a `dsl_dir` whose
`dd_origin_obj` points at the origin snapshot, a `dsl_dataset` whose
`ds_prev_snap_obj` references it, registration under the parent DSL dir's child
map, and dependent-clone tracking on the origin snapshot's `ds_next_clones_obj`.
Because this driver is not copy-on-write, a clone eagerly deep-copies the
snapshot's object-set into private blocks (O(dataset size)) rather than sharing
them O(1) as OpenZFS does — the on-disk DSL *structures* match OpenZFS; only the
block-sharing optimisation is replaced by the driver's existing eager-copy
invariant (the same one snapshots use).

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

- Single pool; the writer targets a single dataset (the reader also
  navigates nested datasets and multi-vdev/RAID-Z pools)
- The writer does not compress or encrypt data blocks; the reader
  decompresses (lz4/gzip/zstd/lzjb/zle) and decrypts (native AES-CCM/GCM)
  transparently
- Snapshots and clones are supported (create/read snapshots, create writable
  clones), but as eager block copies rather than O(1) copy-on-write; no ACLs
- Maximum 28 objects (files + directories) per pool image
- Directory names limited to 49 bytes

## Test coverage

~86% statement coverage, enforced by a CI floor. The uncovered
remainder is defensive error handling on rare on-disk corruption paths.
