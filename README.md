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
| Grow / Resize | ✅ | `FS.Grow` / `FS.GrowTo`; `FS.Resize` dispatches to Grow or Shrink based on the requested size |
| Shrink | ✅ | `FS.Shrink` / `FS.ShrinkWithMode` — `ShrinkMode_Rebuild` / `ShrinkMode_InPlace` / `ShrinkMode_Auto` (picks InPlace when the pool is snapshot-free, else Rebuild) |
| Symlinks / hardlinks | ✅ | `filesystem.Symlinker` / `filesystem.HardLinker` (type-assert `FS`) |
| chmod / chown / chtimes | ✅ | `filesystem.MetadataSetter` (type-assert `FS`) |
| Multi-vdev pools (mirror / raidz) | ✅ Read | `OpenFromDevices` — one backend per leaf in on-disk `vdev_tree.children` order; a missing raidz data leg is not yet reconstructed from parity |


## Module

```text
github.com/go-filesystems/zfs
```

## API

`FS` is an interface (not a struct) — every entry point below returns `FS`,
and every method is called through that interface value (`fs.Info()`, not
`(*FS).Info`).

### Opening / creating

```go
// Open opens an existing ZFS image. partIndex=-1 uses the whole image.
func Open(imagePath string, partIndex int) (FS, error)

// Format creates a new ZFS image of sizeBytes at path and opens it.
func Format(path string, sizeBytes int64, cfg FormatConfig) (FS, error)

// OpenDataset opens a specific dataset (by DSL path) inside an existing image.
func OpenDataset(imagePath string, partIndex int, datasetPath string) (FS, error)

// OpenFromDevice / OpenFromDeviceDataset open a pool backed by an arbitrary
// BlockBackend instead of an *os.File-backed image (LUKS/qcow2/in-memory).
func OpenFromDevice(dev BlockBackend, partIndex int) (FS, error)
func OpenFromDeviceDataset(dev BlockBackend, partIndex int, datasetPath string) (FS, error)

// OpenFromDeviceDatasetWithKey opens a native-encrypted dataset. The key
// argument is either a 32-byte raw wrapping key or a passphrase (any other
// length); a passphrase is derived on the fly using the salt/iter count
// stored in the dataset's DSL_CRYPTO_KEY object.
func OpenFromDeviceDatasetWithKey(dev BlockBackend, partIndex int, datasetPath string, key []byte) (FS, error)

// OpenFromDevices opens a multi-vdev (mirror / raidz) pool: one backend per
// leaf, in the same order as the on-disk vdev_tree.children array. A missing
// raidz data leg is not yet reconstructed from parity.
func OpenFromDevices(devs []BlockBackend, partIndex int, datasetPath string) (FS, error)

// OpenSnapshot opens a dataset's frozen snapshot read-only.
func OpenSnapshot(imagePath string, partIndex int, datasetPath, snapName string) (FS, error)
```

### FS interface

```go
type FS interface {
    filesystem.Filesystem // Close, ReadFile, ListDir, Stat, WriteFile, ReadLink,
                           // MkDir, DeleteFile, DeleteDir, Rename

    Info() Info               // uberblock fields: version, TXG, GUID sum, timestamp, label/slot/offset, endian
    PartitionOffset() int64

    // GrowTo / Grow are the grow-only entry points; they reject shrink
    // targets with a wrapped filesystem.ErrShrinkUnsupported.
    GrowTo(newSizeBytes int64) error
    Grow(newSizeBytes int64) error
    // Resize is bidirectional: newSize > current routes to Grow, newSize <
    // current routes to Shrink (in ShrinkMode_Auto).
    Resize(newSize int64) error
    // Shrink / ShrinkWithMode expose the shrink path; ShrinkMode selects the
    // on-disk relocation strategy (Rebuild / InPlace / Auto).
    Shrink(newSize int64) error
    ShrinkWithMode(newSize int64, mode ShrinkMode) error

    Snapshot(snapName string) error
    Clone(snapName, cloneName string) error
    Origin() (string, error)
    DestroySnapshot(snapName string) error
}
```

### Optional capabilities (type-assert)

Symlinks, hardlinks, and POSIX metadata mutators are not part of the `FS`
interface itself — the underlying driver satisfies the corresponding optional
interfaces from `github.com/go-filesystems/interface`, so callers type-assert:

```go
if s, ok := fs.(filesystem.Symlinker); ok {
    _ = s.Symlink("/target", "/link")
}
if h, ok := fs.(filesystem.HardLinker); ok {
    _ = h.Link("/existing", "/newname")
}
if m, ok := fs.(filesystem.MetadataSetter); ok {
    _ = m.Chmod("/file", 0o644)
    _ = m.Chown("/file", 1000, 1000)
    _ = m.Chtimes("/file", atime, mtime)
}
```

### Snapshots and clones

`Snapshot` freezes the currently-open dataset (read it back via
`OpenSnapshot`); `Clone` creates a writable dataset from a snapshot (reach it
via `OpenDataset`); `Origin` returns `"<pool>@<snapshot>"` for a clone or `""`
otherwise; `DestroySnapshot` removes a snapshot, failing if it still has
dependent clones.

A clone is created with a faithful on-disk DSL layout: a `dsl_dir` whose
`dd_origin_obj` points at the origin snapshot, a `dsl_dataset` whose
`ds_prev_snap_obj` references it, registration under the parent DSL dir's child
map, and dependent-clone tracking on the origin snapshot's `ds_next_clones_obj`.
Because this driver is not copy-on-write, a clone eagerly deep-copies the
snapshot's object-set into private blocks (O(dataset size)) rather than sharing
them O(1) as OpenZFS does — the on-disk DSL *structures* match OpenZFS; only the
block-sharing optimisation is replaced by the driver's existing eager-copy
invariant (the same one snapshots use).

`Close()` is part of the embedded `filesystem.Filesystem` interface above.

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
