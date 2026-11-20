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
| OpenFile (`filesystem.Opener`) | ✅ | Positional reads: each `ReadAt` reads only the data blocks of its window (the indirect blocks are cached per handle); holes read as zeros. A 1 MiB read at 66 MiB of a 72 MiB file allocates 1.1 MB through it and 538 MB through `ReadFile` |
| Parallel reads | ✅ v0.8.0 | The records of a `ReadFile`, of a large or sequential `ReadAt`, are read, checksum-verified (a damaged copy falls back to the block's other DVAs) and decompressed on up to `min(GOMAXPROCS, 8)` goroutines (`inflight.Ordered`); `ReadAt` keeps decoded records in a bounded adaptive cache (`inflight.Cache`). See [Parallel reads](#parallel-reads) |
| MkDir / Delete / Rename | ✅ | Directory operations supported |
| Snapshots | ✅ | Create via `FS.Snapshot`, read via `OpenSnapshot`, remove via `FS.DestroySnapshot` |
| Clones | ✅ | Create writable dataset from a snapshot via `FS.Clone`; `FS.Origin` reports the origin; dependent-clone tracking blocks snapshot destroy |
| Compression | ✅ Read | Transparent decompress on read (lz4 / gzip / zstd / lzjb / zle); lz4 through the shared `go-compressions/lz4` decoder (2036 MiB/s on a 256 MiB lz4 file in an arm64 VM, the kernel 1768) |
| Block checksums | ✅ Verified on read | fletcher4, fletcher2, SHA-256, SHA-512/256 and, keyed with the pool checksum salt (`org.illumos:checksum_salt`, read from the MOS when the dataset is opened), BLAKE3 (`go-compressions/blake3`), Skein (`go-compressions/skein`) and Edon-R (`go-compressions/edonr`) are checked against the block pointer on every read (before decryption and decompression), plain and encrypted; a damaged block is `ErrChecksum`, never data. Tested against pools written by the OpenZFS 2.3.4 kernel (`checksum=blake3|skein|edonr`, plus an encrypted dataset each). fletcher4 is `go-simd/adler32/fletcher4` (AVX-512, AVX2, NEON): 23 GB/s on an M4 Max, 45 GB/s on a Ryzen 7950X |
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

## Untrusted input

An image is attacker-controlled bytes. Every allocation and walk the driver sizes
from a value read off the image is checked against what the image can hold
**before** it happens (tests assert the allocation or the device-read count for
each refused road). Bounds come from the OpenZFS sources (`zio.c`
`zfs_blkptr_verify`, `zap_leaf.c`, `nvpair.c`, `spa.h`).

| Input | Bound |
|---|---|
| block pointer LSIZE / PSIZE | at most `SPA_MAXBLOCKSIZE` (16 MiB), as `zfs_blkptr_verify`; the fields themselves reach 32 MiB |
| embedded block pointer | LSIZE at most 16 MiB; an uncompressed one cannot be longer than its 112-byte payload |
| decompression (lz4, lzjb, zle) | the destination must be reachable from the input at the codec's maximum expansion (255:1, 8:1, 256:1); an lz4 block that would produce more than the logical size is refused (as OpenZFS does) instead of being generated and thrown away |
| gzip | the destination grows with what the stream produces |
| zstd | the frame header is parsed and its declared content size must equal the block's logical size, and the size must be reachable at the format's 32768:1 maximum (RFC 8878: 128 KiB per RLE block of 4 bytes), all before the destination is allocated; window and memory capped at 16 MiB |
| `ReadFile` / `ReadLink` | `dn_maxblkid` is read from the image and a hole costs nothing on disk, so the object is limited to `DefaultMaxReadSize` (1 GiB; `fs.(interface{ SetMaxReadSize(int64) })` changes it) and refused with `ErrTooLarge` before any buffer is sized; the result can never outgrow the limit whatever the block pointers claim |
| indirect blocks | read once per walk, not once per data block (the last block at each level is kept) |
| fat-ZAP leaf | the entries of a leaf are charged against the leaf's chunk count (an entry needing more than the leaf has is invalid, `zap_entry_create`) |
| nvlist label | nesting at most 100 (`nvpair_max_recursion`); nvlist arrays no longer than the bytes they sit in; nested lists share the label's bytes instead of copying them per level |
| RAID-Z `ashift` | 9 to 16 (`ASHIFT_MIN`, `ASHIFT_MAX`) |
| block larger than 128 KiB | read in doubling, aligned chunks, so a pointer past the end of the device costs 128 KiB, not PSIZE (up to 16 MiB) per pointer |
| indirect block geometry | `dn_nlevels` and `dn_indblkshift` come from the image: the coverage of a root pointer is kept as a shift, since 2^(shift x levels) overflows 64 bits |

Fuzz targets: `FuzzDecompressBlock`, `FuzzReadEmbedded`, `FuzzNVList`,
`FuzzZAPLeaf`, `FuzzDnodeWalk`, `FuzzVdevLabel` (allocation stays proportional
to the input), plus the existing `FuzzParseFatZAPLeaf`, `FuzzParseFatZAP`,
`FuzzReadDnodeData`, `FuzzPartitionOffset` and `FuzzOpen`.

## Parallel reads

Records are independent once their block pointers are known, so a read resolves
the pointers of a window of records (serial, through the indirect-block cache) and
hands them to `inflight.Ordered`, which runs `readBlock` on up to
`min(GOMAXPROCS, 8)` goroutines and returns the records in file order, at most
that many in flight. `readBlock` does all the work of a record: device read,
checksum verification (fletcher4 SIMD, SHA-256/512, BLAKE3, Skein, Edon-R), the
fall-back to another DVA when a copy fails its checksum, decryption, decompression.
Nothing is skipped to go faster, and the first error in file order is the one
returned. `ReadFile` decodes a window of 16 records per worker at a time. `ReadAt`
decodes the records it spans in parallel, and, when it continues the previous
`ReadAt` (a sequential reader), the next 2 x workers records into a cache shared by
the pool's open files: `inflight.Cache`, the adaptive cache of squashfs v0.9.0, 8
MiB to start, growing (to 256 MiB) only when a record it evicted is asked for
again; any write to the pool empties it. Knobs, by type assertion on the
`filesystem.Filesystem`: `SetReadParallelism(n)` (n <= 1 decodes serially; default
`min(GOMAXPROCS, 8)`) and `SetMaxDataCache(bytes)`. A `BlockBackend` you supply
must allow concurrent `ReadAt` calls, as `io.ReaderAt` asks (before v0.8.0 the
calls were serialised). Bounds and caveats: a read is served a window of 16 x
workers records at a time; up to that many decoded records (16 MiB each at most)
are in flight beyond `SetMaxReadSize`'s ceiling, which is checked as records
arrive; the record cache is per pool handle, up to 256 MiB, and is emptied by a
write made through the same handle only: a second handle on the same device that
rewrites a block in place (reachable with `checksum=off`) is not seen, so do not
read through one handle while another writes the same pool, or call
`SetMaxDataCache` low. With several workers a damaged record and a damaged
indirect block in one window report the indirect block's error first.

Measured 2026-11-17 in the kerneljudge VM (4 vCPUs, Apple M4 Max host, `chcpu` to
1 CPU for the 1-CPU rows), one 256 MiB file of word-like text, medians of 5
interleaved rounds, caches dropped and the pool exported and imported between
measurements. Every round is bracketed by `kerneljudge.Calibrate`: the 1-CPU runs
read 650-700 Mops/s and the 4-CPU runs 2550-2600, uniform in every series shown
(a series that was not is re-measured, not printed). Kernel = OpenZFS 2.4.1
module. v0.7.3 is the previous release, same harness
(`readpath_perf_test.go`, `kerneljudge run --perf --test-run KernelJudgeReadPath`).

Sequential read, 1 MiB `ReadAt`, MiB/s:

| data | CPUs | kernel | v0.7.3 | v0.8.0 |
|---|---:|---:|---:|---:|
| off, fletcher4 | 1 | 2532 | 4567 | 4459 |
| off, fletcher4 | 4 | 3865 | 4297 | 5199 |
| lz4 | 1 | 1694 | 2061 | 2153 |
| lz4 | 4 | 2072 | 1895 | 3361 |
| zstd | 1 | 924 | 796 | 795 |
| zstd | 4 | 1000 | 743 | 1876 |

Random 4 KiB reads, reads/s, cold (first pass after open or import) / warm (second
pass over the same offsets):

| data | CPUs | kernel | v0.7.3 | v0.8.0 |
|---|---:|---:|---:|---:|
| off, fletcher4 | 1 | 121 k / 154 k | 27.5 k / 30.2 k | 51.9 k / 88.1 k |
| off, fletcher4 | 4 | 90.5 k / 167 k | 25.0 k / 25.8 k | 53.0 k / 96.2 k |
| lz4 | 1 | 26.1 k / 27.2 k | 14.4 k / 15.2 k | 45.7 k / 88.5 k |
| lz4 | 4 | 24.2 k / 27.9 k | 13.7 k / 14.3 k | 44.2 k / 93.2 k |
| zstd | 1 | 9.9 k / 9.9 k | 5.9 k / 5.9 k | 30.2 k / 85.6 k |
| zstd | 4 | 9.6 k / 10.0 k | 5.3 k / 5.4 k | 30.7 k / 92.7 k |

Reading it: at 1 CPU the sequential figures are unchanged (one worker is the old
serial walk); at 4 CPUs lz4 is 1.6 x the kernel and zstd 1.9 x. The random-read
gains come from the record cache (v0.7.3 decoded a whole 128 KiB record for every
4 KiB read): compressed data is now 1.8 to 3.2 x the kernel cold and 3.3 to 9.2 x
warm. Sequential zstd at 1 CPU was behind the kernel at v0.8.0 (795 against 924
MiB/s); re-measured at v0.8.3 on 2026-11-18 (same VM and harness, host 1-minute
load 5, calibration 684 Mops/s uniform) it reads 1086 MiB/s against the kernel's
943 (rounds 1058 to 1091 against 865 to 968), 1.15 x. The kernel's own rows differ by up to 9 % between the two runs (3865 against
4254 MiB/s, uncompressed 4 CPUs, sequential), so differences of that size between
two columns are not a result; `kerneljudge compare` refuses runs from different
regimes.

### Indirect blocks stay cached (v0.8.1)

A random read has to name its record first, and that walks the object's indirect
blocks. The per-handle cache held one indirect block per level, so on a file of
more than 128 MiB at the default record size (two or more level-1 blocks of 1024
pointers) a random read changed block about every other time and read the 128 KiB
indirect block from the device and verified it again. The kernel looks the parent up
in the dbuf hash first (`module/zfs/dbuf.c`, `dbuf_findbp` calls `dbuf_hold_impl`,
which calls `dbuf_find`) and verifies a block once, when it is read into the ARC
(`module/zfs/zio.c`, `zio_checksum_verify`; an ARC hit is not verified again, `arc.c`
`arc_read`), as this driver does for records: verification is unchanged. Verified
indirect blocks now also go to a bounded cache of the pool (8 to 64 MiB, emptied by a
write exactly as the record cache is), keyed by block pointer.

Random 4 KiB reads, reads/s, cold / warm, medians of 5 interleaved rounds, v0.8.0
against v0.8.1 in the same session, regimes uniform (`kerneljudge compare` accepted
the pairs shown), one 256 MiB file:

| data | CPUs | kernel | v0.8.0 | v0.8.1 |
|---|---:|---:|---:|---:|
| off, fletcher4 | 1 | 131 k / 183 k | 55 k / 92 k | 145 k / 1.79 M |
| lz4 | 1 | 27.6 k / 29 k | 48 k / 91 k | 102 k / 1.80 M |
| zstd | 1 | 10.5 k / 10.6 k | 32 k / 90 k | 51 k / 1.85 M |

At 4 CPUs the same: uncompressed 136-142 k cold, 1.8 M warm. Uncompressed random
reads are now at or above the kernel (1.1 x cold, about 10 x warm: the warm path is a
lookup and a 4 KiB copy against the kernel's page cache and ARC path). Sequential
reads were measured in the same pairs; in a harness that runs the random phases
first in the same process they read 5 to 25 % lower with v0.8.1 while the kernel
column did not move, and with the random phases left out of both builds they are
within 4 % (a comparable pair: uncompressed 1 CPU 4642 against 4531 MiB/s), on the
host with and without a random phase first no difference either. The coupling was
allocation (zfs#73): `ReadAt` decoded each record into a fresh buffer and copied
it out, so a sequential pass allocated its own size, and in the 1-CPU guest the
GC and page faults a random phase leaves behind cost it 10 to 27 %. Records
stored as they are (no compression, no encryption) of a request of a record or
more are now read, verified, straight into the caller's buffer the first time
they are read, and cached only on their second read (admission on second touch,
`inflight.Cache.Seen`, inflight v0.6.0), so a stream read once allocates nothing and
a region read again is cached as before (warm whole-record re-read: parity with
v0.8.3). `Open` no longer decodes the pool's data blocks while looking for the
allocator's high-water mark. In the VM (one comparable pair, regime 469 Mops/s,
uncompressed, against v0.8.3) a sequential pass after a random phase went from 3256
to 4668 MiB/s at 1 CPU and from 3641 to 5349 at 4 CPUs.

## Judged by

The Linux kernel's OpenZFS module (`zpool import -o readonly=on`, `zpool create`)
and `zdb -c`, run as root in a Tart VM by
[kerneljudge](https://github.com/go-filesystems/kerneljudge) (`kerneljudge run
--driver <clone>`; the test is `kerneljudge_test.go`, behind `FS_KERNEL_JUDGE=1`;
zfs-kmod 2.4.1, zfs 2.2.2 userland, Linux 7.0). Our `Format` image and the pool
`zpool create` writes are each held to a fixed corpus (nested directories, UTF-8
names, a 32 MiB file, a sparse file, symlinks, times) by `zdb -c`, a kernel
import and mount, and this reader. Without symlinks both directions pass byte for
byte. Fixed by this release: [#52](https://github.com/go-filesystems/zfs/issues/52)
(the label said the pool was ACTIVE: `zpool import` needed `-f`) and
[#55](https://github.com/go-filesystems/zfs/issues/55) (`ReadFile` of a sparse file
failed). Open, logged as `KNOWN DEFECT` by the test:
[#53](https://github.com/go-filesystems/zfs/issues/53) (the kernel cannot read a
symlink `Symlink` writes) and [#54](https://github.com/go-filesystems/zfs/issues/54)
(`ReadLink` returns an empty target for a kernel-written symlink).

## Limitations

- Single pool; the writer targets a single dataset (the reader also
  navigates nested datasets and multi-vdev/RAID-Z pools)
- The writer emits fletcher4 checksums only and persists no pool checksum
  salt: BLAKE3, Skein and Edon-R are read (and verified), never written (a
  write into a kernel-made salted pool fails before any salted block is made)
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
