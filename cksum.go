package filesystem_zfs

// cksum.go — OpenZFS block-pointer checksums (fletcher4 / SHA-256).
//
// Unlike the embedded label/uberblock self-checksum (see labelcksum.go,
// which stores a zio_eck_t trailer INSIDE the checksummed region), a
// regular block pointer stores its checksum OUT-OF-LINE in the pointing
// blkptr's blk_cksum[4] field. The checksum covers exactly the physical
// (on-disk) bytes of the block it points to — the post-compression,
// post-encryption payload that lives at the DVA — and nothing of the
// blkptr itself.
//
// The algorithm is selected by the blk_prop checksum-type field
// (bits 47:40). OpenZFS uses:
//
//	fletcher4 — default for nearly all metadata and data blocks.
//	sha256    — used for some metadata (and dedup); fletcher4 is an
//	            acceptable substitute for our writer's blocks as long
//	            as the blk_prop type field agrees with what we store.
//
// We emit fletcher4 everywhere (matching what `zpool create` uses for
// the MOS objset, dnode arrays, ZAPs and data on an OpenZFS 2.3 pool),
// and set the blk_prop checksum type accordingly so OpenZFS verifies
// our blocks during `zdb -e -p` traversal and `zpool import`.
//
// Byte order: a fletcher4 checksum is four uint64 accumulators. On a
// little-endian pool ZFS stores them in native (little-endian) order in
// blk_cksum[0..3] — no per-word byteswap (contrast with the SHA-256
// label checksum, whose digest words are forced big-endian). This is
// what zio_checksum_compute does: fletcher4_native writes the raw
// accumulators and the BP's byteorder bit (set for LE) tells the reader
// no swap is needed.

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// ZIO checksum types (zio_checksum_t / zio_checksum enum in
// sys/zio_checksum.h). Only the values we read or write are named.
const (
	zioChecksumInherit = 0
	zioChecksumOn      = 1
	zioChecksumOff     = 2
	zioChecksumLabel   = 3
	zioChecksumGangHdr = 4
	zioChecksumZILOG   = 5
	zioChecksumFletch2 = 6
	zioChecksumFletch4 = 7
	zioChecksumSHA256  = 8
)

// fletcher4 computes the ZFS fletcher4 checksum over buf and returns the
// four 64-bit accumulators (a, b, c, d), exactly as
// fletcher_4_scalar_native() does in module/zfs/zfs_fletcher.c.
//
// The input is processed as a stream of 32-bit little-endian words. buf's
// length must be a multiple of 4 (block sizes are always 512-aligned, so
// this always holds for on-disk blocks).
func fletcher4(buf []byte) [4]uint64 {
	var a, b, c, d uint64
	n := len(buf) / 4
	for i := 0; i < n; i++ {
		w := uint64(binary.LittleEndian.Uint32(buf[i*4:]))
		a += w
		b += a
		c += b
		d += c
	}
	return [4]uint64{a, b, c, d}
}

// sha256Checksum computes the ZFS SHA-256 block checksum over buf. ZFS
// stores the digest as four big-endian uint64 words (abd_checksum_sha256
// in module/zfs/sha2_zfs.c forces BE_64 on each word). We return the
// words such that storing them little-endian into blk_cksum reproduces
// the on-disk bytes.
func sha256Checksum(buf []byte) [4]uint64 {
	sum := sha256.Sum256(buf)
	var c [4]uint64
	for i := 0; i < 4; i++ {
		c[i] = binary.BigEndian.Uint64(sum[i*8 : i*8+8])
	}
	return c
}

// blockChecksum computes the checksum of the physical block bytes `phys`
// using the algorithm named by ctype (a zioChecksum* value), returning
// the four words to store in a blkptr's blk_cksum field.
func blockChecksum(ctype uint8, phys []byte) [4]uint64 {
	switch ctype {
	case zioChecksumSHA256:
		return sha256Checksum(phys)
	default:
		// fletcher4 is the default for everything else we write.
		return fletcher4(phys)
	}
}

// fletcher2 is fletcher_2_native (module/zfs/zfs_fletcher.c): 64-bit words
// taken in pairs, two interleaved accumulator chains. buf's length is a
// multiple of 16 for an on-disk block.
func fletcher2(buf []byte) [4]uint64 {
	var a0, a1, b0, b1 uint64
	for i := 0; i+16 <= len(buf); i += 16 {
		a0 += binary.LittleEndian.Uint64(buf[i:])
		a1 += binary.LittleEndian.Uint64(buf[i+8:])
		b0 += a0
		b1 += a1
	}
	return [4]uint64{a0, a1, b0, b1}
}

// ErrChecksum is returned (wrapped) when a block read from disk does not match
// the checksum its block pointer records: the kernel's zio_checksum_error, which
// surfaces as EIO. The data of such a block is never returned.
var ErrChecksum = errors.New("zfs: block checksum mismatch")

// verifyBlockChecksum checks the physical bytes `phys` of the block `bp` points
// to against bp.cksum, as zio_checksum_verify does on every read.
//
// Verified: fletcher4, fletcher2 and SHA-256 on little-endian block pointers.
// Not verified, because no implementation exists here yet: SHA-512/256, Skein,
// Edon-R, BLAKE3 (and a big-endian pool): those blocks are returned as before.
// OFF and embedded block pointers carry no checksum.
func verifyBlockChecksum(bp blkptr, phys []byte) error {
	if bp.isEmbedded() || bp.prop&bpLEBit == 0 {
		return nil
	}
	var got [4]uint64
	switch bp.checksumType() {
	case zioChecksumFletch4:
		got = fletcher4(phys)
	case zioChecksumFletch2:
		got = fletcher2(phys)
	case zioChecksumSHA256:
		got = sha256Checksum(phys)
	default:
		return nil
	}
	want := bp.cksum
	if bp.prop&blkPropCryptBit != 0 && bp.dmuType() != dmotObjset {
		// zio_checksum_error_impl (zio_checksum.c:514-525, OpenZFS 2.3.0): the
		// stored checksum is the 128-bit truncation (w0^w2, w1^w3), the last two
		// words hold the MAC and are not compared. Objset blocks keep all four.
		got[0] ^= got[2]
		got[1] ^= got[3]
		got[2], got[3], want[2], want[3] = 0, 0, 0, 0
	}
	if got != want {
		return fmt.Errorf("%w: type %d at 0x%X: have %x, block pointer says %x",
			ErrChecksum, bp.checksumType(), bp.dvaOffset(0), got, want)
	}
	return nil
}
