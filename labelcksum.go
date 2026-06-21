package filesystem_zfs

// labelcksum.go — OpenZFS self-checksum (ZIO_CHECKSUM_LABEL) for the
// vdev_phys nvlist region and the uberblocks.
//
// Both the 112 KiB vdev_phys region and each uberblock slot end in a
// zio_eck_t trailer:
//
//	struct zio_eck_t {           // 40 bytes
//	    uint64_t    zec_magic;   // ZEC_MAGIC = 0x0210da7ab10c7a11
//	    zio_cksum_t zec_cksum;   // 4 × uint64
//	};
//
// The checksum is produced by zio_checksum_compute() with
// ZIO_CHECKSUM_LABEL (module/zfs/zio_checksum.c). For an embedded,
// label-flavoured checksum the procedure is:
//
//  1. eck_offset = size - sizeof(zio_eck_t)
//  2. zec_magic  = ZEC_MAGIC
//  3. zec_cksum  = the label "verifier": ZIO_SET_CHECKSUM(offset,0,0,0)
//     where offset is the byte offset of THIS region within the vdev.
//  4. SHA-256 over the whole buffer (magic + verifier embedded).
//  5. zec_cksum  = the resulting digest, each 64-bit word stored as
//     BE_64(word) (see abd_checksum_sha256 in module/zfs/sha2_zfs.c —
//     the digest words are forced big-endian for on-disk compat).
//
// Without this trailer zdb reports "Bad label cksum" and `zpool import`
// refuses the pool. Verified byte-for-byte against labels written by
// real `zpool create` on OpenZFS 2.3.

import (
	"crypto/sha256"
	"encoding/binary"
)

const (
	// zecMagic is ZEC_MAGIC, the zio_eck_t marker (stored little-endian).
	zecMagic = 0x0210da7ab10c7a11
	// zioEckSize is sizeof(zio_eck_t): 8-byte magic + 4×8-byte cksum.
	zioEckSize = 40
)

// labelSelfChecksum fills the zio_eck_t trailer of buf in place.
//
//	buf       is the full checksummed region (e.g. a 112 KiB vdev_phys
//	          copy, or a single uberblock slot). Its last 40 bytes are
//	          the zio_eck_t.
//	regionOff is the byte offset of buf within the vdev — the value fed
//	          to the label verifier (ZIO_SET_CHECKSUM(off,0,0,0)).
func labelSelfChecksum(buf []byte, regionOff uint64) {
	n := len(buf)
	eck := n - zioEckSize
	le := binary.LittleEndian

	// zec_magic
	le.PutUint64(buf[eck:eck+8], zecMagic)
	// zec_cksum := verifier seed [regionOff, 0, 0, 0]
	le.PutUint64(buf[eck+8:eck+16], regionOff)
	le.PutUint64(buf[eck+16:eck+24], 0)
	le.PutUint64(buf[eck+24:eck+32], 0)
	le.PutUint64(buf[eck+32:eck+40], 0)

	// SHA-256 over the whole region with the verifier embedded.
	sum := sha256.Sum256(buf)

	// zc_word[i] = BE_64(sha_word[i]). The SHA digest bytes are the
	// big-endian representation of each word; storing that big-endian
	// load as a native little-endian uint64 reproduces OpenZFS's
	// BE_64() store exactly.
	for i := 0; i < 4; i++ {
		w := binary.BigEndian.Uint64(sum[i*8 : i*8+8])
		le.PutUint64(buf[eck+8+i*8:eck+16+i*8], w)
	}
}
