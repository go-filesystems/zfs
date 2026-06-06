package filesystem_zfs

// crypt.go — integration glue between the ZFS driver and the
// pure-Go `github.com/go-encryptions/zfscrypt` primitives.
//
// Responsibilities split:
//
//   * zfscrypt owns the cryptography proper: PBKDF2-HMAC-SHA1
//     wrapping-key derivation, AES-CCM/GCM unwrap of the
//     (MEK || HMAC-key) blob, HKDF-SHA512 per-block key
//     derivation, AEAD decryption of a single ZFS block.
//
//   * This file owns the ZFS-side plumbing: the cryptCtx struct
//     carried on every `zfsFS`, the blkptr.isEncrypted() flag
//     accessor, decryptBlock() that pulls per-block (IV, MAC,
//     salt) out of a blkptr and hands the work to zfscrypt, and
//     the OpenFromDeviceDatasetWithKey entry point that callers
//     use when they have a passphrase/key in hand.
//
// What's still TODO (clearly marked below — see findCryptKey):
// parsing the DSL_CRYPTO_KEY bonus area to extract the wrapped
// MEK + salt + iters + IV + MAC + crypt_algorithm. That code
// belongs here (the package already knows how to walk ZAP/dnode
// objects) but needs vectors from a real encrypted pool to
// validate; it can land independently of the crypto primitives.

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/go-encryptions/zfscrypt"
)

// cryptingReader wraps a blockBackend so the per-FS encryption
// state rides along with the reader. readBlock type-asserts on
// this wrapper when it encounters an encrypted block; this keeps
// the read-helper signatures (readBlock, readDataBlock,
// findDataBP, readDnodeData, …) byte-for-byte compatible with
// pre-encryption callers and confines the diff for native
// encryption to this single file + a tiny edit in readBlock.
type cryptingReader struct {
	blockBackend
	crypt *cryptCtx
}

// Ensure the wrapper still satisfies the read side.
var _ io.ReaderAt = (*cryptingReader)(nil)

// OpenFromDeviceDatasetWithKey is the encryption-aware twin of
// OpenFromDeviceDataset. wrappingKeyOrPassphrase is either:
//
//   - a 32-byte raw wrapping key (already derived by the caller
//     via zfscrypt.DeriveWrappingKey, or supplied by an external
//     key store), or
//   - a passphrase shorter or longer than 32 bytes, in which case
//     this function derives the wrapping key on the fly using
//     the salt + iter count stored in the dataset's
//     DSL_CRYPTO_KEY object.
//
// On success the returned FS reads encrypted blocks transparently
// — every cleartext consumer (Stat / ListDir / ReadFile / …)
// works unchanged.
//
// Status: the crypto primitives this entry point depends on
// (github.com/go-encryptions/ccm + github.com/go-encryptions/zfscrypt) are
// implemented and unit-tested. The DSL_CRYPTO_KEY on-disk parser
// the entry point calls into (loadCryptKey, below) is the
// remaining piece — until it is filled in this function returns
// a "not yet implemented" error so callers don't silently get an
// undecrypted FS.
func OpenFromDeviceDatasetWithKey(dev BlockBackend, partIndex int, datasetPath string, wrappingKeyOrPassphrase []byte) (FS, error) {
	off, err := openPartitionOffset(dev, partIndex)
	if err != nil {
		dev.Close()
		return nil, err
	}
	info, err := openReadInfo(dev, off)
	if err != nil {
		dev.Close()
		return nil, err
	}
	fs := &zfsFS{f: dev, partOffset: off + vdevLabelStartSize, info: info, labelOffset: off}
	fs.curTxg = info.TransactionGroup

	if err := fs.loadCryptKey(wrappingKeyOrPassphrase); err != nil {
		dev.Close()
		return nil, err
	}
	// Replace fs.f with the crypting wrapper so every subsequent
	// readBlock sees the crypt context.
	fs.f = &cryptingReader{blockBackend: dev, crypt: fs.crypt}

	rootBPBuf := make([]byte, blkptrSize)
	if _, e2 := fs.f.ReadAt(rootBPBuf, info.Offset+40); e2 == nil {
		rootBP := parseBlkptr(rootBPBuf)
		if !rootBP.isNull() {
			if ds, e3 := openNamedDataset(fs.f, off, rootBP, datasetPath); e3 == nil {
				fs.zplDS = ds
				if sz, e4 := fs.f.Size(); e4 == nil {
					fs.initAllocator(sz)
				}
			} else if datasetPath != "" {
				fs.f.Close()
				return nil, fmt.Errorf("zfs: open dataset %q: %w", datasetPath, e3)
			}
		}
	}
	return fs, nil
}

// blkPropCryptBit is bit 61 of blk_prop — BP_CRYPT_BLKPTR in
// OpenZFS, set when the block was encrypted via dataset-level
// native encryption.
const blkPropCryptBit = uint64(1) << 61

// isEncrypted reports whether the block referenced by bp was
// written through the native-encryption path.
func (bp blkptr) isEncrypted() bool { return bp.prop&blkPropCryptBit != 0 }

// cryptCtx is the running per-FS encryption state, populated when
// the pool was opened via OpenFromDeviceDatasetWithKey and the
// target dataset is encrypted. nil otherwise — readBlock then
// short-circuits the decrypt path.
type cryptCtx struct {
	// Suite of the data-encryption AEAD for this dataset (one of
	// AES-{128,192,256}-{CCM,GCM}). Comes from the dataset's
	// DSL_CRYPTO_KEY.crypt_algorithm field.
	suite zfscrypt.Suite
	// mek is the 32-byte master encryption key recovered by
	// unwrapping the on-disk wrapped MEK with the user-derived
	// wrapping key.
	mek []byte
	// hmacKey is the 32-byte sibling key recovered alongside the
	// MEK; OpenZFS uses it to authenticate metadata that bypasses
	// the AEAD layer.
	hmacKey []byte
}

// readBlockEncrypted is the encryption-aware physical-read helper.
// It performs the raw on-disk read first (so block-pointer
// resolution stays inside blockptr.go), and only switches to the
// decrypt path when both the block is encrypted AND a crypt
// context is available.
//
// Decompression continues to happen in the existing readBlock
// implementation; this wrapper restores the plaintext payload
// before the decompressor runs.
func decryptBlockPayload(c *cryptCtx, bp blkptr, ciphertext []byte) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("zfs: encrypted block read with no crypt context — open the FS with OpenFromDeviceDatasetWithKey")
	}
	iv, mac, salt, err := extractBlockCrypt(bp)
	if err != nil {
		return nil, fmt.Errorf("zfs: extract block crypt fields: %w", err)
	}

	key, err := zfscrypt.DeriveBlockKey(c.suite, c.mek, salt)
	if err != nil {
		return nil, fmt.Errorf("zfs: derive block key: %w", err)
	}
	ad := blockAAD(bp)

	pt, err := zfscrypt.DecryptBlock(c.suite, key, iv, mac, ciphertext, ad)
	if err != nil {
		return nil, fmt.Errorf("zfs: decrypt block: %w", err)
	}
	return pt, nil
}

// extractBlockCrypt pulls the per-block IV (12 bytes), MAC
// (16 bytes) and salt (variable) out of a blkptr. In OpenZFS the
// IV and MAC overlay the blk_pad and the lower part of the cksum
// fields for encrypted blocks; the salt re-uses physBirth.
//
// TODO: nail down the exact field layout against OpenZFS
// include/sys/zio_crypt.h before relying on this in production.
// The structural placement is documented (encrypted blocks
// repurpose pad/cksum slots) but the precise byte offsets are
// best confirmed against a known-good encrypted pool. The
// implementation below mirrors what the OpenZFS source comments
// describe and round-trips correctly against synthetic data
// produced by the same encoder, but it has NOT been validated
// against a third-party encrypted pool image. See the
// matching memory:userland-fs-drivers entry for the verification
// plan.
func extractBlockCrypt(bp blkptr) (iv, mac, salt []byte, err error) {
	// IV: 96 bits laid down in blk_pad[0..7] + cksum[0] bottom 4 bytes.
	iv = make([]byte, zfscrypt.IVSize)
	// blk_pad lives at bytes 56..71 in the on-disk struct. We have it
	// in parsed form only through bp.cksum / bp.fill / bp.physBirth /
	// bp.birth fields. To stay layout-correct re-encode the raw bytes
	// from the fields we actually keep.
	var pad8 [8]byte
	binary.LittleEndian.PutUint64(pad8[:], bp.fill) // pad[0..7] held in `fill` slot in our parsed struct
	copy(iv[0:8], pad8[:])
	// IV bytes 8..11: low 4 bytes of cksum[0]
	var ck0 [8]byte
	binary.LittleEndian.PutUint64(ck0[:], bp.cksum[0])
	copy(iv[8:12], ck0[0:4])

	// MAC: 128 bits, cksum[2..3] in OpenZFS's encrypted layout.
	mac = make([]byte, zfscrypt.MACSize)
	var ck2, ck3 [8]byte
	binary.LittleEndian.PutUint64(ck2[:], bp.cksum[2])
	binary.LittleEndian.PutUint64(ck3[:], bp.cksum[3])
	copy(mac[0:8], ck2[:])
	copy(mac[8:16], ck3[:])

	// Salt: 64 bits, physBirth slot in the encrypted layout.
	salt = make([]byte, 8)
	binary.LittleEndian.PutUint64(salt, bp.physBirth)
	return iv, mac, salt, nil
}

// blockAAD assembles the additional-authenticated-data bytes that
// OpenZFS computes over a blkptr's "sensitive" fields before
// running the AEAD. The pool authenticates these so the block
// can't be relocated or replayed silently. The bytes we hash here
// are the canonical "non-encrypted fixed bits" of the blkptr.
//
// TODO: same caveat as extractBlockCrypt — the field selection
// matches OpenZFS source comments but should be cross-checked
// against a real pool before being relied on.
func blockAAD(bp blkptr) []byte {
	out := make([]byte, 0, 24)
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], bp.birth)
	out = append(out, buf[:]...)
	binary.LittleEndian.PutUint64(buf[:], bp.prop&^(blkPropCryptBit))
	out = append(out, buf[:]...)
	// First DVA's allocated size + offset.
	binary.LittleEndian.PutUint64(buf[:], bp.dva[0][0])
	out = append(out, buf[:]...)
	return out
}

// findAndLoadKey discovers the dataset's DSL_CRYPTO_KEY object,
// reads its bonus area, derives the wrapping key from the
// caller-supplied passphrase (or raw key), and unwraps the MEK +
// HMAC key. Populates fs.crypt on success.
//
// TODO: actually parse the DSL_CRYPTO_KEY bonus area. The hook
// lives here so the rest of the integration can land first; until
// the parser is filled in, OpenFromDeviceDatasetWithKey will
// return a clear "encryption metadata parser not implemented yet"
// error rather than silently mis-decrypting.
func (fs *zfsFS) loadCryptKey(rawKeyOrPass []byte) error {
	return fmt.Errorf("zfs: DSL_CRYPTO_KEY bonus parser not yet implemented (have crypto primitives via github.com/go-crypto/{ccm,zfscrypt}; need on-disk format wiring — see crypt.go TODOs)")
}
