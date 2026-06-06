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
// Status:
//   * crypto primitives (PBKDF2 wrap-key derivation, AES-CCM/GCM
//     unwrap, HKDF per-block key, AEAD block decrypt) — done in
//     github.com/go-encryptions/zfscrypt.
//   * DSL_CRYPTO_KEY on-disk parser (DSLCryptoKey struct,
//     parseDSLCryptoKeyPhys, parseDSLCryptoKeyFromZAP,
//     marshalDSLCryptoKeyPhys, unwrapDSLCryptoKey, AAD helper) —
//     implemented and unit-tested in this file.
//   * Remaining: walk the DSL tree from the dataset to its
//     DSL_CRYPTO_KEY object and feed those bytes through the
//     parser. That step needs vectors from a real encrypted pool
//     to validate end-to-end; until it is wired loadCryptKey
//     returns a clearly-named "locator not wired" error.

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
// Status: crypto primitives (github.com/go-encryptions/ccm +
// .../zfscrypt) and the DSL_CRYPTO_KEY on-disk parser
// (parseDSLCryptoKeyPhys / parseDSLCryptoKeyFromZAP) are in
// place. The remaining piece is the dataset-walker that locates
// the DSL_CRYPTO_KEY object for a given dataset and feeds its
// bytes through the parser; until that lands loadCryptKey
// surfaces a clear "locator not wired" error so callers don't
// silently get an undecrypted FS.
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

// ---------------------------------------------------------------------------
// DSL_CRYPTO_KEY on-disk layout
// ---------------------------------------------------------------------------
//
// In OpenZFS the DSL_CRYPTO_KEY object is a ZAP whose attributes are the
// wrapped MEK, wrapped HMAC key, IV, MAC, salt, iters, crypto suite and
// GUID. The `dsl_crypto_key_phys_t` struct in include/sys/dsl_crypt.h is
// the in-memory shape; reads/writes go through the ZAP layer rather than
// landing as a raw bonus blob.
//
// We model the parsed metadata as `DSLCryptoKey` and offer two on-disk
// shapes:
//
//   - A fixed-layout packed binary form (parseDSLCryptoKeyPhys /
//     marshalDSLCryptoKeyPhys) that is convenient to round-trip in tests
//     and to ship a key out-of-band (e.g. a key file, a debug dump).
//
//   - A ZAP-attribute form (parseDSLCryptoKeyFromZAP) that takes the
//     name→bytes map a ZAP walker produces and assembles the same struct.
//
// Both shapes feed into the same DSLCryptoKey, so the rest of the
// crypto plumbing only sees the parsed value.
//
// Constants below match the OpenZFS source: KEY_MAX_LEN = 32,
// HMAC_MAX_LEN = 32, MASTER_KEY_MAX_LEN = 32, WRAPPING_IV_LEN = 13,
// WRAPPING_MAC_LEN = 16, ZIO_DATA_SALT_LEN = 8.

const (
	// DSLMasterKeyMaxLen is the length of the wrapped master encryption
	// key blob (matches MASTER_KEY_MAX_LEN in OpenZFS).
	DSLMasterKeyMaxLen = 32
	// DSLHMACKeyMaxLen is the length of the wrapped HMAC key blob.
	DSLHMACKeyMaxLen = 32
	// DSLWrappingIVLen is the length of the wrap-time IV (13 bytes —
	// OpenZFS uses a 13-byte IV for the unwrap AEAD, distinct from the
	// 12-byte per-block IVs).
	DSLWrappingIVLen = 13
	// DSLWrappingMACLen is the length of the wrap-time MAC tag.
	DSLWrappingMACLen = 16
	// DSLSaltLen is the length of the PBKDF2 salt.
	DSLSaltLen = 8
	// DSLCryptoKeyPhysSize is the on-wire packed size of a
	// `dsl_crypto_key_phys`-style record:
	//   suite(8) + guid(8) + version(8) + iters(8) +
	//   iv(13) + pad(3) + mac(16) +
	//   wrapped MEK(32) + wrapped HMAC(32) + salt(8) = 136 bytes.
	DSLCryptoKeyPhysSize = 8 + 8 + 8 + 8 + 13 + 3 + 16 + DSLMasterKeyMaxLen + DSLHMACKeyMaxLen + DSLSaltLen
)

// ZAP attribute names used by OpenZFS to store DSL_CRYPTO_KEY fields.
// Mirrors the DSL_CRYPTO_KEY_* macros in include/sys/dsl_crypt.h.
const (
	zapDSLCryptoKeyCryptSuite = "DSL_CRYPTO_SUITE"
	zapDSLCryptoKeyGUID       = "DSL_CRYPTO_GUID"
	zapDSLCryptoKeyIV         = "DSL_CRYPTO_IV"
	zapDSLCryptoKeyMAC        = "DSL_CRYPTO_MAC"
	zapDSLCryptoKeyMasterKey  = "DSL_CRYPTO_MASTER_KEY_1"
	zapDSLCryptoKeyHMACKey    = "DSL_CRYPTO_HMAC_KEY_1"
	zapDSLCryptoKeySalt       = "DSL_CRYPTO_SALT"
	zapDSLCryptoKeyIters      = "DSL_CRYPTO_ITERS"
	zapDSLCryptoKeyVersion    = "DSL_CRYPTO_VERSION"
)

// DSLCryptoKey is the parsed form of a ZFS dataset's DSL_CRYPTO_KEY
// object. It carries everything the unwrap step needs: the AEAD suite,
// the wrap-time IV+MAC, the wrapped (MEK||HMAC) blob, and the PBKDF2
// salt+iters used to derive the wrapping key from a passphrase.
//
// Field sizes are validated at parse time; downstream code (Unwrap,
// DeriveWrappingKey) can therefore assume they are correct.
type DSLCryptoKey struct {
	// Suite is the data-encryption AEAD chosen for this dataset.
	Suite zfscrypt.Suite
	// GUID is the dataset key's unique identifier, used as part of the
	// unwrap AAD so a wrapped blob can't be silently swapped between
	// datasets.
	GUID uint64
	// Version is the on-disk format version of the DSL_CRYPTO_KEY
	// record (OpenZFS shipped version 0 historically; later format
	// changes bumped this).
	Version uint64
	// Iters is the PBKDF2-HMAC-SHA1 iteration count used to derive the
	// wrapping key from a passphrase. Zero means a raw key was supplied
	// directly.
	Iters uint64
	// IV is the 13-byte wrap-time IV passed to AES-CCM/GCM during the
	// MEK unwrap step.
	IV []byte
	// MAC is the 16-byte authentication tag emitted by the wrap step.
	MAC []byte
	// WrappedMasterKey is the AEAD ciphertext of the master encryption
	// key, exactly DSLMasterKeyMaxLen bytes.
	WrappedMasterKey []byte
	// WrappedHMACKey is the AEAD ciphertext of the per-dataset HMAC
	// key, exactly DSLHMACKeyMaxLen bytes.
	WrappedHMACKey []byte
	// Salt is the PBKDF2 salt; meaningful only when Iters > 0.
	Salt []byte
}

// parseDSLCryptoKeyPhys decodes a packed `dsl_crypto_key_phys`-style
// record. The layout is:
//
//	+0   uint64 suite      (little-endian)
//	+8   uint64 guid
//	+16  uint64 version
//	+24  uint64 iters
//	+32  [13]   iv
//	+45  [3]    pad (must be zero — rejected otherwise so silent
//	            corruption is surfaced rather than swallowed)
//	+48  [16]   mac
//	+64  [32]   wrapped master key
//	+96  [32]   wrapped hmac key
//	+128 [8]    salt
//	== 136 bytes total.
//
// All multi-byte integers are little-endian. The function copies bytes
// out of the input so the returned DSLCryptoKey does not alias the
// caller's buffer.
func parseDSLCryptoKeyPhys(buf []byte) (*DSLCryptoKey, error) {
	if len(buf) < DSLCryptoKeyPhysSize {
		return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY bonus too short: have %d bytes, want at least %d", len(buf), DSLCryptoKeyPhysSize)
	}
	rawSuite := binary.LittleEndian.Uint64(buf[0:8])
	suite := zfscrypt.Suite(rawSuite)
	if rawSuite > 0xff || suite.KeyLen() == 0 {
		return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY: invalid crypto suite %d", rawSuite)
	}

	// Reject non-zero pad — it signals either a layout mismatch or a
	// tampered record.
	if buf[45] != 0 || buf[46] != 0 || buf[47] != 0 {
		return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY: non-zero pad bytes at offset 45..47")
	}

	k := &DSLCryptoKey{
		Suite:            suite,
		GUID:             binary.LittleEndian.Uint64(buf[8:16]),
		Version:          binary.LittleEndian.Uint64(buf[16:24]),
		Iters:            binary.LittleEndian.Uint64(buf[24:32]),
		IV:               append([]byte(nil), buf[32:45]...),
		MAC:              append([]byte(nil), buf[48:64]...),
		WrappedMasterKey: append([]byte(nil), buf[64:96]...),
		WrappedHMACKey:   append([]byte(nil), buf[96:128]...),
		Salt:             append([]byte(nil), buf[128:136]...),
	}
	return k, nil
}

// marshalDSLCryptoKeyPhys is the inverse of parseDSLCryptoKeyPhys. It
// is primarily a test helper (round-tripping fixture blobs) but lives
// in production code so external callers building synthetic DSL_CRYPTO
// blobs (e.g. for tooling) can use the same encoder the parser
// validates against.
func marshalDSLCryptoKeyPhys(k *DSLCryptoKey) ([]byte, error) {
	if k == nil {
		return nil, fmt.Errorf("zfs: marshalDSLCryptoKeyPhys: nil key")
	}
	if k.Suite.KeyLen() == 0 {
		return nil, fmt.Errorf("zfs: marshalDSLCryptoKeyPhys: invalid suite %d", uint8(k.Suite))
	}
	if len(k.IV) != DSLWrappingIVLen {
		return nil, fmt.Errorf("zfs: marshalDSLCryptoKeyPhys: IV must be %d bytes, got %d", DSLWrappingIVLen, len(k.IV))
	}
	if len(k.MAC) != DSLWrappingMACLen {
		return nil, fmt.Errorf("zfs: marshalDSLCryptoKeyPhys: MAC must be %d bytes, got %d", DSLWrappingMACLen, len(k.MAC))
	}
	if len(k.WrappedMasterKey) != DSLMasterKeyMaxLen {
		return nil, fmt.Errorf("zfs: marshalDSLCryptoKeyPhys: master key must be %d bytes, got %d", DSLMasterKeyMaxLen, len(k.WrappedMasterKey))
	}
	if len(k.WrappedHMACKey) != DSLHMACKeyMaxLen {
		return nil, fmt.Errorf("zfs: marshalDSLCryptoKeyPhys: hmac key must be %d bytes, got %d", DSLHMACKeyMaxLen, len(k.WrappedHMACKey))
	}
	if len(k.Salt) != DSLSaltLen {
		return nil, fmt.Errorf("zfs: marshalDSLCryptoKeyPhys: salt must be %d bytes, got %d", DSLSaltLen, len(k.Salt))
	}
	out := make([]byte, DSLCryptoKeyPhysSize)
	binary.LittleEndian.PutUint64(out[0:8], uint64(k.Suite))
	binary.LittleEndian.PutUint64(out[8:16], k.GUID)
	binary.LittleEndian.PutUint64(out[16:24], k.Version)
	binary.LittleEndian.PutUint64(out[24:32], k.Iters)
	copy(out[32:45], k.IV)
	// out[45:48] stays zero — explicit pad.
	copy(out[48:64], k.MAC)
	copy(out[64:96], k.WrappedMasterKey)
	copy(out[96:128], k.WrappedHMACKey)
	copy(out[128:136], k.Salt)
	return out, nil
}

// parseDSLCryptoKeyFromZAP builds a DSLCryptoKey from the name→bytes
// map a ZAP walker produces for a DSL_CRYPTO_KEY object. Required
// attributes: SUITE, GUID, IV, MAC, MASTER_KEY_1, HMAC_KEY_1, SALT,
// ITERS. VERSION is optional (defaults to 0).
//
// The function performs the same length and range checks as
// parseDSLCryptoKeyPhys so callers can rely on the resulting struct's
// invariants identically.
func parseDSLCryptoKeyFromZAP(attrs map[string][]byte) (*DSLCryptoKey, error) {
	if attrs == nil {
		return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY ZAP attrs: nil map")
	}
	getU64 := func(name string) (uint64, error) {
		v, ok := attrs[name]
		if !ok {
			return 0, fmt.Errorf("zfs: DSL_CRYPTO_KEY ZAP attrs: missing %q", name)
		}
		if len(v) != 8 {
			return 0, fmt.Errorf("zfs: DSL_CRYPTO_KEY ZAP attrs: %q must be 8 bytes, got %d", name, len(v))
		}
		return binary.LittleEndian.Uint64(v), nil
	}
	getBytes := func(name string, want int) ([]byte, error) {
		v, ok := attrs[name]
		if !ok {
			return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY ZAP attrs: missing %q", name)
		}
		if len(v) != want {
			return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY ZAP attrs: %q must be %d bytes, got %d", name, want, len(v))
		}
		return append([]byte(nil), v...), nil
	}

	rawSuite, err := getU64(zapDSLCryptoKeyCryptSuite)
	if err != nil {
		return nil, err
	}
	if rawSuite > 0xff || zfscrypt.Suite(rawSuite).KeyLen() == 0 {
		return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY ZAP attrs: invalid crypto suite %d", rawSuite)
	}
	guid, err := getU64(zapDSLCryptoKeyGUID)
	if err != nil {
		return nil, err
	}
	iters, err := getU64(zapDSLCryptoKeyIters)
	if err != nil {
		return nil, err
	}
	iv, err := getBytes(zapDSLCryptoKeyIV, DSLWrappingIVLen)
	if err != nil {
		return nil, err
	}
	mac, err := getBytes(zapDSLCryptoKeyMAC, DSLWrappingMACLen)
	if err != nil {
		return nil, err
	}
	mek, err := getBytes(zapDSLCryptoKeyMasterKey, DSLMasterKeyMaxLen)
	if err != nil {
		return nil, err
	}
	hk, err := getBytes(zapDSLCryptoKeyHMACKey, DSLHMACKeyMaxLen)
	if err != nil {
		return nil, err
	}
	salt, err := getBytes(zapDSLCryptoKeySalt, DSLSaltLen)
	if err != nil {
		return nil, err
	}

	// VERSION is optional — older pools have no entry, treat as 0.
	var version uint64
	if v, ok := attrs[zapDSLCryptoKeyVersion]; ok {
		if len(v) != 8 {
			return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY ZAP attrs: %q must be 8 bytes, got %d", zapDSLCryptoKeyVersion, len(v))
		}
		version = binary.LittleEndian.Uint64(v)
	}

	return &DSLCryptoKey{
		Suite:            zfscrypt.Suite(rawSuite),
		GUID:             guid,
		Version:          version,
		Iters:            iters,
		IV:               iv,
		MAC:              mac,
		WrappedMasterKey: mek,
		WrappedHMACKey:   hk,
		Salt:             salt,
	}, nil
}

// dslCryptoKeyUnwrapAAD assembles the additional-authenticated-data
// bytes that wrap/unwrap pass to the AEAD. OpenZFS authenticates the
// GUID + suite + version so a wrapped (MEK||HMAC) blob can't silently
// be moved between datasets or have its metadata tampered with.
func dslCryptoKeyUnwrapAAD(k *DSLCryptoKey) []byte {
	ad := make([]byte, 24)
	binary.LittleEndian.PutUint64(ad[0:8], k.GUID)
	binary.LittleEndian.PutUint64(ad[8:16], uint64(k.Suite))
	binary.LittleEndian.PutUint64(ad[16:24], k.Version)
	return ad
}

// unwrapDSLCryptoKey takes a parsed DSLCryptoKey and a wrapping key (or
// passphrase), derives the wrapping key if needed, and returns the
// 32-byte MEK + 32-byte HMAC key. It is the bridge between the parser
// and the zfscrypt primitive layer.
//
// If iters > 0 the input is treated as a passphrase and fed through
// PBKDF2 with the stored salt+iters; otherwise the input must already
// be 32 bytes and is used directly.
func unwrapDSLCryptoKey(k *DSLCryptoKey, rawKeyOrPass []byte) (mek, hmacKey []byte, err error) {
	if k == nil {
		return nil, nil, fmt.Errorf("zfs: unwrapDSLCryptoKey: nil key")
	}
	if len(rawKeyOrPass) == 0 {
		return nil, nil, fmt.Errorf("zfs: unwrapDSLCryptoKey: empty passphrase / key")
	}
	var wrappingKey []byte
	if k.Iters > 0 {
		wrappingKey, err = zfscrypt.DeriveWrappingKey(rawKeyOrPass, k.Salt, int(k.Iters))
		if err != nil {
			return nil, nil, fmt.Errorf("zfs: derive wrapping key: %w", err)
		}
	} else {
		if len(rawKeyOrPass) != zfscrypt.WrappingKeyLen {
			return nil, nil, fmt.Errorf("zfs: unwrapDSLCryptoKey: raw key must be %d bytes when iters == 0, got %d", zfscrypt.WrappingKeyLen, len(rawKeyOrPass))
		}
		wrappingKey = rawKeyOrPass
	}

	// zfscrypt.Unwrap takes a 12-byte IV. OpenZFS stores 13 bytes for
	// the wrap IV but uses only the first 12 for the CCM nonce on the
	// read path; the 13th byte is the L parameter. Pass the first 12
	// bytes here.
	if len(k.IV) < zfscrypt.IVSize {
		return nil, nil, fmt.Errorf("zfs: unwrapDSLCryptoKey: IV too short (%d)", len(k.IV))
	}
	wrapped := make([]byte, 0, DSLMasterKeyMaxLen+DSLHMACKeyMaxLen)
	wrapped = append(wrapped, k.WrappedMasterKey...)
	wrapped = append(wrapped, k.WrappedHMACKey...)
	ad := dslCryptoKeyUnwrapAAD(k)

	return zfscrypt.Unwrap(k.Suite, wrappingKey, k.IV[:zfscrypt.IVSize], k.MAC, wrapped, ad)
}

// loadCryptKey discovers the dataset's DSL_CRYPTO_KEY object, reads it,
// derives the wrapping key from the caller-supplied passphrase (or raw
// key), and unwraps the MEK + HMAC key. Populates fs.crypt on success.
//
// The on-disk discovery half (walking the DSL tree from the dataset
// down to the DSL_CRYPTO_KEY ZAP object and pulling its attributes
// off-disk) is not wired here yet because it needs vectors from a real
// encrypted pool to validate. The parser, marshaller, ZAP-attr decoder
// and unwrap helper that consume those bytes are all implemented and
// directly tested via crypt_test.go fixtures; this function will be
// the thin glue that calls them once the dataset-walker side lands.
//
// Until the dataset walker is in place we return a clearly-named
// "metadata locator not wired" error so callers can distinguish it
// from a corrupt-pool error.
func (fs *zfsFS) loadCryptKey(rawKeyOrPass []byte) error {
	return fmt.Errorf("zfs: DSL_CRYPTO_KEY dataset locator not yet wired (parser is implemented — see parseDSLCryptoKeyPhys / parseDSLCryptoKeyFromZAP; the missing piece is walking the DSL tree to the dataset's crypto-key object)")
}
