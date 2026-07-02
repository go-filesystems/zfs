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
//   * DSL-tree locator (loadCryptKey → locateDSLCryptoKey /
//     findCryptoKeyObj): walks the MOS from the uberblock root BP to
//     the dataset's DSL directory, resolves its DD_FIELD_CRYPTO_KEY_OBJ
//     (following the parent chain for inherited keys), reads the
//     crypto-key ZAP off disk via zapListAllRaw and feeds it to the
//     parser. Validated end-to-end against a real aes-256-gcm
//     passphrase pool (crypt_pool_test.go).

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
// Status: fully wired. The crypto primitives (github.com/go-encryptions/ccm
// + .../zfscrypt), the DSL_CRYPTO_KEY on-disk parser
// (parseDSLCryptoKeyPhys / parseDSLCryptoKeyFromZAP) and the DSL-tree
// walker that locates a dataset's DSL_CRYPTO_KEY object (loadCryptKey →
// locateDSLCryptoKey) are all in place and validated end-to-end against a
// real aes-256-gcm passphrase pool (see crypt_pool_test.go).
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

	// Read the pool's root block pointer (uberblock.ub_rootbp) once; both
	// the crypto-key locator and the dataset open below navigate from it.
	rootBPBuf := make([]byte, blkptrSize)
	if _, err := dev.ReadAt(rootBPBuf, info.Offset+40); err != nil {
		dev.Close()
		return nil, fmt.Errorf("zfs: read root block pointer: %w", err)
	}
	rootBP := parseBlkptr(rootBPBuf)
	if rootBP.isNull() {
		dev.Close()
		return nil, fmt.Errorf("zfs: null root block pointer")
	}

	if err := fs.loadCryptKey(rootBP, datasetPath, wrappingKeyOrPassphrase); err != nil {
		dev.Close()
		return nil, err
	}
	// Replace fs.f with the crypting wrapper so every subsequent
	// readBlock sees the crypt context.
	fs.f = &cryptingReader{blockBackend: dev, crypt: fs.crypt}

	if ds, e3 := openNamedDataset(fs.f, fs.partOffset, rootBP, datasetPath); e3 == nil {
		fs.zplDS = ds
		if sz, e4 := fs.f.Size(); e4 == nil {
			fs.initAllocator(sz)
		}
	} else if datasetPath != "" {
		fs.f.Close()
		return nil, fmt.Errorf("zfs: open dataset %q: %w", datasetPath, e3)
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
	// hmacKey is the 64-byte sibling key recovered alongside the
	// MEK (SHA512_HMAC_KEYLEN); OpenZFS uses it to authenticate
	// metadata that bypasses the AEAD layer.
	hmacKey []byte
	// version is the DSL_CRYPTO_KEY format version. It selects the
	// per-block dnode AAD shape (the blkptr_auth_buf gained an 8-byte
	// pad and the non-portable blk_prop masking changed between
	// versions 0 and 1).
	version uint64
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

	// Dnode blocks are only PARTIALLY encrypted: the dnode cores and
	// their block pointers stay in plaintext (for scrub/claim) and only
	// the encrypted bonus buffers are ciphered, gathered into one AEAD
	// stream with a constructed AAD. Every other encrypted block type
	// (ZPL file data, directory ZAP contents, …) is a normal whole-block
	// AEAD with no additional authenticated data.
	if bp.dmuType() == dmotDnode {
		return decryptDnodeBlock(c, key, iv, mac, ciphertext)
	}

	pt, err := zfscrypt.DecryptBlock(c.suite, key, iv, mac, ciphertext, blockAAD(bp))
	if err != nil {
		return nil, fmt.Errorf("zfs: decrypt block: %w", err)
	}
	return pt, nil
}

// extractBlockCrypt pulls the per-block salt (8 bytes), IV (12
// bytes) and MAC (16 bytes) out of an encrypted block pointer.
//
// Layout — CONFIRMED against OpenZFS (zfs-2.2.x):
//
//   - module/os/{linux,freebsd}/zfs/zio_crypt.c
//     zio_crypt_encode_params_bp / zio_crypt_decode_params_bp:
//
//     salt   = blk_dva[2].dva_word[0]            (ZIO_DATA_SALT_LEN = 8)
//     iv[0:8] = blk_dva[2].dva_word[1]
//     iv[8:12] = BP_GET_IV2(bp)                  (ZIO_DATA_IV_LEN   = 12)
//
//   - zio_crypt_decode_mac_bp:
//
//     mac = blk_cksum.zc_word[2] || zc_word[3]   (ZIO_DATA_MAC_LEN  = 16)
//
//   - include/sys/spa.h BP_GET_IV2 macro:
//
//     BP_GET_IV2(bp) = BF64_GET(blk_fill, 32, 32)  (upper 32 bits of fill)
//
// The diagram in the include/sys/spa.h block comment ("encrypted
// block pointer layout") places the salt at word 4 (DVA[2] word0),
// IV1 at word 5 (DVA[2] word1), IV2 in the upper 32 bits of word b
// (fill count) and the MAC in words e/f (cksum[2..3]).
//
// On a native-little-endian pool the crypt fields are copied
// byte-for-byte out of the uint64 dva/fill/cksum words, so the
// returned byte strings are the little-endian encoding of those
// words. (Big-endian pools byte-swap the words before encoding;
// our blkptr is parsed little-endian from a known-LE on-disk image,
// so re-encoding little-endian here reproduces the original byte
// string the cryptographic layer authenticated.)
//
// VALIDATED end-to-end against a real encrypted pool (aes-256-gcm,
// passphrase keyformat) created with the OpenZFS 2.2 userland: the
// salt/IV/MAC extracted here, combined with the unwrapped master
// key, decrypt the on-disk ciphertext to the exact known plaintext
// (GCM tag verifies). See crypt_test.go golden vectors.
func extractBlockCrypt(bp blkptr) (iv, mac, salt []byte, err error) {
	// salt (8 bytes): DVA[2] word0.
	salt = make([]byte, 8)
	binary.LittleEndian.PutUint64(salt, bp.dva[2][0])

	// IV (12 bytes): DVA[2] word1 (low 8) + upper 32 bits of fill (IV2).
	iv = make([]byte, zfscrypt.IVSize)
	binary.LittleEndian.PutUint64(iv[0:8], bp.dva[2][1])
	iv2 := uint32(bp.fill >> 32) // BP_GET_IV2: BF64_GET(blk_fill, 32, 32)
	binary.LittleEndian.PutUint32(iv[8:12], iv2)

	// MAC (16 bytes): cksum words 2 and 3.
	mac = make([]byte, zfscrypt.MACSize)
	binary.LittleEndian.PutUint64(mac[0:8], bp.cksum[2])
	binary.LittleEndian.PutUint64(mac[8:16], bp.cksum[3])

	return iv, mac, salt, nil
}

// blockAAD returns the additional-authenticated-data the AEAD runs
// over for an ordinary level-0 data block.
//
// CONFIRMED against OpenZFS (zfs-2.2.x) module/os/*/zfs/zio_crypt.c:
// zio_crypt_init_uios() dispatches on the DMU object type. Only
// DMU_OT_INTENT_LOG (ZIL) and DMU_OT_DNODE blocks carry an authbuf;
// the `default:` branch — which covers every normal file/ZPL data
// block — sets `*authbuf = NULL; *auth_len = 0;`. In other words a
// normal data block's AEAD has NO additional authenticated data:
// the salt/IV/MAC stored in the block pointer are all that bind the
// ciphertext, and the MAC alone authenticates the payload.
//
// (ZIL and dnode/objset blocks DO authenticate extra bytes, but
// those are computed over whole in-memory buffers — see
// zio_crypt_init_uios_zil / _dnode — not a small fixed slice of the
// blkptr. Decrypting those block types is out of scope for this
// reader, which targets ZPL file data.)
//
// The previous implementation hashed a fabricated 24-byte slice of
// blkptr fields; that did not match any OpenZFS code path and would
// have made every GCM/CCM tag verification fail. Validated against a
// real aes-256-gcm pool: passing a nil AAD here is what makes the
// on-disk tag verify.
func blockAAD(bp blkptr) []byte {
	_ = bp
	return nil
}

// ---------------------------------------------------------------------------
// DSL_CRYPTO_KEY on-disk layout
// ---------------------------------------------------------------------------
//
// In OpenZFS the DSL_CRYPTO_KEY object is a ZAP whose attributes are the
// wrapped MEK, wrapped HMAC key, IV, MAC, salt, iters, crypto suite and
// GUID (see module/zfs/dsl_crypt.c dsl_crypto_key_open() and the
// DSL_CRYPTO_KEY_* macros in include/sys/dsl_crypt.h). There is no raw
// "phys" bonus blob — every field is an individual ZAP entry; the
// in-memory unwrapped form is zio_crypt_key_t (include/sys/zio_crypt.h).
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
// Constants below are CONFIRMED against OpenZFS (zfs-2.2.x):
//
//   include/sys/zio_crypt.h:
//     #define MASTER_KEY_MAX_LEN  32
//     #define SHA512_HMAC_KEYLEN  64
//     #define WRAPPING_IV_LEN     ZIO_DATA_IV_LEN   (= 12)
//     #define WRAPPING_MAC_LEN    ZIO_DATA_MAC_LEN  (= 16)
//   include/sys/zio.h:
//     #define ZIO_DATA_SALT_LEN   8
//     #define ZIO_DATA_IV_LEN     12
//     #define ZIO_DATA_MAC_LEN    16
//
// module/zfs/dsl_crypt.c dsl_crypto_key_open() reads exactly:
//   MASTER_KEY    -> MASTER_KEY_MAX_LEN (32) bytes
//   HMAC_KEY      -> SHA512_HMAC_KEYLEN (64) bytes
//   IV            -> WRAPPING_IV_LEN    (12) bytes
//   MAC           -> WRAPPING_MAC_LEN   (16) bytes
//   pbkdf2salt    -> uint64 (the salt fed to PBKDF2-HMAC-SHA1)
//   pbkdf2iters   -> uint64

const (
	// DSLMasterKeyMaxLen is the length of the wrapped master encryption
	// key blob (MASTER_KEY_MAX_LEN in OpenZFS).
	DSLMasterKeyMaxLen = 32
	// DSLHMACKeyMaxLen is the length of the wrapped HMAC key blob
	// (SHA512_HMAC_KEYLEN in OpenZFS — 64 bytes, NOT 32). The HMAC key
	// keys an HMAC-SHA512, so it is a full 64-byte block.
	DSLHMACKeyMaxLen = 64
	// DSLWrappingIVLen is the length of the wrap-time IV. OpenZFS uses
	// WRAPPING_IV_LEN == ZIO_DATA_IV_LEN == 12 bytes — the same 12-byte
	// nonce length used for per-block IVs.
	DSLWrappingIVLen = 12
	// DSLWrappingMACLen is the length of the wrap-time MAC tag.
	DSLWrappingMACLen = 16
	// DSLSaltLen is the length of the PBKDF2 salt (the on-disk
	// pbkdf2salt property is a uint64; it is fed to PBKDF2 as its
	// 8-byte little-endian encoding).
	DSLSaltLen = 8
	// DSLCryptoKeyPhysSize is the on-wire packed size of the
	// driver-internal "phys"-style record used for round-tripping key
	// blobs in tests and out-of-band tooling (NOT an OpenZFS on-disk
	// format — OpenZFS stores these fields as ZAP attributes; see
	// parseDSLCryptoKeyFromZAP for the real on-disk shape):
	//   suite(8) + guid(8) + version(8) + iters(8) +
	//   iv(12) + pad(4) + mac(16) +
	//   wrapped MEK(32) + wrapped HMAC(64) + salt(8) = 168 bytes.
	DSLCryptoKeyPhysSize = 8 + 8 + 8 + 8 + 12 + 4 + 16 + DSLMasterKeyMaxLen + DSLHMACKeyMaxLen + DSLSaltLen
)

// ZAP attribute names used by OpenZFS to store DSL_CRYPTO_KEY fields.
// Mirrors the DSL_CRYPTO_KEY_* macros in include/sys/dsl_crypt.h and
// the ZFS_PROP_PBKDF2_{SALT,ITERS} property names (module/zfs/dsl_crypt.c
// stores the salt/iters under the property names, not DSL_CRYPTO_*).
const (
	zapDSLCryptoKeyCryptSuite = "DSL_CRYPTO_SUITE"
	zapDSLCryptoKeyGUID       = "DSL_CRYPTO_GUID"
	zapDSLCryptoKeyIV         = "DSL_CRYPTO_IV"
	zapDSLCryptoKeyMAC        = "DSL_CRYPTO_MAC"
	zapDSLCryptoKeyMasterKey  = "DSL_CRYPTO_MASTER_KEY_1"
	zapDSLCryptoKeyHMACKey    = "DSL_CRYPTO_HMAC_KEY_1"
	zapDSLCryptoKeySalt       = "pbkdf2salt"
	zapDSLCryptoKeyIters      = "pbkdf2iters"
	zapDSLCryptoKeyVersion    = "DSL_CRYPTO_VERSION"
)

// zio_crypt_type_t on-disk values (OpenZFS include/sys/zio_crypt.h).
// The DSL_CRYPTO_SUITE attribute and the version≥1 unwrap AAD both use
// this numbering, which is NOT the same as the compacted
// github.com/go-encryptions/zfscrypt.Suite numbering (that library omits
// the INHERIT/ON/OFF entries, so its AES256GCM is 6 where the on-disk
// value is 8). suiteFromZioCrypt / zioCryptFromSuite bridge the two: the
// DSLCryptoKey and the crypto primitives work in zfscrypt.Suite space,
// while everything that touches the wire (the SUITE attribute and the
// AAD) uses zio_crypt space.
const (
	zioCryptAES128CCM = 3
	zioCryptAES192CCM = 4
	zioCryptAES256CCM = 5
	zioCryptAES128GCM = 6
	zioCryptAES192GCM = 7
	zioCryptAES256GCM = 8
)

// suiteFromZioCrypt maps an on-disk zio_crypt_type_t value to the
// zfscrypt.Suite the driver and crypto primitives use. ok is false for
// inherit/on/off and any out-of-range value.
func suiteFromZioCrypt(v uint64) (zfscrypt.Suite, bool) {
	switch v {
	case zioCryptAES128CCM:
		return zfscrypt.AES128CCM, true
	case zioCryptAES192CCM:
		return zfscrypt.AES192CCM, true
	case zioCryptAES256CCM:
		return zfscrypt.AES256CCM, true
	case zioCryptAES128GCM:
		return zfscrypt.AES128GCM, true
	case zioCryptAES192GCM:
		return zfscrypt.AES192GCM, true
	case zioCryptAES256GCM:
		return zfscrypt.AES256GCM, true
	default:
		return 0, false
	}
}

// zioCryptFromSuite is the inverse of suiteFromZioCrypt: it returns the
// on-disk zio_crypt_type_t value for a zfscrypt.Suite, used to rebuild
// the exact bytes OpenZFS authenticated in the unwrap AAD.
func zioCryptFromSuite(s zfscrypt.Suite) uint64 {
	switch s {
	case zfscrypt.AES128CCM:
		return zioCryptAES128CCM
	case zfscrypt.AES192CCM:
		return zioCryptAES192CCM
	case zfscrypt.AES256CCM:
		return zioCryptAES256CCM
	case zfscrypt.AES128GCM:
		return zioCryptAES128GCM
	case zfscrypt.AES192GCM:
		return zioCryptAES192GCM
	case zfscrypt.AES256GCM:
		return zioCryptAES256GCM
	default:
		return uint64(s)
	}
}

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
	// IV is the 12-byte wrap-time IV passed to AES-CCM/GCM during the
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

// parseDSLCryptoKeyPhys decodes the driver-internal packed key record.
// This is NOT an OpenZFS on-disk format (OpenZFS stores these fields as
// ZAP attributes — see parseDSLCryptoKeyFromZAP); it is a convenient
// fixed-layout encoding used for round-tripping key blobs in tests and
// for shipping a key out-of-band. The field sizes match OpenZFS:
//
//	+0   uint64 suite      (little-endian)
//	+8   uint64 guid
//	+16  uint64 version
//	+24  uint64 iters
//	+32  [12]   iv          (WRAPPING_IV_LEN)
//	+44  [4]    pad (must be zero — rejected otherwise so silent
//	            corruption is surfaced rather than swallowed)
//	+48  [16]   mac         (WRAPPING_MAC_LEN)
//	+64  [32]   wrapped master key   (MASTER_KEY_MAX_LEN)
//	+96  [64]   wrapped hmac key     (SHA512_HMAC_KEYLEN)
//	+160 [8]    salt                 (pbkdf2 salt, little-endian uint64)
//	== 168 bytes total.
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
	if buf[44] != 0 || buf[45] != 0 || buf[46] != 0 || buf[47] != 0 {
		return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY: non-zero pad bytes at offset 44..47")
	}

	k := &DSLCryptoKey{
		Suite:            suite,
		GUID:             binary.LittleEndian.Uint64(buf[8:16]),
		Version:          binary.LittleEndian.Uint64(buf[16:24]),
		Iters:            binary.LittleEndian.Uint64(buf[24:32]),
		IV:               append([]byte(nil), buf[32:44]...),
		MAC:              append([]byte(nil), buf[48:64]...),
		WrappedMasterKey: append([]byte(nil), buf[64:96]...),
		WrappedHMACKey:   append([]byte(nil), buf[96:160]...),
		Salt:             append([]byte(nil), buf[160:168]...),
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
	copy(out[32:44], k.IV)
	// out[44:48] stays zero — explicit pad.
	copy(out[48:64], k.MAC)
	copy(out[64:96], k.WrappedMasterKey)
	copy(out[96:160], k.WrappedHMACKey)
	copy(out[160:168], k.Salt)
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

	// DSL_CRYPTO_SUITE is an on-disk zio_crypt_type_t value; translate it
	// into the zfscrypt.Suite space the rest of the driver works in.
	rawSuite, err := getU64(zapDSLCryptoKeyCryptSuite)
	if err != nil {
		return nil, err
	}
	suite, ok := suiteFromZioCrypt(rawSuite)
	if !ok {
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
		Suite:            suite,
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
// bytes that wrap/unwrap pass to the AEAD.
//
// CONFIRMED against OpenZFS (zfs-2.2.x) module/os/*/zfs/zio_crypt.c
// zio_crypt_key_unwrap():
//
//	if (version == 0) {
//	    aad_len = 8;  aad[0] = LE_64(guid);
//	} else {
//	    aad_len = 24; aad[0]=LE_64(guid); aad[1]=LE_64(crypt); aad[2]=LE_64(version);
//	}
//
// i.e. version-0 pools authenticate the GUID only (8 bytes); the
// current on-disk version (1) additionally authenticates the crypto
// suite and version (24 bytes total). All little-endian.
func dslCryptoKeyUnwrapAAD(k *DSLCryptoKey) []byte {
	if k.Version == 0 {
		ad := make([]byte, 8)
		binary.LittleEndian.PutUint64(ad[0:8], k.GUID)
		return ad
	}
	ad := make([]byte, 24)
	binary.LittleEndian.PutUint64(ad[0:8], k.GUID)
	// OpenZFS authenticates the on-disk zio_crypt_type_t value here, not
	// the compacted zfscrypt.Suite number.
	binary.LittleEndian.PutUint64(ad[8:16], zioCryptFromSuite(k.Suite))
	binary.LittleEndian.PutUint64(ad[16:24], k.Version)
	return ad
}

// unwrapDSLCryptoKey takes a parsed DSLCryptoKey and a wrapping key (or
// passphrase), derives the wrapping key if needed, and returns the
// 32-byte MEK + 64-byte HMAC key. It is the bridge between the parser
// and the zfscrypt primitive layer.
//
// If iters > 0 the input is treated as a passphrase and fed through
// PBKDF2 with the stored salt+iters; otherwise the input must already
// be 32 bytes and is used directly.
//
// CONFIRMED against OpenZFS (zfs-2.2.x) module/zfs/dsl_crypt.c +
// module/os/*/zfs/zio_crypt.c, and validated end-to-end against a real
// aes-256-gcm pool: the wrap IV is exactly 12 bytes (WRAPPING_IV_LEN ==
// ZIO_DATA_IV_LEN) and is used directly as the AEAD nonce; the wrapped
// ciphertext is the 32-byte master key concatenated with the 64-byte
// HMAC key (96 bytes total).
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

	// The wrap IV is exactly 12 bytes and is used as the AEAD nonce.
	if len(k.IV) != zfscrypt.IVSize {
		return nil, nil, fmt.Errorf("zfs: unwrapDSLCryptoKey: IV must be %d bytes, got %d", zfscrypt.IVSize, len(k.IV))
	}
	wrapped := make([]byte, 0, DSLMasterKeyMaxLen+DSLHMACKeyMaxLen)
	wrapped = append(wrapped, k.WrappedMasterKey...)
	wrapped = append(wrapped, k.WrappedHMACKey...)
	ad := dslCryptoKeyUnwrapAAD(k)

	return zfscrypt.Unwrap(k.Suite, wrappingKey, k.IV, k.MAC, wrapped, ad)
}

// ddFieldCryptoKeyObj names the ZAP attribute OpenZFS stores on an
// encrypted dataset's DSL directory object; its uint64 value is the MOS
// object number of that dataset's DSL_CRYPTO_KEY. See
// include/sys/dsl_dir.h (DD_FIELD_CRYPTO_KEY_OBJ) and
// module/zfs/dsl_crypt.c dsl_dir_hold_obj(), which does
// zap_lookup(mos, ddobj, DD_FIELD_CRYPTO_KEY_OBJ, …). The "com.datto:"
// prefix reflects the feature's original authorship (Datto's native
// encryption).
const ddFieldCryptoKeyObj = "com.datto:crypto_key_obj"

// maxDSLDirParentWalk bounds the walk up the DSL directory parent chain
// when locating a dataset's crypto key. Real DSL dir hierarchies are a
// handful of levels deep (rpool/ROOT/distro); the cap only defends
// against a corrupt parent pointer that forms a chain.
const maxDSLDirParentWalk = 64

// loadCryptKey discovers the dataset's DSL_CRYPTO_KEY object, reads it,
// derives the wrapping key from the caller-supplied passphrase (or raw
// key), and unwraps the MEK + HMAC key. Populates fs.crypt on success.
//
// rootBP is the pool's uberblock root block pointer; datasetPath is the
// "/"-separated path (relative to the pool root, optionally with a
// trailing "@snap") of the dataset whose key to load. The locator reads
// only cleartext MOS metadata — the object set, DSL directory chain and
// crypto-key ZAP are never encrypted — so it runs against the raw device
// before the crypting reader is installed.
func (fs *zfsFS) loadCryptKey(rootBP blkptr, datasetPath string, rawKeyOrPass []byte) error {
	if len(rawKeyOrPass) == 0 {
		return fmt.Errorf("zfs: DSL_CRYPTO_KEY: empty passphrase / key")
	}
	key, err := locateDSLCryptoKey(fs.f, fs.partOffset, rootBP, datasetPath)
	if err != nil {
		return err
	}
	mek, hmacKey, err := unwrapDSLCryptoKey(key, rawKeyOrPass)
	if err != nil {
		return fmt.Errorf("zfs: DSL_CRYPTO_KEY unwrap: %w", err)
	}
	fs.crypt = &cryptCtx{suite: key.Suite, mek: mek, hmacKey: hmacKey, version: key.Version}
	return nil
}

// locateDSLCryptoKey walks the MOS from the pool root block pointer to
// the named dataset's DSL directory, resolves that directory's
// DSL_CRYPTO_KEY object (following the parent chain for datasets that
// inherit their key from an ancestor encryption root), reads the
// crypto-key ZAP off disk and returns the parsed key.
func locateDSLCryptoKey(r io.ReaderAt, partOff int64, rootBP blkptr, datasetPath string) (*DSLCryptoKey, error) {
	// A trailing "@snap" selects a snapshot, which shares the head
	// dataset's crypto key — drop it before the DSL-dir walk.
	dsPath, _ := splitSnapSuffix(datasetPath)

	mos, err := openObjset(r, partOff, rootBP)
	if err != nil {
		return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY: open MOS: %w", err)
	}
	if mos.osType != dmuOSTMeta {
		return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY: MOS has unexpected type %d", mos.osType)
	}

	poolDirDN, err := mos.readObject(mosPoolDirObj)
	if err != nil {
		return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY: read pool dir object: %w", err)
	}
	poolDirEntries, err := zapListAll(r, partOff, poolDirDN)
	if err != nil {
		return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY: pool dir ZAP: %w", err)
	}
	dirObj, ok := poolDirEntries[dmuPoolRootDataset]
	if !ok {
		return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY: pool dir missing 'root_dataset' key")
	}

	// Walk the child-dir chain to the requested dataset's DSL directory
	// (mirrors openNamedDataset's Step 2.5).
	for _, segment := range splitPath(dsPath) {
		dslDirDN, err := mos.readObject(dirObj)
		if err != nil {
			return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY: read DSL dir %d on the way to %q: %w", dirObj, dsPath, err)
		}
		bonus := dslDirDN.bonusData()
		if len(bonus) < ddChildDirZAPObj+8 {
			return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY: DSL dir %d bonus too short for childDirZAP", dirObj)
		}
		childZAP := binary.LittleEndian.Uint64(bonus[ddChildDirZAPObj:])
		if childZAP == 0 {
			return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY: DSL dir %d has no children resolving %q", dirObj, dsPath)
		}
		childDN, err := mos.readObject(childZAP)
		if err != nil {
			return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY: read child-dir ZAP %d: %w", childZAP, err)
		}
		children, err := zapListAll(r, partOff, childDN)
		if err != nil {
			return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY: parse child-dir ZAP %d: %w", childZAP, err)
		}
		next, ok := children[segment]
		if !ok {
			return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY: dataset segment %q not found under DSL dir %d (have: %v)", segment, dirObj, childKeys(children))
		}
		dirObj = next
	}

	cryptoObj, err := findCryptoKeyObj(r, partOff, mos, dirObj)
	if err != nil {
		return nil, err
	}

	ckDN, err := mos.readObject(cryptoObj)
	if err != nil {
		return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY: read crypto-key object %d: %w", cryptoObj, err)
	}
	attrs, err := zapListAllRaw(r, partOff, ckDN)
	if err != nil {
		return nil, fmt.Errorf("zfs: DSL_CRYPTO_KEY: read crypto-key ZAP %d: %w", cryptoObj, err)
	}
	return parseDSLCryptoKeyFromZAP(attrs)
}

// findCryptoKeyObj resolves the DSL_CRYPTO_KEY object number for the DSL
// directory dslDirObj. Each encrypted dataset's DSL directory is a ZAP
// carrying a DD_FIELD_CRYPTO_KEY_OBJ entry; a dataset that inherits its
// key from an ancestor encryption root may not carry the entry itself,
// so we walk up the dd_parent_obj chain until we find one.
func findCryptoKeyObj(r io.ReaderAt, partOff int64, mos *objset, dslDirObj uint64) (uint64, error) {
	cur := dslDirObj
	for depth := 0; cur != 0 && depth < maxDSLDirParentWalk; depth++ {
		dslDirDN, err := mos.readObject(cur)
		if err != nil {
			return 0, fmt.Errorf("zfs: DSL_CRYPTO_KEY: read DSL dir %d: %w", cur, err)
		}
		if obj, err := zapLookup(r, partOff, dslDirDN, ddFieldCryptoKeyObj); err == nil && obj != 0 {
			return obj, nil
		}
		bonus := dslDirDN.bonusData()
		if len(bonus) < ddParentObj+8 {
			break
		}
		parent := binary.LittleEndian.Uint64(bonus[ddParentObj:])
		if parent == cur {
			break
		}
		cur = parent
	}
	return 0, fmt.Errorf("zfs: DSL_CRYPTO_KEY: dataset is not encrypted or has no %q entry up the DSL-dir chain", ddFieldCryptoKeyObj)
}
