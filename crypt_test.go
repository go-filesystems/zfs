package filesystem_zfs

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/go-encryptions/zfscrypt"
)

// TestIsEncryptedFlag confirms the blkptr accessor reads the right
// bit out of blk_prop.
func TestIsEncryptedFlag(t *testing.T) {
	var bp blkptr
	if bp.isEncrypted() {
		t.Errorf("zero blkptr unexpectedly reads as encrypted")
	}
	bp.prop = blkPropCryptBit
	if !bp.isEncrypted() {
		t.Errorf("blkptr with BP_CRYPT bit set should read as encrypted")
	}
	// Setting other bits doesn't flip the encryption flag.
	bp.prop = 0
	bp.prop |= bpDedupBit
	if bp.isEncrypted() {
		t.Errorf("dedup bit set must not be confused with crypt bit")
	}
}

// TestDecryptBlockPayloadWithoutContext ensures the "no context"
// error path fires rather than panicking with a nil deref.
func TestDecryptBlockPayloadWithoutContext(t *testing.T) {
	var bp blkptr
	bp.prop = blkPropCryptBit
	_, err := decryptBlockPayload(nil, bp, []byte("ciphertext"))
	if err == nil {
		t.Fatalf("expected error when crypt context is nil")
	}
	if !strings.Contains(err.Error(), "no crypt context") {
		t.Errorf("error %q does not mention missing context", err)
	}
}

// TestExtractBlockCryptShape confirms the field-extraction helper
// returns the documented sizes AND pulls the salt/IV/MAC from the exact
// blkptr slots the OpenZFS encoder uses (DVA[2] words for salt+IV1, the
// upper 32 bits of fill for IV2, and cksum[2..3] for the MAC).
func TestExtractBlockCryptShape(t *testing.T) {
	var bp blkptr
	bp.dva[2][0] = 0x1122334455667788 // salt
	bp.dva[2][1] = 0x99aabbccddeeff00 // iv[0:8]
	bp.fill = 0xCAFEBABE00000001      // low32 = fill count, high32 = IV2
	bp.cksum[2] = 0xaabbccddeeff0011  // mac[0:8]
	bp.cksum[3] = 0x2233445566778899  // mac[8:16]

	iv, mac, salt, err := extractBlockCrypt(bp)
	if err != nil {
		t.Fatalf("extractBlockCrypt: %v", err)
	}
	if len(iv) != zfscrypt.IVSize {
		t.Errorf("IV size = %d, want %d", len(iv), zfscrypt.IVSize)
	}
	if len(mac) != zfscrypt.MACSize {
		t.Errorf("MAC size = %d, want %d", len(mac), zfscrypt.MACSize)
	}
	if len(salt) != 8 {
		t.Errorf("salt size = %d, want 8", len(salt))
	}

	// salt = DVA[2] word0 (little-endian).
	wantSalt := make([]byte, 8)
	binary.LittleEndian.PutUint64(wantSalt, bp.dva[2][0])
	if !bytes.Equal(salt, wantSalt) {
		t.Errorf("salt = %x, want %x (DVA[2] word0)", salt, wantSalt)
	}
	// iv[0:8] = DVA[2] word1; iv[8:12] = upper 32 bits of fill (IV2).
	wantIV := make([]byte, 12)
	binary.LittleEndian.PutUint64(wantIV[0:8], bp.dva[2][1])
	binary.LittleEndian.PutUint32(wantIV[8:12], uint32(bp.fill>>32))
	if !bytes.Equal(iv, wantIV) {
		t.Errorf("iv = %x, want %x (DVA[2] word1 + IV2)", iv, wantIV)
	}
	// mac = cksum[2] || cksum[3].
	wantMAC := make([]byte, 16)
	binary.LittleEndian.PutUint64(wantMAC[0:8], bp.cksum[2])
	binary.LittleEndian.PutUint64(wantMAC[8:16], bp.cksum[3])
	if !bytes.Equal(mac, wantMAC) {
		t.Errorf("mac = %x, want %x (cksum[2..3])", mac, wantMAC)
	}
}

// TestBlockAADIsEmpty pins the OpenZFS behaviour that a normal level-0
// data block's AEAD carries NO additional authenticated data: only ZIL
// and dnode/objset blocks do, and those compute the authbuf over whole
// in-memory buffers (out of scope for this reader). The previous
// implementation hashed a fabricated 24-byte slice of blkptr fields,
// which would have made every real-pool tag verification fail.
func TestBlockAADIsEmpty(t *testing.T) {
	var bp blkptr
	bp.birth = 0x42
	bp.prop = blkPropCryptBit | 0xff
	bp.dva[0][0] = 0xdeadbeef
	if ad := blockAAD(bp); len(ad) != 0 {
		t.Fatalf("blockAAD length = %d, want 0 (normal data blocks have no AAD)", len(ad))
	}
}

// sampleDSLCryptoKey returns a fully-populated DSLCryptoKey suitable
// for round-tripping through parse/marshal. Field values are arbitrary
// but distinct so a copy bug in either direction will show up as a
// field-mismatch failure.
func sampleDSLCryptoKey() *DSLCryptoKey {
	iv := make([]byte, DSLWrappingIVLen)
	for i := range iv {
		iv[i] = byte(0x10 + i)
	}
	mac := make([]byte, DSLWrappingMACLen)
	for i := range mac {
		mac[i] = byte(0x40 + i)
	}
	mek := make([]byte, DSLMasterKeyMaxLen)
	for i := range mek {
		mek[i] = byte(0x80 + i)
	}
	hk := make([]byte, DSLHMACKeyMaxLen)
	for i := range hk {
		hk[i] = byte(0xa0 + i)
	}
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	return &DSLCryptoKey{
		Suite:            zfscrypt.AES256CCM,
		GUID:             0x0123456789abcdef,
		Version:          1,
		Iters:            350000,
		IV:               iv,
		MAC:              mac,
		WrappedMasterKey: mek,
		WrappedHMACKey:   hk,
		Salt:             salt,
	}
}

// TestDSLCryptoKeyPhysRoundTrip is the headline test for the parser:
// marshalling a known-good DSLCryptoKey then parsing it back must yield
// a byte-identical struct.
func TestDSLCryptoKeyPhysRoundTrip(t *testing.T) {
	in := sampleDSLCryptoKey()
	buf, err := marshalDSLCryptoKeyPhys(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(buf) != DSLCryptoKeyPhysSize {
		t.Fatalf("marshalled length = %d, want %d", len(buf), DSLCryptoKeyPhysSize)
	}
	// Pad bytes must be zero (offsets 44..47 in the packed record).
	if buf[44] != 0 || buf[45] != 0 || buf[46] != 0 || buf[47] != 0 {
		t.Errorf("pad bytes not zeroed: %x %x %x %x", buf[44], buf[45], buf[46], buf[47])
	}

	out, err := parseDSLCryptoKeyPhys(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.Suite != in.Suite {
		t.Errorf("Suite: got %v, want %v", out.Suite, in.Suite)
	}
	if out.GUID != in.GUID {
		t.Errorf("GUID: got %x, want %x", out.GUID, in.GUID)
	}
	if out.Version != in.Version {
		t.Errorf("Version: got %d, want %d", out.Version, in.Version)
	}
	if out.Iters != in.Iters {
		t.Errorf("Iters: got %d, want %d", out.Iters, in.Iters)
	}
	if !bytes.Equal(out.IV, in.IV) {
		t.Errorf("IV mismatch:\n  got  %x\n  want %x", out.IV, in.IV)
	}
	if !bytes.Equal(out.MAC, in.MAC) {
		t.Errorf("MAC mismatch:\n  got  %x\n  want %x", out.MAC, in.MAC)
	}
	if !bytes.Equal(out.WrappedMasterKey, in.WrappedMasterKey) {
		t.Errorf("MEK mismatch")
	}
	if !bytes.Equal(out.WrappedHMACKey, in.WrappedHMACKey) {
		t.Errorf("HMAC key mismatch")
	}
	if !bytes.Equal(out.Salt, in.Salt) {
		t.Errorf("Salt mismatch:\n  got  %x\n  want %x", out.Salt, in.Salt)
	}
}

// TestDSLCryptoKeyPhysDoesNotAlias verifies the parser copies field
// slices out of the input buffer — mutating the buffer after parse
// must not change the parsed struct.
func TestDSLCryptoKeyPhysDoesNotAlias(t *testing.T) {
	in := sampleDSLCryptoKey()
	buf, err := marshalDSLCryptoKeyPhys(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := parseDSLCryptoKeyPhys(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Scribble over every byte of the source buffer.
	for i := range buf {
		buf[i] = 0xff
	}
	if !bytes.Equal(out.IV, in.IV) || !bytes.Equal(out.MAC, in.MAC) ||
		!bytes.Equal(out.WrappedMasterKey, in.WrappedMasterKey) ||
		!bytes.Equal(out.WrappedHMACKey, in.WrappedHMACKey) ||
		!bytes.Equal(out.Salt, in.Salt) {
		t.Errorf("parser aliases input buffer")
	}
}

// TestParseDSLCryptoKeyPhysErrors covers each error branch in the
// parser.
func TestParseDSLCryptoKeyPhysErrors(t *testing.T) {
	good, err := marshalDSLCryptoKeyPhys(sampleDSLCryptoKey())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	t.Run("too short", func(t *testing.T) {
		_, err := parseDSLCryptoKeyPhys(good[:DSLCryptoKeyPhysSize-1])
		if err == nil || !strings.Contains(err.Error(), "too short") {
			t.Errorf("expected too-short error, got %v", err)
		}
	})

	t.Run("invalid suite zero", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		binary.LittleEndian.PutUint64(bad[0:8], 0)
		_, err := parseDSLCryptoKeyPhys(bad)
		if err == nil || !strings.Contains(err.Error(), "invalid crypto suite") {
			t.Errorf("expected invalid-suite error, got %v", err)
		}
	})

	t.Run("invalid suite high", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		binary.LittleEndian.PutUint64(bad[0:8], 1<<32)
		_, err := parseDSLCryptoKeyPhys(bad)
		if err == nil || !strings.Contains(err.Error(), "invalid crypto suite") {
			t.Errorf("expected invalid-suite error, got %v", err)
		}
	})

	t.Run("non-zero pad", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		bad[46] = 0x42
		_, err := parseDSLCryptoKeyPhys(bad)
		if err == nil || !strings.Contains(err.Error(), "pad") {
			t.Errorf("expected pad error, got %v", err)
		}
	})
}

// TestMarshalDSLCryptoKeyPhysErrors covers the marshal validators.
func TestMarshalDSLCryptoKeyPhysErrors(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(k *DSLCryptoKey)
		wantSub string
	}{
		{"nil", func(k *DSLCryptoKey) {}, "nil key"},
		{"bad suite", func(k *DSLCryptoKey) { k.Suite = zfscrypt.Suite(99) }, "invalid suite"},
		{"short IV", func(k *DSLCryptoKey) { k.IV = k.IV[:5] }, "IV must"},
		{"short MAC", func(k *DSLCryptoKey) { k.MAC = k.MAC[:5] }, "MAC must"},
		{"short MEK", func(k *DSLCryptoKey) { k.WrappedMasterKey = k.WrappedMasterKey[:5] }, "master key"},
		{"short HMAC", func(k *DSLCryptoKey) { k.WrappedHMACKey = k.WrappedHMACKey[:5] }, "hmac key"},
		{"short salt", func(k *DSLCryptoKey) { k.Salt = k.Salt[:1] }, "salt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var k *DSLCryptoKey
			if tc.name != "nil" {
				k = sampleDSLCryptoKey()
				tc.mutate(k)
			}
			_, err := marshalDSLCryptoKeyPhys(k)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not contain %q", err, tc.wantSub)
			}
		})
	}
}

// sampleZAPAttrs returns the ZAP-attribute form of the same key
// sampleDSLCryptoKey produces.
func sampleZAPAttrs(k *DSLCryptoKey) map[string][]byte {
	u64 := func(v uint64) []byte {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, v)
		return b
	}
	return map[string][]byte{
		zapDSLCryptoKeyCryptSuite: u64(uint64(k.Suite)),
		zapDSLCryptoKeyGUID:       u64(k.GUID),
		zapDSLCryptoKeyVersion:    u64(k.Version),
		zapDSLCryptoKeyIters:      u64(k.Iters),
		zapDSLCryptoKeyIV:         append([]byte(nil), k.IV...),
		zapDSLCryptoKeyMAC:        append([]byte(nil), k.MAC...),
		zapDSLCryptoKeyMasterKey:  append([]byte(nil), k.WrappedMasterKey...),
		zapDSLCryptoKeyHMACKey:    append([]byte(nil), k.WrappedHMACKey...),
		zapDSLCryptoKeySalt:       append([]byte(nil), k.Salt...),
	}
}

// TestParseDSLCryptoKeyFromZAPRoundTrip exercises the ZAP-attribute
// parser path.
func TestParseDSLCryptoKeyFromZAPRoundTrip(t *testing.T) {
	in := sampleDSLCryptoKey()
	attrs := sampleZAPAttrs(in)
	out, err := parseDSLCryptoKeyFromZAP(attrs)
	if err != nil {
		t.Fatalf("parseDSLCryptoKeyFromZAP: %v", err)
	}
	if out.Suite != in.Suite || out.GUID != in.GUID || out.Version != in.Version ||
		out.Iters != in.Iters || !bytes.Equal(out.IV, in.IV) ||
		!bytes.Equal(out.MAC, in.MAC) ||
		!bytes.Equal(out.WrappedMasterKey, in.WrappedMasterKey) ||
		!bytes.Equal(out.WrappedHMACKey, in.WrappedHMACKey) ||
		!bytes.Equal(out.Salt, in.Salt) {
		t.Errorf("round-trip mismatch:\n  in  %+v\n  out %+v", in, out)
	}
}

// TestParseDSLCryptoKeyFromZAPVersionOptional verifies the version
// entry is optional and defaults to 0.
func TestParseDSLCryptoKeyFromZAPVersionOptional(t *testing.T) {
	in := sampleDSLCryptoKey()
	attrs := sampleZAPAttrs(in)
	delete(attrs, zapDSLCryptoKeyVersion)
	out, err := parseDSLCryptoKeyFromZAP(attrs)
	if err != nil {
		t.Fatalf("parseDSLCryptoKeyFromZAP: %v", err)
	}
	if out.Version != 0 {
		t.Errorf("Version with no entry = %d, want 0", out.Version)
	}
}

// TestParseDSLCryptoKeyFromZAPErrors covers each error branch in the
// ZAP-attribute parser.
func TestParseDSLCryptoKeyFromZAPErrors(t *testing.T) {
	good := sampleZAPAttrs(sampleDSLCryptoKey())

	t.Run("nil map", func(t *testing.T) {
		_, err := parseDSLCryptoKeyFromZAP(nil)
		if err == nil || !strings.Contains(err.Error(), "nil map") {
			t.Errorf("expected nil-map error, got %v", err)
		}
	})

	required := []string{
		zapDSLCryptoKeyCryptSuite,
		zapDSLCryptoKeyGUID,
		zapDSLCryptoKeyIters,
		zapDSLCryptoKeyIV,
		zapDSLCryptoKeyMAC,
		zapDSLCryptoKeyMasterKey,
		zapDSLCryptoKeyHMACKey,
		zapDSLCryptoKeySalt,
	}
	for _, name := range required {
		t.Run("missing "+name, func(t *testing.T) {
			attrs := map[string][]byte{}
			for k, v := range good {
				attrs[k] = v
			}
			delete(attrs, name)
			_, err := parseDSLCryptoKeyFromZAP(attrs)
			if err == nil || !strings.Contains(err.Error(), "missing") {
				t.Errorf("expected missing-attr error for %q, got %v", name, err)
			}
		})
	}

	// Wrong-size scalar (suite encoded in 4 bytes instead of 8).
	t.Run("bad u64 size", func(t *testing.T) {
		attrs := map[string][]byte{}
		for k, v := range good {
			attrs[k] = v
		}
		attrs[zapDSLCryptoKeyCryptSuite] = []byte{1, 2, 3, 4}
		_, err := parseDSLCryptoKeyFromZAP(attrs)
		if err == nil || !strings.Contains(err.Error(), "must be 8 bytes") {
			t.Errorf("expected size error, got %v", err)
		}
	})

	// Wrong-size byte field (IV truncated to 5 bytes).
	t.Run("bad iv size", func(t *testing.T) {
		attrs := map[string][]byte{}
		for k, v := range good {
			attrs[k] = v
		}
		attrs[zapDSLCryptoKeyIV] = []byte{1, 2, 3, 4, 5}
		_, err := parseDSLCryptoKeyFromZAP(attrs)
		if err == nil || !strings.Contains(err.Error(), "IV") {
			t.Errorf("expected IV size error, got %v", err)
		}
	})

	// Invalid suite value (KeyLen()==0 path).
	t.Run("invalid suite", func(t *testing.T) {
		attrs := map[string][]byte{}
		for k, v := range good {
			attrs[k] = v
		}
		bad := make([]byte, 8)
		binary.LittleEndian.PutUint64(bad, 99)
		attrs[zapDSLCryptoKeyCryptSuite] = bad
		_, err := parseDSLCryptoKeyFromZAP(attrs)
		if err == nil || !strings.Contains(err.Error(), "invalid crypto suite") {
			t.Errorf("expected invalid-suite error, got %v", err)
		}
	})

	// Out-of-range suite value (rawSuite > 0xff path).
	t.Run("suite too large", func(t *testing.T) {
		attrs := map[string][]byte{}
		for k, v := range good {
			attrs[k] = v
		}
		bad := make([]byte, 8)
		binary.LittleEndian.PutUint64(bad, 1<<32)
		attrs[zapDSLCryptoKeyCryptSuite] = bad
		_, err := parseDSLCryptoKeyFromZAP(attrs)
		if err == nil || !strings.Contains(err.Error(), "invalid crypto suite") {
			t.Errorf("expected invalid-suite error, got %v", err)
		}
	})

	// Wrong-size version entry.
	t.Run("bad version size", func(t *testing.T) {
		attrs := map[string][]byte{}
		for k, v := range good {
			attrs[k] = v
		}
		attrs[zapDSLCryptoKeyVersion] = []byte{1, 2, 3}
		_, err := parseDSLCryptoKeyFromZAP(attrs)
		if err == nil || !strings.Contains(err.Error(), "VERSION") {
			t.Errorf("expected version size error, got %v", err)
		}
	})
}

// TestDSLCryptoKeyUnwrapAADStable confirms the AAD bytes are
// deterministic and reflect the GUID + suite + version, so a wrapped
// blob can't be relocated to a different dataset without tripping the
// AEAD tag check.
func TestDSLCryptoKeyUnwrapAADStable(t *testing.T) {
	k := sampleDSLCryptoKey()
	ad1 := dslCryptoKeyUnwrapAAD(k)
	ad2 := dslCryptoKeyUnwrapAAD(k)
	if !bytes.Equal(ad1, ad2) {
		t.Errorf("AAD is non-deterministic")
	}
	if len(ad1) != 24 {
		t.Errorf("AAD length = %d, want 24", len(ad1))
	}
	if binary.LittleEndian.Uint64(ad1[0:8]) != k.GUID {
		t.Errorf("AAD[0:8] != GUID")
	}
	if binary.LittleEndian.Uint64(ad1[8:16]) != uint64(k.Suite) {
		t.Errorf("AAD[8:16] != suite")
	}
	if binary.LittleEndian.Uint64(ad1[16:24]) != k.Version {
		t.Errorf("AAD[16:24] != version")
	}

	// Mutating the GUID changes the AAD.
	k2 := sampleDSLCryptoKey()
	k2.GUID++
	if bytes.Equal(ad1, dslCryptoKeyUnwrapAAD(k2)) {
		t.Errorf("AAD did not change when GUID changed")
	}

	// Version-0 keys authenticate the GUID only (8 bytes), per OpenZFS
	// zio_crypt_key_unwrap().
	k0 := sampleDSLCryptoKey()
	k0.Version = 0
	ad0 := dslCryptoKeyUnwrapAAD(k0)
	if len(ad0) != 8 {
		t.Fatalf("version-0 AAD length = %d, want 8", len(ad0))
	}
	if binary.LittleEndian.Uint64(ad0[0:8]) != k0.GUID {
		t.Errorf("version-0 AAD[0:8] != GUID")
	}
}

// TestUnwrapDSLCryptoKeyValidation covers the input-validation branches
// of unwrapDSLCryptoKey. The success path requires real ciphertext from
// a wrap step and is left to integration testing once the dataset
// walker lands.
func TestUnwrapDSLCryptoKeyValidation(t *testing.T) {
	t.Run("nil key", func(t *testing.T) {
		_, _, err := unwrapDSLCryptoKey(nil, []byte("hunter2"))
		if err == nil || !strings.Contains(err.Error(), "nil key") {
			t.Errorf("expected nil-key error, got %v", err)
		}
	})
	t.Run("empty pass", func(t *testing.T) {
		_, _, err := unwrapDSLCryptoKey(sampleDSLCryptoKey(), nil)
		if err == nil || !strings.Contains(err.Error(), "empty passphrase") {
			t.Errorf("expected empty-pass error, got %v", err)
		}
	})
	t.Run("raw key wrong size", func(t *testing.T) {
		k := sampleDSLCryptoKey()
		k.Iters = 0
		_, _, err := unwrapDSLCryptoKey(k, []byte("short"))
		if err == nil || !strings.Contains(err.Error(), "raw key must be") {
			t.Errorf("expected raw-key size error, got %v", err)
		}
	})
	t.Run("bad iters propagates", func(t *testing.T) {
		// DeriveWrappingKey rejects iters <= 0; we hit that path by
		// pretending iters is set but secretly zero is handled above,
		// so use a different signal: keep iters>0 but show the call
		// reaches zfscrypt by passing valid inputs and watching for
		// the eventual AEAD-tag failure (the wrap inputs aren't
		// genuine ciphertext, so Unwrap must error out cleanly rather
		// than panic).
		_, _, err := unwrapDSLCryptoKey(sampleDSLCryptoKey(), []byte("hunter2"))
		if err == nil {
			t.Fatalf("expected unwrap to fail on synthetic ciphertext")
		}
		if !strings.Contains(err.Error(), "unwrap") && !strings.Contains(err.Error(), "message authentication") {
			// Either error class is acceptable; both prove the AEAD
			// layer was reached.
			t.Errorf("expected unwrap/AEAD error, got %v", err)
		}
	})
	t.Run("wrong iv length on parsed key", func(t *testing.T) {
		k := sampleDSLCryptoKey()
		k.IV = k.IV[:8]
		_, _, err := unwrapDSLCryptoKey(k, []byte("hunter2"))
		if err == nil || !strings.Contains(err.Error(), "IV must be 12 bytes") {
			t.Errorf("expected IV-length error, got %v", err)
		}
	})
	t.Run("raw key path reaches AEAD", func(t *testing.T) {
		// iters == 0 hits the "raw key" branch. The 32-byte raw key
		// is fed straight to Unwrap; the synthetic ciphertext won't
		// authenticate, so we expect an unwrap/AEAD error rather than
		// success — what matters here is that the raw-key branch is
		// exercised (no PBKDF2 derivation).
		k := sampleDSLCryptoKey()
		k.Iters = 0
		raw := make([]byte, zfscrypt.WrappingKeyLen)
		_, _, err := unwrapDSLCryptoKey(k, raw)
		if err == nil {
			t.Fatalf("expected AEAD failure on synthetic ciphertext")
		}
	})
	t.Run("derive wrapping key error", func(t *testing.T) {
		// Iters > 0 with a passphrase reaches DeriveWrappingKey. With
		// a positive (sane) iters value the call succeeds and proceeds
		// to Unwrap, which fails on synthetic data. To hit the
		// DeriveWrappingKey error return we'd need iters to be invalid
		// post-validation, which the parser already rejects upstream
		// (iters is uint64 and DeriveWrappingKey only errors on
		// iters<=0). This branch is therefore unreachable from a
		// parsed-on-disk key and is left as a defense-in-depth check.
		// We still exercise the positive-iters path here to keep the
		// PBKDF2 derivation line covered.
		k := sampleDSLCryptoKey()
		k.Iters = 1 // minimal positive iters keeps the test fast
		_, _, err := unwrapDSLCryptoKey(k, []byte("p"))
		if err == nil {
			t.Fatalf("expected AEAD failure")
		}
	})
}

// TestOpenFromDeviceDatasetWithKeyLocatorNotWired exercises the public
// entry point end-to-end. Until the DSL-tree walker is wired the entry
// point surfaces a clearly-named "locator not wired" error rather than
// silently mis-decrypting. The parser/marshaller/ZAP-decoder this
// commit lands are exercised directly by the round-trip tests above —
// the locator wiring is the next step (see TODO in loadCryptKey).
func TestOpenFromDeviceDatasetWithKeyLocatorNotWired(t *testing.T) {
	dev := newMemBackend(256 * 1024)

	prev := openReadInfo
	openReadInfo = func(_ io.ReaderAt, _ int64) (Info, error) {
		return Info{Offset: 0}, nil
	}
	t.Cleanup(func() { openReadInfo = prev })

	prevPart := openPartitionOffset
	openPartitionOffset = func(_ io.ReaderAt, _ int) (int64, error) {
		return 0, nil
	}
	t.Cleanup(func() { openPartitionOffset = prevPart })

	_, err := OpenFromDeviceDatasetWithKey(dev, -1, "ROOT", []byte("hunter2"))
	if err == nil {
		t.Fatalf("expected loadCryptKey locator-not-wired error")
	}
	if !strings.Contains(err.Error(), "DSL_CRYPTO_KEY") {
		t.Errorf("error %q does not point at the locator TODO", err)
	}
}

// memBackend is a tiny in-memory BlockBackend for the smoke test.
type memBackend struct{ buf []byte }

func newMemBackend(n int) *memBackend { return &memBackend{buf: make([]byte, n)} }

func (m *memBackend) ReadAt(p []byte, off int64) (int, error)  { return copy(p, m.buf[off:]), nil }
func (m *memBackend) WriteAt(p []byte, off int64) (int, error) { return copy(m.buf[off:], p), nil }
func (m *memBackend) Sync() error                              { return nil }
func (m *memBackend) Size() (int64, error)                     { return int64(len(m.buf)), nil }
func (m *memBackend) Truncate(size int64) error                { m.buf = m.buf[:size]; return nil }
func (m *memBackend) Close() error                             { return nil }

// TestDecryptBlockPayloadOracle is an end-to-end test against a real
// OpenZFS 2.2 encrypted pool (aes-256-gcm). It builds a blkptr whose
// salt/IV/MAC slots hold the exact bytes the OpenZFS encoder wrote, a
// cryptCtx carrying the real unwrapped master key, and decrypts the
// real 4096-byte on-disk ciphertext block through the production path
// (extractBlockCrypt -> DeriveBlockKey -> blockAAD -> DecryptBlock).
// The GCM tag only verifies if every field placement is correct, so a
// pass proves the confirmed layout end-to-end. Vectors were captured
// with zdb; see github.com/go-encryptions/zfscrypt TestOpenZFSOracleVectors
// for the key-derivation half of the same pool.
func TestDecryptBlockPayloadOracle(t *testing.T) {
	mustHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("hex: %v", err)
		}
		return b
	}
	mek := mustHex("068333f3e4b511cff3875c15df066367c4f8a2f9dfef0722ec2e63cb75675f8c")

	// Reconstruct the on-disk blkptr crypt slots from the oracle:
	//   salt = DVA[2] word0, iv[0:8] = DVA[2] word1, iv[8:12] = IV2 (high32 of fill),
	//   mac  = cksum[2] || cksum[3].
	salt := mustHex("f4c84b8f5ba994f1")
	iv := mustHex("86aaf533f77fb83e20edfe74")
	mac := mustHex("7fe245cdb07227e6d5a35e2352ac0089")

	var bp blkptr
	bp.prop = blkPropCryptBit
	bp.dva[2][0] = binary.LittleEndian.Uint64(salt)
	bp.dva[2][1] = binary.LittleEndian.Uint64(iv[0:8])
	bp.fill = uint64(binary.LittleEndian.Uint32(iv[8:12])) << 32 // IV2 in high 32 bits

	bp.cksum[2] = binary.LittleEndian.Uint64(mac[0:8])
	bp.cksum[3] = binary.LittleEndian.Uint64(mac[8:16])

	// Sanity: extractBlockCrypt round-trips the slots back to the oracle bytes.
	gotIV, gotMAC, gotSalt, err := extractBlockCrypt(bp)
	if err != nil {
		t.Fatalf("extractBlockCrypt: %v", err)
	}
	if !bytes.Equal(gotSalt, salt) || !bytes.Equal(gotIV, iv) || !bytes.Equal(gotMAC, mac) {
		t.Fatalf("extractBlockCrypt mismatch:\n salt %x want %x\n iv %x want %x\n mac %x want %x",
			gotSalt, salt, gotIV, iv, gotMAC, mac)
	}

	c := &cryptCtx{suite: zfscrypt.AES256GCM, mek: mek}
	ct, err := base64.StdEncoding.DecodeString(oracleZFSCiphertext)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	pt, err := decryptBlockPayload(c, bp, ct)
	if err != nil {
		t.Fatalf("decryptBlockPayload (real on-disk block): %v", err)
	}
	if !bytes.Contains(pt, []byte("ZFSORACLEPATTERN0123456789ABCDEF")) {
		t.Fatalf("decrypted block missing known plaintext; head=%x", pt[:48])
	}
}

// oracleZFSCiphertext is the full 4096-byte L0 data block (DVA 0:66000)
// of the known file in a real OpenZFS 2.2 aes-256-gcm pool, base64.
// Decrypting it with the oracle key + blkptr crypt fields reproduces the
// known plaintext, validating the on-disk crypt layout end-to-end.
const oracleZFSCiphertext = "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"
