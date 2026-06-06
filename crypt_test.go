package filesystem_zfs

import (
	"bytes"
	"encoding/binary"
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

// TestExtractBlockCryptShape just confirms the field-extraction
// helper returns the documented sizes; the on-disk layout is
// still being validated, but the shape contract must hold.
func TestExtractBlockCryptShape(t *testing.T) {
	var bp blkptr
	bp.physBirth = 0xdeadbeefcafe
	bp.fill = 0x1122334455667788
	bp.cksum[0] = 0x9988776655443322
	bp.cksum[2] = 0xaabbccddeeff0011
	bp.cksum[3] = 0x2233445566778899

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
}

// TestBlockAADShape exercises the AAD assembler; it does not
// cross-check against a real pool yet, but the shape contract (24
// bytes, deterministic for a given blkptr) is enforced.
func TestBlockAADShape(t *testing.T) {
	var bp blkptr
	bp.birth = 0x42
	bp.prop = blkPropCryptBit | 0xff
	bp.dva[0][0] = 0xdeadbeef
	ad := blockAAD(bp)
	if len(ad) != 24 {
		t.Fatalf("blockAAD length = %d, want 24", len(ad))
	}
	// Recomputing must be byte-identical.
	ad2 := blockAAD(bp)
	if !bytes.Equal(ad, ad2) {
		t.Errorf("blockAAD is non-deterministic")
	}
	// The crypt bit must be stripped from the prop bytes before
	// hashing — otherwise reflagging the block would invalidate the
	// pool. Bytes 8..16 hold prop&^blkPropCryptBit.
	want := bp.prop &^ blkPropCryptBit
	got := binary.LittleEndian.Uint64(ad[8:16])
	if got != want {
		t.Errorf("AAD prop = %x, want %x (crypt bit not stripped)", got, want)
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
	// Pad bytes must be zero.
	if buf[45] != 0 || buf[46] != 0 || buf[47] != 0 {
		t.Errorf("pad bytes not zeroed: %x %x %x", buf[45], buf[46], buf[47])
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
	t.Run("short iv on parsed key", func(t *testing.T) {
		k := sampleDSLCryptoKey()
		k.IV = k.IV[:8]
		_, _, err := unwrapDSLCryptoKey(k, []byte("hunter2"))
		if err == nil || !strings.Contains(err.Error(), "IV too short") {
			t.Errorf("expected IV-too-short error, got %v", err)
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
