package filesystem_zfs

import (
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

// TestOpenFromDeviceDatasetWithKeyNotImplementedYet exercises the
// public entry point end-to-end and confirms it surfaces the
// "DSL_CRYPTO_KEY parser not implemented" error rather than
// silently mis-decrypting. Replace with a real round-trip once the
// parser lands.
func TestOpenFromDeviceDatasetWithKeyNotImplementedYet(t *testing.T) {
	// Build a tiny in-memory blockBackend so the entry point gets
	// past the open-partition step before loadCryptKey trips.
	dev := newMemBackend(256 * 1024)

	// Override the read-info hook to return a benign Info — we just
	// need to reach loadCryptKey.
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
		t.Fatalf("expected loadCryptKey TODO error")
	}
	if !strings.Contains(err.Error(), "DSL_CRYPTO_KEY") {
		t.Errorf("error %q does not point at the TODO parser", err)
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
