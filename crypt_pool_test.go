package filesystem_zfs

// crypt_pool_test.go — end-to-end validation of the DSL_CRYPTO_KEY
// locator against a REAL encrypted pool.
//
// testdata/crypto/encrypted.tar.zst holds a single-vdev pool image
// (d0.img) created with OpenZFS 2.2.2 in a Tart VM:
//
//	truncate -s 128M /tmp/enc.raw
//	zpool create -o ashift=12 -O compression=off -O atime=off encpool /tmp/enc.raw
//	printf 'hunter2!' | zfs create -o encryption=aes-256-gcm \
//	    -o keyformat=passphrase -o keylocation=prompt \
//	    -o pbkdf2iters=100000 encpool/secret
//	printf 'hello-encrypted-zfs\n' > /encpool/secret/greeting.txt
//	# blob.bin = ("0123456789abcdefZFSencrypt!!*#@=" * 256)  (8192 bytes)
//	zpool export encpool
//
// The dataset "secret" is its own encryption root (aes-256-gcm,
// passphrase keyformat, PBKDF2 100000 iters). Opening it with the
// passphrase exercises the whole new path: MOS walk → DSL directory →
// DD_FIELD_CRYPTO_KEY_OBJ → crypto-key ZAP (zapListAllRaw) →
// parseDSLCryptoKeyFromZAP → unwrapDSLCryptoKey → transparent
// per-block AES-256-GCM decrypt of the file contents.

import (
	"archive/tar"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// extractCryptoFixture decompresses testdata/crypto/<name>.tar.zst into a
// temp dir and returns the path of the single d0.img vdev.
func extractCryptoFixture(t *testing.T, name string) string {
	t.Helper()
	src := filepath.Join("testdata", "crypto", name+".tar.zst")
	f, err := os.Open(src)
	if err != nil {
		t.Fatalf("open fixture %s: %v", src, err)
	}
	defer f.Close()
	zr, err := zstd.NewReader(f)
	if err != nil {
		t.Fatalf("zstd reader: %v", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	dir := t.TempDir()
	var img string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		dst := filepath.Join(dir, hdr.Name)
		w, err := os.Create(dst)
		if err != nil {
			t.Fatalf("create %s: %v", dst, err)
		}
		if _, err := io.Copy(w, tr); err != nil {
			t.Fatalf("extract %s: %v", dst, err)
		}
		w.Close()
		img = dst
	}
	if img == "" {
		t.Fatal("fixture contained no regular file")
	}
	return img
}

func openEncryptedFixture(t *testing.T, dataset string, pass []byte) FS {
	t.Helper()
	img := extractCryptoFixture(t, "encrypted")
	f, err := os.OpenFile(img, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open image: %v", err)
	}
	fs, err := OpenFromDeviceDatasetWithKey(&osFileBackend{f: f}, -1, dataset, pass)
	if err != nil {
		t.Fatalf("OpenFromDeviceDatasetWithKey(%q): %v", dataset, err)
	}
	return fs
}

// TestOpenEncryptedPoolPassphrase is the headline end-to-end test: it
// opens the real aes-256-gcm dataset with the correct passphrase and
// reads back two known-plaintext files, proving the locator + unwrap +
// per-block decrypt path is byte-exact against OpenZFS.
func TestOpenEncryptedPoolPassphrase(t *testing.T) {
	fs := openEncryptedFixture(t, "secret", []byte("hunter2!"))

	cases := []struct {
		path    string
		size    int
		wantMD5 string
	}{
		{"/greeting.txt", 20, "b092d2cf86883dfd07f4c49a7fdf74d7"},
		{"/blob.bin", 8192, "19a90b5e364293985ba87fb03776bba7"},
	}
	for _, c := range cases {
		data, err := fs.ReadFile(c.path)
		if err != nil {
			t.Fatalf("read %s: %v", c.path, err)
		}
		if len(data) != c.size {
			t.Fatalf("%s size = %d want %d", c.path, len(data), c.size)
		}
		sum := md5.Sum(data)
		if got := hex.EncodeToString(sum[:]); got != c.wantMD5 {
			t.Errorf("%s md5 = %s want %s (decrypt mismatch)", c.path, got, c.wantMD5)
		}
	}
	if got := string(mustRead(t, fs, "/greeting.txt")); got != "hello-encrypted-zfs\n" {
		t.Errorf("greeting content = %q", got)
	}
}

func mustRead(t *testing.T, fs FS, path string) []byte {
	t.Helper()
	b, err := fs.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// TestOpenEncryptedPoolWrongPassphrase confirms a wrong passphrase is
// rejected at unwrap time (AEAD tag mismatch) rather than silently
// yielding a garbage master key.
func TestOpenEncryptedPoolWrongPassphrase(t *testing.T) {
	img := extractCryptoFixture(t, "encrypted")
	f, err := os.OpenFile(img, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open image: %v", err)
	}
	defer f.Close()
	_, err = OpenFromDeviceDatasetWithKey(&osFileBackend{f: f}, -1, "secret", []byte("wrong-pass"))
	if err == nil {
		t.Fatal("expected wrong-passphrase open to fail")
	}
}

// TestLocateDSLCryptoKeyRealPool checks the locator in isolation against
// the real pool: it must find and parse the DSL_CRYPTO_KEY for the
// encrypted dataset and reject an unencrypted / nonexistent one.
func TestLocateDSLCryptoKeyRealPool(t *testing.T) {
	img := extractCryptoFixture(t, "encrypted")
	f, err := os.OpenFile(img, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open image: %v", err)
	}
	defer f.Close()
	dev := &osFileBackend{f: f}

	off, err := openPartitionOffset(dev, -1)
	if err != nil {
		t.Fatalf("partition offset: %v", err)
	}
	info, err := openReadInfo(dev, off)
	if err != nil {
		t.Fatalf("read info: %v", err)
	}
	rootBPBuf := make([]byte, blkptrSize)
	if _, err := dev.ReadAt(rootBPBuf, info.Offset+40); err != nil {
		t.Fatalf("read root BP: %v", err)
	}
	rootBP := parseBlkptr(rootBPBuf)
	partOff := off + vdevLabelStartSize

	key, err := locateDSLCryptoKey(dev, partOff, rootBP, "secret")
	if err != nil {
		t.Fatalf("locateDSLCryptoKey(secret): %v", err)
	}
	if key.Suite.KeyLen() == 0 {
		t.Errorf("located key has invalid suite %d", uint8(key.Suite))
	}
	if len(key.WrappedMasterKey) != DSLMasterKeyMaxLen || len(key.WrappedHMACKey) != DSLHMACKeyMaxLen {
		t.Errorf("located key blob lengths wrong: mek=%d hmac=%d", len(key.WrappedMasterKey), len(key.WrappedHMACKey))
	}
	if key.Iters == 0 {
		t.Errorf("expected non-zero PBKDF2 iters for a passphrase dataset")
	}
	// The unwrap must succeed with the real passphrase.
	if _, _, err := unwrapDSLCryptoKey(key, []byte("hunter2!")); err != nil {
		t.Errorf("unwrap located key: %v", err)
	}

	// The pool root ("") is not encrypted — the locator must say so.
	if _, err := locateDSLCryptoKey(dev, partOff, rootBP, ""); err == nil {
		t.Error("expected pool root to have no DSL_CRYPTO_KEY")
	}
	// A nonexistent dataset must fail in the child-dir walk.
	if _, err := locateDSLCryptoKey(dev, partOff, rootBP, "nope"); err == nil {
		t.Error("expected nonexistent dataset to fail")
	}
	// A deep path whose first segment exists but has no children fails at
	// the child-dir descent (secret has no sub-datasets).
	if _, err := locateDSLCryptoKey(dev, partOff, rootBP, "secret/deeper"); err == nil {
		t.Error("expected descent past a leaf dataset to fail")
	}
	// A snapshot suffix is stripped before the walk; a bogus dataset with a
	// snap suffix still fails on the dataset name.
	if _, err := locateDSLCryptoKey(dev, partOff, rootBP, "nope@snap"); err == nil {
		t.Error("expected snapshot of nonexistent dataset to fail")
	}
}

// TestLocateDSLCryptoKeyBadRootBP covers the MOS-open failure branch: a
// null root block pointer cannot be opened as an object set.
func TestLocateDSLCryptoKeyBadRootBP(t *testing.T) {
	if _, err := locateDSLCryptoKey(bytes.NewReader(nil), 0, blkptr{}, "secret"); err == nil {
		t.Fatal("expected MOS-open failure for a null root BP")
	}
}

// TestLocateDSLCryptoKeyWrongObjsetType covers the branch that rejects a
// root block pointer that resolves to a non-META object set.
func TestLocateDSLCryptoKeyWrongObjsetType(t *testing.T) {
	blk := make([]byte, 1024)
	blk[704] = dmuOSTZFS // os_type != DMU_OST_META
	bp := makeBlkptr(0, 1024, 1024, zcompressOff, dmotObjset, 0, 1)
	if _, err := locateDSLCryptoKey(bytes.NewReader(blk), 0, bp, "secret"); err == nil {
		t.Fatal("expected wrong-objset-type error")
	}
}

// TestOpenFromDeviceDatasetWithKeyWrongDataset drives the public entry
// point's dataset-open error branch against the real pool.
func TestOpenFromDeviceDatasetWithKeyWrongDataset(t *testing.T) {
	img := extractCryptoFixture(t, "encrypted")
	f, err := os.OpenFile(img, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open image: %v", err)
	}
	defer f.Close()
	// "secret2" does not exist: loadCryptKey's locator fails first.
	if _, err := OpenFromDeviceDatasetWithKey(&osFileBackend{f: f}, -1, "secret2", []byte("hunter2!")); err == nil {
		t.Fatal("expected open of nonexistent encrypted dataset to fail")
	}
}
