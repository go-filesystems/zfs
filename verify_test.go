package filesystem_zfs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

// checkedReader is an in-memory device that asks readBlock to verify.
type checkedReader struct{ *bytes.Reader }

func (checkedReader) verifying() bool { return true }

func checkedBlock(t *testing.T, ctype uint8, content []byte, mutate func(*blkptr)) error {
	t.Helper()
	buf := make([]byte, 512)
	copy(buf, content)
	bp := makeBlkptrCksum(0, 512, 512, zcompressOff, dmotPlainFileContents, 0, 1, ctype)
	switch ctype {
	case zioChecksumFletch2:
		bp.cksum = fletcher2(buf)
	case zioChecksumSHA512:
		bp.cksum = sha512Checksum(buf)
	default:
		setBPChecksum(&bp, buf)
	}
	if mutate != nil {
		mutate(&bp)
	}
	_, err := readBlock(checkedReader{bytes.NewReader(buf)}, 0, bp)
	return err
}

// A block that matches its checksum reads; one that does not is refused with
// ErrChecksum, for each algorithm the driver verifies.
func TestVerifyBlockChecksum_RefusesMismatch(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ctype uint8
	}{{"fletcher4", zioChecksumFletch4}, {"fletcher2", zioChecksumFletch2}, {"sha256", zioChecksumSHA256}, {"sha512", zioChecksumSHA512}} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkedBlock(t, tc.ctype, []byte("hello, zfs"), nil); err != nil {
				t.Fatalf("a matching block was refused: %v", err)
			}
			for w := 0; w < 4; w++ {
				err := checkedBlock(t, tc.ctype, []byte("hello, zfs"), func(bp *blkptr) { bp.cksum[w] ^= 1 })
				if !errors.Is(err, ErrChecksum) {
					t.Fatalf("checksum word %d off by one bit: err = %v, want ErrChecksum", w, err)
				}
			}
		})
	}
}

// A salted checksum type of a pool whose salt is unknown is not verified (and
// not refused).
func TestVerifyBlockChecksum_SaltedWithoutSaltReads(t *testing.T) {
	for _, ct := range []uint8{zioChecksumSkein, zioChecksumEdonR, zioChecksumBlake3} {
		if err := checkedBlock(t, ct, []byte("x"), func(bp *blkptr) { bp.cksum = [4]uint64{1, 2, 3, 4} }); err != nil {
			t.Fatalf("type %d without a salt must read as before: %v", ct, err)
		}
	}
}

// saltedReader is checkedReader plus a pool checksum salt.
type saltedReader struct {
	checkedReader
	salt *[32]byte
}

func (s saltedReader) checksumSalt() *[32]byte   { return s.salt }
func (s saltedReader) setChecksumSalt(*[32]byte) {}

func testSalt() *[32]byte {
	var s [32]byte
	for i := range s {
		s[i] = byte(0xA0 + i)
	}
	return &s
}

// Skein, Edon-R and BLAKE3 are keyed with the pool salt: a matching block reads,
// every flipped bit of every checksum word is refused, a different salt is refused.
func TestVerifyBlockChecksum_Salted(t *testing.T) {
	buf := make([]byte, 512)
	copy(buf, "salted block")
	for _, ct := range []uint8{zioChecksumSkein, zioChecksumEdonR, zioChecksumBlake3} {
		bp := makeBlkptrCksum(0, 512, 512, zcompressOff, dmotPlainFileContents, 0, 1, ct)
		bp.cksum = saltedChecksum(ct, buf, testSalt())
		if err := verifyBlockChecksum(bp, buf, testSalt()); err != nil {
			t.Fatalf("type %d: matching block refused: %v", ct, err)
		}
		for w := 0; w < 4; w++ {
			bad := bp
			bad.cksum[w] ^= 1
			if err := verifyBlockChecksum(bad, buf, testSalt()); !errors.Is(err, ErrChecksum) {
				t.Fatalf("type %d word %d: %v", ct, w, err)
			}
		}
		other := *testSalt()
		other[0] ^= 1
		if err := verifyBlockChecksum(bp, buf, &other); !errors.Is(err, ErrChecksum) {
			t.Fatalf("type %d: another pool's salt accepted: %v", ct, err)
		}
		// through readBlock, with the reader carrying the salt
		rd := saltedReader{checkedReader{bytes.NewReader(buf)}, testSalt()}
		if _, err := readBlock(rd, 0, bp); err != nil {
			t.Fatalf("type %d: readBlock: %v", ct, err)
		}
		buf[3] ^= 1
		if _, err := readBlock(rd, 0, bp); !errors.Is(err, ErrChecksum) {
			t.Fatalf("type %d: damaged block read: %v", ct, err)
		}
		buf[3] ^= 1
	}
}

// Encrypted non-objset blocks: Edon-R (salted, no DEDUP flag) folds like
// fletcher, Skein and BLAKE3 (DEDUP) do not (zio_checksum.c:187-207, 514-525).
func TestVerifyBlockChecksum_SaltedCrypt(t *testing.T) {
	buf := make([]byte, 512)
	copy(buf, "ciphertext")
	for _, tc := range []struct {
		ct   uint8
		fold bool
	}{{zioChecksumSkein, false}, {zioChecksumBlake3, false}, {zioChecksumEdonR, true}} {
		got := saltedChecksum(tc.ct, buf, testSalt())
		bp := makeBlkptrCksum(0, 512, 512, zcompressOff, dmotPlainFileContents, 0, 1, tc.ct)
		bp.prop |= blkPropCryptBit
		right := [4]uint64{got[0], got[1], 0xdead, 0xbeef}
		wrong := [4]uint64{got[0] ^ got[2], got[1] ^ got[3], 0, 0}
		if tc.fold {
			right, wrong = wrong, right
		}
		bp.cksum = right
		if err := verifyBlockChecksum(bp, buf, testSalt()); err != nil {
			t.Fatalf("type %d: correct truncation refused: %v", tc.ct, err)
		}
		bp.cksum = wrong
		if err := verifyBlockChecksum(bp, buf, testSalt()); !errors.Is(err, ErrChecksum) {
			t.Fatalf("type %d: wrong truncation accepted: %v", tc.ct, err)
		}
	}
}

// Without the verifying reader nothing changes: the same mismatch reads.
func TestVerifyBlockChecksum_OffByDefault(t *testing.T) {
	buf := make([]byte, 512)
	bp := makeBlkptrCksum(0, 512, 512, zcompressOff, dmotPlainFileContents, 0, 1, zioChecksumFletch4)
	bp.cksum = [4]uint64{9, 9, 9, 9}
	if _, err := readBlock(bytes.NewReader(buf), 0, bp); err != nil {
		t.Fatalf("a plain reader must not verify: %v", err)
	}
}

// An encrypted (non-objset) block stores w0^w2, w1^w3 and ignores the last two
// words (zio_checksum.c:514-525); an objset block keeps all four.
func TestVerifyBlockChecksum_CryptTruncation(t *testing.T) {
	buf := make([]byte, 512)
	copy(buf, "ciphertext")
	got := fletcher4(buf)
	bp := makeBlkptrCksum(0, 512, 512, zcompressOff, dmotPlainFileContents, 0, 1, zioChecksumFletch4)
	bp.prop |= blkPropCryptBit
	bp.cksum = [4]uint64{got[0] ^ got[2], got[1] ^ got[3], 0xdead, 0xbeef} // MAC words are not compared
	if err := verifyBlockChecksum(bp, buf, nil); err != nil {
		t.Fatalf("encrypted block with a correct truncated checksum was refused: %v", err)
	}
	bp.cksum[0] ^= 1
	if err := verifyBlockChecksum(bp, buf, nil); !errors.Is(err, ErrChecksum) {
		t.Fatalf("encrypted block with a wrong truncated checksum: %v", err)
	}
	obj := makeBlkptrCksum(0, 512, 512, zcompressOff, dmotObjset, 0, 1, zioChecksumFletch4)
	obj.prop |= blkPropCryptBit
	obj.cksum = [4]uint64{got[0] ^ got[2], got[1] ^ got[3], 0, 0}
	if err := verifyBlockChecksum(obj, buf, nil); !errors.Is(err, ErrChecksum) {
		t.Fatalf("an objset block compares all four words: %v", err)
	}
}

// flipByteAt corrupts one byte of the image file.
func flipByteAt(t *testing.T, img string, off int64) {
	t.Helper()
	f, err := os.OpenFile(img, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var b [1]byte
	if _, err := f.ReadAt(b[:], off); err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0x01
	if _, err := f.WriteAt(b[:], off); err != nil {
		t.Fatal(err)
	}
}

// The defect this closes: a damaged block was returned silently. A byte flipped
// in a file's data block, and one in a directory's ZAP block, must be refused
// with ErrChecksum by every read entry point; the untouched file still reads.
func TestCorruptBlockIsRefusedOnRead(t *testing.T) {
	img := filepath.Join(t.TempDir(), "pool.img")
	ifs, err := Format(img, 8<<20, FormatConfig{PoolName: "ckread"})
	if err != nil {
		t.Fatal(err)
	}
	fs := ifs.(*zfsFS)
	good := bytes.Repeat([]byte("intact "), 100)
	victim := bytes.Repeat([]byte("damaged "), 100)
	if err := fs.WriteFile("/good", good, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/victim", victim, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.MkDir("/d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/d/inner", []byte("inner"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Where the victim's data block and /d's ZAP block live.
	vobj, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, "/victim")
	if err != nil {
		t.Fatal(err)
	}
	vdn, err := fs.zplDS.zplOS.readObject(vobj)
	if err != nil {
		t.Fatal(err)
	}
	dataOff := fs.partOffset + vdn.blkptrAt(0).dvaOffset(0)
	dobj, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, "/d")
	if err != nil {
		t.Fatal(err)
	}
	ddn, err := fs.zplDS.zplOS.readObject(dobj)
	if err != nil {
		t.Fatal(err)
	}
	zapOff := fs.partOffset + ddn.blkptrAt(0).dvaOffset(0)
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}

	// Pristine image first: everything reads.
	ok, err := Open(img, -1)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ok.ReadFile("/victim"); err != nil || !bytes.Equal(got, victim) {
		t.Fatalf("pristine ReadFile: %v", err)
	}
	ok.Close()

	flipByteAt(t, img, dataOff+3)
	flipByteAt(t, img, zapOff+40)

	bad, err := Open(img, -1)
	if err != nil {
		t.Fatalf("Open of an image whose damage is in a data block: %v", err)
	}
	defer bad.Close()

	if got, err := bad.ReadFile("/good"); err != nil || !bytes.Equal(got, good) {
		t.Fatalf("an untouched file must still read: %v", err)
	}
	if got, err := bad.ReadFile("/victim"); !errors.Is(err, ErrChecksum) {
		t.Fatalf("ReadFile of a damaged block: err = %v, %d bytes returned; want ErrChecksum and no data", err, len(got))
	}
	of, err := bad.(filesystem.Opener).OpenFile("/victim")
	if err == nil {
		if _, rerr := of.ReadAt(make([]byte, 16), 0); !errors.Is(rerr, ErrChecksum) {
			t.Fatalf("ReadAt of a damaged block: err = %v, want ErrChecksum", rerr)
		}
	} else if !errors.Is(err, ErrChecksum) {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := bad.ListDir("/d"); !errors.Is(err, ErrChecksum) {
		t.Fatalf("ListDir of a damaged ZAP block: err = %v, want ErrChecksum", err)
	}
	if _, err := bad.Stat("/d/inner"); !errors.Is(err, ErrChecksum) {
		t.Fatalf("Stat through a damaged ZAP block: err = %v, want ErrChecksum", err)
	}
}

// zio_checksum.c:514-525: an encrypted non-objset block drops the MAC words, and
// folds (w0^w2, w1^w3) only for types WITHOUT ZCHECKSUM_FLAG_DEDUP; SHA-256 and
// SHA-512/256 have it, so their first two words are compared as they are.
func TestVerifyBlockChecksum_CryptDedupTypesDoNotFold(t *testing.T) {
	buf := make([]byte, 512)
	copy(buf, "ciphertext")
	for _, tc := range []struct {
		ctype uint8
		sum   func([]byte) [4]uint64
	}{{zioChecksumSHA256, sha256Checksum}, {zioChecksumSHA512, sha512Checksum}} {
		got := tc.sum(buf)
		bp := makeBlkptrCksum(0, 512, 512, zcompressOff, dmotPlainFileContents, 0, 1, tc.ctype)
		bp.prop |= blkPropCryptBit
		bp.cksum = [4]uint64{got[0], got[1], 0xdead, 0xbeef} // unfolded, MAC words ignored
		if err := verifyBlockChecksum(bp, buf, nil); err != nil {
			t.Fatalf("type %d: an unfolded truncated checksum was refused: %v", tc.ctype, err)
		}
		bp.cksum = [4]uint64{got[0] ^ got[2], got[1] ^ got[3], 0, 0} // the fletcher fold is wrong here
		if err := verifyBlockChecksum(bp, buf, nil); !errors.Is(err, ErrChecksum) {
			t.Fatalf("type %d: a folded checksum was accepted: %v", tc.ctype, err)
		}
	}
}

// A damaged first copy of a block that has a second DVA is read from the copy,
// as the kernel does; with both damaged it is ErrChecksum.
func TestReadBlockFallsBackToAnotherDVA(t *testing.T) {
	good := bytes.Repeat([]byte("good block "), 50)[:512]
	bad := append([]byte(nil), good...)
	bad[7] ^= 1
	img := make([]byte, 2048)
	copy(img[0:], bad)    // DVA 0 at 0: damaged
	copy(img[512:], good) // DVA 1 at 512
	bp := makeBlkptrCksum(0, 512, 512, zcompressOff, dmotPlainFileContents, 0, 1, zioChecksumFletch4)
	bp.dva[1] = makeDVA(512, 512)
	setBPChecksum(&bp, good)
	got, err := readBlock(checkedReader{bytes.NewReader(img)}, 0, bp)
	if err != nil || !bytes.Equal(got, good) {
		t.Fatalf("the intact copy was not used: %v", err)
	}
	copy(img[512:], bad)
	if _, err := readBlock(checkedReader{bytes.NewReader(img)}, 0, bp); !errors.Is(err, ErrChecksum) {
		t.Fatalf("both copies damaged: err = %v, want ErrChecksum", err)
	}
}
