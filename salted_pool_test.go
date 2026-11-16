package filesystem_zfs

// salted_pool_test.go — Skein, Edon-R and BLAKE3 block checksums against
// pools written by the OpenZFS KERNEL.
//
// testdata/salted/<algo>.tar.zst holds a 64 MiB single-vdev pool (d0.img)
// created in a Tart VM (Ubuntu, OpenZFS userland 2.2.2, zfs.ko 2.3.4):
//
//	zpool create -o ashift=12 -O compression=off -O atime=off \
//	    -O checksum=<algo> <algo>pool d0.img
//	yes "0123456789abcdefZFSsalted-<algo>!!*#@=" | head -c 300000 > /<algo>pool/blob.bin
//	printf 'hello-<algo>\n' > /<algo>pool/greeting.txt
//	printf 'hunter2!' | zfs create -o encryption=aes-256-gcm -o keyformat=passphrase \
//	    -o keylocation=prompt -o pbkdf2iters=100000 <algo>pool/secret
//	yes "0123456789abcdefZFSencrypt-<algo>!!*#@=" | head -c 300000 > /<algo>pool/secret/blob.bin
//	printf 'hello-encrypted-<algo>\n' > /<algo>pool/secret/greeting.txt
//	zpool export <algo>pool
//
// A scrub of each re-imported pool by the kernel reported 0 errors. The md5
// sums below are the kernel's view of the files (md5sum while mounted).

import (
	"archive/tar"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

type saltedFixture struct {
	name    string
	ctype   uint8
	plain   map[string]string // path -> md5 of the plain dataset
	secret  map[string]string // path -> md5 of the encrypted dataset
	dataset string
}

var saltedFixtures = []saltedFixture{
	{"blake3", zioChecksumBlake3,
		map[string]string{"/blob.bin": "88dfff53d48603fcfb2d78b4ea2c36cf", "/greeting.txt": "feb7308a2228e9c8df2d8a559d49f979"},
		map[string]string{"/blob.bin": "a366089da19ce6b04a91a4593e24c3f1", "/greeting.txt": "e0271c4e4c07aa5e058996a4f8da92d9"}, "secret"},
	{"skein", zioChecksumSkein,
		map[string]string{"/blob.bin": "2571a8bbc59a320e8b93f715cd1f7729", "/greeting.txt": "b47cb3b577a3f77b4240949e43bdb7f3"},
		map[string]string{"/blob.bin": "52ac12ac36eb602cc5ed216429ba69a8", "/greeting.txt": "adb10ef34dcbef2de22f8b6e323c842e"}, "secret"},
	{"edonr", zioChecksumEdonR,
		map[string]string{"/blob.bin": "16d1a7df6626b9e2a1de0b6dc91afdd1", "/greeting.txt": "f5e33da50828c67c6226ef9c8e0a29b7"},
		map[string]string{"/blob.bin": "f987d072553db9948d925e492b4847df", "/greeting.txt": "12d6d37f23723e554f688fab123c282c"}, "secret"},
}

// extractSaltedFixture writes a fresh writable copy of the pool image.
func extractSaltedFixture(t *testing.T, name string) string {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "salted", name+".tar.zst"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := zstd.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err != nil {
			t.Fatalf("fixture %s: %v", name, err)
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Name != "d0.img" {
			continue
		}
		dst := filepath.Join(t.TempDir(), "d0.img")
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(out, tr); err != nil {
			t.Fatal(err)
		}
		if err := out.Close(); err != nil {
			t.Fatal(err)
		}
		return dst
	}
}

func openSalted(t *testing.T, img string, dataset string, pass []byte) *zfsFS {
	t.Helper()
	f, err := os.OpenFile(img, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	var fs FS
	if dataset == "" {
		fs, err = OpenFromDeviceDataset(&osFileBackend{f: f}, -1, "")
	} else {
		fs, err = OpenFromDeviceDatasetWithKey(&osFileBackend{f: f}, -1, dataset, pass)
	}
	if err != nil {
		t.Fatalf("open %q: %v", dataset, err)
	}
	z, ok := fs.(*zfsFS)
	if !ok {
		t.Fatalf("unexpected FS type %T", fs)
	}
	return z
}

// firstBlock returns the first block pointer of a file and the image offset of
// its first copy.
func firstBlock(t *testing.T, fs *zfsFS, path string) (blkptr, int64) {
	t.Helper()
	obj, err := fs.zplDS.lookupPath(fs.f, fs.partOffset, path)
	if err != nil {
		t.Fatal(err)
	}
	dn, err := fs.zplDS.zplOS.readObject(obj)
	if err != nil {
		t.Fatal(err)
	}
	bp := dn.blkptrAt(0)
	return bp, fs.partOffset + bp.dvaOffset(0)
}

// firstDataBlock returns the block pointer of the file's first LEVEL-0 block
// (through the indirect block when the file has one) and its image offset.
func firstDataBlock(t *testing.T, fs *zfsFS, path string) (blkptr, int64) {
	t.Helper()
	bp, _ := firstBlock(t, fs, path)
	for bp.level() > 0 {
		blk, err := readBlock(fs.f, fs.partOffset, bp)
		if err != nil {
			t.Fatal(err)
		}
		bp = parseBlkptr(blk[:blkptrSize])
	}
	return bp, fs.partOffset + bp.dvaOffset(0)
}

// A byte flipped in a DATA block (level 0, one copy) is refused with
// ErrChecksum for each salted type, plain and encrypted, and the block really
// carries that type.
func TestSaltedPoolsRefuseDataCorruption(t *testing.T) {
	for _, fx := range saltedFixtures {
		for _, dataset := range []string{"", fx.dataset} {
			name := fx.name + "/plain"
			if dataset != "" {
				name = fx.name + "/encrypted"
			}
			t.Run(name, func(t *testing.T) {
				img := extractSaltedFixture(t, fx.name)
				pass := []byte("hunter2!")
				clean := openSalted(t, img, dataset, pass)
				bp, off := firstDataBlock(t, clean, "/blob.bin")
				if bp.level() != 0 || bp.checksumType() != fx.ctype {
					t.Fatalf("level %d type %d, want a level-0 block of type %d", bp.level(), bp.checksumType(), fx.ctype)
				}
				flipByteAt(t, img, off+100)
				bad := openSalted(t, img, dataset, pass)
				if _, err := bad.ReadFile("/blob.bin"); !errors.Is(err, ErrChecksum) {
					t.Fatalf("ReadFile of a damaged data block: %v, want ErrChecksum", err)
				}
			})
		}
	}
}

// A pool with no salt entry has its salted blocks refused with a clear error.
func TestVerifyBlockChecksum_NoSaltEntryRefusesSalted(t *testing.T) {
	bp := makeBlkptrCksum(0, 512, 512, zcompressOff, dmotPlainFileContents, 0, 1, zioChecksumBlake3)
	err := verifyBlockChecksum(bp, make([]byte, 512), noChecksumSalt)
	if !errors.Is(err, ErrChecksum) {
		t.Fatalf("err = %v, want ErrChecksum", err)
	}
	fl := makeBlkptrCksum(0, 512, 512, zcompressOff, dmotPlainFileContents, 0, 1, zioChecksumFletch4)
	fl.cksum = fletcher4(make([]byte, 512))
	if err := verifyBlockChecksum(fl, make([]byte, 512), noChecksumSalt); err != nil {
		t.Fatalf("a fletcher4 block must not need a salt: %v", err)
	}
}

func checkFiles(t *testing.T, fs *zfsFS, want map[string]string) {
	t.Helper()
	for p, sum := range want {
		data, err := fs.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		h := md5.Sum(data)
		if got := hex.EncodeToString(h[:]); got != sum {
			t.Fatalf("%s: md5 %s, the kernel wrote %s", p, got, sum)
		}
	}
}

// The driver reads kernel-written salted pools byte-identically with
// verification on, the salt having been read from the MOS, and the data blocks
// really carry the salted type (so the verification is not vacuous).
func TestSaltedPoolsReadVerified(t *testing.T) {
	for _, fx := range saltedFixtures {
		t.Run(fx.name, func(t *testing.T) {
			img := extractSaltedFixture(t, fx.name)
			plain := openSalted(t, img, "", nil)
			if plain.vb.checksumSalt() == nil {
				t.Fatal("the pool checksum salt was not read")
			}
			bp, _ := firstBlock(t, plain, "/blob.bin")
			if bp.checksumType() != fx.ctype {
				t.Fatalf("blob.bin block uses checksum type %d, want %d", bp.checksumType(), fx.ctype)
			}
			checkFiles(t, plain, fx.plain)

			enc := openSalted(t, img, fx.dataset, []byte("hunter2!"))
			ebp, _ := firstBlock(t, enc, "/blob.bin")
			if ebp.checksumType() != fx.ctype || ebp.prop&blkPropCryptBit == 0 {
				t.Fatalf("encrypted blob.bin: checksum type %d crypt %v", ebp.checksumType(), ebp.prop&blkPropCryptBit != 0)
			}
			checkFiles(t, enc, fx.secret)
		})
	}
}

// A byte flipped in every copy of a salted block (the first block pointer of a
// file here is an indirect block, which the kernel stores in two copies) is
// refused with ErrChecksum, plain and encrypted. With only the first copy
// damaged the read heals from the second, as the kernel does; the untouched
// image reads (control).
func TestSaltedPoolsRefuseCorruption(t *testing.T) {
	for _, fx := range saltedFixtures {
		for _, dataset := range []string{"", fx.dataset} {
			name := fx.name + "/plain"
			if dataset != "" {
				name = fx.name + "/encrypted"
			}
			t.Run(name, func(t *testing.T) {
				img := extractSaltedFixture(t, fx.name)
				pass := []byte("hunter2!")
				clean := openSalted(t, img, dataset, pass)
				bp, off := firstBlock(t, clean, "/blob.bin")
				if _, err := clean.ReadFile("/blob.bin"); err != nil {
					t.Fatalf("control read: %v", err)
				}
				flipByteAt(t, img, off+100)
				if bp.dva[1][0]&0xFFFFFF == 0 {
					t.Fatal("expected a second copy of the first block")
				}
				healed := openSalted(t, img, dataset, pass)
				if _, err := healed.ReadFile("/blob.bin"); err != nil {
					t.Fatalf("one damaged copy must heal from the other: %v", err)
				}
				for i := 1; i < 3 && bp.dva[i][0]&0xFFFFFF != 0; i++ {
					flipByteAt(t, img, clean.partOffset+bp.dvaOffset(i)+100)
				}
				bad := openSalted(t, img, dataset, pass)
				if _, err := bad.ReadFile("/blob.bin"); !errors.Is(err, ErrChecksum) {
					t.Fatalf("ReadFile of a damaged block: %v, want ErrChecksum", err)
				}
			})
		}
	}
}
