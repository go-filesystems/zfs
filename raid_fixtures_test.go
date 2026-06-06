package filesystem_zfs

import (
	"archive/tar"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// extractRAIDFixture decompresses testdata/raid/<layout>.tar.zst into a
// temp directory and returns the list of *.img file paths in lexical
// order (d0.img, d1.img, ...). Each ZFS fixture was created with
// `zpool create <pool> <layout> /tmp/zfs-fix/d*.img` in a Debian 12
// VM (zfsutils 2.1.11 + ZFS kernel module 6.1.0-48-cloud-arm64), then
// `zfs create <pool>/data` and `hello.txt` + `blob.bin` written before
// `zpool export`. The pool is exported so the on-disk state is the
// committed transaction group.
func extractRAIDFixture(t *testing.T, layout string) []string {
	t.Helper()
	src := filepath.Join("testdata", "raid", layout+".tar.zst")
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
	var out []string
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
		out = append(out, dst)
	}
	return out
}

// raidLayoutExpectations describes what the fixture contains.
type raidLayoutExpectations struct {
	poolName    string
	dataset     string // "<pool>/data"
	helloMD5    string
	blobMD5     string
	helloBytes  int
	blobBytes   int
}

func raidLayoutInfo(layout string) raidLayoutExpectations {
	poolByLayout := map[string]string{
		"single": "tp1",
		"mirror": "tp2",
		"raidz1": "tp3",
		"raidz2": "tp4",
		"raidz3": "tp5",
	}
	helloMD5 := map[string]string{
		"single": "e283a296b0edabf2856d1f6506b496fe", // hello-from-single\n
		"mirror": "9bf80bb4561d03792898e3a84975e592", // hello-from-mirror\n
		"raidz1": "0f8d50b1f6db6727dec5830944214ff8",
		"raidz2": "e9993102a615b98608a1f2b1fb8f214b",
		"raidz3": "528d1809b92c92900552b7a1a304f02f",
	}
	blobMD5 := map[string]string{
		"single": "0e2b4c683dd0f580ed98f7596fe4eaaf",
		"mirror": "260332d530ae132f55b61c25ca1e4879",
		"raidz1": "bf5f50e246300bd9e0a91e01d6e15bc0",
		"raidz2": "f106a07f21f2dd0332764ef70067e77e",
		"raidz3": "5787ea5dd603eb04c8e0b40728e3f2e3",
	}
	pool := poolByLayout[layout]
	return raidLayoutExpectations{
		poolName: pool,
		// OpenDataset's "dataset" arg is the path under the pool root
		// (the pool name is the implicit container, not a segment).
		dataset: "data",
		helloMD5:   helloMD5[layout],
		blobMD5:    blobMD5[layout],
		helloBytes: len(fmt.Sprintf("hello-from-%s\n", layout)),
		blobBytes:  64 * 1024,
	}
}

func checkRAIDExpectations(t *testing.T, fs FS, layout string) {
	t.Helper()
	exp := raidLayoutInfo(layout)
	hello, err := fs.ReadFile("/hello.txt")
	if err != nil {
		t.Fatalf("read /hello.txt from %s/data: %v", exp.poolName, err)
	}
	if len(hello) != exp.helloBytes {
		t.Fatalf("hello.txt size = %d want %d", len(hello), exp.helloBytes)
	}
	sum := md5.Sum(hello)
	if got := hex.EncodeToString(sum[:]); got != exp.helloMD5 {
		t.Fatalf("hello.txt md5 = %s want %s (content=%q)", got, exp.helloMD5, string(hello))
	}
	blob, err := fs.ReadFile("/blob.bin")
	if err != nil {
		t.Fatalf("read /blob.bin: %v", err)
	}
	if len(blob) != exp.blobBytes {
		t.Fatalf("blob.bin size = %d want %d", len(blob), exp.blobBytes)
	}
	sum2 := md5.Sum(blob)
	if got := hex.EncodeToString(sum2[:]); got != exp.blobMD5 {
		t.Fatalf("blob.bin md5 = %s want %s", got, exp.blobMD5)
	}
}
