// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package filesystem_zfs

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// FuzzOpen feeds whole byte blobs to Open, and almost none of them are pools.
// Measured by logging every input that survived the open, a 45-second run
// produced 29 -- essentially only the seeds. A pool is a label region, an
// uberblock array and a MOS object set that have to agree with each other, and
// a random mutation of a whole image never produces that.
//
// This target splices fuzzer-chosen bytes into a *real formatted pool* instead,
// so the corrupted field is reached by code that has already found a valid
// uberblock: the MOS traversal, the DSL directory, the dnode decoder and the
// ZAP parsers behind them.

var (
	poolOnce sync.Once
	poolSeed []byte
)

// formattedPool returns the bytes of a real 16 MiB pool with a file in it.
// Built once; the fuzz target copies it per iteration and never mutates this.
func formattedPool(t testing.TB) []byte {
	t.Helper()
	poolOnce.Do(func() {
		dir, err := os.MkdirTemp("", "zfsfuzz")
		if err != nil {
			return
		}
		defer func() { _ = os.RemoveAll(dir) }()
		path := filepath.Join(dir, "pool.img")

		ifs, err := Format(path, 16*1024*1024, FormatConfig{PoolName: "fuzz"})
		if err != nil {
			return
		}
		if err := ifs.WriteFile("/seed.txt", []byte("hello hardening world"), 0o644); err != nil {
			_ = ifs.Close()
			return
		}
		_ = ifs.Close()

		img, err := os.ReadFile(path)
		if err != nil {
			return
		}
		poolSeed = img
	})
	if poolSeed == nil {
		t.Skip("could not format a seed pool")
	}
	return poolSeed
}

func FuzzOpenPatched(f *testing.F) {
	base := formattedPool(f)

	// Seeds aimed at the structures worth corrupting: the first label's
	// uberblock region, and the start of the data area behind it.
	f.Add(int64(uberblockRegionOffset), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add(int64(uberblockRegionOffset+16), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add(int64(uberblockRegionOffset+40), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add(int64(4*vdevLabelSize), []byte{0xff, 0xff, 0xff, 0xff})
	f.Add(int64(4*vdevLabelSize+0x4000), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, off int64, patch []byte) {
		if len(patch) == 0 || len(patch) > 4096 {
			return
		}
		if off < 0 || off >= int64(len(base)) {
			return
		}
		img := make([]byte, len(base))
		copy(img, base)
		copy(img[off:], patch)

		fs, err := OpenFromDevice(&memBackend{buf: img}, -1)
		if err != nil {
			return
		}
		defer func() { _ = fs.Close() }()
		_ = fs.Info()
		_, _ = fs.Stat("/")
		_, _ = fs.ListDir("/")
		_, _ = fs.ReadFile("/seed.txt")
	})
}
