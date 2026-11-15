package filesystem_zfs

// The Linux kernel's OpenZFS module (zpool import, zfs mount) and zdb as the
// judge of this driver, in a Tart VM. Skipped unless FS_KERNEL_JUDGE=1;
// github.com/go-filesystems/kerneljudge's cmd/kerneljudge sets it and runs this
// as root in the VM:
//
//	kerneljudge run --driver <clone of this repository> [--perf]

import (
	"testing"

	filesystem "github.com/go-filesystems/interface"
	kj "github.com/go-filesystems/kerneljudge"
)

const judgePool = "kjz"

func kernelJudgeDriver() kj.Driver {
	return kj.Driver{
		Name:   "zfs",
		FSType: "zfs",
		Pool:   &kj.Pool{Name: judgePool, CreateArgs: []string{"-o", "ashift=12"}},
		Open: func(img string) (filesystem.Filesystem, error) {
			f, err := Open(img, -1)
			if err != nil {
				return nil, err
			}
			return f, nil
		},
		Format: func(img string, size int64) (filesystem.Filesystem, error) {
			return Format(img, size, FormatConfig{PoolName: judgePool})
		},
		Variants: []kj.Variant{{
			// Every symlink we write fails the kernel's readlink and stops its
			// walk: look behind them.
			Name: "no-links",
			Opts: func(o *kj.Options) { o.Caps.Symlinks = false },
		}},
		Known: []kj.Known{
			// The kernel cannot readlink a symlink we wrote (#53), which stops
			// its walk of the tree.
			{Test: `/write$`, Match: `^kernel mount walk: readlink`, Issue: "zfs#53"},
			// Our reader returns an empty target for a kernel symlink (#54).
			{Test: `/reverse-kernel$`, Match: `^our reader vs corpus: /\S*link\S*: link target want`, Issue: "zfs#54"},
		},
		// The pool is created by the judge's read-write "mount"; no mkfs step.
		Mkfs:    []string{"true"},
		Fsck:    [][]string{{"zdb", "-e", "-p", "{dir}", "-c", judgePool}},
		Compare: kj.Compare{Mtime: false, Xattrs: false, Perm: true},
	}
}

func TestKernelJudge(t *testing.T)     { kj.Run(t, kernelJudgeDriver()) }
func TestKernelJudgePerf(t *testing.T) { kj.RunPerf(t, kernelJudgeDriver(), kj.PerfOptions{}) }
