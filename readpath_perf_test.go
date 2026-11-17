package filesystem_zfs

// Sequential and random 4 KiB reads of one compressed file, the Linux kernel's
// OpenZFS against this driver, at 1 and 4 CPUs, for compression=off (with
// fletcher4), lz4 and zstd. The driver is measured with the default parallel
// decode and with SetReadParallelism(1) in the same rounds. Skipped unless
// FS_KERNEL_JUDGE_PERF=1; run as root in the VM:
//
//	kerneljudge run --perf --driver <clone of this repository> --test-run KernelJudgeReadPath
//
// Every figure is bracketed by kerneljudge.Calibrate: a round whose two
// calibrations differ, or that left the regime of the first round, is measured
// again (twice at most); the regime is printed on every PERF line, so that
// `kerneljudge compare` refuses runs made in different regimes.

import (
	"bytes"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
	kj "github.com/go-filesystems/kerneljudge"
)

const (
	rpLarge = 256 << 20
	rpChunk = 1 << 20
	rpReads = 20000
	rpPool  = "kjrp"
)

func rpRun(args ...string) (string, error) {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	return string(out), err
}

// rpExport exports the pool, retrying while the kernel still says it is busy
// (a just-closed file or the unmount can lag by a moment, more so on a busy host).
func rpExport(t *testing.T) {
	t.Helper()
	var out string
	var err error
	for range 10 {
		if out, err = rpRun("zpool", "export", rpPool); err == nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("zpool export: %v\n%s", err, out)
}

func rpMust(t *testing.T, args ...string) {
	t.Helper()
	if out, err := rpRun(args...); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
}

// rpGen writes rpLarge bytes of word-like text (compressible about 2x by lz4).
func rpGen(w io.Writer) error {
	r := rand.New(rand.NewPCG(42, 43))
	vocab := make([][]byte, 6000)
	for i := range vocab {
		b := make([]byte, 3+r.IntN(8))
		for j := range b {
			b[j] = byte('a' + r.IntN(26))
		}
		vocab[i] = b
	}
	buf := make([]byte, 0, 1<<20)
	for total := 0; total < rpLarge; total += len(buf) {
		buf = buf[:0]
		for len(buf) < 1<<20-16 {
			k := int(float64(len(vocab)) * r.Float64() * r.Float64() * r.Float64())
			buf = append(buf, vocab[k]...)
			if r.IntN(12) == 0 {
				buf = append(buf, '\n')
			} else {
				buf = append(buf, ' ')
			}
		}
		for len(buf) < 1<<20 {
			buf = append(buf, ' ')
		}
		if _, err := w.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

func rpRandom(read func(p []byte, off int64) error) error {
	r := rand.New(rand.NewPCG(9, 9))
	buf := make([]byte, 4096)
	for range rpReads {
		if err := read(buf, int64(r.IntN(rpLarge/4096))*4096); err != nil {
			return err
		}
	}
	return nil
}

func rpMedian(r []float64) float64 {
	s := append([]float64(nil), r...)
	sort.Float64s(s)
	return s[len(s)/2]
}

func rpOnline(t *testing.T, n int) {
	if n == 1 {
		rpRun("chcpu", "-d", "1-3")
	} else {
		rpRun("chcpu", "-e", "1-3")
	}
	time.Sleep(time.Second)
	runtime.GOMAXPROCS(n)
}

func rpLoad1() float64 {
	b, _ := os.ReadFile("/proc/loadavg")
	var v float64
	fmt.Sscanf(string(b), "%f", &v)
	return v
}

type rpSeries struct {
	vals    []float64
	regimes kj.Regimes
}

func (s *rpSeries) line(t *testing.T, name, op, impl, unit string) {
	t.Logf("PERF %s | %-14s | %-6s | median %9.1f %s | rounds %v | | %s", name, op, impl, rpMedian(s.vals), unit, s.vals, kj.RegimeText(s.regimes))
}

func TestKernelJudgeReadPath(t *testing.T) {
	if os.Getenv("FS_KERNEL_JUDGE_PERF") != "1" {
		t.Skip("FS_KERNEL_JUDGE_PERF=1 to measure")
	}
	rounds := 5
	if v, err := strconv.Atoi(os.Getenv("FS_KERNEL_JUDGE_ROUNDS")); err == nil && v > 0 {
		rounds = v
	}
	defer rpRun("chcpu", "-e", "1-3")
	for _, comp := range []string{"off", "lz4", "zstd"} {
		t.Run(comp, func(t *testing.T) {
			dir := t.TempDir()
			img, mnt := filepath.Join(dir, "pool.img"), "/kjrpmnt"
			if err := os.WriteFile(img, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(img, 1<<30); err != nil {
				t.Fatal(err)
			}
			os.MkdirAll(mnt, 0o755)
			rpMust(t, "zpool", "create", "-f", "-o", "ashift=12", "-O", "compression="+comp, "-O", "checksum=fletcher4", "-O", "mountpoint="+mnt, rpPool, img)
			f, err := os.Create(filepath.Join(mnt, "large.bin"))
			if err != nil {
				t.Fatal(err)
			}
			if err := rpGen(f); err != nil {
				t.Fatal(err)
			}
			f.Close()
			rpExport(t)
			defer rpRun("zpool", "export", rpPool)
			imp := func() { rpMust(t, "zpool", "import", "-d", dir, "-o", "readonly=on", rpPool) }
			dropCaches := func() { os.WriteFile("/proc/sys/vm/drop_caches", []byte("3"), 0) }

			for _, ncpu := range []int{1, 4} {
				rpOnline(t, ncpu)
				for i := 0; i < 24 && rpLoad1() > 1.0; i++ {
					time.Sleep(5 * time.Second)
				}
				if rpLoad1() > 1.0 {
					t.Skip("VM load above 1.0")
				}
				name := fmt.Sprintf("zfs-%s-cpus%d", comp, ncpu)
				// series: seq / rand cold / rand warm for kernel, ours(par), ours(serial)
				var seq, cold, warm [3]rpSeries
				const kernel, par, serial = 0, 1, 2
				add := func(s *rpSeries, v float64) { s.vals = append(s.vals, v) }
				oneRound := func() {
					dropCaches()
					imp()
					start := time.Now()
					fl, err := os.Open(filepath.Join(mnt, "large.bin"))
					if err != nil {
						t.Fatal(err)
					}
					n, err := io.CopyBuffer(io.Discard, struct{ io.Reader }{fl}, make([]byte, rpChunk))
					el := time.Since(start)
					fl.Close()
					if err != nil || n != rpLarge {
						t.Fatalf("kernel read %d: %v", n, err)
					}
					add(&seq[kernel], float64(n)/(1<<20)/el.Seconds())
					rpExport(t)
					imp()
					fk, _ := os.Open(filepath.Join(mnt, "large.bin"))
					rd := func(p []byte, off int64) error {
						_, err := fk.ReadAt(p, off)
						if err == io.EOF {
							err = nil
						}
						return err
					}
					start = time.Now()
					if err := rpRandom(rd); err != nil {
						t.Fatal(err)
					}
					add(&cold[kernel], rpReads/time.Since(start).Seconds())
					start = time.Now()
					rpRandom(rd)
					add(&warm[kernel], rpReads/time.Since(start).Seconds())
					fk.Close()
					rpExport(t)

					for _, w := range []int{par, serial} {
						workers := 0
						if w == serial {
							workers = 1
						}
						open := func() (filesystem.Filesystem, filesystem.File) {
							ifs, err := Open(img, -1)
							if err != nil {
								t.Fatal(err)
							}
							// The same file measures a build without the setter (before v0.8.0).
							if s, ok := ifs.(interface{ SetReadParallelism(int) }); ok && workers > 0 {
								s.SetReadParallelism(workers)
							}
							of, err := ifs.(filesystem.Opener).OpenFile("/large.bin")
							if err != nil {
								t.Fatal(err)
							}
							return ifs, of
						}
						dropCaches()
						start := time.Now()
						p, of := open()
						buf := make([]byte, rpChunk)
						var off int64
						for off < of.Size() {
							n, err := of.ReadAt(buf, off)
							off += int64(n)
							if err != nil && err != io.EOF {
								t.Fatal(err)
							}
							if n == 0 {
								break
							}
						}
						if off != rpLarge {
							t.Fatalf("ours read %d", off)
						}
						add(&seq[w], float64(off)/(1<<20)/time.Since(start).Seconds())
						of.Close()
						p.Close()
						dropCaches()
						p, of = open()
						rd := func(b []byte, o int64) error {
							_, err := of.ReadAt(b, o)
							if err == io.EOF {
								err = nil
							}
							return err
						}
						start = time.Now()
						if err := rpRandom(rd); err != nil {
							t.Fatal(err)
						}
						add(&cold[w], rpReads/time.Since(start).Seconds())
						start = time.Now()
						rpRandom(rd)
						add(&warm[w], rpReads/time.Since(start).Seconds())
						of.Close()
						p.Close()
					}
				}
				// Every round is bracketed by a calibration; a round that straddled a
				// change of regime, or left the first round's, is measured again.
				var first *kj.Regime
				for r := 0; r < rounds; r++ {
					var lens [3][3]int
					var rg kj.Regime
					for attempt := 0; ; attempt++ {
						for i := range lens {
							lens[0][i], lens[1][i], lens[2][i] = len(seq[i].vals), len(cold[i].vals), len(warm[i].vals)
						}
						rg = kj.Regime{Before: kj.Calibrate(0).Mops, Tol: kj.DefaultRegimeTolerance}
						oneRound()
						rg.After = kj.Calibrate(0).Mops
						ref := rg
						if first != nil {
							ref = *first
						}
						if (rg.Steady() && kj.SameRegime(rg.Mops(), ref.Mops(), rg.Tol)) || attempt >= 2 {
							break
						}
						t.Logf("round %d ran in regime %s: measured again after a pause", r, rg.Label())
						for i := range lens {
							seq[i].vals, cold[i].vals, warm[i].vals = seq[i].vals[:lens[0][i]], cold[i].vals[:lens[1][i]], warm[i].vals[:lens[2][i]]
						}
						time.Sleep(10 * time.Second)
					}
					if first == nil {
						first = &rg
					}
					for i := range seq {
						seq[i].regimes = append(seq[i].regimes, rg)
						cold[i].regimes = append(cold[i].regimes, rg)
						warm[i].regimes = append(warm[i].regimes, rg)
					}
				}
				for i, impl := range []string{"kernel", "ours", "serial"} {
					seq[i].line(t, name, "seq read", impl, "MiB/s")
					cold[i].line(t, name, "rand4k cold", impl, "reads/s")
					warm[i].line(t, name, "rand4k warm", impl, "reads/s")
				}
			}
			rpOnline(t, 4)
			// untimed content check against the generator
			ifs, err := Open(img, -1)
			if err != nil {
				t.Fatal(err)
			}
			defer ifs.Close()
			got, err := ifs.ReadFile("/large.bin")
			var want bytes.Buffer
			rpGen(&want)
			if err != nil || !bytes.Equal(got, want.Bytes()) {
				t.Fatalf("content check failed: %v", err)
			}
		})
	}
}
