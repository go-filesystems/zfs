package filesystem_zfs

// zfs#73 inside the kerneljudge VM: where does the cost of a sequential read
// after a random phase come from? Run as root in the guest:
//
//	kerneljudge run --perf --rounds 5 --driver <clone> --test-run Seq73VM
//
// Every variant drops the guest page cache, optionally runs a prior phase, drops
// the cache again, then times ONE sequential pass on a fresh Open (or a raw
// pread pass for the control), with the rusage and /proc/vmstat deltas of the pass.

import (
	"bufio"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
	kj "github.com/go-filesystems/kerneljudge"
)

func s73vmstat() map[string]int64 {
	m := map[string]int64{}
	f, err := os.Open("/proc/vmstat")
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) == 2 {
			v, _ := strconv.ParseInt(p[1], 10, 64)
			m[p[0]] = v
		}
	}
	return m
}

// s73steal is the guest's steal time in clock ticks.
func s73steal() int64 {
	b, _ := os.ReadFile("/proc/stat")
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "cpu ") {
			p := strings.Fields(l)
			if len(p) > 8 {
				v, _ := strconv.ParseInt(p[8], 10, 64)
				return v
			}
		}
	}
	return 0
}

type s73sample struct {
	mibs                     float64
	utime, stime             float64 // ms
	minflt, majflt, numGC    int64
	thp, pgfault, pgmajfault int64
	steal                    int64
	pgpgin                   int64
}

func s73measure(size int64, pass func()) s73sample {
	var r0, r1 syscall.Rusage
	var m0, m1 runtime.MemStats
	v0 := s73vmstat()
	st0 := s73steal()
	runtime.ReadMemStats(&m0)
	syscall.Getrusage(syscall.RUSAGE_SELF, &r0)
	start := time.Now()
	pass()
	el := time.Since(start)
	syscall.Getrusage(syscall.RUSAGE_SELF, &r1)
	runtime.ReadMemStats(&m1)
	v1 := s73vmstat()
	tv := func(a, b syscall.Timeval) float64 {
		return float64(b.Sec-a.Sec)*1e3 + float64(b.Usec-a.Usec)/1e3
	}
	return s73sample{
		mibs:  float64(size) / (1 << 20) / el.Seconds(),
		utime: tv(r0.Utime, r1.Utime), stime: tv(r0.Stime, r1.Stime),
		minflt: int64(r1.Minflt - r0.Minflt), majflt: int64(r1.Majflt - r0.Majflt),
		numGC: int64(m1.NumGC - m0.NumGC),
		thp:   v1["thp_fault_alloc"] - v0["thp_fault_alloc"], pgfault: v1["pgfault"] - v0["pgfault"],
		pgmajfault: v1["pgmajfault"] - v0["pgmajfault"], steal: s73steal() - st0, pgpgin: v1["pgpgin"] - v0["pgpgin"],
	}
}

func TestSeq73VM(t *testing.T) {
	if os.Getenv("FS_KERNEL_JUDGE_PERF") != "1" {
		t.Skip("FS_KERNEL_JUDGE_PERF=1 to measure")
	}
	for _, n := range []int{1, 4} {
		t.Run(fmt.Sprintf("cpus%d", n), func(t *testing.T) { seq73VM(t, n) })
	}
}

func seq73VM(t *testing.T, ncpu int) {
	rounds := 5
	if v, err := strconv.Atoi(os.Getenv("FS_KERNEL_JUDGE_ROUNDS")); err == nil && v > 0 {
		rounds = v
	}
	defer rpRun("chcpu", "-e", "1-3")
	dir := t.TempDir()
	img, mnt := filepath.Join(dir, "pool.img"), "/kjrpmnt"
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(img, 1<<30); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(mnt, 0o755)
	rpMust(t, "zpool", "create", "-f", "-o", "ashift=12", "-O", "compression=off", "-O", "checksum=fletcher4", "-O", "mountpoint="+mnt, rpPool, img)
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
	dropCaches := func() { os.WriteFile("/proc/sys/vm/drop_caches", []byte("3"), 0) }
	rpOnline(t, ncpu)
	for i := 0; i < 24 && rpLoad1() > 1.0; i++ {
		time.Sleep(5 * time.Second)
	}

	open := func(workers int) (filesystem.Filesystem, filesystem.File) {
		ifs, err := Open(img, -1)
		if err != nil {
			t.Fatal(err)
		}
		if s, ok := ifs.(interface{ SetReadParallelism(int) }); ok && workers > 0 {
			s.SetReadParallelism(workers)
		}
		of, err := ifs.(filesystem.Opener).OpenFile("/large.bin")
		if err != nil {
			t.Fatal(err)
		}
		return ifs, of
	}
	seqOurs := func(of filesystem.File) {
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
	}
	randOurs := func(workers int) {
		p, of := open(workers)
		rd := func(b []byte, o int64) error {
			_, err := of.ReadAt(b, o)
			if err == io.EOF {
				err = nil
			}
			return err
		}
		rpRandom(rd)
		rpRandom(rd)
		of.Close()
		p.Close()
	}
	// pread control: the same I/O pattern on the raw image, no zfs decode.
	randRaw := func() {
		fh, err := os.Open(img)
		if err != nil {
			t.Fatal(err)
		}
		defer fh.Close()
		r := rand.New(rand.NewPCG(9, 9))
		buf := make([]byte, 128<<10)
		for range 2 * rpReads {
			fh.ReadAt(buf, int64(r.IntN((1<<30)/(128<<10)))*(128<<10))
		}
	}
	seqRaw := func() {
		fh, err := os.Open(img)
		if err != nil {
			t.Fatal(err)
		}
		defer fh.Close()
		buf := make([]byte, 128<<10)
		for off := int64(0); off < rpLarge; off += int64(len(buf)) {
			fh.ReadAt(buf, off+(4<<20))
		}
	}
	randKernel := func() {
		rpMust(t, "zpool", "import", "-d", dir, "-o", "readonly=on", rpPool)
		fk, _ := os.Open(filepath.Join(mnt, "large.bin"))
		rd := func(p []byte, off int64) error {
			_, err := fk.ReadAt(p, off)
			if err == io.EOF {
				err = nil
			}
			return err
		}
		rpRandom(rd)
		rpRandom(rd)
		fk.Close()
		rpExport(t)
	}

	type variant struct {
		name  string
		prior func()
		raw   bool
		setup func() func() // before the pass, returns undo
		w     int
	}
	nop := func() {}
	variants := []variant{
		{name: "ours:none", prior: nop},
		{name: "ours:rand", prior: func() { randOurs(0) }},
		{name: "ours:rand+GC+FreeOS", prior: func() { randOurs(0); runtime.GC(); debug.FreeOSMemory() }},
		{name: "ours:rand,GCoff", prior: func() { randOurs(0) }, setup: func() func() {
			old := debug.SetGCPercent(-1)
			return func() { debug.SetGCPercent(old) }
		}},
		{name: "ours:kernelrand", prior: randKernel},
		{name: "serial:none", prior: nop, w: 1},
		{name: "serial:rand", prior: func() { randOurs(1) }, w: 1},
		{name: "raw:none", prior: nop, raw: true},
		{name: "raw:rand", prior: randRaw, raw: true},
	}
	res := map[string][]s73sample{}
	var regimes []kj.Regime
	for r := 0; r < rounds; r++ {
		rg := kj.Regime{Before: kj.Calibrate(0).Mops, Tol: kj.DefaultRegimeTolerance}
		for _, v := range variants {
			dropCaches()
			v.prior()
			dropCaches()
			var s s73sample
			undo := func() {}
			if v.setup != nil {
				undo = v.setup()
			}
			if v.raw {
				s = s73measure(rpLarge, seqRaw)
			} else {
				// The harness times Open too (pool caches empty, as a mount would be).
				s = s73measure(rpLarge, func() {
					p, of := open(v.w)
					seqOurs(of)
					of.Close()
					p.Close()
				})
			}
			undo()
			res[v.name] = append(res[v.name], s)
			t.Logf("round %d %-22s %7.0f MiB/s user %6.0fms sys %6.0fms minflt %7d majflt %4d GC %3d thp %3d steal %d pgpgin %d",
				r, v.name, s.mibs, s.utime, s.stime, s.minflt, s.majflt, s.numGC, s.thp, s.steal, s.pgpgin)
		}
		rg.After = kj.Calibrate(0).Mops
		regimes = append(regimes, rg)
	}
	med := func(f func(s73sample) float64, v string) float64 {
		var x []float64
		for _, s := range res[v] {
			x = append(x, f(s))
		}
		sort.Float64s(x)
		return x[len(x)/2]
	}
	for _, v := range variants {
		t.Logf("SEQ73VM %-22s median %7.0f MiB/s user %6.0fms sys %6.0fms minflt %7.0f GC %3.0f pgpgin %8.0f | rounds %s",
			v.name, med(func(s s73sample) float64 { return s.mibs }, v.name),
			med(func(s s73sample) float64 { return s.utime }, v.name), med(func(s s73sample) float64 { return s.stime }, v.name),
			med(func(s s73sample) float64 { return float64(s.minflt) }, v.name), med(func(s s73sample) float64 { return float64(s.numGC) }, v.name),
			med(func(s s73sample) float64 { return float64(s.pgpgin) }, v.name), fmt.Sprint(func() []string {
				var o []string
				for _, s := range res[v.name] {
					o = append(o, fmt.Sprintf("%.0f", s.mibs))
				}
				return o
			}()))
	}
	for i, rg := range regimes {
		t.Logf("regime round %d: %s", i, rg.Label())
	}
	// PERF lines, so that `kerneljudge compare` refuses runs of different regimes.
	for _, v := range variants {
		s := rpSeries{regimes: regimes}
		for _, x := range res[v.name] {
			s.vals = append(s.vals, x.mibs)
		}
		s.line(t, fmt.Sprintf("seq73-cpus%d", ncpu), v.name, "ours", "MiB/s")
	}
}
