package filesystem_zfs

// stress_test.go — stress / soak / fuzz suite for the in-tree ZFS
// driver. Scales between a fast pre-commit run (testing.Short(),
// ~seconds) and an overnight soak run via env vars + flags:
//
//   -stress.workers       (default 8)            concurrent goroutines for
//                                                the read/write/delete test
//   -stress.duration      (short: 200ms / long:  per-test wall-clock budget
//                          ZFS_STRESS_DURATION   for the concurrent R/W test
//                          e.g. "3h")
//   -stress.file-mb       (short: 4 MiB /        size of the "large file"
//                          long: 64 MiB)         single-block exerciser
//   -stress.files         (short: 200 /          count for the "many files"
//                          long: 5000)           write/delete cycle test
//   -stress.crypto-iters  (short: 200 /          DSL_CRYPTO_KEY parse/marshal
//                          long: 50_000)         round-trip iterations
//   -stress.raid-readers  (short: 4 /            goroutines hitting each
//                          long: 16)             RAID fixture in parallel
//
// All heavy paths are gated on `!testing.Short()` so the default
// `go test ./...` finishes well under 30s. The env vars override the
// long-mode defaults so CI can dial them up without recompiling.
//
// IMPORTANT design choices forced by the current writer state:
//
//   - The writer has known spec-divergence bugs (label NVList offset,
//     uberblock placement) that `zdb` rejects. EVERY stress assertion
//     here goes through the in-tree reader on output produced by the
//     in-tree writer — the "closed loop" the writer is correct against.
//     Driving e.g. `zpool import` on these images is intentionally NOT
//     a goal of this file; see compatw_test.go for that gate.
//
//   - Format() reserves a 16 KiB ZPL object array → 32 dnode slots,
//     of which 4 are pre-claimed by the format, leaving 28 free file
//     slots per pool. The "many files" stress test therefore uses
//     write→delete cycling on a SINGLE pool so the slot pool gets
//     recycled `-stress.files` times (this catches the ZAP delete /
//     re-insert + slot reuse paths under load, which is the real
//     interesting thing — not "fill 28 slots once").
//
//   - WriteFile splits payloads larger than 128 KiB into 128-KiB
//     data blocks addressed through indirect block pointers
//     (writeBlockTree, up to L6). Small files (<= 128 KiB) still go
//     through a single 4-KiB direct BP for compactness. The
//     large-file test exercises BOTH paths depending on -stress.file-mb.
//     The reader side's indirect-BP code (findDataBP) is exercised by
//     both this lib's own writer output and the real `zpool create`
//     RAID fixtures.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-encryptions/zfscrypt"
)

// ── knobs ────────────────────────────────────────────────────────────────────

var (
	flagStressWorkers = flag.Int("stress.workers", 8,
		"concurrent worker goroutines for TestStress_ConcurrentRW")
	flagStressDuration = flag.Duration("stress.duration", 0,
		"wall-clock budget for TestStress_ConcurrentRW (0 = auto: 200ms short / 30s long / env override)")
	flagStressFileMB = flag.Int("stress.file-mb", 0,
		"file size in MiB for TestStress_LargeFile (0 = auto: 4 short / 64 long)")
	flagStressFiles = flag.Int("stress.files", 0,
		"file count for TestStress_ManyFiles (0 = auto: 200 short / 5_000 long)")
	flagStressCryptoIters = flag.Int("stress.crypto-iters", 0,
		"iteration count for TestStress_CryptoRoundTrip (0 = auto: 200 short / 50_000 long)")
	flagStressRAIDReaders = flag.Int("stress.raid-readers", 0,
		"concurrent readers per RAID fixture in TestStress_RAIDProfileSweep (0 = auto: 4 short / 16 long)")
)

// envDurationOr returns ZFS_STRESS_DURATION parsed as a duration,
// falling back to fallback. Invalid env values are ignored (with a
// best-effort log) so a typo doesn't kill an overnight soak.
func envDurationOr(t testing.TB, key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		t.Logf("stress: %s=%q is not a valid duration, using %s", key, v, fallback)
	}
	return fallback
}

func envIntOr(t testing.TB, key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
		t.Logf("stress: %s=%q is not a positive int, using %d", key, v, fallback)
	}
	return fallback
}

// stressDuration resolves the effective wall-clock budget for the
// concurrent test, honouring (highest precedence first) the -flag,
// the ZFS_STRESS_DURATION env var, and the short/long auto-default.
func stressDuration(t testing.TB) time.Duration {
	if *flagStressDuration > 0 {
		return *flagStressDuration
	}
	if testing.Short() {
		return envDurationOr(t, "ZFS_STRESS_DURATION", 200*time.Millisecond)
	}
	return envDurationOr(t, "ZFS_STRESS_DURATION", 30*time.Second)
}

func stressFileMB(t testing.TB) int {
	if *flagStressFileMB > 0 {
		return *flagStressFileMB
	}
	if testing.Short() {
		return envIntOr(t, "ZFS_STRESS_FILE_MB", 4)
	}
	return envIntOr(t, "ZFS_STRESS_FILE_MB", 64)
}

func stressFiles(t testing.TB) int {
	if *flagStressFiles > 0 {
		return *flagStressFiles
	}
	if testing.Short() {
		return envIntOr(t, "ZFS_STRESS_FILES", 200)
	}
	return envIntOr(t, "ZFS_STRESS_FILES", 5000)
}

func stressCryptoIters(t testing.TB) int {
	if *flagStressCryptoIters > 0 {
		return *flagStressCryptoIters
	}
	if testing.Short() {
		return envIntOr(t, "ZFS_STRESS_CRYPTO_ITERS", 200)
	}
	return envIntOr(t, "ZFS_STRESS_CRYPTO_ITERS", 50_000)
}

func stressRAIDReaders(t testing.TB) int {
	if *flagStressRAIDReaders > 0 {
		return *flagStressRAIDReaders
	}
	if testing.Short() {
		return envIntOr(t, "ZFS_STRESS_RAID_READERS", 4)
	}
	return envIntOr(t, "ZFS_STRESS_RAID_READERS", 16)
}

func stressWorkers() int { return *flagStressWorkers }

// ── shared helpers ───────────────────────────────────────────────────────────

// newStressFS formats a fresh pool of size sizeBytes and returns the
// concrete *zfsFS so the stress paths can poke at internals if needed.
// Cleanup is registered via t.Cleanup.
func newStressFS(t testing.TB, sizeBytes int64, poolName string) *zfsFS {
	t.Helper()
	path := filepath.Join(t.TempDir(), poolName+".img")
	ifs, err := Format(path, sizeBytes, FormatConfig{PoolName: poolName})
	if err != nil {
		t.Fatalf("Format(%s, %d): %v", path, sizeBytes, err)
	}
	fs, ok := ifs.(*zfsFS)
	if !ok {
		t.Fatalf("Format returned %T, want *zfsFS", ifs)
	}
	t.Cleanup(func() { _ = fs.Close() })
	return fs
}

// reopenStressFS closes fs.f, re-opens the underlying file with the
// same backing path, and returns the fresh *zfsFS. Used by the fsync
// / re-open semantics test.
func reopenStressFS(t testing.TB, path string) *zfsFS {
	t.Helper()
	ifs, err := Open(path, -1)
	if err != nil {
		t.Fatalf("re-Open(%s): %v", path, err)
	}
	fs, ok := ifs.(*zfsFS)
	if !ok {
		t.Fatalf("Open returned %T, want *zfsFS", ifs)
	}
	t.Cleanup(func() { _ = fs.Close() })
	return fs
}

// ── 1. concurrent R/W ────────────────────────────────────────────────────────

// TestStress_ConcurrentRW launches -stress.workers goroutines that
// each loop write → read-back → integrity-check → delete on a small
// hot set of filenames inside a SINGLE pool. The driver's per-FS
// mutex serialises operations, which is the property we want to
// stress: contention + lock ordering + ZAP insert / delete /
// reinsert under load.
//
// Knobs:
//
//	-stress.workers   N goroutines (default 8)
//	-stress.duration  wall-clock budget (200ms short / 30s long /
//	                  ZFS_STRESS_DURATION override)
//
// Integrity: every file's payload is rand[8 .. 8+len], with the first
// 8 bytes being a uint64 seed; readback recomputes the payload from
// the seed and compares sha256.
func TestStress_ConcurrentRW(t *testing.T) {
	workers := stressWorkers()
	if workers < 1 {
		workers = 1
	}
	duration := stressDuration(t)
	// 28 free file slots in a single pool. Workers each get a small
	// per-worker filename namespace to avoid READ-AFTER-OWN-WRITE
	// races between unrelated goroutines (the FS mutex protects each
	// individual op but two workers hitting the same name would see
	// readback of "someone else's last write"). Per-worker hotsets
	// still produce real contention on the FS mutex + allocator +
	// ZAP, which is the property we want to stress.
	const hotPerWorker = 3
	if workers*hotPerWorker > 24 {
		// 28-slot ceiling minus a small margin for slot-reuse churn
		newWorkers := 24 / hotPerWorker
		t.Logf("stress: capping workers from %d to %d (pool has 28 free dnode slots; hot set per worker = %d)",
			workers, newWorkers, hotPerWorker)
		workers = newWorkers
	}

	// Pool size scales with duration: long soak runs need a larger
	// data area because the bump-pointer allocator (see alloc.go) does
	// NOT reclaim space on DeleteFile — every WriteFile bumps the
	// next-free pointer monotonically. Below we budget ~64 KiB of pool
	// data area per estimated write op (worker_count × estimated
	// ops/sec × duration_seconds × poolBlockSize, with a generous
	// multiplier so we stay well clear of out-of-space mid-run).
	const (
		estOpsPerWorkerSec = 5000
		dataPerOpBytes     = 64 * 1024 // very rough budget; tiny files allocate 1 block (4 KiB) each, but headroom is cheap
		minPoolBytes       = 8 * 1024 * 1024
	)
	budget := int64(workers) * int64(estOpsPerWorkerSec) *
		int64(duration/time.Second+1) * int64(dataPerOpBytes)
	poolSize := budget + minPoolBytes
	if poolSize > 4*1024*1024*1024 {
		// Cap at 4 GiB so we don't surprise CI with absurd temp files
		// when the user dials -stress.duration up to many hours. At
		// the allocator-exhaustion point the test still produces a
		// useful signal (writes start failing cleanly with
		// out-of-space, the test just stops accumulating work).
		poolSize = 4 * 1024 * 1024 * 1024
	}
	fs := newStressFS(t, poolSize, "stress_concurrent")

	var (
		writes      atomic.Int64
		reads       atomic.Int64
		deletes     atomic.Int64
		errs        atomic.Int64
		opsPostGrow atomic.Int64 // ops successfully completed after the mid-run grow
		grown       atomic.Bool  // set true once the mid-run Grow has returned
	)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)

	start := time.Now()
	for w := 0; w < workers; w++ {
		go func(workerID int) {
			defer wg.Done()
			rng := mrand.New(mrand.NewSource(int64(workerID)*1_000_003 + start.UnixNano()))
			for {
				select {
				case <-stop:
					return
				default:
				}
				name := fmt.Sprintf("/w%dh%d", workerID, rng.Intn(hotPerWorker))
				op := rng.Intn(3)
				switch op {
				case 0, 1: // bias towards writes so files keep being created
					seed := rng.Uint64()
					payload := makeSeededPayload(seed, 32+rng.Intn(256))
					if err := fs.WriteFile(name, payload, 0o644); err != nil {
						// "pool full" is an expected, recoverable error
						// when the hot set is saturated — count it but
						// don't fail.
						errs.Add(1)
						continue
					}
					writes.Add(1)
					if grown.Load() {
						opsPostGrow.Add(1)
					}
					// Read back and verify.
					got, err := fs.ReadFile(name)
					if err != nil {
						errs.Add(1)
						continue
					}
					reads.Add(1)
					if sha256.Sum256(got) != sha256.Sum256(payload) {
						t.Errorf("worker %d: %s readback mismatch (len got=%d want=%d)",
							workerID, name, len(got), len(payload))
						return
					}
				case 2:
					if err := fs.DeleteFile(name); err == nil {
						deletes.Add(1)
					}
				}
			}
		}(w)
	}

	// Mid-run grow: at the halfway mark, expand the pool by 50% and
	// confirm workers keep operating after the call returns. The grow
	// path takes the same FS mutex that WriteFile / ReadFile / Delete
	// use, so this exercises lock ordering + label rewrite under live
	// concurrent load. The post-grow ops counter MUST be non-zero (for
	// any non-trivial duration) or the test fails — a regression would
	// be Grow somehow wedging the workers (e.g. by resetting the bump
	// pointer back over already-allocated extents, which the pre-fix
	// initAllocator-based grow path would have done).
	growTimer := time.AfterFunc(duration/2, func() {
		curSize, err := fs.f.Size()
		if err != nil {
			t.Errorf("mid-run grow: Size: %v", err)
			grown.Store(true)
			return
		}
		newSize := curSize + curSize/2
		// Cap at +1 GiB so dialling -stress.duration way up doesn't
		// blow temp disk. Even a small bump validates the grow path.
		if newSize > curSize+1024*1024*1024 {
			newSize = curSize + 1024*1024*1024
		}
		if err := fs.Grow(newSize); err != nil {
			t.Errorf("mid-run Grow(%d): %v", newSize, err)
		}
		grown.Store(true)
	})
	defer growTimer.Stop()

	time.AfterFunc(duration, func() { close(stop) })
	wg.Wait()
	elapsed := time.Since(start)

	totalOps := writes.Load() + reads.Load() + deletes.Load()
	t.Logf("stress concurrent RW: workers=%d duration=%s writes=%d reads=%d deletes=%d errs=%d total=%d ops/s=%.0f opsPostGrow=%d",
		workers, elapsed, writes.Load(), reads.Load(), deletes.Load(), errs.Load(),
		totalOps, float64(totalOps)/elapsed.Seconds(), opsPostGrow.Load())

	if totalOps == 0 {
		t.Fatalf("no operations completed in %s", elapsed)
	}
	// The mid-run grow fires at duration/2, so workers should produce
	// some ops afterwards before the stop signal. For very short
	// durations (testing.Short default = 200 ms) the grow may land too
	// close to stop for any post-grow ops to be observed; require
	// post-grow progress only at >= 1 s budgets.
	if grown.Load() && duration >= time.Second && opsPostGrow.Load() == 0 {
		t.Errorf("workers stopped making progress after mid-run grow (duration=%s, totalOps=%d)", duration, totalOps)
	}
}

// TestStress_AllocReclaim verifies the allocator reclaims space on
// Delete (and on WriteFile-over-existing) so that long write/delete
// cycles do NOT monotonically exhaust the pool. Regression for the
// bump-pointer-never-reclaims bug.
//
// Strategy: a small pool, a tight write/delete loop on a single name,
// many more iterations than the pool would hold without reclaim. Pool
// occupancy (nextFree − dataStart) is sampled after each iteration; if
// it grows past one allocation's worth of overhead the test fails
// (real ZFS bumps slightly per txg but reclaim keeps it bounded).
func TestStress_AllocReclaim(t *testing.T) {
	// 4 MiB pool. WriteFile padded to one 4 KiB block per call. Without
	// reclaim, 256+ iterations exhausts the data area; we run 2_000.
	const (
		poolBytes = 4 * 1024 * 1024
		iters     = 2_000
	)
	fs := newStressFS(t, poolBytes, "stress_allocreclaim")
	startBump := fs.alloc.nextFree
	const payload = "alloc-reclaim sentinel"

	// One write to seed nextFree past format overhead.
	if err := fs.WriteFile("/r.txt", []byte(payload), 0o644); err != nil {
		t.Fatalf("seed WriteFile: %v", err)
	}
	bumpAfterFirst := fs.alloc.nextFree

	for i := 0; i < iters; i++ {
		// Overwrite (in-place) — should reuse the previous extent via
		// the free-list (WriteFile frees the previous BP first).
		if err := fs.WriteFile("/r.txt", []byte(payload), 0o644); err != nil {
			t.Fatalf("iter %d: overwrite: %v", i, err)
		}
		// Bump pointer must not grow monotonically across overwrites.
		if fs.alloc.nextFree != bumpAfterFirst {
			t.Fatalf("iter %d: bump pointer grew on overwrite: was %d, now %d (alloc reclaim broken)",
				i, bumpAfterFirst, fs.alloc.nextFree)
		}
	}

	// Now exercise the Delete-then-Write cycle: same property.
	for i := 0; i < iters; i++ {
		if err := fs.DeleteFile("/r.txt"); err != nil {
			t.Fatalf("iter %d: DeleteFile: %v", i, err)
		}
		if err := fs.WriteFile("/r.txt", []byte(payload), 0o644); err != nil {
			t.Fatalf("iter %d: post-delete WriteFile: %v", i, err)
		}
		// Allocator should be cycling the same block — bump stays put.
		if fs.alloc.nextFree > bumpAfterFirst {
			t.Fatalf("iter %d: bump pointer grew via delete+write: was %d, now %d",
				i, bumpAfterFirst, fs.alloc.nextFree)
		}
	}
	t.Logf("stress alloc-reclaim: %d overwrites + %d delete+write cycles; "+
		"bump went %d → %d (delta=%d bytes; reclaim works)",
		iters, iters, startBump, fs.alloc.nextFree, fs.alloc.nextFree-startBump)
}

// TestStress_AllocReclaim_ConcurrentRW asserts that a 30-second-ish
// concurrent write/delete burst keeps allocator occupancy bounded —
// the integration of the alloc fix with the FS-level locking and the
// dnode reclaim walker. Short-mode runs 1s.
func TestStress_AllocReclaim_ConcurrentRW(t *testing.T) {
	duration := stressDuration(t)
	const (
		poolBytes  = 8 * 1024 * 1024
		workers    = 4
		hotPerWork = 3
	)
	fs := newStressFS(t, poolBytes, "stress_allocreclaim_rw")
	startNextFree := fs.alloc.nextFree

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	start := time.Now()
	for w := 0; w < workers; w++ {
		go func(workerID int) {
			defer wg.Done()
			rng := mrand.New(mrand.NewSource(int64(workerID) + start.UnixNano()))
			for {
				select {
				case <-stop:
					return
				default:
				}
				name := fmt.Sprintf("/w%dh%d", workerID, rng.Intn(hotPerWork))
				payload := makeSeededPayload(rng.Uint64(), 32+rng.Intn(128))
				_ = fs.WriteFile(name, payload, 0o644)
				if rng.Intn(3) == 0 {
					_ = fs.DeleteFile(name)
				}
			}
		}(w)
	}
	time.AfterFunc(duration, func() { close(stop) })
	wg.Wait()

	// The pool started with startNextFree bytes used; after a burst of
	// writes/deletes, the bump pointer is allowed to have advanced by
	// at most the size of the live working set (workers * hotPerWork
	// files × poolBlockSize) plus some slack for overhead. If reclaim
	// is broken the bump pointer will have walked to or past the pool
	// limit (4 MiB above start; the allocator would have OOM'd).
	delta := fs.alloc.nextFree - startNextFree
	maxAcceptable := int64(workers*hotPerWork*poolBlockSize*8) + 64*1024 // generous slack
	if delta > maxAcceptable {
		t.Fatalf("alloc bump grew by %d bytes (live working set fits in %d) — reclaim broken",
			delta, maxAcceptable)
	}
	t.Logf("stress alloc-reclaim concurrent: duration=%s workers=%d bump-delta=%d (cap %d)",
		duration, workers, delta, maxAcceptable)
}

// ── 2. large file ────────────────────────────────────────────────────────────

// TestStress_LargeFile writes a multi-MiB file, reads it back, and
// verifies sha256 integrity. The WriteFile path lays the whole
// payload into a single block (multi-block / indirect-BP on writes is
// not yet implemented — see file-level doc); this test therefore
// exercises the allocator + WriteAt pipeline for a payload large
// enough to exceed typical OS write buffer sizes but still well below
// the pool capacity.
//
// Knob: -stress.file-mb (4 short, 64 long).
func TestStress_LargeFile(t *testing.T) {
	if testing.Short() && stressFileMB(t) > 8 {
		t.Skip("stress: -short: large-file test skipped at file-mb > 8")
	}
	fileMB := stressFileMB(t)
	// WriteFile now splits payloads larger than 128 KiB into
	// 128-KiB-blocks addressed through indirect block pointers
	// (writeBlockTree, up to 6 levels). With indblkshift=17 and
	// 128 KiB data blocks, the cap is bpsPerIndir^5 × 128 KiB ≈
	// 144 PiB — well past anything the stress suite drives. We still
	// keep a sanity ceiling far above realistic test sizes so a
	// fat-fingered -stress.file-mb doesn't exhaust the temp FS.
	const writerCapMiB = 256
	if fileMB > writerCapMiB {
		t.Logf("stress: capping file-mb at %d MiB (sanity ceiling; was %d)",
			writerCapMiB, fileMB)
		fileMB = writerCapMiB
	}
	// Pool must comfortably hold the payload + format overhead +
	// label area. 2x the payload + 8 MiB headroom is plenty.
	poolBytes := int64(fileMB)*1024*1024*2 + 8*1024*1024
	fs := newStressFS(t, poolBytes, "stress_largefile")

	payload := makeSeededPayload(0xDEADBEEF, fileMB*1024*1024)
	want := sha256.Sum256(payload)

	t0 := time.Now()
	if err := fs.WriteFile("/big.bin", payload, 0o644); err != nil {
		t.Fatalf("WriteFile %d MiB: %v", fileMB, err)
	}
	writeElapsed := time.Since(t0)

	t1 := time.Now()
	got, err := fs.ReadFile("/big.bin")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	readElapsed := time.Since(t1)

	if len(got) != len(payload) {
		t.Fatalf("ReadFile len = %d, want %d", len(got), len(payload))
	}
	if sha256.Sum256(got) != want {
		t.Fatalf("ReadFile sha256 mismatch")
	}
	mb := float64(fileMB)
	t.Logf("stress large-file: %d MiB write=%s (%.1f MiB/s) read=%s (%.1f MiB/s) sha256=%s",
		fileMB, writeElapsed, mb/writeElapsed.Seconds(),
		readElapsed, mb/readElapsed.Seconds(),
		hex.EncodeToString(want[:8]))
}

// ── 3. many files (write/delete cycling) ────────────────────────────────────

// TestStress_ManyFiles cycles -stress.files write/delete pairs
// through a 28-slot pool. This forces the ZAP delete / reinsert path
// and the dnode-slot reuse path to be exercised repeatedly — far more
// interesting than a one-shot "fill once" test, since the bug surface
// for ZFS writes lives in the update-in-place paths.
//
// The slot count is intentionally bounded by the writer's
// fmtZPLObjArrayObjs limit (32 = 28 free); honoring -stress.files
// faithfully without lifting the bound means cycling.
func TestStress_ManyFiles(t *testing.T) {
	targetFiles := stressFiles(t)
	// 8 MiB pool — same as ConcurrentRW. Files are small (16 bytes).
	fs := newStressFS(t, 8*1024*1024, "stress_manyfiles")

	const liveSet = 20 // keep below the 28-slot ceiling
	var written, deleted, errs int
	start := time.Now()
	for i := 0; i < targetFiles; i++ {
		name := fmt.Sprintf("/f%d", i%liveSet)
		payload := []byte(fmt.Sprintf("payload-%d", i))
		// Delete previous (best-effort — first liveSet iterations
		// won't find one).
		if i >= liveSet {
			if err := fs.DeleteFile(name); err != nil {
				errs++
				continue
			}
			deleted++
		}
		if err := fs.WriteFile(name, payload, 0o644); err != nil {
			errs++
			continue
		}
		written++

		// Periodic readback so we don't blindly write into a corrupt
		// pool. Every 1/64th of the run, verify a random live file
		// round-trips.
		if i > 0 && i%((targetFiles/64)+1) == 0 {
			probeName := fmt.Sprintf("/f%d", i%liveSet)
			if _, err := fs.ReadFile(probeName); err != nil {
				t.Fatalf("stress many-files: probe readback at i=%d failed: %v", i, err)
			}
		}
	}
	elapsed := time.Since(start)
	if written == 0 {
		t.Fatalf("no writes succeeded in %d attempts", targetFiles)
	}
	t.Logf("stress many-files: target=%d written=%d deleted=%d errs=%d elapsed=%s ops/s=%.0f",
		targetFiles, written, deleted, errs, elapsed,
		float64(written+deleted)/elapsed.Seconds())
}

// ── 4. fsync / txg-commit semantics ──────────────────────────────────────────

// TestStress_TxgCommitSemantics verifies that operations which
// complete WriteFile (and therefore reach commitUberblock) survive a
// close + fresh Open cycle, AND that the post-write uberblock txg
// monotonically increases past genesis. This is the strongest "fsync
// semantics" assertion the current writer permits: WriteFile is
// atomic at the txg level — either the file is fully visible after
// the next Open (post-commit) or it never existed.
//
// We additionally simulate a "torn write" by overwriting one
// uberblock slot's slot OTHER than the one Open will pick (so the
// reader's freshest-txg selector is forced to skip the bad slot).
// This exercises the readInfo() invalid-magic skip path under a
// realistic on-disk corruption.
func TestStress_TxgCommitSemantics(t *testing.T) {
	const (
		nFiles   = 12
		poolSize = 8 * 1024 * 1024
	)
	path := filepath.Join(t.TempDir(), "txg.img")
	ifs, err := Format(path, poolSize, FormatConfig{PoolName: "stresstxg"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	fs := ifs.(*zfsFS)
	genesisTxg := fs.info.TransactionGroup

	// Write nFiles — every WriteFile commits a txg.
	wantPayloads := map[string][]byte{}
	for i := 0; i < nFiles; i++ {
		name := fmt.Sprintf("/sync%d", i)
		payload := makeSeededPayload(uint64(i)*0x9E3779B97F4A7C15, 16+i*7)
		if err := fs.WriteFile(name, payload, 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
		wantPayloads[name] = payload
	}
	finalTxg := fs.curTxg
	if finalTxg <= genesisTxg {
		t.Fatalf("commitUberblock did not bump txg: genesis=%d final=%d", genesisTxg, finalTxg)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Simulate a torn write: corrupt the uberblock slot at index
	// (finalTxg+1)%uberblockSlots — that's the NEXT slot the writer
	// would have used. The reader must still pick the right one.
	tornSlot := int((finalTxg + 1) % uberblockSlots)
	rawf, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	tornOff := int64(0)*vdevLabelSize + uberblockRegionOffset + int64(tornSlot)*uberblockSize
	garbage := make([]byte, uberblockSize)
	for i := range garbage {
		garbage[i] = 0xAA
	}
	if _, err := rawf.WriteAt(garbage, tornOff); err != nil {
		t.Fatalf("write garbage uberblock: %v", err)
	}
	if err := rawf.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}

	// Re-open: reader must pick the freshest VALID uberblock, ignoring
	// the torn slot, and find every committed file.
	fs2 := reopenStressFS(t, path)
	if fs2.info.TransactionGroup < finalTxg {
		t.Errorf("re-Open picked txg %d, want >= final committed txg %d",
			fs2.info.TransactionGroup, finalTxg)
	}
	for name, want := range wantPayloads {
		got, err := fs2.ReadFile(name)
		if err != nil {
			t.Errorf("post-reopen ReadFile %s: %v", name, err)
			continue
		}
		if sha256.Sum256(got) != sha256.Sum256(want) {
			t.Errorf("post-reopen %s payload mismatch (got len=%d want len=%d)",
				name, len(got), len(want))
		}
	}
	t.Logf("stress txg-commit: nFiles=%d genesisTxg=%d finalTxg=%d torn-slot=%d reopened-txg=%d",
		nFiles, genesisTxg, finalTxg, tornSlot, fs2.info.TransactionGroup)
}

// ── 5. parser fuzzing ────────────────────────────────────────────────────────

// FuzzOpen drives the Open() path with random inputs seeded from the
// committed RAID fixture tarballs. The goal is: no panic, no OOM, no
// hang — Open must either return a valid FS or a clean error for ANY
// input. The corpus is filled in TestStress_ParserFuzzSeeds when the
// suite runs with `-run TestStress -fuzz=FuzzOpen` and is otherwise
// idle.
func FuzzOpen(f *testing.F) {
	seedPath := filepath.Join("testdata", "raid", "single.tar.zst")
	if data, err := os.ReadFile(seedPath); err == nil {
		f.Add(data)
	}
	// Always seed with at least a few synthetic inputs so the fuzzer
	// has corpus even when testdata is unreadable.
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 4096))
	f.Add([]byte("EFI PART"))
	ub := makeUberblock(binary.LittleEndian, 1, 1, 1, 1)
	bare := make([]byte, 2*vdevLabelSize+uberblockRegionOffset+uberblockSize)
	writeUberblock(bare, 0, 0, ub)
	f.Add(bare)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < uberblockSize {
			return
		}
		path := filepath.Join(t.TempDir(), "fuzz.img")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skipf("WriteFile fuzz input: %v", err)
		}
		// Open MUST NOT panic / hang on arbitrary input.
		fs, err := Open(path, -1)
		if err == nil {
			_ = fs.Info()
			_ = fs.PartitionOffset()
			// Try a stat — also must not panic.
			_, _ = fs.Stat("/")
			fs.Close()
		}
		// ProbeLabel is the other public input boundary — exercise it
		// too. It takes an io.ReaderAt, so we use a bytes.Reader.
		_, _ = ProbeLabel(&byteReaderAtFuzz{b: data}, 0)
	})
}

// byteReaderAtFuzz is a minimal io.ReaderAt over a byte slice;
// avoids pulling in bytes.NewReader's strings handling and keeps the
// fuzz hot path lean.
type byteReaderAtFuzz struct{ b []byte }

func (r *byteReaderAtFuzz) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(r.b)) {
		return 0, io.EOF
	}
	n := copy(p, r.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// TestStress_ParserSmoke runs a non-fuzz smoke pass that flexes the
// same code paths FuzzOpen targets. It exists so the normal `go test`
// (without -fuzz) still covers the random-input-resilience property
// on every run, just with a fixed PRNG seed for reproducibility.
func TestStress_ParserSmoke(t *testing.T) {
	rng := mrand.New(mrand.NewSource(0x5712C0DE))
	iters := 32
	if !testing.Short() {
		iters = 256
	}
	t0 := time.Now()
	for i := 0; i < iters; i++ {
		size := 1024 + rng.Intn(64*1024)
		buf := make([]byte, size)
		_, _ = rand.Read(buf)
		path := filepath.Join(t.TempDir(), fmt.Sprintf("smoke%d.img", i))
		if err := os.WriteFile(path, buf, 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
		fs, err := Open(path, -1)
		if err == nil {
			_, _ = fs.Stat("/")
			fs.Close()
		}
		_, _ = ProbeLabel(&byteReaderAtFuzz{b: buf}, 0)
	}
	t.Logf("stress parser-smoke: %d iterations in %s", iters, time.Since(t0))
}

// ── 6. fault injection (backing-store I/O errors) ────────────────────────────

// faultyBackend wraps a blockBackend and injects ReadAt errors after
// failAfter successful reads. It mirrors the existing
// countingReaderAt helper but extends to the full blockBackend
// surface so an Open() can complete on the underlying device while
// later reads fail.
type faultyBackend struct {
	inner     blockBackend
	failAfter int64
	calls     atomic.Int64
}

func (f *faultyBackend) ReadAt(p []byte, off int64) (int, error) {
	if f.calls.Add(1) > f.failAfter {
		return 0, errors.New("faultyBackend: injected read failure")
	}
	return f.inner.ReadAt(p, off)
}
func (f *faultyBackend) WriteAt(p []byte, off int64) (int, error) { return f.inner.WriteAt(p, off) }
func (f *faultyBackend) Sync() error                              { return f.inner.Sync() }
func (f *faultyBackend) Truncate(size int64) error                { return f.inner.Truncate(size) }
func (f *faultyBackend) Close() error                             { return f.inner.Close() }
func (f *faultyBackend) Size() (int64, error)                     { return f.inner.Size() }

// TestStress_FaultInjection runs reads against an in-memory pool
// whose backing-store ReadAt fails after a budget of N successful
// reads. The driver must propagate every error as a clean Go error
// (never panic), at every budget point N from 0 .. some-upper-bound.
//
// This is functionally a property test: "the read path is panic-free
// against any ReadAt-fail boundary".
func TestStress_FaultInjection(t *testing.T) {
	// Build a pool, close it, then re-open through a faulty wrapper.
	path := filepath.Join(t.TempDir(), "fault.img")
	ifs, err := Format(path, 8*1024*1024, FormatConfig{PoolName: "stressfault"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if err := ifs.WriteFile("/canary.txt", []byte("canary"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ifs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	upper := int64(20)
	if !testing.Short() {
		upper = 200
	}
	panicked := atomic.Bool{}
	for budget := int64(0); budget <= upper; budget++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked.Store(true)
					t.Errorf("budget=%d: driver PANICKED on injected read error: %v", budget, r)
				}
			}()
			f, err := os.OpenFile(path, os.O_RDWR, 0o600)
			if err != nil {
				t.Errorf("budget=%d: open: %v", budget, err)
				return
			}
			fb := &faultyBackend{inner: &osFileBackend{f: f}, failAfter: budget}
			fs, err := OpenFromDevice(fb, -1)
			if err != nil {
				// Expected for many low budgets — Open does several reads.
				return
			}
			defer fs.Close()
			// Best-effort exercise — every call may legitimately fail.
			_, _ = fs.Stat("/")
			_, _ = fs.ListDir("/")
			_, _ = fs.ReadFile("/canary.txt")
		}()
	}
	t.Logf("stress fault-injection: probed %d ReadAt budgets, panics=%v", upper+1, panicked.Load())
}

// ── 7. RAID profile sweep (read-only concurrent fixtures) ───────────────────

// TestStress_RAIDProfileSweep hammers the RAID fixtures
// (testdata/raid/*) with concurrent readers, exercising BOTH the
// single-leg OpenDataset path (which works for single + each mirror
// leg) and the multi-leg OpenFromDevices path (which is the only way
// raidz reads succeed). Both paths run side-by-side so each layout's
// open-failure mode is captured precisely:
//
//   - single  → single-leg open is the canonical path (multi-leg n/a).
//   - mirror  → single-leg per leg + multi-leg both must succeed.
//   - raidz*  → multi-leg must succeed; single-leg is expected to fail
//     because raidz scatters data across legs.
//
// When a failure mode regresses (e.g. multi-leg raidz starts failing
// the way Bug 4's earlier report described), the per-layout
// diagnostic surfaces exactly which path broke.
func TestStress_RAIDProfileSweep(t *testing.T) {
	readers := stressRAIDReaders(t)
	layouts := []string{"single", "mirror", "raidz1", "raidz2", "raidz3"}

	for _, layout := range layouts {
		layout := layout
		t.Run(layout, func(t *testing.T) {
			t.Parallel()
			imgs := extractRAIDFixture(t, layout)
			if len(imgs) == 0 {
				t.Skipf("no fixture images for %s", layout)
			}
			exp := raidLayoutInfo(layout)
			isRAIDZ := layout == "raidz1" || layout == "raidz2" || layout == "raidz3"

			var (
				wg               sync.WaitGroup
				singleOpens      atomic.Int64
				singleOpenErrs   atomic.Int64
				multiOpens       atomic.Int64
				multiOpenErrs    atomic.Int64
				reads            atomic.Int64
				readErrs         atomic.Int64
				lastSingleErr    atomic.Pointer[string]
				lastMultiOpenErr atomic.Pointer[string]
				lastMultiReadErr atomic.Pointer[string]
			)
			wg.Add(readers)
			start := time.Now()
			for r := 0; r < readers; r++ {
				go func() {
					defer wg.Done()
					// Single-leg path.
					singleFS, err := OpenDataset(imgs[0], -1, exp.dataset)
					if err != nil {
						singleOpenErrs.Add(1)
						s := err.Error()
						lastSingleErr.Store(&s)
					} else {
						singleOpens.Add(1)
						if _, err := singleFS.ReadFile("/hello.txt"); err != nil {
							readErrs.Add(1)
						} else {
							reads.Add(1)
						}
						_ = singleFS.Close()
					}

					// Multi-leg path — open every leg as a backend and
					// route via OpenFromDevices. This is the path that
					// raidz strictly requires.
					if len(imgs) >= 1 {
						backends := make([]BlockBackend, 0, len(imgs))
						files := make([]*os.File, 0, len(imgs))
						openOK := true
						for _, p := range imgs {
							f, err := os.OpenFile(p, os.O_RDWR, 0o600)
							if err != nil {
								openOK = false
								break
							}
							files = append(files, f)
							backends = append(backends, &osFileBackend{f: f})
						}
						if !openOK {
							for _, f := range files {
								_ = f.Close()
							}
						} else {
							multiFS, err := OpenFromDevices(backends, -1, exp.dataset)
							if err != nil {
								multiOpenErrs.Add(1)
								s := err.Error()
								lastMultiOpenErr.Store(&s)
								for _, f := range files {
									_ = f.Close()
								}
							} else {
								multiOpens.Add(1)
								if _, err := multiFS.ReadFile("/hello.txt"); err != nil {
									readErrs.Add(1)
									s := err.Error()
									lastMultiReadErr.Store(&s)
								} else {
									reads.Add(1)
								}
								_ = multiFS.Close()
							}
						}
					}
				}()
			}
			wg.Wait()
			t.Logf("stress raid %s: readers=%d single-opens=%d single-errs=%d "+
				"multi-opens=%d multi-errs=%d reads=%d readErrs=%d elapsed=%s",
				layout, readers, singleOpens.Load(), singleOpenErrs.Load(),
				multiOpens.Load(), multiOpenErrs.Load(),
				reads.Load(), readErrs.Load(), time.Since(start))

			// Failure-mode invariants — fail loudly on regression so the
			// "Bug 4" multi-leg raidz path doesn't silently re-break.
			if isRAIDZ && multiOpens.Load() == 0 {
				diag := "<no error captured>"
				if p := lastMultiOpenErr.Load(); p != nil {
					diag = *p
				}
				t.Errorf("multi-leg %s: every OpenFromDevices failed (Bug 4 regressed). "+
					"Last error: %s", layout, diag)
			}
			if !isRAIDZ && singleOpens.Load() == 0 {
				diag := "<no error captured>"
				if p := lastSingleErr.Load(); p != nil {
					diag = *p
				}
				t.Errorf("%s: every single-leg OpenDataset failed. Last error: %s",
					layout, diag)
			}
		})
	}
}

// ── 8. crypto round-trip stress (DSL_CRYPTO_KEY) ─────────────────────────────

// TestStress_CryptoRoundTrip cycles parse/marshal of random valid
// DSL_CRYPTO_KEY blobs `-stress.crypto-iters` times, asserting
// byte-identical round-trip. The blobs are GENERATED via
// marshalDSLCryptoKeyPhys on randomised but valid fields, then fed
// back through parseDSLCryptoKeyPhys; failure of round-trip
// integrity is a bug in either side.
//
// The ZAP-attribute path (parseDSLCryptoKeyFromZAP) gets a parallel
// cycle: build attribute map from the same DSLCryptoKey, re-parse,
// compare struct field-by-field.
func TestStress_CryptoRoundTrip(t *testing.T) {
	iters := stressCryptoIters(t)
	suites := []zfscrypt.Suite{
		zfscrypt.AES128CCM,
		zfscrypt.AES192CCM,
		zfscrypt.AES256CCM,
		zfscrypt.AES128GCM,
		zfscrypt.AES192GCM,
		zfscrypt.AES256GCM,
	}

	rng := mrand.New(mrand.NewSource(0xC0DECAFE))
	t0 := time.Now()
	for i := 0; i < iters; i++ {
		k := randomDSLCryptoKey(t, rng, suites[i%len(suites)])

		// Phys round-trip
		buf, err := marshalDSLCryptoKeyPhys(k)
		if err != nil {
			t.Fatalf("iter %d: marshalDSLCryptoKeyPhys: %v", i, err)
		}
		if len(buf) != DSLCryptoKeyPhysSize {
			t.Fatalf("iter %d: marshal len %d, want %d", i, len(buf), DSLCryptoKeyPhysSize)
		}
		k2, err := parseDSLCryptoKeyPhys(buf)
		if err != nil {
			t.Fatalf("iter %d: parseDSLCryptoKeyPhys: %v", i, err)
		}
		if !dslCryptoKeyEqual(k, k2) {
			t.Fatalf("iter %d: phys round-trip mismatch:\n  in=%+v\n  out=%+v", i, k, k2)
		}
		// Re-marshal the parsed copy and compare byte-for-byte.
		buf2, err := marshalDSLCryptoKeyPhys(k2)
		if err != nil {
			t.Fatalf("iter %d: re-marshal: %v", i, err)
		}
		if !bytesEqual(buf, buf2) {
			t.Fatalf("iter %d: phys re-marshal bytes differ", i)
		}

		// ZAP-attribute round-trip via the parser.
		attrs := map[string][]byte{
			zapDSLCryptoKeyCryptSuite: u64bytes(uint64(k.Suite)),
			zapDSLCryptoKeyGUID:       u64bytes(k.GUID),
			zapDSLCryptoKeyIters:      u64bytes(k.Iters),
			zapDSLCryptoKeyIV:         k.IV,
			zapDSLCryptoKeyMAC:        k.MAC,
			zapDSLCryptoKeyMasterKey:  k.WrappedMasterKey,
			zapDSLCryptoKeyHMACKey:    k.WrappedHMACKey,
			zapDSLCryptoKeySalt:       k.Salt,
			zapDSLCryptoKeyVersion:    u64bytes(k.Version),
		}
		k3, err := parseDSLCryptoKeyFromZAP(attrs)
		if err != nil {
			t.Fatalf("iter %d: parseDSLCryptoKeyFromZAP: %v", i, err)
		}
		if !dslCryptoKeyEqual(k, k3) {
			t.Fatalf("iter %d: ZAP-attr round-trip mismatch:\n  in=%+v\n  out=%+v", i, k, k3)
		}

		// AAD must be deterministic and round-trip-stable.
		if !bytesEqual(dslCryptoKeyUnwrapAAD(k), dslCryptoKeyUnwrapAAD(k2)) {
			t.Fatalf("iter %d: AAD differs after round-trip", i)
		}
	}
	elapsed := time.Since(t0)
	t.Logf("stress crypto round-trip: iters=%d elapsed=%s iters/s=%.0f",
		iters, elapsed, float64(iters)/elapsed.Seconds())
}

// randomDSLCryptoKey builds a fully-populated valid DSLCryptoKey with
// random bytes for every variable-length field. crypto/rand is used
// for entropy so unwrap doesn't trip on patterns; iters and version
// are drawn from sensible ranges (iters > 0 so the passphrase path
// is selectable, version 0..3 covering the format-version field).
func randomDSLCryptoKey(t testing.TB, rng *mrand.Rand, suite zfscrypt.Suite) *DSLCryptoKey {
	t.Helper()
	iv := make([]byte, DSLWrappingIVLen)
	mac := make([]byte, DSLWrappingMACLen)
	mek := make([]byte, DSLMasterKeyMaxLen)
	hk := make([]byte, DSLHMACKeyMaxLen)
	salt := make([]byte, DSLSaltLen)
	for _, b := range [][]byte{iv, mac, mek, hk, salt} {
		if _, err := rand.Read(b); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
	}
	bigGUID, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	return &DSLCryptoKey{
		Suite:            suite,
		GUID:             bigGUID.Uint64(),
		Version:          uint64(rng.Intn(4)),
		Iters:            uint64(1 + rng.Intn(100_000)),
		IV:               iv,
		MAC:              mac,
		WrappedMasterKey: mek,
		WrappedHMACKey:   hk,
		Salt:             salt,
	}
}

func dslCryptoKeyEqual(a, b *DSLCryptoKey) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Suite == b.Suite &&
		a.GUID == b.GUID &&
		a.Version == b.Version &&
		a.Iters == b.Iters &&
		bytesEqual(a.IV, b.IV) &&
		bytesEqual(a.MAC, b.MAC) &&
		bytesEqual(a.WrappedMasterKey, b.WrappedMasterKey) &&
		bytesEqual(a.WrappedHMACKey, b.WrappedHMACKey) &&
		bytesEqual(a.Salt, b.Salt)
}

// ── small helpers ────────────────────────────────────────────────────────────

// makeSeededPayload returns a deterministic byte slice of length n
// whose first 8 bytes are the seed (LE) and remaining bytes are the
// math/rand stream seeded by `seed`. Identical seed → identical
// payload → integrity check via sha256 stays cheap.
func makeSeededPayload(seed uint64, n int) []byte {
	if n < 8 {
		n = 8
	}
	buf := make([]byte, n)
	binary.LittleEndian.PutUint64(buf[:8], seed)
	rng := mrand.New(mrand.NewSource(int64(seed)))
	for i := 8; i < n; i++ {
		buf[i] = byte(rng.Uint32())
	}
	return buf
}

func u64bytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
