package filesystem_zfs

// parread.go — parallel decoding of the data records of an object.
//
// The records of a file are independent once their block pointers are known:
// each is read, checksum-verified (against its other DVAs on a mismatch),
// decrypted and decompressed by readBlock on its own. Resolving the pointers
// walks the indirect blocks through a one-entry-per-level cache that is not safe
// to share, so it stays serial and cheap; the expensive part (the device read,
// fletcher4/sha/blake3 verification, LZ4/ZSTD/GZIP decode) runs on up to
// readWorkers() goroutines under inflight.Ordered, which bounds the records in
// flight and hands them back in file order. Verification is NOT skipped: every
// worker calls readBlock, which verifies whenever the backend is verifying
// (switched on for the whole read operation, see verifyReads).
//
// The decoded records of ReadAt go to a bounded cache shared by the open files
// of the pool (inflight.Cache, the adaptive cache of squashfs v0.9.0): it starts
// at 8 MiB and grows, up to DefaultMaxDataCacheBytes, only when a record it
// evicted is asked for again. A write to the pool through this handle empties
// it (verifyBackend counts the writes).

import (
	"context"
	"io"
	"runtime"

	"github.com/go-filesystems/inflight"
)

const (
	// maxReadParallelism caps the default worker count: past it the decoders
	// are memory-bound and the extra goroutines buy nothing.
	maxReadParallelism = 8

	// windowPerWorker is how many records ReadFile resolves and decodes per
	// worker before handing them back: a window of 16 x workers keeps the tail
	// of a window (workers idle while the last records finish) under 1/16.
	windowPerWorker = 16

	// startDataCacheBytes is the decoded-record cache a pool starts with.
	startDataCacheBytes = 8 << 20

	// DefaultMaxDataCacheBytes is how far the decoded-record cache may grow when
	// the workload re-reads records it evicted: 256 MiB, as in squashfs.
	DefaultMaxDataCacheBytes int64 = 256 << 20
)

// defaultReadParallelism is min(GOMAXPROCS, maxReadParallelism), at least 1.
func defaultReadParallelism() int {
	return max(1, min(runtime.GOMAXPROCS(0), maxReadParallelism))
}

// SetReadParallelism sets how many records of one read are decoded at once:
// n <= 1 decodes serially (the behaviour before v0.8.0), n is capped at 64. The
// default is min(GOMAXPROCS, 8). Safe to call at any time.
func (fs *zfsFS) SetReadParallelism(n int) {
	fs.workers.Store(int32(max(1, min(n, 64))))
}

// readWorkers is the worker count.
func (fs *zfsFS) readWorkers() int {
	if w := int(fs.workers.Load()); w > 0 {
		return w
	}
	return defaultReadParallelism()
}

// SetMaxDataCache sets how many bytes of decoded records ReadAt may cache at
// most (default DefaultMaxDataCacheBytes); n below the starting 8 MiB means 8
// MiB. A cache already above it shrinks at once.
func (fs *zfsFS) SetMaxDataCache(n int64) {
	if n <= 0 { // zero is the default, always, not "the start size" until the next write
		n = DefaultMaxDataCacheBytes
	}
	fs.dcMax.Store(n)
	if c := fs.dc.Load(); c != nil {
		c.SetMax(n)
	}
	if c := fs.ic.Load(); c != nil {
		c.SetMax(min(n, maxIndirectCacheBytes))
	}
}

type dataCache = inflight.Cache[blkptr, []byte]

func recordCost(b []byte) int64 { return int64(len(b)) }

// dataCache returns the pool's decoded-record cache, emptied first when the
// pool was written to since it was filled. Called with fs.mu held.
func (fs *zfsFS) records() *dataCache {
	if fs.vb == nil {
		return nil // no write counter: nothing to know a stale record by
	}
	if g := fs.vb.writes.Load(); g != fs.dcGen || fs.dc.Load() == nil {
		fs.dcGen = g
		mx := fs.dcMax.Load()
		if mx <= 0 {
			mx = DefaultMaxDataCacheBytes
		}
		fs.dc.Store(inflight.NewCache[blkptr, []byte](startDataCacheBytes, mx, recordCost))
		fs.ic.Store(inflight.NewCache[blkptr, []byte](startDataCacheBytes, min(mx, maxIndirectCacheBytes), recordCost))
	}
	return fs.dc.Load()
}

// maxIndirectCacheBytes bounds the verified indirect blocks a pool keeps: 64
// MiB is 512 blocks of 128 KiB, each addressing 1024 records, so 64 GiB of file
// at the default record size before one is evicted.
const maxIndirectCacheBytes = 64 << 20

// writeGen is the number of writes made through the pool's backend so far.
func (fs *zfsFS) writeGen() uint64 {
	if fs.vb == nil {
		return 0
	}
	return fs.vb.writes.Load()
}

// recordJob is one data record to decode: its index in the object and pointer.
type recordJob struct {
	blk uint64
	bp  blkptr
	// into, when set, is the part of the caller's buffer this record fills
	// whole: a record stored as it is is read straight into it (readBlockInto)
	// and neither allocated nor cached.
	into []byte
}

// decodeRecord is readBlock, with a hole (a null pointer) read as blkSz zeros.
func decodeRecord(r io.ReaderAt, partOff int64, bp blkptr, blkSz int) ([]byte, error) {
	if bp.isNull() {
		return make([]byte, blkSz), nil
	}
	return readBlock(r, partOff, bp)
}

// decodeRecords decodes jobs on up to w goroutines and calls emit(k, data) in
// job order. The first error in job order stops the run and is returned, so a
// damaged record reports exactly as the serial walk would have. Jobs from index
// soft on are best effort: their error is swallowed and emit gets nil data.
func decodeRecords(r io.ReaderAt, partOff int64, jobs []recordJob, blkSz, w, soft int, emit func(k int, data []byte) error) error {
	one := func(k int) ([]byte, error) {
		if into := jobs[k].into; into != nil {
			if ok, err := readBlockInto(r, partOff, jobs[k].bp, into); ok {
				return nil, err // the bytes are in place: nothing to emit
			}
		}
		data, err := decodeRecord(r, partOff, jobs[k].bp, blkSz)
		if err != nil && k >= soft {
			return nil, nil
		}
		return data, err
	}
	if w < 2 || len(jobs) < 2 {
		for k := range jobs {
			data, err := one(k)
			if err != nil {
				return err
			}
			if err := emit(k, data); err != nil {
				return err
			}
		}
		return nil
	}
	return inflight.Ordered(context.Background(), len(jobs), w,
		func(_ context.Context, k int) ([]byte, error) { return one(k) }, emit)
}

// recordBP is the block pointer of record blk (null for a hole).
func recordBP(r io.ReaderAt, partOff int64, dn *dnode, blk uint64, c *indirectCache) (blkptr, error) {
	if dn.nlevels == 0 || dn.nblkptr == 0 {
		return blkptr{}, nil
	}
	return findDataBPCached(r, partOff, dn, blk, c)
}

// readAhead is the sequential window: records decoded past the end of a read
// that continues the previous one, in workers x readAheadFactor.
const readAheadFactor = 2

// fillRecords copies [off, off+len(dst)) of the object into dst (already
// zeroed) record by record, decoding the missing records in parallel and
// leaving them in the pool's cache. ahead more records are decoded into the
// cache when the read is sequential. Called with fs.mu held and verification
// on.
func (f *zfsFile) fillRecords(dst []byte, off uint64, sequential bool) error {
	fs := f.fs
	w := fs.readWorkers()
	bs := uint64(f.blkSz)
	hi := off + uint64(len(dst))
	first, last := off/bs, (hi-1)/bs
	if last > f.dn.maxblkid {
		last = f.dn.maxblkid
	}
	if first > last {
		return nil
	}
	want := last
	if sequential && w > 1 {
		want = min(last+uint64(readAheadFactor*w), f.dn.maxblkid)
	}
	cache := fs.records()
	f.cache.shared = fs.ic.Load()
	copyOut := func(blk uint64, data []byte) {
		start := blk * bs
		// A record never covers more than its slot, whatever lsize a hostile
		// pointer claims: its overflow must not land on a neighbour.
		lo, top := max(start, off), min(start+uint64(min(len(data), f.blkSz)), hi)
		if top > lo {
			copy(dst[lo-off:top-off], data[lo-start:top-start])
		}
	}
	// Resolve the pointers; serve what is cached; queue the rest.
	// A failing pointer does not end the pass at once: the records before it
	// are decoded first and their error, if any, is the one reported, as the
	// serial walk would (#71).
	var jobs []recordJob
	var ptrErr error
	for blk := first; blk <= want; blk++ {
		bp, err := recordBP(fs.f, fs.partOffset, f.dn, blk, &f.cache)
		if err != nil {
			if blk <= last {
				ptrErr = err
			} // else a pointer past the request: the reader meets it, and its error, when it gets there
			break
		}
		if bp.isNull() {
			continue // a hole: dst is zero already
		}
		if blk > last && len(dst) >= f.blkSz && storedAsIs(bp) {
			// A request of a record or more is read straight into its buffer, one
			// record per worker; nothing to decode ahead (the device read is the
			// whole cost), and a read-ahead record would be a buffer allocated
			// only to be copied from. A smaller request still reads ahead.
			break
		}
		if data, ok := cache.Get(bp); ok {
			if blk <= last {
				copyOut(blk, data)
			}
			continue
		}
		job := recordJob{blk: blk, bp: bp}
		if start := blk * bs; blk <= last && start >= off && start+bs <= hi {
			job.into = dst[start-off : start-off+bs]
		}
		jobs = append(jobs, job)
	}
	if len(jobs) == 0 {
		return ptrErr
	}
	// A read-ahead alone waits for a full batch: when the reader's own records
	// are all cached and fewer than w are missing, decoding them now would only
	// add latency to this call.
	soft := len(jobs) // the first read-ahead job: its failure is not this read's
	for k, j := range jobs {
		if j.blk > last {
			soft = k
			break
		}
	}
	if soft == 0 && len(jobs) < w {
		return nil
	}
	if err := decodeRecords(fs.f, fs.partOffset, jobs, f.blkSz, w, soft, func(k int, data []byte) error {
		if data == nil {
			return nil // a read-ahead record that failed: it fails again, in order, when read
		}
		cache.Put(jobs[k].bp, data)
		if k < soft {
			copyOut(jobs[k].blk, data)
		}
		return nil
	}); err != nil {
		return err
	}
	return ptrErr
}
