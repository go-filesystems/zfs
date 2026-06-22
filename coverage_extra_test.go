package filesystem_zfs

// coverage_extra_test.go — focused unit tests for small, self-contained
// helpers that the fixture-driven integration tests do not exercise on
// every code path: the multi-vdev pool's metadata passthrough + routing,
// the SHA-256 block checksum, the vdev-tree ashift walk, and the two-word
// space-map log encoding. Each test pins a concrete on-disk/algorithmic
// invariant rather than merely touching the line.

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

// trackingBackend is a full blockBackend that records which lifecycle
// calls were made and can be told to fail them, so the multiVdevPool
// passthroughs can be asserted exactly.
type trackingBackend struct {
	buf       []byte
	syncErr   error
	truncErr  error
	closeErr  error
	synced    bool
	truncated int64
	closed    int
}

func (t *trackingBackend) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(t.buf)) {
		return 0, errors.New("eof")
	}
	return copy(p, t.buf[off:]), nil
}
func (t *trackingBackend) WriteAt(p []byte, off int64) (int, error) { return copy(t.buf[off:], p), nil }
func (t *trackingBackend) Sync() error                              { t.synced = true; return t.syncErr }
func (t *trackingBackend) Size() (int64, error)                     { return int64(len(t.buf)), nil }
func (t *trackingBackend) Truncate(s int64) error                   { t.truncated = s; return t.truncErr }
func (t *trackingBackend) Close() error                             { t.closed++; return t.closeErr }

func TestMultiVdevPoolPassthrough(t *testing.T) {
	prim := &trackingBackend{buf: make([]byte, 1<<20)}
	tree := &vdev{typ: vdevTypeMirror}
	m := newMultiVdevPool(prim, []blockBackend{prim}, tree, 0)

	if err := m.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !prim.synced {
		t.Fatal("Sync did not delegate to primary")
	}
	if sz, err := m.Size(); err != nil || sz != 1<<20 {
		t.Fatalf("Size = %d, %v; want %d, nil", sz, err, 1<<20)
	}
	if err := m.Truncate(4096); err != nil || prim.truncated != 4096 {
		t.Fatalf("Truncate: err=%v truncated=%d", err, prim.truncated)
	}

	// WriteAt is unconditionally rejected (read-only pool).
	if _, err := m.WriteAt([]byte{1}, 0); err == nil {
		t.Fatal("WriteAt should be rejected on a multi-vdev pool")
	}

	// Sync error propagates.
	prim.syncErr = errors.New("boom")
	if err := m.Sync(); err == nil {
		t.Fatal("Sync error not propagated")
	}
}

func TestMultiVdevPoolCloseDedups(t *testing.T) {
	// The same backend appears twice in the leaf slice (mirror legs that
	// resolved to one device): Close must invoke it exactly once.
	a := &trackingBackend{buf: make([]byte, 16)}
	b := &trackingBackend{buf: make([]byte, 16)}
	m := newMultiVdevPool(a, []blockBackend{a, b, a}, &vdev{typ: vdevTypeMirror}, 0)
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if a.closed != 1 {
		t.Fatalf("duplicate leaf closed %d times, want 1", a.closed)
	}
	if b.closed != 1 {
		t.Fatalf("leaf b closed %d times, want 1", b.closed)
	}

	// First close error is surfaced.
	c := &trackingBackend{buf: make([]byte, 16), closeErr: errors.New("x")}
	m2 := newMultiVdevPool(c, []blockBackend{c}, &vdev{typ: vdevTypeMirror}, 0)
	if err := m2.Close(); err == nil {
		t.Fatal("Close error not surfaced")
	}
}

func TestMultiVdevPoolReadRouting(t *testing.T) {
	// A read below the data-area start is a label/uberblock read and must
	// be routed to the primary verbatim.
	prim := &trackingBackend{buf: make([]byte, vdevLabelStartSize+4096)}
	prim.buf[7] = 0xAB // sentinel inside the label region
	m := newMultiVdevPool(prim, []blockBackend{prim}, &vdev{typ: vdevTypeMirror}, 0)

	p := make([]byte, 8)
	if _, err := m.ReadAt(p, 0); err != nil {
		t.Fatalf("label ReadAt: %v", err)
	}
	if p[7] != 0xAB {
		t.Fatalf("label read did not hit primary: got %x", p[7])
	}

	// An unknown root vdev type in the data area is rejected.
	bad := newMultiVdevPool(prim, []blockBackend{prim}, &vdev{typ: vdevType("bogus")}, 0)
	if _, err := bad.ReadAt(make([]byte, 8), vdevLabelStartSize+512); err == nil {
		t.Fatal("unsupported root vdev type should error")
	}

	// Single-leaf (file/disk) root passes through to the primary.
	single := newMultiVdevPool(prim, []blockBackend{prim}, &vdev{typ: vdevTypeDisk}, 0)
	if _, err := single.ReadAt(make([]byte, 8), vdevLabelStartSize); err != nil {
		t.Fatalf("single-leaf passthrough: %v", err)
	}
}

func TestSHA256BlockChecksum(t *testing.T) {
	buf := make([]byte, 512)
	for i := range buf {
		buf[i] = byte(i)
	}
	want := sha256.Sum256(buf)

	got := sha256Checksum(buf)
	// ZFS stores the digest as four big-endian uint64 words; reconstruct
	// the raw 32-byte digest from the returned words and compare.
	var raw [32]byte
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint64(raw[i*8:], got[i])
	}
	if raw != want {
		t.Fatalf("sha256Checksum digest mismatch\n got %x\nwant %x", raw, want)
	}

	// blockChecksum must dispatch SHA-256 to the same result, and anything
	// else to fletcher4 (which differs from the SHA path).
	if blockChecksum(zioChecksumSHA256, buf) != got {
		t.Fatal("blockChecksum(SHA256) != sha256Checksum")
	}
	if blockChecksum(zioChecksumFletch4, buf) == got {
		t.Fatal("blockChecksum(fletcher4) unexpectedly equals SHA-256")
	}
	if blockChecksum(zioChecksumFletch4, buf) != fletcher4(buf) {
		t.Fatal("blockChecksum default branch != fletcher4")
	}
}

func TestFirstLeafAshift(t *testing.T) {
	if got := firstLeafAshift(nil); got != 0 {
		t.Fatalf("nil tree ashift = %d, want 0", got)
	}
	// Leaf directly.
	leaf := &vdev{typ: vdevTypeDisk, ashift: 12}
	if got := firstLeafAshift(leaf); got != 12 {
		t.Fatalf("leaf ashift = %d, want 12", got)
	}
	// Nested: first reachable leaf wins; a zero-ashift leaf is skipped in
	// favour of the next non-zero one.
	tree := &vdev{
		typ: vdevTypeRoot,
		children: []*vdev{
			{typ: vdevTypeMirror, children: []*vdev{
				{typ: vdevTypeFile, ashift: 0},
				{typ: vdevTypeFile, ashift: 13},
			}},
		},
	}
	if got := firstLeafAshift(tree); got != 13 {
		t.Fatalf("nested ashift = %d, want 13", got)
	}
	// No non-zero leaf anywhere => 0.
	empty := &vdev{typ: vdevTypeRoot, children: []*vdev{{typ: vdevTypeDisk, ashift: 0}}}
	if got := firstLeafAshift(empty); got != 0 {
		t.Fatalf("all-zero tree ashift = %d, want 0", got)
	}
}

func TestEncodeSpaceMapLogTwoWord(t *testing.T) {
	// A run larger than a single word can hold (smRunMaxUnits << smShift =
	// 128 MiB) must be emitted as a two-word entry: prefix 0b11 in the top
	// two bits of word0, and the offset/type packed into word1.
	maxSingle := int64(smRunMaxUnits) << smShift
	run := maxSingle + (4 << smShift) // forces overflow into a 2-word entry
	off := int64(1 << smShift)

	log := encodeSpaceMapLog([]smRange{{off: off, length: run, typ: smFree}})
	if len(log) < 16 {
		t.Fatalf("expected at least a two-word (16-byte) entry, got %d bytes", len(log))
	}
	w0 := binary.LittleEndian.Uint64(log[0:8])
	if w0>>62 != sm2Prefix {
		t.Fatalf("first emitted word is not a two-word entry: prefix=%b", w0>>62)
	}

	// Cross-check the encoder directly against the standalone function so
	// the packed layout is pinned, not just the prefix bit. The whole run
	// (> maxSingle) is emitted as one two-word entry, so encode the full
	// run length here, not just the single-word ceiling.
	wantW0, wantW1 := encodeSMTwoWord(off, run, 0, smFree)
	gotW0 := binary.LittleEndian.Uint64(log[0:8])
	gotW1 := binary.LittleEndian.Uint64(log[8:16])
	if gotW0 != wantW0 || gotW1 != wantW1 {
		t.Fatalf("two-word entry mismatch: got (%#x,%#x) want (%#x,%#x)",
			gotW0, gotW1, wantW0, wantW1)
	}
	// The free-type bit must be set in word1's top bit.
	if wantW1>>sm2OffsetBits != 1 {
		t.Fatalf("smFree type bit not set in word1: %#x", wantW1)
	}
}
