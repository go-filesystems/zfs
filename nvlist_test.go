package filesystem_zfs

import (
	"encoding/binary"
	"testing"
)

// ── nvUint64Array ─────────────────────────────────────────────────────────────

func TestNVUint64Array(t *testing.T) {
	vals := []uint64{1, 2, 3}
	p := nvUint64Array("myarray", vals)
	if p.name != "myarray" {
		t.Fatalf("name = %q, want myarray", p.name)
	}
	if p.typ != nvDataTypeUint64Array {
		t.Fatalf("typ = %d, want %d", p.typ, nvDataTypeUint64Array)
	}
	if p.nelem != 3 {
		t.Fatalf("nelem = %d, want 3", p.nelem)
	}
	if len(p.data) != 3*8 {
		t.Fatalf("data len = %d, want 24", len(p.data))
	}
	if binary.BigEndian.Uint64(p.data[0:8]) != 1 {
		t.Fatalf("data[0] = %d, want 1", binary.BigEndian.Uint64(p.data[0:8]))
	}
	if binary.BigEndian.Uint64(p.data[8:16]) != 2 {
		t.Fatalf("data[1] = %d, want 2", binary.BigEndian.Uint64(p.data[8:16]))
	}
}

func TestNVUint64ArrayEmpty(t *testing.T) {
	p := nvUint64Array("empty", nil)
	if p.nelem != 0 || len(p.data) != 0 {
		t.Fatalf("empty array: nelem=%d data=%d", p.nelem, len(p.data))
	}
}

func TestNVListEncoding(t *testing.T) {
	// Verify the full list encodes without panic and produces non-empty output.
	list := nvList{
		nvUint64("version", 5000),
		nvString("name", "testpool"),
		nvNVList("features", nvList{nvUint64("f", 1)}),
		nvNVListArray("array", []nvList{
			{nvUint64("x", 10)},
		}),
		nvUint64Array("guids", []uint64{1, 2}),
	}
	encoded := encodeNVList(list)
	if len(encoded) == 0 {
		t.Fatal("encodeNVList returned empty slice")
	}
	// Must end with 8 zero bytes (null terminator).
	tail := encoded[len(encoded)-8:]
	for i, b := range tail {
		if b != 0 {
			t.Fatalf("null terminator byte %d = 0x%X, want 0", i, b)
		}
	}
}
