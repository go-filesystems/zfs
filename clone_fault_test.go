package filesystem_zfs

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// faultMemBackend is an in-memory blockBackend that can inject a WriteAt (or
// ReadAt) failure after a configurable number of successful operations, letting
// tests walk the write/read error branches of Clone / DestroySnapshot without a
// real device. It grows on out-of-range writes, mirroring a sparse image file.
type faultMemBackend struct {
	data      []byte
	writeN    int
	readN     int
	failWrite int // 0 = never; fail once writeN exceeds this
	failRead  int // 0 = never; fail once readN exceeds this
}

func (m *faultMemBackend) ReadAt(p []byte, off int64) (int, error) {
	m.readN++
	if m.failRead > 0 && m.readN > m.failRead {
		return 0, fmt.Errorf("injected read failure")
	}
	if off < 0 || off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (m *faultMemBackend) WriteAt(p []byte, off int64) (int, error) {
	m.writeN++
	if m.failWrite > 0 && m.writeN > m.failWrite {
		return 0, fmt.Errorf("injected write failure")
	}
	if end := off + int64(len(p)); end > int64(len(m.data)) {
		grown := make([]byte, end)
		copy(grown, m.data)
		m.data = grown
	}
	copy(m.data[off:], p)
	return len(p), nil
}

func (m *faultMemBackend) Sync() error          { return nil }
func (m *faultMemBackend) Size() (int64, error) { return int64(len(m.data)), nil }
func (m *faultMemBackend) Close() error         { return nil }
func (m *faultMemBackend) Truncate(n int64) error {
	if n < int64(len(m.data)) {
		m.data = m.data[:n]
	} else {
		grown := make([]byte, n)
		copy(grown, m.data)
		m.data = grown
	}
	return nil
}

// formatSnapImage builds a pool image (formatted, one file, one snapshot) and
// returns its raw bytes, for replay against fault-injecting backends.
func formatSnapImage(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fault.img")
	fs, err := Format(path, 48*1024*1024, FormatConfig{PoolName: "faulttest"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if err := fs.WriteFile("/f", []byte("base-contents"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.Snapshot("snap1"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile image: %v", err)
	}
	return data
}

// formatCloneImage builds a pool image that already contains a clone "c" of
// snapshot "snap1", and returns its raw bytes.
func formatCloneImage(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cloneimg.img")
	fs, err := Format(path, 48*1024*1024, FormatConfig{PoolName: "faulttest"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if err := fs.WriteFile("/f", []byte("base-contents"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs.Snapshot("snap1"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := fs.Clone("snap1", "c"); err != nil {
		t.Fatalf("Clone: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile image: %v", err)
	}
	return data
}

// TestClone_OriginFaultSweep opens the clone under read-fault injection and
// calls Origin, walking the read-error branches of Origin / snapshotFullName /
// poolName. Past the fault count Origin returns the correct "<pool>@<snap>".
func TestClone_OriginFaultSweep(t *testing.T) {
	base := formatCloneImage(t)

	// Fault-free baseline: Origin resolves the full "<pool>@<snap>" name.
	clean := &faultMemBackend{data: append([]byte(nil), base...)}
	fsClean, err := OpenFromDeviceDataset(clean, -1, "c")
	if err != nil {
		t.Fatalf("OpenFromDeviceDataset(c): %v", err)
	}
	if got, err := fsClean.Origin(); err != nil || got != "faulttest@snap1" {
		t.Fatalf("clean Origin() = %q, err=%v; want faulttest@snap1", got, err)
	}
	fsClean.Close()

	// Sweep a read fault across the whole open+Origin sequence; wherever it
	// lands, Origin must surface an error rather than a wrong name or panic.
	sawError := false
	for fr := 1; fr <= 400; fr++ {
		m := &faultMemBackend{data: append([]byte(nil), base...), failRead: fr}
		fs, err := OpenFromDeviceDataset(m, -1, "c")
		if err != nil {
			continue // read fault during open — unusable handle, skip
		}
		got, err := fs.Origin()
		if err != nil {
			sawError = true
		} else if got != "" && got != "faulttest@snap1" {
			t.Errorf("Origin() returned a wrong name %q under read fault %d", got, fr)
		}
		fs.Close()
	}
	if !sawError {
		t.Error("no injected read failure ever surfaced from Origin")
	}
}

// TestClone_WriteFaultSweep injects a WriteAt failure after each of the first N
// writes Clone performs and confirms Clone reports the error (rather than
// silently corrupting or panicking). This walks the many "write failed" error
// returns threaded through cloneFromSnapshot and its MOS helpers.
func TestClone_WriteFaultSweep(t *testing.T) {
	base := formatSnapImage(t)

	sawError := false
	sawSuccess := false
	for fa := 1; fa <= 60; fa++ {
		m := &faultMemBackend{data: append([]byte(nil), base...), failWrite: fa}
		fs, err := OpenFromDevice(m, -1)
		if err != nil {
			// Opening does no writes, so this should not happen; tolerate it.
			continue
		}
		err = fs.Clone("snap1", "c")
		if err != nil {
			sawError = true
		} else {
			sawSuccess = true
		}
		fs.Close()
	}
	if !sawError {
		t.Error("no injected write failure ever surfaced from Clone")
	}
	if !sawSuccess {
		t.Error("Clone never succeeded even past its write count — sweep upper bound too low")
	}
}

// TestClone_ReadFaultSweep injects a ReadAt failure partway through Clone,
// exercising the read-error branches (copyObjsetTree reads, MOS object reads).
func TestClone_ReadFaultSweep(t *testing.T) {
	base := formatSnapImage(t)

	sawError := false
	for fr := 1; fr <= 40; fr++ {
		m := &faultMemBackend{data: append([]byte(nil), base...), failRead: fr}
		fs, err := OpenFromDevice(m, -1)
		if err != nil {
			// A read fault during open is fine — it just means this handle is
			// unusable; move on.
			continue
		}
		if fs.Clone("snap1", "c") != nil {
			sawError = true
		}
		fs.Close()
	}
	if !sawError {
		t.Error("no injected read failure ever surfaced from Clone")
	}
}

// TestDestroySnapshot_WriteFaultSweep injects a WriteAt failure during
// DestroySnapshot of a clone-free snapshot, exercising its write-error returns
// (snapname removal, chain relink, MOS-object frees, commit).
func TestDestroySnapshot_WriteFaultSweep(t *testing.T) {
	base := formatSnapImage(t)

	sawError := false
	sawSuccess := false
	for fa := 1; fa <= 30; fa++ {
		m := &faultMemBackend{data: append([]byte(nil), base...), failWrite: fa}
		fs, err := OpenFromDevice(m, -1)
		if err != nil {
			continue
		}
		if fs.DestroySnapshot("snap1") != nil {
			sawError = true
		} else {
			sawSuccess = true
		}
		fs.Close()
	}
	if !sawError {
		t.Error("no injected write failure ever surfaced from DestroySnapshot")
	}
	if !sawSuccess {
		t.Error("DestroySnapshot never succeeded past its write count")
	}
}
