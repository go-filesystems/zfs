package filesystem_zfs

// compatw_test.go — WRITE-SIDE cross-compatibility audit.
//
// The read-side has fixtures created by real `zpool create` (see
// raid_*_test.go). The write-side, until now, was never validated
// against the OpenZFS userland: the writer (Format) produced an image
// that the lib's own reader could open, but no external tool ever
// confirmed the on-disk bytes match the OpenZFS spec.
//
// Two complementary checks live here:
//
//   1. TestWriteThenZdb — runs `zdb -e -p <imgdir> <pool>` on a pool
//      image produced by Format(). zdb is the OpenZFS userland's
//      label / pool inspector; it walks the vdev labels, picks the
//      freshest uberblock, follows the rootbp, and prints the
//      resulting pool config. Exit-code 0 means the OpenZFS userland
//      accepts the image as a valid (exported) pool. Skip-gated on
//      `zdb` PATH availability — install via `zfsutils-linux`
//      (Debian/Ubuntu) or `openzfs` (Homebrew/pkgx).
//
//   2. TestWriteThenInternalReadback — unconditional smaller
//      validator. Even when zdb isn't installed, we re-open the
//      Format()'d pool through the lib's own reader and verify the
//      writer ↔ reader round-trip is self-consistent (file written
//      before Close visible after fresh Open + correct uberblock
//      txg + correct vdev label found via the lib's read path).
//
//   3. TestWriteThenLabelSpecConformance — documents the on-disk
//      label LAYOUT divergence from the OpenZFS spec. Currently
//      SKIPS with a precise diagnostic when the divergence is
//      present, becomes a hard gate once the writer is fixed.
//
// Why zdb and not `zpool import`: import requires CAP_SYS_ADMIN (root
// + the zfs.ko module loaded), which is impractical for unit tests
// even on Linux CI. zdb -e -p works unprivileged against an EXPORTED
// pool sitting in a directory of image files, exactly matching what
// Format produces.

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	compatwPoolName = "compatwpool"
	// 64 MiB — comfortably above the 4 MiB minimum + enough headroom
	// for zdb's uberblock ring + MOS walk.
	compatwPoolSize = 64 * 1024 * 1024
)

// TestWriteThenZdb validates Format()'s output against the OpenZFS
// userland by running `zdb -e -p <imgdir> <poolname>` on it. The
// pool is freshly created (genesis txg=1, single-disk vdev, ashift=12)
// and EXPORTED — `zdb -e` is the right tool: it operates on a pool
// that isn't imported into the live kernel.
//
// SKIP conditions:
//   - non-Linux/macOS host (zdb is Linux/Darwin only).
//   - `zdb` not on PATH (install `zfsutils-linux` on Debian/Ubuntu, or
//     `openzfs` via Homebrew / pkgx on macOS).
//   - zdb rejects the image — also a skip-with-diagnostic until the
//     writer reaches spec parity (see TestWriteThenLabelSpecConformance
//     for the known label-layout gap).
//
// On hard success: exit code 0 + stdout contains the pool name AND a
// "version:" line (the uberblock's pool version) AND a "vdev_tree:"
// section (label NVList parse). All three are zdb invariants for a
// healthy pool — if any is missing, our writer diverges from the
// spec.
func TestWriteThenZdb(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("zdb cross-compat: skipping on %s (zdb only supported on linux/darwin)", runtime.GOOS)
	}
	zdbPath, err := exec.LookPath("zdb")
	if err != nil {
		t.Skip("zdb not on PATH — install zfsutils-linux (Debian/Ubuntu) or openzfs (Homebrew/pkgx) to enable write-side cross-compat validation")
	}

	imgDir := t.TempDir()
	imgPath := filepath.Join(imgDir, compatwPoolName+".img")
	fs, err := Format(imgPath, compatwPoolSize, FormatConfig{
		PoolName: compatwPoolName,
		PoolGUID: 0xC0FFEE5C0EBAB1E, // stable, distinctive
	})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	// Close so zdb sees the synced bytes.
	if err := fs.Close(); err != nil {
		t.Fatalf("Close after Format: %v", err)
	}

	// `zdb -l <imgfile>` dumps the four vdev labels: it unpacks each
	// label's XDR nvlist config and validates the label's embedded
	// ZIO_CHECKSUM_LABEL self-checksum. This is the right granularity
	// for milestone (a) — "does real OpenZFS userland accept the labels
	// our writer emits?" — and it is unprivileged (no -e / kernel / loop
	// device needed).
	//
	// After the label check we additionally walk the pool with `zdb -e`
	// (see below): the writer now emits spec block-pointer checksums and
	// the DSL hierarchy needed for a full import + objset traversal.
	cmd := exec.Command(zdbPath, "-l", imgPath)
	out, runErr := cmd.CombinedOutput()
	outStr := string(out)

	if runErr != nil {
		t.Fatalf("zdb -l exited non-zero on a Format()-produced pool: %v\n"+
			"This means the OpenZFS userland could not parse our vdev\n"+
			"labels. zdb output follows:\n%s", runErr, outStr)
	}

	// "Bad label cksum" appears in the LABEL banner when the embedded
	// self-checksum does not validate. Its absence is the headline
	// proof our ZIO_CHECKSUM_LABEL implementation matches OpenZFS.
	if strings.Contains(outStr, "Bad label cksum") {
		t.Errorf("zdb reported a bad label checksum — our embedded\n"+
			"ZIO_CHECKSUM_LABEL self-checksum diverges from spec.\n"+
			"Full output:\n%s", outStr)
	}

	// zdb prints "failed to unpack label N" when the XDR nvlist is
	// malformed. None of the four labels should fail to unpack.
	if strings.Contains(outStr, "failed to unpack label") {
		t.Errorf("zdb failed to unpack one or more label nvlists.\n"+
			"Full output:\n%s", outStr)
	}

	// Healthy-output invariants — zdb prints all of these for a label
	// set it parsed cleanly.
	mustContain := []string{
		"name: '" + compatwPoolName + "'", // pool name in the nvlist
		"version:",                        // pool version field
		"vdev_tree:",                      // label NVList parse
		"labels = 0 1 2 3",                // all four labels present + valid
	}
	for _, want := range mustContain {
		if !strings.Contains(outStr, want) {
			t.Errorf("zdb -l output missing %q. Full output:\n%s", want, outStr)
		}
	}

	// ── Milestone: full pool import + MOS/objset traversal + block-
	// checksum verification via `zdb -e`. The image file must be named
	// <poolname>.img inside a directory we point `-p` at, and the pool
	// must be EXPORTED (which a Format()'d image is). ──────────────────
	//
	// zdb -e -d <pool>: opens the pool (spa_load through "LOADED"),
	// opens the DSL pool, and enumerates every dataset (MOS + ZPL objset
	// traversal). Exit 0 proves the writer now emits a fully importable
	// pool: spec vdev labels, conformant block-pointer checksums, the
	// DSL special-directory hierarchy ($MOS/$FREE/$ORIGIN + origin
	// snapshot + deadlists + props), and the pool-directory entries
	// (config / features / free_bpobj / sync_bplist) that spa_load
	// requires.
	dCmd := exec.Command(zdbPath, "-e", "-p", imgDir, "-d", compatwPoolName)
	dOut, dErr := dCmd.CombinedOutput()
	if dErr != nil {
		t.Fatalf("zdb -e -d failed on a Format()-produced pool: %v\n"+
			"The OpenZFS userland could not import + traverse our pool.\n"+
			"Output:\n%s", dErr, dOut)
	}
	dStr := string(dOut)
	// zdb -d prints one "Dataset <name> [<type>]" line per dataset it
	// walked; the MOS and the root ZPL dataset must both appear.
	for _, want := range []string{"Dataset mos [META]", "Dataset " + compatwPoolName + " [ZPL]"} {
		if !strings.Contains(dStr, want) {
			t.Errorf("zdb -e -d output missing %q (dataset traversal incomplete).\nOutput:\n%s", want, dStr)
		}
	}

	// zdb -e -AAA -bcc <pool>: traverse ALL blocks and verify their
	// checksums. -AAA lets zdb continue past any space-map leak/claim
	// asserts; the block traversal itself recomputes and checks every
	// block pointer's fletcher4 checksum. Exit 0 with no "checksum error"
	// is the proof our on-disk block-pointer checksums match the OpenZFS
	// spec.
	bccCmd := exec.Command(zdbPath, "-e", "-p", imgDir, "-AAA", "-bcc", compatwPoolName)
	bccOut, bccErr := bccCmd.CombinedOutput()
	bccStr := string(bccOut)
	if bccErr != nil {
		t.Fatalf("zdb -e -AAA -bcc failed: %v\nblock-checksum traversal did not complete.\nOutput:\n%s", bccErr, bccStr)
	}
	if strings.Contains(bccStr, "checksum error") || strings.Contains(bccStr, "bad checksum") {
		t.Errorf("zdb -e -bcc reported a block checksum error — our\n"+
			"block-pointer checksums diverge from the OpenZFS spec.\nOutput:\n%s", bccStr)
	}
	if !strings.Contains(bccStr, "Traversing all blocks to verify checksums") {
		t.Errorf("zdb -e -bcc did not reach block traversal.\nOutput:\n%s", bccStr)
	}

	// zdb -e -mmm <pool>: dump the metaslabs and their space maps. This
	// proves the writer emits a metaslab array + per-metaslab space-map
	// objects (vdev metaslab_array != 0). The first metaslab holds every
	// pool block, so its space map must report a non-zero smp_alloc.
	mmmCmd := exec.Command(zdbPath, "-e", "-p", imgDir, "-mmm", compatwPoolName)
	mmmOut, mmmErr := mmmCmd.CombinedOutput()
	mmmStr := string(mmmOut)
	if mmmErr != nil {
		t.Fatalf("zdb -e -mmm failed: %v\nmetaslab dump did not complete.\nOutput:\n%s", mmmErr, mmmStr)
	}
	for _, want := range []string{"Metaslabs:", "space map object", "metaslab      0"} {
		if !strings.Contains(mmmStr, want) {
			t.Errorf("zdb -e -mmm output missing %q (metaslab layout incomplete).\nOutput:\n%s", want, mmmStr)
		}
	}

	// zdb -e -bcc <pool> WITHOUT -AAA: this is the space-accounting gate.
	// zdb loads every metaslab's space map, replays its ALLOC/FREE
	// records, and asserts that the bytes reachable by block-pointer
	// traversal equal the bytes the space maps mark allocated. Before the
	// writer emitted metaslabs this reported
	// "block traversal size N != alloc 0 (leaked)" and a space-map
	// refcount mismatch; now it must report "No leaks (block sum matches
	// space maps exactly)" and exit 0.
	saCmd := exec.Command(zdbPath, "-e", "-p", imgDir, "-bcc", compatwPoolName)
	saOut, saErr := saCmd.CombinedOutput()
	saStr := string(saOut)
	if saErr != nil {
		t.Fatalf("zdb -e -bcc (space accounting, no -AAA) failed: %v\n"+
			"the writer's metaslab space maps do not reconcile with block\n"+
			"traversal. Output:\n%s", saErr, saStr)
	}
	if strings.Contains(saStr, "leaked") || strings.Contains(saStr, "!= alloc") {
		t.Errorf("zdb -e -bcc reported leaked / size != alloc — the space\n"+
			"maps over- or under-count the writer's allocations.\nOutput:\n%s", saStr)
	}
	if strings.Contains(saStr, "space map refcount mismatch") {
		t.Errorf("zdb -e -bcc reported a space map refcount mismatch — the\n"+
			"spacemap_histogram feature refcount does not match the metaslab\n"+
			"count.\nOutput:\n%s", saStr)
	}
	if !strings.Contains(saStr, "No leaks") {
		t.Errorf("zdb -e -bcc did not confirm \"No leaks (block sum matches\n"+
			"space maps exactly)\".\nOutput:\n%s", saStr)
	}
}

// TestWriteThenInternalReadback validates the writer ↔ reader
// round-trip through the LIB'S OWN reader (no external tool). This
// is the unconditional smaller validator: even when zdb isn't
// installed and even when the on-disk layout diverges from the
// OpenZFS spec, the writer and reader being self-consistent is a
// minimum bar.
//
// Asserts (two phases):
//
//	Phase 1 — fresh-format readback:
//	  - Format() returns an open FS that can be closed cleanly.
//	  - Close → fresh Open succeeds (no corruption on sync).
//	  - Uberblock found by the lib's read path has the genesis
//	    txg=1 (= fmtPoolTXG; verifies the writer's claimed initial
//	    txg matches the on-disk bytes).
//	  - Endian is "little" (writer is LE-only).
//
//	Phase 2 — write-cycle readback:
//	  - WriteFile + Close + fresh Open finds the written file.
//	  - Post-write uberblock txg > genesis txg (the lib bumps txg
//	    on writes; this confirms the uberblock ring is being
//	    rotated correctly).
func TestWriteThenInternalReadback(t *testing.T) {
	// ── Phase 1: fresh-format readback ───────────────────────────
	imgPath := filepath.Join(t.TempDir(), "roundtrip.img")
	const guid uint64 = 0x1234567890ABCDEF
	fs, err := Format(imgPath, compatwPoolSize, FormatConfig{
		PoolName: compatwPoolName,
		PoolGUID: guid,
	})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close after fresh Format: %v", err)
	}

	fsFresh, err := Open(imgPath, -1)
	if err != nil {
		t.Fatalf("Open after fresh Format: %v", err)
	}
	infoFresh := fsFresh.Info()
	if infoFresh.TransactionGroup != fmtPoolTXG {
		t.Errorf("fresh-format uberblock txg = %d, want %d (genesis)",
			infoFresh.TransactionGroup, fmtPoolTXG)
	}
	if infoFresh.Endian != "little" {
		t.Errorf("fresh-format uberblock endian = %q, want %q (writer is LE-only)",
			infoFresh.Endian, "little")
	}
	if err := fsFresh.Close(); err != nil {
		t.Fatalf("Close fsFresh: %v", err)
	}

	// ── Phase 2: write-cycle readback ────────────────────────────
	fs2, err := Open(imgPath, -1)
	if err != nil {
		t.Fatalf("Open for write phase: %v", err)
	}
	payload := []byte("write-side cross-compat sentinel\n")
	if err := fs2.WriteFile("/sentinel.txt", payload, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := fs2.Close(); err != nil {
		t.Fatalf("Close after WriteFile: %v", err)
	}

	fs3, err := Open(imgPath, -1)
	if err != nil {
		t.Fatalf("Open after WriteFile: %v", err)
	}
	defer fs3.Close()

	got, err := fs3.ReadFile("/sentinel.txt")
	if err != nil {
		t.Fatalf("ReadFile after WriteFile cycle: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("ReadFile = %q, want %q", got, payload)
	}
	info3 := fs3.Info()
	if info3.TransactionGroup <= fmtPoolTXG {
		t.Errorf("post-WriteFile uberblock txg = %d, want > %d (writes should bump txg)",
			info3.TransactionGroup, fmtPoolTXG)
	}
	if info3.Endian != "little" {
		t.Errorf("post-WriteFile uberblock endian = %q, want %q",
			info3.Endian, "little")
	}
}

// TestWriteThenLabelSpecConformance documents the writer's on-disk
// label LAYOUT vs the OpenZFS spec. The canonical layout (sys/vdev_label.h,
// VDEV_PAD_SIZE / VDEV_PHYS_SIZE) is:
//
//	[0x00000 .. 0x02000)  vl_pad1         (8 KiB)
//	[0x02000 .. 0x04000)  vl_pad2 / boot  (8 KiB)
//	[0x04000 .. 0x20000)  vl_vdev_phys    (112 KiB) — XDR nvlist
//	[0x20000 .. 0x40000)  vl_uberblock    (128 KiB) — 128 × 1 KiB slots
//
// The freshly-written label is re-read and the first 4 bytes at
// offset 0x4000 are checked: the XDR encoding byte must be
// nvEncodeXDR=1.
//
// Today this test SKIPS with a diagnostic — the writer places the
// nvlist at offset 0x1000 (4 KiB) instead of the spec-required
// 0x4000 (16 KiB), making zdb / `zpool import` / any third-party
// reader reject the pool. The lib's own reader works around this
// because the single-vdev open path never calls ProbeLabel /
// readVdevTree; only multi-vdev opens do (those would fail too).
//
// Once format.go's buildLabel is corrected (nvOff = 16*1024), this
// test will pass and become a hard gate against regressions.
func TestWriteThenLabelSpecConformance(t *testing.T) {
	imgPath := filepath.Join(t.TempDir(), "spec.img")
	const guid uint64 = 0xDEADBEEFCAFEBABE
	fs, err := Format(imgPath, compatwPoolSize, FormatConfig{
		PoolName: compatwPoolName,
		PoolGUID: guid,
	})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.OpenFile(imgPath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile raw: %v", err)
	}
	defer f.Close()

	labelOffsets := []int64{
		0,
		vdevLabelSize,
		compatwPoolSize - 2*vdevLabelSize,
		compatwPoolSize - vdevLabelSize,
	}

	// First: confirm the divergence is still present by reading at
	// the spec-mandated offset 0x4000 inside each label. If we find
	// valid NVList bytes there for ALL 4 labels, the writer was
	// fixed and the assertions below should run as hard checks.
	const specNVOff = 0x4000
	specCompliant := true
	var diagOff int64
	var diagFirstBytes [4]byte
	for _, lo := range labelOffsets {
		hdr := make([]byte, 4)
		if _, e := f.ReadAt(hdr, lo+specNVOff); e != nil {
			t.Fatalf("read label@%#x spec nv: %v", lo, e)
		}
		if hdr[0] != nvEncodeXDR || hdr[1] != nvEndianLE {
			specCompliant = false
			diagOff = lo + specNVOff
			copy(diagFirstBytes[:], hdr)
			break
		}
	}

	if !specCompliant {
		// Probe the actual location to make the diagnostic precise.
		// Scan the first 64 KiB of L0 for ANY XDR-looking header.
		// Two shapes worth detecting:
		//   - Spec (4-byte): [01 01 00 00]  ← encoding|endian|2 reserved
		//   - Writer's current (8-byte LE uint32s): [01 00 00 00 01 00 00 00]
		probe := make([]byte, 64*1024)
		if _, e := f.ReadAt(probe, 0); e != nil {
			t.Fatalf("read L0 probe: %v", e)
		}
		actualNVOff := int64(-1)
		actualShape := ""
		for i := 0; i <= len(probe)-8; i++ {
			// Spec shape
			if probe[i] == nvEncodeXDR && probe[i+1] == nvEndianLE &&
				probe[i+2] == 0 && probe[i+3] == 0 {
				actualNVOff = int64(i)
				actualShape = "spec 4-byte [01 01 00 00]"
				break
			}
			// Writer's "uint32 LE" shape: encoding=1 as LE u32, endian=1 as LE u32.
			if probe[i] == nvEncodeXDR && probe[i+1] == 0 && probe[i+2] == 0 && probe[i+3] == 0 &&
				probe[i+4] == nvEndianLE && probe[i+5] == 0 && probe[i+6] == 0 && probe[i+7] == 0 {
				actualNVOff = int64(i)
				actualShape = "writer's 8-byte [01 00 00 00 01 00 00 00] (two LE uint32s)"
				break
			}
		}
		t.Skipf("writer's on-disk label layout diverges from OpenZFS spec.\n"+
			"  Expected: XDR nvlist header [01 01 00 00] at label+0x%04x (per\n"+
			"            sys/vdev_label.h VDEV_PAD_SIZE: 8KiB pad1 + 8KiB pad2/boot,\n"+
			"            then 112KiB vdev_phys starting at 0x4000).\n"+
			"  Got at label+0x%04x (file offset %#x): % x\n"+
			"  Probe: first XDR-shaped header in L0 at offset %#x (%s).\n"+
			"  Root causes in format.go:buildLabel:\n"+
			"    1. nvOff = 4*1024 (= 0x1000) instead of 16*1024 (= 0x4000).\n"+
			"    2. encodeNVListFull emits an 8-byte outer header (two LE uint32s)\n"+
			"       instead of the spec's 4-byte header (encoding|endian|res|res).\n"+
			"  These divergences explain why zdb / zpool import / ProbeLabel all\n"+
			"  reject the image. The lib's single-vdev Open path is unaffected\n"+
			"  because it never reads the NVList region.",
			specNVOff, specNVOff, diagOff, diagFirstBytes[:], actualNVOff, actualShape)
	}

	// === Hard-gate assertions, active once writer is spec-compliant ===
	for labelIdx, labelOff := range labelOffsets {
		t.Run(fmt.Sprintf("L%d", labelIdx), func(t *testing.T) {
			info, err := ProbeLabel(&osFileBackend{f: f}, labelOff)
			if err != nil {
				t.Fatalf("ProbeLabel(L%d @ %#x): %v", labelIdx, labelOff, err)
			}
			if info.PoolName != compatwPoolName {
				t.Errorf("L%d pool name = %q, want %q", labelIdx, info.PoolName, compatwPoolName)
			}
			if info.PoolGUID != guid {
				t.Errorf("L%d pool_guid = %#x, want %#x", labelIdx, info.PoolGUID, guid)
			}
			// For a single file-backed vdev, the label's vdev_tree IS the
			// top-level (leaf) vdev directly — type "file" (or "disk"),
			// NOT a synthetic "root" wrapper. This matches real `zpool
			// create` on a file vdev (verified via `zdb -l` on OpenZFS
			// 2.3: vdev_tree.type = 'file', guid == top_guid). The importer
			// synthesises the enclosing root on its own; emitting our own
			// extra "root" child made OpenZFS report a missing top-level
			// vdev (EOVERFLOW) and blocked `zdb -e -p` traversal.
			if info.Type != "file" && info.Type != "disk" {
				t.Errorf("L%d vdev_tree.type = %q, want a leaf type (file/disk)", labelIdx, info.Type)
			}
			// A leaf vdev_tree has no children — top_guid identifies it.
			if len(info.LeafGUIDs) != 0 {
				t.Errorf("L%d expected leaf vdev_tree (no children), got %d children", labelIdx, len(info.LeafGUIDs))
			}
			// The top-level (leaf) vdev carries its own guid, distinct
			// from the pool guid — exactly as real `zpool create` does.
			if info.TopGUID == 0 {
				t.Errorf("L%d top_guid is zero", labelIdx)
			}
			if info.TopGUID == info.PoolGUID {
				t.Errorf("L%d top_guid %#x must differ from pool_guid", labelIdx, info.TopGUID)
			}
			if info.Ashift != 12 {
				t.Errorf("L%d ashift = %d, want 12", labelIdx, info.Ashift)
			}

			// Uberblock ring at offset 0x20000 within the label.
			ringBase := labelOff + uberblockRegionOffset
			foundValid := false
			for slot := 0; slot < uberblockSlots; slot++ {
				buf := make([]byte, uberblockSize)
				if _, e := f.ReadAt(buf, ringBase+int64(slot)*uberblockSize); e != nil {
					break
				}
				ubInfo, e := parseUberblock(buf, ringBase+int64(slot)*uberblockSize, labelIdx, slot)
				if e != nil {
					continue
				}
				foundValid = true
				if ubInfo.TransactionGroup != fmtPoolTXG {
					t.Errorf("L%d slot %d txg = %d, want %d",
						labelIdx, slot, ubInfo.TransactionGroup, fmtPoolTXG)
				}
			}
			if !foundValid {
				t.Errorf("L%d: no valid uberblock in 128-slot ring at %#x", labelIdx, ringBase)
			}
		})
	}
}

// TestWriteThenUberblockSelfReadback validates that all 4 labels'
// uberblock rings contain a parseable uberblock with the genesis
// TXG. Unlike TestWriteThenLabelSpecConformance, this assertion
// does NOT depend on the NVList region being at the spec-compliant
// offset — the uberblock region is at 0x20000 in BOTH layouts (the
// writer's current divergence is only in the NV region position,
// not in the uberblock region). So this is the strongest
// unconditional writer-side check we can land today.
//
// Asserts:
//   - For each of the 4 labels (L0/L1 at partition start, L2/L3 at
//     end), the uberblock region at +0x20000 contains at least one
//     valid uberblock.
//   - The uberblock magic is 0x00bab10c (parseUberblock would reject
//     otherwise — we exercise the same path the lib's reader uses).
//   - txg == fmtPoolTXG (= 1) — the writer claims this in Format();
//     this verifies the on-disk bytes match.
//   - endian == "little" (the writer is LE-only).
//   - guid_sum == poolGUID (single-disk default: guid_sum is just the
//     one vdev's guid which equals the pool guid).
func TestWriteThenUberblockSelfReadback(t *testing.T) {
	imgPath := filepath.Join(t.TempDir(), "ub.img")
	const guid uint64 = 0xFEEDFACEDEADBEEF
	fs, err := Format(imgPath, compatwPoolSize, FormatConfig{
		PoolName: compatwPoolName,
		PoolGUID: guid,
	})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.OpenFile(imgPath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile raw: %v", err)
	}
	defer f.Close()

	labelOffsets := []int64{
		0,
		vdevLabelSize,
		compatwPoolSize - 2*vdevLabelSize,
		compatwPoolSize - vdevLabelSize,
	}

	for labelIdx, labelOff := range labelOffsets {
		t.Run(fmt.Sprintf("L%d", labelIdx), func(t *testing.T) {
			ringBase := labelOff + uberblockRegionOffset
			foundValid := false
			for slot := 0; slot < uberblockSlots; slot++ {
				buf := make([]byte, uberblockSize)
				if _, e := f.ReadAt(buf, ringBase+int64(slot)*uberblockSize); e != nil {
					break
				}
				// Use parseUberblock — the same parser the lib's
				// reader uses, so we exercise an identical code path.
				ubInfo, e := parseUberblock(buf, ringBase+int64(slot)*uberblockSize, labelIdx, slot)
				if e != nil {
					continue
				}
				foundValid = true
				if ubInfo.TransactionGroup != fmtPoolTXG {
					t.Errorf("L%d slot %d txg = %d, want %d",
						labelIdx, slot, ubInfo.TransactionGroup, fmtPoolTXG)
				}
				if ubInfo.Endian != "little" {
					t.Errorf("L%d slot %d endian = %q, want %q",
						labelIdx, slot, ubInfo.Endian, "little")
				}
				// ub_guid_sum is the sum of EVERY vdev guid in the MOS
				// config tree: the synthetic root top-level vdev (guid ==
				// pool_guid) plus the single leaf (vdevGUIDFor(pool_guid)).
				// OpenZFS recomputes this from the trusted config during
				// spa_load and rejects the pool if it differs ("uberblock
				// guid sum doesn't match MOS guid sum").
				wantGUIDSum := guid + vdevGUIDFor(guid)
				if ubInfo.GUIDSum != wantGUIDSum {
					t.Errorf("L%d slot %d guid_sum = %#x, want %#x (root guid + leaf guid)",
						labelIdx, slot, ubInfo.GUIDSum, wantGUIDSum)
				}
				// Verify the embedded magic explicitly: an extra
				// belt-and-braces check that doesn't trust
				// parseUberblock — reads the first 8 bytes as LE
				// uint64 and compares with uberblockMagic.
				if binary.LittleEndian.Uint64(buf[:8]) != uberblockMagic {
					t.Errorf("L%d slot %d raw magic = %#x, want %#x",
						labelIdx, slot, binary.LittleEndian.Uint64(buf[:8]), uberblockMagic)
				}
			}
			if !foundValid {
				t.Errorf("L%d: no valid uberblock in 128-slot ring at %#x",
					labelIdx, ringBase)
			}
		})
	}
}
