package filesystem_zfs

import (
	"os"
	"testing"
)

// TestRAIDFixture_Single verifies the single-vdev fixture opens and
// reads correctly through the existing single-device path.
//
// Currently SKIPPED — the lib's on-disk parser doesn't handle real
// OpenZFS 2.1.11 images yet. The first divergence: openObjset reads
// os_type=0 instead of 1 (DMU_OST_META) at the correct offset 0x2C0,
// which means the blkptr decoding / decompression pipeline produces
// different bytes than what OpenZFS wrote. Diagnosing this requires
// systematic verification of:
//
//   - vdev label NVList parsing (uberblock_array layout, ashift, top
//     vdev tree)
//   - uberblock selection (newest TXG in active rotating slot)
//   - blkptr DVA decoding for non-zero vdev fields (the existing code
//     hardcodes DVA[0] vdev=0, which is fine for single-vdev pools but
//     the decompression-input bytes still come out wrong)
//   - LZ4 / LZJB / ZLE / EMBEDDED compression of the MOS root block
//   - Pre-Big-Sur "Default features" set (pre-active features on 2.1.x
//     including hole_birth, embedded_data, large_blocks, …)
//
// Each item needs cross-referencing with OpenZFS 2.1 source and the
// raw bytes of a known-good test pool. That's a multi-hour focused
// session — fixtures are committed so the next iteration has them.
// See also TestRAIDFixture_AllProfiles below.
func TestRAIDFixture_Single(t *testing.T) {
	imgs := extractRAIDFixture(t, "single")
	if len(imgs) != 1 {
		t.Fatalf("single layout: expected 1 image, got %d", len(imgs))
	}
	exp := raidLayoutInfo("single")
	fs, err := OpenDataset(imgs[0], -1, exp.dataset)
	if err != nil {
		t.Fatalf("OpenDataset(%s, %s): %v", imgs[0], exp.dataset, err)
	}
	defer fs.Close()
	checkRAIDExpectations(t, fs, "single")
}

// TestRAIDFixture_Mirror verifies that the existing single-leg open
// path correctly serves a mirror pool. ZFS mirrors store identical
// data at the same DVA offset on every leg, so opening any leg with
// the existing single-device opener should "just work" — no
// multi-vdev infrastructure needed for mirror reads. RAID-Z1/Z2/Z3
// will still need a multi-vdev refactor (vdev tree NVList parsing +
// raidz_map_alloc stripe geometry); see TestRAIDFixture_RaidZ.
func TestRAIDFixture_Mirror(t *testing.T) {
	imgs := extractRAIDFixture(t, "mirror")
	if len(imgs) != 2 {
		t.Fatalf("mirror layout: expected 2 images, got %d", len(imgs))
	}
	exp := raidLayoutInfo("mirror")
	for i, img := range imgs {
		t.Run("leg"+string(rune('0'+i)), func(t *testing.T) {
			fs, err := OpenDataset(img, -1, exp.dataset)
			if err != nil {
				t.Fatalf("OpenDataset(%s, %s): %v", img, exp.dataset, err)
			}
			defer fs.Close()
			checkRAIDExpectations(t, fs, "mirror")
		})
	}
}

// TestRAIDFixture_RaidZ verifies healthy-path RAID-Z1/Z2/Z3 reads
// via OpenFromDevices feeding all leg backends. Degraded reads
// (missing legs requiring parity reconstruction) are not yet
// implemented — see memory:userland-fs-drivers.
func TestRAIDFixture_RaidZ(t *testing.T) {
	for _, layout := range []string{"raidz1", "raidz2", "raidz3"} {
		t.Run(layout, func(t *testing.T) {
			imgs := extractRAIDFixture(t, layout)
			backends := make([]BlockBackend, 0, len(imgs))
			for _, p := range imgs {
				f, err := os.OpenFile(p, os.O_RDWR, 0o600)
				if err != nil {
					t.Fatalf("open %s: %v", p, err)
				}
				backends = append(backends, &osFileBackend{f: f})
			}
			exp := raidLayoutInfo(layout)
			fs, err := OpenFromDevices(backends, -1, exp.dataset)
			if err != nil {
				t.Fatalf("OpenFromDevices(%s, %d legs): %v", layout, len(backends), err)
			}
			defer fs.Close()
			checkRAIDExpectations(t, fs, layout)
		})
	}
}
