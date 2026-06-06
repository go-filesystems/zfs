package filesystem_zfs

import (
	"bytes"
	"testing"
)

// ── dnodeSize ─────────────────────────────────────────────────────────────────

func TestDnodeSize(t *testing.T) {
	dn := &dnode{extraSlots: 0}
	if got := dn.dnodeSize(); got != dnodeMinSize {
		t.Fatalf("dnodeSize(extraSlots=0) = %d, want %d", got, dnodeMinSize)
	}
	dn.extraSlots = 1
	if got := dn.dnodeSize(); got != 2*dnodeMinSize {
		t.Fatalf("dnodeSize(extraSlots=1) = %d, want %d", got, 2*dnodeMinSize)
	}
}

// ── readDnodeData zero block ──────────────────────────────────────────────────

func TestReadDnodeData_NullFirstBlkptr(t *testing.T) {
	// dn.maxblkid == 0 and blkptrAt(0).isNull() → returns (nil, nil).
	dn := newDnode(dmotPlainFileContents, 1, 0, 0)
	// blkptrAt(0) is all zeros → isNull() = true; maxblkid = 0 (default).
	data, err := readDnodeData(bytes.NewReader(nil), 0, dn)
	if err != nil {
		t.Fatalf("readDnodeData null: %v", err)
	}
	if data != nil {
		t.Fatalf("readDnodeData null = %v, want nil", data)
	}
}

func TestReadDnodeData_MultiBlock(t *testing.T) {
	// Build a dnode with 2 data blocks.
	const bsz = 512
	block0 := bytes.Repeat([]byte{'A'}, bsz)
	block1 := bytes.Repeat([]byte{'B'}, bsz)
	img := append(block0, block1...)

	dn := newDnode(dmotPlainFileContents, 2, 0, 0)
	dn.datablkszsec = 1 // 1 * 512 = 512 bytes per block
	dn.nlevels = 1
	dn.maxblkid = 1
	dn.setBlkptrAt(0, makeBlkptr(0, bsz, bsz, zcompressOff, dmotPlainFileContents, 0, 1))
	dn.setBlkptrAt(1, makeBlkptr(int64(bsz), bsz, bsz, zcompressOff, dmotPlainFileContents, 0, 1))
	dn.encode()

	data, err := readDnodeData(bytes.NewReader(img), 0, dn)
	if err != nil {
		t.Fatalf("readDnodeData multiblock: %v", err)
	}
	if len(data) != 2*bsz {
		t.Fatalf("len = %d, want %d", len(data), 2*bsz)
	}
	if data[0] != 'A' || data[bsz] != 'B' {
		t.Fatalf("unexpected data content")
	}
}

// ── findDataBP level > 1 ─────────────────────────────────────────────────────

func TestFindDataBP_IndirectLevel(t *testing.T) {
	// nlevels=2, nblkptr=1, indblkshift=7 (128-byte indirect block = 1 BP)
	// The dnode's blkptr[0] points to an "indirect block" containing 1 BP,
	// which in turn points to actual data.
	//
	// Image layout:
	//   [0..511]   indirect block (128 usable, padded to 512)
	//   [512..1023] data block (512 bytes, content = 'Z')
	const psize = 512 // physical size for both blocks
	indirBuf := make([]byte, psize)
	dataBuf := bytes.Repeat([]byte{'Z'}, psize)

	// Build the BP that points to the data block (at offset 512).
	dataBP := makeBlkptr(psize, psize, psize, zcompressOff, dmotPlainFileContents, 0, 1)
	encodeBlkptr(dataBP, indirBuf[0:blkptrSize])

	img := append(indirBuf, dataBuf...)

	// Build dnode with nlevels=2.
	dn := newDnode(dmotPlainFileContents, 1, 0, 0)
	dn.datablkszsec = 1
	dn.nlevels = 2
	dn.indblkshift = 7 // 2^7 = 128-byte indirect block body → bpsPerBlock = 128/128 = 1
	dn.maxblkid = 0
	// Root blkptr[0] → indirect block at offset 0, psize=512.
	dn.setBlkptrAt(0, makeBlkptr(0, psize, psize, zcompressOff, dmotPlainFileContents, 0, 1))
	dn.encode()

	data, err := readDataBlock(bytes.NewReader(img), 0, dn, 0)
	if err != nil {
		t.Fatalf("readDataBlock indirect: %v", err)
	}
	if data[0] != 'Z' {
		t.Fatalf("data[0] = %q, want 'Z'", data[0])
	}
}

func TestFindDataBP_BlockIDExceedsNblkptr(t *testing.T) {
	// nlevels=1, nblkptr=1, blockID=5 → exceeds nblkptr → error
	dn := newDnode(dmotPlainFileContents, 1, 0, 0)
	dn.nlevels = 1
	_, err := findDataBP(bytes.NewReader(nil), 0, dn, 5)
	if err == nil {
		t.Fatal("expected error for blockID >= nblkptr")
	}
}

func TestFindDataBP_BlockIDExceedsDnodeCapacity(t *testing.T) {
	// nlevels=2, nblkptr=1, indblkshift=7 → covered = 1; blockID=1 → rpIdx=1 ≥ nblkptr=1 → error
	dn := newDnode(dmotPlainFileContents, 1, 0, 0)
	dn.nlevels = 2
	dn.indblkshift = 7
	_, err := findDataBP(bytes.NewReader(nil), 0, dn, 1)
	if err == nil {
		t.Fatal("expected error for blockID exceeding dnode capacity")
	}
}

func TestFindDataBP_NullIndirectBlock(t *testing.T) {
	// Indirect block pointer is null → findDataBP returns empty blkptr (no error).
	dn := newDnode(dmotPlainFileContents, 1, 0, 0)
	dn.nlevels = 2
	dn.indblkshift = 7
	// blkptrAt(0) is null (all zeros).
	dn.encode()
	bp, err := findDataBP(bytes.NewReader(nil), 0, dn, 0)
	if err != nil {
		t.Fatalf("expected nil error for null indirect BP, got %v", err)
	}
	if !bp.isNull() {
		t.Fatalf("expected null BP result, got non-null")
	}
}

func TestFindDataBP_IndirBlockOutOfBounds(t *testing.T) {
	// After reading the indirect block, the index is out of bounds.
	// Use a small indirect block (128 bytes) but put the data BP at position 0
	// and ask for blockID that results in idx=0 initially.
	const psize = 512
	indirBuf := make([]byte, psize)
	// No data BP at any position (all null).
	img := indirBuf

	dn := newDnode(dmotPlainFileContents, 1, 0, 0)
	dn.nlevels = 2
	dn.indblkshift = 7 // bpsPerBlock = 1
	dn.setBlkptrAt(0, makeBlkptr(0, psize, psize, zcompressOff, dmotPlainFileContents, 0, 1))
	dn.encode()

	// blockID=0 → idx=0 (within bounds); null BP at idx=0 → index ok but null returned.
	bp, err := findDataBP(bytes.NewReader(img), 0, dn, 0)
	if err != nil {
		t.Fatalf("findDataBP with null embedded BP: %v", err)
	}
	if !bp.isNull() {
		t.Fatalf("expected null BP from empty indirect block")
	}
}

func TestReadDataBlock_NullBPFromIndirect(t *testing.T) {
	// When findDataBP returns a null blkptr (indirect block has empty entry),
	// readDataBlock should return a zero block of dataBlockSize.
	const psize = 512
	// Indirect block: all zeros at index 0 (null BP).
	indirBuf := make([]byte, psize)

	dn := newDnode(dmotPlainFileContents, 1, 0, 0)
	dn.datablkszsec = 1 // 512 bytes per data block
	dn.nlevels = 2
	dn.indblkshift = 7 // bpsPerBlock=1
	dn.setBlkptrAt(0, makeBlkptr(0, psize, psize, zcompressOff, dmotPlainFileContents, 0, 1))
	dn.encode()

	blk, err := readDataBlock(bytes.NewReader(indirBuf), 0, dn, 0)
	if err != nil {
		t.Fatalf("readDataBlock null indirect entry: %v", err)
	}
	// Should return a zero block of dataBlockSize = 512
	if len(blk) != 512 {
		t.Fatalf("len = %d, want 512", len(blk))
	}
	for _, b := range blk {
		if b != 0 {
			t.Fatal("expected zero block from null indirect BP")
		}
	}
}

func TestReadDataBlock_ZeroLevelDnode(t *testing.T) {
	// nlevels=0 → returns zero block of dataBlockSize.
	dn := newDnode(dmotPlainFileContents, 1, 0, 0)
	dn.nlevels = 0
	dn.encode()
	data, err := readDataBlock(bytes.NewReader(nil), 0, dn, 0)
	if err != nil {
		t.Fatalf("nlevels=0: %v", err)
	}
	if len(data) != dn.dataBlockSize() {
		t.Fatalf("len = %d, want %d", len(data), dn.dataBlockSize())
	}
}

// ── additional coverage tests ─────────────────────────────────────────────────

func TestReadDnodeData_ZeroDataBlockSize(t *testing.T) {
	// maxblkid=0, non-null blkptr[0], but datablkszsec=0 → blkSz==0 → return nil, nil.
	dn := newDnode(dmotPlainFileContents, 1, 0, 0)
	dn.datablkszsec = 0
	dn.setBlkptrAt(0, makeBlkptr(0, 512, 512, zcompressOff, dmotPlainFileContents, 0, 1))
	dn.maxblkid = 0
	dn.encode()
	data, err := readDnodeData(bytes.NewReader(nil), 0, dn)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if data != nil {
		t.Fatalf("expected nil data, got %v", data)
	}
}

func TestReadDnodeData_ReadError(t *testing.T) {
	// maxblkid=0, non-null blkptr, but empty reader → ReadAt fails → error.
	dn := newDnode(dmotPlainFileContents, 1, 0, 0)
	dn.datablkszsec = 1 // 512-byte block
	dn.setBlkptrAt(0, makeBlkptr(0, 512, 512, zcompressOff, dmotPlainFileContents, 0, 1))
	dn.maxblkid = 0
	dn.encode()
	_, err := readDnodeData(bytes.NewReader(nil), 0, dn)
	if err == nil {
		t.Fatal("expected error for failed ReadAt")
	}
}

func TestFindDataBP_IndirBlockReadError(t *testing.T) {
	// nlevels=2, non-null outer BP, but reader is empty → readBlock fails on indirect block.
	dn := newDnode(dmotPlainFileContents, 1, 0, 0)
	dn.nlevels = 2
	dn.indblkshift = 7
	dn.setBlkptrAt(0, makeBlkptr(0, 512, 512, zcompressOff, dmotPlainFileContents, 0, 1))
	dn.encode()
	_, err := findDataBP(bytes.NewReader(nil), 0, dn, 0)
	if err == nil {
		t.Fatal("expected error when indirect block ReadAt fails")
	}
}
