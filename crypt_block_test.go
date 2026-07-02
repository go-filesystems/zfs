package filesystem_zfs

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/go-encryptions/zfscrypt"
)

// ── suite bridge ──────────────────────────────────────────────────────────────

func TestSuiteFromZioCrypt(t *testing.T) {
	cases := []struct {
		in    uint64
		want  zfscrypt.Suite
		wantK bool
	}{
		{zioCryptAES128CCM, zfscrypt.AES128CCM, true},
		{zioCryptAES192CCM, zfscrypt.AES192CCM, true},
		{zioCryptAES256CCM, zfscrypt.AES256CCM, true},
		{zioCryptAES128GCM, zfscrypt.AES128GCM, true},
		{zioCryptAES192GCM, zfscrypt.AES192GCM, true},
		{zioCryptAES256GCM, zfscrypt.AES256GCM, true},
		{0, 0, false},  // inherit
		{1, 0, false},  // on
		{2, 0, false},  // off
		{9, 0, false},  // functions (out of range)
		{99, 0, false}, // garbage
	}
	for _, c := range cases {
		got, ok := suiteFromZioCrypt(c.in)
		if ok != c.wantK || (ok && got != c.want) {
			t.Errorf("suiteFromZioCrypt(%d) = (%v,%v), want (%v,%v)", c.in, got, ok, c.want, c.wantK)
		}
	}
}

func TestZioCryptFromSuite(t *testing.T) {
	round := []zfscrypt.Suite{
		zfscrypt.AES128CCM, zfscrypt.AES192CCM, zfscrypt.AES256CCM,
		zfscrypt.AES128GCM, zfscrypt.AES192GCM, zfscrypt.AES256GCM,
	}
	for _, s := range round {
		v := zioCryptFromSuite(s)
		back, ok := suiteFromZioCrypt(v)
		if !ok || back != s {
			t.Errorf("zioCryptFromSuite(%v)=%d did not round-trip (back=%v ok=%v)", s, v, back, ok)
		}
	}
	// Non-AES suite falls through to the raw numeric value.
	if got := zioCryptFromSuite(zfscrypt.SuiteInherit); got != uint64(zfscrypt.SuiteInherit) {
		t.Errorf("zioCryptFromSuite(inherit) = %d, want %d", got, uint64(zfscrypt.SuiteInherit))
	}
}

// ── object-type classification ────────────────────────────────────────────────

func TestDmuOTIsEncrypted(t *testing.T) {
	enc := []uint8{dmotIntentLog, dmotDnode, dmotPlainFileContents, dmotDirContents,
		dmotSA, dmotSAMasterNode, dmotUnlinkedSet, dmotACL, dmotUint64Other}
	for _, ot := range enc {
		if !dmuOTIsEncrypted(ot) {
			t.Errorf("dmuOTIsEncrypted(%d) = false, want true", ot)
		}
	}
	plain := []uint8{dmotNone, dmotObjset, dmotMasterNode, dmotDSLDir, dmotObjectDirectory, dmotZAPOther}
	for _, ot := range plain {
		if dmuOTIsEncrypted(ot) {
			t.Errorf("dmuOTIsEncrypted(%d) = true, want false", ot)
		}
	}
	// NEWTYPE encoding: the encryption flag lives in the type byte.
	if !dmuOTIsEncrypted(dmuOTNewType | dmuOTEncryptedFlag) {
		t.Error("newtype encrypted flag not honoured")
	}
	if dmuOTIsEncrypted(dmuOTNewType) {
		t.Error("newtype without encrypted flag should be plaintext")
	}
}

func TestBpIsEncrypted(t *testing.T) {
	// Level-0 encrypted-type block with the crypt bit → encrypted.
	enc := makeBlkptr(4096, 4096, 4096, zcompressOff, dmotPlainFileContents, 0, 1)
	enc.prop |= blkPropCryptBit
	if !bpIsEncrypted(enc) {
		t.Error("expected level-0 plain-file crypt block to be encrypted")
	}
	// Authenticated: crypt bit, level 0, non-encrypted type (objset).
	auth := makeBlkptr(4096, 4096, 4096, zcompressOff, dmotObjset, 0, 1)
	auth.prop |= blkPropCryptBit
	if bpIsEncrypted(auth) {
		t.Error("objset block must be authenticated, not encrypted")
	}
	// Indirect: crypt bit, level > 0.
	ind := makeBlkptr(4096, 4096, 4096, zcompressOff, dmotPlainFileContents, 1, 1)
	ind.prop |= blkPropCryptBit
	if bpIsEncrypted(ind) {
		t.Error("level>0 block must not be treated as encrypted")
	}
	// No crypt bit at all.
	if bpIsEncrypted(makeBlkptr(4096, 4096, 4096, zcompressOff, dmotPlainFileContents, 0, 1)) {
		t.Error("block without crypt bit is not encrypted")
	}
}

// ── portable blk_prop masking + auth buf ──────────────────────────────────────

func TestBpZeroNonportableProp(t *testing.T) {
	bp := makeBlkptr(8192, 4096, 4096, zcompressLZ4, dmotPlainFileContents, 0, 1)
	bp.prop |= bpDedupBit
	bp.prop |= uint64(0x5) << bpCksumShift // some checksum
	// version 1, level 0: dedup + checksum cleared, compression kept.
	got := bpZeroNonportableProp(bp, 1)
	if got&bpDedupBit != 0 {
		t.Error("dedup bit not cleared")
	}
	if (got>>bpCksumShift)&bpCksumBits != 0 {
		t.Error("checksum not cleared")
	}
	if (got>>bpCompressShift)&bpCompressBits != zcompressLZ4 {
		t.Error("level-0 compression must be preserved")
	}

	// version 1, level > 0: byteorder, compression and psize cleared too.
	ind := makeBlkptr(8192, 4096, 4096, zcompressLZ4, dmotPlainFileContents, 2, 1)
	ind.prop |= bpLEBit
	g2 := bpZeroNonportableProp(ind, 1)
	if g2&bpLEBit != 0 || (g2>>bpCompressShift)&bpCompressBits != 0 || (g2>>bpPsizeShift)&bpPsizeBits != 0 {
		t.Errorf("indirect non-portable fields not cleared: %#x", g2)
	}

	// version 0: psize also cleared, compression preserved.
	g0 := bpZeroNonportableProp(bp, 0)
	if (g0>>bpPsizeShift)&bpPsizeBits != 0 {
		t.Error("version-0 psize not cleared")
	}

	// hole (version 1): whole prop zeroed.
	var hole blkptr
	hole.prop = 0xdeadbeef
	if bpZeroNonportableProp(hole, 1) != 0 {
		t.Error("hole prop must be zeroed at version 1")
	}
}

func TestBlkptrAuthBuf(t *testing.T) {
	bp := makeBlkptr(4096, 4096, 4096, zcompressOff, dmotPlainFileContents, 0, 1)
	bp.prop |= blkPropCryptBit
	bp.cksum[2] = 0x1122334455667788
	bp.cksum[3] = 0x99aabbccddeeff00

	v1 := blkptrAuthBuf(bp, 1)
	if len(v1) != 32 {
		t.Fatalf("version-1 bab len = %d, want 32", len(v1))
	}
	if binary.LittleEndian.Uint64(v1[8:16]) != bp.cksum[2] ||
		binary.LittleEndian.Uint64(v1[16:24]) != bp.cksum[3] {
		t.Error("mac words not copied from checksum")
	}
	if !bytes.Equal(v1[24:32], make([]byte, 8)) {
		t.Error("version-1 pad must be zero")
	}

	v0 := blkptrAuthBuf(bp, 0)
	if len(v0) != 24 {
		t.Fatalf("version-0 bab len = %d, want 24 (no pad)", len(v0))
	}

	// OBJSET pointer → zero MAC.
	obj := makeBlkptr(4096, 4096, 4096, zcompressOff, dmotObjset, 0, 1)
	obj.prop |= blkPropCryptBit
	obj.cksum[2], obj.cksum[3] = 1, 2
	ob := blkptrAuthBuf(obj, 1)
	if !bytes.Equal(ob[8:24], make([]byte, 16)) {
		t.Error("objset pointer must carry a zero MAC")
	}

	// Hole → zero MAC and zero prop.
	var hole blkptr
	hb := blkptrAuthBuf(hole, 1)
	if !bytes.Equal(hb, make([]byte, 32)) {
		t.Errorf("hole auth buf must be all zero, got %x", hb)
	}
}

// ── dnode-block decryption ─────────────────────────────────────────────────────

// makeDnodeSlot builds one dnode_phys_t (512 bytes) with the given header
// fields; the blkptr/bonus region is left zero.
func makeDnodeSlot(typ, nblkptr, bonusType uint8, bonusLen uint16, flags uint8) []byte {
	b := make([]byte, dnodeMinSize)
	b[0] = typ
	b[3] = nblkptr
	b[4] = bonusType
	b[7] = flags
	binary.LittleEndian.PutUint16(b[10:], bonusLen)
	return b
}

func TestDecryptDnodeBlockNoCrypt(t *testing.T) {
	// A block whose only dnode has a non-encrypted bonus (master node ZAP)
	// has nothing to decrypt: decryptDnodeBlock returns it unchanged.
	blk := make([]byte, 0, 2*dnodeMinSize)
	blk = append(blk, makeDnodeSlot(dmotMasterNode, 1, dmotMasterNode, 16, 0)...)
	blk = append(blk, makeDnodeSlot(dmotNone, 0, dmotNone, 0, 0)...)
	c := &cryptCtx{suite: zfscrypt.AES256GCM, version: 1}
	out, err := decryptDnodeBlock(c, make([]byte, 32), make([]byte, 12), make([]byte, 16), blk)
	if err != nil {
		t.Fatalf("no-crypt dnode block: %v", err)
	}
	if !bytes.Equal(out, blk) {
		t.Error("no-crypt dnode block should be returned unchanged")
	}
}

func TestDecryptDnodeBlockInvalidLayout(t *testing.T) {
	// nblkptr large enough that the bonus region overruns the 512-byte slot.
	blk := makeDnodeSlot(dmotSA, 6, dmotSA, 64, 0)
	c := &cryptCtx{suite: zfscrypt.AES256GCM, version: 1}
	_, err := decryptDnodeBlock(c, make([]byte, 32), make([]byte, 12), make([]byte, 16), blk)
	if err == nil {
		t.Fatal("expected invalid-layout error")
	}
}

func TestDecryptDnodeBlockAEADFailure(t *testing.T) {
	// An encrypted-bonus dnode with a bogus key/MAC must fail the AEAD tag
	// rather than return garbage.
	blk := makeDnodeSlot(dmotPlainFileContents, 1, dmotSA, 64, 0)
	c := &cryptCtx{suite: zfscrypt.AES256GCM, version: 1}
	_, err := decryptDnodeBlock(c, make([]byte, 32), make([]byte, 12), make([]byte, 16), blk)
	if err == nil {
		t.Fatal("expected AEAD failure on bogus dnode ciphertext")
	}
}

func TestDecryptBlockPayloadNilCtx(t *testing.T) {
	if _, err := decryptBlockPayload(nil, blkptr{}, nil); err == nil {
		t.Fatal("expected error for nil crypt context")
	}
}

func TestDecryptBlockPayloadDeriveKeyError(t *testing.T) {
	// A malformed master key (not 32 bytes) fails at DeriveBlockKey before
	// any AEAD work — for a normal (non-dnode) encrypted block.
	c := &cryptCtx{suite: zfscrypt.AES256GCM, mek: make([]byte, 7), version: 1}
	bp := makeBlkptr(4096, 4096, 4096, zcompressOff, dmotPlainFileContents, 0, 1)
	if _, err := decryptBlockPayload(c, bp, make([]byte, 4096)); err == nil {
		t.Fatal("expected derive-block-key error for short mek")
	}
}

func TestDecryptBlockPayloadNormalAEADFailure(t *testing.T) {
	// A well-formed key but bogus ciphertext must fail the tag on the
	// normal (whole-block, nil-AAD) path.
	c := &cryptCtx{suite: zfscrypt.AES256GCM, mek: make([]byte, 32), version: 1}
	bp := makeBlkptr(4096, 4096, 4096, zcompressOff, dmotPlainFileContents, 0, 1)
	if _, err := decryptBlockPayload(c, bp, make([]byte, 4096)); err == nil {
		t.Fatal("expected AEAD failure on bogus ciphertext")
	}
}

func TestDecryptDnodeBlockTruncatedTail(t *testing.T) {
	// A trailing partial dnode slot (extra_slots claims 2 slots but only 1
	// is present) is skipped by the len-guard, leaving nothing to decrypt.
	blk := makeDnodeSlot(dmotMasterNode, 1, dmotMasterNode, 16, 0)
	blk[12] = 3 // claim 4 slots — overruns the single 512-byte slot
	c := &cryptCtx{suite: zfscrypt.AES256GCM, version: 1}
	out, err := decryptDnodeBlock(c, make([]byte, 32), make([]byte, 12), make([]byte, 16), blk)
	if err != nil {
		t.Fatalf("truncated-tail dnode: %v", err)
	}
	if !bytes.Equal(out, blk) {
		t.Error("truncated-tail block should be returned unchanged")
	}
}
