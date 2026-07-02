package filesystem_zfs

// crypt_block.go — block-level classification and the dnode partial
// gather-AEAD for native-encryption reads.
//
// OpenZFS overloads blk_prop bit 61 (BP_USES_CRYPT) across three block
// kinds (include/sys/spa.h):
//
//   - BP_IS_ENCRYPTED      crypt ∧ level 0 ∧ DMU_OT_IS_ENCRYPTED(type):
//                          the block body is ciphertext and must be
//                          decrypted with the per-block key.
//   - BP_IS_AUTHENTICATED  crypt ∧ level 0 ∧ !encrypted-type: the body
//                          is PLAINTEXT (compressed) and merely carries
//                          an HMAC; it is readable without decryption.
//   - BP_HAS_INDIRECT_MAC  crypt ∧ level > 0: an indirect block whose
//                          MAC words hold a checksum-of-MACs; the body
//                          is again plaintext.
//
// Only the first kind is decrypted; the read path decompresses the
// other two unchanged. Getting this classification right is what makes
// the objset block (authenticated) and indirect blocks (MAC-cksum)
// readable — the previous whole-BP_USES_CRYPT test tried to decrypt them
// and tripped the AEAD tag.

import (
	"encoding/binary"
	"fmt"

	"github.com/go-encryptions/zfscrypt"
)

const (
	// dnodeCoreSize is DNODE_CORE_SIZE — the dnode header before the
	// block-pointer/bonus region and the number of bytes authenticated
	// (as AAD) from each dnode when decrypting a dnode block.
	dnodeCoreSize = 64
	// dnodeFlagSpillBlkptr is DNODE_FLAG_SPILL_BLKPTR. It is also the
	// only bit in DNODE_CRYPT_PORTABLE_FLAGS_MASK, so masking dn_flags
	// with it yields the portable flags authenticated in the AAD.
	dnodeFlagSpillBlkptr = 1 << 2

	// DMU new-type encoding: object types with DMU_OT_NEWTYPE set store
	// their metadata/encryption flags directly in the type byte instead
	// of in the dmu_ot[] table.
	dmuOTNewType       = 0x80
	dmuOTEncryptedFlag = 0x20
)

// dmuOTIsEncrypted mirrors OpenZFS's DMU_OT_IS_ENCRYPTED: it reports
// whether a DMU object type's blocks (and bonus buffers) are encrypted
// rather than merely authenticated. The legacy branch matches the
// ot_encrypt column of the dmu_ot[] table (module/zfs/dmu.c); the
// new-type branch reads the encryption flag out of the type byte.
func dmuOTIsEncrypted(ot uint8) bool {
	if ot&dmuOTNewType != 0 {
		return ot&dmuOTEncryptedFlag != 0
	}
	switch ot {
	case dmotIntentLog, dmotDnode, dmotOldACL, dmotPlainFileContents,
		dmotDirContents, dmotUnlinkedSet, dmotZVol, dmotPlainOther,
		dmotUint64Other, dmotACL, dmotSysACL, dmotFUID,
		dmotUserGroupUsed, dmotUserGroupQuota, dmotSA, dmotSAMasterNode,
		dmotSAAttrRegistration, dmotSAAttrLayouts, dmotDedup:
		return true
	default:
		return false
	}
}

// bpUsesCrypt reports whether blk_prop's crypt bit (61) is set — true
// for encrypted, authenticated and indirect-MAC blocks alike.
func bpUsesCrypt(bp blkptr) bool { return bp.prop&blkPropCryptBit != 0 }

// bpIsEncrypted implements OpenZFS's BP_IS_ENCRYPTED: the block body is
// ciphertext and must be run through the per-block AEAD. Authenticated
// (level-0, non-encrypted type) and indirect (level > 0) crypt blocks
// return false — their bodies are plaintext.
func bpIsEncrypted(bp blkptr) bool {
	return bpUsesCrypt(bp) && bp.level() == 0 && dmuOTIsEncrypted(bp.dmuType())
}

// decryptDnodeBlock decrypts an encrypted dnode-array block. Only the
// encrypted bonus buffers are ciphertext; they are gathered (in dnode
// order) into a single AEAD stream authenticated by an AAD assembled
// from every dnode's core fields, block pointers and plaintext bonus
// buffers. On success it returns a copy of the block with the bonus
// buffers replaced by their plaintext.
//
// Mirrors module/os/*/zfs/zio_crypt.c zio_crypt_init_uios_dnode +
// zio_do_crypt_uio for a little-endian (non-byteswapped) pool.
func decryptDnodeBlock(c *cryptCtx, key, iv, mac, block []byte) ([]byte, error) {
	out := append([]byte(nil), block...)

	var aad []byte
	var gathered []byte
	type region struct{ off, length int }
	var regions []region

	for i := 0; i+dnodeMinSize <= len(block); {
		dnp := block[i:]
		dnSize := (int(dnp[12]) + 1) * dnodeMinSize
		if i+dnSize > len(block) {
			break
		}
		typ := dnp[0]
		nblkptr := int(dnp[3])
		bonusType := dnp[4]
		bonusLen := binary.LittleEndian.Uint16(dnp[10:])
		flags := dnp[7]
		hasSpill := flags&dnodeFlagSpillBlkptr != 0

		bonusOff := dnodeCoreSize + nblkptr*blkptrSize
		// A corrupt dn_nblkptr / dn_extra_slots must not slice out of
		// bounds; bail on any dnode whose declared regions overrun the
		// slot. maxBonus extends to DN_MAX_BONUS_LEN (the spill blkptr, or
		// the end of the dnode) to stay AES-block aligned exactly as the
		// writer did.
		maxBonusEnd := dnSize
		if hasSpill {
			maxBonusEnd = dnSize - blkptrSize
		}
		if bonusOff > maxBonusEnd || i+maxBonusEnd > len(block) {
			return nil, fmt.Errorf("zfs: decrypt dnode block: dnode at %d has invalid layout (nblkptr=%d spill=%v)", i, nblkptr, hasSpill)
		}
		maxBonus := maxBonusEnd - bonusOff

		// AAD: dnode core (64 bytes) with non-portable dn_flags masked
		// out and dn_used zeroed.
		core := make([]byte, dnodeCoreSize)
		copy(core, dnp[:dnodeCoreSize])
		core[7] &= dnodeFlagSpillBlkptr
		for k := 24; k < 32; k++ {
			core[k] = 0
		}
		aad = append(aad, core...)

		// AAD: one blkptr_auth_buf per data/indirect block pointer, then
		// the spill pointer if present.
		for j := 0; j < nblkptr; j++ {
			base := dnodeCoreSize + j*blkptrSize
			aad = append(aad, blkptrAuthBuf(parseBlkptr(dnp[base:base+blkptrSize]), c.version)...)
		}
		if hasSpill {
			spillOff := dnSize - blkptrSize
			aad = append(aad, blkptrAuthBuf(parseBlkptr(dnp[spillOff:spillOff+blkptrSize]), c.version)...)
		}

		// Bonus buffer: encrypted → gather ciphertext; otherwise → append
		// its plaintext to the AAD (it is authenticated, not encrypted).
		if typ != dmotNone && dmuOTIsEncrypted(bonusType) && bonusLen != 0 {
			regions = append(regions, region{off: i + bonusOff, length: maxBonus})
			gathered = append(gathered, block[i+bonusOff:i+bonusOff+maxBonus]...)
		} else {
			aad = append(aad, block[i+bonusOff:i+bonusOff+maxBonus]...)
		}

		i += dnSize
	}

	// A dnode block with no encrypted bonus buffers (no_crypt) is stored
	// as plaintext — return it unchanged.
	if len(gathered) == 0 {
		return out, nil
	}

	pt, err := zfscrypt.DecryptBlock(c.suite, key, iv, mac, gathered, aad)
	if err != nil {
		return nil, fmt.Errorf("zfs: decrypt dnode block: %w", err)
	}

	pos := 0
	for _, rg := range regions {
		copy(out[rg.off:rg.off+rg.length], pt[pos:pos+rg.length])
		pos += rg.length
	}
	return out, nil
}

// blkptrAuthBuf builds the blkptr_auth_buf_t bytes OpenZFS folds into the
// dnode AAD for one block pointer: the little-endian blk_prop with its
// non-portable bits zeroed, the 16-byte MAC decoded from the checksum
// words, and (version ≥ 1 only) an 8-byte zero pad.
func blkptrAuthBuf(bp blkptr, version uint64) []byte {
	out := make([]byte, 0, 32)
	var propb [8]byte
	binary.LittleEndian.PutUint64(propb[:], bpZeroNonportableProp(bp, version))
	out = append(out, propb[:]...)

	mac := make([]byte, zioDataMACLen)
	// zio_crypt_decode_mac_bp: OBJSET pointers and holes carry a zero MAC.
	if bp.dmuType() != dmotObjset && !bp.isNull() {
		binary.LittleEndian.PutUint64(mac[0:8], bp.cksum[2])
		binary.LittleEndian.PutUint64(mac[8:16], bp.cksum[3])
	}
	out = append(out, mac...)

	if version != 0 {
		out = append(out, make([]byte, 8)...) // bab_pad
	}
	return out
}

// zioDataMACLen is ZIO_DATA_MAC_LEN.
const zioDataMACLen = 16

// bpZeroNonportableProp returns blk_prop with the fields OpenZFS treats
// as non-portable zeroed, matching zio_crypt_bp_zero_nonportable_blkprop
// so the AAD is reproducible across raw sends. The dedup and checksum
// fields are always cleared; version-0 pools additionally clear psize,
// and indirect (level > 0) pointers also clear byteorder, compression
// and psize.
func bpZeroNonportableProp(bp blkptr, version uint64) uint64 {
	const (
		cksumMask = uint64(bpCksumBits) << bpCksumShift
		psizeMask = uint64(bpPsizeBits) << bpPsizeShift
		compMask  = uint64(bpCompressBits) << bpCompressShift
	)
	prop := bp.prop
	if version == 0 {
		prop &^= bpDedupBit
		prop &^= cksumMask
		prop &^= psizeMask
		return prop
	}
	if bp.isNull() {
		return 0
	}
	if (prop>>bpLevelShift)&bpLevelBits != 0 {
		prop &^= bpLEBit
		prop &^= compMask
		prop &^= psizeMask
	}
	prop &^= bpDedupBit
	prop &^= cksumMask
	return prop
}
