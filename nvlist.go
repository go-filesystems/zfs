package filesystem_zfs

// nvlist.go – Minimal NVList XDR encoder for ZFS vdev labels.
//
// The NVList in a ZFS vdev label is XDR-encoded (NV_ENCODE_XDR = 1).
// Format:
//   [0..3]   encode    (int32 LE): 1 = XDR
//   [4..7]   endian    (int32 LE): 1 = LE
//   nvpairs (big-endian XDR until null terminator):
//     [0..3]   encoded_size (int32 BE): total bytes of this pair
//     [4..7]   decoded_size (int32 BE): size when decoded to native struct
//     [8..11]  name_len (int32 BE): length of name including null
//     [12..]   name (name_len bytes, XDR-padded to 4 bytes)
//     [+4]     type (int32 BE): DATA_TYPE_*
//     [+4]     nelem (int32 BE): number of elements
//     [+]      data
//   null terminator: 8 zero bytes

import (
	"encoding/binary"
)

const (
	nvEncodeXDR = 1
	nvEndianLE  = 1

	// NVPair types (DATA_TYPE_*) from OpenZFS sys/nvpair.h.
	// Pre-2026-05-22 the lib had several of these wrong by ~3 (e.g.
	// UINT64 was 11 instead of 8, STRING was 14 instead of 9) —
	// self-consistent with the lib's encoder but incompatible with
	// every real ZFS pool. Reset to the canonical OpenZFS values.
	nvDataTypeUnknown      = 0
	nvDataTypeBoolean      = 1
	nvDataTypeByte         = 2
	nvDataTypeInt16        = 3
	nvDataTypeUint16       = 4
	nvDataTypeInt32        = 5
	nvDataTypeUint32       = 6
	nvDataTypeInt64        = 7
	nvDataTypeUint64       = 8
	nvDataTypeString       = 9
	nvDataTypeByteArray    = 10
	nvDataTypeInt16Array   = 11
	nvDataTypeUint16Array  = 12
	nvDataTypeInt32Array   = 13
	nvDataTypeUint32Array  = 14
	nvDataTypeInt64Array   = 15
	nvDataTypeUint64Array  = 16
	nvDataTypeStringArray  = 17
	nvDataTypeHRTime       = 18
	nvDataTypeNVList       = 19
	nvDataTypeNVListArray  = 20
	nvDataTypeBoolValue    = 21
	nvDataTypeInt8         = 22
	nvDataTypeUint8        = 23
	nvDataTypeBoolArray    = 24
	nvDataTypeInt8Array    = 25
	nvDataTypeUint8Array   = 26
)

// nvPair represents a name-value pair.
type nvPair struct {
	name  string
	typ   int32
	nelem int32
	data  []byte // raw XDR-encoded value data
}

// nvList is an ordered list of nvPairs.
type nvList []nvPair

// nvUint64 returns an nvPair holding a uint64.
func nvUint64(name string, val uint64) nvPair {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, val)
	return nvPair{name: name, typ: nvDataTypeUint64, nelem: 1, data: b}
}

// nvString returns an nvPair holding a string.
func nvString(name, val string) nvPair {
	// XDR string: 4 bytes length (BE) + bytes + padding to 4-byte boundary
	b := encodeXDRString(val)
	return nvPair{name: name, typ: nvDataTypeString, nelem: 1, data: b}
}

// nvNVList returns an nvPair holding a nested nvlist.
//
// The data slice carries the inner XDR sequence: the BE [version,
// nvflags] header followed by the pair stream. decodeInnerNVList
// (the corresponding decoder) consumes exactly that shape.
func nvNVList(name string, inner nvList) nvPair {
	b := encodeInnerNVList(inner)
	// For NVList type: nelem = 1, data = inner-header + encoded list
	return nvPair{name: name, typ: nvDataTypeNVList, nelem: 1, data: b}
}

// nvNVListArray returns an nvPair holding an array of nvlists. Each
// element is prefixed with its own inner [version, nvflags] BE header,
// matching the decoder loop in parsedNVPair.nvlistArrayValue().
func nvNVListArray(name string, lists []nvList) nvPair {
	var all []byte
	for _, l := range lists {
		all = append(all, encodeInnerNVList(l)...)
	}
	return nvPair{name: name, typ: nvDataTypeNVListArray, nelem: int32(len(lists)), data: all}
}

// encodeInnerNVList encodes a single nested NVList: the 8-byte BE
// [version, nvflags] header (NV_VERSION=0, NV_UNIQUE_NAME=1) followed
// by the pair body produced by encodeNVList. The decoder's
// decodeInnerNVList strips the first 8 bytes before walking pairs.
func encodeInnerNVList(pairs nvList) []byte {
	inner := make([]byte, 8)
	binary.BigEndian.PutUint32(inner[0:4], 0) // nvl_version = 0
	binary.BigEndian.PutUint32(inner[4:8], 1) // nvl_nvflag = NV_UNIQUE_NAME=1
	return append(inner, encodeNVList(pairs)...)
}

// nvUint64Array returns an nvPair holding an array of uint64.
func nvUint64Array(name string, vals []uint64) nvPair {
	b := make([]byte, 8*len(vals))
	for i, v := range vals {
		binary.BigEndian.PutUint64(b[i*8:], v)
	}
	return nvPair{name: name, typ: nvDataTypeUint64Array, nelem: int32(len(vals)), data: b}
}

// encodeNVList encodes an nvList into XDR bytes (without the 8-byte outer header).
func encodeNVList(pairs nvList) []byte {
	var out []byte
	for _, p := range pairs {
		out = append(out, encodeNVPair(p)...)
	}
	out = append(out, 0, 0, 0, 0) // null terminator
	out = append(out, 0, 0, 0, 0)
	return out
}

// encodeNVPair encodes a single nvPair into XDR bytes.
//
// On-disk shape (all fields big-endian, matching OpenZFS nvs_xdr):
//
//	encoded_size (int32) — total bytes of this pair on disk
//	decoded_size (int32) — size of the native nvpair_t once unpacked
//	name_len     (int32) — strlen(name), WITHOUT the trailing NUL
//	name         — name_len bytes, zero-padded to a 4-byte boundary
//	               (the implied NUL falls inside that padding)
//	type         (int32) — DATA_TYPE_*
//	nelem        (int32)
//	data         — type-dependent XDR value
//
// Earlier revisions emitted name_len = strlen+1 and the NUL byte in the
// stream, and set decoded_size = encoded_size. Both diverged from the
// spec and made zdb / zpool import fail to unpack the label nvlist.
func encodeNVPair(p nvPair) []byte {
	nameLen := len(p.name)                     // strlen, no NUL
	namePadded := (nameLen + 3) &^ 3           // round up to 4-byte XDR boundary
	nameEncoded := make([]byte, namePadded)
	copy(nameEncoded, p.name)

	// Pair content (after encoded_size and decoded_size):
	// name_len (4) + name (padded) + type (4) + nelem (4) + data
	pairContent := make([]byte, 0, 4+len(nameEncoded)+4+4+len(p.data))
	pairContent = appendInt32BE(pairContent, int32(nameLen))
	pairContent = append(pairContent, nameEncoded...)
	pairContent = appendInt32BE(pairContent, p.typ)
	pairContent = appendInt32BE(pairContent, p.nelem)
	pairContent = append(pairContent, p.data...)

	// encoded_size = 4 (encoded_size field) + 4 (decoded_size) + len(pairContent)
	encodedSize := int32(4 + 4 + len(pairContent))
	decodedSize := nvpairDecodedSize(nameLen, p)

	var out []byte
	out = appendInt32BE(out, encodedSize)
	out = appendInt32BE(out, decodedSize)
	out = append(out, pairContent...)
	return out
}

// nvpairHdrNative is sizeof(nvpair_t) in OpenZFS userland: four 32-bit
// fields (nvp_size, nvp_name_sz, nvp_value_elem, nvp_type). The name
// (with its NUL) is laid out immediately after, the whole header+name
// rounded up to 8 bytes, then the native value (also 8-aligned).
const nvpairHdrNative = 16

func align8(n int) int { return (n + 7) &^ 7 }

// nvpairDecodedSize computes decoded_size: the number of bytes the pair
// occupies as a native nvpair_t once unpacked. Verified byte-for-byte
// against labels written by real `zpool create` (see the commit that
// introduced it). The formula is:
//
//	align8(sizeof(nvpair_t) + namelen + 1) + native_value_size
func nvpairDecodedSize(nameLen int, p nvPair) int32 {
	hdr := align8(nvpairHdrNative + nameLen + 1)
	var val int
	switch p.typ {
	case nvDataTypeUint64, nvDataTypeInt64,
		nvDataTypeUint32, nvDataTypeInt32,
		nvDataTypeUint16, nvDataTypeInt16,
		nvDataTypeUint8, nvDataTypeInt8,
		nvDataTypeByte, nvDataTypeBoolValue:
		// Scalars are stored as a single 8-byte native slot.
		val = 8
	case nvDataTypeString:
		// data = 4-byte XDR length + string bytes (NUL-padded to 4).
		// Native string = strlen+1 rounded to 8.
		strLen := 0
		if len(p.data) >= 4 {
			strLen = int(binary.BigEndian.Uint32(p.data[:4]))
		}
		val = align8(strLen + 1)
	case nvDataTypeUint64Array, nvDataTypeInt64Array:
		val = align8(8 * int(p.nelem))
	case nvDataTypeNVList:
		// One native nvlist_t handle.
		val = 24
	case nvDataTypeNVListArray:
		// nelem native nvlist_t handles, 32 bytes apiece.
		val = 32 * int(p.nelem)
	default:
		val = align8(len(p.data))
	}
	return int32(hdr + val)
}

// encodeNVListFull encodes an nvList with the spec-compliant 4-byte
// outer header (encoding | endian | reserved | reserved), followed by
// the inner [version, nvflags] BE header and the XDR-encoded pairs.
//
// Per OpenZFS sys/nvpair_impl.h (nvs_header_t):
//
//	struct nvs_header_t {
//	    uchar_t nvh_encoding;   // NV_ENCODE_*
//	    uchar_t nvh_endian;     // NV_BIG_ENDIAN / NV_LITTLE_ENDIAN
//	    uchar_t nvh_reserved1;
//	    uchar_t nvh_reserved2;
//	};
//
// Earlier versions of this encoder emitted two LE uint32s (8 bytes)
// instead of the 4 bytes above; that produced labels rejected by zdb /
// zpool import / any third-party reader. The lib's own decoder
// (decodeNVList in nvparse.go) has always read the spec-compliant
// 4-byte shape — the writer is the side that needed correcting.
func encodeNVListFull(pairs nvList) []byte {
	// 4-byte spec-compliant outer header (nvs_header_t).
	hdr := []byte{nvEncodeXDR, nvEndianLE, 0, 0}
	return append(hdr, encodeInnerNVList(pairs)...)
}

func encodeXDRString(s string) []byte {
	b := []byte(s)
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(b)))
	pad := xdrPad(len(b))
	return append(append(lenBytes, b...), pad...)
}

func xdrPad(n int) []byte {
	mod := n % 4
	if mod == 0 {
		return nil
	}
	return make([]byte, 4-mod)
}

func appendInt32BE(b []byte, v int32) []byte {
	x := make([]byte, 4)
	binary.BigEndian.PutUint32(x, uint32(v))
	return append(b, x...)
}
