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
func nvNVList(name string, inner nvList) nvPair {
	b := encodeNVList(inner)
	// For NVList type: nelem = 1, data = encoded inner list
	return nvPair{name: name, typ: nvDataTypeNVList, nelem: 1, data: b}
}

// nvNVListArray returns an nvPair holding an array of nvlists.
func nvNVListArray(name string, lists []nvList) nvPair {
	var all []byte
	for _, l := range lists {
		all = append(all, encodeNVList(l)...)
	}
	return nvPair{name: name, typ: nvDataTypeNVListArray, nelem: int32(len(lists)), data: all}
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
func encodeNVPair(p nvPair) []byte {
	// name_len including null + XDR pad
	nameBytes := append([]byte(p.name), 0)
	namePad := xdrPad(len(nameBytes))
	nameEncoded := append(nameBytes, namePad...)

	// Pair content (after encoded_size and decoded_size):
	// name_len (4) + name + type (4) + nelem (4) + data
	pairContent := make([]byte, 0, 4+len(nameEncoded)+4+4+len(p.data))
	pairContent = appendInt32BE(pairContent, int32(len(nameBytes))) // name_len w/ null
	pairContent = append(pairContent, nameEncoded...)
	pairContent = appendInt32BE(pairContent, p.typ)
	pairContent = appendInt32BE(pairContent, p.nelem)
	pairContent = append(pairContent, p.data...)

	// encoded_size = 4 (encoded_size field) + 4 (decoded_size) + len(pairContent)
	encodedSize := int32(4 + 4 + len(pairContent))
	decodedSize := encodedSize // approximate

	var out []byte
	out = appendInt32BE(out, encodedSize)
	out = appendInt32BE(out, decodedSize)
	out = append(out, pairContent...)
	return out
}

// encodeNVListFull encodes an nvList with the 8-byte outer header.
func encodeNVListFull(pairs nvList) []byte {
	// 8-byte header: encode (LE int32) + endian (LE int32)
	hdr := make([]byte, 8)
	binary.LittleEndian.PutUint32(hdr[0:4], nvEncodeXDR)
	binary.LittleEndian.PutUint32(hdr[4:8], nvEndianLE)
	// Inner nvlist version + nvflags (NV_VERSION=0, NV_UNIQUE_NAME=1)
	inner := make([]byte, 8)
	binary.BigEndian.PutUint32(inner[0:4], 0) // nvl_version = 0
	binary.BigEndian.PutUint32(inner[4:8], 1) // nvl_nvflag = NV_UNIQUE_NAME=1
	body := encodeNVList(pairs)
	return append(append(hdr, inner...), body...)
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
