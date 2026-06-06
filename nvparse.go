package filesystem_zfs

// nvparse.go — NVList XDR DECODER for ZFS vdev labels (counterpart of
// the encoder in nvlist.go). cloud-boot-init needs this to walk the
// vdev_tree NVList of a multi-vdev pool and discover the RAID-Z /
// mirror topology before opening the FS.
//
// Format (matches the comment in nvlist.go):
//
//	[0..3]   encode  (int32 LE) = 1 (XDR)
//	[4..7]   endian  (int32 LE) = 1 (LE)
//	then nvpairs in XDR (big-endian) until an 8-byte zero terminator:
//	  [0..3]   encoded_size (int32 BE) — total bytes of this pair
//	  [4..7]   decoded_size (int32 BE) — ignored
//	  [8..11]  name_len     (int32 BE)
//	  [12..]   name bytes padded to 4-byte boundary (no trailing NUL,
//	                                                  the name_len is
//	                                                  the exact length)
//	  [+4]     type   (int32 BE) — DATA_TYPE_*
//	  [+4]     nelem  (int32 BE)
//	  [+]      data   — type-dependent encoding

import (
	"encoding/binary"
	"fmt"
)

// parsedNVPair is the decoded form of an on-disk nvpair.
type parsedNVPair struct {
	name  string
	typ   int32
	nelem int32
	data  []byte // raw XDR-encoded value bytes (caller decodes per type)
}

// parsedNVList is an ordered list of parsedNVPair.
type parsedNVList []parsedNVPair

// findByName returns the first pair with the given name, or nil.
func (l parsedNVList) findByName(name string) *parsedNVPair {
	for i := range l {
		if l[i].name == name {
			return &l[i]
		}
	}
	return nil
}

// uint64Value returns the uint64 stored in a DATA_TYPE_UINT64 pair.
func (p *parsedNVPair) uint64Value() (uint64, error) {
	if p.typ != nvDataTypeUint64 || len(p.data) < 8 {
		return 0, fmt.Errorf("nvpair %q: not a uint64 (typ=%d len=%d)", p.name, p.typ, len(p.data))
	}
	return binary.BigEndian.Uint64(p.data[:8]), nil
}

// stringValue returns the string stored in a DATA_TYPE_STRING pair.
func (p *parsedNVPair) stringValue() (string, error) {
	if p.typ != nvDataTypeString {
		return "", fmt.Errorf("nvpair %q: not a string (typ=%d)", p.name, p.typ)
	}
	if len(p.data) < 4 {
		return "", fmt.Errorf("nvpair %q: string data too short", p.name)
	}
	n := int(binary.BigEndian.Uint32(p.data[:4]))
	if 4+n > len(p.data) {
		return "", fmt.Errorf("nvpair %q: string length %d exceeds data %d", p.name, n, len(p.data)-4)
	}
	return string(p.data[4 : 4+n]), nil
}

// nvlistValue returns a decoded nested NVList for a DATA_TYPE_NVLIST
// pair. The inner XDR uses its own [version, nvflags] header.
func (p *parsedNVPair) nvlistValue() (parsedNVList, error) {
	if p.typ != nvDataTypeNVList {
		return nil, fmt.Errorf("nvpair %q: not an nvlist (typ=%d)", p.name, p.typ)
	}
	return decodeInnerNVList(p.data)
}

// nvlistArrayValue returns N decoded nested NVLists for a
// DATA_TYPE_NVLIST_ARRAY pair.
func (p *parsedNVPair) nvlistArrayValue() ([]parsedNVList, error) {
	if p.typ != nvDataTypeNVListArray {
		return nil, fmt.Errorf("nvpair %q: not an nvlist array (typ=%d)", p.name, p.typ)
	}
	out := make([]parsedNVList, 0, p.nelem)
	rest := p.data
	for i := int32(0); i < p.nelem; i++ {
		// Each element starts with its own (version, nvflags) header.
		if len(rest) < 8 {
			return nil, fmt.Errorf("nvpair %q: short nvlist-array element %d", p.name, i)
		}
		inner, consumed, err := decodeInnerNVListWithBytes(rest)
		if err != nil {
			return nil, fmt.Errorf("nvpair %q: element %d: %w", p.name, i, err)
		}
		out = append(out, inner)
		rest = rest[consumed:]
	}
	return out, nil
}

// decodeNVList decodes a top-level XDR NVList. The 4-byte outer
// nvs_header (encoding byte + endian byte + 2 reserved) is consumed
// first; the inner header (version + nvflags = 8 bytes BE) is handled
// by decodeInnerNVList below.
func decodeNVList(b []byte) (parsedNVList, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("nvlist: short outer header")
	}
	encoding := b[0]
	endian := b[1]
	// b[2], b[3] are reserved.
	if encoding != nvEncodeXDR {
		return nil, fmt.Errorf("nvlist: unsupported encoding %d", encoding)
	}
	if endian != nvEndianLE {
		return nil, fmt.Errorf("nvlist: unsupported endian %d", endian)
	}
	return decodeInnerNVList(b[4:])
}

// decodeInnerNVList decodes the inner XDR sequence: [version, nvflags]
// + nvpairs + 8-byte terminator. Used for outer-header-less NVLists
// (the ones nested inside an outer NVList).
func decodeInnerNVList(b []byte) (parsedNVList, error) {
	out, _, err := decodeInnerNVListWithBytes(b)
	return out, err
}

func decodeInnerNVListWithBytes(b []byte) (parsedNVList, int, error) {
	if len(b) < 8 {
		return nil, 0, fmt.Errorf("nvlist: short inner header")
	}
	// Inner header: version(uint32 BE) + nvflags(uint32 BE)
	// Some encoders use BE here per the XDR convention.
	off := 8 // skip version + nvflags
	var out parsedNVList
	for off < len(b) {
		// 8-byte terminator means end of pairs.
		if off+8 <= len(b) {
			if binary.BigEndian.Uint32(b[off:off+4]) == 0 && binary.BigEndian.Uint32(b[off+4:off+8]) == 0 {
				off += 8
				break
			}
		}
		if off+16 > len(b) {
			return nil, 0, fmt.Errorf("nvlist: pair header truncated at off %d", off)
		}
		encSize := int(int32(binary.BigEndian.Uint32(b[off : off+4])))
		// decoded_size at off+4 — ignored.
		nameLen := int(binary.BigEndian.Uint32(b[off+8 : off+12]))
		if encSize <= 0 || off+encSize > len(b) {
			return nil, 0, fmt.Errorf("nvlist: bad encoded_size %d at off %d", encSize, off)
		}
		nameStart := off + 12
		if nameStart+nameLen > len(b) {
			return nil, 0, fmt.Errorf("nvlist: name truncated at off %d (len=%d)", off, nameLen)
		}
		name := string(b[nameStart : nameStart+nameLen])
		// Trim trailing NULs — older encoders pad with NULs to the
		// XDR length boundary.
		for len(name) > 0 && name[len(name)-1] == 0 {
			name = name[:len(name)-1]
		}
		// XDR pads the name field up to a 4-byte boundary.
		namePadded := (nameLen + 3) &^ 3
		typeOff := nameStart + namePadded
		if typeOff+8 > off+encSize {
			return nil, 0, fmt.Errorf("nvlist: pair %q: type/nelem out of pair range", name)
		}
		typ := int32(binary.BigEndian.Uint32(b[typeOff : typeOff+4]))
		nelem := int32(binary.BigEndian.Uint32(b[typeOff+4 : typeOff+8]))
		dataStart := typeOff + 8
		dataEnd := off + encSize
		out = append(out, parsedNVPair{
			name:  name,
			typ:   typ,
			nelem: nelem,
			data:  append([]byte(nil), b[dataStart:dataEnd]...),
		})
		off += encSize
	}
	return out, off, nil
}
