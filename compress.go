package filesystem_zfs

// compress.go – Decompression for ZFS block data.
// Implements LZ4 (most common), LZJB (legacy), and ZLE (zero-length encoding).

import (
	"encoding/binary"
	"fmt"
)

// lz4Decompress decompresses ZFS LZ4-compressed data.
// ZFS LZ4 format: 4 bytes big-endian compressed size, then raw LZ4 block data.
// dst is the expected uncompressed size.
func lz4Decompress(src []byte, dstSize int) ([]byte, error) {
	if len(src) < 4 {
		return nil, fmt.Errorf("zfs: lz4: source too short")
	}
	// First 4 bytes: big-endian compressed blob size (excluding the header)
	compSize := int(binary.BigEndian.Uint32(src[:4]))
	if 4+compSize > len(src) {
		return nil, fmt.Errorf("zfs: lz4: compressed size %d exceeds buffer %d", compSize, len(src)-4)
	}
	return lz4DecodeBlock(src[4:4+compSize], dstSize)
}

// lz4DecodeBlock decompresses a raw LZ4 block (no frame header).
// dst capacity is dstSize bytes.
func lz4DecodeBlock(src []byte, dstSize int) ([]byte, error) {
	dst := make([]byte, 0, dstSize)
	si := 0
	for {
		if si >= len(src) {
			break
		}
		token := src[si]
		si++

		// Literal length
		litLen := int(token >> 4)
		if litLen == 15 {
			for si < len(src) {
				extra := src[si]
				si++
				litLen += int(extra)
				if extra != 255 {
					break
				}
			}
		}

		// Copy literals
		if si+litLen > len(src) {
			return nil, fmt.Errorf("zfs: lz4: literal overflow")
		}
		dst = append(dst, src[si:si+litLen]...)
		si += litLen

		// Last sequence has no match
		if si >= len(src) {
			break
		}
		if len(src)-si < 2 {
			break
		}

		// Match offset (LE uint16)
		offset := int(binary.LittleEndian.Uint16(src[si:]))
		si += 2
		if offset == 0 {
			return nil, fmt.Errorf("zfs: lz4: zero match offset")
		}

		// Match length
		matchLen := int(token&0xF) + 4
		if token&0xF == 15 {
			for si < len(src) {
				extra := src[si]
				si++
				matchLen += int(extra)
				if extra != 255 {
					break
				}
			}
		}

		// Copy match from already-decoded output
		matchStart := len(dst) - offset
		if matchStart < 0 {
			return nil, fmt.Errorf("zfs: lz4: invalid match offset %d at pos %d", offset, len(dst))
		}
		for i := 0; i < matchLen; i++ {
			dst = append(dst, dst[matchStart+i])
		}

		if len(dst) >= dstSize {
			break
		}
	}
	if len(dst) < dstSize {
		// Pad with zeros if needed (shouldn't happen with correct data)
		extra := make([]byte, dstSize-len(dst))
		dst = append(dst, extra...)
	}
	return dst[:dstSize], nil
}

// lzjbDecompress decompresses LZJB-compressed data (legacy ZFS default).
// LZJB is a simple sliding-window compression with 9-bit symbols.
func lzjbDecompress(src []byte, dstSize int) ([]byte, error) {
	dst := make([]byte, dstSize)
	const (
		nbitsHz       = 9
		copyrangeMask = (1 << nbitsHz) - 1
	)
	si, di := 0, 0
	for di < dstSize {
		if si >= len(src) {
			break
		}
		ctrlByte := int(src[si])
		si++
		for msk := 1; msk < 0x100 && di < dstSize; msk <<= 1 {
			if si >= len(src) {
				break
			}
			if ctrlByte&msk != 0 {
				// Back reference: 2 bytes
				if si+1 >= len(src) {
					break
				}
				copyDst := di
				hi := src[si]
				lo := src[si+1]
				si += 2
				offset := ((int(hi) & copyrangeMask) << 8) | int(lo)
				if offset == 0 {
					break
				}
				copyLen := (hi >> 5) + 3
				for i := 0; i < int(copyLen) && di < dstSize; i++ {
					src2 := copyDst - offset
					if src2 < 0 {
						dst[di] = 0
					} else {
						dst[di] = dst[src2]
					}
					di++
				}
			} else {
				// Literal byte
				dst[di] = src[si]
				si++
				di++
			}
		}
	}
	return dst, nil
}

// zleDecompress decompresses ZLE (zero-length encoding) data.
// ZLE encodes runs of zeros: non-zero bytes are stored literally,
// runs of zeros are encoded as 0 + (length - 1) bytes.
func zleDecompress(src []byte, dstSize int) ([]byte, error) {
	dst := make([]byte, dstSize)
	si, di := 0, 0
	for di < dstSize && si < len(src) {
		if src[si] == 0 {
			si++
			if si >= len(src) {
				di++
				continue
			}
			n := int(src[si]) + 1
			si++
			di += n
		} else {
			dst[di] = src[si]
			si++
			di++
		}
	}
	return dst, nil
}
