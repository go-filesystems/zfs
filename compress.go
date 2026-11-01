package filesystem_zfs

// compress.go – Decompression for ZFS block data.
// Implements LZ4 (most common), LZJB (legacy), ZLE (zero-length encoding),
// GZIP (raw zlib stream) and ZSTD (with the ZFS zstd header).

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/go-volumes/safeio"
	"github.com/klauspost/compress/zstd"
)

// Maximum expansion of each codec, in output bytes per input byte. lsize comes
// from the block pointer, so the destination buffer must not be sized from it
// unless the input can actually produce that much: an embedded pointer carries
// at most 112 payload bytes, and declaring 16 MiB of logical size for them was
// a 16 MiB allocation per read.
//
//   - LZ4: "this format has a maximum achievable compression ratio of about
//     ~250" (doc/lz4_Block_format.md); every 255-valued length byte adds 255.
//   - LZJB: a copy item is 2 bytes and yields at most 10 (copyLen =
//     (hi>>5)+3), a literal 1 for 1; 8 is generous.
//   - ZLE: a control byte yields at most 256-zleParam = 192 zero bytes.
const (
	lz4MaxExpansion  = 255
	lzjbMaxExpansion = 8
	zleMaxExpansion  = 256

	// zstdMaxExpansion: a block is at most 128 KiB (Block_Maximum_Size) and an
	// RLE_Block is a 3-byte header plus one byte standing for up to that many
	// (RFC 8878 sections 3.1.1.2.1 to 3.1.1.2.4): 131072 / 4 = 32768.
	zstdMaxExpansion = 32768
)

// expansionSlack is the zero-padding the decoders have always tolerated for a
// short or empty stream (a destination larger than the stream produces comes
// back zero-filled); the gate leaves that much room and no more.
const expansionSlack = 4096

// checkExpansion refuses a destination size that srcLen input bytes cannot
// produce with a codec expanding at most ratio:1 (plus expansionSlack).
func checkExpansion(codec string, srcLen, dstSize, ratio int) error {
	if dstSize < 0 || int64(dstSize) > int64(ratio)*int64(srcLen)+expansionSlack {
		return fmt.Errorf("zfs: %s: %d input bytes cannot expand to %d (max %d:1): %w", codec, srcLen, dstSize, ratio, safeio.ErrTooLarge)
	}
	return nil
}

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
	if err := checkExpansion("lz4", len(src), dstSize, lz4MaxExpansion); err != nil {
		return nil, err
	}
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
		// matchLen is extended by 255-valued bytes with no limit in the
		// format; never produce more than the destination holds (the
		// result is cut to dstSize below, so the tail would be thrown away
		// after being generated -- 1.5 GB from a 1 MiB block).
		if room := dstSize - len(dst); matchLen > room {
			matchLen = room
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
	if err := checkExpansion("lzjb", len(src), dstSize, lzjbMaxExpansion); err != nil {
		return nil, err
	}
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

// zleParam is the ZLE level used by OpenZFS for the ZIO_COMPRESS_ZLE
// algorithm (module/zfs/zio_compress.c: {"zle", 64, ...}). It is the
// threshold separating literal runs from zero runs in the control byte.
const zleParam = 64

// zleDecompress decompresses OpenZFS ZLE (zero-length encoding) data.
//
// ZLE is a stream of control bytes. For each control byte c, let length = c + 1:
//   - if length <= n  (i.e. c < n): the next length bytes are LITERAL bytes
//     copied verbatim from the source;
//   - if length >  n  (i.e. c >= n): a run of (length - n) ZERO bytes is emitted
//     and NO bytes follow the control byte.
//
// This mirrors module/zfs/zle.c:zfs_zle_decompress_buf with n = zleParam (64).
// The previous implementation used a non-spec "0x00 + (len-1)" zero-run format
// that decoded real OpenZFS ZLE blocks to garbage.
func zleDecompress(src []byte, dstSize int) ([]byte, error) {
	const n = zleParam
	if err := checkExpansion("zle", len(src), dstSize, zleMaxExpansion); err != nil {
		return nil, err
	}
	dst := make([]byte, dstSize)
	si, di := 0, 0
	for si < len(src) && di < dstSize {
		length := 1 + int(src[si])
		si++
		if length <= n {
			// Literal run: copy `length` bytes verbatim.
			if si+length > len(src) {
				return nil, fmt.Errorf("zfs: zle: literal run of %d overruns source (%d left)", length, len(src)-si)
			}
			if di+length > dstSize {
				return nil, fmt.Errorf("zfs: zle: literal run of %d overruns destination (%d left)", length, dstSize-di)
			}
			copy(dst[di:], src[si:si+length])
			si += length
			di += length
		} else {
			// Zero run: emit (length - n) zeros. dst is already zeroed,
			// so just advance the destination cursor.
			zeros := length - n
			if di+zeros > dstSize {
				return nil, fmt.Errorf("zfs: zle: zero run of %d overruns destination (%d left)", zeros, dstSize-di)
			}
			di += zeros
		}
	}
	return dst, nil
}

// gzipDecompress decompresses ZFS GZIP-compressed block data.
//
// OpenZFS stores GZIP-compressed blocks as a raw zlib stream (RFC 1950): the
// kernel's gzip_compress / gzip_decompress (module/zfs/gzip.c) call zlib's
// compress2()/uncompress() directly on the buffer, with NO extra framing and
// NO length prefix. The on-disk byte therefore decodes the same way for every
// gzip-1..9 level (ZIO_COMPRESS_GZIP_1..9): the level only affects the
// encoder, not the wire format. We feed the physical buffer to a zlib reader;
// the zlib trailer terminates the stream, so any allocation slack past the
// stream end is harmless.
//
// dstSize is the expected logical (decompressed) size.
func gzipDecompress(src []byte, dstSize int) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(src))
	if err != nil {
		return nil, fmt.Errorf("zfs: gzip: %w", err)
	}
	defer zr.Close()

	// The destination grows with what the stream actually produces (capped at
	// dstSize+1 to notice an overlong stream); it is not sized from lsize up
	// front, which a block pointer is free to set to 16 MiB for a few bytes.
	var out bytes.Buffer
	out.Grow(min(dstSize, 64*len(src)+4096))
	_, err = io.Copy(&out, io.LimitReader(zr, int64(dstSize)+1))
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, fmt.Errorf("zfs: gzip: %w", err)
	}
	if out.Len() != dstSize {
		return nil, fmt.Errorf("zfs: gzip: decompressed %d bytes, want %d", out.Len(), dstSize)
	}
	return out.Bytes(), nil
}

// zstdHeaderSize is the size of the ZFS zstd header (zfs_zstdhdr_t) that
// precedes the magicless zstd frame on disk: a 4-byte big-endian compressed
// length (c_len) followed by a 4-byte big-endian version+level field
// (raw_version_level). See include/sys/zstd/zstd.h.
const zstdHeaderSize = 8

// zstdMagic is the standard zstd frame magic number (little-endian
// 0xFD2FB528). OpenZFS compresses with ZSTD_f_zstd1_magicless (see
// module/zstd/zfs_zstd.c, "Use the 'magicless' zstd header which saves us 4
// header bytes"), so the on-disk frame omits this prefix. The portable Go
// zstd decoder only accepts standard frames, so we re-prepend the magic to
// reconstruct an equivalent standard frame before decoding.
var zstdMagic = []byte{0x28, 0xB5, 0x2F, 0xFD}

// zstdDecoder is a shared, stateless zstd decoder. klauspost's decoder is safe
// for concurrent use across goroutines via DecodeAll.
var zstdDecoder = func() *zstd.Decoder {
	// A block is at most SPA_MAXBLOCKSIZE (16 MiB) of logical data, so neither
	// its output nor its window can legitimately exceed that; the library
	// defaults (64 GiB decoded, 512 MiB window) are limits for trusted input.
	//
	// The destination is exactly the block's logical size, so DecodeAll is
	// limited to the capacity it is given: a frame header declaring a content
	// size (up to 16 MiB here) made DecodeAll grow the destination to it
	// before decoding, 3 MB for a 13-byte block.
	d, err := zstd.NewReader(nil,
		zstd.WithDecoderMaxMemory(spaMaxBlockSize),
		zstd.WithDecoderMaxWindow(spaMaxBlockSize),
		zstd.WithDecodeAllCapLimit(true))
	if err != nil {
		panic(fmt.Sprintf("zfs: zstd: init decoder: %v", err))
	}
	return d
}()

// zstdDecompress decompresses ZFS ZSTD-compressed block data
// (ZIO_COMPRESS_ZSTD).
//
// OpenZFS wraps the zstd frame with a zfs_zstdhdr_t header
// (include/sys/zstd/zstd.h):
//
//	struct zfs_zstdhdr {
//	        uint32_t c_len;              // big-endian compressed length
//	        uint32_t raw_version_level;  // big-endian packed version + level
//	        char     data[];             // raw zstd frame (c_len bytes)
//	};
//
// zfs_zstd_decompress_level (module/zstd/zfs_zstd.c) reads c_len with BE_32 and
// passes hdr->data with length c_len to a decompression context configured for
// the magicless format. We mirror that: skip the 8-byte header, take c_len
// bytes, re-prepend the standard zstd magic, and decode into a dstSize buffer.
//
// dstSize is the expected logical (decompressed) size.
func zstdDecompress(src []byte, dstSize int) ([]byte, error) {
	if len(src) < zstdHeaderSize {
		return nil, fmt.Errorf("zfs: zstd: source too short for header (%d < %d)", len(src), zstdHeaderSize)
	}
	cLen := int(binary.BigEndian.Uint32(src[:4]))
	frameStart := zstdHeaderSize
	if cLen < 0 || frameStart+cLen > len(src) {
		return nil, fmt.Errorf("zfs: zstd: c_len %d exceeds buffer (%d available)", cLen, len(src)-frameStart)
	}
	// Reconstruct a standard frame: magic + magicless on-disk frame.
	frame := make([]byte, 0, 4+cLen)
	frame = append(frame, zstdMagic...)
	frame = append(frame, src[frameStart:frameStart+cLen]...)

	// The destination is allocated at its full size (DecodeAll is limited to
	// the capacity it is given), so refuse before allocating what this frame
	// cannot produce: a frame header that does not parse, a declared content
	// size other than the block's logical size (the result must be exactly
	// dstSize), or a size beyond the format's maximum expansion.
	var h zstd.Header
	if err := h.Decode(frame); err != nil {
		return nil, fmt.Errorf("zfs: zstd: %w", err)
	}
	if h.HasFCS && h.FrameContentSize != uint64(dstSize) {
		return nil, fmt.Errorf("zfs: zstd: frame declares %d bytes, want %d", h.FrameContentSize, dstSize)
	}
	if err := checkExpansion("zstd", cLen, dstSize, zstdMaxExpansion); err != nil {
		return nil, err
	}

	dst, err := zstdDecoder.DecodeAll(frame, make([]byte, 0, dstSize))
	if err != nil {
		return nil, fmt.Errorf("zfs: zstd: %w", err)
	}
	if len(dst) != dstSize {
		return nil, fmt.Errorf("zfs: zstd: decompressed %d bytes, want %d", len(dst), dstSize)
	}
	return dst, nil
}
