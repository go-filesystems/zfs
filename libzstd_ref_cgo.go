//go:build libzstd

package filesystem_zfs

// libzstd, the C library OpenZFS embeds, as the reference for the zstd record
// decode benchmarks (zstd_libzstd_test.go). Built only with -tags libzstd:
//
//	CGO_CFLAGS=-I/opt/homebrew/include CGO_LDFLAGS='-L/opt/homebrew/lib -lzstd' \
//	  go test -tags libzstd -run xxx -bench ZstdRecord -benchtime 3s -cpu 1 .

/*
#define ZSTD_STATIC_LINKING_ONLY
#include <stdlib.h>
#include <zstd.h>

static size_t ref_compress(void *dst, size_t dcap, const void *src, size_t n, int level) {
	ZSTD_CCtx *c = ZSTD_createCCtx();
	ZSTD_CCtx_setParameter(c, ZSTD_c_format, ZSTD_f_zstd1_magicless);
	ZSTD_CCtx_setParameter(c, ZSTD_c_compressionLevel, level);
	ZSTD_CCtx_setParameter(c, ZSTD_c_contentSizeFlag, 1);
	ZSTD_CCtx_setPledgedSrcSize(c, n);
	ZSTD_CCtx_setParameter(c, ZSTD_c_checksumFlag, 0);
	size_t r = ZSTD_compress2(c, dst, dcap, src, n);
	ZSTD_freeCCtx(c);
	return r;
}

static ZSTD_DCtx *ref_dctx(void) {
	ZSTD_DCtx *d = ZSTD_createDCtx();
	ZSTD_DCtx_setParameter(d, ZSTD_d_format, ZSTD_f_zstd1_magicless);
	return d;
}

static size_t ref_decompress(ZSTD_DCtx *d, void *dst, size_t dcap, const void *src, size_t n) {
	return ZSTD_decompressDCtx(d, dst, dcap, src, n);
}
*/
import "C"

import "unsafe"

// refCompress compresses src as one magicless zstd frame at level.
func refCompress(src []byte, level int) []byte {
	dst := make([]byte, C.ZSTD_compressBound(C.size_t(len(src))))
	n := C.ref_compress(unsafe.Pointer(&dst[0]), C.size_t(len(dst)), unsafe.Pointer(&src[0]), C.size_t(len(src)), C.int(level))
	if C.ZSTD_isError(n) != 0 {
		panic("libzstd: compress")
	}
	return dst[:n]
}

type refDecoder struct{ d *C.ZSTD_DCtx }

func newRefDecoder() refDecoder { return refDecoder{C.ref_dctx()} }

// decode decodes a magicless frame into dst and returns the byte count (-1 on error).
func (r refDecoder) decode(dst, frame []byte) int {
	n := C.ref_decompress(r.d, unsafe.Pointer(&dst[0]), C.size_t(len(dst)), unsafe.Pointer(&frame[0]), C.size_t(len(frame)))
	if C.ZSTD_isError(n) != 0 {
		return -1
	}
	return int(n)
}
