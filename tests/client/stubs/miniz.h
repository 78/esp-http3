#pragma once
// Host substitute only for the ESP ROM tinfl/CRC boundary. Production gzip
// framing, ring consumption, bounds and trailer validation compile unchanged.
// zlib owns its host dictionary; ESP tinfl uses the provided wrapping history.
#include <cstddef>
#include <cstdint>
#include <zlib.h>
#define HTTP3_HOST_TINFL_TEST_ADAPTER 1
// ROM miniz 1.15 may consume trailer bytes into its low-endian bit buffer.
// The deferred mode models those bytes being consumed by a previous call,
// while output is drained before the inflater reports DONE.
inline bool host_tinfl_legacy_lookahead = false;
inline bool host_tinfl_legacy_defer_done = false;
inline size_t host_tinfl_prefetched_bytes = 0;
inline size_t host_tinfl_deferred_completions = 0;
enum {
    TINFL_FLAG_PARSE_ZLIB_HEADER = 1,
    TINFL_FLAG_HAS_MORE_INPUT = 2,
    TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF = 4,
    TINFL_FLAG_COMPUTE_ADLER32 = 8
};
enum tinfl_status { TINFL_STATUS_BAD_PARAM=-3, TINFL_STATUS_FAILED=-1,
    TINFL_STATUS_DONE=0, TINFL_STATUS_NEEDS_MORE_INPUT=1, TINFL_STATUS_HAS_MORE_OUTPUT=2 };
struct tinfl_decompressor {
    int m_state = 0;
    uint32_t m_num_bits = 0;
    uint32_t m_bit_buf = 0;
    z_stream stream{};
    ~tinfl_decompressor() { if (m_state == 1) inflateEnd(&stream); }
};
inline void tinfl_init(tinfl_decompressor* r) {
    if (r->m_state == 1) inflateEnd(&r->stream);
    r->m_state = 0;
    r->m_num_bits = r->m_bit_buf = 0;
    r->stream = z_stream{};
}
inline tinfl_status tinfl_decompress(tinfl_decompressor* r, const uint8_t* input, size_t* input_size,
                                    uint8_t*, uint8_t* output, size_t* output_size, uint32_t flags) {
    if (r->m_state == 2) {
        r->m_state = 0;
        *input_size = *output_size = 0;
        ++host_tinfl_deferred_completions;
        return TINFL_STATUS_DONE;
    }
    if (!r->m_state) {
        if (inflateInit2(&r->stream, flags & TINFL_FLAG_PARSE_ZLIB_HEADER ? MAX_WBITS : -MAX_WBITS) != Z_OK)
            return TINFL_STATUS_FAILED;
        r->m_state = 1;
    }
    r->stream.next_in = const_cast<Bytef*>(input);
    r->stream.avail_in = static_cast<uInt>(*input_size);
    r->stream.next_out = output;
    r->stream.avail_out = static_cast<uInt>(*output_size);
    const int result = inflate(&r->stream, Z_NO_FLUSH);
    *input_size -= r->stream.avail_in;
    *output_size -= r->stream.avail_out;
    if (result == Z_STREAM_END) {
        size_t prefetched = 0;
        if (host_tinfl_legacy_lookahead) {
            prefetched = r->stream.avail_in < 2 ? r->stream.avail_in : 2;
            // Three end-of-block padding bits remain below the complete bytes.
            // Their value is intentionally nonzero to catch missing alignment.
            r->m_num_bits = 3 + 8 * prefetched;
            r->m_bit_buf = 5;
            for (size_t i = 0; i < prefetched; ++i)
                r->m_bit_buf |= uint32_t(r->stream.next_in[i]) << (3 + 8 * i);
            *input_size += prefetched;
            host_tinfl_prefetched_bytes += prefetched;
        }
        inflateEnd(&r->stream);
        if (host_tinfl_legacy_defer_done && prefetched && *output_size) {
            r->m_state = 2;
            return TINFL_STATUS_HAS_MORE_OUTPUT;
        }
        r->m_state=0;
        return TINFL_STATUS_DONE;
    }
    if (result != Z_OK && result != Z_BUF_ERROR) return TINFL_STATUS_FAILED;
    if (!r->stream.avail_out) return TINFL_STATUS_HAS_MORE_OUTPUT;
    return (flags & TINFL_FLAG_HAS_MORE_INPUT) ? TINFL_STATUS_NEEDS_MORE_INPUT : TINFL_STATUS_FAILED;
}
inline unsigned long mz_crc32(unsigned long crc, const unsigned char* bytes, size_t size) {
    return crc32(crc, bytes, static_cast<uInt>(size));
}
