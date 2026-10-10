#include "client/gzip_decoder.h"
#include "esp_http3_memory.h"
#include "miniz.h"
#include "esp_log.h"
#include <algorithm>
#include <cstring>
#include <new>

namespace esp_http3 {
namespace {
constexpr size_t kHistorySize = 32768;
constexpr size_t kMaxHeaderSize = 65536 + 1024;
constexpr size_t kMaxMembers = 128;
uint32_t Crc(uint32_t crc, const uint8_t* bytes, size_t size) {
    return static_cast<uint32_t>(mz_crc32(crc, bytes, size));
}
uint32_t Little32(const uint8_t* bytes) {
    return uint32_t(bytes[0]) | (uint32_t(bytes[1]) << 8) |
           (uint32_t(bytes[2]) << 16) | (uint32_t(bytes[3]) << 24);
}
}  // namespace

struct GzipDecoder::State {
    enum class Phase { kHeader, kExtraLength, kExtra, kName, kComment, kHeaderCrc,
                       kDeflate, kTrailer, kBetweenMembers, kDone, kError };
    Phase phase = Phase::kHeader;
    tinfl_decompressor inflater{};
    uint8_t history[kHistorySize];
    uint8_t fixed[10]{};
    uint8_t trailer[8]{};
    size_t field_size = 0;
    size_t header_size = 0;
    uint32_t header_crc = 0;
    uint8_t flags = 0;
    size_t extra_remaining = 0;
    size_t history_offset = 0;
    size_t pending_offset = 0;
    size_t pending_size = 0;
    size_t total_decoded = 0;
    size_t limit = 0;
    size_t members = 0;
    uint32_t member_decoded = 0;
    uint32_t member_crc = 0;
    const char* error = "";

    void Fail(const char* message) {
        ESP_LOGW("GzipDecoder", "%s (phase=%u field=%zu decoded=%zu)",
            message, static_cast<unsigned>(phase), field_size, total_decoded);
        error = message; phase = Phase::kError;
    }
    void NextField() {
        field_size = 0;
        if (flags & 4) { flags &= ~4; phase = Phase::kExtraLength; }
        else if (flags & 8) { flags &= ~8; phase = Phase::kName; }
        else if (flags & 16) { flags &= ~16; phase = Phase::kComment; }
        else if (flags & 2) { flags &= ~2; phase = Phase::kHeaderCrc; }
        else { phase = Phase::kDeflate; tinfl_init(&inflater); }
    }
    void StartMember() {
        phase = Phase::kHeader;
        field_size = header_size = 0;
        header_crc = member_crc = member_decoded = 0;
        flags = 0;
        history_offset = 0;
    }
};

GzipDecoder::GzipDecoder(size_t decoded_body_limit) {
    void* workspace = memory::Allocate(sizeof(State), alignof(State));
    if (workspace) {
        state_ = new (workspace) State;
        state_->limit = decoded_body_limit;
    }
}
GzipDecoder::~GzipDecoder() {
    if (state_) {
        state_->~State();
        memory::Deallocate(state_);
    }
}
GzipDecoder* GzipDecoder::Create(size_t decoded_body_limit) {
    void* storage = memory::Allocate(sizeof(GzipDecoder), alignof(GzipDecoder));
    if (!storage) return nullptr;
    auto* decoder = new (storage) GzipDecoder(decoded_body_limit);
    if (!decoder->state_) { Destroy(decoder); return nullptr; }
    return decoder;
}
void GzipDecoder::Destroy(GzipDecoder* decoder) {
    if (!decoder) return;
    decoder->~GzipDecoder();
    memory::Deallocate(decoder);
}
const char* GzipDecoder::GetError() const { return state_->error; }
size_t GzipDecoder::DecodedBytes() const { return state_->total_decoded; }

GzipDecoder::Result GzipDecoder::Decode(const uint8_t* input, size_t input_size, bool input_finished,
                                      size_t& consumed, uint8_t* output, size_t output_size, size_t& written) {
    consumed = written = 0;
    State& s = *state_;
    if (s.phase == State::Phase::kError) return Result::kError;
    if (!output || !output_size || (!input && input_size)) {
        s.Fail("Invalid gzip decode buffer"); return Result::kError;
    }
    for (;;) {
        if (s.pending_size) {
            written = std::min(output_size, s.pending_size);
            memcpy(output, s.history + s.pending_offset, written);
            s.pending_offset += written;
            s.pending_size -= written;
            return Result::kData;
        }
        if (s.phase == State::Phase::kDone) return Result::kFinished;
        if (s.phase == State::Phase::kError) return Result::kError;
        if (s.phase == State::Phase::kBetweenMembers) {
            if (consumed == input_size) {
                if (!input_finished) return Result::kPending;
                s.phase = State::Phase::kDone;
                return Result::kFinished;
            }
            s.StartMember();
        }
        if (s.phase == State::Phase::kDeflate) {
            // Even without new input tinfl can still hold a pending match. The
            // complete wrapping history size must remain visible to the ROM API.
            static const uint8_t empty = 0;
            size_t in_size = input_size - consumed;
            size_t out_size = kHistorySize - s.history_offset;
            const auto status = tinfl_decompress(&s.inflater,
                in_size ? input + consumed : &empty, &in_size, s.history,
                s.history + s.history_offset, &out_size,
                input_finished ? 0 : TINFL_FLAG_HAS_MORE_INPUT);
            consumed += in_size;
            if (out_size > s.limit - s.total_decoded) {
                s.Fail("Decoded gzip body exceeds limit"); return Result::kError;
            }
            if (out_size) {
                s.member_crc = Crc(s.member_crc, s.history + s.history_offset, out_size);
                s.member_decoded += static_cast<uint32_t>(out_size);
                s.total_decoded += out_size;
                s.pending_offset = s.history_offset;
                s.pending_size = out_size;
                s.history_offset = (s.history_offset + out_size) % kHistorySize;
            }
            if (status < 0) { s.Fail("Invalid gzip deflate body"); return Result::kError; }
            if (status == TINFL_STATUS_DONE) {
                s.phase = State::Phase::kTrailer; s.field_size = 0;
                // ESP ROM miniz 1.15 can prefetch gzip trailer bytes into its
                // bit buffer, unlike newer tinfl versions which put them back.
                // The bytes are already included in consumed (possibly by an
                // earlier call), so recover the byte-aligned prefix instead of
                // rewinding receive/QUIC flow control or counting it twice.
                const size_t buffered_bytes = s.inflater.m_num_bits / 8;
                if (buffered_bytes >= sizeof(s.trailer)) {
                    s.Fail("Invalid gzip trailer lookahead"); return Result::kError;
                }
                auto prefetched = s.inflater.m_bit_buf >> (s.inflater.m_num_bits & 7);
                for (size_t i = 0; i < buffered_bytes; ++i) {
                    s.trailer[s.field_size++] = static_cast<uint8_t>(prefetched & 0xff);
                    prefetched >>= 8;
                }
            } else if (!out_size && !in_size) {
                if (input_finished) { s.Fail("Truncated gzip deflate body"); return Result::kError; }
                return Result::kPending;
            }
            if (s.pending_size) continue;
            if (status != TINFL_STATUS_DONE && consumed == input_size) {
                if (input_finished) { s.Fail("Truncated gzip deflate body"); return Result::kError; }
                return Result::kPending;
            }
            continue;
        }
        if (consumed == input_size) {
            if (input_finished) { s.Fail("Truncated gzip header or trailer"); return Result::kError; }
            return Result::kPending;
        }
        const uint8_t byte = input[consumed++];
        if (s.phase != State::Phase::kTrailer) {
            if (++s.header_size > kMaxHeaderSize) {
                s.Fail("Gzip header exceeds limit"); return Result::kError;
            }
            if (s.phase != State::Phase::kHeaderCrc) s.header_crc = Crc(s.header_crc, &byte, 1);
        }
        switch (s.phase) {
        case State::Phase::kHeader:
            s.fixed[s.field_size++] = byte;
            if (s.field_size == 10) {
                if (s.fixed[0] != 0x1f || s.fixed[1] != 0x8b || s.fixed[2] != 8 || (s.fixed[3] & 0xe0)) {
                    s.Fail("Invalid gzip header"); break;
                }
                if (++s.members > kMaxMembers) { s.Fail("Too many gzip members"); break; }
                s.flags = s.fixed[3]; s.NextField();
            }
            break;
        case State::Phase::kExtraLength:
            s.fixed[s.field_size++] = byte;
            if (s.field_size == 2) {
                s.extra_remaining = size_t(s.fixed[0]) | (size_t(s.fixed[1]) << 8);
                if (s.extra_remaining) s.phase = State::Phase::kExtra;
                else s.NextField();
            }
            break;
        case State::Phase::kExtra:
            if (!--s.extra_remaining) s.NextField();
            break;
        case State::Phase::kName:
        case State::Phase::kComment:
            if (!byte) s.NextField();
            break;
        case State::Phase::kHeaderCrc:
            s.fixed[s.field_size++] = byte;
            if (s.field_size == 2) {
                const auto expected = uint16_t(s.fixed[0]) | (uint16_t(s.fixed[1]) << 8);
                if ((s.header_crc & 0xffff) != expected) s.Fail("Gzip header CRC mismatch");
                else s.NextField();
            }
            break;
        case State::Phase::kTrailer:
            s.trailer[s.field_size++] = byte;
            if (s.field_size == 8) {
                if (Little32(s.trailer) != s.member_crc) s.Fail("Gzip body CRC mismatch");
                else if (Little32(s.trailer + 4) != s.member_decoded) s.Fail("Gzip body size mismatch");
                else s.phase = State::Phase::kBetweenMembers;
            }
            break;
        default: break;
        }
    }
}
}  // namespace esp_http3
