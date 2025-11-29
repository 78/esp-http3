/**
 * @file quic_varint.cc
 * @brief QUIC Variable-Length Integer Encoding (RFC 9000 Section 16)
 */

#include "quic/quic_varint.h"

namespace esp_http3 {
namespace quic {

size_t EncodeVarint(uint64_t value, uint8_t* out, size_t out_len) {
    if (value <= 63) {
        // 1 byte: 00xxxxxx
        if (out_len < 1) return 0;
        out[0] = static_cast<uint8_t>(value);
        return 1;
    } else if (value <= 16383) {
        // 2 bytes: 01xxxxxx xxxxxxxx
        if (out_len < 2) return 0;
        out[0] = static_cast<uint8_t>((value >> 8) | 0x40);
        out[1] = static_cast<uint8_t>(value & 0xFF);
        return 2;
    } else if (value <= 1073741823) {
        // 4 bytes: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        if (out_len < 4) return 0;
        out[0] = static_cast<uint8_t>((value >> 24) | 0x80);
        out[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        out[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        out[3] = static_cast<uint8_t>(value & 0xFF);
        return 4;
    } else {
        // 8 bytes: 11xxxxxx xxxxxxxx ... xxxxxxxx
        if (out_len < 8) return 0;
        out[0] = static_cast<uint8_t>((value >> 56) | 0xC0);
        out[1] = static_cast<uint8_t>((value >> 48) & 0xFF);
        out[2] = static_cast<uint8_t>((value >> 40) & 0xFF);
        out[3] = static_cast<uint8_t>((value >> 32) & 0xFF);
        out[4] = static_cast<uint8_t>((value >> 24) & 0xFF);
        out[5] = static_cast<uint8_t>((value >> 16) & 0xFF);
        out[6] = static_cast<uint8_t>((value >> 8) & 0xFF);
        out[7] = static_cast<uint8_t>(value & 0xFF);
        return 8;
    }
}

size_t DecodeVarint(const uint8_t* data, size_t len, uint64_t* out_value) {
    if (len == 0 || data == nullptr || out_value == nullptr) {
        return 0;
    }

    uint8_t first_byte = data[0];
    uint8_t prefix = first_byte >> 6;

    if (prefix == 0) {
        // 1 byte
        *out_value = first_byte & 0x3F;
        return 1;
    } else if (prefix == 1) {
        // 2 bytes
        if (len < 2) return 0;
        *out_value = (static_cast<uint64_t>(first_byte & 0x3F) << 8) |
                     static_cast<uint64_t>(data[1]);
        return 2;
    } else if (prefix == 2) {
        // 4 bytes
        if (len < 4) return 0;
        *out_value = (static_cast<uint64_t>(first_byte & 0x3F) << 24) |
                     (static_cast<uint64_t>(data[1]) << 16) |
                     (static_cast<uint64_t>(data[2]) << 8) |
                     static_cast<uint64_t>(data[3]);
        return 4;
    } else {
        // 8 bytes
        if (len < 8) return 0;
        *out_value = (static_cast<uint64_t>(first_byte & 0x3F) << 56) |
                     (static_cast<uint64_t>(data[1]) << 48) |
                     (static_cast<uint64_t>(data[2]) << 40) |
                     (static_cast<uint64_t>(data[3]) << 32) |
                     (static_cast<uint64_t>(data[4]) << 24) |
                     (static_cast<uint64_t>(data[5]) << 16) |
                     (static_cast<uint64_t>(data[6]) << 8) |
                     static_cast<uint64_t>(data[7]);
        return 8;
    }
}

size_t VarintEncodedSize(uint64_t value) {
    if (value <= 63) {
        return 1;
    } else if (value <= 16383) {
        return 2;
    } else if (value <= 1073741823) {
        return 4;
    } else {
        return 8;
    }
}

uint64_t DecodePacketNumber(int64_t largest_pn, uint64_t truncated_pn, uint8_t pn_nbits) {
    // RFC 9000 Appendix A.3: Sample Packet Number Decoding Algorithm
    
    // If no packets received yet, the truncated PN is the full PN
    if (largest_pn < 0) {
        return truncated_pn;
    }

    uint64_t expected_pn = static_cast<uint64_t>(largest_pn) + 1;
    uint64_t pn_win = 1ULL << pn_nbits;
    uint64_t pn_hwin = pn_win >> 1;
    uint64_t pn_mask = pn_win - 1;

    // Calculate candidate packet number
    uint64_t candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

    // Adjust if candidate is outside the expected window
    if (candidate_pn + pn_hwin <= expected_pn && 
        candidate_pn < (1ULL << 62) - pn_win) {
        return candidate_pn + pn_win;
    }
    if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win) {
        return candidate_pn - pn_win;
    }
    return candidate_pn;
}

} // namespace quic
} // namespace esp_http3

