/**
 * @file h3_frame.cc
 * @brief HTTP/3 Frame Implementation
 */

#include "h3/h3_frame.h"
#include "h3/h3_constants.h"
#include "quic/quic_varint.h"
#include "esp_log.h"

#include <cstring>

namespace esp_http3 {
namespace h3 {

using quic::EncodeVarint;
using quic::DecodeVarint;
using quic::VarintEncodedSize;
using quic::BufferWriter;
using quic::BufferReader;

//=============================================================================
// Frame Building
//=============================================================================

size_t BuildSettingsFrame(const std::vector<std::pair<uint64_t, uint64_t>>& settings,
                          uint8_t* out, size_t out_len) {
    // Calculate payload size
    size_t payload_size = 0;
    for (const auto& setting : settings) {
        payload_size += VarintEncodedSize(setting.first);
        payload_size += VarintEncodedSize(setting.second);
    }
    
    BufferWriter writer(out, out_len);
    
    // Frame type
    if (!writer.WriteVarint(static_cast<uint64_t>(H3FrameType::kSettings))) {
        return 0;
    }
    
    // Frame length
    if (!writer.WriteVarint(payload_size)) {
        return 0;
    }
    
    // Settings
    for (const auto& setting : settings) {
        if (!writer.WriteVarint(setting.first)) return 0;
        if (!writer.WriteVarint(setting.second)) return 0;
    }
    
    return writer.Offset();
}

size_t BuildDefaultSettingsFrame(uint8_t* out, size_t out_len) {
    std::vector<std::pair<uint64_t, uint64_t>> default_settings = {
        {settings::kMaxFieldSectionSize, 16384},
        {settings::kQpackMaxTableCapacity, 0},      // No dynamic table
        {settings::kQpackBlockedStreams, 0},        // No blocked streams
    };
    return BuildSettingsFrame(default_settings, out, out_len);
}

size_t BuildHeadersFrame(const std::vector<uint8_t>& encoded_headers,
                         uint8_t* out, size_t out_len) {
    BufferWriter writer(out, out_len);
    
    // Frame type
    if (!writer.WriteVarint(static_cast<uint64_t>(H3FrameType::kHeaders))) {
        return 0;
    }
    
    // Frame length
    if (!writer.WriteVarint(encoded_headers.size())) {
        return 0;
    }
    
    // Header block
    if (!writer.WriteBytes(encoded_headers.data(), encoded_headers.size())) {
        return 0;
    }
    
    return writer.Offset();
}

size_t BuildDataFrame(const uint8_t* data, size_t data_len,
                      uint8_t* out, size_t out_len) {
    BufferWriter writer(out, out_len);
    
    // Frame type
    if (!writer.WriteVarint(static_cast<uint64_t>(H3FrameType::kData))) {
        return 0;
    }
    
    // Frame length
    if (!writer.WriteVarint(data_len)) {
        return 0;
    }
    
    // Data
    if (data_len > 0 && !writer.WriteBytes(data, data_len)) {
        return 0;
    }
    
    return writer.Offset();
}

size_t BuildGoawayFrame(uint64_t stream_id, uint8_t* out, size_t out_len) {
    BufferWriter writer(out, out_len);
    
    // Frame type
    if (!writer.WriteVarint(static_cast<uint64_t>(H3FrameType::kGoaway))) {
        return 0;
    }
    
    // Frame length
    if (!writer.WriteVarint(VarintEncodedSize(stream_id))) {
        return 0;
    }
    
    // Stream ID
    if (!writer.WriteVarint(stream_id)) {
        return 0;
    }
    
    return writer.Offset();
}

//=============================================================================
// Frame Parsing
//=============================================================================

bool ParseH3FrameHeader(const uint8_t* data, size_t len, H3FrameHeader* out) {
    BufferReader reader(data, len);
    
    uint64_t type;
    if (!reader.ReadVarint(&type)) {
        return false;
    }
    out->type = static_cast<H3FrameType>(type);
    
    if (!reader.ReadVarint(&out->length)) {
        return false;
    }
    
    out->header_size = reader.Offset();
    return true;
}

bool ParseSettingsFrame(const uint8_t* data, size_t len, SettingsFrame* out) {
    BufferReader reader(data, len);
    
    while (reader.Remaining() > 0) {
        uint64_t id, value;
        if (!reader.ReadVarint(&id)) return false;
        if (!reader.ReadVarint(&value)) return false;
        
        switch (id) {
            case settings::kMaxFieldSectionSize:
                out->max_field_section_size = value;
                out->has_max_field_section_size = true;
                break;
            case settings::kQpackMaxTableCapacity:
                out->qpack_max_table_capacity = value;
                out->has_qpack_max_table_capacity = true;
                break;
            case settings::kQpackBlockedStreams:
                out->qpack_blocked_streams = value;
                out->has_qpack_blocked_streams = true;
                break;
            default:
                // Unknown settings are ignored
                break;
        }
    }
    
    return true;
}

//=============================================================================
// QPACK Encoding
//=============================================================================

size_t QpackEncodeInteger(uint64_t value, uint8_t prefix_bits,
                          uint8_t* out, size_t out_len) {
    if (out_len == 0) return 0;
    
    uint8_t max_prefix = (1 << prefix_bits) - 1;
    
    if (value < max_prefix) {
        out[0] |= static_cast<uint8_t>(value);
        return 1;
    }
    
    out[0] |= max_prefix;
    value -= max_prefix;
    
    size_t offset = 1;
    while (value >= 128 && offset < out_len) {
        out[offset++] = static_cast<uint8_t>((value & 0x7F) | 0x80);
        value >>= 7;
    }
    
    if (offset < out_len) {
        out[offset++] = static_cast<uint8_t>(value);
    } else {
        return 0;
    }
    
    return offset;
}

size_t QpackEncodeString(const std::string& str, bool huffman,
                         uint8_t* out, size_t out_len) {
    // For simplicity, we don't implement Huffman encoding
    // Just use literal encoding
    (void)huffman;
    
    size_t len = str.size();
    
    // First byte: H bit (0 for literal) + length
    out[0] = 0;  // H=0
    size_t offset = QpackEncodeInteger(len, 7, out, out_len);
    if (offset == 0) return 0;
    
    if (offset + len > out_len) return 0;
    
    std::memcpy(out + offset, str.data(), len);
    return offset + len;
}

// Helper: find static table index for common headers
static int FindStaticIndex(const std::string& name, const std::string& value) {
    // Check for exact matches first
    for (size_t i = 0; i < kQpackStaticTableSize; i++) {
        if (name == kQpackStaticTable[i].name) {
            if (value.empty() || value == kQpackStaticTable[i].value) {
                return static_cast<int>(i);
            }
        }
    }
    return -1;
}

static int FindStaticIndexNameOnly(const std::string& name) {
    for (size_t i = 0; i < kQpackStaticTableSize; i++) {
        if (name == kQpackStaticTable[i].name) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

size_t BuildQpackRequestHeaders(const std::string& method,
                                const std::string& path,
                                const std::string& authority,
                                const std::string& scheme,
                                const std::vector<std::pair<std::string, std::string>>& extra_headers,
                                uint8_t* out, size_t out_len) {
    BufferWriter writer(out, out_len);
    
    // Required Insert Count = 0 (no dynamic table)
    if (!writer.WriteUint8(0)) return 0;
    
    // Delta Base = 0 (sign bit + delta base)
    if (!writer.WriteUint8(0)) return 0;
    
    // Helper to encode a header
    auto encode_header = [&writer](const std::string& name, 
                                   const std::string& value) -> bool {
        // Try to find in static table
        int idx = FindStaticIndex(name, value);
        if (idx >= 0) {
            // Indexed Header Field (static)
            // 11xxxxxx - indexed header field
            uint8_t first = 0xC0;
            if (!writer.WriteUint8(first)) return false;
            
            size_t consumed = QpackEncodeInteger(static_cast<uint64_t>(idx), 6,
                                                  writer.Data() + writer.Offset() - 1,
                                                  writer.Remaining() + 1);
            if (consumed == 0) return false;
            writer.Seek(writer.Offset() + consumed - 1);
            return true;
        }
        
        // Try name-only match
        int name_idx = FindStaticIndexNameOnly(name);
        if (name_idx >= 0) {
            // Literal Header Field With Name Reference (static)
            // 01N1xxxx - literal with name reference
            uint8_t first = 0x50;  // Static, no Huffman on value
            if (!writer.WriteUint8(first)) return false;
            
            size_t consumed = QpackEncodeInteger(static_cast<uint64_t>(name_idx), 4,
                                                  writer.Data() + writer.Offset() - 1,
                                                  writer.Remaining() + 1);
            if (consumed == 0) return false;
            writer.Seek(writer.Offset() + consumed - 1);
            
            // Value
            consumed = QpackEncodeString(value, false,
                                          writer.Data() + writer.Offset(),
                                          writer.Remaining());
            if (consumed == 0) return false;
            writer.Seek(writer.Offset() + consumed);
            return true;
        }
        
        // Literal Header Field Without Name Reference (RFC 9204 Section 4.5.6)
        // Format: 001NHXXX | name (H-encoded) | value (L-encoded)
        // N = 0 (never index = false)
        // H = 0 (no Huffman on name)
        // XXX = 3-bit prefix for name length
        
        uint8_t first = 0x20;  // 001N=0 H=0
        size_t name_len = name.size();
        
        // Encode name length with 3-bit prefix (max 7)
        if (name_len < 7) {
            first |= static_cast<uint8_t>(name_len);
            if (!writer.WriteUint8(first)) return false;
        } else {
            // Multi-byte name length
            first |= 0x07;  // 111 = 7, indicating multi-byte
            if (!writer.WriteUint8(first)) return false;
            
            // Continue encoding remaining length
            size_t remaining = name_len - 7;
            while (remaining >= 128) {
                if (!writer.WriteUint8(static_cast<uint8_t>((remaining & 0x7F) | 0x80))) {
                    return false;
                }
                remaining >>= 7;
            }
            if (!writer.WriteUint8(static_cast<uint8_t>(remaining))) {
                return false;
            }
        }
        
        // Write name bytes directly (no length prefix - already encoded above)
        if (!writer.WriteBytes(reinterpret_cast<const uint8_t*>(name.data()), name_len)) {
            return false;
        }
        
        // Write value string with standard QPACK string encoding (H + 7-bit length + data)
        size_t consumed = QpackEncodeString(value, false,
                                             writer.Data() + writer.Offset(),
                                             writer.Remaining());
        if (consumed == 0) return false;
        writer.Seek(writer.Offset() + consumed);
        return true;
    };
    
    // Encode pseudo-headers
    if (!encode_header(":method", method)) return 0;
    if (!encode_header(":scheme", scheme)) return 0;
    if (!encode_header(":authority", authority)) return 0;
    if (!encode_header(":path", path)) return 0;
    
    // Encode extra headers
    for (const auto& h : extra_headers) {
        if (!encode_header(h.first, h.second)) return 0;
    }
    
    return writer.Offset();
}

//=============================================================================
// QPACK Decoding
//=============================================================================

// HPACK/QPACK Huffman decoder (RFC 7541 Appendix B)
// Optimized: Table sorted by code length for faster early exit
// Format: {code, bits, sym}
static const struct { uint32_t code; uint8_t bits; uint8_t sym; } kHuffmanTable[] = {
    // 5-bit codes (most common - 10 symbols)
    {0x00, 5, 48},  // '0'
    {0x01, 5, 49},  // '1'
    {0x02, 5, 50},  // '2'
    {0x03, 5, 97},  // 'a'
    {0x04, 5, 99},  // 'c'
    {0x05, 5, 101}, // 'e'
    {0x06, 5, 105}, // 'i'
    {0x07, 5, 111}, // 'o'
    {0x08, 5, 115}, // 's'
    {0x09, 5, 116}, // 't'
    // 6-bit codes (22 symbols)
    {0x14, 6, 32},  // ' '
    {0x15, 6, 37},  // '%'
    {0x16, 6, 45},  // '-'
    {0x17, 6, 46},  // '.'
    {0x18, 6, 47},  // '/'
    {0x19, 6, 51},  // '3'
    {0x1a, 6, 52},  // '4'
    {0x1b, 6, 53},  // '5'
    {0x1c, 6, 54},  // '6'
    {0x1d, 6, 55},  // '7'
    {0x1e, 6, 56},  // '8'
    {0x1f, 6, 57},  // '9'
    {0x20, 6, 61},  // '='
    {0x21, 6, 65},  // 'A'
    {0x22, 6, 95},  // '_'
    {0x23, 6, 98},  // 'b'
    {0x24, 6, 100}, // 'd'
    {0x25, 6, 102}, // 'f'
    {0x26, 6, 103}, // 'g'
    {0x27, 6, 104}, // 'h'
    {0x28, 6, 108}, // 'l'
    {0x29, 6, 109}, // 'm'
    {0x2a, 6, 110}, // 'n'
    {0x2b, 6, 112}, // 'p'
    {0x2c, 6, 114}, // 'r'
    {0x2d, 6, 117}, // 'u'
    // 7-bit codes (32 symbols)
    {0x5c, 7, 58},  // ':'
    {0x5d, 7, 66},  // 'B'
    {0x5e, 7, 67},  // 'C'
    {0x5f, 7, 68},  // 'D'
    {0x60, 7, 69},  // 'E'
    {0x61, 7, 70},  // 'F'
    {0x62, 7, 71},  // 'G'
    {0x63, 7, 72},  // 'H'
    {0x64, 7, 73},  // 'I'
    {0x65, 7, 74},  // 'J'
    {0x66, 7, 75},  // 'K'
    {0x67, 7, 76},  // 'L'
    {0x68, 7, 77},  // 'M'
    {0x69, 7, 78},  // 'N'
    {0x6a, 7, 79},  // 'O'
    {0x6b, 7, 80},  // 'P'
    {0x6c, 7, 81},  // 'Q'
    {0x6d, 7, 82},  // 'R'
    {0x6e, 7, 83},  // 'S'
    {0x6f, 7, 84},  // 'T'
    {0x70, 7, 85},  // 'U'
    {0x71, 7, 86},  // 'V'
    {0x72, 7, 87},  // 'W'
    {0x73, 7, 89},  // 'Y'
    {0x74, 7, 106}, // 'j'
    {0x75, 7, 107}, // 'k'
    {0x76, 7, 113}, // 'q'
    {0x77, 7, 118}, // 'v'
    {0x78, 7, 119}, // 'w'
    {0x79, 7, 120}, // 'x'
    {0x7a, 7, 121}, // 'y'
    {0x7b, 7, 122}, // 'z'
    // 8-bit codes (6 symbols)
    {0xf8, 8, 38},  // '&'
    {0xf9, 8, 42},  // '*'
    {0xfa, 8, 44},  // ','
    {0xfb, 8, 59},  // ';'
    {0xfc, 8, 88},  // 'X'
    {0xfd, 8, 90},  // 'Z'
    // 10-bit codes
    {0x3f8, 10, 33},  // '!'
    {0x3f9, 10, 34},  // '"'
    {0x3fa, 10, 40},  // '('
    {0x3fb, 10, 41},  // ')'
    {0x3fc, 10, 63},  // '?'
    // 11-bit codes
    {0x7fa, 11, 39},  // '\''
    {0x7fb, 11, 43},  // '+'
    {0x7fc, 11, 124}, // '|'
    // 12-bit codes
    {0xffa, 12, 35},  // '#'
    {0xffb, 12, 62},  // '>'
    // 13-bit codes
    {0x1ff8, 13, 0},   // NUL
    {0x1ff9, 13, 36},  // '$'
    {0x1ffa, 13, 64},  // '@'
    {0x1ffb, 13, 91},  // '['
    {0x1ffc, 13, 93},  // ']'
    {0x1ffd, 13, 126}, // '~'
    // 14-bit codes
    {0x3ffc, 14, 94},  // '^'
    {0x3ffd, 14, 125}, // '}'
    // 15-bit codes
    {0x7ffc, 15, 60},  // '<'
    {0x7ffd, 15, 96},  // '`'
    {0x7ffe, 15, 123}, // '{'
    // 19-bit codes
    {0x7fff0, 19, 92},  // '\\'
    {0x7fff1, 19, 195},
    {0x7fff2, 19, 208},
    // 20-bit codes
    {0xfffe6, 20, 128}, {0xfffe7, 20, 130}, {0xfffe8, 20, 131}, {0xfffe9, 20, 162},
    {0xfffea, 20, 184}, {0xfffeb, 20, 194}, {0xfffec, 20, 224}, {0xfffed, 20, 226},
    // 21-bit codes
    {0x1fffdc, 21, 153}, {0x1fffdd, 21, 161}, {0x1fffde, 21, 167}, {0x1fffdf, 21, 172},
    {0x1fffe0, 21, 176}, {0x1fffe1, 21, 177}, {0x1fffe2, 21, 179}, {0x1fffe3, 21, 209},
    {0x1fffe4, 21, 216}, {0x1fffe5, 21, 217}, {0x1fffe6, 21, 227}, {0x1fffe7, 21, 229},
    {0x1fffe8, 21, 230},
    // 22-bit codes
    {0x3fffd2, 22, 129}, {0x3fffd3, 22, 132}, {0x3fffd4, 22, 133}, {0x3fffd5, 22, 134},
    {0x3fffd6, 22, 136}, {0x3fffd7, 22, 146}, {0x3fffd8, 22, 154}, {0x3fffd9, 22, 156},
    {0x3fffda, 22, 160}, {0x3fffdb, 22, 163}, {0x3fffdc, 22, 164}, {0x3fffdd, 22, 169},
    {0x3fffde, 22, 170}, {0x3fffdf, 22, 173}, {0x3fffe0, 22, 178}, {0x3fffe1, 22, 181},
    {0x3fffe2, 22, 185}, {0x3fffe3, 22, 186}, {0x3fffe4, 22, 187}, {0x3fffe5, 22, 189},
    {0x3fffe6, 22, 190}, {0x3fffe7, 22, 196}, {0x3fffe8, 22, 198}, {0x3fffe9, 22, 228},
    {0x3fffea, 22, 232}, {0x3fffeb, 22, 233},
    // 23-bit codes
    {0x7fffd8, 23, 1}, {0x7fffd9, 23, 135}, {0x7fffda, 23, 137}, {0x7fffdb, 23, 138},
    {0x7fffdc, 23, 139}, {0x7fffdd, 23, 140}, {0x7fffde, 23, 141}, {0x7fffdf, 23, 143},
    {0x7fffe0, 23, 147}, {0x7fffe1, 23, 149}, {0x7fffe2, 23, 150}, {0x7fffe3, 23, 151},
    {0x7fffe4, 23, 152}, {0x7fffe5, 23, 155}, {0x7fffe6, 23, 157}, {0x7fffe7, 23, 158},
    {0x7fffe8, 23, 165}, {0x7fffe9, 23, 166}, {0x7fffea, 23, 168}, {0x7fffeb, 23, 174},
    {0x7fffec, 23, 175}, {0x7fffed, 23, 180}, {0x7fffee, 23, 182}, {0x7fffef, 23, 183},
    {0x7ffff0, 23, 188}, {0x7ffff1, 23, 191}, {0x7ffff2, 23, 197}, {0x7ffff3, 23, 231},
    {0x7ffff4, 23, 239},
    // 24-bit codes
    {0xffffea, 24, 9}, {0xffffeb, 24, 142}, {0xffffec, 24, 144}, {0xffffed, 24, 145},
    {0xffffee, 24, 148}, {0xffffef, 24, 159}, {0xfffff0, 24, 171}, {0xfffff1, 24, 206},
    {0xfffff2, 24, 215}, {0xfffff3, 24, 225}, {0xfffff4, 24, 236}, {0xfffff5, 24, 237},
    // 25-bit codes
    {0x1ffffec, 25, 199}, {0x1ffffed, 25, 207}, {0x1ffffee, 25, 234}, {0x1ffffef, 25, 235},
    // 26-bit codes
    {0x3ffffe0, 26, 192}, {0x3ffffe1, 26, 193}, {0x3ffffe2, 26, 200}, {0x3ffffe3, 26, 201},
    {0x3ffffe4, 26, 202}, {0x3ffffe5, 26, 205}, {0x3ffffe6, 26, 210}, {0x3ffffe7, 26, 213},
    {0x3ffffe8, 26, 218}, {0x3ffffe9, 26, 219}, {0x3ffffea, 26, 238}, {0x3ffffeb, 26, 240},
    {0x3ffffec, 26, 242}, {0x3ffffed, 26, 243}, {0x3ffffee, 26, 255},
    // 27-bit codes
    {0x7ffffde, 27, 203}, {0x7ffffdf, 27, 204}, {0x7ffffe0, 27, 211}, {0x7ffffe1, 27, 212},
    {0x7ffffe2, 27, 214}, {0x7ffffe3, 27, 221}, {0x7ffffe4, 27, 222}, {0x7ffffe5, 27, 223},
    {0x7ffffe6, 27, 241}, {0x7ffffe7, 27, 244}, {0x7ffffe8, 27, 245}, {0x7ffffe9, 27, 246},
    {0x7ffffea, 27, 247}, {0x7ffffeb, 27, 248}, {0x7ffffec, 27, 250}, {0x7ffffed, 27, 251},
    {0x7ffffee, 27, 252}, {0x7ffffef, 27, 253}, {0x7fffff0, 27, 254},
    // 28-bit codes
    {0x3ffffe2, 28, 2}, {0x3ffffe3, 28, 3}, {0x3ffffe4, 28, 4}, {0x3ffffe5, 28, 5},
    {0x3ffffe6, 28, 6}, {0x3ffffe7, 28, 7}, {0x3ffffe8, 28, 8}, {0x3ffffe9, 28, 11},
    {0x3ffffea, 28, 12}, {0x3ffffeb, 28, 14}, {0x3ffffec, 28, 15}, {0x3ffffed, 28, 16},
    {0x3ffffee, 28, 17}, {0x3ffffef, 28, 18}, {0x3fffff0, 28, 19}, {0x3fffff1, 28, 20},
    {0x3fffff2, 28, 21}, {0x3fffff3, 28, 23}, {0x3fffff4, 28, 24}, {0x3fffff5, 28, 25},
    {0x3fffff6, 28, 26}, {0x3fffff7, 28, 27}, {0x3fffff8, 28, 28}, {0x3fffff9, 28, 29},
    {0x3fffffa, 28, 30}, {0x3fffffb, 28, 31}, {0x3fffffc, 28, 127}, {0xffffffd, 28, 220},
    {0xffffffe, 28, 249},
    // 30-bit codes (EOS and control chars)
    {0x3ffffffc, 30, 10}, {0x3ffffffd, 30, 13}, {0x3ffffffe, 30, 22},
};
static constexpr size_t kHuffmanTableSize = sizeof(kHuffmanTable) / sizeof(kHuffmanTable[0]);

// Index where each bit-length group starts (for faster lookup)
// Allows skipping codes that are too long for current accumulator
static constexpr size_t kBitLengthStart[] = {
    0,    // unused (0-4 bits)
    0,    // 5-bit starts at 0
    10,   // 6-bit starts at 10
    32,   // 7-bit starts at 32
    64,   // 8-bit starts at 64
    70,   // unused (9 bits)
    70,   // 10-bit starts at 70
    75,   // 11-bit starts at 75
    78,   // 12-bit starts at 78
    80,   // 13-bit starts at 80
    86,   // 14-bit starts at 86
    88,   // 15-bit starts at 88
};

// Returns decoded string length, or 0 on error
static size_t HuffmanDecode(const uint8_t* input, size_t input_len, 
                            std::string* output) {
    output->clear();
    output->reserve(input_len * 2);  // Huffman typically expands
    
    uint64_t accumulator = 0;
    uint8_t bits_in_acc = 0;
    
    for (size_t i = 0; i < input_len; i++) {
        accumulator = (accumulator << 8) | input[i];
        bits_in_acc += 8;
        
        // Decode symbols while we have enough bits
        while (bits_in_acc >= 5) {
            bool found = false;
            
            // Search table (sorted by code length for early exit on common chars)
            for (size_t j = 0; j < kHuffmanTableSize; j++) {
                uint8_t code_bits = kHuffmanTable[j].bits;
                if (code_bits > bits_in_acc) continue;
                
                uint32_t mask = (1U << code_bits) - 1;
                uint32_t code = (accumulator >> (bits_in_acc - code_bits)) & mask;
                
                if (code == kHuffmanTable[j].code) {
                    output->push_back(static_cast<char>(kHuffmanTable[j].sym));
                    bits_in_acc -= code_bits;
                    accumulator &= (1ULL << bits_in_acc) - 1;
                    found = true;
                    break;
                }
            }
            
            if (!found) {
                // Need more bits to decode the next symbol.
                // Don't check for EOS padding here - only check after all input
                // is consumed. Some symbols like '~' (0x1ffd, 13 bits) start with
                // many consecutive 1s which could be mistaken for EOS padding.
                break;
            }
        }
    }
    
    // After processing all input, check remaining bits.
    // Valid EOS padding must be all 1s, up to 7 bits (RFC 7541 Section 5.2).
    if (bits_in_acc > 0) {
        if (bits_in_acc > 7) {
            // More than 7 bits remaining means incomplete/corrupted data
            return 0;
        }
        uint32_t padding_mask = (1U << bits_in_acc) - 1;
        if ((accumulator & padding_mask) != padding_mask) {
            // Padding is not all 1s - invalid
            return 0;
        }
    }
    
    return output->size();
}

/**
 * @brief URL decode (percent decode) a string
 * 
 * Decodes percent-encoded characters (e.g., %E7%8E%B0 -> 现)
 * 
 * @param input Input string (may contain %XX encoded bytes)
 * @param output Output decoded string
 * @return true on success, false on invalid encoding
 */
bool UrlDecode(const std::string& input, std::string* output) {
    output->clear();
    output->reserve(input.size());  // Usually same or smaller
    
    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '%' && i + 2 < input.size()) {
            // Try to decode %XX
            char hex1 = input[i + 1];
            char hex2 = input[i + 2];
            
            if ((hex1 >= '0' && hex1 <= '9') || (hex1 >= 'A' && hex1 <= 'F') || (hex1 >= 'a' && hex1 <= 'f')) {
                if ((hex2 >= '0' && hex2 <= '9') || (hex2 >= 'A' && hex2 <= 'F') || (hex2 >= 'a' && hex2 <= 'f')) {
                    // Valid hex digits
                    uint8_t byte = 0;
                    if (hex1 >= '0' && hex1 <= '9') {
                        byte = (hex1 - '0') << 4;
                    } else if (hex1 >= 'A' && hex1 <= 'F') {
                        byte = (hex1 - 'A' + 10) << 4;
                    } else {
                        byte = (hex1 - 'a' + 10) << 4;
                    }
                    
                    if (hex2 >= '0' && hex2 <= '9') {
                        byte |= (hex2 - '0');
                    } else if (hex2 >= 'A' && hex2 <= 'F') {
                        byte |= (hex2 - 'A' + 10);
                    } else {
                        byte |= (hex2 - 'a' + 10);
                    }
                    
                    output->push_back(static_cast<char>(byte));
                    i += 2;  // Skip the two hex digits
                    continue;
                }
            }
            // Invalid % encoding, keep as-is
            output->push_back(input[i]);
        } else {
            output->push_back(input[i]);
        }
    }
    
    return true;
}

size_t QpackDecodeInteger(const uint8_t* data, size_t len,
                          uint8_t prefix_bits, uint64_t* value) {
    if (len == 0) return 0;
    
    uint8_t max_prefix = (1 << prefix_bits) - 1;
    *value = data[0] & max_prefix;
    
    if (*value < max_prefix) {
        return 1;
    }
    
    size_t offset = 1;
    uint64_t m = 0;
    
    while (offset < len) {
        uint8_t b = data[offset++];
        *value += (static_cast<uint64_t>(b & 0x7F) << m);
        m += 7;
        
        if ((b & 0x80) == 0) {
            return offset;
        }
        
        if (m > 62) {
            return 0;  // Overflow
        }
    }
    
    return 0;  // Incomplete
}

size_t QpackDecodeString(const uint8_t* data, size_t len, std::string* str) {
    if (len == 0) return 0;
    
    bool huffman = (data[0] & 0x80) != 0;
    
    uint64_t str_len;
    size_t consumed = QpackDecodeInteger(data, len, 7, &str_len);
    if (consumed == 0) return 0;
    
    if (consumed + str_len > len) return 0;
    
    if (huffman) {
        // Decode Huffman-encoded string
        if (HuffmanDecode(data + consumed, static_cast<size_t>(str_len), str) == 0 
            && str_len > 0) {
            // Huffman decode failed, fall back to raw copy (for debugging)
            str->assign(reinterpret_cast<const char*>(data + consumed), 
                        static_cast<size_t>(str_len));
        }
    } else {
        str->assign(reinterpret_cast<const char*>(data + consumed),
                    static_cast<size_t>(str_len));
    }
    
    return consumed + static_cast<size_t>(str_len);
}

bool GetStaticTableEntry(size_t index, std::string* name, std::string* value) {
    if (index >= kQpackStaticTableSize) {
        return false;
    }
    *name = kQpackStaticTable[index].name;
    *value = kQpackStaticTable[index].value;
    return true;
}

bool DecodeQpackHeaderBlock(const uint8_t* data, size_t len,
                            std::vector<HeaderField>* headers) {
    static const char* TAG = "QPACK";
    
    if (len < 2) {
        ESP_LOGW(TAG, "Header block too short: %zu bytes", len);
        return false;
    }
    
    // Required Insert Count (RFC 9204 Section 4.5.1)
    // RIC indicates how many dynamic table entries are required
    uint64_t ric;
    size_t consumed = QpackDecodeInteger(data, len, 8, &ric);
    if (consumed == 0) {
        ESP_LOGW(TAG, "Failed to decode Required Insert Count");
        return false;
    }
    
    // Delta Base
    size_t offset = consumed;
    if (offset >= len) {
        ESP_LOGW(TAG, "No Delta Base in header block");
        return false;
    }
    
    bool sign = (data[offset] & 0x80) != 0;
    uint64_t delta_base;
    consumed = QpackDecodeInteger(data + offset, len - offset, 7, &delta_base);
    if (consumed == 0) {
        ESP_LOGW(TAG, "Failed to decode Delta Base");
        return false;
    }
    offset += consumed;
    
    // Calculate Base for dynamic table references
    // Base = sign ? (RIC - delta_base - 1) : (RIC + delta_base)
    int64_t base = sign ? (static_cast<int64_t>(ric) - delta_base - 1) 
                        : (static_cast<int64_t>(ric) + delta_base);
    
    // Check if dynamic table is required
    if (ric != 0) {
        ESP_LOGW(TAG, "Server requires QPACK dynamic table (RIC=%llu, Base=%lld)", 
                 (unsigned long long)ric, (long long)base);
        ESP_LOGW(TAG, "Dynamic table not supported - headers cannot be decoded!");
        ESP_LOGW(TAG, "Hint: Server may need SETTINGS with qpack_max_table_capacity=0");
        // TODO: Implement dynamic table support for full compatibility
        return false;
    }
    
    // Parse header fields
    while (offset < len) {
        uint8_t first = data[offset];
        
        if ((first & 0x80) != 0) {
            // Indexed Header Field (RFC 9204 Section 4.5.2)
            // 1Txxxxxx - T=1: static table, T=0: dynamic table
            bool is_static = (first & 0x40) != 0;
            
            uint64_t index;
            consumed = QpackDecodeInteger(data + offset, len - offset, 6, &index);
            if (consumed == 0) {
                ESP_LOGW(TAG, "Failed to decode indexed header index");
                return false;
            }
            offset += consumed;
            
            if (!is_static) {
                ESP_LOGW(TAG, "Dynamic table reference at index %llu (not supported)",
                         (unsigned long long)index);
                return false;
            }
            
            HeaderField field;
            if (!GetStaticTableEntry(static_cast<size_t>(index), 
                                      &field.name, &field.value)) {
                ESP_LOGW(TAG, "Invalid static table index: %llu", (unsigned long long)index);
                return false;
            }
            headers->push_back(std::move(field));
            
        } else if ((first & 0x40) != 0) {
            // Literal Header Field With Name Reference (RFC 9204 Section 4.5.4)
            // 01NTxxxx - N=never index, T=1: static, T=0: dynamic
            bool is_static = (first & 0x10) != 0;
            
            uint64_t index;
            consumed = QpackDecodeInteger(data + offset, len - offset, 4, &index);
            if (consumed == 0) {
                ESP_LOGW(TAG, "Failed to decode literal header name index");
                return false;
            }
            offset += consumed;
            
            std::string name, value;
            if (!is_static) {
                ESP_LOGW(TAG, "Dynamic table name reference at index %llu (not supported)",
                         (unsigned long long)index);
                return false;
            }
            
            if (!GetStaticTableEntry(static_cast<size_t>(index), &name, &value)) {
                ESP_LOGW(TAG, "Invalid static table index for name: %llu", 
                         (unsigned long long)index);
                return false;
            }
            
            // Read value
            consumed = QpackDecodeString(data + offset, len - offset, &value);
            if (consumed == 0) {
                ESP_LOGW(TAG, "Failed to decode header value");
                return false;
            }
            offset += consumed;
            
            headers->push_back({std::move(name), std::move(value)});
            
        } else if ((first & 0x20) != 0) {
            // Literal Header Field Without Name Reference (RFC 9204 Section 4.5.6)
            // 001NHxxx - N: never index, H: Huffman for name, xxx: 3-bit name length prefix
            std::string name, value;
            
            // Extract Huffman flag for name from bit 3 of first byte
            bool name_huffman = (first & 0x08) != 0;
            
            // Decode name length using 3-bit prefix (consumes first byte)
            uint64_t name_len;
            consumed = QpackDecodeInteger(data + offset, len - offset, 3, &name_len);
            if (consumed == 0) {
                ESP_LOGW(TAG, "Failed to decode literal header name length");
                return false;
            }
            offset += consumed;
            
            // Read name bytes
            if (offset + name_len > len) {
                ESP_LOGW(TAG, "Header name truncated: need %llu, have %zu",
                         (unsigned long long)name_len, len - offset);
                return false;
            }
            
            if (name_huffman) {
                // Huffman decode name
                if (HuffmanDecode(data + offset, static_cast<size_t>(name_len), &name) == 0 
                    && name_len > 0) {
                    // Fallback to raw if Huffman decode fails
                    name.assign(reinterpret_cast<const char*>(data + offset), 
                                static_cast<size_t>(name_len));
                }
            } else {
                name.assign(reinterpret_cast<const char*>(data + offset),
                            static_cast<size_t>(name_len));
            }
            offset += static_cast<size_t>(name_len);
            
            // Read value using standard QPACK string format (H + 7-bit length prefix)
            consumed = QpackDecodeString(data + offset, len - offset, &value);
            if (consumed == 0) {
                ESP_LOGW(TAG, "Failed to decode literal header value");
                return false;
            }
            offset += consumed;
            
            headers->push_back({std::move(name), std::move(value)});
            
        } else if ((first & 0x10) != 0) {
            // Indexed Header Field With Post-Base Index (RFC 9204 Section 4.5.3)
            // 0001xxxx - references dynamic table entry inserted after Base
            uint64_t index;
            consumed = QpackDecodeInteger(data + offset, len - offset, 4, &index);
            if (consumed == 0) return false;
            offset += consumed;
            
            ESP_LOGW(TAG, "Post-base dynamic table reference at index %llu (not supported)",
                     (unsigned long long)index);
            return false;
            
        } else {
            // Literal Header Field With Post-Base Name Reference (RFC 9204 Section 4.5.5)
            // 0000Nxxx - N=never index, references dynamic table name
            ESP_LOGW(TAG, "Post-base literal name reference (not supported), byte=0x%02x", first);
            return false;
        }
    }
    
    return true;
}

} // namespace h3
} // namespace esp_http3

