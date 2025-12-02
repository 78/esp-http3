/**
 * @file h3_frame.h
 * @brief HTTP/3 Frame Building and Parsing (RFC 9114)
 */

#pragma once

#include "quic/quic_types.h"
#include "h3/h3_constants.h"
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace esp_http3 {
namespace h3 {

//=============================================================================
// Frame Building
//=============================================================================

/**
 * @brief Build SETTINGS frame
 * 
 * @param settings Settings to encode
 * @param out Output buffer
 * @param out_len Output buffer size
 * @return Bytes written, or 0 on failure
 */
size_t BuildSettingsFrame(const std::vector<std::pair<uint64_t, uint64_t>>& settings,
                          uint8_t* out, size_t out_len);

/**
 * @brief Build default client SETTINGS frame
 */
size_t BuildDefaultSettingsFrame(uint8_t* out, size_t out_len);

/**
 * @brief Build HEADERS frame with QPACK-encoded headers
 * 
 * @param encoded_headers QPACK-encoded header block
 * @param out Output buffer
 * @param out_len Output buffer size
 * @return Bytes written, or 0 on failure
 */
size_t BuildHeadersFrame(const std::vector<uint8_t>& encoded_headers,
                         uint8_t* out, size_t out_len);

/**
 * @brief Build DATA frame
 * 
 * @param data Data payload
 * @param data_len Data length
 * @param out Output buffer
 * @param out_len Output buffer size
 * @return Bytes written, or 0 on failure
 */
size_t BuildDataFrame(const uint8_t* data, size_t data_len,
                      uint8_t* out, size_t out_len);

/**
 * @brief Build GOAWAY frame
 * 
 * @param stream_id Stream ID
 * @param out Output buffer
 * @param out_len Output buffer size
 * @return Bytes written, or 0 on failure
 */
size_t BuildGoawayFrame(uint64_t stream_id, uint8_t* out, size_t out_len);

//=============================================================================
// Frame Parsing
//=============================================================================

/**
 * @brief HTTP/3 frame types
 */
enum class H3FrameType : uint64_t {
    kData = 0x00,
    kHeaders = 0x01,
    kCancelPush = 0x03,
    kSettings = 0x04,
    kPushPromise = 0x05,
    kGoaway = 0x07,
    kMaxPushId = 0x0d,
};

/**
 * @brief Parsed H3 frame header
 */
struct H3FrameHeader {
    H3FrameType type;
    uint64_t length;
    size_t header_size;  // Bytes consumed for type + length
};

/**
 * @brief Parse H3 frame header
 * 
 * @param data Input data
 * @param len Data length
 * @param out Output header
 * @return true on success
 */
bool ParseH3FrameHeader(const uint8_t* data, size_t len, H3FrameHeader* out);

/**
 * @brief Parsed SETTINGS frame
 */
struct SettingsFrame {
    uint64_t max_field_section_size = 0;
    uint64_t qpack_max_table_capacity = 0;
    uint64_t qpack_blocked_streams = 0;
    bool has_max_field_section_size = false;
    bool has_qpack_max_table_capacity = false;
    bool has_qpack_blocked_streams = false;
};

/**
 * @brief Parse SETTINGS frame payload
 * 
 * @param data Frame payload (after header)
 * @param len Payload length
 * @param out Output settings
 * @return true on success
 */
bool ParseSettingsFrame(const uint8_t* data, size_t len, SettingsFrame* out);

//=============================================================================
// QPACK Encoding (Static Table Only)
//=============================================================================

/**
 * @brief QPACK encode integer
 * 
 * @param value Value to encode
 * @param prefix_bits Number of prefix bits (5, 6, or 8)
 * @param out Output buffer
 * @param out_len Output buffer size
 * @return Bytes written
 */
size_t QpackEncodeInteger(uint64_t value, uint8_t prefix_bits,
                          uint8_t* out, size_t out_len);

/**
 * @brief QPACK encode string (literal)
 * 
 * @param str String to encode
 * @param huffman Use Huffman encoding
 * @param out Output buffer
 * @param out_len Output buffer size
 * @return Bytes written
 */
size_t QpackEncodeString(const std::string& str, bool huffman,
                         uint8_t* out, size_t out_len);

/**
 * @brief Build QPACK-encoded request headers
 * 
 * Uses static table only (no dynamic table).
 * 
 * @param method HTTP method (GET, POST, etc.)
 * @param path Request path
 * @param authority Host authority
 * @param scheme Scheme (https)
 * @param extra_headers Additional headers
 * @param out Output buffer
 * @param out_len Output buffer size
 * @return Bytes written, or 0 on failure
 */
size_t BuildQpackRequestHeaders(const std::string& method,
                                const std::string& path,
                                const std::string& authority,
                                const std::string& scheme,
                                const std::vector<std::pair<std::string, std::string>>& extra_headers,
                                uint8_t* out, size_t out_len);

//=============================================================================
// QPACK Decoding (Static Table Only)
//=============================================================================

/**
 * @brief QPACK decode integer
 * 
 * @param data Input data
 * @param len Data length
 * @param prefix_bits Number of prefix bits
 * @param value Output value
 * @return Bytes consumed, or 0 on failure
 */
size_t QpackDecodeInteger(const uint8_t* data, size_t len, 
                          uint8_t prefix_bits, uint64_t* value);

/**
 * @brief QPACK decode string
 * 
 * @param data Input data
 * @param len Data length
 * @param str Output string
 * @return Bytes consumed, or 0 on failure
 */
size_t QpackDecodeString(const uint8_t* data, size_t len, std::string* str);

/**
 * @brief Parsed header field
 */
struct HeaderField {
    std::string name;
    std::string value;
};

/**
 * @brief Decode QPACK header block
 * 
 * @param data Header block data
 * @param len Data length
 * @param headers Output headers
 * @return true on success
 */
bool DecodeQpackHeaderBlock(const uint8_t* data, size_t len,
                            std::vector<HeaderField>* headers);

/**
 * @brief URL decode (percent decode) a string
 * 
 * Decodes percent-encoded characters (e.g., %E7%8E%B0 -> 现)
 * 
 * @param input Input string (may contain %XX encoded bytes)
 * @param output Output decoded string
 * @return true on success, false on invalid encoding
 */
bool UrlDecode(const std::string& input, std::string* output);

/**
 * @brief Get static table entry by index
 * 
 * @param index Static table index
 * @param name Output name
 * @param value Output value
 * @return true if found
 */
bool GetStaticTableEntry(size_t index, std::string* name, std::string* value);

} // namespace h3
} // namespace esp_http3

