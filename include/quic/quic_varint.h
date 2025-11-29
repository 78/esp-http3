/**
 * @file quic_varint.h
 * @brief QUIC Variable-Length Integer Encoding (RFC 9000 Section 16)
 */

#pragma once

#include <cstdint>
#include <cstddef>

namespace esp_http3 {
namespace quic {

/**
 * @brief Encode a variable-length integer
 * 
 * QUIC uses a variable-length encoding with 1, 2, 4, or 8 bytes.
 * The two most significant bits indicate the length.
 * 
 * @param value Value to encode (0 to 2^62-1)
 * @param out Output buffer (must be at least 8 bytes)
 * @param out_len Output buffer length
 * @return Number of bytes written, or 0 if buffer too small
 */
size_t EncodeVarint(uint64_t value, uint8_t* out, size_t out_len);

/**
 * @brief Decode a variable-length integer
 * 
 * @param data Input data
 * @param len Input data length
 * @param out_value Output value
 * @return Number of bytes consumed, or 0 if insufficient data
 */
size_t DecodeVarint(const uint8_t* data, size_t len, uint64_t* out_value);

/**
 * @brief Get the encoded size of a variable-length integer
 * 
 * @param value Value to encode
 * @return Number of bytes needed (1, 2, 4, or 8)
 */
size_t VarintEncodedSize(uint64_t value);

/**
 * @brief Decode a truncated packet number
 * 
 * Reconstructs the full packet number from a truncated value.
 * Uses RFC 9000 Appendix A.3 algorithm.
 * 
 * @param largest_pn Largest packet number received so far (-1 if none)
 * @param truncated_pn Truncated packet number from wire
 * @param pn_nbits Number of bits in truncated_pn (8, 16, 24, or 32)
 * @return Full reconstructed packet number
 */
uint64_t DecodePacketNumber(int64_t largest_pn, uint64_t truncated_pn, uint8_t pn_nbits);

} // namespace quic
} // namespace esp_http3

