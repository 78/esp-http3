/**
 * @file quic_packet.h
 * @brief QUIC Packet Building and Parsing (RFC 9000)
 */

#pragma once

#include "quic/quic_types.h"
#include "quic/quic_constants.h"
#include <cstdint>
#include <cstddef>
#include <vector>

namespace esp_http3 {
namespace quic {

//=============================================================================
// Packet Header Structures
//=============================================================================

/**
 * @brief QUIC Long Header
 */
struct LongHeader {
    uint8_t header_byte = 0;
    uint32_t version = 0;
    ConnectionId dcid;
    ConnectionId scid;
    
    // Derived
    PacketType type() const {
        return static_cast<PacketType>((header_byte >> 4) & 0x03);
    }
    
    bool IsInitial() const { return type() == PacketType::kInitial; }
    bool IsHandshake() const { return type() == PacketType::kHandshake; }
    bool Is0RTT() const { return type() == PacketType::k0Rtt; }
    bool IsRetry() const { return type() == PacketType::kRetry; }
};

/**
 * @brief QUIC Short Header
 */
struct ShortHeader {
    uint8_t header_byte = 0;
    ConnectionId dcid;
    
    bool spin_bit() const { return (header_byte & 0x20) != 0; }
    bool key_phase() const { return (header_byte & 0x04) != 0; }
};

/**
 * @brief Parsed packet info
 */
struct PacketInfo {
    bool is_long_header = false;
    LongHeader long_header;
    ShortHeader short_header;
    
    uint64_t packet_number = 0;
    size_t pn_length = 0;
    size_t header_length = 0;
    size_t payload_offset = 0;
    size_t payload_length = 0;
    
    // Total bytes consumed by this packet (for coalesced packet handling)
    size_t packet_size = 0;
    
    // For Initial packets
    std::vector<uint8_t> token;
};

//=============================================================================
// Packet Building
//=============================================================================

/**
 * @brief Build Initial packet
 * 
 * @param dcid Destination Connection ID
 * @param scid Source Connection ID
 * @param token Token (from Retry, may be empty)
 * @param packet_number Packet number
 * @param payload Frames payload (unencrypted)
 * @param payload_len Payload length
 * @param client_secrets Client Initial secrets
 * @param out Output buffer
 * @param out_len Output buffer size
 * @param min_packet_size Minimum packet size (for padding)
 * @return Size of packet written, or 0 on failure
 */
size_t BuildInitialPacket(const ConnectionId& dcid,
                          const ConnectionId& scid,
                          const uint8_t* token, size_t token_len,
                          uint64_t packet_number,
                          const uint8_t* payload, size_t payload_len,
                          const CryptoSecrets& client_secrets,
                          uint8_t* out, size_t out_len,
                          size_t min_packet_size = 1200);

/**
 * @brief Build Handshake packet
 * 
 * @param dcid Destination Connection ID
 * @param scid Source Connection ID
 * @param packet_number Packet number
 * @param payload Frames payload (unencrypted)
 * @param payload_len Payload length
 * @param client_secrets Client Handshake secrets
 * @param out Output buffer
 * @param out_len Output buffer size
 * @return Size of packet written, or 0 on failure
 */
size_t BuildHandshakePacket(const ConnectionId& dcid,
                            const ConnectionId& scid,
                            uint64_t packet_number,
                            const uint8_t* payload, size_t payload_len,
                            const CryptoSecrets& client_secrets,
                            uint8_t* out, size_t out_len);

/**
 * @brief Build 1-RTT (Short Header) packet
 * 
 * @param dcid Destination Connection ID
 * @param packet_number Packet number
 * @param spin_bit Spin bit value
 * @param key_phase Key phase bit
 * @param payload Frames payload (unencrypted)
 * @param payload_len Payload length
 * @param app_secrets Application secrets
 * @param out Output buffer
 * @param out_len Output buffer size
 * @return Size of packet written, or 0 on failure
 */
size_t Build1RttPacket(const ConnectionId& dcid,
                       uint64_t packet_number,
                       bool spin_bit,
                       bool key_phase,
                       const uint8_t* payload, size_t payload_len,
                       const CryptoSecrets& app_secrets,
                       uint8_t* out, size_t out_len);

//=============================================================================
// Packet Parsing
//=============================================================================

/**
 * @brief Parse packet header (without decryption)
 * 
 * @param data Raw packet data
 * @param len Packet length
 * @param expected_dcid_len Expected DCID length (for short headers)
 * @param info Output packet info
 * @return true on success
 */
bool ParsePacketHeader(const uint8_t* data, size_t len,
                       size_t expected_dcid_len,
                       PacketInfo* info);

/**
 * @brief Decrypt Initial packet
 * 
 * @param packet Raw packet
 * @param packet_len Packet length
 * @param server_secrets Server Initial secrets
 * @param largest_pn Largest received packet number (-1 if none)
 * @param info Output packet info
 * @param payload_out Output decrypted payload
 * @param payload_out_len Output payload buffer size
 * @return Decrypted payload size, or 0 on failure
 */
size_t DecryptInitialPacket(uint8_t* packet, size_t packet_len,
                            const CryptoSecrets& server_secrets,
                            int64_t largest_pn,
                            PacketInfo* info,
                            uint8_t* payload_out, size_t payload_out_len);

/**
 * @brief Decrypt Handshake packet
 * 
 * @param packet Raw packet
 * @param packet_len Packet length
 * @param server_secrets Server Handshake secrets
 * @param largest_pn Largest received packet number (-1 if none)
 * @param info Output packet info
 * @param payload_out Output decrypted payload
 * @param payload_out_len Output payload buffer size
 * @return Decrypted payload size, or 0 on failure
 */
size_t DecryptHandshakePacket(uint8_t* packet, size_t packet_len,
                              const CryptoSecrets& server_secrets,
                              int64_t largest_pn,
                              PacketInfo* info,
                              uint8_t* payload_out, size_t payload_out_len);

/**
 * @brief Decrypt 1-RTT (Short Header) packet
 * 
 * @param packet Raw packet
 * @param packet_len Packet length
 * @param dcid_len DCID length
 * @param server_secrets Server Application secrets
 * @param largest_pn Largest received packet number (-1 if none)
 * @param info Output packet info
 * @param payload_out Output decrypted payload
 * @param payload_out_len Output payload buffer size
 * @return Decrypted payload size, or 0 on failure
 */
size_t Decrypt1RttPacket(uint8_t* packet, size_t packet_len,
                         size_t dcid_len,
                         const CryptoSecrets& server_secrets,
                         int64_t largest_pn,
                         PacketInfo* info,
                         uint8_t* payload_out, size_t payload_out_len);

/**
 * @brief Parse Retry packet
 * 
 * @param packet Raw packet
 * @param packet_len Packet length
 * @param original_dcid Original DCID (for integrity validation)
 * @param info Output packet info
 * @param new_scid Output: new SCID (to use as new DCID)
 * @param retry_token Output: retry token
 * @return true if valid Retry packet
 */
bool ParseRetryPacket(const uint8_t* packet, size_t packet_len,
                      const ConnectionId& original_dcid,
                      PacketInfo* info,
                      ConnectionId* new_scid,
                      std::vector<uint8_t>* retry_token);

//=============================================================================
// Utility Functions
//=============================================================================

/**
 * @brief Check if packet is a long header packet
 * 
 * @param first_byte First byte of packet
 * @return true if long header
 */
inline bool IsLongHeader(uint8_t first_byte) {
    return (first_byte & 0x80) != 0;
}

/**
 * @brief Get packet type from long header first byte
 * 
 * @param first_byte First byte of packet
 * @return Packet type
 */
inline PacketType GetLongHeaderType(uint8_t first_byte) {
    return static_cast<PacketType>((first_byte >> 4) & 0x03);
}

/**
 * @brief Calculate packet number length from packet number value
 * 
 * @param pn Packet number
 * @return Length needed (1-4)
 */
size_t GetPacketNumberLength(uint64_t pn);

/**
 * @brief Encode packet number to minimum bytes
 * 
 * @param pn Packet number
 * @param out Output buffer
 * @return Bytes written (1-4)
 */
size_t EncodePacketNumber(uint64_t pn, uint8_t* out);

} // namespace quic
} // namespace esp_http3

