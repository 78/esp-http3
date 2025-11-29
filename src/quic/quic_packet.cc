/**
 * @file quic_packet.cc
 * @brief QUIC Packet Building and Parsing Implementation
 */

#include "quic/quic_packet.h"
#include "quic/quic_varint.h"
#include "quic/quic_aead.h"
#include "quic/quic_frame.h"

#include <cstring>
#include <esp_log.h>

namespace esp_http3 {
namespace quic {

static const char* TAG = "QUIC_PKT";

//=============================================================================
// Utility Functions
//=============================================================================

size_t GetPacketNumberLength(uint64_t pn) {
    if (pn <= 0xFF) return 1;
    if (pn <= 0xFFFF) return 2;
    if (pn <= 0xFFFFFF) return 3;
    return 4;
}

size_t EncodePacketNumber(uint64_t pn, uint8_t* out) {
    size_t len = GetPacketNumberLength(pn);
    for (size_t i = 0; i < len; i++) {
        out[len - 1 - i] = static_cast<uint8_t>(pn & 0xFF);
        pn >>= 8;
    }
    return len;
}

//=============================================================================
// Packet Building - Helper
//=============================================================================

static size_t BuildLongHeader(PacketType type,
                              const ConnectionId& dcid,
                              const ConnectionId& scid,
                              uint8_t* out) {
    size_t offset = 0;
    
    // First byte: 1 | 1 | TT | Reserved | PN Len (will be set later)
    // For now, use 2-byte PN length (0x01)
    out[offset++] = 0xC0 | (static_cast<uint8_t>(type) << 4) | 0x01;
    
    // Version
    out[offset++] = (kQuicVersion1 >> 24) & 0xFF;
    out[offset++] = (kQuicVersion1 >> 16) & 0xFF;
    out[offset++] = (kQuicVersion1 >> 8) & 0xFF;
    out[offset++] = kQuicVersion1 & 0xFF;
    
    // DCID length + DCID
    out[offset++] = static_cast<uint8_t>(dcid.Length());
    std::memcpy(out + offset, dcid.Data(), dcid.Length());
    offset += dcid.Length();
    
    // SCID length + SCID
    out[offset++] = static_cast<uint8_t>(scid.Length());
    std::memcpy(out + offset, scid.Data(), scid.Length());
    offset += scid.Length();
    
    return offset;
}

//=============================================================================
// Packet Building
//=============================================================================

size_t BuildInitialPacket(const ConnectionId& dcid,
                          const ConnectionId& scid,
                          const uint8_t* token, size_t token_len,
                          uint64_t packet_number,
                          const uint8_t* payload, size_t payload_len,
                          const CryptoSecrets& client_secrets,
                          uint8_t* out, size_t out_len,
                          size_t min_packet_size) {
    if (!client_secrets.valid) {
        return 0;
    }
    
    // Calculate sizes
    size_t pn_len = GetPacketNumberLength(packet_number);
    
    // Build header (without length and PN)
    uint8_t header[256];
    size_t header_offset = 0;
    
    // First byte (will update PN length later)
    header[header_offset++] = 0xC0 | 0x00 | (pn_len - 1);  // Initial type = 0
    
    // Version
    header[header_offset++] = (kQuicVersion1 >> 24) & 0xFF;
    header[header_offset++] = (kQuicVersion1 >> 16) & 0xFF;
    header[header_offset++] = (kQuicVersion1 >> 8) & 0xFF;
    header[header_offset++] = kQuicVersion1 & 0xFF;
    
    // DCID
    header[header_offset++] = static_cast<uint8_t>(dcid.Length());
    std::memcpy(header + header_offset, dcid.Data(), dcid.Length());
    header_offset += dcid.Length();
    
    // SCID
    header[header_offset++] = static_cast<uint8_t>(scid.Length());
    std::memcpy(header + header_offset, scid.Data(), scid.Length());
    header_offset += scid.Length();
    
    // Token length + token
    header_offset += EncodeVarint(token_len, header + header_offset, 
                                   sizeof(header) - header_offset);
    if (token_len > 0) {
        std::memcpy(header + header_offset, token, token_len);
        header_offset += token_len;
    }
    
    // Calculate payload + padding + auth tag
    size_t encrypted_payload_len = payload_len + 16;  // +16 for auth tag
    
    // Calculate total packet size
    size_t length_field_size = VarintEncodedSize(pn_len + encrypted_payload_len);
    size_t total_header_len = header_offset + length_field_size + pn_len;
    size_t total_packet_len = total_header_len + encrypted_payload_len;
    
    // Add padding if needed
    size_t padding_len = 0;
    if (total_packet_len < min_packet_size) {
        padding_len = min_packet_size - total_packet_len;
    }
    
    // Recalculate with padding
    encrypted_payload_len = payload_len + padding_len + 16;
    length_field_size = VarintEncodedSize(pn_len + encrypted_payload_len);
    total_header_len = header_offset + length_field_size + pn_len;
    total_packet_len = total_header_len + encrypted_payload_len;
    
    if (total_packet_len > out_len) {
        return 0;
    }
    
    // Build final packet
    size_t offset = 0;
    std::memcpy(out, header, header_offset);
    offset = header_offset;
    
    // Length field
    offset += EncodeVarint(pn_len + encrypted_payload_len, out + offset, out_len - offset);
    
    // Remember PN offset for header protection
    size_t pn_offset = offset;
    
    // Packet number
    offset += EncodePacketNumber(packet_number, out + offset);
    
    // Prepare plaintext (payload + padding)
    std::vector<uint8_t> plaintext(payload_len + padding_len);
    std::memcpy(plaintext.data(), payload, payload_len);
    std::memset(plaintext.data() + payload_len, 0, padding_len);  // PADDING frames
    
    // Encrypt
    size_t header_len = offset;
    size_t encrypted_len = AeadEncrypt(client_secrets.key.data(),
                                        client_secrets.iv.data(),
                                        packet_number,
                                        out, header_len,
                                        plaintext.data(), plaintext.size(),
                                        out + offset);
    if (encrypted_len == 0) {
        return 0;
    }
    offset += encrypted_len;
    
    // Apply header protection
    const uint8_t* sample = out + pn_offset + 4;  // Sample starts 4 bytes after PN
    if (!ApplyHeaderProtection(client_secrets.hp.data(),
                                sample,
                                out,
                                out + pn_offset,
                                pn_len)) {
        return 0;
    }
    
    return offset;
}

size_t BuildHandshakePacket(const ConnectionId& dcid,
                            const ConnectionId& scid,
                            uint64_t packet_number,
                            const uint8_t* payload, size_t payload_len,
                            const CryptoSecrets& client_secrets,
                            uint8_t* out, size_t out_len) {
    if (!client_secrets.valid) {
        return 0;
    }
    
    size_t pn_len = GetPacketNumberLength(packet_number);
    
    // Build header
    uint8_t header[256];
    size_t header_offset = 0;
    
    // First byte: Handshake type = 2
    header[header_offset++] = 0xC0 | (0x02 << 4) | (pn_len - 1);
    
    // Version
    header[header_offset++] = (kQuicVersion1 >> 24) & 0xFF;
    header[header_offset++] = (kQuicVersion1 >> 16) & 0xFF;
    header[header_offset++] = (kQuicVersion1 >> 8) & 0xFF;
    header[header_offset++] = kQuicVersion1 & 0xFF;
    
    // DCID
    header[header_offset++] = static_cast<uint8_t>(dcid.Length());
    std::memcpy(header + header_offset, dcid.Data(), dcid.Length());
    header_offset += dcid.Length();
    
    // SCID
    header[header_offset++] = static_cast<uint8_t>(scid.Length());
    std::memcpy(header + header_offset, scid.Data(), scid.Length());
    header_offset += scid.Length();
    
    // Calculate encrypted payload length
    size_t encrypted_payload_len = payload_len + 16;
    
    // Length field
    size_t length_val = pn_len + encrypted_payload_len;
    header_offset += EncodeVarint(length_val, header + header_offset,
                                   sizeof(header) - header_offset);
    
    // Copy header to output
    std::memcpy(out, header, header_offset);
    size_t offset = header_offset;
    
    // PN offset
    size_t pn_offset = offset;
    
    // Packet number
    offset += EncodePacketNumber(packet_number, out + offset);
    
    // Encrypt
    size_t header_len = offset;
    size_t encrypted_len = AeadEncrypt(client_secrets.key.data(),
                                        client_secrets.iv.data(),
                                        packet_number,
                                        out, header_len,
                                        payload, payload_len,
                                        out + offset);
    if (encrypted_len == 0) {
        return 0;
    }
    offset += encrypted_len;
    
    // Apply header protection
    const uint8_t* sample = out + pn_offset + 4;
    if (!ApplyHeaderProtection(client_secrets.hp.data(),
                                sample,
                                out,
                                out + pn_offset,
                                pn_len)) {
        return 0;
    }
    
    return offset;
}

size_t Build1RttPacket(const ConnectionId& dcid,
                       uint64_t packet_number,
                       bool spin_bit,
                       bool key_phase,
                       const uint8_t* payload, size_t payload_len,
                       const CryptoSecrets& app_secrets,
                       uint8_t* out, size_t out_len) {
    if (!app_secrets.valid) {
        return 0;
    }
    
    size_t pn_len = GetPacketNumberLength(packet_number);
    
    // First byte: 0 | 1 | S | Reserved | K | PN Len
    uint8_t first_byte = 0x40 | (pn_len - 1);
    if (spin_bit) first_byte |= 0x20;
    if (key_phase) first_byte |= 0x04;
    
    // Build header
    size_t offset = 0;
    out[offset++] = first_byte;
    
    // DCID (no length field for short header)
    std::memcpy(out + offset, dcid.Data(), dcid.Length());
    offset += dcid.Length();
    
    // PN offset
    size_t pn_offset = offset;
    
    // Packet number
    offset += EncodePacketNumber(packet_number, out + offset);
    
    // Check buffer size
    size_t header_len = offset;
    if (header_len + payload_len + 16 > out_len) {
        return 0;
    }
    
    // Encrypt
    size_t encrypted_len = AeadEncrypt(app_secrets.key.data(),
                                        app_secrets.iv.data(),
                                        packet_number,
                                        out, header_len,
                                        payload, payload_len,
                                        out + offset);
    if (encrypted_len == 0) {
        return 0;
    }
    offset += encrypted_len;
    
    // Apply header protection
    const uint8_t* sample = out + pn_offset + 4;
    if (!ApplyHeaderProtection(app_secrets.hp.data(),
                                sample,
                                out,
                                out + pn_offset,
                                pn_len)) {
        return 0;
    }
    
    return offset;
}

//=============================================================================
// Packet Parsing
//=============================================================================

bool ParsePacketHeader(const uint8_t* data, size_t len,
                       size_t expected_dcid_len,
                       PacketInfo* info) {
    if (len < 1) {
        return false;
    }
    
    uint8_t first_byte = data[0];
    info->is_long_header = IsLongHeader(first_byte);
    
    if (info->is_long_header) {
        // Long header
        if (len < 7) {
            return false;
        }
        
        info->long_header.header_byte = first_byte;
        info->long_header.version = 
            (static_cast<uint32_t>(data[1]) << 24) |
            (static_cast<uint32_t>(data[2]) << 16) |
            (static_cast<uint32_t>(data[3]) << 8) |
            static_cast<uint32_t>(data[4]);
        
        size_t offset = 5;
        
        // DCID
        uint8_t dcid_len = data[offset++];
        if (offset + dcid_len > len) return false;
        info->long_header.dcid.Set(data + offset, dcid_len);
        offset += dcid_len;
        
        // SCID
        if (offset >= len) return false;
        uint8_t scid_len = data[offset++];
        if (offset + scid_len > len) return false;
        info->long_header.scid.Set(data + offset, scid_len);
        offset += scid_len;
        
        info->header_length = offset;
        
        // For Initial packets, parse token but don't include in header_length
        // (token is handled separately in DecryptInitialPacket)
        if (info->long_header.IsInitial()) {
            BufferReader reader(data + offset, len - offset);
            uint64_t token_len;
            if (!reader.ReadVarint(&token_len)) return false;
            if (reader.Remaining() < token_len) return false;
            
            if (token_len > 0) {
                info->token.assign(reader.Current(), 
                                   reader.Current() + token_len);
            }
            // Note: header_length stays at offset (after SCID)
            // Token and Length fields are parsed in DecryptInitialPacket
        }
        
    } else {
        // Short header
        info->short_header.header_byte = first_byte;
        
        if (len < 1 + expected_dcid_len) {
            return false;
        }
        
        info->short_header.dcid.Set(data + 1, expected_dcid_len);
        info->header_length = 1 + expected_dcid_len;
    }
    
    return true;
}

size_t DecryptInitialPacket(uint8_t* packet, size_t packet_len,
                            const CryptoSecrets& server_secrets,
                            int64_t largest_pn,
                            PacketInfo* info,
                            uint8_t* payload_out, size_t payload_out_len) {
    if (!server_secrets.valid) {
        ESP_LOGW(TAG, "DecryptInitial: secrets not valid");
        return 0;
    }
    if (packet_len < 20) {
        ESP_LOGW(TAG, "DecryptInitial: packet too short (%zu)", packet_len);
        return 0;
    }
    
    // Parse header first
    if (!ParsePacketHeader(packet, packet_len, 0, info)) {
        ESP_LOGW(TAG, "DecryptInitial: ParsePacketHeader failed");
        return 0;
    }
    
    if (!info->is_long_header || !info->long_header.IsInitial()) {
        ESP_LOGW(TAG, "DecryptInitial: not Initial packet");
        return 0;
    }
    
    // Find packet number offset
    BufferReader reader(packet + info->header_length, 
                        packet_len - info->header_length);
    
    // Token length + token
    uint64_t token_len;
    if (!reader.ReadVarint(&token_len)) {
        ESP_LOGW(TAG, "DecryptInitial: failed to read token_len");
        return 0;
    }
    if (!reader.Skip(token_len)) {
        ESP_LOGW(TAG, "DecryptInitial: failed to skip token");
        return 0;
    }
    
    // Length
    uint64_t length;
    if (!reader.ReadVarint(&length)) {
        ESP_LOGW(TAG, "DecryptInitial: failed to read length");
        return 0;
    }
    
    size_t pn_offset = info->header_length + 
                       (packet_len - info->header_length - reader.Remaining());
    
    // Remove header protection
    size_t pn_len;
    if (!RemoveHeaderProtection(server_secrets.hp.data(),
                                 packet, packet_len,
                                 pn_offset,
                                 true,  // long header
                                 &pn_len)) {
        ESP_LOGW(TAG, "DecryptInitial: RemoveHeaderProtection failed");
        return 0;
    }
    
    // Read packet number
    uint64_t truncated_pn = 0;
    for (size_t i = 0; i < pn_len; i++) {
        truncated_pn = (truncated_pn << 8) | packet[pn_offset + i];
    }
    
    // Reconstruct full packet number
    info->packet_number = DecodePacketNumber(largest_pn, truncated_pn, pn_len * 8);
    info->pn_length = pn_len;
    info->payload_offset = pn_offset + pn_len;
    info->payload_length = length - pn_len - 16;  // -16 for auth tag
    
    // Decrypt using length field (NOT packet_len - handles coalesced packets)
    size_t header_len = pn_offset + pn_len;
    size_t ciphertext_len = length - pn_len;  // length field includes pn_len + ciphertext
    
    // Calculate total packet size (for coalesced packet handling)
    info->packet_size = pn_offset + length;
    
    // Validate ciphertext length
    if (ciphertext_len < 16) {
        ESP_LOGW(TAG, "DecryptInitial: ciphertext too short (%zu)", ciphertext_len);
        return 0;
    }
    
    if (ciphertext_len > payload_out_len + 16) {
        ESP_LOGW(TAG, "DecryptInitial: ciphertext too large (%zu > %zu)",
                 ciphertext_len, payload_out_len + 16);
        return 0;
    }
    
    // Validate that the packet fits in the UDP datagram
    if (header_len + ciphertext_len > packet_len) {
        ESP_LOGW(TAG, "DecryptInitial: packet extends beyond datagram (%zu + %zu > %zu)",
                 header_len, ciphertext_len, packet_len);
        return 0;
    }
    
    size_t decrypted_len = AeadDecrypt(server_secrets.key.data(),
                                        server_secrets.iv.data(),
                                        info->packet_number,
                                        packet, header_len,
                                        packet + header_len, ciphertext_len,
                                        payload_out);
    
    if (decrypted_len == 0) {
        ESP_LOGW(TAG, "DecryptInitial: AeadDecrypt failed (auth tag mismatch?)");
    }
    
    return decrypted_len;
}

size_t DecryptHandshakePacket(uint8_t* packet, size_t packet_len,
                              const CryptoSecrets& server_secrets,
                              int64_t largest_pn,
                              PacketInfo* info,
                              uint8_t* payload_out, size_t payload_out_len) {
    if (!server_secrets.valid || packet_len < 20) {
        ESP_LOGW(TAG, "DecryptHandshake: secrets invalid or packet too short");
        return 0;
    }
    
    // Parse header
    if (!ParsePacketHeader(packet, packet_len, 0, info)) {
        ESP_LOGW(TAG, "DecryptHandshake: ParsePacketHeader failed");
        return 0;
    }
    
    if (!info->is_long_header || !info->long_header.IsHandshake()) {
        ESP_LOGW(TAG, "DecryptHandshake: not a Handshake packet (first_byte=0x%02x)", 
                 packet[0]);
        return 0;
    }
    
    // Find packet number offset (after DCID + SCID)
    BufferReader reader(packet + info->header_length,
                        packet_len - info->header_length);
    
    // Length
    uint64_t length;
    if (!reader.ReadVarint(&length)) {
        ESP_LOGW(TAG, "DecryptHandshake: failed to read length");
        return 0;
    }
    
    size_t pn_offset = info->header_length + 
                       (packet_len - info->header_length - reader.Remaining());
    
    // Remove header protection
    size_t pn_len;
    if (!RemoveHeaderProtection(server_secrets.hp.data(),
                                 packet, packet_len,
                                 pn_offset,
                                 true,
                                 &pn_len)) {
        ESP_LOGW(TAG, "DecryptHandshake: RemoveHeaderProtection failed");
        return 0;
    }
    
    // Read packet number
    uint64_t truncated_pn = 0;
    for (size_t i = 0; i < pn_len; i++) {
        truncated_pn = (truncated_pn << 8) | packet[pn_offset + i];
    }
    
    info->packet_number = DecodePacketNumber(largest_pn, truncated_pn, pn_len * 8);
    info->pn_length = pn_len;
    info->payload_offset = pn_offset + pn_len;
    info->payload_length = length - pn_len - 16;
    
    // Decrypt using length field (NOT packet_len - handles coalesced packets)
    size_t header_len = pn_offset + pn_len;
    size_t ciphertext_len = length - pn_len;  // length field includes pn_len + ciphertext
    
    // Calculate total packet size (for coalesced packet handling)
    info->packet_size = pn_offset + length;
    
    // Validate ciphertext length
    if (ciphertext_len < 16) {
        ESP_LOGW(TAG, "DecryptHandshake: ciphertext too short (%zu)", ciphertext_len);
        return 0;
    }
    
    // Check output buffer size (ciphertext = plaintext + 16 byte auth tag)
    if (ciphertext_len > payload_out_len + 16) {
        ESP_LOGW(TAG, "DecryptHandshake: ciphertext too large (%zu > %zu)",
                 ciphertext_len, payload_out_len + 16);
        return 0;
    }
    
    // Validate that the packet fits in the UDP datagram
    if (header_len + ciphertext_len > packet_len) {
        ESP_LOGW(TAG, "DecryptHandshake: packet extends beyond datagram (%zu + %zu > %zu)",
                 header_len, ciphertext_len, packet_len);
        return 0;
    }
    
    size_t decrypted_len = AeadDecrypt(server_secrets.key.data(),
                                        server_secrets.iv.data(),
                                        info->packet_number,
                                        packet, header_len,
                                        packet + header_len, ciphertext_len,
                                        payload_out);
    
    if (decrypted_len == 0) {
        ESP_LOGW(TAG, "DecryptHandshake: AeadDecrypt failed (auth tag mismatch?)");
    }
    
    return decrypted_len;
}

size_t Decrypt1RttPacket(uint8_t* packet, size_t packet_len,
                         size_t dcid_len,
                         const CryptoSecrets& server_secrets,
                         int64_t largest_pn,
                         PacketInfo* info,
                         uint8_t* payload_out, size_t payload_out_len) {
    if (!server_secrets.valid || packet_len < 20) {
        return 0;
    }
    
    info->is_long_header = false;
    info->short_header.header_byte = packet[0];
    info->short_header.dcid.Set(packet + 1, dcid_len);
    
    size_t pn_offset = 1 + dcid_len;
    
    // Remove header protection
    size_t pn_len;
    if (!RemoveHeaderProtection(server_secrets.hp.data(),
                                 packet, packet_len,
                                 pn_offset,
                                 false,  // short header
                                 &pn_len)) {
        return 0;
    }
    
    // Read packet number
    uint64_t truncated_pn = 0;
    for (size_t i = 0; i < pn_len; i++) {
        truncated_pn = (truncated_pn << 8) | packet[pn_offset + i];
    }
    
    info->packet_number = DecodePacketNumber(largest_pn, truncated_pn, pn_len * 8);
    info->pn_length = pn_len;
    info->header_length = pn_offset + pn_len;
    
    // Decrypt
    size_t header_len = info->header_length;
    size_t ciphertext_len = packet_len - header_len;
    
    // Check output buffer size (ciphertext = plaintext + 16 byte auth tag)
    if (ciphertext_len > payload_out_len + 16) {
        return 0;
    }
    
    size_t decrypted_len = AeadDecrypt(server_secrets.key.data(),
                                        server_secrets.iv.data(),
                                        info->packet_number,
                                        packet, header_len,
                                        packet + header_len, ciphertext_len,
                                        payload_out);
    
    info->payload_length = decrypted_len;
    return decrypted_len;
}

bool ParseRetryPacket(const uint8_t* packet, size_t packet_len,
                      const ConnectionId& original_dcid,
                      PacketInfo* info,
                      ConnectionId* new_scid,
                      std::vector<uint8_t>* retry_token) {
    // Minimum: 1 + 4 + 1 + 0 + 1 + 0 + 16 = 23 bytes
    if (packet_len < 23) {
        return false;
    }
    
    // Verify integrity tag
    if (!VerifyRetryIntegrityTag(original_dcid.Data(), original_dcid.Length(),
                                  packet, packet_len)) {
        return false;
    }
    
    // Parse header
    if (!ParsePacketHeader(packet, packet_len, 0, info)) {
        return false;
    }
    
    if (!info->is_long_header || !info->long_header.IsRetry()) {
        return false;
    }
    
    *new_scid = info->long_header.scid;
    
    // Token is everything between header and integrity tag
    size_t token_start = info->header_length;
    size_t token_end = packet_len - 16;
    
    if (token_end > token_start) {
        retry_token->assign(packet + token_start, packet + token_end);
    } else {
        retry_token->clear();
    }
    
    return true;
}

} // namespace quic
} // namespace esp_http3

