/**
 * @file quic_aead.h
 * @brief QUIC AEAD Encryption/Decryption (RFC 9001)
 * 
 * Implements AES-128-GCM AEAD and header protection using mbedtls.
 */

#pragma once

#include "quic/quic_types.h"
#include <cstdint>
#include <cstddef>

namespace esp_http3 {
namespace quic {

//=============================================================================
// AEAD Encryption/Decryption
//=============================================================================

/**
 * @brief Encrypt payload using AES-128-GCM
 * 
 * @param key AEAD key (16 bytes)
 * @param iv AEAD IV (12 bytes)
 * @param packet_number Packet number
 * @param aad Additional authenticated data (QUIC header)
 * @param aad_len AAD length
 * @param plaintext Plaintext to encrypt
 * @param plaintext_len Plaintext length
 * @param ciphertext_out Output buffer (must be plaintext_len + 16)
 * @return Size of ciphertext including tag, or 0 on failure
 */
size_t AeadEncrypt(const uint8_t* key, const uint8_t* iv,
                   uint64_t packet_number,
                   const uint8_t* aad, size_t aad_len,
                   const uint8_t* plaintext, size_t plaintext_len,
                   uint8_t* ciphertext_out);

/**
 * @brief Decrypt ciphertext using AES-128-GCM
 * 
 * @param key AEAD key (16 bytes)
 * @param iv AEAD IV (12 bytes)
 * @param packet_number Packet number
 * @param aad Additional authenticated data (QUIC header)
 * @param aad_len AAD length
 * @param ciphertext Ciphertext with auth tag
 * @param ciphertext_len Ciphertext length (including 16-byte tag)
 * @param plaintext_out Output buffer (must be at least ciphertext_len - 16)
 * @return Size of plaintext, or 0 on failure
 */
size_t AeadDecrypt(const uint8_t* key, const uint8_t* iv,
                   uint64_t packet_number,
                   const uint8_t* aad, size_t aad_len,
                   const uint8_t* ciphertext, size_t ciphertext_len,
                   uint8_t* plaintext_out);

//=============================================================================
// Header Protection
//=============================================================================

/**
 * @brief Apply or remove header protection
 * 
 * Header protection is XOR-based and is its own inverse.
 * 
 * @param hp_key Header protection key (16 bytes)
 * @param sample Sample from ciphertext (16 bytes)
 * @param first_byte First byte of header (will be modified in-place)
 * @param pn_bytes Packet number bytes (will be modified in-place)
 * @param pn_len Length of packet number (1-4)
 * @return true on success
 */
bool ApplyHeaderProtection(const uint8_t* hp_key,
                           const uint8_t* sample,
                           uint8_t* first_byte,
                           uint8_t* pn_bytes,
                           size_t pn_len);

/**
 * @brief Remove header protection and return packet number length
 * 
 * @param hp_key Header protection key (16 bytes)
 * @param packet Pointer to start of packet
 * @param packet_len Total packet length
 * @param pn_offset Offset of packet number in packet
 * @param is_long_header True if long header packet
 * @param pn_len_out Output: packet number length (1-4)
 * @return true on success
 */
bool RemoveHeaderProtection(const uint8_t* hp_key,
                            uint8_t* packet,
                            size_t packet_len,
                            size_t pn_offset,
                            bool is_long_header,
                            size_t* pn_len_out);

//=============================================================================
// Retry Integrity Tag
//=============================================================================

/**
 * @brief Compute Retry packet integrity tag
 * 
 * @param odcid Original Destination Connection ID
 * @param odcid_len ODCID length
 * @param retry_packet Retry packet (without integrity tag)
 * @param retry_len Retry packet length
 * @param tag_out Output tag (16 bytes)
 * @return true on success
 */
bool ComputeRetryIntegrityTag(const uint8_t* odcid, size_t odcid_len,
                               const uint8_t* retry_packet, size_t retry_len,
                               uint8_t* tag_out);

/**
 * @brief Verify Retry packet integrity tag
 * 
 * @param odcid Original Destination Connection ID
 * @param odcid_len ODCID length
 * @param retry_packet Full Retry packet (including tag)
 * @param retry_len Full Retry packet length
 * @return true if tag is valid
 */
bool VerifyRetryIntegrityTag(const uint8_t* odcid, size_t odcid_len,
                              const uint8_t* retry_packet, size_t retry_len);

//=============================================================================
// Nonce Generation
//=============================================================================

/**
 * @brief Generate AEAD nonce from IV and packet number
 * 
 * @param iv Base IV (12 bytes)
 * @param packet_number Packet number
 * @param nonce_out Output nonce (12 bytes)
 */
void GenerateNonce(const uint8_t* iv, uint64_t packet_number, uint8_t* nonce_out);

} // namespace quic
} // namespace esp_http3

