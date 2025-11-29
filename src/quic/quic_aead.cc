/**
 * @file quic_aead.cc
 * @brief QUIC AEAD Implementation using mbedtls
 */

#include "quic/quic_aead.h"
#include "quic/quic_constants.h"

#include <mbedtls/gcm.h>
#include <mbedtls/aes.h>

#include <cstring>
#include <esp_log.h>

namespace esp_http3 {
namespace quic {

static const char* TAG = "QUIC_AEAD";

//=============================================================================
// Nonce Generation
//=============================================================================

void GenerateNonce(const uint8_t* iv, uint64_t packet_number, uint8_t* nonce_out) {
    // Copy IV as base
    std::memcpy(nonce_out, iv, 12);
    
    // XOR packet number into rightmost bytes (big-endian)
    for (int i = 0; i < 8; i++) {
        nonce_out[11 - i] ^= static_cast<uint8_t>((packet_number >> (i * 8)) & 0xFF);
    }
}

//=============================================================================
// AEAD Encryption/Decryption
//=============================================================================

size_t AeadEncrypt(const uint8_t* key, const uint8_t* iv,
                   uint64_t packet_number,
                   const uint8_t* aad, size_t aad_len,
                   const uint8_t* plaintext, size_t plaintext_len,
                   uint8_t* ciphertext_out) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    
    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (ret != 0) {
        ESP_LOGW(TAG, "AeadEncrypt: mbedtls_gcm_setkey failed: %d", ret);
        mbedtls_gcm_free(&ctx);
        return 0;
    }
    
    // Generate nonce
    uint8_t nonce[12];
    GenerateNonce(iv, packet_number, nonce);
    
    // Encrypt and generate tag
    uint8_t tag[16];
    ret = mbedtls_gcm_crypt_and_tag(&ctx,
                                     MBEDTLS_GCM_ENCRYPT,
                                     plaintext_len,
                                     nonce, 12,
                                     aad, aad_len,
                                     plaintext,
                                     ciphertext_out,
                                     16, tag);
    
    mbedtls_gcm_free(&ctx);
    
    if (ret != 0) {
        ESP_LOGW(TAG, "AeadEncrypt: mbedtls_gcm_crypt_and_tag failed: %d", ret);
        return 0;
    }
    
    // Append tag to ciphertext
    std::memcpy(ciphertext_out + plaintext_len, tag, 16);
    
    return plaintext_len + 16;
}

size_t AeadDecrypt(const uint8_t* key, const uint8_t* iv,
                   uint64_t packet_number,
                   const uint8_t* aad, size_t aad_len,
                   const uint8_t* ciphertext, size_t ciphertext_len,
                   uint8_t* plaintext_out) {
    if (ciphertext_len < 16) {
        ESP_LOGW(TAG, "AeadDecrypt: ciphertext too short (%zu bytes)", ciphertext_len);
        return 0;  // Too short, no room for tag
    }
    
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    
    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (ret != 0) {
        ESP_LOGW(TAG, "AeadDecrypt: mbedtls_gcm_setkey failed: %d", ret);
        mbedtls_gcm_free(&ctx);
        return 0;
    }
    
    // Generate nonce
    uint8_t nonce[12];
    GenerateNonce(iv, packet_number, nonce);
    
    size_t plaintext_len = ciphertext_len - 16;
    const uint8_t* tag = ciphertext + plaintext_len;
    
    // Decrypt and verify tag
    ret = mbedtls_gcm_auth_decrypt(&ctx,
                                    plaintext_len,
                                    nonce, 12,
                                    aad, aad_len,
                                    tag, 16,
                                    ciphertext,
                                    plaintext_out);
    
    mbedtls_gcm_free(&ctx);
    
    if (ret != 0) {
        ESP_LOGW(TAG, "AeadDecrypt: mbedtls_gcm_auth_decrypt failed: %d (auth tag mismatch?)", ret);
        return 0;  // Decryption or auth failed
    }
    
    return plaintext_len;
}

//=============================================================================
// Header Protection
//=============================================================================

// AES-ECB encrypt a single block for header protection
static bool AesEcbEncrypt(const uint8_t* key, const uint8_t* input, uint8_t* output) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    
    int ret = mbedtls_aes_setkey_enc(&ctx, key, 128);
    if (ret != 0) {
        ESP_LOGW(TAG, "AesEcbEncrypt: mbedtls_aes_setkey_enc failed: %d", ret);
        mbedtls_aes_free(&ctx);
        return false;
    }
    
    ret = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, input, output);
    mbedtls_aes_free(&ctx);
    
    if (ret != 0) {
        ESP_LOGW(TAG, "AesEcbEncrypt: mbedtls_aes_crypt_ecb failed: %d", ret);
        return false;
    }
    return true;
}

bool ApplyHeaderProtection(const uint8_t* hp_key,
                           const uint8_t* sample,
                           uint8_t* first_byte,
                           uint8_t* pn_bytes,
                           size_t pn_len) {
    // Compute mask = AES-ECB(hp_key, sample)
    uint8_t mask[16];
    if (!AesEcbEncrypt(hp_key, sample, mask)) {
        ESP_LOGW(TAG, "ApplyHeaderProtection: AesEcbEncrypt failed");
        return false;
    }
    
    // For long headers: mask 4 bits of first byte
    // For short headers: mask 5 bits of first byte
    bool is_long_header = (*first_byte & 0x80) != 0;
    if (is_long_header) {
        *first_byte ^= (mask[0] & 0x0F);
    } else {
        *first_byte ^= (mask[0] & 0x1F);
    }
    
    // XOR packet number bytes with mask[1..pn_len]
    for (size_t i = 0; i < pn_len; i++) {
        pn_bytes[i] ^= mask[1 + i];
    }
    
    return true;
}

bool RemoveHeaderProtection(const uint8_t* hp_key,
                            uint8_t* packet,
                            size_t packet_len,
                            size_t pn_offset,
                            bool is_long_header,
                            size_t* pn_len_out) {
    // Sample is at pn_offset + 4
    if (pn_offset + 4 + 16 > packet_len) {
        ESP_LOGW(TAG, "RemoveHeaderProtection: not enough data for sample (pn_offset=%zu, packet_len=%zu)", 
                 pn_offset, packet_len);
        return false;  // Not enough data for sample
    }
    
    const uint8_t* sample = packet + pn_offset + 4;
    
    // Compute mask
    uint8_t mask[16];
    if (!AesEcbEncrypt(hp_key, sample, mask)) {
        ESP_LOGW(TAG, "RemoveHeaderProtection: AesEcbEncrypt failed");
        return false;
    }
    
    // Unmask first byte
    if (is_long_header) {
        packet[0] ^= (mask[0] & 0x0F);
    } else {
        packet[0] ^= (mask[0] & 0x1F);
    }
    
    // Get packet number length from first byte
    size_t pn_len = (packet[0] & 0x03) + 1;
    *pn_len_out = pn_len;
    
    // Unmask packet number
    for (size_t i = 0; i < pn_len; i++) {
        packet[pn_offset + i] ^= mask[1 + i];
    }
    
    return true;
}

//=============================================================================
// Retry Integrity Tag
//=============================================================================

// Retry key and nonce (RFC 9001, Section 5.8)
static const uint8_t kRetryKey[16] = {
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e
};

static const uint8_t kRetryNonce[12] = {
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
    0x23, 0x98, 0x25, 0xbb
};

bool ComputeRetryIntegrityTag(const uint8_t* odcid, size_t odcid_len,
                               const uint8_t* retry_packet, size_t retry_len,
                               uint8_t* tag_out) {
    // Build pseudo-packet for AEAD:
    // ODCID length (1 byte) + ODCID + Retry packet
    std::vector<uint8_t> aad;
    aad.reserve(1 + odcid_len + retry_len);
    aad.push_back(static_cast<uint8_t>(odcid_len));
    aad.insert(aad.end(), odcid, odcid + odcid_len);
    aad.insert(aad.end(), retry_packet, retry_packet + retry_len);
    
    // Compute tag using AES-128-GCM with empty plaintext
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    
    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, kRetryKey, 128);
    if (ret != 0) {
        ESP_LOGW(TAG, "ComputeRetryIntegrityTag: mbedtls_gcm_setkey failed: %d", ret);
        mbedtls_gcm_free(&ctx);
        return false;
    }
    
    ret = mbedtls_gcm_crypt_and_tag(&ctx,
                                     MBEDTLS_GCM_ENCRYPT,
                                     0,  // No plaintext
                                     kRetryNonce, 12,
                                     aad.data(), aad.size(),
                                     nullptr,  // No input
                                     nullptr,  // No output
                                     16, tag_out);
    
    mbedtls_gcm_free(&ctx);
    if (ret != 0) {
        ESP_LOGW(TAG, "ComputeRetryIntegrityTag: mbedtls_gcm_crypt_and_tag failed: %d", ret);
        return false;
    }
    return true;
}

bool VerifyRetryIntegrityTag(const uint8_t* odcid, size_t odcid_len,
                              const uint8_t* retry_packet, size_t retry_len) {
    if (retry_len < 16) {
        ESP_LOGW(TAG, "VerifyRetryIntegrityTag: retry packet too short (%zu bytes)", retry_len);
        return false;  // Too short for tag
    }
    
    // Extract received tag
    const uint8_t* received_tag = retry_packet + retry_len - 16;
    
    // Compute expected tag (excluding the tag itself from input)
    uint8_t expected_tag[16];
    if (!ComputeRetryIntegrityTag(odcid, odcid_len, 
                                   retry_packet, retry_len - 16,
                                   expected_tag)) {
        ESP_LOGW(TAG, "VerifyRetryIntegrityTag: ComputeRetryIntegrityTag failed");
        return false;
    }
    
    // Constant-time compare
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= received_tag[i] ^ expected_tag[i];
    }
    
    return diff == 0;
}

} // namespace quic
} // namespace esp_http3

