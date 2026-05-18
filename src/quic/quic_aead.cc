/**
 * @file quic_aead.cc
 * @brief QUIC AEAD Implementation using mbedtls
 */

#include "quic/quic_aead.h"
#include "quic/quic_constants.h"

#include <psa/crypto.h>

#include <cstring>
#include <esp_log.h>

namespace esp_http3 {
namespace quic {

static const char* TAG = "QUIC_AEAD";

static psa_key_id_t ImportAesKey(const uint8_t* key, psa_key_usage_t usage,
                                 psa_algorithm_t algorithm) {
    psa_crypto_init();

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    psa_set_key_algorithm(&attributes, algorithm);
    psa_set_key_usage_flags(&attributes, usage);

    psa_key_id_t key_id = 0;
    psa_status_t status = psa_import_key(&attributes, key, 16, &key_id);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) {
        ESP_LOGW(TAG, "ImportAesKey failed: %ld", static_cast<long>(status));
        return 0;
    }

    return key_id;
}

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
    psa_key_id_t key_id = ImportAesKey(key, PSA_KEY_USAGE_ENCRYPT, PSA_ALG_GCM);
    if (key_id == 0) {
        return 0;
    }
    
    // Generate nonce
    uint8_t nonce[12];
    GenerateNonce(iv, packet_number, nonce);
    
    size_t ciphertext_len = 0;
    psa_status_t status = psa_aead_encrypt(key_id,
                                           PSA_ALG_GCM,
                                           nonce, sizeof(nonce),
                                           aad, aad_len,
                                           plaintext, plaintext_len,
                                           ciphertext_out, plaintext_len + 16,
                                           &ciphertext_len);
    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        ESP_LOGW(TAG, "AeadEncrypt: psa_aead_encrypt failed: %ld", static_cast<long>(status));
        return 0;
    }
    
    return ciphertext_len;
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
    
    psa_key_id_t key_id = ImportAesKey(key, PSA_KEY_USAGE_DECRYPT, PSA_ALG_GCM);
    if (key_id == 0) {
        return 0;
    }
    
    // Generate nonce
    uint8_t nonce[12];
    GenerateNonce(iv, packet_number, nonce);
    
    size_t plaintext_len = 0;
    psa_status_t status = psa_aead_decrypt(key_id,
                                           PSA_ALG_GCM,
                                           nonce, sizeof(nonce),
                                           aad, aad_len,
                                           ciphertext, ciphertext_len,
                                           plaintext_out, ciphertext_len - 16,
                                           &plaintext_len);
    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        ESP_LOGW(TAG, "AeadDecrypt: psa_aead_decrypt failed: %ld (auth tag mismatch?)",
                 static_cast<long>(status));
        return 0;  // Decryption or auth failed
    }
    
    return plaintext_len;
}

//=============================================================================
// Header Protection
//=============================================================================

// AES-ECB encrypt a single block for header protection
static bool AesEcbEncrypt(const uint8_t* key, const uint8_t* input, uint8_t* output) {
    psa_key_id_t key_id = ImportAesKey(key, PSA_KEY_USAGE_ENCRYPT, PSA_ALG_ECB_NO_PADDING);
    if (key_id == 0) {
        return false;
    }
    
    size_t output_len = 0;
    psa_status_t status = psa_cipher_encrypt(key_id,
                                             PSA_ALG_ECB_NO_PADDING,
                                             input, 16,
                                             output, 16,
                                             &output_len);
    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS || output_len != 16) {
        ESP_LOGW(TAG, "AesEcbEncrypt: psa_cipher_encrypt failed: %ld len=%zu",
                 static_cast<long>(status), output_len);
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
    psa_key_id_t key_id = ImportAesKey(kRetryKey, PSA_KEY_USAGE_ENCRYPT, PSA_ALG_GCM);
    if (key_id == 0) {
        return false;
    }

    uint8_t ciphertext[16] = {};
    uint8_t empty_plaintext = 0;
    size_t ciphertext_len = 0;
    psa_status_t status = psa_aead_encrypt(key_id,
                                           PSA_ALG_GCM,
                                           kRetryNonce, sizeof(kRetryNonce),
                                           aad.data(), aad.size(),
                                           &empty_plaintext, 0,
                                           ciphertext, sizeof(ciphertext),
                                           &ciphertext_len);
    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS || ciphertext_len != 16) {
        ESP_LOGW(TAG, "ComputeRetryIntegrityTag: psa_aead_encrypt failed: %ld len=%zu",
                 static_cast<long>(status), ciphertext_len);
        return false;
    }

    std::memcpy(tag_out, ciphertext, sizeof(ciphertext));
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
