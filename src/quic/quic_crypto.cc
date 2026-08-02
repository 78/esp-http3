/**
 * @file quic_crypto.cc
 * @brief QUIC Key Derivation Implementation using mbedtls
 */

#include "quic/quic_crypto.h"
#include "quic/quic_constants.h"

#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS

#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/private/sha256.h>
#include <psa/crypto.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <esp_log.h>
#include <esp_random.h>

namespace esp_http3 {
namespace quic {

static const char* TAG = "QUIC_CRYPTO";

// Bounded scratch sizes for HKDF helpers. The TLS 1.3 / QUIC labels and
// contexts used in this codebase never exceed these sizes (longest label
// "c hs traffic" = 12 bytes, longest context = SHA-256 hash = 32 bytes),
// so a 96-byte stack buffer leaves comfortable headroom while saving ~900
// bytes of stack per HKDF call compared to the spec's worst-case 255+255.
static constexpr size_t kHkdfInfoMaxSize = 96;
static constexpr size_t kHkdfHmacInputMaxSize = 96;

//=============================================================================
// SHA-256 Context Implementation
//=============================================================================

struct Sha256Context::Impl {
    mbedtls_sha256_context ctx;
    bool initialized = false;
};

Sha256Context::Sha256Context() : impl_(new Impl()) {
    mbedtls_sha256_init(&impl_->ctx);
    Reset();
}

Sha256Context::~Sha256Context() {
    mbedtls_sha256_free(&impl_->ctx);
    delete impl_;
}

void Sha256Context::Reset() {
    mbedtls_sha256_starts(&impl_->ctx, 0);  // 0 = SHA-256 (not SHA-224)
    impl_->initialized = true;
}

void Sha256Context::Update(const uint8_t* data, size_t len) {
    if (impl_->initialized) {
        mbedtls_sha256_update(&impl_->ctx, data, len);
    }
}

void Sha256Context::Finish(uint8_t* out) {
    if (impl_->initialized) {
        mbedtls_sha256_finish(&impl_->ctx, out);
        impl_->initialized = false;
    }
}

void Sha256Context::GetHash(uint8_t* out) const {
    if (impl_->initialized) {
        // Clone the context to get intermediate hash
        mbedtls_sha256_context clone;
        mbedtls_sha256_init(&clone);
        mbedtls_sha256_clone(&clone, &impl_->ctx);
        mbedtls_sha256_finish(&clone, out);
        mbedtls_sha256_free(&clone);
    }
}

//=============================================================================
// Basic Crypto Functions
//=============================================================================

bool Sha256(const uint8_t* data, size_t len, uint8_t* out) {
    int ret = mbedtls_sha256(data, len, out, 0);
    if (ret != 0) {
        ESP_LOGW(TAG, "Sha256 failed: %d", ret);
        return false;
    }
    return true;
}

bool HmacSha256(const uint8_t* key, size_t key_len,
                const uint8_t* data, size_t data_len,
                uint8_t* out) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == nullptr) {
        ESP_LOGW(TAG, "HmacSha256: mbedtls_md_info_from_type failed");
        return false;
    }
    
    int ret = mbedtls_md_hmac(md, key, key_len, data, data_len, out);
    if (ret != 0) {
        ESP_LOGW(TAG, "HmacSha256: mbedtls_md_hmac failed: %d", ret);
        return false;
    }
    return true;
}

bool HkdfExtract(const uint8_t* salt, size_t salt_len,
                 const uint8_t* ikm, size_t ikm_len,
                 uint8_t* out) {
    uint8_t zero_salt[32] = {};
    if (salt == nullptr || salt_len == 0) {
        salt = zero_salt;
        salt_len = sizeof(zero_salt);
    }

    if (!HmacSha256(salt, salt_len, ikm, ikm_len, out)) {
        ESP_LOGW(TAG, "HkdfExtract failed");
        return false;
    }
    return true;
}

static bool HkdfExpandSha256(const uint8_t* prk, size_t prk_len,
                             const uint8_t* info, size_t info_len,
                             uint8_t* out, size_t out_len) {
    if (out_len > 255 * 32) {
        ESP_LOGW(TAG, "HkdfExpandSha256: output too long (%zu)", out_len);
        return false;
    }

    // Worst case usage: T(i-1) (32B) + info + counter (1B). Reject early
    // if a caller supplies an info longer than our scratch can hold.
    if (info_len + 32 + 1 > kHkdfHmacInputMaxSize) {
        ESP_LOGW(TAG, "HkdfExpandSha256: info_len=%zu exceeds scratch (%zu)",
                 info_len, kHkdfHmacInputMaxSize);
        return false;
    }

    std::array<uint8_t, kHkdfHmacInputMaxSize> hmac_input{};
    uint8_t previous[32] = {};
    uint8_t block[32] = {};
    size_t previous_len = 0;
    size_t produced = 0;
    uint8_t counter = 1;

    while (produced < out_len) {
        size_t hmac_input_len = 0;

        if (previous_len > 0) {
            std::memcpy(hmac_input.data() + hmac_input_len, previous, previous_len);
            hmac_input_len += previous_len;
        }
        if (info_len > 0) {
            std::memcpy(hmac_input.data() + hmac_input_len, info, info_len);
            hmac_input_len += info_len;
        }
        hmac_input[hmac_input_len++] = counter;

        if (!HmacSha256(prk, prk_len, hmac_input.data(), hmac_input_len, block)) {
            ESP_LOGW(TAG, "HkdfExpandSha256: HMAC block failed");
            mbedtls_platform_zeroize(hmac_input.data(), hmac_input.size());
            return false;
        }

        size_t copy_len = std::min(sizeof(block), out_len - produced);
        std::memcpy(out + produced, block, copy_len);
        std::memcpy(previous, block, sizeof(previous));
        previous_len = sizeof(previous);
        produced += copy_len;
        counter++;
    }

    mbedtls_platform_zeroize(hmac_input.data(), hmac_input.size());
    mbedtls_platform_zeroize(previous, sizeof(previous));
    mbedtls_platform_zeroize(block, sizeof(block));
    return true;
}

bool HkdfExpandLabel(const uint8_t* secret, size_t secret_len,
                     const uint8_t* label, size_t label_len,
                     const uint8_t* context, size_t context_len,
                     uint8_t* out, size_t out_len) {
    // Build TLS 1.3 HkdfLabel structure:
    // struct {
    //     uint16 length = Length;
    //     opaque label<7..255> = "tls13 " + Label;
    //     opaque context<0..255> = Context;
    // } HkdfLabel;

    const char* tls13_prefix = "tls13 ";
    const size_t prefix_len = 6;
    const size_t full_label_len = prefix_len + label_len;

    // 2 (length) + 1 (label_len) + full_label + 1 (ctx_len) + context
    const size_t needed = 2 + 1 + full_label_len + 1 + context_len;
    if (full_label_len > 255 || context_len > 255 ||
        needed > kHkdfInfoMaxSize) {
        ESP_LOGW(TAG, "HkdfExpandLabel: info too long (label=%zu, context=%zu, needed=%zu, max=%zu)",
                 full_label_len, context_len, needed, kHkdfInfoMaxSize);
        return false;
    }

    std::array<uint8_t, kHkdfInfoMaxSize> info{};
    size_t info_len = 0;

    // Length (2 bytes, big-endian)
    info[info_len++] = static_cast<uint8_t>((out_len >> 8) & 0xFF);
    info[info_len++] = static_cast<uint8_t>(out_len & 0xFF);

    // Label length + label
    info[info_len++] = static_cast<uint8_t>(full_label_len);
    std::memcpy(info.data() + info_len, tls13_prefix, prefix_len);
    info_len += prefix_len;
    std::memcpy(info.data() + info_len, label, label_len);
    info_len += label_len;

    // Context length + context
    info[info_len++] = static_cast<uint8_t>(context_len);
    if (context_len > 0) {
        std::memcpy(info.data() + info_len, context, context_len);
        info_len += context_len;
    }

    if (!HkdfExpandSha256(secret, secret_len, info.data(), info_len, out, out_len)) {
        ESP_LOGW(TAG, "HkdfExpandLabel failed");
        return false;
    }
    return true;
}

//=============================================================================
// Initial Key Derivation
//=============================================================================

// Helper to derive traffic keys from secret
static bool DeriveTrafficKeys(const uint8_t* secret, CryptoSecrets* out) {
    // key = HKDF-Expand-Label(Secret, "quic key", "", 16)
    // iv  = HKDF-Expand-Label(Secret, "quic iv", "", 12)
    // hp  = HKDF-Expand-Label(Secret, "quic hp", "", 16)
    
    const uint8_t* quic_key = reinterpret_cast<const uint8_t*>("quic key");
    const uint8_t* quic_iv = reinterpret_cast<const uint8_t*>("quic iv");
    const uint8_t* quic_hp = reinterpret_cast<const uint8_t*>("quic hp");
    
    if (!HkdfExpandLabel(secret, 32, quic_key, 8, nullptr, 0, 
                         out->key.data(), 16)) {
        ESP_LOGW(TAG, "DeriveTrafficKeys: failed to derive key");
        return false;
    }
    
    if (!HkdfExpandLabel(secret, 32, quic_iv, 7, nullptr, 0,
                         out->iv.data(), 12)) {
        ESP_LOGW(TAG, "DeriveTrafficKeys: failed to derive iv");
        return false;
    }
    
    if (!HkdfExpandLabel(secret, 32, quic_hp, 7, nullptr, 0,
                         out->hp.data(), 16)) {
        ESP_LOGW(TAG, "DeriveTrafficKeys: failed to derive hp");
        return false;
    }
    
    // Copy the secret for potential key updates
    std::memcpy(out->traffic_secret.data(), secret, 32);
    out->valid = true;
    
    return true;
}

bool DeriveClientInitialSecrets(const uint8_t* dcid, size_t dcid_len,
                                 CryptoSecrets* out) {
    // initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
    uint8_t initial_secret[32];
    if (!HkdfExtract(kQuicV1InitialSalt.data(), kQuicV1InitialSalt.size(),
                     dcid, dcid_len, initial_secret)) {
        ESP_LOGW(TAG, "DeriveClientInitialSecrets: HkdfExtract failed");
        return false;
    }
    
    // client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    const uint8_t* label = reinterpret_cast<const uint8_t*>("client in");
    uint8_t client_secret[32];
    if (!HkdfExpandLabel(initial_secret, 32, label, 9, nullptr, 0,
                         client_secret, 32)) {
        ESP_LOGW(TAG, "DeriveClientInitialSecrets: HkdfExpandLabel failed");
        return false;
    }
    
    return DeriveTrafficKeys(client_secret, out);
}

bool DeriveServerInitialSecrets(const uint8_t* dcid, size_t dcid_len,
                                 CryptoSecrets* out) {
    // initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
    uint8_t initial_secret[32];
    if (!HkdfExtract(kQuicV1InitialSalt.data(), kQuicV1InitialSalt.size(),
                     dcid, dcid_len, initial_secret)) {
        ESP_LOGW(TAG, "DeriveServerInitialSecrets: HkdfExtract failed");
        return false;
    }
    
    // server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
    const uint8_t* label = reinterpret_cast<const uint8_t*>("server in");
    uint8_t server_secret[32];
    if (!HkdfExpandLabel(initial_secret, 32, label, 9, nullptr, 0,
                         server_secret, 32)) {
        ESP_LOGW(TAG, "DeriveServerInitialSecrets: HkdfExpandLabel failed");
        return false;
    }
    
    return DeriveTrafficKeys(server_secret, out);
}

//=============================================================================
// Handshake Key Derivation
//=============================================================================

bool DeriveHandshakeSecrets(const uint8_t* shared_secret,
                            const uint8_t* transcript_hash,
                            CryptoSecrets* client_out,
                            CryptoSecrets* server_out,
                            uint8_t* handshake_secret_out) {
    // TLS 1.3 Key Schedule:
    // 0
    // |
    // v
    // PSK ->  HKDF-Extract = Early Secret
    // ...
    // (EC)DHE -> HKDF-Extract = Handshake Secret
    //                          |
    //                          +-----> Derive-Secret(., "c hs traffic", CH..SH) = client_handshake_traffic_secret
    //                          +-----> Derive-Secret(., "s hs traffic", CH..SH) = server_handshake_traffic_secret
    
    // For non-PSK: early_secret = HKDF-Extract(salt=0, IKM=0)
    uint8_t zeros[32] = {0};
    uint8_t early_secret[32];
    if (!HkdfExtract(nullptr, 0, zeros, 32, early_secret)) {
        ESP_LOGW(TAG, "DeriveHandshakeSecrets: HkdfExtract(early_secret) failed");
        return false;
    }
    
    // derived_secret = Derive-Secret(early_secret, "derived", "")
    const uint8_t* derived_label = reinterpret_cast<const uint8_t*>("derived");
    uint8_t empty_hash[32];
    if (!Sha256(nullptr, 0, empty_hash)) {  // Hash of empty string
        ESP_LOGW(TAG, "DeriveHandshakeSecrets: Sha256(empty) failed");
        return false;
    }
    
    uint8_t derived_secret[32];
    if (!HkdfExpandLabel(early_secret, 32, derived_label, 7, empty_hash, 32,
                         derived_secret, 32)) {
        ESP_LOGW(TAG, "DeriveHandshakeSecrets: HkdfExpandLabel(derived_secret) failed");
        return false;
    }
    
    // handshake_secret = HKDF-Extract(derived_secret, shared_secret)
    uint8_t handshake_secret[32];
    if (!HkdfExtract(derived_secret, 32, shared_secret, 32, handshake_secret)) {
        ESP_LOGW(TAG, "DeriveHandshakeSecrets: HkdfExtract(handshake_secret) failed");
        return false;
    }
    
    // Save handshake secret for application key derivation
    if (handshake_secret_out) {
        std::memcpy(handshake_secret_out, handshake_secret, 32);
    }
    
    // client_hs_traffic = Derive-Secret(hs_secret, "c hs traffic", transcript)
    const uint8_t* c_hs_label = reinterpret_cast<const uint8_t*>("c hs traffic");
    uint8_t client_hs_secret[32];
    if (!HkdfExpandLabel(handshake_secret, 32, c_hs_label, 12, transcript_hash, 32,
                         client_hs_secret, 32)) {
        ESP_LOGW(TAG, "DeriveHandshakeSecrets: HkdfExpandLabel(client_hs_traffic) failed");
        return false;
    }
    
    // server_hs_traffic = Derive-Secret(hs_secret, "s hs traffic", transcript)
    const uint8_t* s_hs_label = reinterpret_cast<const uint8_t*>("s hs traffic");
    uint8_t server_hs_secret[32];
    if (!HkdfExpandLabel(handshake_secret, 32, s_hs_label, 12, transcript_hash, 32,
                         server_hs_secret, 32)) {
        ESP_LOGW(TAG, "DeriveHandshakeSecrets: HkdfExpandLabel(server_hs_traffic) failed");
        return false;
    }
    
    // Derive traffic keys
    if (client_out && !DeriveTrafficKeys(client_hs_secret, client_out)) {
        ESP_LOGW(TAG, "DeriveHandshakeSecrets: DeriveTrafficKeys(client) failed");
        return false;
    }
    if (server_out && !DeriveTrafficKeys(server_hs_secret, server_out)) {
        ESP_LOGW(TAG, "DeriveHandshakeSecrets: DeriveTrafficKeys(server) failed");
        return false;
    }
    
    return true;
}

bool DeriveHandshakeSecretsWithPsk(const uint8_t* shared_secret,
                                    const uint8_t* transcript_hash,
                                    const uint8_t* psk,
                                    CryptoSecrets* client_out,
                                    CryptoSecrets* server_out,
                                    uint8_t* handshake_secret_out) {
    // TLS 1.3 Key Schedule with PSK:
    // PSK -> HKDF-Extract = Early Secret (instead of zeros)
    // ...
    // (EC)DHE -> HKDF-Extract = Handshake Secret
    
    // For PSK: early_secret = HKDF-Extract(salt=0, IKM=PSK)
    uint8_t early_secret[32];
    if (!HkdfExtract(nullptr, 0, psk, 32, early_secret)) {
        ESP_LOGW(TAG, "DeriveHandshakeSecretsWithPsk: HkdfExtract(early_secret) failed");
        return false;
    }
    
    // derived_secret = Derive-Secret(early_secret, "derived", "")
    const uint8_t* derived_label = reinterpret_cast<const uint8_t*>("derived");
    uint8_t empty_hash[32];
    if (!Sha256(nullptr, 0, empty_hash)) {
        ESP_LOGW(TAG, "DeriveHandshakeSecretsWithPsk: Sha256(empty) failed");
        return false;
    }
    
    uint8_t derived_secret[32];
    if (!HkdfExpandLabel(early_secret, 32, derived_label, 7, empty_hash, 32,
                         derived_secret, 32)) {
        ESP_LOGW(TAG, "DeriveHandshakeSecretsWithPsk: HkdfExpandLabel(derived_secret) failed");
        return false;
    }
    
    // handshake_secret = HKDF-Extract(derived_secret, shared_secret)
    uint8_t handshake_secret[32];
    if (!HkdfExtract(derived_secret, 32, shared_secret, 32, handshake_secret)) {
        ESP_LOGW(TAG, "DeriveHandshakeSecretsWithPsk: HkdfExtract(handshake_secret) failed");
        return false;
    }
    
    // Save handshake secret
    if (handshake_secret_out) {
        std::memcpy(handshake_secret_out, handshake_secret, 32);
    }
    
    // Derive traffic secrets (same as non-PSK mode from here)
    const uint8_t* c_hs_label = reinterpret_cast<const uint8_t*>("c hs traffic");
    uint8_t client_hs_secret[32];
    if (!HkdfExpandLabel(handshake_secret, 32, c_hs_label, 12, transcript_hash, 32,
                         client_hs_secret, 32)) {
        ESP_LOGW(TAG, "DeriveHandshakeSecretsWithPsk: HkdfExpandLabel(client_hs_traffic) failed");
        return false;
    }
    
    const uint8_t* s_hs_label = reinterpret_cast<const uint8_t*>("s hs traffic");
    uint8_t server_hs_secret[32];
    if (!HkdfExpandLabel(handshake_secret, 32, s_hs_label, 12, transcript_hash, 32,
                         server_hs_secret, 32)) {
        ESP_LOGW(TAG, "DeriveHandshakeSecretsWithPsk: HkdfExpandLabel(server_hs_traffic) failed");
        return false;
    }
    
    // Derive traffic keys
    if (client_out && !DeriveTrafficKeys(client_hs_secret, client_out)) {
        ESP_LOGW(TAG, "DeriveHandshakeSecretsWithPsk: DeriveTrafficKeys(client) failed");
        return false;
    }
    if (server_out && !DeriveTrafficKeys(server_hs_secret, server_out)) {
        ESP_LOGW(TAG, "DeriveHandshakeSecretsWithPsk: DeriveTrafficKeys(server) failed");
        return false;
    }
    
    ESP_LOGI(TAG, "Derived Handshake secrets with PSK");
    return true;
}

//=============================================================================
// Application Key Derivation
//=============================================================================

bool DeriveApplicationSecrets(const uint8_t* handshake_secret,
                              const uint8_t* transcript_hash,
                              CryptoSecrets* client_out,
                              CryptoSecrets* server_out,
                              uint8_t* master_secret_out) {
    // derived_secret = Derive-Secret(handshake_secret, "derived", "")
    const uint8_t* derived_label = reinterpret_cast<const uint8_t*>("derived");
    uint8_t empty_hash[32];
    if (!Sha256(nullptr, 0, empty_hash)) {
        ESP_LOGW(TAG, "DeriveApplicationSecrets: Sha256(empty) failed");
        return false;
    }
    
    uint8_t derived_secret[32];
    if (!HkdfExpandLabel(handshake_secret, 32, derived_label, 7, empty_hash, 32,
                         derived_secret, 32)) {
        ESP_LOGW(TAG, "DeriveApplicationSecrets: HkdfExpandLabel(derived_secret) failed");
        return false;
    }
    
    // master_secret = HKDF-Extract(derived_secret, 0)
    uint8_t zeros[32] = {0};
    uint8_t master_secret[32];
    if (!HkdfExtract(derived_secret, 32, zeros, 32, master_secret)) {
        ESP_LOGW(TAG, "DeriveApplicationSecrets: HkdfExtract(master_secret) failed");
        return false;
    }
    
    if (master_secret_out) {
        std::memcpy(master_secret_out, master_secret, 32);
    }
    
    // client_app_traffic = Derive-Secret(master_secret, "c ap traffic", transcript)
    const uint8_t* c_ap_label = reinterpret_cast<const uint8_t*>("c ap traffic");
    uint8_t client_app_secret[32];
    if (!HkdfExpandLabel(master_secret, 32, c_ap_label, 12, transcript_hash, 32,
                         client_app_secret, 32)) {
        ESP_LOGW(TAG, "DeriveApplicationSecrets: HkdfExpandLabel(client_app_traffic) failed");
        return false;
    }
    
    // server_app_traffic = Derive-Secret(master_secret, "s ap traffic", transcript)
    const uint8_t* s_ap_label = reinterpret_cast<const uint8_t*>("s ap traffic");
    uint8_t server_app_secret[32];
    if (!HkdfExpandLabel(master_secret, 32, s_ap_label, 12, transcript_hash, 32,
                         server_app_secret, 32)) {
        ESP_LOGW(TAG, "DeriveApplicationSecrets: HkdfExpandLabel(server_app_traffic) failed");
        return false;
    }
    
    // Derive traffic keys
    if (client_out && !DeriveTrafficKeys(client_app_secret, client_out)) {
        ESP_LOGW(TAG, "DeriveApplicationSecrets: DeriveTrafficKeys(client) failed");
        return false;
    }
    if (server_out && !DeriveTrafficKeys(server_app_secret, server_out)) {
        ESP_LOGW(TAG, "DeriveApplicationSecrets: DeriveTrafficKeys(server) failed");
        return false;
    }
    
    return true;
}

//=============================================================================
// Key Update (RFC 9001 Section 6)
//=============================================================================

bool DeriveNextApplicationSecrets(const uint8_t* current_client_secret,
                                   const uint8_t* current_server_secret,
                                   CryptoSecrets* next_client_out,
                                   CryptoSecrets* next_server_out) {
    // Key Update uses "quic ku" label:
    // application_traffic_secret_N+1 = HKDF-Expand-Label(
    //     application_traffic_secret_N, "quic ku", "", 32)
    
    const uint8_t* ku_label = reinterpret_cast<const uint8_t*>("quic ku");
    
    // Derive next client secret
    if (next_client_out) {
        uint8_t next_client_secret[32];
        if (!HkdfExpandLabel(current_client_secret, 32, ku_label, 7, 
                             nullptr, 0, next_client_secret, 32)) {
            ESP_LOGW(TAG, "DeriveNextApplicationSecrets: client key update failed");
            return false;
        }
        
        // Store the new traffic secret
        std::memcpy(next_client_out->traffic_secret.data(), next_client_secret, 32);
        
        // Derive traffic keys from new secret
        if (!DeriveTrafficKeys(next_client_secret, next_client_out)) {
            ESP_LOGW(TAG, "DeriveNextApplicationSecrets: DeriveTrafficKeys(client) failed");
            return false;
        }
    }
    
    // Derive next server secret
    if (next_server_out) {
        uint8_t next_server_secret[32];
        if (!HkdfExpandLabel(current_server_secret, 32, ku_label, 7,
                             nullptr, 0, next_server_secret, 32)) {
            ESP_LOGW(TAG, "DeriveNextApplicationSecrets: server key update failed");
            return false;
        }
        
        // Store the new traffic secret
        std::memcpy(next_server_out->traffic_secret.data(), next_server_secret, 32);
        
        // Derive traffic keys from new secret
        if (!DeriveTrafficKeys(next_server_secret, next_server_out)) {
            ESP_LOGW(TAG, "DeriveNextApplicationSecrets: DeriveTrafficKeys(server) failed");
            return false;
        }
    }
    
    return true;
}

//=============================================================================
// Finished Message
//=============================================================================

bool ComputeFinishedVerifyData(const uint8_t* traffic_secret,
                               const uint8_t* transcript_hash,
                               uint8_t* out) {
    // finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", 32)
    const uint8_t* finished_label = reinterpret_cast<const uint8_t*>("finished");
    uint8_t finished_key[32];
    if (!HkdfExpandLabel(traffic_secret, 32, finished_label, 8, nullptr, 0,
                         finished_key, 32)) {
        ESP_LOGW(TAG, "ComputeFinishedVerifyData: HkdfExpandLabel(finished_key) failed");
        return false;
    }
    
    // verify_data = HMAC(finished_key, transcript_hash)
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == nullptr) {
        ESP_LOGW(TAG, "ComputeFinishedVerifyData: mbedtls_md_info_from_type failed");
        return false;
    }
    
    int ret = mbedtls_md_hmac(md, finished_key, 32, transcript_hash, 32, out);
    if (ret != 0) {
        ESP_LOGW(TAG, "ComputeFinishedVerifyData: mbedtls_md_hmac failed: %d", ret);
        return false;
    }
    return true;
}

bool BuildClientFinishedMessage(const uint8_t* client_hs_traffic_secret,
                                const uint8_t* transcript_hash,
                                uint8_t* out, size_t* out_len) {
    // Finished message:
    // struct {
    //     HandshakeType msg_type = finished (20)
    //     uint24 length = 32
    //     opaque verify_data[32]
    // }
    
    out[0] = 20;  // Finished
    out[1] = 0;
    out[2] = 0;
    out[3] = 32;  // verify_data length
    
    if (!ComputeFinishedVerifyData(client_hs_traffic_secret, transcript_hash, out + 4)) {
        ESP_LOGW(TAG, "BuildClientFinishedMessage: ComputeFinishedVerifyData failed");
        return false;
    }
    
    *out_len = 36;
    return true;
}

//=============================================================================
// X25519 Key Exchange (using the PSA Crypto API)
//
// The legacy mbedtls ECP/MPI/ECDH low-level API was removed in mbedtls 4.x
// (ESP-IDF 6.2), so X25519 is implemented through PSA, which is available on
// both ESP-IDF 6.0 and 6.2. For Curve25519/X25519 the PSA raw export format is
// the 32-byte little-endian u-coordinate, matching the QUIC/TLS 1.3 wire
// format produced by the previous implementation.
//=============================================================================

bool GenerateX25519KeyPair(uint8_t* private_key_out, uint8_t* public_key_out) {
    if (psa_crypto_init() != PSA_SUCCESS) {
        ESP_LOGW(TAG, "X25519 keygen: psa_crypto_init failed");
        return false;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attributes, 255);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);

    psa_key_id_t key_id = 0;
    psa_status_t status = psa_generate_key(&attributes, &key_id);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) {
        ESP_LOGW(TAG, "X25519 keygen: psa_generate_key failed: %ld", static_cast<long>(status));
        return false;
    }

    bool ok = true;
    size_t olen = 0;

    status = psa_export_key(key_id, private_key_out, 32, &olen);
    if (status != PSA_SUCCESS || olen != 32) {
        ESP_LOGW(TAG, "X25519 keygen: export private failed: %ld, olen=%zu",
                 static_cast<long>(status), olen);
        ok = false;
    }

    if (ok) {
        status = psa_export_public_key(key_id, public_key_out, 32, &olen);
        if (status != PSA_SUCCESS || olen != 32) {
            ESP_LOGW(TAG, "X25519 keygen: export public failed: %ld, olen=%zu",
                     static_cast<long>(status), olen);
            ok = false;
        }
    }

    psa_destroy_key(key_id);
    return ok;
}

bool X25519ECDH(const uint8_t* private_key,
                const uint8_t* peer_public_key,
                uint8_t* shared_secret_out) {
    if (psa_crypto_init() != PSA_SUCCESS) {
        ESP_LOGW(TAG, "X25519 ECDH: psa_crypto_init failed");
        return false;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attributes, 255);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);

    psa_key_id_t key_id = 0;
    psa_status_t status = psa_import_key(&attributes, private_key, 32, &key_id);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) {
        ESP_LOGW(TAG, "X25519 ECDH: import private failed: %ld", static_cast<long>(status));
        return false;
    }

    size_t olen = 0;
    status = psa_raw_key_agreement(PSA_ALG_ECDH, key_id,
                                   peer_public_key, 32,
                                   shared_secret_out, 32, &olen);
    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS || olen != 32) {
        ESP_LOGW(TAG, "X25519 ECDH: key agreement failed: %ld, olen=%zu",
                 static_cast<long>(status), olen);
        return false;
    }

    return true;
}

} // namespace quic
} // namespace esp_http3
