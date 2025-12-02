/**
 * @file quic_crypto.cc
 * @brief QUIC Key Derivation Implementation using mbedtls
 */

#include "quic/quic_crypto.h"
#include "quic/quic_constants.h"

#include <mbedtls/hkdf.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/platform_util.h>

#include <cstring>
#include <esp_log.h>

namespace esp_http3 {
namespace quic {

static const char* TAG = "QUIC_CRYPTO";

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

bool HkdfExtract(const uint8_t* salt, size_t salt_len,
                 const uint8_t* ikm, size_t ikm_len,
                 uint8_t* out) {
    // Use mbedtls HKDF-Extract
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == nullptr) {
        ESP_LOGW(TAG, "HkdfExtract: mbedtls_md_info_from_type failed");
        return false;
    }
    
    int ret = mbedtls_hkdf_extract(md, salt, salt_len, ikm, ikm_len, out);
    if (ret != 0) {
        ESP_LOGW(TAG, "HkdfExtract failed: %d", ret);
        return false;
    }
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
    size_t prefix_len = 6;
    size_t full_label_len = prefix_len + label_len;
    
    if (full_label_len > 255 || context_len > 255) {
        ESP_LOGW(TAG, "HkdfExpandLabel: label or context too long (label=%zu, context=%zu)", 
                 full_label_len, context_len);
        return false;
    }
    
    // Build info buffer
    uint8_t info[2 + 1 + 255 + 1 + 255];
    size_t info_len = 0;
    
    // Length (2 bytes, big-endian)
    info[info_len++] = static_cast<uint8_t>((out_len >> 8) & 0xFF);
    info[info_len++] = static_cast<uint8_t>(out_len & 0xFF);
    
    // Label length + label
    info[info_len++] = static_cast<uint8_t>(full_label_len);
    std::memcpy(info + info_len, tls13_prefix, prefix_len);
    info_len += prefix_len;
    std::memcpy(info + info_len, label, label_len);
    info_len += label_len;
    
    // Context length + context
    info[info_len++] = static_cast<uint8_t>(context_len);
    if (context_len > 0) {
        std::memcpy(info + info_len, context, context_len);
        info_len += context_len;
    }
    
    // Use mbedtls HKDF-Expand
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == nullptr) {
        ESP_LOGW(TAG, "HkdfExpandLabel: mbedtls_md_info_from_type failed");
        return false;
    }
    
    int ret = mbedtls_hkdf_expand(md, secret, secret_len, info, info_len, out, out_len);
    if (ret != 0) {
        ESP_LOGW(TAG, "HkdfExpandLabel failed: %d", ret);
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
// X25519 Key Exchange (using mbedtls ECP API with point I/O functions)
// 
// NOTE: For Curve25519/X25519, mbedtls uses point format where:
// - Public key is 32 bytes (X coordinate only, little-endian)
// - mbedtls_ecp_point_read_binary/write_binary handle the format correctly
//=============================================================================

bool GenerateX25519KeyPair(uint8_t* private_key_out, uint8_t* public_key_out) {
    mbedtls_ecp_group grp;
    mbedtls_mpi priv;
    mbedtls_ecp_point pub;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&priv);
    mbedtls_ecp_point_init(&pub);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    
    int ret = -1;
    
    // Seed the random number generator
    const char* pers = "quic_x25519_keygen";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                reinterpret_cast<const unsigned char*>(pers),
                                strlen(pers));
    if (ret != 0) {
        ESP_LOGW("QUIC_CRYPTO", "X25519 keygen: ctr_drbg_seed failed: %d", ret);
        goto cleanup;
    }
    
    // Load Curve25519 group
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0) {
        ESP_LOGW("QUIC_CRYPTO", "X25519 keygen: group_load failed: %d", ret);
        goto cleanup;
    }
    
    // Generate key pair
    ret = mbedtls_ecdh_gen_public(&grp, &priv, &pub,
                                   mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ESP_LOGW("QUIC_CRYPTO", "X25519 keygen: gen_public failed: %d", ret);
        goto cleanup;
    }
    
    // Export private key - mbedtls generates Curve25519 private key properly
    // The private key needs to be in the specific format for X25519
    ret = mbedtls_mpi_write_binary_le(&priv, private_key_out, 32);
    if (ret != 0) {
        ESP_LOGW("QUIC_CRYPTO", "X25519 keygen: export private failed: %d", ret);
        goto cleanup;
    }
    
    // Export public key using point write (handles format correctly)
    {
        size_t olen = 0;
        ret = mbedtls_ecp_point_write_binary(&grp, &pub, MBEDTLS_ECP_PF_COMPRESSED,
                                              &olen, public_key_out, 32);
        if (ret != 0 || olen != 32) {
            ESP_LOGW("QUIC_CRYPTO", "X25519 keygen: export public failed: %d, olen=%zu", ret, olen);
            if (ret == 0) ret = -1;
            goto cleanup;
        }
    }
    
    ret = 0;
    
cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&priv);
    mbedtls_ecp_point_free(&pub);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    
    return ret == 0;
}

bool X25519ECDH(const uint8_t* private_key,
                const uint8_t* peer_public_key,
                uint8_t* shared_secret_out) {
    mbedtls_ecp_group grp;
    mbedtls_mpi priv, shared;
    mbedtls_ecp_point peer_pub;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&priv);
    mbedtls_mpi_init(&shared);
    mbedtls_ecp_point_init(&peer_pub);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    
    int ret = -1;
    
    // Seed the random number generator
    const char* pers = "quic_x25519_ecdh";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                reinterpret_cast<const unsigned char*>(pers),
                                strlen(pers));
    if (ret != 0) {
        ESP_LOGW("QUIC_CRYPTO", "X25519 ECDH: ctr_drbg_seed failed: %d", ret);
        goto cleanup;
    }
    
    // Load Curve25519 group
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0) {
        ESP_LOGW("QUIC_CRYPTO", "X25519 ECDH: group_load failed: %d", ret);
        goto cleanup;
    }
    
    // Import our private key (X25519 format is little-endian)
    ret = mbedtls_mpi_read_binary_le(&priv, private_key, 32);
    if (ret != 0) {
        ESP_LOGW("QUIC_CRYPTO", "X25519 ECDH: read private failed: %d", ret);
        goto cleanup;
    }
    
    // Import peer's public key using point read (handles Curve25519 format)
    ret = mbedtls_ecp_point_read_binary(&grp, &peer_pub, peer_public_key, 32);
    if (ret != 0) {
        ESP_LOGW("QUIC_CRYPTO", "X25519 ECDH: read peer public failed: %d", ret);
        goto cleanup;
    }
    
    // Compute shared secret
    ret = mbedtls_ecdh_compute_shared(&grp, &shared, &peer_pub, &priv,
                                       mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ESP_LOGW("QUIC_CRYPTO", "X25519 ECDH: compute_shared failed: %d", ret);
        goto cleanup;
    }
    
    // Export shared secret (X25519 format is little-endian)
    ret = mbedtls_mpi_write_binary_le(&shared, shared_secret_out, 32);
    if (ret != 0) {
        ESP_LOGW("QUIC_CRYPTO", "X25519 ECDH: export shared failed: %d", ret);
        goto cleanup;
    }
    
    ret = 0;
    
cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&priv);
    mbedtls_mpi_free(&shared);
    mbedtls_ecp_point_free(&peer_pub);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    
    return ret == 0;
}

} // namespace quic
} // namespace esp_http3

