/**
 * @file crypto_manager.cc
 * @brief QUIC Crypto Manager Implementation
 */

#include "client/crypto_manager.h"
#include "quic/quic_crypto.h"

#include <cstring>
#include <random>
#include <esp_log.h>
#include <esp_random.h>

namespace esp_http3 {

static const char* TAG = "CryptoManager";

//=============================================================================
// Constructor / Destructor
//=============================================================================

CryptoManager::CryptoManager() {
    Reset();
}

CryptoManager::~CryptoManager() {
    // Clear sensitive data
    memset(x25519_private_key_, 0, sizeof(x25519_private_key_));
    memset(handshake_secret_, 0, sizeof(handshake_secret_));
    memset(master_secret_, 0, sizeof(master_secret_));
}

//=============================================================================
// Initialization
//=============================================================================

void CryptoManager::Initialize() {
    Reset();
}

void CryptoManager::Reset() {
    // Clear all key material
    memset(x25519_private_key_, 0, sizeof(x25519_private_key_));
    memset(x25519_public_key_, 0, sizeof(x25519_public_key_));
    memset(client_random_, 0, sizeof(client_random_));
    memset(handshake_secret_, 0, sizeof(handshake_secret_));
    memset(master_secret_, 0, sizeof(master_secret_));
    
    // Reset secrets
    client_initial_secrets_ = quic::CryptoSecrets{};
    server_initial_secrets_ = quic::CryptoSecrets{};
    client_handshake_secrets_ = quic::CryptoSecrets{};
    server_handshake_secrets_ = quic::CryptoSecrets{};
    client_app_secrets_ = quic::CryptoSecrets{};
    server_app_secrets_ = quic::CryptoSecrets{};
    
    // Reset previous secrets (Key Update)
    prev_client_app_secrets_ = quic::CryptoSecrets{};
    prev_server_app_secrets_ = quic::CryptoSecrets{};
    
    // Reset transcript
    transcript_hash_.Reset();
    
    // Reset state
    level_ = CryptoLevel::kNone;
    
    // Reset Key Update state
    key_phase_ = 0;
    key_update_generation_ = 0;
}

//=============================================================================
// Key Generation
//=============================================================================

bool CryptoManager::GenerateKeyPair() {
    // Generate X25519 key pair
    if (!quic::GenerateX25519KeyPair(x25519_private_key_, x25519_public_key_)) {
        ESP_LOGE(TAG, "GenerateX25519KeyPair failed");
        return false;
    }
    
    // Generate client random using ESP-IDF hardware random number generator
    // This avoids stack allocation (~2.5KB for std::mt19937) and is more efficient
    for (size_t i = 0; i < sizeof(client_random_); i += 4) {
        uint32_t random_word = esp_random();
        size_t remaining = sizeof(client_random_) - i;
        size_t copy_len = remaining < 4 ? remaining : 4;
        memcpy(client_random_ + i, &random_word, copy_len);
    }
    
    if (debug_) {
        ESP_LOGI(TAG, "Generated X25519 key pair and client random");
    }
    
    return true;
}

//=============================================================================
// Initial Keys
//=============================================================================

bool CryptoManager::DeriveInitialSecrets(const uint8_t* dcid, size_t dcid_len) {
    // Derive client Initial secrets
    if (!quic::DeriveClientInitialSecrets(dcid, dcid_len, &client_initial_secrets_)) {
        ESP_LOGE(TAG, "DeriveClientInitialSecrets failed");
        return false;
    }
    
    // Derive server Initial secrets
    if (!quic::DeriveServerInitialSecrets(dcid, dcid_len, &server_initial_secrets_)) {
        ESP_LOGE(TAG, "DeriveServerInitialSecrets failed");
        return false;
    }
    
    level_ = CryptoLevel::kInitial;
    
    if (debug_) {
        ESP_LOGI(TAG, "Derived Initial secrets from DCID (len=%zu)", dcid_len);
    }
    
    // Notify callback
    if (on_keys_) {
        on_keys_(CryptoLevel::kInitial,
                 client_initial_secrets_.traffic_secret.data(),
                 server_initial_secrets_.traffic_secret.data());
    }
    
    return true;
}

//=============================================================================
// Transcript Hash Management
//=============================================================================

void CryptoManager::ResetTranscript() {
    transcript_hash_.Reset();
}

void CryptoManager::UpdateTranscript(const uint8_t* data, size_t len) {
    transcript_hash_.Update(data, len);
}

void CryptoManager::GetTranscriptHash(uint8_t* out) const {
    transcript_hash_.GetHash(out);
}

//=============================================================================
// Handshake Keys
//=============================================================================

bool CryptoManager::DeriveHandshakeSecrets(const uint8_t* server_public_key,
                                            const uint8_t* server_hello,
                                            size_t sh_len) {
    // Compute ECDH shared secret
    uint8_t shared_secret[32];
    if (!quic::X25519ECDH(x25519_private_key_, server_public_key, shared_secret)) {
        ESP_LOGE(TAG, "X25519ECDH failed");
        return false;
    }
    
    // Get transcript hash (should include ClientHello + ServerHello)
    // Note: ServerHello should already be in the transcript before calling this
    uint8_t transcript[32];
    GetTranscriptHash(transcript);
    
    // Derive handshake secrets
    if (!quic::DeriveHandshakeSecrets(shared_secret, transcript,
                                       &client_handshake_secrets_,
                                       &server_handshake_secrets_,
                                       handshake_secret_)) {
        ESP_LOGE(TAG, "DeriveHandshakeSecrets failed");
        return false;
    }
    
    // Clear shared secret
    memset(shared_secret, 0, sizeof(shared_secret));
    
    level_ = CryptoLevel::kHandshake;
    
    if (debug_) {
        ESP_LOGI(TAG, "Derived Handshake secrets");
    }
    
    // Notify callback
    if (on_keys_) {
        on_keys_(CryptoLevel::kHandshake,
                 client_handshake_secrets_.traffic_secret.data(),
                 server_handshake_secrets_.traffic_secret.data());
    }
    
    return true;
}

//=============================================================================
// Application Keys
//=============================================================================

bool CryptoManager::DeriveApplicationSecrets() {
    // Get transcript hash (should include up to Server Finished)
    uint8_t transcript[32];
    GetTranscriptHash(transcript);
    
    // Derive application secrets
    if (!quic::DeriveApplicationSecrets(handshake_secret_, transcript,
                                         &client_app_secrets_,
                                         &server_app_secrets_,
                                         master_secret_)) {
        ESP_LOGE(TAG, "DeriveApplicationSecrets failed");
        return false;
    }
    
    level_ = CryptoLevel::kApplication;
    
    if (debug_) {
        ESP_LOGI(TAG, "Derived Application secrets");
    }
    
    // Notify callback
    if (on_keys_) {
        on_keys_(CryptoLevel::kApplication,
                 client_app_secrets_.traffic_secret.data(),
                 server_app_secrets_.traffic_secret.data());
    }
    
    return true;
}

//=============================================================================
// Client Finished
//=============================================================================

bool CryptoManager::BuildClientFinished(uint8_t* out, size_t* out_len) {
    // Get transcript hash before Finished
    uint8_t transcript[32];
    GetTranscriptHash(transcript);
    
    // Build Finished message
    if (!quic::BuildClientFinishedMessage(client_handshake_secrets_.traffic_secret.data(),
                                           transcript,
                                           out, out_len)) {
        ESP_LOGE(TAG, "BuildClientFinishedMessage failed");
        return false;
    }
    
    if (debug_) {
        ESP_LOGI(TAG, "Built Client Finished message (%zu bytes)", *out_len);
    }
    
    return true;
}

//=============================================================================
// Key Update (RFC 9001 Section 6)
//=============================================================================

bool CryptoManager::InitiateKeyUpdate() {
    if (!HasApplicationKeys()) {
        if (debug_) {
            ESP_LOGW(TAG, "Cannot initiate Key Update: no application secrets");
        }
        return false;
    }
    
    // Save current secrets as previous
    prev_client_app_secrets_ = client_app_secrets_;
    prev_server_app_secrets_ = server_app_secrets_;
    
    // Derive next generation secrets
    quic::CryptoSecrets next_client, next_server;
    if (!quic::DeriveNextApplicationSecrets(
            client_app_secrets_.traffic_secret.data(),
            server_app_secrets_.traffic_secret.data(),
            &next_client, &next_server)) {
        ESP_LOGE(TAG, "DeriveNextApplicationSecrets failed");
        return false;
    }
    
    // Switch to new keys
    client_app_secrets_ = next_client;
    server_app_secrets_ = next_server;
    
    // Flip key phase
    key_phase_ = 1 - key_phase_;
    key_update_generation_++;
    
    if (debug_) {
        ESP_LOGI(TAG, "Key Update initiated! Generation: %lu, Phase: %u",
                 key_update_generation_, key_phase_);
    }
    
    // Notify callback
    if (on_keys_) {
        on_keys_(CryptoLevel::kApplication,
                 client_app_secrets_.traffic_secret.data(),
                 server_app_secrets_.traffic_secret.data());
    }
    
    return true;
}

void CryptoManager::HandlePeerKeyUpdate(uint8_t received_key_phase) {
    if (received_key_phase == key_phase_) {
        return;  // Same key phase, no update needed
    }
    
    if (debug_) {
        ESP_LOGI(TAG, "Peer initiated Key Update (phase: %u -> %u)",
                 key_phase_, received_key_phase);
    }
    
    // Save current secrets as previous
    prev_client_app_secrets_ = client_app_secrets_;
    prev_server_app_secrets_ = server_app_secrets_;
    
    // Derive next generation secrets
    quic::CryptoSecrets next_client, next_server;
    if (!quic::DeriveNextApplicationSecrets(
            client_app_secrets_.traffic_secret.data(),
            server_app_secrets_.traffic_secret.data(),
            &next_client, &next_server)) {
        ESP_LOGE(TAG, "HandlePeerKeyUpdate: DeriveNextApplicationSecrets failed");
        return;
    }
    
    // Switch to new keys
    client_app_secrets_ = next_client;
    server_app_secrets_ = next_server;
    
    // Update key phase
    key_phase_ = received_key_phase;
    key_update_generation_++;
    
    // Notify callback
    if (on_keys_) {
        on_keys_(CryptoLevel::kApplication,
                 client_app_secrets_.traffic_secret.data(),
                 server_app_secrets_.traffic_secret.data());
    }
    
    if (debug_) {
        ESP_LOGI(TAG, "Keys updated to generation %lu", key_update_generation_);
    }
}

void CryptoManager::CompleteKeyUpdate() {
    // Clear previous keys
    prev_client_app_secrets_.Clear();
    prev_server_app_secrets_.Clear();
    
    if (debug_) {
        ESP_LOGI(TAG, "Key Update complete (generation %lu)", key_update_generation_);
    }
}

} // namespace esp_http3

