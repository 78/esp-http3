/**
 * @file crypto_manager.h
 * @brief QUIC Crypto Manager - Centralized cryptographic operations
 * 
 * Manages all cryptographic state and operations for a QUIC connection:
 * - Key derivation (Initial, Handshake, Application)
 * - Packet encryption/decryption
 * - Transcript hash management
 * - X25519 key exchange
 * 
 * This centralizes crypto logic that was previously scattered across
 * QuicConnection, making it more modular and easier to extend
 * (e.g., for 0-RTT support).
 */

#pragma once

#include "quic/quic_types.h"
#include "quic/quic_crypto.h"
#include "quic/quic_constants.h"
#include <cstdint>
#include <cstddef>
#include <functional>
#include <vector>

namespace esp_http3 {

//=============================================================================
// Crypto State Enum
//=============================================================================

/**
 * @brief Encryption level / key state
 */
enum class CryptoLevel {
    kNone,          ///< No keys derived yet
    kInitial,       ///< Initial keys available
    kHandshake,     ///< Handshake keys available
    kApplication,   ///< 1-RTT application keys available
};

//=============================================================================
// Key Derivation Callback
//=============================================================================

/**
 * @brief Callback when keys are derived (for keylog)
 * 
 * @param level Encryption level (initial, handshake, application)
 * @param client_secret Client traffic secret
 * @param server_secret Server traffic secret
 */
using OnKeysCallback = std::function<void(CryptoLevel level,
                                           const uint8_t* client_secret,
                                           const uint8_t* server_secret)>;

//=============================================================================
// CryptoManager Class
//=============================================================================

/**
 * @brief Manages cryptographic state for a QUIC connection
 * 
 * Encapsulates all key derivation, encryption, and decryption operations.
 * Maintains the TLS 1.3 transcript hash for proper key derivation.
 * 
 * Usage:
 * @code
 * CryptoManager crypto;
 * crypto.Initialize();
 * crypto.GenerateKeyPair();
 * crypto.DeriveInitialSecrets(dcid, dcid_len);
 * // After receiving ServerHello:
 * crypto.DeriveHandshakeSecrets(server_public_key, server_hello, sh_len);
 * // After receiving Finished:
 * crypto.DeriveApplicationSecrets();
 * @endcode
 */
class CryptoManager {
public:
    CryptoManager();
    ~CryptoManager();
    
    // Non-copyable
    CryptoManager(const CryptoManager&) = delete;
    CryptoManager& operator=(const CryptoManager&) = delete;
    
    /**
     * @brief Initialize the crypto manager
     * 
     * Resets all state and prepares for a new connection.
     */
    void Initialize();
    
    /**
     * @brief Reset all crypto state
     */
    void Reset();
    
    /**
     * @brief Set debug mode
     */
    void SetDebug(bool enable) { debug_ = enable; }
    
    /**
     * @brief Set callback for key derivation events
     */
    void SetOnKeys(OnKeysCallback cb) { on_keys_ = std::move(cb); }
    
    //=========================================================================
    // Key Generation
    //=========================================================================
    
    /**
     * @brief Generate X25519 key pair and client random
     * 
     * @return true on success
     */
    bool GenerateKeyPair();
    
    /**
     * @brief Set external X25519 key pair (for keypair reuse across connections)
     * 
     * Allows reusing a previously generated key pair to speed up reconnection.
     * The client_random will still be regenerated for each connection.
     * 
     * @param private_key X25519 private key (32 bytes)
     * @param public_key X25519 public key (32 bytes)
     * @return true if keys are valid
     */
    bool SetKeyPair(const uint8_t* private_key, const uint8_t* public_key);
    
    /**
     * @brief Generate only client random (when reusing keypair)
     * 
     * Called when SetKeyPair() was used to reuse an existing keypair.
     * client_random must be fresh for each connection for security.
     */
    void GenerateClientRandom();
    
    /**
     * @brief Check if key pair is already set
     */
    bool HasKeyPair() const;
    
    /**
     * @brief Get public key for ClientHello
     */
    const uint8_t* GetPublicKey() const { return x25519_public_key_; }
    
    /**
     * @brief Get private key (for caching)
     */
    const uint8_t* GetPrivateKey() const { return x25519_private_key_; }
    
    /**
     * @brief Get client random for ClientHello
     */
    const uint8_t* GetClientRandom() const { return client_random_; }
    
    //=========================================================================
    // Initial Keys
    //=========================================================================
    
    /**
     * @brief Derive Initial encryption keys from DCID
     * 
     * @param dcid Destination Connection ID
     * @param dcid_len DCID length
     * @return true on success
     */
    bool DeriveInitialSecrets(const uint8_t* dcid, size_t dcid_len);
    
    /**
     * @brief Check if Initial keys are available
     */
    bool HasInitialKeys() const { return client_initial_secrets_.valid; }
    
    /**
     * @brief Get client Initial secrets
     */
    const quic::CryptoSecrets& GetClientInitialSecrets() const { 
        return client_initial_secrets_; 
    }
    
    /**
     * @brief Get server Initial secrets
     */
    const quic::CryptoSecrets& GetServerInitialSecrets() const { 
        return server_initial_secrets_; 
    }
    
    //=========================================================================
    // Transcript Hash Management
    //=========================================================================
    
    /**
     * @brief Reset the transcript hash
     */
    void ResetTranscript();
    
    /**
     * @brief Update transcript hash with TLS message
     * 
     * @param data TLS message data
     * @param len Data length
     */
    void UpdateTranscript(const uint8_t* data, size_t len);
    
    /**
     * @brief Get current transcript hash
     * 
     * @param out Output buffer (32 bytes)
     */
    void GetTranscriptHash(uint8_t* out) const;
    
    //=========================================================================
    // Handshake Keys
    //=========================================================================
    
    /**
     * @brief Derive Handshake keys after ServerHello
     * 
     * @param server_public_key Server's X25519 public key (32 bytes)
     * @param server_hello ServerHello message (for transcript)
     * @param sh_len ServerHello length
     * @return true on success
     */
    bool DeriveHandshakeSecrets(const uint8_t* server_public_key,
                                 const uint8_t* server_hello,
                                 size_t sh_len);
    
    /**
     * @brief Check if Handshake keys are available
     */
    bool HasHandshakeKeys() const { return client_handshake_secrets_.valid; }
    
    /**
     * @brief Get client Handshake secrets
     */
    const quic::CryptoSecrets& GetClientHandshakeSecrets() const { 
        return client_handshake_secrets_; 
    }
    
    /**
     * @brief Get server Handshake secrets
     */
    const quic::CryptoSecrets& GetServerHandshakeSecrets() const { 
        return server_handshake_secrets_; 
    }
    
    //=========================================================================
    // Application Keys
    //=========================================================================
    
    /**
     * @brief Derive Application (1-RTT) keys after Server Finished
     * 
     * Uses the current transcript hash (should include Server Finished).
     * 
     * @return true on success
     */
    bool DeriveApplicationSecrets();
    
    /**
     * @brief Check if Application keys are available
     */
    bool HasApplicationKeys() const { return client_app_secrets_.valid; }
    
    /**
     * @brief Get client Application secrets
     */
    const quic::CryptoSecrets& GetClientAppSecrets() const { 
        return client_app_secrets_; 
    }
    
    /**
     * @brief Get server Application secrets
     */
    const quic::CryptoSecrets& GetServerAppSecrets() const { 
        return server_app_secrets_; 
    }
    
    //=========================================================================
    // Key Update (RFC 9001 Section 6)
    //=========================================================================
    
    /**
     * @brief Initiate a Key Update
     * 
     * Derives next generation application secrets and switches to them.
     * 
     * @return true if key update was initiated
     */
    bool InitiateKeyUpdate();
    
    /**
     * @brief Handle a Key Update initiated by peer
     * 
     * Called when a packet with different key phase is received.
     * 
     * @param received_key_phase Key phase from received packet
     */
    void HandlePeerKeyUpdate(uint8_t received_key_phase);
    
    /**
     * @brief Complete key update after confirmation
     * 
     * Clears previous generation keys.
     */
    void CompleteKeyUpdate();
    
    /**
     * @brief Get current key phase (0 or 1)
     */
    uint8_t GetKeyPhase() const { return key_phase_; }
    
    /**
     * @brief Get key update generation count
     */
    uint32_t GetKeyUpdateGeneration() const { return key_update_generation_; }
    
    /**
     * @brief Check if previous keys are available
     * 
     * Previous keys are kept for a short time to decrypt delayed packets.
     */
    bool HasPreviousKeys() const { return prev_client_app_secrets_.valid; }
    
    /**
     * @brief Get previous client Application secrets
     */
    const quic::CryptoSecrets& GetPrevClientAppSecrets() const {
        return prev_client_app_secrets_;
    }
    
    /**
     * @brief Get previous server Application secrets
     */
    const quic::CryptoSecrets& GetPrevServerAppSecrets() const {
        return prev_server_app_secrets_;
    }
    
    //=========================================================================
    // Client Finished
    //=========================================================================
    
    /**
     * @brief Build Client Finished message
     * 
     * @param out Output buffer (must be at least 36 bytes)
     * @param out_len Output length written
     * @return true on success
     */
    bool BuildClientFinished(uint8_t* out, size_t* out_len);
    
    //=========================================================================
    // State Accessors
    //=========================================================================
    
    /**
     * @brief Get current encryption level
     */
    CryptoLevel GetLevel() const { return level_; }
    
    /**
     * @brief Get handshake secret (for app key derivation)
     */
    const uint8_t* GetHandshakeSecret() const { return handshake_secret_; }
    
    /**
     * @brief Get master secret (for resumption, if derived)
     */
    const uint8_t* GetMasterSecret() const { return master_secret_; }

private:
    // Key material
    uint8_t x25519_private_key_[32];
    uint8_t x25519_public_key_[32];
    uint8_t client_random_[32];
    
    // Intermediate secrets
    uint8_t handshake_secret_[32];
    uint8_t master_secret_[32];
    
    // Crypto secrets for each level
    quic::CryptoSecrets client_initial_secrets_;
    quic::CryptoSecrets server_initial_secrets_;
    quic::CryptoSecrets client_handshake_secrets_;
    quic::CryptoSecrets server_handshake_secrets_;
    quic::CryptoSecrets client_app_secrets_;
    quic::CryptoSecrets server_app_secrets_;
    
    // Previous application secrets (for Key Update)
    quic::CryptoSecrets prev_client_app_secrets_;
    quic::CryptoSecrets prev_server_app_secrets_;
    
    // Transcript hash context
    quic::Sha256Context transcript_hash_;
    
    // State
    CryptoLevel level_ = CryptoLevel::kNone;
    bool debug_ = false;
    
    // Key Update state
    uint8_t key_phase_ = 0;          ///< Current key phase (0 or 1)
    uint32_t key_update_generation_ = 0;  ///< Key update generation count
    
    // Callback
    OnKeysCallback on_keys_;
};

} // namespace esp_http3

