/**
 * @file quic_crypto.h
 * @brief QUIC Key Derivation (RFC 9001)
 * 
 * Implements TLS 1.3 key schedule for QUIC using mbedtls.
 */

#pragma once

#include "quic/quic_types.h"
#include <cstdint>
#include <cstddef>

namespace esp_http3 {
namespace quic {

//=============================================================================
// HKDF Functions (RFC 5869)
//=============================================================================

/**
 * @brief HKDF-Extract using SHA-256
 * 
 * @param salt Salt value
 * @param salt_len Salt length
 * @param ikm Input keying material
 * @param ikm_len IKM length
 * @param out Output PRK (32 bytes)
 * @return true on success
 */
bool HkdfExtract(const uint8_t* salt, size_t salt_len,
                 const uint8_t* ikm, size_t ikm_len,
                 uint8_t* out);

/**
 * @brief HKDF-Expand-Label (TLS 1.3 style)
 * 
 * @param secret Secret to expand
 * @param secret_len Secret length
 * @param label Label (without "tls13 " prefix)
 * @param label_len Label length
 * @param context Context (usually transcript hash)
 * @param context_len Context length
 * @param out Output buffer
 * @param out_len Desired output length
 * @return true on success
 */
bool HkdfExpandLabel(const uint8_t* secret, size_t secret_len,
                     const uint8_t* label, size_t label_len,
                     const uint8_t* context, size_t context_len,
                     uint8_t* out, size_t out_len);

//=============================================================================
// Initial Key Derivation
//=============================================================================

/**
 * @brief Derive client Initial secrets from DCID
 * 
 * @param dcid Destination Connection ID
 * @param dcid_len DCID length
 * @param out Output secrets
 * @return true on success
 */
bool DeriveClientInitialSecrets(const uint8_t* dcid, size_t dcid_len,
                                 CryptoSecrets* out);

/**
 * @brief Derive server Initial secrets from DCID
 */
bool DeriveServerInitialSecrets(const uint8_t* dcid, size_t dcid_len,
                                 CryptoSecrets* out);

//=============================================================================
// Handshake Key Derivation
//=============================================================================

/**
 * @brief Derive Handshake secrets from ECDH shared secret
 * 
 * @param shared_secret ECDH shared secret (32 bytes)
 * @param transcript_hash SHA-256 of ClientHello + ServerHello
 * @param client_out Output client secrets
 * @param server_out Output server secrets
 * @param handshake_secret_out Output handshake secret (for app key derivation)
 * @return true on success
 */
bool DeriveHandshakeSecrets(const uint8_t* shared_secret,
                            const uint8_t* transcript_hash,
                            CryptoSecrets* client_out,
                            CryptoSecrets* server_out,
                            uint8_t* handshake_secret_out);

//=============================================================================
// Application Key Derivation
//=============================================================================

/**
 * @brief Derive Application (1-RTT) secrets
 * 
 * @param handshake_secret Handshake secret (from DeriveHandshakeSecrets)
 * @param transcript_hash SHA-256 up to and including Server Finished
 * @param client_out Output client secrets
 * @param server_out Output server secrets
 * @param master_secret_out Output master secret (for resumption)
 * @return true on success
 */
bool DeriveApplicationSecrets(const uint8_t* handshake_secret,
                              const uint8_t* transcript_hash,
                              CryptoSecrets* client_out,
                              CryptoSecrets* server_out,
                              uint8_t* master_secret_out);

//=============================================================================
// Finished Message
//=============================================================================

/**
 * @brief Compute TLS 1.3 Finished verify_data
 * 
 * @param traffic_secret Handshake traffic secret
 * @param transcript_hash Transcript hash up to this point
 * @param out Output verify_data (32 bytes)
 * @return true on success
 */
bool ComputeFinishedVerifyData(const uint8_t* traffic_secret,
                               const uint8_t* transcript_hash,
                               uint8_t* out);

/**
 * @brief Build Client Finished TLS message
 * 
 * @param client_hs_traffic_secret Client handshake traffic secret
 * @param transcript_hash Transcript hash
 * @param out Output buffer (must be at least 36 bytes)
 * @param out_len Output length written
 * @return true on success
 */
bool BuildClientFinishedMessage(const uint8_t* client_hs_traffic_secret,
                                const uint8_t* transcript_hash,
                                uint8_t* out, size_t* out_len);

//=============================================================================
// X25519 Key Exchange
//=============================================================================

/**
 * @brief Generate X25519 key pair
 * 
 * @param private_key_out Output private key (32 bytes)
 * @param public_key_out Output public key (32 bytes)
 * @return true on success
 */
bool GenerateX25519KeyPair(uint8_t* private_key_out, uint8_t* public_key_out);

/**
 * @brief Perform X25519 ECDH
 * 
 * @param private_key Our private key (32 bytes)
 * @param peer_public_key Peer's public key (32 bytes)
 * @param shared_secret_out Output shared secret (32 bytes)
 * @return true on success
 */
bool X25519ECDH(const uint8_t* private_key,
                const uint8_t* peer_public_key,
                uint8_t* shared_secret_out);

//=============================================================================
// SHA-256 Hash
//=============================================================================

/**
 * @brief Compute SHA-256 hash
 * 
 * @param data Input data
 * @param len Data length
 * @param out Output hash (32 bytes)
 * @return true on success
 */
bool Sha256(const uint8_t* data, size_t len, uint8_t* out);

/**
 * @brief SHA-256 incremental context
 */
class Sha256Context {
public:
    Sha256Context();
    ~Sha256Context();
    
    void Reset();
    void Update(const uint8_t* data, size_t len);
    void Finish(uint8_t* out);
    
    // Get intermediate hash without finishing
    void GetHash(uint8_t* out) const;
    
private:
    struct Impl;
    Impl* impl_;
};

} // namespace quic
} // namespace esp_http3

