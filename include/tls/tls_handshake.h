/**
 * @file tls_handshake.h
 * @brief TLS 1.3 Handshake Messages for QUIC (RFC 8446)
 */

#pragma once

#include "quic/quic_types.h"
#include "quic/quic_frame.h"
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace esp_http3 {
namespace tls {

//=============================================================================
// TLS Constants
//=============================================================================

// TLS 1.3 version
constexpr uint16_t kTls13Version = 0x0304;
constexpr uint16_t kTlsLegacyVersion = 0x0303;

// Handshake message types
enum class HandshakeType : uint8_t {
    kClientHello = 1,
    kServerHello = 2,
    kNewSessionTicket = 4,
    kEncryptedExtensions = 8,
    kCertificate = 11,
    kCertificateVerify = 15,
    kFinished = 20,
};

// Extension types
enum class ExtensionType : uint16_t {
    kServerName = 0,
    kSupportedGroups = 10,
    kSignatureAlgorithms = 13,
    kALPN = 16,
    kSupportedVersions = 43,
    kKeyShare = 51,
    kQUICTransportParameters = 0x39,
};

// Cipher suites
constexpr uint16_t kTls13Aes128GcmSha256 = 0x1301;

// Named groups
constexpr uint16_t kX25519 = 0x001d;

// Signature algorithms
constexpr uint16_t kRsaPssSha256 = 0x0804;
constexpr uint16_t kEcdsaSecp256r1Sha256 = 0x0403;

//=============================================================================
// ClientHello Building
//=============================================================================

/**
 * @brief Build TLS 1.3 ClientHello message
 * 
 * @param hostname Server hostname (SNI)
 * @param client_random 32-byte random
 * @param x25519_public_key 32-byte X25519 public key
 * @param transport_params QUIC transport parameters
 * @param out Output buffer
 * @param out_len Output buffer size
 * @return Size written, or 0 on failure
 */
size_t BuildClientHello(const std::string& hostname,
                         const uint8_t* client_random,
                         const uint8_t* x25519_public_key,
                         const quic::TransportParameters& transport_params,
                         uint8_t* out, size_t out_len);

//=============================================================================
// ServerHello Parsing
//=============================================================================

/**
 * @brief Parsed ServerHello data
 */
struct ServerHelloData {
    uint8_t server_random[32] = {0};
    uint8_t session_id[32] = {0};
    uint8_t session_id_len = 0;
    uint16_t cipher_suite = 0;
    uint8_t compression_method = 0;
    
    // From extensions
    uint16_t selected_version = 0;
    uint16_t key_share_group = 0;
    uint8_t key_share_public_key[32] = {0};
    
    bool is_hello_retry_request = false;
};

/**
 * @brief Parse ServerHello message
 * 
 * @param data TLS record data (after handshake header)
 * @param len Data length
 * @param out Output parsed data
 * @return true on success
 */
bool ParseServerHello(const uint8_t* data, size_t len, ServerHelloData* out);

//=============================================================================
// EncryptedExtensions Parsing
//=============================================================================

/**
 * @brief Parsed EncryptedExtensions data
 */
struct EncryptedExtensionsData {
    std::string alpn;
    quic::TransportParameters transport_params;
    bool has_transport_params = false;
};

/**
 * @brief Parse EncryptedExtensions message
 * 
 * @param data TLS record data (after handshake header)
 * @param len Data length
 * @param out Output parsed data
 * @return true on success
 */
bool ParseEncryptedExtensions(const uint8_t* data, size_t len,
                               EncryptedExtensionsData* out);

//=============================================================================
// Certificate Parsing
//=============================================================================

/**
 * @brief Single certificate entry
 */
struct CertificateEntry {
    std::vector<uint8_t> cert_data;
    // Extensions not parsed for simplicity
};

/**
 * @brief Parsed Certificate message
 */
struct CertificateData {
    uint8_t certificate_request_context_len = 0;
    std::vector<CertificateEntry> certificates;
};

/**
 * @brief Parse Certificate message
 * 
 * @param data TLS record data (after handshake header)
 * @param len Data length
 * @param out Output parsed data
 * @return true on success
 */
bool ParseCertificate(const uint8_t* data, size_t len, CertificateData* out);

//=============================================================================
// CertificateVerify Parsing
//=============================================================================

/**
 * @brief Parsed CertificateVerify message
 */
struct CertificateVerifyData {
    uint16_t signature_algorithm = 0;
    std::vector<uint8_t> signature;
};

/**
 * @brief Parse CertificateVerify message
 * 
 * @param data TLS record data (after handshake header)
 * @param len Data length
 * @param out Output parsed data
 * @return true on success
 */
bool ParseCertificateVerify(const uint8_t* data, size_t len,
                             CertificateVerifyData* out);

//=============================================================================
// Finished Message
//=============================================================================

/**
 * @brief Parsed Finished message
 */
struct FinishedData {
    uint8_t verify_data[32] = {0};
};

/**
 * @brief Parse Finished message
 * 
 * @param data TLS record data (after handshake header)
 * @param len Data length
 * @param out Output parsed data
 * @return true on success
 */
bool ParseFinished(const uint8_t* data, size_t len, FinishedData* out);

//=============================================================================
// NewSessionTicket Parsing
//=============================================================================

/**
 * @brief Parsed NewSessionTicket message
 */
struct NewSessionTicketData {
    uint32_t ticket_lifetime = 0;
    uint32_t ticket_age_add = 0;
    std::vector<uint8_t> ticket_nonce;
    std::vector<uint8_t> ticket;
    // Extensions not parsed
};

/**
 * @brief Parse NewSessionTicket message
 * 
 * @param data TLS record data (after handshake header)
 * @param len Data length
 * @param out Output parsed data
 * @return true on success
 */
bool ParseNewSessionTicket(const uint8_t* data, size_t len,
                            NewSessionTicketData* out);

//=============================================================================
// Utility Functions
//=============================================================================

/**
 * @brief Parse TLS handshake message header
 * 
 * @param data Raw data
 * @param len Data length
 * @param msg_type Output message type
 * @param msg_len Output message length
 * @return Bytes consumed for header (4), or 0 on failure
 */
size_t ParseHandshakeHeader(const uint8_t* data, size_t len,
                            HandshakeType* msg_type, uint32_t* msg_len);

} // namespace tls
} // namespace esp_http3

