/**
 * @file tls_handshake.cc
 * @brief TLS 1.3 Handshake Messages Implementation
 */

#include "tls/tls_handshake.h"
#include "quic/quic_frame.h"
#include "quic/quic_crypto.h"
#include <esp_log.h>

#include <cstring>
#include <vector>

static const char* TAG = "TlsHandshake";

namespace esp_http3 {
namespace tls {

using quic::BufferWriter;
using quic::BufferReader;

//=============================================================================
// Helper Functions
//=============================================================================

static bool WriteExtension(BufferWriter* w, ExtensionType type, 
                           const uint8_t* data, size_t len) {
    if (!w->WriteUint16(static_cast<uint16_t>(type))) return false;
    if (!w->WriteUint16(static_cast<uint16_t>(len))) return false;
    if (len > 0 && !w->WriteBytes(data, len)) return false;
    return true;
}

//=============================================================================
// ClientHello Building
//=============================================================================

size_t BuildClientHello(const std::string& hostname,
                         const uint8_t* client_random,
                         const uint8_t* x25519_public_key,
                         const quic::TransportParameters& transport_params,
                         uint8_t* out, size_t out_len) {
    // Build extensions first
    std::vector<uint8_t> extensions(1024);
    BufferWriter ext_writer(extensions.data(), extensions.size());
    
    // 1. SNI extension
    {
        std::vector<uint8_t> sni_data(256);
        BufferWriter sni(sni_data.data(), sni_data.size());
        
        // Server Name List length (2 bytes) - will fill later
        size_t list_len_pos = sni.Offset();
        sni.WriteUint16(0);
        
        // Name Type (host_name = 0)
        sni.WriteUint8(0);
        
        // Host Name length
        sni.WriteUint16(static_cast<uint16_t>(hostname.size()));
        sni.WriteBytes(reinterpret_cast<const uint8_t*>(hostname.data()), 
                       hostname.size());
        
        // Fix up list length
        uint16_t list_len = static_cast<uint16_t>(sni.Offset() - 2);
        sni_data[list_len_pos] = static_cast<uint8_t>(list_len >> 8);
        sni_data[list_len_pos + 1] = static_cast<uint8_t>(list_len & 0xFF);
        
        if (!WriteExtension(&ext_writer, ExtensionType::kServerName,
                            sni_data.data(), sni.Offset())) {
            return 0;
        }
    }
    
    // 2. Supported Groups extension
    {
        uint8_t groups[] = {0x00, 0x02, 0x00, 0x1d};  // Length=2, X25519
        if (!WriteExtension(&ext_writer, ExtensionType::kSupportedGroups,
                            groups, sizeof(groups))) {
            return 0;
        }
    }
    
    // 3. Signature Algorithms extension
    {
        uint8_t sig_algs[] = {
            0x00, 0x04,  // Length = 4
            0x04, 0x03,  // ecdsa_secp256r1_sha256
            0x08, 0x04,  // rsa_pss_rsae_sha256
        };
        if (!WriteExtension(&ext_writer, ExtensionType::kSignatureAlgorithms,
                            sig_algs, sizeof(sig_algs))) {
            return 0;
        }
    }
    
    // 4. Supported Versions extension (ClientHello format)
    {
        // Format: 1 byte length + versions (2 bytes each)
        uint8_t versions[] = {
            0x02,        // List length = 2 bytes (one version)
            0x03, 0x04   // TLS 1.3 = 0x0304
        };
        if (!WriteExtension(&ext_writer, ExtensionType::kSupportedVersions,
                            versions, sizeof(versions))) {
            return 0;
        }
    }
    
    // 5. Key Share extension
    {
        uint8_t key_share[64];
        BufferWriter ks(key_share, sizeof(key_share));
        
        // Client Key Share Length
        ks.WriteUint16(32 + 4);  // group(2) + key_len(2) + key(32)
        
        // Named Group
        ks.WriteUint16(kX25519);
        
        // Key Exchange length
        ks.WriteUint16(32);
        
        // Key Exchange
        ks.WriteBytes(x25519_public_key, 32);
        
        if (!WriteExtension(&ext_writer, ExtensionType::kKeyShare,
                            key_share, ks.Offset())) {
            return 0;
        }
    }
    
    // 6. ALPN extension
    {
        uint8_t alpn_data[] = {
            0x00, 0x03,  // ALPN Extension Length
            0x02,        // Protocol Name Length
            'h', '3'     // "h3"
        };
        if (!WriteExtension(&ext_writer, ExtensionType::kALPN,
                            alpn_data, sizeof(alpn_data))) {
            return 0;
        }
    }
    
    // 7. QUIC Transport Parameters extension
    {
        std::vector<uint8_t> tp_data(256);
        size_t tp_len = quic::BuildTransportParameters(transport_params, 
                                                        tp_data.data(), tp_data.size());
        if (tp_len == 0) {
            return 0;
        }
        if (!WriteExtension(&ext_writer, ExtensionType::kQUICTransportParameters,
                            tp_data.data(), tp_len)) {
            return 0;
        }
    }
    
    size_t extensions_len = ext_writer.Offset();
    
    // Build ClientHello
    BufferWriter writer(out, out_len);
    
    // Handshake header placeholder (will fill length later)
    size_t msg_start = writer.Offset();
    if (!writer.WriteUint8(static_cast<uint8_t>(HandshakeType::kClientHello))) {
        return 0;
    }
    if (!writer.WriteUint8(0) || !writer.WriteUint16(0)) {  // Length placeholder
        return 0;
    }
    
    size_t body_start = writer.Offset();
    
    // Legacy version (TLS 1.2)
    if (!writer.WriteUint16(kTlsLegacyVersion)) {
        return 0;
    }
    
    // Random
    if (!writer.WriteBytes(client_random, 32)) {
        return 0;
    }
    
    // Session ID (empty for QUIC)
    if (!writer.WriteUint8(0)) {
        return 0;
    }
    
    // Cipher Suites
    if (!writer.WriteUint16(2)) {  // Length
        return 0;
    }
    if (!writer.WriteUint16(kTls13Aes128GcmSha256)) {
        return 0;
    }
    
    // Compression Methods (null only)
    if (!writer.WriteUint8(1)) {  // Length
        return 0;
    }
    if (!writer.WriteUint8(0)) {  // null compression
        return 0;
    }
    
    // Extensions
    if (!writer.WriteUint16(static_cast<uint16_t>(extensions_len))) {
        return 0;
    }
    if (!writer.WriteBytes(extensions.data(), extensions_len)) {
        return 0;
    }
    
    // Fix up message length
    size_t body_len = writer.Offset() - body_start;
    out[msg_start + 1] = static_cast<uint8_t>((body_len >> 16) & 0xFF);
    out[msg_start + 2] = static_cast<uint8_t>((body_len >> 8) & 0xFF);
    out[msg_start + 3] = static_cast<uint8_t>(body_len & 0xFF);
    
    return writer.Offset();
}

//=============================================================================
// ClientHello with PSK Building
//=============================================================================

size_t BuildClientHelloWithPsk(const std::string& hostname,
                                const uint8_t* client_random,
                                const uint8_t* x25519_public_key,
                                const quic::TransportParameters& transport_params,
                                const PskParameters& psk,
                                uint8_t* out, size_t out_len) {
    if (!psk.valid) {
        ESP_LOGW(TAG, "BuildClientHelloWithPsk: PSK not valid, falling back to full handshake");
        return BuildClientHello(hostname, client_random, x25519_public_key, 
                                transport_params, out, out_len);
    }
    
    // Build extensions first (same as BuildClientHello, plus PSK extensions)
    std::vector<uint8_t> extensions(2048);  // Larger buffer for PSK
    BufferWriter ext_writer(extensions.data(), extensions.size());
    
    // 1. SNI extension
    {
        std::vector<uint8_t> sni_data(256);
        BufferWriter sni(sni_data.data(), sni_data.size());
        size_t list_len_pos = sni.Offset();
        sni.WriteUint16(0);
        sni.WriteUint8(0);
        sni.WriteUint16(static_cast<uint16_t>(hostname.size()));
        sni.WriteBytes(reinterpret_cast<const uint8_t*>(hostname.data()), 
                       hostname.size());
        uint16_t list_len = static_cast<uint16_t>(sni.Offset() - 2);
        sni_data[list_len_pos] = static_cast<uint8_t>(list_len >> 8);
        sni_data[list_len_pos + 1] = static_cast<uint8_t>(list_len & 0xFF);
        if (!WriteExtension(&ext_writer, ExtensionType::kServerName,
                            sni_data.data(), sni.Offset())) {
            return 0;
        }
    }
    
    // 2. Supported Groups extension
    {
        uint8_t groups[] = {0x00, 0x02, 0x00, 0x1d};
        if (!WriteExtension(&ext_writer, ExtensionType::kSupportedGroups,
                            groups, sizeof(groups))) {
            return 0;
        }
    }
    
    // 3. Signature Algorithms extension
    {
        uint8_t sig_algs[] = {
            0x00, 0x04,
            0x04, 0x03,
            0x08, 0x04,
        };
        if (!WriteExtension(&ext_writer, ExtensionType::kSignatureAlgorithms,
                            sig_algs, sizeof(sig_algs))) {
            return 0;
        }
    }
    
    // 4. Supported Versions extension
    {
        uint8_t versions[] = {0x02, 0x03, 0x04};
        if (!WriteExtension(&ext_writer, ExtensionType::kSupportedVersions,
                            versions, sizeof(versions))) {
            return 0;
        }
    }
    
    // 5. Key Share extension
    {
        uint8_t key_share[64];
        BufferWriter ks(key_share, sizeof(key_share));
        ks.WriteUint16(32 + 4);
        ks.WriteUint16(kX25519);
        ks.WriteUint16(32);
        ks.WriteBytes(x25519_public_key, 32);
        if (!WriteExtension(&ext_writer, ExtensionType::kKeyShare,
                            key_share, ks.Offset())) {
            return 0;
        }
    }
    
    // 6. ALPN extension
    {
        uint8_t alpn_data[] = {0x00, 0x03, 0x02, 'h', '3'};
        if (!WriteExtension(&ext_writer, ExtensionType::kALPN,
                            alpn_data, sizeof(alpn_data))) {
            return 0;
        }
    }
    
    // 7. QUIC Transport Parameters extension
    {
        std::vector<uint8_t> tp_data(256);
        size_t tp_len = quic::BuildTransportParameters(transport_params, 
                                                        tp_data.data(), tp_data.size());
        if (tp_len == 0) {
            return 0;
        }
        if (!WriteExtension(&ext_writer, ExtensionType::kQUICTransportParameters,
                            tp_data.data(), tp_len)) {
            return 0;
        }
    }
    
    // 8. PSK Key Exchange Modes extension (MUST come before pre_shared_key)
    {
        uint8_t psk_modes[] = {
            0x01,  // Length = 1
            static_cast<uint8_t>(PskKeyExchangeMode::kPskDheKe)  // PSK with (EC)DHE
        };
        if (!WriteExtension(&ext_writer, ExtensionType::kPskKeyExchangeModes,
                            psk_modes, sizeof(psk_modes))) {
            return 0;
        }
    }
    
    // 9. Pre-Shared Key extension (MUST be last)
    // We need to compute the binder, which requires:
    // 1. Build partial ClientHello up to binders
    // 2. Compute hash of partial ClientHello (excluding binders_length and binders)
    // 3. Compute binder using binder_key
    
    // First, build the pre_shared_key extension structure (without binder value)
    std::vector<uint8_t> psk_ext_data(512);
    BufferWriter psk_writer(psk_ext_data.data(), psk_ext_data.size());
    
    // Identities
    size_t identities_len_pos = psk_writer.Offset();
    psk_writer.WriteUint16(0);  // Placeholder for identities length
    
    size_t identity_start = psk_writer.Offset();
    // Identity (ticket)
    psk_writer.WriteUint16(static_cast<uint16_t>(psk.identity.ticket.size()));
    psk_writer.WriteBytes(psk.identity.ticket.data(), psk.identity.ticket.size());
    // Obfuscated ticket age
    psk_writer.WriteUint32(psk.identity.obfuscated_ticket_age);
    
    // Fix up identities length
    uint16_t identities_len = static_cast<uint16_t>(psk_writer.Offset() - identity_start);
    psk_ext_data[identities_len_pos] = static_cast<uint8_t>(identities_len >> 8);
    psk_ext_data[identities_len_pos + 1] = static_cast<uint8_t>(identities_len & 0xFF);
    
    // Record position where binders start (for transcript hash calculation)
    // RFC 8446: transcript includes everything up to but NOT including binders_length
    size_t psk_ext_hash_len = psk_writer.Offset();  // This is where binders_length starts
    
    // Binders length and placeholder
    psk_writer.WriteUint16(33);  // 1 byte length + 32 bytes HMAC
    psk_writer.WriteUint8(32);   // Binder length = 32 bytes (SHA-256)
    // Write zeros as placeholder for binder value
    uint8_t zero_binder[32] = {0};
    psk_writer.WriteBytes(zero_binder, 32);
    
    // Calculate how many bytes to exclude from hash (binders_length + binder_length + binder)
    size_t binders_total_len = psk_writer.Offset() - psk_ext_hash_len;  // = 2 + 1 + 32 = 35
    
    // Write the pre_shared_key extension
    if (!WriteExtension(&ext_writer, ExtensionType::kPreSharedKey,
                        psk_ext_data.data(), psk_writer.Offset())) {
        return 0;
    }
    
    size_t extensions_len = ext_writer.Offset();
    
    // Now build the partial ClientHello for binder computation
    // The transcript for binder includes everything up to (but not including) the binder values
    BufferWriter writer(out, out_len);
    
    // Handshake header
    size_t msg_start = writer.Offset();
    if (!writer.WriteUint8(static_cast<uint8_t>(HandshakeType::kClientHello))) {
        return 0;
    }
    if (!writer.WriteUint8(0) || !writer.WriteUint16(0)) {
        return 0;
    }
    
    size_t body_start = writer.Offset();
    
    // Legacy version
    if (!writer.WriteUint16(kTlsLegacyVersion)) {
        return 0;
    }
    
    // Random
    if (!writer.WriteBytes(client_random, 32)) {
        return 0;
    }
    
    // Session ID (empty for QUIC)
    if (!writer.WriteUint8(0)) {
        return 0;
    }
    
    // Cipher Suites
    if (!writer.WriteUint16(2)) {
        return 0;
    }
    if (!writer.WriteUint16(kTls13Aes128GcmSha256)) {
        return 0;
    }
    
    // Compression Methods
    if (!writer.WriteUint8(1)) {
        return 0;
    }
    if (!writer.WriteUint8(0)) {
        return 0;
    }
    
    // Extensions
    if (!writer.WriteUint16(static_cast<uint16_t>(extensions_len))) {
        return 0;
    }
    if (!writer.WriteBytes(extensions.data(), extensions_len)) {
        return 0;
    }
    
    // Fix up message length
    size_t body_len = writer.Offset() - body_start;
    out[msg_start + 1] = static_cast<uint8_t>((body_len >> 16) & 0xFF);
    out[msg_start + 2] = static_cast<uint8_t>((body_len >> 8) & 0xFF);
    out[msg_start + 3] = static_cast<uint8_t>(body_len & 0xFF);
    
    // Now compute the binder
    // 1. Derive early_secret = HKDF-Extract(0, PSK)
    uint8_t zeros[32] = {0};
    uint8_t early_secret[32];
    if (!quic::HkdfExtract(zeros, 32, psk.psk, 32, early_secret)) {
        ESP_LOGE(TAG, "BuildClientHelloWithPsk: HkdfExtract(early_secret) failed");
        return 0;
    }
    
    // 2. Derive binder_key = Derive-Secret(early_secret, "res binder", "")
    uint8_t empty_hash[32];
    if (!quic::Sha256(nullptr, 0, empty_hash)) {
        ESP_LOGE(TAG, "BuildClientHelloWithPsk: Sha256(empty) failed");
        return 0;
    }
    
    const uint8_t* binder_label = reinterpret_cast<const uint8_t*>("res binder");
    uint8_t binder_key[32];
    if (!quic::HkdfExpandLabel(early_secret, 32, binder_label, 10, empty_hash, 32,
                                binder_key, 32)) {
        ESP_LOGE(TAG, "BuildClientHelloWithPsk: HkdfExpandLabel(binder_key) failed");
        return 0;
    }
    
    // 3. Compute transcript hash up to (but not including) binders
    // RFC 8446 Section 4.2.11.2: The transcript includes a partial ClientHello
    // up to and including the PreSharedKey extension's identities field,
    // but NOT including the binders_length and binders themselves.
    // binders_total_len = 2 (binders_length) + 1 (binder_length) + 32 (binder) = 35
    size_t hash_len = writer.Offset() - binders_total_len;
    uint8_t transcript_hash[32];
    if (!quic::Sha256(out, hash_len, transcript_hash)) {
        ESP_LOGE(TAG, "BuildClientHelloWithPsk: Sha256(transcript) failed");
        return 0;
    }
    
    ESP_LOGD(TAG, "PSK binder: hash_len=%zu, total_len=%zu, binders_excluded=%zu",
             hash_len, writer.Offset(), binders_total_len);
    
    // 4. Derive finished_key from binder_key
    const uint8_t* finished_label = reinterpret_cast<const uint8_t*>("finished");
    uint8_t finished_key[32];
    if (!quic::HkdfExpandLabel(binder_key, 32, finished_label, 8, nullptr, 0,
                                finished_key, 32)) {
        ESP_LOGE(TAG, "BuildClientHelloWithPsk: HkdfExpandLabel(finished_key) failed");
        return 0;
    }
    
    // 5. Compute binder = HMAC(finished_key, transcript_hash)
    uint8_t binder[32];
    if (!quic::HmacSha256(finished_key, 32, transcript_hash, 32, binder)) {
        ESP_LOGE(TAG, "BuildClientHelloWithPsk: HmacSha256(binder) failed");
        return 0;
    }
    
    // 6. Write the binder value into the message
    std::memcpy(out + (writer.Offset() - 32), binder, 32);
    
    ESP_LOGI(TAG, "Built ClientHello with PSK (ticket=%zu bytes, total=%zu bytes)",
             psk.identity.ticket.size(), writer.Offset());
    
    return writer.Offset();
}

//=============================================================================
// Parsing Helpers
//=============================================================================

size_t ParseHandshakeHeader(const uint8_t* data, size_t len,
                            HandshakeType* msg_type, uint32_t* msg_len) {
    if (len < 4) {
        return 0;
    }
    
    *msg_type = static_cast<HandshakeType>(data[0]);
    *msg_len = (static_cast<uint32_t>(data[1]) << 16) |
               (static_cast<uint32_t>(data[2]) << 8) |
               static_cast<uint32_t>(data[3]);
    
    return 4;
}

//=============================================================================
// ServerHello Parsing
//=============================================================================

bool ParseServerHello(const uint8_t* data, size_t len, ServerHelloData* out) {
    BufferReader reader(data, len);
    
    // Legacy version
    uint16_t legacy_version;
    if (!reader.ReadUint16(&legacy_version)) return false;
    
    // Random
    if (!reader.ReadBytes(out->server_random, 32)) return false;
    
    // Check for HelloRetryRequest magic
    static const uint8_t kHelloRetryRequestMagic[32] = {
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
    };
    out->is_hello_retry_request = 
        (std::memcmp(out->server_random, kHelloRetryRequestMagic, 32) == 0);
    
    // Session ID
    if (!reader.ReadUint8(&out->session_id_len)) return false;
    if (out->session_id_len > 32 || reader.Remaining() < out->session_id_len) {
        return false;
    }
    if (out->session_id_len > 0) {
        if (!reader.ReadBytes(out->session_id, out->session_id_len)) return false;
    }
    
    // Cipher Suite
    if (!reader.ReadUint16(&out->cipher_suite)) return false;
    
    // Compression Method
    if (!reader.ReadUint8(&out->compression_method)) return false;
    
    // Extensions
    uint16_t extensions_len;
    if (!reader.ReadUint16(&extensions_len)) return false;
    
    if (reader.Remaining() < extensions_len) return false;
    
    size_t ext_end = reader.Offset() + extensions_len;
    while (reader.Offset() < ext_end) {
        uint16_t ext_type, ext_len;
        if (!reader.ReadUint16(&ext_type)) return false;
        if (!reader.ReadUint16(&ext_len)) return false;
        
        if (reader.Remaining() < ext_len) return false;
        
        const uint8_t* ext_data = reader.Current();
        
        if (ext_type == static_cast<uint16_t>(ExtensionType::kSupportedVersions)) {
            if (ext_len >= 2) {
                out->selected_version = (static_cast<uint16_t>(ext_data[0]) << 8) |
                                        static_cast<uint16_t>(ext_data[1]);
            }
        } else if (ext_type == static_cast<uint16_t>(ExtensionType::kKeyShare)) {
            BufferReader ks_reader(ext_data, ext_len);
            uint16_t group;
            if (!ks_reader.ReadUint16(&group)) return false;
            out->key_share_group = group;
            
            uint16_t key_len;
            if (!ks_reader.ReadUint16(&key_len)) return false;
            
            if (key_len == 32 && ks_reader.Remaining() >= 32) {
                if (!ks_reader.ReadBytes(out->key_share_public_key, 32)) return false;
            }
        } else if (ext_type == static_cast<uint16_t>(ExtensionType::kPreSharedKey)) {
            // Pre-shared key extension in ServerHello contains only the selected identity index
            if (ext_len >= 2) {
                out->has_psk = true;
                out->selected_psk_identity = (static_cast<uint16_t>(ext_data[0]) << 8) |
                                             static_cast<uint16_t>(ext_data[1]);
            }
        }
        
        reader.Skip(ext_len);
    }
    
    return true;
}

//=============================================================================
// EncryptedExtensions Parsing
//=============================================================================

bool ParseEncryptedExtensions(const uint8_t* data, size_t len,
                               EncryptedExtensionsData* out) {
    BufferReader reader(data, len);
    
    // Extensions length
    uint16_t extensions_len;
    if (!reader.ReadUint16(&extensions_len)) return false;
    
    if (reader.Remaining() < extensions_len) return false;
    
    size_t ext_end = reader.Offset() + extensions_len;
    while (reader.Offset() < ext_end) {
        uint16_t ext_type, ext_len;
        if (!reader.ReadUint16(&ext_type)) return false;
        if (!reader.ReadUint16(&ext_len)) return false;
        
        if (reader.Remaining() < ext_len) return false;
        
        const uint8_t* ext_data = reader.Current();
        
        if (ext_type == static_cast<uint16_t>(ExtensionType::kALPN)) {
            // ALPN: 2-byte list length, then (1-byte name length, name)*
            if (ext_len >= 4) {
                uint8_t name_len = ext_data[2];
                if (name_len <= ext_len - 3) {
                    out->alpn.assign(reinterpret_cast<const char*>(ext_data + 3), 
                                     name_len);
                }
            }
        } else if (ext_type == static_cast<uint16_t>(ExtensionType::kQUICTransportParameters)) {
            if (quic::ParseTransportParameters(ext_data, ext_len, &out->transport_params)) {
                out->has_transport_params = true;
            }
        }
        
        reader.Skip(ext_len);
    }
    
    return true;
}

//=============================================================================
// Certificate Parsing
//=============================================================================

bool ParseCertificate(const uint8_t* data, size_t len, CertificateData* out) {
    BufferReader reader(data, len);
    
    // Certificate Request Context
    if (!reader.ReadUint8(&out->certificate_request_context_len)) return false;
    if (out->certificate_request_context_len > 0) {
        reader.Skip(out->certificate_request_context_len);
    }
    
    // Certificate List length (3 bytes)
    if (reader.Remaining() < 3) return false;
    uint32_t certs_len = (static_cast<uint32_t>(reader.Current()[0]) << 16) |
                         (static_cast<uint32_t>(reader.Current()[1]) << 8) |
                         static_cast<uint32_t>(reader.Current()[2]);
    reader.Skip(3);
    
    if (reader.Remaining() < certs_len) return false;
    
    size_t certs_end = reader.Offset() + certs_len;
    while (reader.Offset() < certs_end) {
        // Certificate data length (3 bytes)
        if (reader.Remaining() < 3) return false;
        uint32_t cert_len = (static_cast<uint32_t>(reader.Current()[0]) << 16) |
                            (static_cast<uint32_t>(reader.Current()[1]) << 8) |
                            static_cast<uint32_t>(reader.Current()[2]);
        reader.Skip(3);
        
        if (reader.Remaining() < cert_len) return false;
        
        CertificateEntry entry;
        entry.cert_data.assign(reader.Current(), reader.Current() + cert_len);
        out->certificates.push_back(std::move(entry));
        reader.Skip(cert_len);
        
        // Extensions length (2 bytes)
        uint16_t ext_len;
        if (!reader.ReadUint16(&ext_len)) return false;
        if (reader.Remaining() < ext_len) return false;
        reader.Skip(ext_len);
    }
    
    return true;
}

//=============================================================================
// CertificateVerify Parsing
//=============================================================================

bool ParseCertificateVerify(const uint8_t* data, size_t len,
                             CertificateVerifyData* out) {
    BufferReader reader(data, len);
    
    if (!reader.ReadUint16(&out->signature_algorithm)) return false;
    
    uint16_t sig_len;
    if (!reader.ReadUint16(&sig_len)) return false;
    
    if (reader.Remaining() < sig_len) return false;
    
    out->signature.assign(reader.Current(), reader.Current() + sig_len);
    
    return true;
}

//=============================================================================
// Finished Parsing
//=============================================================================

bool ParseFinished(const uint8_t* data, size_t len, FinishedData* out) {
    if (len < 32) {
        return false;
    }
    
    std::memcpy(out->verify_data, data, 32);
    return true;
}

//=============================================================================
// NewSessionTicket Parsing
//=============================================================================

bool ParseNewSessionTicket(const uint8_t* data, size_t len,
                            NewSessionTicketData* out) {
    BufferReader reader(data, len);
    
    if (!reader.ReadUint32(&out->ticket_lifetime)) return false;
    if (!reader.ReadUint32(&out->ticket_age_add)) return false;
    
    // Ticket nonce
    uint8_t nonce_len;
    if (!reader.ReadUint8(&nonce_len)) return false;
    if (reader.Remaining() < nonce_len) return false;
    out->ticket_nonce.assign(reader.Current(), reader.Current() + nonce_len);
    reader.Skip(nonce_len);
    
    // Ticket
    uint16_t ticket_len;
    if (!reader.ReadUint16(&ticket_len)) return false;
    if (reader.Remaining() < ticket_len) return false;
    out->ticket.assign(reader.Current(), reader.Current() + ticket_len);
    reader.Skip(ticket_len);
    
    // Parse extensions
    uint16_t ext_len;
    if (!reader.ReadUint16(&ext_len)) return false;
    
    // early_data extension type = 42 (0x002a)
    constexpr uint16_t kEarlyDataExtType = 42;
    
    size_t ext_end = reader.Offset() + ext_len;
    while (reader.Offset() < ext_end && reader.Remaining() >= 4) {
        uint16_t ext_type, ext_data_len;
        if (!reader.ReadUint16(&ext_type)) break;
        if (!reader.ReadUint16(&ext_data_len)) break;
        if (reader.Remaining() < ext_data_len) break;
        
        if (ext_type == kEarlyDataExtType) {
            out->has_early_data = true;
            // early_data extension contains max_early_data_size (4 bytes)
            if (ext_data_len >= 4) {
                reader.ReadUint32(&out->max_early_data_size);
            } else {
                reader.Skip(ext_data_len);
            }
        } else {
            reader.Skip(ext_data_len);
        }
    }
    
    return true;
}

} // namespace tls
} // namespace esp_http3

