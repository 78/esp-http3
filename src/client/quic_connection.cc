/**
 * @file quic_connection.cc
 * @brief QUIC Connection Implementation
 */

#include "client/quic_connection.h"
#include "client/ack_manager.h"
#include "client/flow_controller.h"
#include "client/loss_detector.h"
#include "h3/h3_handler.h"
#include "quic/quic_crypto.h"
#include "quic/quic_aead.h"
#include "quic/quic_packet.h"
#include "quic/quic_frame.h"
#include "tls/tls_handshake.h"

#include <cstring>
#include <map>
#include <random>
#include <esp_log.h>

namespace esp_http3 {

static const char* TAG = "QuicConnection";

// Helper to dump packet data in debug mode
static void DumpPacket(const char* direction, const uint8_t* data, size_t len, bool enabled) {
    if (!enabled || len == 0) return;
    
    ESP_LOGI(TAG, "%s packet (%zu bytes):", direction, len);
    
    // Print hex dump (max 64 bytes to avoid flooding)
    size_t dump_len = len > 64 ? 64 : len;
    char hex_line[50];  // 16 bytes * 3 chars = 48 + null
    
    for (size_t i = 0; i < dump_len; i += 16) {
        size_t line_len = 0;
        for (size_t j = 0; j < 16 && (i + j) < dump_len; j++) {
            line_len += snprintf(hex_line + line_len, sizeof(hex_line) - line_len, 
                                 "%02x ", data[i + j]);
        }
        ESP_LOGI(TAG, "  %04x: %s", (unsigned)i, hex_line);
    }
    
    if (len > 64) {
        ESP_LOGI(TAG, "  ... (%zu more bytes)", len - 64);
    }
}

//=============================================================================
// QuicConnection::Impl
//=============================================================================

class QuicConnection::Impl {
public:
    Impl(SendCallback send_cb, const QuicConfig& config);
    ~Impl();
    
    bool StartHandshake();
    void Close(int error_code, const std::string& reason);
    ConnectionState GetState() const { return state_; }
    bool IsConnected() const { return state_ == ConnectionState::kConnected; }
    
    void ProcessReceivedData(uint8_t* data, size_t len);
    void OnTimerTick(uint32_t elapsed_ms);
    
    int SendRequest(const std::string& method,
                    const std::string& path,
                    const std::vector<std::pair<std::string, std::string>>& headers,
                    const uint8_t* body, size_t body_len);
    
    int OpenStream(const std::string& method,
                   const std::string& path,
                   const std::vector<std::pair<std::string, std::string>>& headers);
    bool WriteStream(int stream_id, const uint8_t* data, size_t len);
    bool FinishStream(int stream_id);
    
    void SetOnConnected(OnConnectedCallback cb) { on_connected_ = std::move(cb); }
    void SetOnDisconnected(OnDisconnectedCallback cb) { on_disconnected_ = std::move(cb); }
    void SetOnResponse(OnResponseCallback cb) { on_response_ = std::move(cb); }
    void SetOnStreamData(OnStreamDataCallback cb) { on_stream_data_ = std::move(cb); }
    
    QuicConnection::Stats GetStats() const;

private:
    // Handshake processing
    bool SendInitialPacket(bool is_retransmit = false);
    size_t ProcessInitialPacket(uint8_t* data, size_t len);    // Returns consumed bytes
    size_t ProcessHandshakePacket(uint8_t* data, size_t len);  // Returns consumed bytes
    bool Process1RttPacket(uint8_t* data, size_t len);
    
    // TLS message processing
    bool ProcessServerHello(const uint8_t* data, size_t len);
    bool ProcessEncryptedExtensions(const uint8_t* data, size_t len);
    bool ProcessCertificate(const uint8_t* data, size_t len);
    bool ProcessCertificateVerify(const uint8_t* data, size_t len);
    bool ProcessServerFinished(const uint8_t* data, size_t len);
    bool SendClientFinished();
    
    // Frame processing
    void ProcessFrames(const uint8_t* data, size_t len, quic::PacketType pkt_type);
    void ProcessAckFrame(quic::BufferReader* reader, quic::PacketType pkt_type);
    void ProcessCryptoFrame(quic::BufferReader* reader, quic::PacketType pkt_type);
    void ProcessStreamFrame(quic::BufferReader* reader, uint8_t frame_type);
    void ProcessConnectionCloseFrame(quic::BufferReader* reader, bool is_app);
    void ProcessMaxDataFrame(quic::BufferReader* reader);
    void ProcessMaxStreamDataFrame(quic::BufferReader* reader);
    void ProcessHandshakeDoneFrame();
    void ProcessNewConnectionIdFrame(quic::BufferReader* reader);
    
    // Packet sending
    bool SendPacket(const uint8_t* data, size_t len);
    bool SendAckIfNeeded(quic::PacketType pkt_type);
    bool SendPendingFrames();
    
    // QUIC stream sending for H3
    bool SendStreamData(uint64_t stream_id, const uint8_t* data, 
                        size_t len, bool fin);
    
    // Flow control updates
    bool SendMaxDataFrame();
    bool SendMaxStreamDataFrame(uint64_t stream_id);
    void CheckAndSendFlowControlUpdates();
    
    // Generate random bytes
    void GenerateRandom(uint8_t* buf, size_t len);

private:
    SendCallback send_cb_;
    QuicConfig config_;
    ConnectionState state_ = ConnectionState::kIdle;
    
    // Callbacks
    OnConnectedCallback on_connected_;
    OnDisconnectedCallback on_disconnected_;
    OnResponseCallback on_response_;
    OnStreamDataCallback on_stream_data_;
    
    // Connection IDs
    quic::ConnectionId dcid_;           // Destination CID (server's)
    quic::ConnectionId scid_;           // Source CID (ours)
    quic::ConnectionId initial_dcid_;   // Original DCID
    
    // Crypto state
    quic::CryptoSecrets client_initial_secrets_;
    quic::CryptoSecrets server_initial_secrets_;
    quic::CryptoSecrets client_handshake_secrets_;
    quic::CryptoSecrets server_handshake_secrets_;
    quic::CryptoSecrets client_app_secrets_;
    quic::CryptoSecrets server_app_secrets_;
    
    uint8_t x25519_private_key_[32];
    uint8_t x25519_public_key_[32];
    uint8_t client_random_[32];
    uint8_t handshake_secret_[32];
    
    // TLS transcript hash
    quic::Sha256Context transcript_hash_;
    
    // Transport parameters
    quic::TransportParameters local_params_;
    quic::TransportParameters peer_params_;
    
    // Packet number spaces
    AckManager initial_ack_mgr_;
    AckManager handshake_ack_mgr_;
    AckManager app_ack_mgr_;
    
    SentPacketTracker initial_tracker_;
    SentPacketTracker handshake_tracker_;
    SentPacketTracker app_tracker_;
    
    // Flow control
    FlowController flow_controller_;
    
    // Loss detection
    LossDetector loss_detector_;
    
    // HTTP/3
    std::unique_ptr<h3::H3Handler> h3_handler_;
    
    // Crypto data buffers (for reassembly)
    std::vector<uint8_t> initial_crypto_buffer_;
    std::vector<uint8_t> handshake_crypto_buffer_;
    size_t initial_crypto_offset_ = 0;
    size_t handshake_crypto_offset_ = 0;
    
    // Out-of-order CRYPTO data cache: offset -> data
    // Used to buffer CRYPTO frames that arrive before their expected offset
    std::map<uint64_t, std::vector<uint8_t>> initial_crypto_cache_;
    std::map<uint64_t, std::vector<uint8_t>> handshake_crypto_cache_;
    
    // Timers
    uint64_t time_since_last_activity_us_ = 0;
    uint64_t handshake_start_time_us_ = 0;
    uint64_t current_time_us_ = 0;
    
    // Stats
    uint32_t packets_sent_ = 0;
    uint32_t packets_received_ = 0;
    uint32_t bytes_sent_ = 0;
    uint32_t bytes_received_ = 0;
    
    // Retry token
    std::vector<uint8_t> retry_token_;
    
    // Flags
    bool handshake_complete_ = false;
    bool h3_initialized_ = false;
    
    // Pre-allocated buffers to avoid heap allocation in hot paths
    uint8_t packet_buf_[1500];       // For building outgoing packets
    uint8_t payload_buf_[1500];      // For decrypted payloads
    uint8_t frame_buf_[1500];        // For building frames
};

//=============================================================================
// Impl Constructor/Destructor
//=============================================================================

QuicConnection::Impl::Impl(SendCallback send_cb, const QuicConfig& config)
    : send_cb_(std::move(send_cb))
    , config_(config) {
    
    h3_handler_ = std::make_unique<h3::H3Handler>();
    
    // Set up local transport parameters
    local_params_.max_idle_timeout = config_.idle_timeout_ms;
    local_params_.initial_max_data = config_.max_data;
    local_params_.initial_max_stream_data_bidi_local = config_.max_stream_data;
    local_params_.initial_max_stream_data_bidi_remote = config_.max_stream_data;
    local_params_.initial_max_stream_data_uni = config_.max_stream_data;
    local_params_.initial_max_streams_bidi = 100;
    local_params_.initial_max_streams_uni = 100;
    local_params_.active_connection_id_limit = 4;
    
    // Initialize flow controller
    flow_controller_.Initialize(config_.max_data, config_.max_stream_data);
}

QuicConnection::Impl::~Impl() = default;

//=============================================================================
// Connection Lifecycle
//=============================================================================

bool QuicConnection::Impl::StartHandshake() {
    if (state_ != ConnectionState::kIdle) {
        return false;
    }
    
    // Record start time for performance measurement
    uint64_t start_time_us = quic::GetCurrentTimeUs();
    
    state_ = ConnectionState::kHandshakeInProgress;
    handshake_start_time_us_ = start_time_us;
    current_time_us_ = handshake_start_time_us_;
    
    // Generate connection IDs
    GenerateRandom(scid_.data.data(), 8);
    scid_.length = 8;
    GenerateRandom(dcid_.data.data(), 8);
    dcid_.length = 8;
    initial_dcid_ = dcid_;
    
    // Set local SCID in transport params
    local_params_.initial_source_connection_id = scid_;
    
    // Generate X25519 key pair
    if (!quic::GenerateX25519KeyPair(x25519_private_key_, x25519_public_key_)) {
        state_ = ConnectionState::kFailed;
        return false;
    }
    
    // Generate client random
    GenerateRandom(client_random_, 32);
    
    // Derive initial secrets
    if (!quic::DeriveClientInitialSecrets(dcid_.Data(), dcid_.Length(),
                                           &client_initial_secrets_)) {
        state_ = ConnectionState::kFailed;
        return false;
    }
    
    if (!quic::DeriveServerInitialSecrets(dcid_.Data(), dcid_.Length(),
                                           &server_initial_secrets_)) {
        state_ = ConnectionState::kFailed;
        return false;
    }
    
    // Initialize transcript hash
    transcript_hash_.Reset();
    
    // Send Initial packet with ClientHello
    if (!SendInitialPacket()) {
        state_ = ConnectionState::kFailed;
        return false;
    }
    
    // Calculate and print elapsed time
    if (config_.enable_debug) {
        uint64_t end_time_us = quic::GetCurrentTimeUs();
        uint64_t elapsed_us = end_time_us - start_time_us;
        ESP_LOGI(TAG, "[PERF] StartHandshake took %llu us (%.3f ms)", 
                elapsed_us, elapsed_us / 1000.0f);
    }
    
    return true;
}

void QuicConnection::Impl::Close(int error_code, const std::string& reason) {
    if (state_ == ConnectionState::kClosed) {
        return;
    }
    
    // Build and send CONNECTION_CLOSE
    uint8_t frame_buf[256];
    quic::BufferWriter writer(frame_buf, sizeof(frame_buf));
    
    quic::BuildConnectionCloseFrame(&writer, 
                                     static_cast<uint64_t>(error_code), 
                                     0, reason);
    
    // Send in appropriate packet type (use pre-allocated member buffer)
    size_t packet_len = 0;
    
    if (handshake_complete_) {
        packet_len = quic::Build1RttPacket(dcid_,
                                            app_tracker_.AllocatePacketNumber(),
                                            false, false,
                                            frame_buf, writer.Offset(),
                                            client_app_secrets_,
                                            packet_buf_, sizeof(packet_buf_));
    } else {
        packet_len = quic::BuildInitialPacket(dcid_, scid_,
                                               retry_token_.data(), 
                                               retry_token_.size(),
                                               initial_tracker_.AllocatePacketNumber(),
                                               frame_buf, writer.Offset(),
                                               client_initial_secrets_,
                                               packet_buf_, sizeof(packet_buf_));
    }
    
    if (packet_len > 0) {
        SendPacket(packet_buf_, packet_len);
    }
    
    state_ = ConnectionState::kClosed;
    
    if (on_disconnected_) {
        on_disconnected_(error_code, reason);
    }
}

//=============================================================================
// Initial Packet
//=============================================================================

bool QuicConnection::Impl::SendInitialPacket(bool is_retransmit) {
    // Build ClientHello (use payload_buf_ temporarily)
    size_t ch_len = tls::BuildClientHello(config_.hostname,
                                           client_random_,
                                           x25519_public_key_,
                                           local_params_,
                                           payload_buf_, sizeof(payload_buf_));
    if (ch_len == 0) {
        ESP_LOGE(TAG, "BuildClientHello failed");
        return false;
    }
    
    // Update transcript hash only on first send, not on retransmit
    // PTO retransmits the same ClientHello, so transcript hash should not be updated again
    if (!is_retransmit) {
        transcript_hash_.Update(payload_buf_, ch_len);
    }
    
    // Build CRYPTO frame
    quic::BufferWriter writer(frame_buf_, sizeof(frame_buf_));
    if (!quic::BuildCryptoFrame(&writer, 0, payload_buf_, ch_len)) {
        ESP_LOGE(TAG, "BuildCryptoFrame failed");
        return false;
    }
    
    // Build Initial packet
    uint64_t pn = initial_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::BuildInitialPacket(dcid_, scid_,
                                                  retry_token_.data(),
                                                  retry_token_.size(),
                                                  pn,
                                                  frame_buf_, writer.Offset(),
                                                  client_initial_secrets_,
                                                  packet_buf_, sizeof(packet_buf_),
                                                  1200);  // Minimum 1200 bytes
    
    if (packet_len == 0) {
        ESP_LOGE(TAG, "BuildInitialPacket failed");
        return false;
    }
    
    // Track sent packet
    initial_tracker_.OnPacketSent(pn, current_time_us_, packet_len, true);
    loss_detector_.OnPacketSent(pn, current_time_us_, packet_len, true);
    
    return SendPacket(packet_buf_, packet_len);
}

//=============================================================================
// Packet Processing
//=============================================================================

void QuicConnection::Impl::ProcessReceivedData(uint8_t* data, size_t len) {
    if (len == 0 || state_ == ConnectionState::kClosed) {
        return;
    }
    
    // Record start time for performance measurement
    uint64_t start_time_us = quic::GetCurrentTimeUs();
    
    current_time_us_ = start_time_us;
    time_since_last_activity_us_ = 0;
    packets_received_++;
    bytes_received_ += len;
    
    // Process coalesced packets in a loop (data is mutable, no copy needed)
    size_t offset = 0;
    while (offset < len) {
        uint8_t* pkt_data = data + offset;
        size_t pkt_len = len - offset;
        size_t consumed = 0;
        
        // Check packet type
        if (quic::IsLongHeader(pkt_data[0])) {
            quic::PacketType type = quic::GetLongHeaderType(pkt_data[0]);
        
        switch (type) {
            case quic::PacketType::kInitial:
                    consumed = ProcessInitialPacket(pkt_data, pkt_len);
                break;
            case quic::PacketType::kHandshake:
                    consumed = ProcessHandshakePacket(pkt_data, pkt_len);
                break;
            case quic::PacketType::kRetry:
                    // Handle Retry (no coalescing for Retry)
                {
                    ESP_LOGI(TAG, "Received Retry packet");
                    quic::PacketInfo info;
                    quic::ConnectionId new_scid;
                    std::vector<uint8_t> token;
                        if (quic::ParseRetryPacket(pkt_data, pkt_len,
                                                initial_dcid_, &info,
                                                &new_scid, &token)) {
                        // Update DCID and retry token
                        dcid_ = new_scid;
                        retry_token_ = std::move(token);
                        
                        // Re-derive initial secrets with new DCID
                        quic::DeriveClientInitialSecrets(dcid_.Data(), dcid_.Length(),
                                                          &client_initial_secrets_);
                        quic::DeriveServerInitialSecrets(dcid_.Data(), dcid_.Length(),
                                                          &server_initial_secrets_);
                        
                        // Resend Initial
                        initial_tracker_.Reset();
                        transcript_hash_.Reset();
                        SendInitialPacket();
                    }
                }
                    consumed = pkt_len;  // Retry packet consumes the rest
                break;
            default:
                ESP_LOGW(TAG, "Unknown long header type: %d", static_cast<int>(type));
                    consumed = pkt_len;  // Skip rest on error
                break;
        }
    } else {
            // Short header (1-RTT) - typically no coalescing
            Process1RttPacket(pkt_data, pkt_len);
            consumed = pkt_len;
        }
        
        // Move to next packet
        if (consumed == 0) {
            // Processing failed, skip rest
            break;
        }
        offset += consumed;
        
        // Check for more coalesced packets
        if (offset < len) {
            ESP_LOGD(TAG, "Processing coalesced packet at offset %zu", offset);
        }
    }
    
    // Calculate and print elapsed time
    if (config_.enable_debug) {
        uint64_t end_time_us = quic::GetCurrentTimeUs();
        uint64_t elapsed_us = end_time_us - start_time_us;
        ESP_LOGI(TAG, "[PERF] ProcessReceivedData took %llu us (%.3f ms), packet size: %zu bytes", 
                elapsed_us, elapsed_us / 1000.0f, len);
    }
}

size_t QuicConnection::Impl::ProcessInitialPacket(uint8_t* data, size_t len) {
    // Check version field (bytes 1-4) - detect Version Negotiation
    if (len >= 5) {
        uint32_t version = (static_cast<uint32_t>(data[1]) << 24) |
                          (static_cast<uint32_t>(data[2]) << 16) |
                          (static_cast<uint32_t>(data[3]) << 8) |
                          static_cast<uint32_t>(data[4]);
        
        if (version == 0) {
            ESP_LOGW(TAG, "Received Version Negotiation! Server doesn't support our version.");
            // Log supported versions from server
            size_t offset = 5;
            // Skip DCID length + DCID
            if (offset < len) {
                uint8_t dcid_len = data[offset++];
                offset += dcid_len;
            }
            // Skip SCID length + SCID
            if (offset < len) {
                uint8_t scid_len = data[offset++];
                offset += scid_len;
            }
            // Log supported versions
            ESP_LOGI(TAG, "Server supported versions:");
            while (offset + 4 <= len) {
                uint32_t sv = (static_cast<uint32_t>(data[offset]) << 24) |
                              (static_cast<uint32_t>(data[offset+1]) << 16) |
                              (static_cast<uint32_t>(data[offset+2]) << 8) |
                              static_cast<uint32_t>(data[offset+3]);
                ESP_LOGI(TAG, "  0x%08lx", (unsigned long)sv);
                offset += 4;
            }
            return 0;  // Version negotiation failure
        }
    }
    
    quic::PacketInfo info;
    
    size_t payload_len = quic::DecryptInitialPacket(
        data, len,
        server_initial_secrets_,
        initial_ack_mgr_.GetLargestReceived(),
        &info,
        payload_buf_, sizeof(payload_buf_));
    
    if (payload_len == 0) {
        if (config_.enable_debug) {
            ESP_LOGW(TAG, "DecryptInitialPacket failed (len=%zu)", len);
        }
        return 0;  // Decryption failed
    }
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "Decrypted Initial packet, PN=%llu, payload=%zu bytes, packet_size=%zu",
                 (unsigned long long)info.packet_number, payload_len, info.packet_size);
    }
    
    // Update DCID from SCID in response
    dcid_ = info.long_header.scid;
    
    // Record received packet
    initial_ack_mgr_.OnPacketReceived(info.packet_number, current_time_us_);
    
    // Process frames
    ProcessFrames(payload_buf_, payload_len, quic::PacketType::kInitial);
    
    return info.packet_size;  // Return consumed bytes for coalesced packet handling
}

size_t QuicConnection::Impl::ProcessHandshakePacket(uint8_t* data, size_t len) {
    if (!server_handshake_secrets_.valid) {
        return 0;  // Haven't derived handshake keys yet
    }
    
    quic::PacketInfo info;
    
    size_t payload_len = quic::DecryptHandshakePacket(
        data, len,
        server_handshake_secrets_,
        handshake_ack_mgr_.GetLargestReceived(),
        &info,
        payload_buf_, sizeof(payload_buf_));
    
    if (payload_len == 0) {
        if (config_.enable_debug) {
            ESP_LOGW(TAG, "DecryptHandshakePacket failed");
        }
        return 0;  // Decryption failed
    }
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "Decrypted Handshake packet, PN=%llu, payload=%zu bytes, packet_size=%zu",
                 (unsigned long long)info.packet_number, payload_len, info.packet_size);
    }
    
    handshake_ack_mgr_.OnPacketReceived(info.packet_number, current_time_us_);
    ProcessFrames(payload_buf_, payload_len, quic::PacketType::kHandshake);
    
    return info.packet_size;  // Return consumed bytes for coalesced packet handling
}

bool QuicConnection::Impl::Process1RttPacket(uint8_t* data, size_t len) {
    if (!server_app_secrets_.valid) {
        return false;
    }
    
    quic::PacketInfo info;
    
    size_t payload_len = quic::Decrypt1RttPacket(
        data, len,
        scid_.Length(),  // Our SCID length is the expected DCID length
        server_app_secrets_,
        app_ack_mgr_.GetLargestReceived(),
        &info,
        payload_buf_, sizeof(payload_buf_));
    
    if (payload_len == 0) {
        if (config_.enable_debug) {
            ESP_LOGW(TAG, "Decrypt1RttPacket failed");
        }
        return false;
    }
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "Decrypted 1-RTT packet, PN=%llu, payload=%zu bytes",
                 (unsigned long long)info.packet_number, payload_len);
    }
    
    app_ack_mgr_.OnPacketReceived(info.packet_number, current_time_us_);
    ProcessFrames(payload_buf_, payload_len, quic::PacketType::k1Rtt);
    
    return true;
}

//=============================================================================
// Frame Processing
//=============================================================================

void QuicConnection::Impl::ProcessFrames(const uint8_t* data, size_t len,
                                          quic::PacketType pkt_type) {
    quic::BufferReader reader(data, len);
    
    const char* pkt_type_str = (pkt_type == quic::PacketType::kInitial) ? "Initial" :
                               (pkt_type == quic::PacketType::kHandshake) ? "Handshake" : "1-RTT";
    
    while (reader.Remaining() > 0) {
        uint8_t frame_type;
        if (!reader.ReadUint8(&frame_type)) {
            break;
        }
        
        // Handle frame based on type
        if (frame_type == 0x00) {
            // PADDING - skip
            quic::ParsePaddingFrames(&reader);
        } else if (frame_type == 0x01) {
            // PING - no action needed
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "[%s] Frame: PING", pkt_type_str);
            }
        } else if (frame_type == 0x02 || frame_type == 0x03) {
            // ACK or ACK_ECN
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "[%s] Frame: ACK%s", pkt_type_str, 
                         frame_type == 0x03 ? "_ECN" : "");
            }
            reader.Seek(reader.Offset() - 1);  // Back up to include frame type
            ProcessAckFrame(&reader, pkt_type);
        } else if (frame_type == 0x06) {
            // CRYPTO
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "[%s] Frame: CRYPTO", pkt_type_str);
            }
            ProcessCryptoFrame(&reader, pkt_type);
        } else if (frame_type >= 0x08 && frame_type <= 0x0f) {
            // STREAM
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "[%s] Frame: STREAM (type=0x%02x)", pkt_type_str, frame_type);
            }
            ProcessStreamFrame(&reader, frame_type);
        } else if (frame_type == 0x10) {
            // MAX_DATA
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "[%s] Frame: MAX_DATA", pkt_type_str);
            }
            ProcessMaxDataFrame(&reader);
        } else if (frame_type == 0x11) {
            // MAX_STREAM_DATA
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "[%s] Frame: MAX_STREAM_DATA", pkt_type_str);
            }
            ProcessMaxStreamDataFrame(&reader);
        } else if (frame_type == 0x12 || frame_type == 0x13) {
            // MAX_STREAMS (0x12=bidi, 0x13=uni)
            // Server is increasing the stream limit - just read and log
            uint64_t max_streams;
            if (reader.ReadVarint(&max_streams)) {
                if (config_.enable_debug) {
                    ESP_LOGI(TAG, "[%s] Frame: MAX_STREAMS_%s, limit=%llu", pkt_type_str,
                             frame_type == 0x12 ? "BIDI" : "UNI", 
                             (unsigned long long)max_streams);
                }
            }
        } else if (frame_type == 0x14) {
            // DATA_BLOCKED - peer is blocked on connection-level flow control
            uint64_t limit;
            if (reader.ReadVarint(&limit)) {
                if (config_.enable_debug) {
                    ESP_LOGI(TAG, "[%s] Frame: DATA_BLOCKED at limit=%llu", pkt_type_str,
                             (unsigned long long)limit);
                }
                // Send MAX_DATA to unblock the peer
                SendMaxDataFrame();
            }
        } else if (frame_type == 0x15) {
            // STREAM_DATA_BLOCKED - peer is blocked on stream-level flow control  
            uint64_t stream_id, limit;
            if (reader.ReadVarint(&stream_id) && reader.ReadVarint(&limit)) {
                if (config_.enable_debug) {
                    ESP_LOGI(TAG, "[%s] Frame: STREAM_DATA_BLOCKED stream=%llu, limit=%llu", 
                             pkt_type_str, (unsigned long long)stream_id, 
                             (unsigned long long)limit);
                }
                // Send MAX_STREAM_DATA to unblock the stream
                SendMaxStreamDataFrame(stream_id);
            }
        } else if (frame_type == 0x16 || frame_type == 0x17) {
            // STREAMS_BLOCKED (0x16=bidi, 0x17=uni) - peer is blocked on stream creation
            uint64_t limit;
            if (reader.ReadVarint(&limit)) {
                if (config_.enable_debug) {
                    ESP_LOGI(TAG, "[%s] Frame: STREAMS_BLOCKED_%s at limit=%llu", pkt_type_str,
                             frame_type == 0x16 ? "BIDI" : "UNI",
                             (unsigned long long)limit);
                }
            }
        } else if (frame_type == 0x18) {
            // NEW_CONNECTION_ID
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "[%s] Frame: NEW_CONNECTION_ID", pkt_type_str);
            }
            ProcessNewConnectionIdFrame(&reader);
        } else if (frame_type == 0x1c) {
            // CONNECTION_CLOSE
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "[%s] Frame: CONNECTION_CLOSE", pkt_type_str);
            }
            ProcessConnectionCloseFrame(&reader, false);
        } else if (frame_type == 0x1d) {
            // APPLICATION_CLOSE
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "[%s] Frame: APPLICATION_CLOSE", pkt_type_str);
            }
            ProcessConnectionCloseFrame(&reader, true);
        } else if (frame_type == 0x1e) {
            // HANDSHAKE_DONE
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "[%s] Frame: HANDSHAKE_DONE", pkt_type_str);
            }
            ProcessHandshakeDoneFrame();
        } else {
            // Unknown frame - try to skip
            if (config_.enable_debug) {
                ESP_LOGW(TAG, "[%s] Unknown frame type: 0x%02x, remaining=%zu", 
                         pkt_type_str, frame_type, reader.Remaining());
            }
            // For now, just break
            break;
        }
    }
    
    SendAckIfNeeded(pkt_type);
}

void QuicConnection::Impl::ProcessAckFrame(quic::BufferReader* reader,
                                            quic::PacketType pkt_type) {
    uint8_t frame_type = 0;
    if (!reader->ReadUint8(&frame_type)) {
        return;
    }
    
    quic::AckFrameData ack_data;
    bool ok = (frame_type == 0x03) ? 
              quic::ParseAckEcnFrame(reader, &ack_data) :
              quic::ParseAckFrame(reader, &ack_data);
    
    if (!ok) return;
    
    // Process ACK based on packet number space
    SentPacketTracker* tracker = nullptr;
    switch (pkt_type) {
        case quic::PacketType::kInitial:
            tracker = &initial_tracker_;
            break;
        case quic::PacketType::kHandshake:
            tracker = &handshake_tracker_;
            break;
        default:
            tracker = &app_tracker_;
            break;
    }
    
    size_t newly_acked;
    tracker->OnAckReceived(ack_data.largest_ack,
                           ack_data.ack_delay,
                           ack_data.first_ack_range,
                           ack_data.ack_ranges,
                           current_time_us_,
                           &newly_acked);
    
    // Update loss detector with RTT
    if (tracker->GetLatestRttUs() > 0) {
        loss_detector_.GetRttEstimator().OnRttSample(
            tracker->GetLatestRttUs(),
            ack_data.ack_delay << initial_ack_mgr_.GetAckDelayExponent());
    }
}

void QuicConnection::Impl::ProcessCryptoFrame(quic::BufferReader* reader,
                                               quic::PacketType pkt_type) {
    quic::CryptoFrameData crypto_data;
    if (!quic::ParseCryptoFrame(reader, &crypto_data)) {
        ESP_LOGW(TAG, "ProcessCryptoFrame: ParseCryptoFrame failed");
        return;
    }
    
    // Select buffer and cache based on packet type
    std::vector<uint8_t>* buffer;
    size_t* expected_offset;
    std::map<uint64_t, std::vector<uint8_t>>* cache;
    const char* space_name;
    
    if (pkt_type == quic::PacketType::kInitial) {
        buffer = &initial_crypto_buffer_;
        expected_offset = &initial_crypto_offset_;
        cache = &initial_crypto_cache_;
        space_name = "Initial";
    } else {
        buffer = &handshake_crypto_buffer_;
        expected_offset = &handshake_crypto_offset_;
        cache = &handshake_crypto_cache_;
        space_name = "Handshake";
    }
    
    uint64_t offset = crypto_data.offset;
    size_t length = crypto_data.length;
    
    // Handle out-of-order or duplicate data
    if (offset > *expected_offset) {
        // Future data - cache it for later reassembly
        ESP_LOGD(TAG, "CRYPTO[%s]: caching out-of-order data, offset=%llu len=%zu (expected %zu)",
                 space_name, (unsigned long long)offset, length, *expected_offset);
        
        // Only cache if not already present (avoid duplicates)
        if (cache->find(offset) == cache->end()) {
            (*cache)[offset] = std::vector<uint8_t>(crypto_data.data, 
                                                     crypto_data.data + length);
        }
        return;
    } else if (offset + length <= *expected_offset) {
        // Completely duplicate data - ignore
        ESP_LOGD(TAG, "CRYPTO[%s]: ignoring duplicate data, offset=%llu len=%zu",
                 space_name, (unsigned long long)offset, length);
        return;
    } else if (offset < *expected_offset) {
        // Partially overlapping data - extract the new portion
        size_t skip = *expected_offset - offset;
        crypto_data.data += skip;
        crypto_data.length -= skip;
        offset = *expected_offset;
        length = crypto_data.length;
        ESP_LOGD(TAG, "CRYPTO[%s]: trimmed overlapping data, new offset=%llu len=%zu",
                 space_name, (unsigned long long)offset, length);
    }
    
    // Append the in-order data
    buffer->insert(buffer->end(), 
                   crypto_data.data, 
                   crypto_data.data + length);
    *expected_offset += length;
    
    // Try to append any cached data that is now contiguous
    while (!cache->empty()) {
        auto it = cache->begin();
        uint64_t cached_offset = it->first;
        
        if (cached_offset > *expected_offset) {
            // Gap still exists, can't process more
            break;
        } else if (cached_offset + it->second.size() <= *expected_offset) {
            // This cached entry is now fully covered, remove it
            cache->erase(it);
            continue;
        } else if (cached_offset < *expected_offset) {
            // Partial overlap with cached data
            size_t skip = *expected_offset - cached_offset;
            buffer->insert(buffer->end(), 
                           it->second.begin() + skip, 
                           it->second.end());
            *expected_offset += (it->second.size() - skip);
            cache->erase(it);
        } else {
            // cached_offset == *expected_offset, perfect match
            buffer->insert(buffer->end(), it->second.begin(), it->second.end());
            *expected_offset += it->second.size();
            cache->erase(it);
        }
    }
    
    // Process TLS messages from the reassembled buffer
    while (buffer->size() >= 4) {
        tls::HandshakeType msg_type;
        uint32_t msg_len;
        size_t hdr_len = tls::ParseHandshakeHeader(buffer->data(), 
                                                    buffer->size(),
                                                    &msg_type, &msg_len);
        if (hdr_len == 0 || buffer->size() < hdr_len + msg_len) {
            ESP_LOGD(TAG, "TLS: waiting for more data, have %zu, need %lu",
                     buffer->size(), msg_len + 4);
            break;
        }
        
        const uint8_t* msg_data = buffer->data() + hdr_len;
        
        switch (msg_type) {
            case tls::HandshakeType::kServerHello:
                ESP_LOGD(TAG, "Processing Server Hello");
                transcript_hash_.Update(buffer->data(), hdr_len + msg_len);
                ProcessServerHello(msg_data, msg_len);
                break;
                
            case tls::HandshakeType::kEncryptedExtensions:
                ESP_LOGD(TAG, "Processing EncryptedExtensions");
                transcript_hash_.Update(buffer->data(), hdr_len + msg_len);
                ProcessEncryptedExtensions(msg_data, msg_len);
                break;
                
            case tls::HandshakeType::kCertificate:
                ESP_LOGD(TAG, "Processing Certificate");
                transcript_hash_.Update(buffer->data(), hdr_len + msg_len);
                ProcessCertificate(msg_data, msg_len);
                break;
                
            case tls::HandshakeType::kCertificateVerify:
                ESP_LOGD(TAG, "Processing CertificateVerify");
                transcript_hash_.Update(buffer->data(), hdr_len + msg_len);
                ProcessCertificateVerify(msg_data, msg_len);
                break;
                
            case tls::HandshakeType::kFinished:
                ESP_LOGD(TAG, "Processing Server Finished");
                transcript_hash_.Update(buffer->data(), hdr_len + msg_len);
                ProcessServerFinished(msg_data, msg_len);
                break;
                
            default:
                ESP_LOGW(TAG, "Unknown TLS message type: %d", 
                         static_cast<int>(msg_type));
                transcript_hash_.Update(buffer->data(), hdr_len + msg_len);
                break;
        }
        
        buffer->erase(buffer->begin(), buffer->begin() + hdr_len + msg_len);
    }
}

bool QuicConnection::Impl::ProcessServerHello(const uint8_t* data, size_t len) {
    tls::ServerHelloData sh;
    if (!tls::ParseServerHello(data, len, &sh)) {
        ESP_LOGW(TAG, "ProcessServerHello: ParseServerHello failed");
        return false;
    }
    
    ESP_LOGD(TAG, "ServerHello: cipher=0x%04x, key_share_group=0x%04x", 
             sh.cipher_suite, sh.key_share_group);
    
    if (sh.is_hello_retry_request) {
        // Handle HRR - for now, fail
        ESP_LOGW(TAG, "ProcessServerHello: HelloRetryRequest not supported");
        state_ = ConnectionState::kFailed;
        return false;
    }
    
    // Compute shared secret
    uint8_t shared_secret[32];
    if (!quic::X25519ECDH(x25519_private_key_, sh.key_share_public_key,
                          shared_secret)) {
        ESP_LOGW(TAG, "ProcessServerHello: X25519ECDH failed");
        state_ = ConnectionState::kFailed;
        return false;
    }
    
    // Get transcript hash up to ServerHello
    uint8_t transcript[32];
    transcript_hash_.GetHash(transcript);
    
    // Derive handshake secrets
    if (!quic::DeriveHandshakeSecrets(shared_secret, transcript,
                                       &client_handshake_secrets_,
                                       &server_handshake_secrets_,
                                       handshake_secret_)) {
        ESP_LOGW(TAG, "ProcessServerHello: DeriveHandshakeSecrets failed");
        state_ = ConnectionState::kFailed;
        return false;
    }
    
    return true;
}

bool QuicConnection::Impl::ProcessEncryptedExtensions(const uint8_t* data, 
                                                       size_t len) {
    tls::EncryptedExtensionsData ee;
    if (!tls::ParseEncryptedExtensions(data, len, &ee)) {
        return false;
    }
    
    if (ee.has_transport_params) {
        peer_params_ = ee.transport_params;
        
        // Update flow controller with peer limits
        flow_controller_.OnMaxDataReceived(peer_params_.initial_max_data);
        loss_detector_.SetMaxAckDelay(peer_params_.max_ack_delay);
    }
    
    return true;
}

bool QuicConnection::Impl::ProcessCertificate(const uint8_t* data, size_t len) {
    tls::CertificateData cert;
    if (!tls::ParseCertificate(data, len, &cert)) {
        return false;
    }
    
    // TODO: Verify certificate chain
    // For embedded systems, we might skip or simplify this
    
    return true;
}

bool QuicConnection::Impl::ProcessCertificateVerify(const uint8_t* data, 
                                                     size_t len) {
    tls::CertificateVerifyData cv;
    if (!tls::ParseCertificateVerify(data, len, &cv)) {
        return false;
    }
    
    // TODO: Verify signature
    
    return true;
}

bool QuicConnection::Impl::ProcessServerFinished(const uint8_t* data, size_t len) {
    tls::FinishedData fin;
    if (!tls::ParseFinished(data, len, &fin)) {
        ESP_LOGW(TAG, "ProcessServerFinished: ParseFinished failed");
        return false;
    }
    
    // TODO: Verify finished MAC
    
    // Derive application secrets
    uint8_t transcript[32];
    transcript_hash_.GetHash(transcript);
    
    uint8_t master_secret[32];
    if (!quic::DeriveApplicationSecrets(handshake_secret_, transcript,
                                         &client_app_secrets_,
                                         &server_app_secrets_,
                                         master_secret)) {
        ESP_LOGW(TAG, "DeriveApplicationSecrets failed");
        state_ = ConnectionState::kFailed;
        return false;
    }
    
    ESP_LOGD(TAG, "Application secrets derived, sending Client Finished");
    
    // Send Client Finished
    return SendClientFinished();
}

bool QuicConnection::Impl::SendClientFinished() {
    // Get transcript hash before Finished
    uint8_t transcript[32];
    transcript_hash_.GetHash(transcript);
    
    // Build Finished message
    uint8_t finished_msg[36];
    size_t finished_len;
    if (!quic::BuildClientFinishedMessage(client_handshake_secrets_.traffic_secret.data(),
                                           transcript,
                                           finished_msg, &finished_len)) {
        ESP_LOGW(TAG, "BuildClientFinishedMessage failed");
        return false;
    }
    
    // Update transcript with our Finished
    transcript_hash_.Update(finished_msg, finished_len);
    
    // Build CRYPTO frame
    uint8_t frames[64];
    quic::BufferWriter writer(frames, sizeof(frames));
    if (!quic::BuildCryptoFrame(&writer, 0, finished_msg, finished_len)) {
        ESP_LOGW(TAG, "BuildCryptoFrame failed");
        return false;
    }
    
    // Build Handshake packet
    uint8_t packet[512];
    uint64_t pn = handshake_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::BuildHandshakePacket(dcid_, scid_,
                                                    pn,
                                                    frames, writer.Offset(),
                                                    client_handshake_secrets_,
                                                    packet, sizeof(packet));
    
    if (packet_len == 0) {
        ESP_LOGW(TAG, "BuildHandshakePacket failed");
        return false;
    }
    
    ESP_LOGD(TAG, "Sending Client Finished in Handshake packet, PN=%llu, len=%zu",
             (unsigned long long)pn, packet_len);
    
    handshake_tracker_.OnPacketSent(pn, current_time_us_, packet_len, true);
    loss_detector_.OnPacketSent(pn, current_time_us_, packet_len, true);
    
    bool ok = SendPacket(packet, packet_len);
    if (ok) {
        state_ = ConnectionState::kConnected;
    }
    return ok;
}

void QuicConnection::Impl::ProcessHandshakeDoneFrame() {
    handshake_complete_ = true;
    state_ = ConnectionState::kConnected;
    
    // Initialize HTTP/3
    if (!h3_initialized_) {
        h3_handler_->Initialize(0, 2);  // Client stream IDs
        
        h3_handler_->SetSendStream([this](uint64_t stream_id, 
                                           const uint8_t* data,
                                           size_t len, bool fin) {
            return SendStreamData(stream_id, data, len, fin);
        });
        
        h3_handler_->SetOnResponse([this](uint64_t stream_id,
                                           const h3::H3Response& response) {
            if (on_response_) {
                H3Response resp;
                resp.status = response.status;
                resp.headers = response.headers;
                resp.body = response.body;
                resp.complete = response.complete;
                on_response_(static_cast<int>(stream_id), resp);
            }
        });
        
        h3_handler_->SetOnStreamData([this](uint64_t stream_id,
                                             const uint8_t* data,
                                             size_t len, bool fin) {
            if (on_stream_data_) {
                on_stream_data_(static_cast<int>(stream_id), data, len, fin);
            }
        });
        
        // Send SETTINGS
        h3_handler_->SendSettings();
        h3_initialized_ = true;
    }
    
    if (on_connected_) {
        on_connected_();
    }
}

void QuicConnection::Impl::ProcessStreamFrame(quic::BufferReader* reader,
                                               uint8_t frame_type) {
    quic::StreamFrameData stream_data;
    if (!quic::ParseStreamFrame(reader, frame_type, &stream_data)) {
        if (config_.enable_debug) {
            ESP_LOGW(TAG, "ParseStreamFrame failed");
        }
        return;
    }
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "  STREAM: id=%llu, offset=%llu, len=%zu, fin=%d",
                 (unsigned long long)stream_data.stream_id,
                 (unsigned long long)stream_data.offset,
                 stream_data.length,
                 stream_data.fin ? 1 : 0);
    }
    
    // Update flow control
    flow_controller_.OnStreamBytesReceived(stream_data.stream_id, 
                                            stream_data.length);
    
    // Pass to H3 handler with offset for proper reassembly
    if (h3_handler_) {
        h3_handler_->OnStreamData(stream_data.stream_id,
                                   stream_data.offset,  // Add offset for reassembly
                                   stream_data.data,
                                   stream_data.length,
                                   stream_data.fin);
    } else if (config_.enable_debug) {
        ESP_LOGW(TAG, "  No H3 handler set, stream data dropped!");
    }
    
    // Check if we should send flow control updates proactively
    // This prevents the peer from becoming blocked
    if (flow_controller_.ShouldSendMaxData()) {
        SendMaxDataFrame();
    }
    if (flow_controller_.ShouldSendMaxStreamData(stream_data.stream_id)) {
        SendMaxStreamDataFrame(stream_data.stream_id);
    }
}

void QuicConnection::Impl::ProcessConnectionCloseFrame(quic::BufferReader* reader,
                                                        bool is_app) {
    quic::ConnectionCloseData close_data;
    if (!quic::ParseConnectionCloseFrame(reader, is_app, &close_data)) {
        return;
    }
    
    state_ = ConnectionState::kClosed;
    
    if (on_disconnected_) {
        on_disconnected_(static_cast<int>(close_data.error_code), 
                         close_data.reason);
    }
}

void QuicConnection::Impl::ProcessMaxDataFrame(quic::BufferReader* reader) {
    uint64_t max_data;
    if (quic::ParseMaxDataFrame(reader, &max_data)) {
        flow_controller_.OnMaxDataReceived(max_data);
    }
}

void QuicConnection::Impl::ProcessMaxStreamDataFrame(quic::BufferReader* reader) {
    uint64_t stream_id, max_stream_data;
    if (quic::ParseMaxStreamDataFrame(reader, &stream_id, &max_stream_data)) {
        flow_controller_.OnMaxStreamDataReceived(stream_id, max_stream_data);
    }
}

void QuicConnection::Impl::ProcessNewConnectionIdFrame(quic::BufferReader* reader) {
    uint64_t seq, retire;
    quic::ConnectionId cid;
    uint8_t token[16];
    
    if (quic::ParseNewConnectionIdFrame(reader, &seq, &retire, &cid, token)) {
        // Store new connection ID for migration (not implemented in v1)
    }
}

//=============================================================================
// Flow Control Updates
//=============================================================================

bool QuicConnection::Impl::SendMaxDataFrame() {
    if (!client_app_secrets_.valid) {
        return false;
    }
    
    // Build MAX_DATA frame
    uint8_t frames[32];
    quic::BufferWriter writer(frames, sizeof(frames));
    
    if (!flow_controller_.BuildMaxDataFrame(&writer)) {
        return false;
    }
    
    // Build 1-RTT packet
    uint8_t packet[256];
    uint64_t pn = app_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::Build1RttPacket(dcid_, pn, false, false,
                                               frames, writer.Offset(),
                                               client_app_secrets_,
                                               packet, sizeof(packet));
    
    if (packet_len == 0) {
        return false;
    }
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "Sending MAX_DATA frame to increase flow control window");
    }
    
    app_tracker_.OnPacketSent(pn, current_time_us_, packet_len, false);
    return SendPacket(packet, packet_len);
}

bool QuicConnection::Impl::SendMaxStreamDataFrame(uint64_t stream_id) {
    if (!client_app_secrets_.valid) {
        return false;
    }
    
    // Build MAX_STREAM_DATA frame
    uint8_t frames[32];
    quic::BufferWriter writer(frames, sizeof(frames));
    
    if (!flow_controller_.BuildMaxStreamDataFrame(&writer, stream_id)) {
        return false;
    }
    
    // Build 1-RTT packet
    uint8_t packet[256];
    uint64_t pn = app_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::Build1RttPacket(dcid_, pn, false, false,
                                               frames, writer.Offset(),
                                               client_app_secrets_,
                                               packet, sizeof(packet));
    
    if (packet_len == 0) {
        return false;
    }
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "Sending MAX_STREAM_DATA for stream %llu", 
                 (unsigned long long)stream_id);
    }
    
    app_tracker_.OnPacketSent(pn, current_time_us_, packet_len, false);
    return SendPacket(packet, packet_len);
}

void QuicConnection::Impl::CheckAndSendFlowControlUpdates() {
    // Check connection-level flow control
    if (flow_controller_.ShouldSendMaxData()) {
        SendMaxDataFrame();
    }
}

//=============================================================================
// Sending
//=============================================================================

bool QuicConnection::Impl::SendPacket(const uint8_t* data, size_t len) {
    if (!send_cb_) {
        return false;
    }
    
    int result = send_cb_(data, len);
    if (result > 0) {
        packets_sent_++;
        bytes_sent_ += len;
        return true;
    }
    return false;
}

bool QuicConnection::Impl::SendAckIfNeeded(quic::PacketType pkt_type) {
    AckManager* ack_mgr = nullptr;
    SentPacketTracker* tracker = nullptr;
    
    switch (pkt_type) {
        case quic::PacketType::kInitial:
            ack_mgr = &initial_ack_mgr_;
            tracker = &initial_tracker_;
            break;
        case quic::PacketType::kHandshake:
            ack_mgr = &handshake_ack_mgr_;
            tracker = &handshake_tracker_;
            break;
        default:
            ack_mgr = &app_ack_mgr_;
            tracker = &app_tracker_;
            break;
    }
    
    if (!ack_mgr->ShouldSendAck()) {
        return true;
    }
    
    // Build ACK frame
    uint8_t frames[64];
    quic::BufferWriter writer(frames, sizeof(frames));
    if (!ack_mgr->BuildAckFrame(&writer, current_time_us_)) {
        return false;
    }
    
    // Build packet
    uint8_t packet[512];
    uint64_t pn = tracker->AllocatePacketNumber();
    size_t packet_len = 0;
    
    switch (pkt_type) {
        case quic::PacketType::kInitial:
            packet_len = quic::BuildInitialPacket(dcid_, scid_,
                                                   retry_token_.data(),
                                                   retry_token_.size(),
                                                   pn,
                                                   frames, writer.Offset(),
                                                   client_initial_secrets_,
                                                   packet, sizeof(packet),
                                                   0);  // No padding for ACK-only
            break;
        case quic::PacketType::kHandshake:
            packet_len = quic::BuildHandshakePacket(dcid_, scid_, pn,
                                                     frames, writer.Offset(),
                                                     client_handshake_secrets_,
                                                     packet, sizeof(packet));
            break;
        default:
            packet_len = quic::Build1RttPacket(dcid_, pn, false, false,
                                                frames, writer.Offset(),
                                                client_app_secrets_,
                                                packet, sizeof(packet));
            break;
    }
    
    if (packet_len == 0) {
        return false;
    }
    
    tracker->OnPacketSent(pn, current_time_us_, packet_len, false);
    ack_mgr->OnAckSent();
    return SendPacket(packet, packet_len);
}

bool QuicConnection::Impl::SendStreamData(uint64_t stream_id,
                                           const uint8_t* data,
                                           size_t len, bool fin) {
    if (!client_app_secrets_.valid) {
        return false;
    }
    
    // Get or create stream flow state to track offset
    StreamFlowState* stream_state = flow_controller_.GetStreamState(stream_id);
    if (!stream_state) {
        // Create stream state with peer's initial max stream data
        uint64_t initial_max = (stream_id & 0x02) ? 
            peer_params_.initial_max_stream_data_uni :
            peer_params_.initial_max_stream_data_bidi_remote;
        flow_controller_.CreateStream(stream_id, initial_max);
        stream_state = flow_controller_.GetStreamState(stream_id);
    }
    
    // Get current send offset for this stream
    uint64_t offset = stream_state ? stream_state->send_offset : 0;
    
    // Build STREAM frame with correct offset (use pre-allocated member buffer)
    quic::BufferWriter writer(frame_buf_, sizeof(frame_buf_));
    
    if (!quic::BuildStreamFrame(&writer, stream_id, offset, data, len, fin)) {
        return false;
    }
    
    // Build 1-RTT packet
    uint64_t pn = app_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::Build1RttPacket(dcid_, pn, false, false,
                                               frame_buf_, writer.Offset(),
                                               client_app_secrets_,
                                               packet_buf_, sizeof(packet_buf_));
    
    if (packet_len == 0) {
        return false;
    }
    
    app_tracker_.OnPacketSent(pn, current_time_us_, packet_len, true);
    loss_detector_.OnPacketSent(pn, current_time_us_, packet_len, true);
    
    // Update flow control
    flow_controller_.OnStreamBytesSent(stream_id, len);
    
    return SendPacket(packet_buf_, packet_len);
}

//=============================================================================
// Timer
//=============================================================================

void QuicConnection::Impl::OnTimerTick(uint32_t elapsed_ms) {
    current_time_us_ = quic::GetCurrentTimeUs();
    time_since_last_activity_us_ += elapsed_ms * 1000;
    
    // Check idle timeout
    if (handshake_complete_ && 
        time_since_last_activity_us_ > config_.idle_timeout_ms * 1000) {
        Close(0, "idle timeout");
        return;
    }
    
    // Check handshake timeout
    if (!handshake_complete_ &&
        current_time_us_ - handshake_start_time_us_ > 
        config_.handshake_timeout_ms * 1000ULL) {
        state_ = ConnectionState::kFailed;
        if (on_disconnected_) {
            on_disconnected_(-1, "handshake timeout");
        }
        return;
    }
    
    // Check PTO
    if (loss_detector_.OnTimerTick(current_time_us_)) {
        // PTO fired - retransmit
        if (!handshake_complete_) {
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "PTO fired, retransmitting Initial");
            }
            SendInitialPacket(true);  // Mark as retransmit to avoid updating transcript hash
        }
    }
}

//=============================================================================
// HTTP/3 Requests
//=============================================================================

int QuicConnection::Impl::SendRequest(
    const std::string& method,
    const std::string& path,
    const std::vector<std::pair<std::string, std::string>>& headers,
    const uint8_t* body, size_t body_len) {
    
    if (!IsConnected() || !h3_handler_) {
        return -1;
    }
    
    int64_t stream_id = h3_handler_->CreateRequestStream();
    if (stream_id < 0) {
        return -1;
    }
    
    std::vector<uint8_t> body_vec;
    if (body && body_len > 0) {
        body_vec.assign(body, body + body_len);
    }
    
    if (!h3_handler_->SendRequest(static_cast<uint64_t>(stream_id),
                                   method, path, config_.hostname,
                                   headers, body_vec)) {
        return -1;
    }
    
    // Create flow state for this stream
    flow_controller_.CreateStream(static_cast<uint64_t>(stream_id),
                                   peer_params_.initial_max_stream_data_bidi_local);
    
    return static_cast<int>(stream_id);
}

int QuicConnection::Impl::OpenStream(
    const std::string& method,
    const std::string& path,
    const std::vector<std::pair<std::string, std::string>>& headers) {
    
    if (!IsConnected() || !h3_handler_) {
        return -1;
    }
    
    int64_t stream_id = h3_handler_->CreateRequestStream();
    if (stream_id < 0) {
        return -1;
    }
    
    flow_controller_.CreateStream(static_cast<uint64_t>(stream_id),
                                   peer_params_.initial_max_stream_data_bidi_local);
    
    // Build and send HEADERS frame only (use pre-allocated member buffers)
    size_t qpack_len = h3::BuildQpackRequestHeaders(
        method, path, config_.hostname, "https", headers,
        payload_buf_, sizeof(payload_buf_));
    
    if (qpack_len == 0) {
        return -1;
    }
    
    // Build HEADERS frame directly into frame_buf_
    // Note: h3::BuildHeadersFrame needs the data as a vector, so we create a lightweight view
    uint8_t h3_frame_buf[1200];  // Local buffer for H3 frame (small, on stack)
    std::vector<uint8_t> encoded(payload_buf_, payload_buf_ + qpack_len);
    size_t hf_len = h3::BuildHeadersFrame(encoded, h3_frame_buf, sizeof(h3_frame_buf));
    
    if (hf_len == 0 || !SendStreamData(static_cast<uint64_t>(stream_id), 
                                        h3_frame_buf, hf_len, false)) {
        return -1;
    }
    
    return static_cast<int>(stream_id);
}

bool QuicConnection::Impl::WriteStream(int stream_id, 
                                        const uint8_t* data, size_t len) {
    if (!IsConnected()) {
        return false;
    }
    
    // Build DATA frame (use payload_buf_ as temp buffer, SendStreamData uses frame_buf_)
    size_t frame_len = h3::BuildDataFrame(data, len, payload_buf_, sizeof(payload_buf_));
    if (frame_len == 0) {
        return false;
    }
    
    return SendStreamData(static_cast<uint64_t>(stream_id), payload_buf_, frame_len, false);
}

bool QuicConnection::Impl::FinishStream(int stream_id) {
    if (!IsConnected()) {
        return false;
    }
    
    // Send empty STREAM frame with FIN
    return SendStreamData(static_cast<uint64_t>(stream_id), nullptr, 0, true);
}

//=============================================================================
// Stats
//=============================================================================

QuicConnection::Stats QuicConnection::Impl::GetStats() const {
    Stats stats;
    stats.packets_sent = packets_sent_;
    stats.packets_received = packets_received_;
    stats.bytes_sent = bytes_sent_;
    stats.bytes_received = bytes_received_;
    
    if (handshake_complete_ && handshake_start_time_us_ > 0) {
        stats.handshake_time_ms = static_cast<uint32_t>(
            (current_time_us_ - handshake_start_time_us_) / 1000);
    }
    
    if (loss_detector_.GetRttEstimator().HasRttSample()) {
        stats.rtt_ms = static_cast<uint32_t>(
            loss_detector_.GetRttEstimator().GetSmoothedRtt() / 1000);
    }
    
    return stats;
}

//=============================================================================
// Utilities
//=============================================================================

void QuicConnection::Impl::GenerateRandom(uint8_t* buf, size_t len) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (size_t i = 0; i < len; i++) {
        buf[i] = static_cast<uint8_t>(dis(gen));
    }
}

//=============================================================================
// QuicConnection Public Interface
//=============================================================================

QuicConnection::QuicConnection(SendCallback send_cb, const QuicConfig& config)
    : impl_(std::make_unique<Impl>(std::move(send_cb), config)) {}

QuicConnection::~QuicConnection() = default;

bool QuicConnection::StartHandshake() {
    return impl_->StartHandshake();
}

void QuicConnection::Close(int error_code, const std::string& reason) {
    impl_->Close(error_code, reason);
}

ConnectionState QuicConnection::GetState() const {
    return impl_->GetState();
}

bool QuicConnection::IsConnected() const {
    return impl_->IsConnected();
}

void QuicConnection::ProcessReceivedData(uint8_t* data, size_t len) {
    impl_->ProcessReceivedData(data, len);
}

void QuicConnection::OnTimerTick(uint32_t elapsed_ms) {
    impl_->OnTimerTick(elapsed_ms);
}

int QuicConnection::SendRequest(
    const std::string& method,
    const std::string& path,
    const std::vector<std::pair<std::string, std::string>>& headers,
    const uint8_t* body, size_t body_len) {
    return impl_->SendRequest(method, path, headers, body, body_len);
}

int QuicConnection::OpenStream(
    const std::string& method,
    const std::string& path,
    const std::vector<std::pair<std::string, std::string>>& headers) {
    return impl_->OpenStream(method, path, headers);
}

bool QuicConnection::WriteStream(int stream_id, const uint8_t* data, size_t len) {
    return impl_->WriteStream(stream_id, data, len);
}

bool QuicConnection::FinishStream(int stream_id) {
    return impl_->FinishStream(stream_id);
}

void QuicConnection::SetOnConnected(OnConnectedCallback cb) {
    impl_->SetOnConnected(std::move(cb));
}

void QuicConnection::SetOnDisconnected(OnDisconnectedCallback cb) {
    impl_->SetOnDisconnected(std::move(cb));
}

void QuicConnection::SetOnResponse(OnResponseCallback cb) {
    impl_->SetOnResponse(std::move(cb));
}

void QuicConnection::SetOnStreamData(OnStreamDataCallback cb) {
    impl_->SetOnStreamData(std::move(cb));
}

QuicConnection::Stats QuicConnection::GetStats() const {
    return impl_->GetStats();
}

} // namespace esp_http3

