/**
 * @file quic_connection.cc
 * @brief QUIC Connection Implementation
 * 
 * Refactored to use component-based architecture:
 * - CryptoManager: Handles all cryptographic operations
 * - FrameProcessor: Parses and dispatches incoming frames
 */

#include "core/quic_connection.h"
#include "core/ack_manager.h"
#include "core/flow_controller.h"
#include "core/loss_detector.h"
#include "core/crypto_manager.h"
#include "core/frame_processor.h"
#include "h3/h3_handler.h"
#include "quic/quic_crypto.h"
#include "quic/quic_aead.h"
#include "quic/quic_packet.h"
#include "quic/quic_frame.h"
#include "tls/tls_handshake.h"

#include <cstring>
#include <map>
#include <set>
#include <random>
#include <esp_log.h>
#include <esp_random.h>

namespace esp_http3 {

static const char* TAG = "QuicConnection";

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
    uint32_t OnTimerTick(uint32_t elapsed_ms);
    
    int SendRequest(const std::string& method,
                    const std::string& path,
                    const std::vector<std::pair<std::string, std::string>>& headers,
                    const uint8_t* body, size_t body_len);
    
    int OpenStream(const std::string& method,
                   const std::string& path,
                   const std::vector<std::pair<std::string, std::string>>& headers);
    ssize_t WriteStream(int stream_id, const uint8_t* data, size_t len);
    bool FinishStream(int stream_id);
    bool ResetStream(int stream_id, uint64_t error_code);
    
    // Flow control checks (borrowed from Python version)
    bool CanSend(int stream_id, size_t len) const;
    size_t GetSendableBytes(int stream_id) const;
    bool IsConnectionBlocked() const { return flow_controller_.IsConnectionBlocked(); }
    bool IsStreamBlocked(int stream_id) const { 
        return flow_controller_.IsStreamBlocked(static_cast<uint64_t>(stream_id)); 
    }
    
    bool IsStreamReset(int stream_id) const {
        uint64_t sid = static_cast<uint64_t>(stream_id);
        return reset_streams_.find(sid) != reset_streams_.end() ||
               stop_sending_streams_.find(sid) != stop_sending_streams_.end();
    }
    
    void AcknowledgeStreamData(int stream_id, size_t bytes) {
        uint64_t sid = static_cast<uint64_t>(stream_id);
        flow_controller_.OnStreamBytesConsumed(sid, bytes);
        
        // Check if we should send flow control updates (backpressure released)
        if (flow_controller_.ShouldSendMaxStreamData(sid)) {
            SendMaxStreamDataFrame(sid);
        }
        if (flow_controller_.ShouldSendMaxData()) {
            SendMaxDataFrame();
        }
    }
    
    void SetOnConnected(OnConnectedCallback cb) { on_connected_ = std::move(cb); }
    void SetOnDisconnected(OnDisconnectedCallback cb) { on_disconnected_ = std::move(cb); }
    void SetOnResponse(OnResponseCallback cb) { on_response_ = std::move(cb); }
    void SetOnStreamData(OnStreamDataCallback cb) { on_stream_data_ = std::move(cb); }
    void SetOnStreamWritable(OnStreamWritableCallback cb) { on_stream_writable_ = std::move(cb); }
    void SetOnWritable(OnWritableCallback cb) { on_writable_ = std::move(cb); }
    
    // DATAGRAM callback type (same as public API)
    using OnDatagramCallback = QuicConnection::OnDatagramCallback;
    void SetOnDatagram(OnDatagramCallback cb) { on_datagram_ = std::move(cb); }
    
    // Key Update
    bool InitiateKeyUpdate();
    uint8_t GetKeyPhase() const { return crypto_.GetKeyPhase(); }
    uint32_t GetKeyUpdateGeneration() const { return crypto_.GetKeyUpdateGeneration(); }
    
    // Path Validation
    bool SendPathChallenge();
    bool IsPathValidated() const { return path_validated_; }
    uint32_t GetPathValidationRtt() const { return path_validation_rtt_ms_; }
    
    // Connection Migration
    bool MigrateConnection();
    bool IsMigrationAllowed() const { return !peer_params_.disable_active_migration; }
    bool IsMigrationInProgress() const { return migration_in_progress_; }
    size_t GetAvailablePeerConnectionIdCount() const;
    
    using OnMigrationCompleteCallback = std::function<void(bool success)>;
    void SetOnMigrationComplete(OnMigrationCompleteCallback cb) { on_migration_complete_ = std::move(cb); }
    
    // DATAGRAM
    bool CanSendDatagram(size_t size) const;
    bool SendDatagram(const uint8_t* data, size_t len);
    size_t GetMaxDatagramSize() const;
    bool IsDatagramAvailable() const;
    
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
    void SendCoalescedAcks();  // Coalesce Initial + Handshake ACKs into one UDP datagram
    
    // Batch mode for aggregating multiple STREAM frames into one packet
    void BeginBatch();
    bool EndBatch();
    
    // QUIC stream sending for H3
    bool SendStreamData(uint64_t stream_id, const uint8_t* data, 
                        size_t len, bool fin);
    
    // Flow control updates
    bool SendMaxDataFrame();
    bool SendMaxStreamDataFrame(uint64_t stream_id);
    void CheckAndSendFlowControlUpdates();
    
    // Generate random bytes
    void GenerateRandom(uint8_t* buf, size_t len);
    
    // Setup frame processor callbacks
    void SetupFrameProcessorCallbacks();
    
    // Frame processor callback handlers (for 1-RTT packets)
    void OnFrameAck(const AckFrameData& ack_data);
    void OnFrameStream(uint64_t stream_id, uint64_t offset,
                       const uint8_t* data, size_t len, bool fin);
    void OnFrameMaxData(uint64_t max_data);
    void OnFrameMaxStreamData(uint64_t stream_id, uint64_t max_data);
    void OnFrameDataBlocked(uint64_t limit);
    void OnFrameStreamDataBlocked(uint64_t stream_id, uint64_t limit);
    void OnFrameConnectionClose(const ConnectionCloseData& data);
    void OnFrameHandshakeDone();
    void OnFrameNewConnectionId(const NewConnectionIdData& data);
    void OnFramePathChallenge(const uint8_t* data);
    void OnFramePathResponse(const uint8_t* data);
    void OnFrameDatagram(const uint8_t* data, size_t len);
    
    // Notify upper layer that connection/streams are writable
    void NotifyWritable();
    
    // Stream cleanup - releases memory associated with a completed stream
    void CleanupStream(uint64_t stream_id);
    
    // Retransmission - resend lost packets
    void RetransmitLostPackets(const std::vector<SentPacketInfo*>& lost_packets);
    
    // PTO handler - dispatches to appropriate probe based on connection state
    void HandlePto();
    
    // PTO probe - send probe packets when PTO fires (1-RTT space)
    void SendPtoProbe();
    
    // Handshake PTO - retransmit Handshake packets (e.g., Client Finished)
    void SendHandshakePtoProbe();
    
    // Connection ID management
    void RetirePeerConnectionIdsPriorTo(uint64_t retire_prior_to);
    bool SendRetireConnectionId(uint64_t sequence_number);
    bool SendNewConnectionId();
    quic::ConnectionId* GetActivePeerConnectionId();
    bool IsStatelessReset(const uint8_t* data, size_t len);
    
    // Check if payload contains ACK-eliciting frames (RFC 9002)
    // Non-ACK-eliciting: PADDING (0x00), ACK (0x02-0x03), CONNECTION_CLOSE (0x1c-0x1d)
    bool HasAckElicitingFrames(const uint8_t* payload, size_t len);
    
    // Connection migration helpers
    quic::ConnectionId* SelectNewPeerConnectionId();
    void CompleteMigration(bool success);
    void SendMigrationPathChallenge();

private:
    SendCallback send_cb_;
    QuicConfig config_;
    ConnectionState state_ = ConnectionState::kIdle;
    
    // Callbacks
    OnConnectedCallback on_connected_;
    OnDisconnectedCallback on_disconnected_;
    OnResponseCallback on_response_;
    OnStreamDataCallback on_stream_data_;
    OnStreamWritableCallback on_stream_writable_;
    OnWritableCallback on_writable_;
    
    // Track reset streams
    std::set<uint64_t> reset_streams_;
    std::set<uint64_t> stop_sending_streams_;
    
    // Connection IDs
    quic::ConnectionId dcid_;           // Destination CID (server's)
    quic::ConnectionId scid_;           // Source CID (ours)
    quic::ConnectionId initial_dcid_;   // Original DCID
    
    // Multi-CID support: Peer's connection IDs (sequence -> CID info)
    struct PeerConnectionIdInfo {
        quic::ConnectionId cid;
        uint8_t stateless_reset_token[16];
        bool retired = false;
    };
    std::map<uint64_t, PeerConnectionIdInfo> peer_connection_ids_;
    uint64_t peer_retire_prior_to_ = 0;
    
    // Our alternative connection IDs (sequence -> CID info)
    struct LocalConnectionIdInfo {
        quic::ConnectionId cid;
        uint8_t stateless_reset_token[16];
    };
    std::map<uint64_t, LocalConnectionIdInfo> local_connection_ids_;
    uint64_t local_cid_sequence_ = 0;  // Next sequence number for NEW_CONNECTION_ID
    
    // Crypto manager (replaces scattered crypto state)
    CryptoManager crypto_;
    
    // Frame processor (handles incoming frame parsing and dispatch)
    FrameProcessor frame_processor_;
    
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
    uint32_t effective_idle_timeout_ms_ = 0;  // min(local, peer) idle timeout
    
    // Stats
    uint32_t packets_sent_ = 0;
    uint32_t packets_received_ = 0;
    uint32_t bytes_sent_ = 0;
    uint32_t bytes_received_ = 0;
    
    // Decrypt failure tracking - close connection after too many consecutive failures
    uint32_t consecutive_decrypt_failures_ = 0;
    static constexpr uint32_t kMaxConsecutiveDecryptFailures = 3;
    
    // Retry token
    std::vector<uint8_t> retry_token_;
    
    // Flags
    bool handshake_complete_ = false;
    bool h3_initialized_ = false;
    
    // Path Validation state
    bool path_validated_ = true;
    uint8_t path_challenge_data_[8] = {0};
    uint64_t path_challenge_sent_time_us_ = 0;
    uint32_t path_validation_rtt_ms_ = 0;
    
    // Connection Migration state
    bool migration_in_progress_ = false;
    quic::ConnectionId pre_migration_dcid_;    // DCID before migration (for rollback)
    uint8_t migration_challenge_data_[8] = {0};
    uint64_t migration_challenge_sent_time_us_ = 0;
    uint32_t migration_retry_count_ = 0;
    static constexpr uint32_t kMaxMigrationRetries = 3;
    OnMigrationCompleteCallback on_migration_complete_;
    
    // DATAGRAM state (RFC 9221)
    uint32_t peer_max_datagram_frame_size_ = 0;
    OnDatagramCallback on_datagram_;
    
    // Pre-allocated buffers to avoid heap allocation in hot paths
    uint8_t packet_buf_[1500];       // For building outgoing packets
    uint8_t payload_buf_[1500];      // For decrypted payloads
    uint8_t frame_buf_[1500];        // For building frames
    
    // Maximum payload size for a single packet (considering headers and encryption overhead)
    static constexpr size_t kMaxPacketPayload = 1200;
    
    // Batch mode - aggregate multiple STREAM frames into one packet
    struct BatchState {
        bool active = false;
        quic::BufferWriter* writer = nullptr;
        
        // Track stream frames for retransmission (each stream's frame info)
        struct StreamFrameInfo {
            uint64_t stream_id;
            size_t frame_start;   // Offset within batch buffer where frame starts
            size_t frame_len;     // Length of frame
        };
        std::vector<StreamFrameInfo> stream_frames;
        
        void Reset() {
            active = false;
            writer = nullptr;
            stream_frames.clear();
        }
    };
    BatchState batch_state_;
    uint8_t batch_frames_[1500];  // Buffer for batch mode frames
};

//=============================================================================
// Impl Constructor/Destructor
//=============================================================================

QuicConnection::Impl::Impl(SendCallback send_cb, const QuicConfig& config)
    : send_cb_(std::move(send_cb))
    , config_(config) {
    
    h3_handler_ = std::make_unique<h3::H3Handler>();
    
    // Initialize effective idle timeout with local config (will be updated with min(local, peer) after handshake)
    effective_idle_timeout_ms_ = config_.idle_timeout_ms;
    
    // Set up local transport parameters
    local_params_.max_idle_timeout = config_.idle_timeout_ms;
    local_params_.initial_max_data = config_.max_data;
    local_params_.initial_max_stream_data_bidi_local = config_.max_stream_data;
    local_params_.initial_max_stream_data_bidi_remote = config_.max_stream_data;
    local_params_.initial_max_stream_data_uni = config_.max_stream_data;
    local_params_.initial_max_streams_bidi = 100;
    local_params_.initial_max_streams_uni = 100;
    local_params_.active_connection_id_limit = 4;
    
    // DATAGRAM support (RFC 9221)
    if (config_.enable_datagram) {
        local_params_.max_datagram_frame_size = config_.max_datagram_frame_size;
    }
    
    // Initialize flow controller
    flow_controller_.Initialize(config_.max_data, config_.max_stream_data);
    
    // Initialize crypto manager
    crypto_.SetDebug(config_.enable_debug);
    crypto_.Initialize();
    
    // Initialize frame processor and set up callbacks
    frame_processor_.SetDebug(config_.enable_debug);
    SetupFrameProcessorCallbacks();
    
    // Set up loss detection callbacks for retransmission
    loss_detector_.SetOnLoss([this](const std::vector<SentPacketInfo*>& lost_packets) {
        RetransmitLostPackets(lost_packets);
    });
    
    loss_detector_.SetOnPto([this]() {
        HandlePto();
    });
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
    
    // Generate X25519 key pair using CryptoManager
    if (!crypto_.GenerateKeyPair()) {
        state_ = ConnectionState::kFailed;
        return false;
    }
    
    // Derive initial secrets using CryptoManager
    if (!crypto_.DeriveInitialSecrets(dcid_.Data(), dcid_.Length())) {
        state_ = ConnectionState::kFailed;
        return false;
    }
    
    // Initialize transcript hash
    crypto_.ResetTranscript();
    
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
    std::vector<uint8_t> frame_buf(256);
    quic::BufferWriter writer(frame_buf.data(), frame_buf.size());
    
    quic::BuildConnectionCloseFrame(&writer, 
                                     static_cast<uint64_t>(error_code), 
                                     0, reason);
    
    // Send in appropriate packet type (use pre-allocated member buffer)
    size_t packet_len = 0;
    
    if (handshake_complete_) {
        packet_len = quic::Build1RttPacket(dcid_,
                                            app_tracker_.AllocatePacketNumber(),
                                            false, crypto_.GetKeyPhase() != 0,
                                            frame_buf.data(), writer.Offset(),
                                            crypto_.GetClientAppSecrets(),
                                            packet_buf_, sizeof(packet_buf_));
    } else {
        packet_len = quic::BuildInitialPacket(dcid_, scid_,
                                               retry_token_.data(), 
                                               retry_token_.size(),
                                               initial_tracker_.AllocatePacketNumber(),
                                               frame_buf.data(), writer.Offset(),
                                               crypto_.GetClientInitialSecrets(),
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
                                           crypto_.GetClientRandom(),
                                           crypto_.GetPublicKey(),
                                           local_params_,
                                           payload_buf_, sizeof(payload_buf_));
    if (ch_len == 0) {
        ESP_LOGE(TAG, "BuildClientHello failed");
        return false;
    }
    
    // Update transcript hash only on first send, not on retransmit
    // PTO retransmits the same ClientHello, so transcript hash should not be updated again
    if (!is_retransmit) {
        crypto_.UpdateTranscript(payload_buf_, ch_len);
    }
    
    // Build CRYPTO frame
    quic::BufferWriter writer(frame_buf_, sizeof(frame_buf_));
    if (!quic::BuildCryptoFrame(&writer, 0, payload_buf_, ch_len)) {
        ESP_LOGE(TAG, "BuildCryptoFrame failed");
        return false;
    }
    
    if (config_.enable_debug && !is_retransmit) {
        ESP_LOGI(TAG, "[SendFrame] CRYPTO (ClientHello) in Initial packet, len=%zu", ch_len);
    }
    
    // Build Initial packet
    uint64_t pn = initial_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::BuildInitialPacket(dcid_, scid_,
                                                  retry_token_.data(),
                                                  retry_token_.size(),
                                                  pn,
                                                  frame_buf_, writer.Offset(),
                                                  crypto_.GetClientInitialSecrets(),
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
    
    current_time_us_ = quic::GetCurrentTimeUs();
    time_since_last_activity_us_ = 0;
    packets_received_++;
    bytes_received_ += len;
    
    // Debug log for received packet
    if (config_.enable_debug) {
        ESP_LOGW(TAG, "[RecvPacket] len=%zu bytes", len);
    }
    
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
                        
                        // Re-derive initial secrets with new DCID using CryptoManager
                        crypto_.DeriveInitialSecrets(dcid_.Data(), dcid_.Length());
                        
                        // Resend Initial
                        initial_tracker_.Reset();
                        crypto_.ResetTranscript();
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
        crypto_.GetServerInitialSecrets(),
        initial_ack_mgr_.GetLargestReceived(),
        &info,
        payload_buf_, sizeof(payload_buf_));
    
    if (payload_len == 0) {
        if (config_.enable_debug) {
            ESP_LOGE(TAG, "DecryptInitialPacket failed (len=%zu)", len);
        }
        return 0;  // Decryption failed
    }
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "Decrypted Initial packet, PN=%llu, payload=%zu bytes, packet_size=%zu",
                 (unsigned long long)info.packet_number, payload_len, info.packet_size);
    }
    
    // If we already have Handshake keys and receive an Initial with different SCID,
    // ignore it - this is a response to our retransmitted Initial from a different server session
    if (crypto_.HasHandshakeKeys() && dcid_.Length() > 0 && dcid_ != info.long_header.scid) {
        if (config_.enable_debug) {
            ESP_LOGW(TAG, "Ignoring Initial packet with different SCID (already have Handshake keys)");
        }
        return info.packet_size;  // Skip this packet, continue with coalesced packets
    }
    
    // Update DCID from SCID in response
    dcid_ = info.long_header.scid;
    
    // Only record packet for ACK generation if it contains ACK-eliciting frames (RFC 9002)
    if (HasAckElicitingFrames(payload_buf_, payload_len)) {
        initial_ack_mgr_.OnPacketReceived(info.packet_number, current_time_us_);
    }
    
    // Process frames
    ProcessFrames(payload_buf_, payload_len, quic::PacketType::kInitial);
    
    return info.packet_size;  // Return consumed bytes for coalesced packet handling
}

size_t QuicConnection::Impl::ProcessHandshakePacket(uint8_t* data, size_t len) {
    if (!crypto_.HasHandshakeKeys()) {
        return 0;  // Haven't derived handshake keys yet
    }
    
    quic::PacketInfo info;
    
    size_t payload_len = quic::DecryptHandshakePacket(
        data, len,
        crypto_.GetServerHandshakeSecrets(),
        handshake_ack_mgr_.GetLargestReceived(),
        &info,
        payload_buf_, sizeof(payload_buf_));
    
    if (payload_len == 0) {
        // Decryption failed - try to skip this packet and continue with coalesced packets
        // This can happen when we receive Handshake packets from a different server session
        // (e.g., response to our retransmitted Initial that created a separate session)
        quic::PacketInfo skip_info;
        if (quic::ParsePacketHeader(data, len, 0, &skip_info) && skip_info.is_long_header) {
            size_t hdr_len = skip_info.header_length;
            quic::BufferReader reader(data + hdr_len, len - hdr_len);
            uint64_t pkt_length;
            if (reader.ReadVarint(&pkt_length)) {
                size_t length_field_size = (len - hdr_len) - reader.Remaining();
                size_t packet_size = hdr_len + length_field_size + pkt_length;
                ESP_LOGD(TAG, "Skipping undecryptable Handshake packet, size=%zu", packet_size);
                return packet_size;  // Skip this packet, continue with next
            }
        }
        return 0;  // Can't parse, stop processing
    }
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "Decrypted Handshake packet, PN=%llu, payload=%zu bytes, packet_size=%zu",
                 (unsigned long long)info.packet_number, payload_len, info.packet_size);
    }
    
    // Only record packet for ACK generation if it contains ACK-eliciting frames (RFC 9002)
    if (HasAckElicitingFrames(payload_buf_, payload_len)) {
        handshake_ack_mgr_.OnPacketReceived(info.packet_number, current_time_us_);
    }
    
    ProcessFrames(payload_buf_, payload_len, quic::PacketType::kHandshake);
    
    return info.packet_size;  // Return consumed bytes for coalesced packet handling
}

bool QuicConnection::Impl::Process1RttPacket(uint8_t* data, size_t len) {
    if (!crypto_.HasApplicationKeys()) {
        return false;
    }
    
    quic::PacketInfo info;
    
    size_t payload_len = quic::Decrypt1RttPacket(
        data, len,
        scid_.Length(),  // Our SCID length is the expected DCID length
        crypto_.GetServerAppSecrets(),
        app_ack_mgr_.GetLargestReceived(),
        &info,
        payload_buf_, sizeof(payload_buf_));
    
    if (payload_len == 0) {
        // Check if this is a Stateless Reset (RFC 9000 Section 10.3)
        // Uses IsStatelessReset() which checks all known reset tokens from:
        // - Transport parameters (initial handshake)
        // - NEW_CONNECTION_ID frames (additional CIDs)
        if (IsStatelessReset(data, len)) {
            ESP_LOGW(TAG, "Received Stateless Reset from server - connection was closed by peer");
            Close(0, "stateless reset received");
            return false;
        }
        
        // Track consecutive decrypt failures - likely means server closed connection
        // but we didn't receive a proper close signal (e.g., server restarted, network issue)
        consecutive_decrypt_failures_++;
        if (consecutive_decrypt_failures_ >= kMaxConsecutiveDecryptFailures) {
            ESP_LOGW(TAG, "Too many consecutive decrypt failures (%lu), closing connection",
                     consecutive_decrypt_failures_);
            Close(0, "decrypt failures - connection likely stale");
            return false;
        }
        
        if (config_.enable_debug) {
            ESP_LOGW(TAG, "Decrypt1RttPacket failed (len=%zu, failures=%lu)",
                     len, consecutive_decrypt_failures_);
        }
        return false;
    }
    
    // Reset failure counter on successful decrypt
    consecutive_decrypt_failures_ = 0;
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "Decrypted 1-RTT packet, PN=%llu, payload=%zu bytes",
                 (unsigned long long)info.packet_number, payload_len);
    }
    
    // Only record packet for ACK generation if it contains ACK-eliciting frames (RFC 9002)
    if (HasAckElicitingFrames(payload_buf_, payload_len)) {
        app_ack_mgr_.OnPacketReceived(info.packet_number, current_time_us_);
    }
    
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
                ESP_LOGI(TAG, "[RecvFrame] [%s] Frame: PING", pkt_type_str);
            }
        } else if (frame_type == 0x02 || frame_type == 0x03) {
            // ACK or ACK_ECN
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "[RecvFrame] [%s] Frame: ACK%s", pkt_type_str, 
                         frame_type == 0x03 ? "_ECN" : "");
            }
            reader.Seek(reader.Offset() - 1);  // Back up to include frame type
            ProcessAckFrame(&reader, pkt_type);
        } else if (frame_type == 0x04) {
            // RESET_STREAM - server is resetting the stream
            uint64_t stream_id, error_code, final_size;
            if (reader.ReadVarint(&stream_id) && 
                reader.ReadVarint(&error_code) && 
                reader.ReadVarint(&final_size)) {
                if (config_.enable_debug) {
                    ESP_LOGI(TAG, "[RecvFrame] [%s] Frame: RESET_STREAM stream=%llu, error=%llu, final_size=%llu", 
                             pkt_type_str, (unsigned long long)stream_id, 
                             (unsigned long long)error_code, (unsigned long long)final_size);
                }
                ESP_LOGW(TAG, "Server reset stream %llu with error code %llu (H3_FRAME_ERROR)", 
                         (unsigned long long)stream_id, (unsigned long long)error_code);
                // Stream was reset by server - this is a fatal error for the stream
                reset_streams_.insert(stream_id);
            }
        } else if (frame_type == 0x05) {
            // STOP_SENDING - server wants us to stop sending data
            uint64_t stream_id, error_code;
            if (reader.ReadVarint(&stream_id) && reader.ReadVarint(&error_code)) {
                if (config_.enable_debug) {
                    ESP_LOGI(TAG, "[RecvFrame] [%s] Frame: STOP_SENDING stream=%llu, error=%llu", 
                             pkt_type_str, (unsigned long long)stream_id, 
                             (unsigned long long)error_code);
                }
                ESP_LOGW(TAG, "Server requested stop sending on stream %llu (error=%llu)", 
                         (unsigned long long)stream_id, (unsigned long long)error_code);
                // Server wants us to stop sending - we should abort the upload
                stop_sending_streams_.insert(stream_id);
            }
        } else if (frame_type == 0x06) {
            // CRYPTO
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "[RecvFrame] [%s] Frame: CRYPTO", pkt_type_str);
            }
            ProcessCryptoFrame(&reader, pkt_type);
        } else if (frame_type >= 0x08 && frame_type <= 0x0f) {
            // STREAM
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "[RecvFrame] [%s] Frame: STREAM (type=0x%02x)", pkt_type_str, frame_type);
            }
            ProcessStreamFrame(&reader, frame_type);
        } else if (frame_type == 0x10) {
            // MAX_DATA
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "[RecvFrame] [%s] Frame: MAX_DATA", pkt_type_str);
            }
            ProcessMaxDataFrame(&reader);
        } else if (frame_type == 0x11) {
            // MAX_STREAM_DATA
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "[RecvFrame] [%s] Frame: MAX_STREAM_DATA", pkt_type_str);
            }
            ProcessMaxStreamDataFrame(&reader);
        } else if (frame_type == 0x12 || frame_type == 0x13) {
            // MAX_STREAMS (0x12=bidi, 0x13=uni)
            // Server is increasing the stream limit - just read and log
            uint64_t max_streams;
            if (reader.ReadVarint(&max_streams)) {
                if (config_.enable_debug) {
                    ESP_LOGI(TAG, "[RecvFrame] [%s] Frame: MAX_STREAMS_%s, limit=%llu", pkt_type_str,
                             frame_type == 0x12 ? "BIDI" : "UNI", 
                             (unsigned long long)max_streams);
                }
            }
        } else if (frame_type == 0x14) {
            // DATA_BLOCKED - peer is blocked on connection-level flow control
            uint64_t limit;
            if (reader.ReadVarint(&limit)) {
                if (config_.enable_debug) {
                    ESP_LOGI(TAG, "[RecvFrame] [%s] Frame: DATA_BLOCKED at limit=%llu", pkt_type_str,
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
                    ESP_LOGI(TAG, "[RecvFrame] [%s] Frame: STREAM_DATA_BLOCKED stream=%llu, limit=%llu", 
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
                    ESP_LOGI(TAG, "[RecvFrame] [%s] Frame: STREAMS_BLOCKED_%s at limit=%llu", pkt_type_str,
                             frame_type == 0x16 ? "BIDI" : "UNI",
                             (unsigned long long)limit);
                }
            }
        } else if (frame_type == 0x18) {
            // NEW_CONNECTION_ID
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "[RecvFrame] [%s] Frame: NEW_CONNECTION_ID", pkt_type_str);
            }
            ProcessNewConnectionIdFrame(&reader);
        } else if (frame_type == 0x1c) {
            // CONNECTION_CLOSE
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "[RecvFrame] [%s] Frame: CONNECTION_CLOSE", pkt_type_str);
            }
            ProcessConnectionCloseFrame(&reader, false);
        } else if (frame_type == 0x1d) {
            // APPLICATION_CLOSE
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "[RecvFrame] [%s] Frame: APPLICATION_CLOSE", pkt_type_str);
            }
            ProcessConnectionCloseFrame(&reader, true);
        } else if (frame_type == 0x1e) {
            // HANDSHAKE_DONE
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "[RecvFrame] [%s] Frame: HANDSHAKE_DONE", pkt_type_str);
            }
            ProcessHandshakeDoneFrame();
        } else {
            // Unknown frame - try to skip
            if (config_.enable_debug) {
                ESP_LOGW(TAG, "[RecvFrame] [%s] Unknown frame type: 0x%02x, remaining=%zu", 
                         pkt_type_str, frame_type, reader.Remaining());
            }
            // For now, just break
            break;
        }
    }
    
    // Note: ACK is NOT sent immediately here.
    // ACK will be sent when:
    // 1. Timer tick triggers ACK deadline (max_ack_delay or 2+ packets received)
    // 2. Piggybacked on other outgoing packets (STREAM, etc.)
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
    
    // Update loss detector with RTT and detect lost packets
    // Note: Decode peer's ACK delay using peer's ack_delay_exponent (from transport params)
    uint64_t decoded_ack_delay = ack_data.ack_delay << peer_params_.ack_delay_exponent;
    
    if (tracker->GetLatestRttUs() > 0) {
        loss_detector_.GetRttEstimator().OnRttSample(
            tracker->GetLatestRttUs(),
            decoded_ack_delay);
    }
    
    // Reset PTO count and detect lost packets (critical for proper timeout behavior)
    loss_detector_.OnAckReceived(ack_data.largest_ack, decoded_ack_delay,
                                  current_time_us_, tracker);
    
    // ACK frees up congestion window, notify upper layer
    if (newly_acked > 0 && pkt_type == quic::PacketType::k1Rtt) {
        NotifyWritable();
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
                crypto_.UpdateTranscript(buffer->data(), hdr_len + msg_len);
                ProcessServerHello(msg_data, msg_len);
                break;
                
            case tls::HandshakeType::kEncryptedExtensions:
                ESP_LOGD(TAG, "Processing EncryptedExtensions");
                crypto_.UpdateTranscript(buffer->data(), hdr_len + msg_len);
                ProcessEncryptedExtensions(msg_data, msg_len);
                break;
                
            case tls::HandshakeType::kCertificate:
                ESP_LOGD(TAG, "Processing Certificate");
                crypto_.UpdateTranscript(buffer->data(), hdr_len + msg_len);
                ProcessCertificate(msg_data, msg_len);
                break;
                
            case tls::HandshakeType::kCertificateVerify:
                ESP_LOGD(TAG, "Processing CertificateVerify");
                crypto_.UpdateTranscript(buffer->data(), hdr_len + msg_len);
                ProcessCertificateVerify(msg_data, msg_len);
                break;
                
            case tls::HandshakeType::kFinished:
                ESP_LOGD(TAG, "Processing Server Finished");
                crypto_.UpdateTranscript(buffer->data(), hdr_len + msg_len);
                ProcessServerFinished(msg_data, msg_len);
                break;
                
            default:
                ESP_LOGW(TAG, "Unknown TLS message type: %d", 
                         static_cast<int>(msg_type));
                crypto_.UpdateTranscript(buffer->data(), hdr_len + msg_len);
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
    
    // Derive handshake secrets using CryptoManager
    // Note: ServerHello should already be in transcript before this call
    if (!crypto_.DeriveHandshakeSecrets(sh.key_share_public_key, nullptr, 0)) {
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
        
        // Calculate effective idle timeout (RFC 9000 Section 10.1)
        // Use minimum of local and peer idle timeout, 0 means disabled
        uint32_t peer_idle_ms = static_cast<uint32_t>(peer_params_.max_idle_timeout);
        if (peer_idle_ms > 0 && config_.idle_timeout_ms > 0) {
            effective_idle_timeout_ms_ = std::min(config_.idle_timeout_ms, peer_idle_ms);
        } else if (peer_idle_ms > 0) {
            effective_idle_timeout_ms_ = peer_idle_ms;
        } else {
            effective_idle_timeout_ms_ = config_.idle_timeout_ms;
        }
        
        if (config_.enable_debug) {
            ESP_LOGI(TAG, "Effective idle timeout: %lu ms (local=%lu, peer=%lu)",
                     effective_idle_timeout_ms_, config_.idle_timeout_ms, peer_idle_ms);
        }
        
        // Update DATAGRAM support (RFC 9221)
        if (peer_params_.max_datagram_frame_size > 0) {
            peer_max_datagram_frame_size_ = static_cast<uint32_t>(peer_params_.max_datagram_frame_size);
            if (config_.enable_debug && config_.enable_datagram) {
                ESP_LOGI(TAG, "Peer supports DATAGRAM (max_size=%lu)", peer_max_datagram_frame_size_);
            }
        }
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
    
    // Derive application secrets using CryptoManager
    if (!crypto_.DeriveApplicationSecrets()) {
        ESP_LOGW(TAG, "DeriveApplicationSecrets failed");
        state_ = ConnectionState::kFailed;
        return false;
    }
    
    ESP_LOGD(TAG, "Application secrets derived, sending Client Finished");
    
    // Send Client Finished
    return SendClientFinished();
}

bool QuicConnection::Impl::SendClientFinished() {
    // Build Finished message using CryptoManager
    uint8_t finished_msg[36];
    size_t finished_len;
    if (!crypto_.BuildClientFinished(finished_msg, &finished_len)) {
        ESP_LOGW(TAG, "BuildClientFinished failed");
        return false;
    }
    
    // Update transcript with our Finished
    crypto_.UpdateTranscript(finished_msg, finished_len);
    
    // Build Handshake frames first: ACK (if needed) + CRYPTO (Client Finished)
    uint8_t hs_frames[128];
    quic::BufferWriter hs_writer(hs_frames, sizeof(hs_frames));
    
    // Add Handshake ACK if we have pending acknowledgments
    if (handshake_ack_mgr_.HasPendingAck()) {
        if (handshake_ack_mgr_.BuildAckFrame(&hs_writer, current_time_us_)) {
            handshake_ack_mgr_.OnAckSent();
            if (config_.enable_debug) {
                ESP_LOGD(TAG, "SendClientFinished: piggybacked Handshake ACK");
            }
        }
    }
    
    // Add CRYPTO frame with Client Finished
    if (!quic::BuildCryptoFrame(&hs_writer, 0, finished_msg, finished_len)) {
        ESP_LOGW(TAG, "BuildCryptoFrame failed");
        return false;
    }
    
    // RFC 9000 Section 12.2 + 14.1: Coalesce Initial ACK + Handshake into one datagram
    // UDP datagrams carrying Initial packets MUST be >= 1200 bytes
    size_t total_len = 0;
    bool has_initial = initial_ack_mgr_.HasPendingAck();
    
    // 1. Build Initial ACK packet (if needed, must come first in coalesced datagram)
    if (has_initial) {
        uint8_t ack_frames[64];
        quic::BufferWriter ack_writer(ack_frames, sizeof(ack_frames));
        if (initial_ack_mgr_.BuildAckFrame(&ack_writer, current_time_us_)) {
            uint64_t ack_pn = initial_tracker_.AllocatePacketNumber();
            
            size_t ack_packet_len = quic::BuildInitialPacket(dcid_, scid_,
                                                              retry_token_.data(),
                                                              retry_token_.size(),
                                                              ack_pn,
                                                              ack_frames, ack_writer.Offset(),
                                                              crypto_.GetClientInitialSecrets(),
                                                              packet_buf_ + total_len,
                                                              sizeof(packet_buf_) - total_len,
                                                              0);  // No internal padding needed
            if (ack_packet_len > 0) {
                initial_tracker_.OnPacketSent(ack_pn, current_time_us_, ack_packet_len, false);
                initial_ack_mgr_.OnAckSent();
                total_len += ack_packet_len;
                if (config_.enable_debug) {
                    ESP_LOGI(TAG, "[SendFrame] Initial ACK, PN=%llu, len=%zu (coalesced)",
                             (unsigned long long)ack_pn, ack_packet_len);
                }
            }
        }
    }
    
    // 2. Build Handshake packet
    uint64_t pn = handshake_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::BuildHandshakePacket(dcid_, scid_,
                                                    pn,
                                                    hs_frames, hs_writer.Offset(),
                                                    crypto_.GetClientHandshakeSecrets(),
                                                    packet_buf_ + total_len,
                                                    sizeof(packet_buf_) - total_len);
    
    if (packet_len == 0) {
        ESP_LOGW(TAG, "BuildHandshakePacket failed");
        return false;
    }
    
    total_len += packet_len;
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "[SendFrame] CRYPTO (Client Finished) in Handshake packet, PN=%llu, len=%zu",
                 (unsigned long long)pn, packet_len);
    }
    
    handshake_tracker_.OnPacketSent(pn, current_time_us_, packet_len, true);
    loss_detector_.OnPacketSent(pn, current_time_us_, packet_len, true);
    
    // RFC 9000 Section 14.1: UDP datagrams carrying Initial packets MUST be >= 1200 bytes
    // Pad the datagram with zeros at the end if needed
    if (has_initial && total_len < 1200) {
        memset(packet_buf_ + total_len, 0, 1200 - total_len);
        total_len = 1200;
    }
    
    // Send coalesced datagram (Initial ACK + Handshake)
    if (config_.enable_debug && has_initial) {
        ESP_LOGI(TAG, "[SendPacket] Coalesced datagram, total len=%zu", total_len);
    }
    
    bool ok = SendPacket(packet_buf_, total_len);
    if (ok) {
        state_ = ConnectionState::kConnected;
    }
    return ok;
}

void QuicConnection::Impl::ProcessHandshakeDoneFrame() {
    handshake_complete_ = true;
    state_ = ConnectionState::kConnected;
    
    // Release handshake-related buffers that are no longer needed
    // These can be quite large (several KB) and are only used during handshake
    // Use swap trick for guaranteed memory release (shrink_to_fit is non-binding)
    std::vector<uint8_t>().swap(initial_crypto_buffer_);
    std::vector<uint8_t>().swap(handshake_crypto_buffer_);
    initial_crypto_cache_.clear();
    handshake_crypto_cache_.clear();
    
    // Reset Initial and Handshake packet number space trackers
    // (no longer needed after handshake completion)
    initial_ack_mgr_.Reset();
    handshake_ack_mgr_.Reset();
    initial_tracker_.Reset();
    handshake_tracker_.Reset();
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "Handshake complete, released crypto buffers and trackers");
    }
    
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
                resp.complete = response.complete;
                resp.error = response.error;
                on_response_(static_cast<int>(stream_id), resp);
            }
        });
        
        h3_handler_->SetOnStreamData([this](uint64_t stream_id,
                                             const uint8_t* data,
                                             size_t len, bool fin) {
            if (on_stream_data_) {
                on_stream_data_(static_cast<int>(stream_id), data, len, fin);
            }
            
            // Clean up stream resources when response is complete (FIN received)
            // This is the proper time to clean up because both directions are now closed:
            // - We sent our FIN (request complete)
            // - Server sent FIN (response complete)
            if (fin) {
                CleanupStream(stream_id);
            }
        });
        
        // Use batch mode to aggregate H3 initialization + NEW_CONNECTION_ID
        // into a single packet (reduces 5 packets to 1)
        BeginBatch();
        
        // Send SETTINGS (creates control stream + QPACK streams, all go into batch)
        h3_handler_->SendSettings();
        
        // Send our first alternative connection ID (also goes into batch)
        SendNewConnectionId();
        
        // Send all accumulated frames in one packet
        EndBatch();
        
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
    
    // Update flow control (must do this even for cancelled streams for protocol consistency)
    // Pass offset to correctly handle out-of-order and duplicate data
    flow_controller_.OnStreamBytesReceived(stream_data.stream_id, 
                                            stream_data.offset,
                                            stream_data.length);
    
    // Check if we've sent STOP_SENDING for this stream - if so, ignore the data
    // The peer may not have received our STOP_SENDING yet, so we just silently drop
    if (stop_sending_streams_.find(stream_data.stream_id) != stop_sending_streams_.end()) {
        if (config_.enable_debug) {
            ESP_LOGW(TAG, "  Ignoring STREAM data for cancelled stream %llu",
                     (unsigned long long)stream_data.stream_id);
        }
        return;
    }
    
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
    
    // Send flow control updates immediately (no queue, no piggyback)
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
    if (!crypto_.HasApplicationKeys()) {
        return false;
    }
    
    // Build MAX_DATA frame
    uint8_t frames[32];
    quic::BufferWriter writer(frames, sizeof(frames));
    
    if (!flow_controller_.BuildMaxDataFrame(&writer)) {
        return false;
    }
    
    size_t frame_len = writer.Offset();
    
    // Build 1-RTT packet
    std::vector<uint8_t> packet(256);
    uint64_t pn = app_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::Build1RttPacket(dcid_, pn, false, crypto_.GetKeyPhase() != 0,
                                               frames, frame_len,
                                               crypto_.GetClientAppSecrets(),
                                               packet.data(), packet.size());
    
    if (packet_len == 0) {
        return false;
    }
    
    if (config_.enable_debug) {
        ESP_LOGW(TAG, "[SendFrame] MAX_DATA frame to increase flow control window, pn=%llu, len=%zu",
                 (unsigned long long)pn, packet_len);
    }
    
    // MAX_DATA is ack-eliciting per RFC 9002 - must be reliably delivered
    // to prevent flow control deadlock
    std::vector<uint8_t> frame_copy(frames, frames + frame_len);
    app_tracker_.OnPacketSent(pn, current_time_us_, packet_len, true, std::move(frame_copy), 0);
    loss_detector_.OnPacketSent(pn, current_time_us_, packet_len, true);
    
    return SendPacket(packet.data(), packet_len);
}

bool QuicConnection::Impl::SendMaxStreamDataFrame(uint64_t stream_id) {
    if (!crypto_.HasApplicationKeys()) {
        return false;
    }
    
    // Build MAX_STREAM_DATA frame
    uint8_t frames[32];
    quic::BufferWriter writer(frames, sizeof(frames));
    
    if (!flow_controller_.BuildMaxStreamDataFrame(&writer, stream_id)) {
        return false;
    }
    
    size_t frame_len = writer.Offset();
    
    // Build 1-RTT packet
    std::vector<uint8_t> packet(256);
    uint64_t pn = app_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::Build1RttPacket(dcid_, pn, false, crypto_.GetKeyPhase() != 0,
                                               frames, frame_len,
                                               crypto_.GetClientAppSecrets(),
                                               packet.data(), packet.size());
    
    if (packet_len == 0) {
        return false;
    }
    
    if (config_.enable_debug) {
        ESP_LOGW(TAG, "[SendFrame] MAX_STREAM_DATA for stream %llu, pn=%llu, len=%zu", 
                 (unsigned long long)stream_id, (unsigned long long)pn, packet_len);
    }
    
    // MAX_STREAM_DATA is ack-eliciting per RFC 9002 - must be reliably delivered
    // to prevent flow control deadlock
    std::vector<uint8_t> frame_copy(frames, frames + frame_len);
    app_tracker_.OnPacketSent(pn, current_time_us_, packet_len, true, std::move(frame_copy), stream_id);
    loss_detector_.OnPacketSent(pn, current_time_us_, packet_len, true);
    
    return SendPacket(packet.data(), packet_len);
}

void QuicConnection::Impl::CheckAndSendFlowControlUpdates() {
    // Check connection-level flow control and send update immediately
    if (flow_controller_.ShouldSendMaxData()) {
        SendMaxDataFrame();
    }
    
    // Send ACK if needed
    SendAckIfNeeded(quic::PacketType::k1Rtt);
}

//=============================================================================
// Sending
//=============================================================================

bool QuicConnection::Impl::SendPacket(const uint8_t* data, size_t len) {
    if (!send_cb_) {
        return false;
    }
    
    if (config_.enable_debug) {
        ESP_LOGW(TAG, "[SendPacket] len=%zu bytes", len);
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
    
    // Use time-based check for proper max_ack_delay handling (RFC 9002)
    if (!ack_mgr->ShouldSendAck(current_time_us_)) {
        return true;
    }
    
    // Build ACK frame - use larger buffer for multi-range ACKs (packet loss scenarios)
    std::vector<uint8_t> frames(256);
    quic::BufferWriter writer(frames.data(), frames.size());
    if (!ack_mgr->BuildAckFrame(&writer, current_time_us_)) {
        ESP_LOGE(TAG, "SendAckIfNeeded: BuildAckFrame FAILED");
        return false;
    }
    
    // Build packet
    std::vector<uint8_t> packet(512);
    uint64_t pn = tracker->AllocatePacketNumber();
    size_t packet_len = 0;
    
    switch (pkt_type) {
        case quic::PacketType::kInitial:
            packet_len = quic::BuildInitialPacket(dcid_, scid_,
                                                   retry_token_.data(),
                                                   retry_token_.size(),
                                                   pn,
                                                   frames.data(), writer.Offset(),
                                                   crypto_.GetClientInitialSecrets(),
                                                   packet.data(), packet.size(),
                                                   0);  // No padding for ACK-only
            break;
        case quic::PacketType::kHandshake:
            packet_len = quic::BuildHandshakePacket(dcid_, scid_, pn,
                                                     frames.data(), writer.Offset(),
                                                     crypto_.GetClientHandshakeSecrets(),
                                                     packet.data(), packet.size());
            break;
        default:
            packet_len = quic::Build1RttPacket(dcid_, pn, false, crypto_.GetKeyPhase() != 0,
                                                frames.data(), writer.Offset(),
                                                crypto_.GetClientAppSecrets(),
                                                packet.data(), packet.size());
            break;
    }
    
    if (packet_len == 0) {
        return false;
    }
    
    tracker->OnPacketSent(pn, current_time_us_, packet_len, false);
    ack_mgr->OnAckSent();
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "[SendFrame] ACK packet, type=%d, PN=%llu, len=%zu", 
                 static_cast<int>(pkt_type), (unsigned long long)pn, packet_len);
    }
    
    return SendPacket(packet.data(), packet_len);
}

void QuicConnection::Impl::SendCoalescedAcks() {
    // RFC 9000 Section 14.1: UDP datagrams carrying Initial packets MUST be at least 1200 bytes
    // Therefore, we do NOT send standalone Initial ACK here.
    // Initial ACK is coalesced with Client Finished in SendClientFinished().
    //
    // This function only sends Handshake ACK (no 1200 byte requirement).
    
    if (!handshake_ack_mgr_.ShouldSendAck(current_time_us_)) {
        return;
    }
    
    if (!crypto_.HasHandshakeKeys()) {
        return;
    }
    
    // Build Handshake ACK packet
    uint8_t frames[64];
    quic::BufferWriter writer(frames, sizeof(frames));
    if (!handshake_ack_mgr_.BuildAckFrame(&writer, current_time_us_)) {
        return;
    }
    
    uint64_t pn = handshake_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::BuildHandshakePacket(dcid_, scid_, pn,
                                                    frames, writer.Offset(),
                                                    crypto_.GetClientHandshakeSecrets(),
                                                    packet_buf_, sizeof(packet_buf_));
    if (packet_len > 0) {
        handshake_tracker_.OnPacketSent(pn, current_time_us_, packet_len, false);
        handshake_ack_mgr_.OnAckSent();
        if (config_.enable_debug) {
            ESP_LOGI(TAG, "[SendFrame] Handshake ACK, PN=%llu, len=%zu",
                     (unsigned long long)pn, packet_len);
        }
        SendPacket(packet_buf_, packet_len);
    }
}

//=============================================================================
// Batch Mode - Aggregate multiple STREAM frames into one packet
//=============================================================================

void QuicConnection::Impl::BeginBatch() {
    if (batch_state_.active) {
        ESP_LOGW(TAG, "BeginBatch called while batch already active");
        return;
    }
    
    batch_state_.Reset();
    batch_state_.active = true;
    batch_state_.writer = new quic::BufferWriter(batch_frames_, sizeof(batch_frames_));
    
    // Add ACK frame if needed (will be at the beginning of packet)
    if (app_ack_mgr_.ShouldSendAck(current_time_us_)) {
        if (app_ack_mgr_.BuildAckFrame(batch_state_.writer, current_time_us_)) {
            app_ack_mgr_.OnAckSent();
            if (config_.enable_debug) {
                ESP_LOGD(TAG, "BeginBatch: added ACK frame");
            }
        }
    }
    
    if (config_.enable_debug) {
        ESP_LOGD(TAG, "BeginBatch: started, control frames offset=%zu", 
                 batch_state_.writer->Offset());
    }
}

bool QuicConnection::Impl::EndBatch() {
    if (!batch_state_.active) {
        ESP_LOGW(TAG, "EndBatch called without active batch");
        return false;
    }
    
    if (!batch_state_.writer || batch_state_.writer->Offset() == 0) {
        // Nothing to send
        delete batch_state_.writer;
        batch_state_.Reset();
        return true;
    }
    
    // Build 1-RTT packet with all accumulated frames
    uint64_t pn = app_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::Build1RttPacket(dcid_, pn, false, crypto_.GetKeyPhase() != 0,
                                               batch_frames_, batch_state_.writer->Offset(),
                                               crypto_.GetClientAppSecrets(),
                                               packet_buf_, sizeof(packet_buf_));
    
    if (packet_len == 0) {
        ESP_LOGE(TAG, "EndBatch: Build1RttPacket failed");
        delete batch_state_.writer;
        batch_state_.Reset();
        return false;
    }
    
    // Track the packet - if it has STREAM frames, it's ack-eliciting
    bool has_stream_frames = !batch_state_.stream_frames.empty();
    
    if (has_stream_frames) {
        // For retransmission, we need to save STREAM frame data
        // Build a combined frames buffer for all STREAM frames
        std::vector<uint8_t> stream_frames_copy;
        for (const auto& info : batch_state_.stream_frames) {
            stream_frames_copy.insert(stream_frames_copy.end(),
                                       batch_frames_ + info.frame_start,
                                       batch_frames_ + info.frame_start + info.frame_len);
        }
        
        // Use first stream's ID for tracking (simplified, could be improved)
        uint64_t primary_stream_id = batch_state_.stream_frames[0].stream_id;
        app_tracker_.OnPacketSent(pn, current_time_us_, packet_len, true, 
                                   std::move(stream_frames_copy), primary_stream_id);
        loss_detector_.OnPacketSent(pn, current_time_us_, packet_len, true);
    } else {
        app_tracker_.OnPacketSent(pn, current_time_us_, packet_len, false);
    }
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "EndBatch: sent packet PN=%llu, len=%zu, %zu stream frames",
                 (unsigned long long)pn, packet_len, batch_state_.stream_frames.size());
    }
    
    bool ok = SendPacket(packet_buf_, packet_len);
    
    delete batch_state_.writer;
    batch_state_.Reset();
    
    return ok;
}

bool QuicConnection::Impl::SendStreamData(uint64_t stream_id,
                                           const uint8_t* data,
                                           size_t len, bool fin) {
    if (!crypto_.HasApplicationKeys()) {
        return false;
    }
    
    // Update current time for accurate PTO calculation
    current_time_us_ = quic::GetCurrentTimeUs();
    
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
    
    //=========================================================================
    // Batch Mode: accumulate STREAM frames, send later in EndBatch()
    //=========================================================================
    if (batch_state_.active && batch_state_.writer) {
        size_t frame_start = batch_state_.writer->Offset();
        
        // Build STREAM frame into batch buffer
        if (!quic::BuildStreamFrame(batch_state_.writer, stream_id, offset, data, len, fin)) {
            ESP_LOGE(TAG, "SendStreamData(batch): BuildStreamFrame failed");
            return false;
        }
        
        size_t frame_len = batch_state_.writer->Offset() - frame_start;
        
        // Track this frame for retransmission
        batch_state_.stream_frames.push_back({stream_id, frame_start, frame_len});
        
        // Update flow control
        flow_controller_.OnStreamBytesSent(stream_id, len);
        
        if (config_.enable_debug) {
            ESP_LOGD(TAG, "SendStreamData(batch): stream=%llu, offset=%llu, len=%zu, fin=%d",
                     (unsigned long long)stream_id, (unsigned long long)offset, len, fin ? 1 : 0);
        }
        
        return true;  // Frame buffered, will be sent in EndBatch()
    }
    
    //=========================================================================
    // Normal Mode: build packet with STREAM frame (optionally piggyback ACK)
    //=========================================================================
    quic::BufferWriter writer(frame_buf_, sizeof(frame_buf_));
    
    // First, add ACK and pending control frames (non-retransmittable)
    // Add ACK frame if needed
    if (app_ack_mgr_.ShouldSendAck(current_time_us_)) {
        if (app_ack_mgr_.BuildAckFrame(&writer, current_time_us_)) {
            app_ack_mgr_.OnAckSent();
            if (config_.enable_debug) {
                ESP_LOGD(TAG, "SendStreamData: piggybacked ACK frame");
            }
        }
    }
    
    // Mark where STREAM frame starts (for retransmission tracking)
    size_t stream_frame_start = writer.Offset();
    
    // Now add the STREAM frame
    if (!quic::BuildStreamFrame(&writer, stream_id, offset, data, len, fin)) {
        return false;
    }
    
    // Save ONLY the STREAM frame data for retransmission (not ACK/control frames)
    size_t stream_frame_len = writer.Offset() - stream_frame_start;
    std::vector<uint8_t> frame_copy(frame_buf_ + stream_frame_start, 
                                     frame_buf_ + stream_frame_start + stream_frame_len);
    
    // Build 1-RTT packet
    uint64_t pn = app_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::Build1RttPacket(dcid_, pn, false, crypto_.GetKeyPhase() != 0,
                                               frame_buf_, writer.Offset(),
                                               crypto_.GetClientAppSecrets(),
                                               packet_buf_, sizeof(packet_buf_));
    
    if (packet_len == 0) {
        return false;
    }
    
    // Track sent packet with STREAM frame data for retransmission
    app_tracker_.OnPacketSent(pn, current_time_us_, packet_len, true, std::move(frame_copy), stream_id);
    loss_detector_.OnPacketSent(pn, current_time_us_, packet_len, true);
    
    // Update flow control
    flow_controller_.OnStreamBytesSent(stream_id, len);
    
    return SendPacket(packet_buf_, packet_len);
}

//=============================================================================
// Timer
//=============================================================================

uint32_t QuicConnection::Impl::OnTimerTick(uint32_t elapsed_ms) {
    current_time_us_ = quic::GetCurrentTimeUs();
    time_since_last_activity_us_ += elapsed_ms * 1000;
    
    // Maximum wait time (60 seconds as upper bound)
    static constexpr uint32_t kMaxWaitMs = 60000;
    uint32_t next_timer_ms = kMaxWaitMs;
    
    // Check idle timeout (use effective timeout which is min of local and peer)
    if (handshake_complete_ && effective_idle_timeout_ms_ > 0) {
        uint64_t idle_deadline_us = effective_idle_timeout_ms_ * 1000ULL;
        if (time_since_last_activity_us_ > idle_deadline_us) {
            Close(0, "idle timeout");
            return 0;
        }
        // Calculate time until idle timeout
        uint64_t remaining_us = idle_deadline_us - time_since_last_activity_us_;
        uint32_t remaining_ms = static_cast<uint32_t>(remaining_us / 1000);
        if (remaining_ms < next_timer_ms) {
            next_timer_ms = remaining_ms;
        }
    }
    
    // Check handshake timeout (only when actively handshaking)
    if (state_ == ConnectionState::kHandshakeInProgress) {
        uint64_t handshake_deadline_us = handshake_start_time_us_ +
                                         config_.handshake_timeout_ms * 1000ULL;
        if (current_time_us_ > handshake_deadline_us) {
            state_ = ConnectionState::kFailed;
            if (on_disconnected_) {
                on_disconnected_(-1, "handshake timeout");
            }
            return 0;
        }
        // Calculate time until handshake timeout
        uint64_t remaining_us = handshake_deadline_us - current_time_us_;
        uint32_t remaining_ms = static_cast<uint32_t>(remaining_us / 1000);
        if (remaining_ms < next_timer_ms) {
            next_timer_ms = remaining_ms;
        }
    }
    
    // Check PTO - all PTO handling is done via on_pto_ callback (HandlePto)
    loss_detector_.OnTimerTick(current_time_us_);
    
    // Calculate precise time until next PTO (considering exponential backoff)
    uint64_t time_until_pto_us = loss_detector_.GetTimeUntilNextPto(current_time_us_);
    if (time_until_pto_us > 0) {
        // Round up: 500us -> 1ms, not 0ms
        uint32_t pto_ms = static_cast<uint32_t>((time_until_pto_us + 999) / 1000);
        if (pto_ms < next_timer_ms) {
            next_timer_ms = pto_ms;
        }
    }
    
    // Check connection migration timeout (3 * PTO timeout for path validation)
    if (migration_in_progress_ && migration_challenge_sent_time_us_ > 0) {
        // Use 3 * PTO (approximately 3 * RTT) as path validation timeout
        uint64_t pto_timeout_us = loss_detector_.GetPtoTimeout() * 1000;  // Convert ms to us
        uint64_t migration_timeout_us = 3 * pto_timeout_us;
        uint64_t elapsed_us = current_time_us_ - migration_challenge_sent_time_us_;
        
        if (elapsed_us > migration_timeout_us) {
            // Migration path validation timeout
            migration_retry_count_++;
            
            if (migration_retry_count_ >= kMaxMigrationRetries) {
                // Max retries reached, fail the migration
                if (config_.enable_debug) {
                    ESP_LOGW(TAG, "Migration failed: path validation timeout after %lu retries",
                             (unsigned long)kMaxMigrationRetries);
                }
                CompleteMigration(false);
            } else {
                // Retry the path challenge
                if (config_.enable_debug) {
                    ESP_LOGI(TAG, "Migration path validation timeout, retrying (%lu/%lu)",
                             migration_retry_count_, (unsigned long)kMaxMigrationRetries);
                }
                SendMigrationPathChallenge();
            }
        } else {
            // Calculate time until migration timeout
            uint64_t remaining_us = migration_timeout_us - elapsed_us;
            uint32_t remaining_ms = static_cast<uint32_t>((remaining_us + 999) / 1000);
            if (remaining_ms < next_timer_ms) {
                next_timer_ms = remaining_ms;
            }
        }
    }
    
    // Check if delayed ACKs need to be sent
    if (handshake_complete_) {
        SendAckIfNeeded(quic::PacketType::k1Rtt);
    } else {
        // During handshake, coalesce Initial + Handshake ACKs into one UDP datagram
        SendCoalescedAcks();
    }
    
    // Calculate time until next ACK deadline
    // Use the appropriate ACK manager based on handshake state
    auto update_timer_from_ack_deadline = [&](uint64_t deadline_us) {
        if (deadline_us > 0 && deadline_us > current_time_us_) {
            uint64_t time_until_ack_us = deadline_us - current_time_us_;
            uint32_t ack_deadline_ms = static_cast<uint32_t>((time_until_ack_us + 999) / 1000);
            if (ack_deadline_ms < next_timer_ms) {
                next_timer_ms = ack_deadline_ms;
            }
        }
    };
    
    if (handshake_complete_) {
        update_timer_from_ack_deadline(app_ack_mgr_.GetAckDeadlineUs());
    } else {
        // During handshake, check Initial and Handshake ACK deadlines
        update_timer_from_ack_deadline(initial_ack_mgr_.GetAckDeadlineUs());
        update_timer_from_ack_deadline(handshake_ack_mgr_.GetAckDeadlineUs());
    }
    
    // Note: Write queue processing is now handled by Http3Manager.
    // This timer tick only handles QUIC-level operations.
    
    // Ensure we don't return 0 (which would mean immediate re-trigger)
    // and cap at maximum wait time
    if (next_timer_ms == 0) {
        next_timer_ms = 1;
    } else if (next_timer_ms > kMaxWaitMs) {
        next_timer_ms = kMaxWaitMs;
    }
    
    return next_timer_ms;
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
    std::vector<uint8_t> h3_frame_buf(1200);
    std::vector<uint8_t> encoded(payload_buf_, payload_buf_ + qpack_len);
    size_t hf_len = h3::BuildHeadersFrame(encoded, h3_frame_buf.data(), h3_frame_buf.size());
    
    if (hf_len == 0 || !SendStreamData(static_cast<uint64_t>(stream_id), 
                                        h3_frame_buf.data(), hf_len, false)) {
        return -1;
    }
    
    return static_cast<int>(stream_id);
}

ssize_t QuicConnection::Impl::WriteStream(int stream_id, 
                                           const uint8_t* data, size_t len) {
    if (!IsConnected()) {
        ESP_LOGE(TAG, "WriteStream failed: not connected");
        return -1;  // Error
    }
    
    // Check flow control before building frame
    size_t sendable = GetSendableBytes(stream_id);
    size_t actual_len = len;
    if (sendable < len) {
        ESP_LOGD(TAG, "WriteStream: flow control limit: sendable=%zu, requested=%zu", sendable, len);
        actual_len = sendable;
        if (actual_len == 0) {
            ESP_LOGD(TAG, "WriteStream: flow control blocked");
            return 0;  // Blocked, no bytes sent
        }
    }
    
    // Build DATA frame (use payload_buf_ as temp buffer, SendStreamData uses frame_buf_)
    size_t frame_len = h3::BuildDataFrame(data, actual_len, payload_buf_, sizeof(payload_buf_));
    if (frame_len == 0) {
        ESP_LOGE(TAG, "WriteStream failed: BuildDataFrame returned 0 (len=%zu, buf_size=%zu)", 
                 actual_len, sizeof(payload_buf_));
        return -1;  // Error
    }
    
    bool result = SendStreamData(static_cast<uint64_t>(stream_id), payload_buf_, frame_len, false);
    if (!result) {
        ESP_LOGE(TAG, "WriteStream failed: SendStreamData returned false (stream_id=%d, frame_len=%zu)", 
                 stream_id, frame_len);
        return -1;  // Error
    }
    
    return static_cast<ssize_t>(actual_len);  // Return bytes of payload written
}

bool QuicConnection::Impl::FinishStream(int stream_id) {
    if (!IsConnected()) {
        return false;
    }
    
    // Send empty STREAM frame with FIN
    return SendStreamData(static_cast<uint64_t>(stream_id), nullptr, 0, true);
}

bool QuicConnection::Impl::ResetStream(int stream_id, uint64_t error_code) {
    if (!IsConnected()) {
        return false;
    }
    
    // Update current time for accurate PTO calculation
    current_time_us_ = quic::GetCurrentTimeUs();
    
    uint64_t sid = static_cast<uint64_t>(stream_id);
    
    // Check if stream was already reset
    if (reset_streams_.find(sid) != reset_streams_.end()) {
        ESP_LOGW(TAG, "ResetStream: stream %d already reset", stream_id);
        return false;
    }
    
    // Get stream flow state to determine final size
    uint64_t final_size = 0;
    StreamFlowState* stream_state = flow_controller_.GetStreamState(sid);
    if (stream_state) {
        final_size = stream_state->send_offset;
    }
    
    // Clear frame data for unacked packets belonging to this stream
    // This prevents unnecessary retransmissions of data that will be ignored by peer
    size_t cleared = app_tracker_.ClearStreamFrames(sid);
    if (config_.enable_debug && cleared > 0) {
        ESP_LOGI(TAG, "ResetStream: cleared frames from %zu unacked packets for stream %d",
                 cleared, stream_id);
    }
    
    // Build both RESET_STREAM and STOP_SENDING frames in the same packet
    // RESET_STREAM: tells peer we won't send more data
    // STOP_SENDING: tells peer to stop sending data to us
    quic::BufferWriter writer(frame_buf_, sizeof(frame_buf_));
    
    if (!quic::BuildResetStreamFrame(&writer, sid, error_code, final_size)) {
        ESP_LOGE(TAG, "ResetStream: failed to build RESET_STREAM frame");
        return false;
    }
    
    if (!quic::BuildStopSendingFrame(&writer, sid, error_code)) {
        ESP_LOGE(TAG, "ResetStream: failed to build STOP_SENDING frame");
        return false;
    }
    
    // Build 1-RTT packet and send
    uint64_t pn = app_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::Build1RttPacket(dcid_, pn, false, crypto_.GetKeyPhase() != 0,
                                               frame_buf_, writer.Offset(),
                                               crypto_.GetClientAppSecrets(),
                                               packet_buf_, sizeof(packet_buf_));
    
    if (packet_len == 0) {
        ESP_LOGE(TAG, "ResetStream: failed to build 1-RTT packet");
        return false;
    }
    
    app_tracker_.OnPacketSent(pn, current_time_us_, packet_len, true);
    loss_detector_.OnPacketSent(pn, current_time_us_, packet_len, true);
    
    // Mark stream as reset locally (both directions)
    reset_streams_.insert(sid);
    stop_sending_streams_.insert(sid);
    
    ESP_LOGI(TAG, "ResetStream: stream %d reset with RESET_STREAM + STOP_SENDING, error=0x%llx, final_size=%llu",
             stream_id, (unsigned long long)error_code, (unsigned long long)final_size);
    
    return SendPacket(packet_buf_, packet_len);
}

//=============================================================================
// Writable Notification
//=============================================================================

void QuicConnection::Impl::NotifyWritable() {
    if (on_writable_) {
        on_writable_();
    }
}

void QuicConnection::Impl::CleanupStream(uint64_t stream_id) {
    // Remove from reset/stop_sending tracking sets
    reset_streams_.erase(stream_id);
    stop_sending_streams_.erase(stream_id);
    
    // Remove flow control state
    flow_controller_.RemoveStream(stream_id);
    
    // Close H3 stream (releases recv_buffer, pending_chunks, etc.)
    if (h3_handler_) {
        h3_handler_->CloseStream(stream_id);
    }
    
    if (config_.enable_debug) {
        ESP_LOGD(TAG, "CleanupStream: stream %llu resources released",
                 (unsigned long long)stream_id);
    }
}

//=============================================================================
// Retransmission
//=============================================================================

void QuicConnection::Impl::RetransmitLostPackets(const std::vector<SentPacketInfo*>& lost_packets) {
    if (!crypto_.HasApplicationKeys()) {
        return;
    }
    
    for (auto* pkt : lost_packets) {
        if (pkt->frames.empty()) {
            // No frame data saved, skip (e.g., ACK-only packets or cleared stream frames)
            continue;
        }
        
        if (config_.enable_debug) {
            ESP_LOGI(TAG, "Retransmitting lost packet PN=%llu (%zu bytes of frames, stream=%llu)",
                     (unsigned long long)pkt->packet_number, pkt->frames.size(),
                     (unsigned long long)pkt->stream_id);
        }
        
        // Build new 1-RTT packet with the same frames
        uint64_t new_pn = app_tracker_.AllocatePacketNumber();
        size_t packet_len = quic::Build1RttPacket(dcid_, new_pn, false, crypto_.GetKeyPhase() != 0,
                                                   pkt->frames.data(), pkt->frames.size(),
                                                   crypto_.GetClientAppSecrets(),
                                                   packet_buf_, sizeof(packet_buf_));
        
        if (packet_len == 0) {
            ESP_LOGW(TAG, "Failed to build retransmit packet");
            continue;
        }
        
        // Copy frames for the new packet (in case it also gets lost)
        std::vector<uint8_t> frame_copy = pkt->frames;
        
        // Track the new packet with same stream_id
        app_tracker_.OnPacketSent(new_pn, current_time_us_, packet_len, true, 
                                  std::move(frame_copy), pkt->stream_id);
        loss_detector_.OnPacketSent(new_pn, current_time_us_, packet_len, true);
        
        SendPacket(packet_buf_, packet_len);
    }
}

void QuicConnection::Impl::HandlePto() {
    // Dispatch PTO handling based on connection state
    if (state_ == ConnectionState::kHandshakeInProgress) {
        // Handshake in progress - retransmit Initial packet
        if (config_.enable_debug) {
            ESP_LOGI(TAG, "PTO fired, retransmitting Initial");
        }
        SendInitialPacket(true);  // Mark as retransmit to avoid updating transcript hash
    } else if (state_ == ConnectionState::kConnected) {
        if (!handshake_complete_) {
            // Client Finished sent but HANDSHAKE_DONE not received yet
            SendHandshakePtoProbe();
        } else {
            // Normal 1-RTT operation
            SendPtoProbe();
        }
    }
}

void QuicConnection::Impl::SendPtoProbe() {
    if (!crypto_.HasApplicationKeys()) {
        return;
    }
    
    // Get unacked packets that have frame data for potential retransmission
    auto unacked = app_tracker_.GetUnackedPackets();
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "PTO fired for 1-RTT, %zu unacked packets", unacked.size());
    }
    
    // Find the oldest unacked packet with frame data to retransmit
    SentPacketInfo* oldest_with_data = nullptr;
    for (auto* pkt : unacked) {
        if (!pkt->frames.empty()) {
            if (!oldest_with_data || pkt->sent_time_us < oldest_with_data->sent_time_us) {
                oldest_with_data = pkt;
            }
        }
    }
    
    if (oldest_with_data) {
        // Retransmit the oldest unacked packet with frame data
        if (config_.enable_debug) {
            ESP_LOGI(TAG, "PTO probe: retransmitting PN=%llu (stream=%llu)",
                     (unsigned long long)oldest_with_data->packet_number,
                     (unsigned long long)oldest_with_data->stream_id);
        }
        
        uint64_t new_pn = app_tracker_.AllocatePacketNumber();
        size_t packet_len = quic::Build1RttPacket(dcid_, new_pn, false, crypto_.GetKeyPhase() != 0,
                                                   oldest_with_data->frames.data(),
                                                   oldest_with_data->frames.size(),
                                                   crypto_.GetClientAppSecrets(),
                                                   packet_buf_, sizeof(packet_buf_));
        
        if (packet_len > 0) {
            std::vector<uint8_t> frame_copy = oldest_with_data->frames;
            app_tracker_.OnPacketSent(new_pn, current_time_us_, packet_len, true, 
                                      std::move(frame_copy), oldest_with_data->stream_id);
            loss_detector_.OnPacketSent(new_pn, current_time_us_, packet_len, true);
            SendPacket(packet_buf_, packet_len);
        }
    } else {
        // No data to retransmit - check if we have any unacked ack-eliciting packets
        // If not, we don't need to send PING as there's nothing waiting for ACK
        if (unacked.empty()) {
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "PTO probe: no unacked packets, clearing PTO timer");
            }
            // Clear PTO timer since there's nothing to probe
            loss_detector_.ClearPtoTimer();
            return;
        }
        
        // We have unacked packets but none have frame data (e.g., pure ACK packets
        // that don't need retransmission). Send PING to elicit ACK.
        if (config_.enable_debug) {
            ESP_LOGI(TAG, "PTO probe: sending PING (no data to retransmit)");
        }
        
        uint8_t ping_frame[1] = {0x01};  // PING frame
        uint64_t pn = app_tracker_.AllocatePacketNumber();
        size_t packet_len = quic::Build1RttPacket(dcid_, pn, false, crypto_.GetKeyPhase() != 0,
                                                   ping_frame, 1,
                                                   crypto_.GetClientAppSecrets(),
                                                   packet_buf_, sizeof(packet_buf_));
        
        if (packet_len > 0) {
            app_tracker_.OnPacketSent(pn, current_time_us_, packet_len, true);
            loss_detector_.OnPacketSent(pn, current_time_us_, packet_len, true);
            SendPacket(packet_buf_, packet_len);
        }
    }
}

void QuicConnection::Impl::SendHandshakePtoProbe() {
    // Retransmit Handshake packets (e.g., Client Finished) when PTO fires
    // after sending Client Finished but before receiving HANDSHAKE_DONE
    auto unacked = handshake_tracker_.GetUnackedPackets();
    if (unacked.empty()) {
        return;
    }
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "PTO fired, retransmitting Handshake packets (%zu unacked)", 
                 unacked.size());
    }
    
    // Find and retransmit one packet with frame data
    for (auto* pkt : unacked) {
        if (pkt->frames.empty()) {
            continue;
        }
        
        uint64_t new_pn = handshake_tracker_.AllocatePacketNumber();
        size_t packet_len = quic::BuildHandshakePacket(
            dcid_, scid_, new_pn,
            pkt->frames.data(), pkt->frames.size(),
            crypto_.GetClientHandshakeSecrets(),
            packet_buf_, sizeof(packet_buf_));
        
        if (packet_len > 0) {
            std::vector<uint8_t> frame_copy = pkt->frames;
            handshake_tracker_.OnPacketSent(new_pn, current_time_us_, 
                                            packet_len, true, std::move(frame_copy));
            loss_detector_.OnPacketSent(new_pn, current_time_us_, packet_len, true);
            SendPacket(packet_buf_, packet_len);
            
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "Retransmitted Handshake packet, new PN=%llu", 
                         (unsigned long long)new_pn);
            }
        }
        break;  // Only retransmit one packet per PTO
    }
}

//=============================================================================
// Flow Control Checks (borrowed from Python version)
//=============================================================================

bool QuicConnection::Impl::CanSend(int stream_id, size_t len) const {
    return GetSendableBytes(stream_id) >= len;
}

size_t QuicConnection::Impl::GetSendableBytes(int stream_id) const {
    // Get connection-level window
    uint64_t conn_window = flow_controller_.GetConnectionSendWindow();
    
    // Get stream-level window
    uint64_t stream_window = flow_controller_.GetStreamSendWindow(
        static_cast<uint64_t>(stream_id));
    
    // Return minimum of both
    uint64_t result = std::min(conn_window, stream_window);
    return static_cast<size_t>(result);
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
    // Use ESP-IDF hardware random number generator
    // This avoids stack allocation (~2.5KB for std::mt19937) and is more efficient
    for (size_t i = 0; i < len; i += 4) {
        uint32_t random_word = esp_random();
        size_t remaining = len - i;
        size_t copy_len = remaining < 4 ? remaining : 4;
        memcpy(buf + i, &random_word, copy_len);
    }
}

bool QuicConnection::Impl::HasAckElicitingFrames(const uint8_t* payload, size_t len) {
    // RFC 9002: Only ACK-eliciting packets should trigger sending ACK
    // Non-ACK-eliciting frames: PADDING (0x00), ACK (0x02-0x03), CONNECTION_CLOSE (0x1c-0x1d)
    quic::BufferReader reader(payload, len);
    
    while (reader.Remaining() > 0) {
        uint8_t frame_type;
        if (!reader.ReadUint8(&frame_type)) break;
        
        // Check if this frame is ACK-eliciting
        if (frame_type != 0x00 && frame_type != 0x02 && frame_type != 0x03 &&
            frame_type != 0x1c && frame_type != 0x1d) {
            return true;  // Found an ACK-eliciting frame
        }
        
        // Skip non-ACK-eliciting frame content to continue scanning
        if (frame_type == 0x00) {
            // PADDING - single byte, already consumed
            continue;
        } else if (frame_type == 0x02 || frame_type == 0x03) {
            // ACK frame - skip its content
            uint64_t largest_ack, ack_delay, ack_range_count, first_range;
            if (!reader.ReadVarint(&largest_ack) || !reader.ReadVarint(&ack_delay) ||
                !reader.ReadVarint(&ack_range_count) || !reader.ReadVarint(&first_range)) {
                break;
            }
            for (uint64_t i = 0; i < ack_range_count; i++) {
                uint64_t gap, range;
                if (!reader.ReadVarint(&gap) || !reader.ReadVarint(&range)) break;
            }
            if (frame_type == 0x03) {
                // ACK_ECN has 3 additional varints
                uint64_t ect0, ect1, ecn_ce;
                reader.ReadVarint(&ect0);
                reader.ReadVarint(&ect1);
                reader.ReadVarint(&ecn_ce);
            }
        } else if (frame_type == 0x1c || frame_type == 0x1d) {
            // CONNECTION_CLOSE frame - skip its content
            uint64_t error_code, frame_type_field, reason_len;
            if (!reader.ReadVarint(&error_code)) break;
            if (frame_type == 0x1c) {
                if (!reader.ReadVarint(&frame_type_field)) break;
            }
            if (!reader.ReadVarint(&reason_len)) break;
            reader.Seek(reader.Offset() + reason_len);
        }
    }
    
    return false;  // No ACK-eliciting frames found
}

//=============================================================================
// Frame Processor Setup (for 1-RTT packets)
//=============================================================================

void QuicConnection::Impl::SetupFrameProcessorCallbacks() {
    // ACK frame callback
    frame_processor_.SetOnAck([this](const AckFrameData& ack_data) {
        OnFrameAck(ack_data);
    });
    
    // STREAM frame callback
    frame_processor_.SetOnStream([this](uint64_t stream_id, uint64_t offset,
                                         const uint8_t* data, size_t len, bool fin) {
        OnFrameStream(stream_id, offset, data, len, fin);
    });
    
    // MAX_DATA frame callback
    frame_processor_.SetOnMaxData([this](uint64_t max_data) {
        OnFrameMaxData(max_data);
    });
    
    // MAX_STREAM_DATA frame callback
    frame_processor_.SetOnMaxStreamData([this](uint64_t stream_id, uint64_t max_data) {
        OnFrameMaxStreamData(stream_id, max_data);
    });
    
    // DATA_BLOCKED frame callback
    frame_processor_.SetOnDataBlocked([this](uint64_t limit) {
        OnFrameDataBlocked(limit);
    });
    
    // STREAM_DATA_BLOCKED frame callback
    frame_processor_.SetOnStreamDataBlocked([this](uint64_t stream_id, uint64_t limit) {
        OnFrameStreamDataBlocked(stream_id, limit);
    });
    
    // CONNECTION_CLOSE frame callback
    frame_processor_.SetOnConnectionClose([this](const ConnectionCloseData& data) {
        OnFrameConnectionClose(data);
    });
    
    // HANDSHAKE_DONE frame callback
    frame_processor_.SetOnHandshakeDone([this]() {
        OnFrameHandshakeDone();
    });
    
    // NEW_CONNECTION_ID frame callback
    frame_processor_.SetOnNewConnectionId([this](const NewConnectionIdData& data) {
        OnFrameNewConnectionId(data);
    });
    
    // PATH_CHALLENGE frame callback
    frame_processor_.SetOnPathChallenge([this](const uint8_t* data) {
        OnFramePathChallenge(data);
    });
    
    // PATH_RESPONSE frame callback
    frame_processor_.SetOnPathResponse([this](const uint8_t* data) {
        OnFramePathResponse(data);
    });
    
    // DATAGRAM frame callback
    frame_processor_.SetOnDatagram([this](const uint8_t* data, size_t len) {
        OnFrameDatagram(data, len);
    });
    
    // RESET_STREAM frame callback
    frame_processor_.SetOnResetStream([this](const ResetStreamData& data) {
        reset_streams_.insert(data.stream_id);
    });
    
    // STOP_SENDING frame callback
    frame_processor_.SetOnStopSending([this](const StopSendingData& data) {
        stop_sending_streams_.insert(data.stream_id);
    });
    
    // RETIRE_CONNECTION_ID frame callback
    // Peer is retiring one of our connection IDs
    frame_processor_.SetOnRetireConnectionId([this](uint64_t sequence_number) {
        // Remove the retired connection ID from our list
        auto it = local_connection_ids_.find(sequence_number);
        if (it != local_connection_ids_.end()) {
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "Peer retired our connection ID seq=%llu", 
                         (unsigned long long)sequence_number);
            }
            local_connection_ids_.erase(it);
            
            // Optionally send a new connection ID to replace the retired one
            SendNewConnectionId();
        }
    });
}

//=============================================================================
// Frame Callback Handlers
//=============================================================================

void QuicConnection::Impl::OnFrameAck(const AckFrameData& ack_data) {
    // Process ACK for application packet number space
    size_t newly_acked;
    app_tracker_.OnAckReceived(ack_data.largest_ack,
                               ack_data.ack_delay,
                               ack_data.first_ack_range,
                               ack_data.ack_ranges,
                               current_time_us_,
                               &newly_acked);
    
    // Update loss detector with RTT and detect lost packets
    // Note: Decode peer's ACK delay using peer's ack_delay_exponent (from transport params)
    uint64_t decoded_ack_delay = ack_data.ack_delay << peer_params_.ack_delay_exponent;
    
    if (app_tracker_.GetLatestRttUs() > 0) {
        loss_detector_.GetRttEstimator().OnRttSample(
            app_tracker_.GetLatestRttUs(),
            decoded_ack_delay);
    }
    
    // Detect lost packets and trigger retransmission via on_loss_ callback
    loss_detector_.OnAckReceived(ack_data.largest_ack, decoded_ack_delay,
                                  current_time_us_, &app_tracker_);
    
    // ACK frees up congestion window, notify upper layer
    if (newly_acked > 0) {
        NotifyWritable();
    }
}

void QuicConnection::Impl::OnFrameStream(uint64_t stream_id, uint64_t offset,
                                          const uint8_t* data, size_t len, bool fin) {
    // Update flow control - pass offset to correctly handle out-of-order/duplicate data
    flow_controller_.OnStreamBytesReceived(stream_id, offset, len);
    
    // Pass to H3 handler
    if (h3_handler_) {
        h3_handler_->OnStreamData(stream_id, offset, data, len, fin);
    }
    
    // Send flow control updates immediately (no queue, no piggyback)
    if (flow_controller_.ShouldSendMaxData()) {
        SendMaxDataFrame();
    }
    if (flow_controller_.ShouldSendMaxStreamData(stream_id)) {
        SendMaxStreamDataFrame(stream_id);
    }
}

void QuicConnection::Impl::OnFrameMaxData(uint64_t max_data) {
    flow_controller_.OnMaxDataReceived(max_data);
    // Flow control window updated, notify upper layer
    NotifyWritable();
}

void QuicConnection::Impl::OnFrameMaxStreamData(uint64_t stream_id, uint64_t max_data) {
    flow_controller_.OnMaxStreamDataReceived(stream_id, max_data);
    
    // Notify upper layer that this stream is now writable
    if (on_stream_writable_) {
        on_stream_writable_(static_cast<int>(stream_id));
    }
}

void QuicConnection::Impl::OnFrameDataBlocked(uint64_t limit) {
    // Peer is blocked on connection-level flow control, send MAX_DATA
    SendMaxDataFrame();
}

void QuicConnection::Impl::OnFrameStreamDataBlocked(uint64_t stream_id, uint64_t limit) {
    // Peer is blocked on stream-level flow control, send MAX_STREAM_DATA
    SendMaxStreamDataFrame(stream_id);
}

void QuicConnection::Impl::OnFrameConnectionClose(const ConnectionCloseData& data) {
    state_ = ConnectionState::kClosed;
    
    if (on_disconnected_) {
        on_disconnected_(static_cast<int>(data.error_code), data.reason);
    }
}

void QuicConnection::Impl::OnFrameHandshakeDone() {
    ProcessHandshakeDoneFrame();
}

void QuicConnection::Impl::OnFrameNewConnectionId(const NewConnectionIdData& data) {
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "NEW_CONNECTION_ID: seq=%llu, retire_prior=%llu, cid_len=%zu",
                 (unsigned long long)data.sequence_number,
                 (unsigned long long)data.retire_prior_to,
                 data.connection_id.length);
    }
    
    // Store the new peer connection ID
    PeerConnectionIdInfo info;
    info.cid = data.connection_id;
    std::memcpy(info.stateless_reset_token, data.stateless_reset_token, 16);
    info.retired = false;
    
    peer_connection_ids_[data.sequence_number] = info;
    
    // Handle retire_prior_to - retire old connection IDs
    if (data.retire_prior_to > peer_retire_prior_to_) {
        peer_retire_prior_to_ = data.retire_prior_to;
        RetirePeerConnectionIdsPriorTo(data.retire_prior_to);
    }
}

//=============================================================================
// Connection ID Management
//=============================================================================

void QuicConnection::Impl::RetirePeerConnectionIdsPriorTo(uint64_t retire_prior_to) {
    for (auto& [seq, info] : peer_connection_ids_) {
        if (seq < retire_prior_to && !info.retired) {
            info.retired = true;
            SendRetireConnectionId(seq);
            
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "Retiring peer connection ID seq=%llu", (unsigned long long)seq);
            }
        }
    }
}

bool QuicConnection::Impl::SendRetireConnectionId(uint64_t sequence_number) {
    if (!crypto_.HasApplicationKeys()) {
        return false;
    }
    
    // Build RETIRE_CONNECTION_ID frame
    quic::BufferWriter writer(frame_buf_, sizeof(frame_buf_));
    if (!quic::BuildRetireConnectionIdFrame(&writer, sequence_number)) {
        return false;
    }
    
    // Build 1-RTT packet
    uint64_t pn = app_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::Build1RttPacket(dcid_, pn, false, crypto_.GetKeyPhase() != 0,
                                               frame_buf_, writer.Offset(),
                                               crypto_.GetClientAppSecrets(),
                                               packet_buf_, sizeof(packet_buf_));
    
    if (packet_len == 0) {
        return false;
    }
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "Sending RETIRE_CONNECTION_ID seq=%llu", (unsigned long long)sequence_number);
    }
    
    app_tracker_.OnPacketSent(pn, current_time_us_, packet_len, true);
    return SendPacket(packet_buf_, packet_len);
}

bool QuicConnection::Impl::SendNewConnectionId() {
    if (!crypto_.HasApplicationKeys()) {
        return false;
    }
    
    // Generate a new connection ID
    uint64_t seq = ++local_cid_sequence_;
    LocalConnectionIdInfo info;
    
    // Generate random CID (8 bytes)
    for (size_t i = 0; i < 8; i += 4) {
        uint32_t random_word = esp_random();
        size_t copy_len = std::min(size_t(4), 8 - i);
        std::memcpy(info.cid.data.data() + i, &random_word, copy_len);
    }
    info.cid.length = 8;
    
    // Generate random stateless reset token (16 bytes)
    for (size_t i = 0; i < 16; i += 4) {
        uint32_t random_word = esp_random();
        size_t copy_len = std::min(size_t(4), 16 - i);
        std::memcpy(info.stateless_reset_token + i, &random_word, copy_len);
    }
    
    // Store it
    local_connection_ids_[seq] = info;
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "Sending NEW_CONNECTION_ID seq=%llu, cid=%02x%02x%02x%02x...",
                 (unsigned long long)seq,
                 info.cid.data[0], info.cid.data[1], info.cid.data[2], info.cid.data[3]);
    }
    
    //=========================================================================
    // Batch Mode: add frame to batch buffer
    //=========================================================================
    if (batch_state_.active && batch_state_.writer) {
        if (!quic::BuildNewConnectionIdFrame(batch_state_.writer, seq, 0, 
                                              info.cid, info.stateless_reset_token)) {
            return false;
        }
        return true;  // Frame buffered, will be sent in EndBatch()
    }
    
    //=========================================================================
    // Normal Mode: build and send immediately
    //=========================================================================
    quic::BufferWriter writer(frame_buf_, sizeof(frame_buf_));
    if (!quic::BuildNewConnectionIdFrame(&writer, seq, 0, info.cid, info.stateless_reset_token)) {
        return false;
    }
    
    // Build 1-RTT packet
    uint64_t pn = app_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::Build1RttPacket(dcid_, pn, false, crypto_.GetKeyPhase() != 0,
                                               frame_buf_, writer.Offset(),
                                               crypto_.GetClientAppSecrets(),
                                               packet_buf_, sizeof(packet_buf_));
    
    if (packet_len == 0) {
        return false;
    }
    
    app_tracker_.OnPacketSent(pn, current_time_us_, packet_len, true);
    return SendPacket(packet_buf_, packet_len);
}

quic::ConnectionId* QuicConnection::Impl::GetActivePeerConnectionId() {
    // Return the first non-retired peer connection ID, or dcid_ if none available
    for (auto& [seq, info] : peer_connection_ids_) {
        if (!info.retired) {
            return &info.cid;
        }
    }
    return &dcid_;
}

bool QuicConnection::Impl::IsStatelessReset(const uint8_t* data, size_t len) {
    // Stateless Reset must be at least 21 bytes (1 byte header + 4 bytes random + 16 bytes token)
    if (len < 21) {
        return false;
    }
    
    // Check the last 16 bytes against known stateless reset tokens
    const uint8_t* token_in_packet = data + len - 16;
    
    // Check against peer's tokens from NEW_CONNECTION_ID
    for (const auto& [seq, info] : peer_connection_ids_) {
        if (std::memcmp(token_in_packet, info.stateless_reset_token, 16) == 0) {
            return true;
        }
    }
    
    // Also check against the stateless_reset_token from transport parameters
    if (peer_params_.stateless_reset_token_present) {
        if (std::memcmp(token_in_packet, peer_params_.stateless_reset_token, 16) == 0) {
            return true;
        }
    }
    
    return false;
}

void QuicConnection::Impl::OnFramePathChallenge(const uint8_t* data) {
    // Respond to PATH_CHALLENGE with PATH_RESPONSE
    if (!crypto_.HasApplicationKeys()) {
        return;
    }
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "PATH_CHALLENGE received, sending PATH_RESPONSE");
    }
    
    // Build PATH_RESPONSE frame
    quic::BufferWriter writer(frame_buf_, sizeof(frame_buf_));
    if (!quic::BuildPathResponseFrame(&writer, data)) {
        return;
    }
    
    // Build 1-RTT packet
    uint64_t pn = app_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::Build1RttPacket(dcid_, pn, false, crypto_.GetKeyPhase() != 0,
                                               frame_buf_, writer.Offset(),
                                               crypto_.GetClientAppSecrets(),
                                               packet_buf_, sizeof(packet_buf_));
    
    if (packet_len > 0) {
        app_tracker_.OnPacketSent(pn, current_time_us_, packet_len, true);
        SendPacket(packet_buf_, packet_len);
    }
}

void QuicConnection::Impl::OnFramePathResponse(const uint8_t* data) {
    // Check if this matches our migration PATH_CHALLENGE
    if (migration_in_progress_ && memcmp(data, migration_challenge_data_, 8) == 0) {
        // Migration path validated successfully
        CompleteMigration(true);
        return;
    }
    
    // Check if this matches our regular PATH_CHALLENGE
    if (memcmp(data, path_challenge_data_, 8) == 0) {
        path_validated_ = true;
        
        if (path_challenge_sent_time_us_ > 0) {
            uint64_t rtt_us = current_time_us_ - path_challenge_sent_time_us_;
            path_validation_rtt_ms_ = static_cast<uint32_t>(rtt_us / 1000);
            
            if (config_.enable_debug) {
                ESP_LOGI(TAG, "Path validated! RTT: %lu ms", path_validation_rtt_ms_);
            }
        }
        
        path_challenge_sent_time_us_ = 0;
        memset(path_challenge_data_, 0, 8);
    }
}

void QuicConnection::Impl::OnFrameDatagram(const uint8_t* data, size_t len) {
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "DATAGRAM received: %zu bytes", len);
    }
    
    if (on_datagram_) {
        on_datagram_(data, len);
    }
}

//=============================================================================
// Key Update
//=============================================================================

bool QuicConnection::Impl::InitiateKeyUpdate() {
    if (!handshake_complete_) {
        if (config_.enable_debug) {
            ESP_LOGW(TAG, "Cannot initiate Key Update: handshake not complete");
        }
        return false;
    }
    
    return crypto_.InitiateKeyUpdate();
}

//=============================================================================
// Path Validation
//=============================================================================

bool QuicConnection::Impl::SendPathChallenge() {
    if (!crypto_.HasApplicationKeys()) {
        return false;
    }
    
    // Generate random challenge data
    GenerateRandom(path_challenge_data_, 8);
    path_challenge_sent_time_us_ = current_time_us_;
    path_validated_ = false;
    
    // Build PATH_CHALLENGE frame
    quic::BufferWriter writer(frame_buf_, sizeof(frame_buf_));
    if (!quic::BuildPathChallengeFrame(&writer, path_challenge_data_)) {
        return false;
    }
    
    // Build 1-RTT packet
    uint64_t pn = app_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::Build1RttPacket(dcid_, pn, false, crypto_.GetKeyPhase() != 0,
                                               frame_buf_, writer.Offset(),
                                               crypto_.GetClientAppSecrets(),
                                               packet_buf_, sizeof(packet_buf_));
    
    if (packet_len == 0) {
        return false;
    }
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "Sending PATH_CHALLENGE");
    }
    
    app_tracker_.OnPacketSent(pn, current_time_us_, packet_len, true);
    return SendPacket(packet_buf_, packet_len);
}

//=============================================================================
// Connection Migration
//=============================================================================

bool QuicConnection::Impl::MigrateConnection() {
    // Check preconditions
    if (state_ != ConnectionState::kConnected) {
        if (config_.enable_debug) {
            ESP_LOGW(TAG, "Migration failed: not connected");
        }
        return false;
    }
    
    if (!crypto_.HasApplicationKeys()) {
        if (config_.enable_debug) {
            ESP_LOGW(TAG, "Migration failed: no application keys");
        }
        return false;
    }
    
    // Check if server allows migration
    if (peer_params_.disable_active_migration) {
        if (config_.enable_debug) {
            ESP_LOGW(TAG, "Migration failed: server disabled active migration");
        }
        return false;
    }
    
    // Check if migration is already in progress
    if (migration_in_progress_) {
        if (config_.enable_debug) {
            ESP_LOGW(TAG, "Migration failed: migration already in progress");
        }
        return false;
    }
    
    // Select a new peer connection ID for the new path
    quic::ConnectionId* new_cid = SelectNewPeerConnectionId();
    if (!new_cid) {
        if (config_.enable_debug) {
            ESP_LOGW(TAG, "Migration failed: no available peer connection ID");
        }
        return false;
    }
    
    // Save current DCID for potential rollback
    pre_migration_dcid_ = dcid_;
    
    // Switch to the new connection ID
    dcid_ = *new_cid;
    
    // Start migration
    migration_in_progress_ = true;
    migration_retry_count_ = 0;
    path_validated_ = false;  // Need to validate new path
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "Starting connection migration to new CID: %02x%02x%02x%02x...",
                 dcid_.data[0], dcid_.data[1], dcid_.data[2], dcid_.data[3]);
    }
    
    // Send PATH_CHALLENGE on the new path
    SendMigrationPathChallenge();
    
    return true;
}

quic::ConnectionId* QuicConnection::Impl::SelectNewPeerConnectionId() {
    // Find the first non-retired, unused peer connection ID that's different from current dcid_
    for (auto& [seq, info] : peer_connection_ids_) {
        if (!info.retired) {
            // Skip if it's the same as current DCID
            if (info.cid == dcid_) {
                continue;
            }
            return &info.cid;
        }
    }
    
    // If no alternative CID available, return nullptr
    return nullptr;
}

size_t QuicConnection::Impl::GetAvailablePeerConnectionIdCount() const {
    size_t count = 0;
    for (const auto& [seq, info] : peer_connection_ids_) {
        if (!info.retired) {
            count++;
        }
    }
    return count;
}

void QuicConnection::Impl::SendMigrationPathChallenge() {
    // Generate random challenge data for migration
    GenerateRandom(migration_challenge_data_, 8);
    migration_challenge_sent_time_us_ = current_time_us_;
    
    // Build PATH_CHALLENGE frame
    quic::BufferWriter writer(frame_buf_, sizeof(frame_buf_));
    if (!quic::BuildPathChallengeFrame(&writer, migration_challenge_data_)) {
        CompleteMigration(false);
        return;
    }
    
    // Build 1-RTT packet with NEW destination CID
    uint64_t pn = app_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::Build1RttPacket(dcid_, pn, false, crypto_.GetKeyPhase() != 0,
                                               frame_buf_, writer.Offset(),
                                               crypto_.GetClientAppSecrets(),
                                               packet_buf_, sizeof(packet_buf_));
    
    if (packet_len == 0) {
        CompleteMigration(false);
        return;
    }
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "Sending migration PATH_CHALLENGE (attempt %lu/%lu)",
                 migration_retry_count_ + 1, kMaxMigrationRetries);
    }
    
    app_tracker_.OnPacketSent(pn, current_time_us_, packet_len, true);
    SendPacket(packet_buf_, packet_len);
}

void QuicConnection::Impl::CompleteMigration(bool success) {
    if (!migration_in_progress_) {
        return;
    }
    
    migration_in_progress_ = false;
    
    if (success) {
        // Migration successful
        path_validated_ = true;
        
        // Calculate path RTT
        if (migration_challenge_sent_time_us_ > 0) {
            uint64_t rtt_us = current_time_us_ - migration_challenge_sent_time_us_;
            path_validation_rtt_ms_ = static_cast<uint32_t>(rtt_us / 1000);
        }
        
        if (config_.enable_debug) {
            ESP_LOGI(TAG, "Connection migration completed successfully! New path RTT: %lu ms",
                     path_validation_rtt_ms_);
        }
        
        // Retire the old connection ID (optional, but good practice)
        // The old DCID should be retired to avoid using it again
        for (auto& [seq, info] : peer_connection_ids_) {
            if (info.cid == pre_migration_dcid_ && !info.retired) {
                info.retired = true;
                SendRetireConnectionId(seq);
                break;
            }
        }
    } else {
        // Migration failed, rollback to old DCID
        dcid_ = pre_migration_dcid_;
        path_validated_ = true;  // Old path is still valid
        
        if (config_.enable_debug) {
            ESP_LOGW(TAG, "Connection migration failed, rolled back to previous path");
        }
    }
    
    // Clear migration state
    migration_challenge_sent_time_us_ = 0;
    memset(migration_challenge_data_, 0, 8);
    migration_retry_count_ = 0;
    
    // Notify callback
    if (on_migration_complete_) {
        on_migration_complete_(success);
    }
}

//=============================================================================
// DATAGRAM (RFC 9221)
//=============================================================================

bool QuicConnection::Impl::CanSendDatagram(size_t size) const {
    if (!config_.enable_datagram) {
        return false;
    }
    if (peer_max_datagram_frame_size_ == 0) {
        return false;
    }
    if (size > 0 && size > peer_max_datagram_frame_size_) {
        return false;
    }
    return true;
}

bool QuicConnection::Impl::SendDatagram(const uint8_t* data, size_t len) {
    if (!crypto_.HasApplicationKeys()) {
        if (config_.enable_debug) {
            ESP_LOGW(TAG, "Cannot send DATAGRAM: handshake not complete");
        }
        return false;
    }
    
    if (!CanSendDatagram(len)) {
        if (config_.enable_debug) {
            if (!config_.enable_datagram) {
                ESP_LOGW(TAG, "DATAGRAM not enabled");
            } else if (peer_max_datagram_frame_size_ == 0) {
                ESP_LOGW(TAG, "Peer doesn't support DATAGRAM");
            } else {
                ESP_LOGW(TAG, "DATAGRAM data (%zu bytes) exceeds peer limit (%lu bytes)",
                         len, peer_max_datagram_frame_size_);
            }
        }
        return false;
    }
    
    // Build DATAGRAM frame
    quic::BufferWriter writer(frame_buf_, sizeof(frame_buf_));
    if (!quic::BuildDatagramFrame(&writer, data, len, true)) {
        return false;
    }
    
    // Build 1-RTT packet
    uint64_t pn = app_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::Build1RttPacket(dcid_, pn, false, crypto_.GetKeyPhase() != 0,
                                               frame_buf_, writer.Offset(),
                                               crypto_.GetClientAppSecrets(),
                                               packet_buf_, sizeof(packet_buf_));
    
    if (packet_len == 0) {
        return false;
    }
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "Sending DATAGRAM: %zu bytes", len);
    }
    
    // Track sent packet (but DATAGRAM is NOT retransmitted on loss)
    app_tracker_.OnPacketSent(pn, current_time_us_, packet_len, true);
    return SendPacket(packet_buf_, packet_len);
}

size_t QuicConnection::Impl::GetMaxDatagramSize() const {
    if (!IsDatagramAvailable()) {
        return 0;
    }
    return std::min(config_.max_datagram_frame_size, peer_max_datagram_frame_size_);
}

bool QuicConnection::Impl::IsDatagramAvailable() const {
    return config_.enable_datagram && peer_max_datagram_frame_size_ > 0;
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

uint32_t QuicConnection::OnTimerTick(uint32_t elapsed_ms) {
    return impl_->OnTimerTick(elapsed_ms);
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

ssize_t QuicConnection::WriteStream(int stream_id, const uint8_t* data, size_t len) {
    return impl_->WriteStream(stream_id, data, len);
}

bool QuicConnection::FinishStream(int stream_id) {
    return impl_->FinishStream(stream_id);
}

bool QuicConnection::ResetStream(int stream_id, uint64_t error_code) {
    return impl_->ResetStream(stream_id, error_code);
}

bool QuicConnection::CanSend(int stream_id, size_t len) const {
    return impl_->CanSend(stream_id, len);
}

size_t QuicConnection::GetSendableBytes(int stream_id) const {
    return impl_->GetSendableBytes(stream_id);
}

bool QuicConnection::IsConnectionBlocked() const {
    return impl_->IsConnectionBlocked();
}

bool QuicConnection::IsStreamBlocked(int stream_id) const {
    return impl_->IsStreamBlocked(stream_id);
}

bool QuicConnection::IsStreamReset(int stream_id) const {
    return impl_->IsStreamReset(stream_id);
}

void QuicConnection::AcknowledgeStreamData(int stream_id, size_t bytes) {
    impl_->AcknowledgeStreamData(stream_id, bytes);
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

void QuicConnection::SetOnStreamWritable(OnStreamWritableCallback cb) {
    impl_->SetOnStreamWritable(std::move(cb));
}

void QuicConnection::SetOnWritable(OnWritableCallback cb) {
    impl_->SetOnWritable(std::move(cb));
}

QuicConnection::Stats QuicConnection::GetStats() const {
    return impl_->GetStats();
}

//=============================================================================
// Key Update Public API
//=============================================================================

bool QuicConnection::InitiateKeyUpdate() {
    return impl_->InitiateKeyUpdate();
}

uint8_t QuicConnection::GetKeyPhase() const {
    return impl_->GetKeyPhase();
}

uint32_t QuicConnection::GetKeyUpdateGeneration() const {
    return impl_->GetKeyUpdateGeneration();
}

//=============================================================================
// Path Validation Public API
//=============================================================================

bool QuicConnection::SendPathChallenge() {
    return impl_->SendPathChallenge();
}

bool QuicConnection::IsPathValidated() const {
    return impl_->IsPathValidated();
}

uint32_t QuicConnection::GetPathValidationRtt() const {
    return impl_->GetPathValidationRtt();
}

//=============================================================================
// Connection Migration Public API
//=============================================================================

bool QuicConnection::MigrateConnection() {
    return impl_->MigrateConnection();
}

bool QuicConnection::IsMigrationAllowed() const {
    return impl_->IsMigrationAllowed();
}

bool QuicConnection::IsMigrationInProgress() const {
    return impl_->IsMigrationInProgress();
}

size_t QuicConnection::GetAvailablePeerConnectionIdCount() const {
    return impl_->GetAvailablePeerConnectionIdCount();
}

void QuicConnection::SetOnMigrationComplete(OnMigrationCompleteCallback cb) {
    impl_->SetOnMigrationComplete(std::move(cb));
}

//=============================================================================
// DATAGRAM Public API (RFC 9221)
//=============================================================================

bool QuicConnection::CanSendDatagram(size_t size) const {
    return impl_->CanSendDatagram(size);
}

bool QuicConnection::SendDatagram(const uint8_t* data, size_t len) {
    return impl_->SendDatagram(data, len);
}

void QuicConnection::SetOnDatagram(OnDatagramCallback cb) {
    impl_->SetOnDatagram(std::move(cb));
}

size_t QuicConnection::GetMaxDatagramSize() const {
    return impl_->GetMaxDatagramSize();
}

bool QuicConnection::IsDatagramAvailable() const {
    return impl_->IsDatagramAvailable();
}

} // namespace esp_http3

