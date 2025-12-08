/**
 * @file quic_connection.cc
 * @brief QUIC Connection Implementation
 * 
 * Refactored to use component-based architecture:
 * - CryptoManager: Handles all cryptographic operations
 * - FrameProcessor: Parses and dispatches incoming frames
 */

#include "client/quic_connection.h"
#include "client/ack_manager.h"
#include "client/flow_controller.h"
#include "client/loss_detector.h"
#include "client/crypto_manager.h"
#include "client/frame_processor.h"
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
    bool WriteStream(int stream_id, const uint8_t* data, size_t len);
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
    
    void SetOnConnected(OnConnectedCallback cb) { on_connected_ = std::move(cb); }
    void SetOnDisconnected(OnDisconnectedCallback cb) { on_disconnected_ = std::move(cb); }
    void SetOnResponse(OnResponseCallback cb) { on_response_ = std::move(cb); }
    void SetOnStreamData(OnStreamDataCallback cb) { on_stream_data_ = std::move(cb); }
    void SetOnWriteComplete(OnWriteCompleteCallback cb) { on_write_complete_ = std::move(cb); }
    void SetOnWriteError(OnWriteErrorCallback cb) { on_write_error_ = std::move(cb); }
    
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
    
    // DATAGRAM
    bool CanSendDatagram(size_t size) const;
    bool SendDatagram(const uint8_t* data, size_t len);
    size_t GetMaxDatagramSize() const;
    bool IsDatagramAvailable() const;
    
    // Queued write API
    // Queue data for sending (supports PSRAM and read-only data)
    // @param data Pointer to data (can be read-only)
    // @param size Size of data in bytes
    // @param deleter Optional deleter function to free memory (nullptr for read-only data)
    bool QueueWrite(int stream_id, const uint8_t* data, size_t size, std::function<void()> deleter = nullptr);
    bool QueueFinish(int stream_id);
    size_t GetQueuedBytes(int stream_id) const;
    bool IsQueueEmpty(int stream_id) const;
    
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
    
    // Write queue processing
    void ProcessWriteQueue();
    
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

private:
    // Write queue item
    struct WriteQueueItem {
        const uint8_t* data = nullptr;  // Pointer to data (can be read-only)
        size_t size = 0;                 // Total size of data
        size_t offset = 0;               // Current send offset within data
        bool finish = false;             // If true, this is a FIN marker (data is nullptr)
        std::function<void()> deleter;    // Optional deleter for freeing memory (null for read-only data)
        
        // Default constructor (required for std::vector)
        WriteQueueItem() = default;
        
        // Constructor for data items
        WriteQueueItem(const uint8_t* d, size_t s, std::function<void()> del = nullptr)
            : data(d), size(s), offset(0), finish(false), deleter(std::move(del)) {}
        
        // Constructor for FIN marker
        WriteQueueItem(bool fin) : data(nullptr), size(0), offset(0), finish(fin), deleter(nullptr) {}
        
        ~WriteQueueItem() {
            if (deleter) {
                deleter();
            }
        }
        
        // Move constructor
        WriteQueueItem(WriteQueueItem&& other) noexcept
            : data(other.data), size(other.size), offset(other.offset), 
              finish(other.finish), deleter(std::move(other.deleter)) {
            other.data = nullptr;
            other.size = 0;
            other.deleter = nullptr;
        }
        
        // Move assignment
        WriteQueueItem& operator=(WriteQueueItem&& other) noexcept {
            if (this != &other) {
                if (deleter) deleter();
                data = other.data;
                size = other.size;
                offset = other.offset;
                finish = other.finish;
                deleter = std::move(other.deleter);
                other.data = nullptr;
                other.size = 0;
                other.deleter = nullptr;
            }
            return *this;
        }
        
        // Disable copy
        WriteQueueItem(const WriteQueueItem&) = delete;
        WriteQueueItem& operator=(const WriteQueueItem&) = delete;
    };
    
    // Per-stream write queue
    struct StreamWriteQueue {
        std::vector<WriteQueueItem> items;
        size_t total_bytes = 0;     // Total bytes queued
        size_t sent_bytes = 0;      // Total bytes sent
        bool finish_queued = false; // FIN is queued
        bool finish_sent = false;   // FIN has been sent
    };
    SendCallback send_cb_;
    QuicConfig config_;
    ConnectionState state_ = ConnectionState::kIdle;
    
    // Callbacks
    OnConnectedCallback on_connected_;
    OnDisconnectedCallback on_disconnected_;
    OnResponseCallback on_response_;
    OnStreamDataCallback on_stream_data_;
    OnWriteCompleteCallback on_write_complete_;
    OnWriteErrorCallback on_write_error_;
    
    // Write queues (stream_id -> queue)
    std::map<int, StreamWriteQueue> write_queues_;
    
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
    
    // DATAGRAM state (RFC 9221)
    uint32_t peer_max_datagram_frame_size_ = 0;
    OnDatagramCallback on_datagram_;
    
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
        ESP_LOGW(TAG, "Decrypted Initial packet, PN=%llu, payload=%zu bytes, packet_size=%zu",
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
        } else if (frame_type == 0x04) {
            // RESET_STREAM - server is resetting the stream
            uint64_t stream_id, error_code, final_size;
            if (reader.ReadVarint(&stream_id) && 
                reader.ReadVarint(&error_code) && 
                reader.ReadVarint(&final_size)) {
                if (config_.enable_debug) {
                    ESP_LOGI(TAG, "[%s] Frame: RESET_STREAM stream=%llu, error=%llu, final_size=%llu", 
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
                    ESP_LOGI(TAG, "[%s] Frame: STOP_SENDING stream=%llu, error=%llu", 
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
    // Note: Decode peer's ACK delay using peer's ack_delay_exponent (from transport params)
    if (tracker->GetLatestRttUs() > 0) {
        loss_detector_.GetRttEstimator().OnRttSample(
            tracker->GetLatestRttUs(),
            ack_data.ack_delay << peer_params_.ack_delay_exponent);
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
    
    // Build CRYPTO frame
    uint8_t frames[64];
    quic::BufferWriter writer(frames, sizeof(frames));
    if (!quic::BuildCryptoFrame(&writer, 0, finished_msg, finished_len)) {
        ESP_LOGW(TAG, "BuildCryptoFrame failed");
        return false;
    }
    
    // Build Handshake packet
    std::vector<uint8_t> packet(512);
    uint64_t pn = handshake_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::BuildHandshakePacket(dcid_, scid_,
                                                    pn,
                                                    frames, writer.Offset(),
                                                    crypto_.GetClientHandshakeSecrets(),
                                                    packet.data(), packet.size());
    
    if (packet_len == 0) {
        ESP_LOGW(TAG, "BuildHandshakePacket failed");
        return false;
    }
    
    ESP_LOGD(TAG, "Sending Client Finished in Handshake packet, PN=%llu, len=%zu",
             (unsigned long long)pn, packet_len);
    
    handshake_tracker_.OnPacketSent(pn, current_time_us_, packet_len, true);
    loss_detector_.OnPacketSent(pn, current_time_us_, packet_len, true);
    
    bool ok = SendPacket(packet.data(), packet_len);
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
        
        // Send SETTINGS
        h3_handler_->SendSettings();
        h3_initialized_ = true;
        
        // Send our first alternative connection ID (like Python version)
        SendNewConnectionId();
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
    flow_controller_.OnStreamBytesReceived(stream_data.stream_id, 
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
    if (!crypto_.HasApplicationKeys()) {
        return false;
    }
    
    // Build MAX_DATA frame
    uint8_t frames[32];
    quic::BufferWriter writer(frames, sizeof(frames));
    
    if (!flow_controller_.BuildMaxDataFrame(&writer)) {
        return false;
    }
    
    // Build 1-RTT packet
    std::vector<uint8_t> packet(256);
    uint64_t pn = app_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::Build1RttPacket(dcid_, pn, false, crypto_.GetKeyPhase() != 0,
                                               frames, writer.Offset(),
                                               crypto_.GetClientAppSecrets(),
                                               packet.data(), packet.size());
    
    if (packet_len == 0) {
        return false;
    }
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "Sending MAX_DATA frame to increase flow control window");
    }
    
    app_tracker_.OnPacketSent(pn, current_time_us_, packet_len, false);
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
    
    // Build 1-RTT packet
    std::vector<uint8_t> packet(256);
    uint64_t pn = app_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::Build1RttPacket(dcid_, pn, false, crypto_.GetKeyPhase() != 0,
                                               frames, writer.Offset(),
                                               crypto_.GetClientAppSecrets(),
                                               packet.data(), packet.size());
    
    if (packet_len == 0) {
        return false;
    }
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "Sending MAX_STREAM_DATA for stream %llu", 
                 (unsigned long long)stream_id);
    }
    
    app_tracker_.OnPacketSent(pn, current_time_us_, packet_len, false);
    return SendPacket(packet.data(), packet_len);
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
    
    // Use time-based check for proper max_ack_delay handling (RFC 9002)
    if (!ack_mgr->ShouldSendAck(current_time_us_)) {
        return true;
    }
    
    // Build ACK frame
    uint8_t frames[64];
    quic::BufferWriter writer(frames, sizeof(frames));
    if (!ack_mgr->BuildAckFrame(&writer, current_time_us_)) {
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
                                                   frames, writer.Offset(),
                                                   crypto_.GetClientInitialSecrets(),
                                                   packet.data(), packet.size(),
                                                   0);  // No padding for ACK-only
            break;
        case quic::PacketType::kHandshake:
            packet_len = quic::BuildHandshakePacket(dcid_, scid_, pn,
                                                     frames, writer.Offset(),
                                                     crypto_.GetClientHandshakeSecrets(),
                                                     packet.data(), packet.size());
            break;
        default:
            packet_len = quic::Build1RttPacket(dcid_, pn, false, crypto_.GetKeyPhase() != 0,
                                                frames, writer.Offset(),
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
        ESP_LOGI(TAG, "Sending ACK packet, PN=%llu, len=%zu", 
                 (unsigned long long)pn, packet_len);
    }
    
    return SendPacket(packet.data(), packet_len);
}

bool QuicConnection::Impl::SendStreamData(uint64_t stream_id,
                                           const uint8_t* data,
                                           size_t len, bool fin) {
    if (!crypto_.HasApplicationKeys()) {
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
    
    // Save frame data for potential retransmission
    std::vector<uint8_t> frame_copy(frame_buf_, frame_buf_ + writer.Offset());
    
    // Build 1-RTT packet
    uint64_t pn = app_tracker_.AllocatePacketNumber();
    size_t packet_len = quic::Build1RttPacket(dcid_, pn, false, crypto_.GetKeyPhase() != 0,
                                               frame_buf_, writer.Offset(),
                                               crypto_.GetClientAppSecrets(),
                                               packet_buf_, sizeof(packet_buf_));
    
    if (packet_len == 0) {
        return false;
    }
    
    // Track sent packet with frame data for retransmission
    app_tracker_.OnPacketSent(pn, current_time_us_, packet_len, true, std::move(frame_copy));
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
    
    // Check if delayed ACKs need to be sent (RFC 9002 max_ack_delay timer)
    if (handshake_complete_) {
        if (app_ack_mgr_.ShouldSendAck(current_time_us_)) {
            SendAckIfNeeded(quic::PacketType::k1Rtt);
        }
    } else {
        // During handshake, check Initial and Handshake ACKs
        if (initial_ack_mgr_.ShouldSendAck(current_time_us_)) {
            SendAckIfNeeded(quic::PacketType::kInitial);
        }
        if (handshake_ack_mgr_.ShouldSendAck(current_time_us_)) {
            SendAckIfNeeded(quic::PacketType::kHandshake);
        }
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
    
    // Process write queues (send queued data respecting flow control)
    // Note: ProcessWriteQueue is also called immediately when MAX_DATA/MAX_STREAM_DATA
    // frames are received, so no polling needed here - just process any remaining data
    if (IsConnected()) {
        ProcessWriteQueue();
    }
    
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

bool QuicConnection::Impl::WriteStream(int stream_id, 
                                        const uint8_t* data, size_t len) {
    if (!IsConnected()) {
        ESP_LOGE(TAG, "WriteStream failed: not connected");
        return false;
    }
    
    // Check flow control before building frame
    size_t sendable = GetSendableBytes(stream_id);
    if (sendable < len) {
        ESP_LOGW(TAG, "WriteStream: flow control limit: sendable=%zu, requested=%zu", sendable, len);
        // Still try to send what we can
        len = sendable;
        if (len == 0) {
            ESP_LOGW(TAG, "WriteStream: flow control blocked");
            return false;
        }
    }
    
    // Build DATA frame (use payload_buf_ as temp buffer, SendStreamData uses frame_buf_)
    size_t frame_len = h3::BuildDataFrame(data, len, payload_buf_, sizeof(payload_buf_));
    if (frame_len == 0) {
        ESP_LOGE(TAG, "WriteStream failed: BuildDataFrame returned 0 (len=%zu, buf_size=%zu)", 
                 len, sizeof(payload_buf_));
        return false;
    }
    
    bool result = SendStreamData(static_cast<uint64_t>(stream_id), payload_buf_, frame_len, false);
    if (!result) {
        ESP_LOGE(TAG, "WriteStream failed: SendStreamData returned false (stream_id=%d, frame_len=%zu)", 
                 stream_id, frame_len);
    }
    return result;
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
    
    // Clean up write queue for this stream
    auto it = write_queues_.find(stream_id);
    if (it != write_queues_.end()) {
        auto& queue = it->second;
        // Call deleters for queued items
        for (auto& item : queue.items) {
            if (item.deleter) {
                item.deleter();
            }
        }
        write_queues_.erase(it);
        
        if (config_.enable_debug) {
            ESP_LOGI(TAG, "ResetStream: cleaned up write queue for stream %d", stream_id);
        }
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
// Queued Write API
//=============================================================================

bool QuicConnection::Impl::QueueWrite(int stream_id, 
                                       const uint8_t* data, 
                                       size_t size,
                                       std::function<void()> deleter) {
    if (!data || size == 0) {
        return false;
    }
    
    auto& queue = write_queues_[stream_id];
    if (queue.finish_queued) {
        ESP_LOGE(TAG, "QueueWrite: stream %d already has FIN queued", stream_id);
        return false;
    }
    
    queue.items.emplace_back(data, size, std::move(deleter));
    queue.total_bytes += size;
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "QueueWrite: stream %d, queued %zu bytes, total pending: %zu",
                 stream_id, size, queue.total_bytes - queue.sent_bytes);
    }
    
    return true;
}

bool QuicConnection::Impl::QueueFinish(int stream_id) {
    auto& queue = write_queues_[stream_id];
    
    if (queue.finish_queued) {
        ESP_LOGW(TAG, "QueueFinish: stream %d already has FIN queued", stream_id);
        return false;
    }
    
    queue.items.emplace_back(true);  // FIN marker
    queue.finish_queued = true;
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "QueueFinish: stream %d, FIN queued", stream_id);
    }
    
    return true;
}

size_t QuicConnection::Impl::GetQueuedBytes(int stream_id) const {
    auto it = write_queues_.find(stream_id);
    if (it == write_queues_.end()) {
        return 0;
    }
    return it->second.total_bytes - it->second.sent_bytes;
}

bool QuicConnection::Impl::IsQueueEmpty(int stream_id) const {
    auto it = write_queues_.find(stream_id);
    if (it == write_queues_.end()) {
        return true;
    }
    const auto& queue = it->second;
    return queue.items.empty() && (!queue.finish_queued || queue.finish_sent);
}

void QuicConnection::Impl::ProcessWriteQueue() {
    // Process each stream's write queue
    for (auto it = write_queues_.begin(); it != write_queues_.end(); ) {
        int stream_id = it->first;
        auto& queue = it->second;
        
        // Check if stream was reset
        if (IsStreamReset(stream_id)) {
            // Notify error and remove queue
            if (on_write_error_) {
                on_write_error_(stream_id, 1, "stream reset by peer");
            }
            it = write_queues_.erase(it);
            
            // Clean up stream resources
            CleanupStream(static_cast<uint64_t>(stream_id));
            continue;
        }
        
        // Process items in this stream's queue
        while (!queue.items.empty()) {
            auto& item = queue.items.front();
            
            // Handle FIN marker
            if (item.finish) {
                if (FinishStream(stream_id)) {
                    queue.finish_sent = true;
                    queue.items.erase(queue.items.begin());
                    
                    // Notify completion
                    if (on_write_complete_) {
                        on_write_complete_(stream_id, queue.sent_bytes);
                    }
                    
                    if (config_.enable_debug) {
                        ESP_LOGI(TAG, "ProcessWriteQueue: stream %d finished, total %zu bytes",
                                 stream_id, queue.sent_bytes);
                    }
                    
                    // Remove completed queue from write_queues_
                    it = write_queues_.erase(it);
                    goto next_stream;
                } else {
                    // FinishStream failed, try again later
                    break;
                }
            }
            
            // Get available flow control window
            size_t sendable = GetSendableBytes(stream_id);
            if (sendable == 0) {
                // Flow control blocked, try next stream
                break;
            }
            
            // Calculate how much to send
            size_t remaining = item.size - item.offset;
            
            // Use a reasonable chunk size (similar to WriteStream's payload_buf_ limit)
            const size_t MAX_CHUNK = 1200;
            size_t chunk_size = std::min({MAX_CHUNK, sendable, remaining});
            
            // Send the chunk
            if (!WriteStream(stream_id, item.data + item.offset, chunk_size)) {
                // Write failed, notify error
                if (on_write_error_) {
                    on_write_error_(stream_id, 2, "WriteStream failed");
                }
                // Remove this stream's queue
                it = write_queues_.erase(it);
                
                // Clean up stream resources
                CleanupStream(static_cast<uint64_t>(stream_id));
                
                goto next_stream;  // Use goto to break out of inner loop and skip ++it
            }
            
            item.offset += chunk_size;
            queue.sent_bytes += chunk_size;
            
            // Check if this item is complete
            if (item.offset >= item.size) {
                queue.items.erase(queue.items.begin());
            }
            
            // Only send one chunk per tick to allow other streams and avoid blocking
            // (Remove this break if you want to send more aggressively)
            break;
        }
        
        ++it;
        next_stream:;
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
            // No frame data saved, skip (e.g., ACK-only packets)
            continue;
        }
        
        if (config_.enable_debug) {
            ESP_LOGI(TAG, "Retransmitting lost packet PN=%llu (%zu bytes of frames)",
                     (unsigned long long)pkt->packet_number, pkt->frames.size());
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
        
        // Track the new packet
        app_tracker_.OnPacketSent(new_pn, current_time_us_, packet_len, true, std::move(frame_copy));
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
            ESP_LOGI(TAG, "PTO probe: retransmitting PN=%llu",
                     (unsigned long long)oldest_with_data->packet_number);
        }
        
        uint64_t new_pn = app_tracker_.AllocatePacketNumber();
        size_t packet_len = quic::Build1RttPacket(dcid_, new_pn, false, crypto_.GetKeyPhase() != 0,
                                                   oldest_with_data->frames.data(),
                                                   oldest_with_data->frames.size(),
                                                   crypto_.GetClientAppSecrets(),
                                                   packet_buf_, sizeof(packet_buf_));
        
        if (packet_len > 0) {
            std::vector<uint8_t> frame_copy = oldest_with_data->frames;
            app_tracker_.OnPacketSent(new_pn, current_time_us_, packet_len, true, std::move(frame_copy));
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
    
    // ACK frees up congestion window (bytes_in_flight decreases, cwnd may increase
    // during slow start), try to send blocked data immediately
    if (newly_acked > 0) {
        ProcessWriteQueue();
    }
}

void QuicConnection::Impl::OnFrameStream(uint64_t stream_id, uint64_t offset,
                                          const uint8_t* data, size_t len, bool fin) {
    // Update flow control
    flow_controller_.OnStreamBytesReceived(stream_id, len);
    
    // Pass to H3 handler
    if (h3_handler_) {
        h3_handler_->OnStreamData(stream_id, offset, data, len, fin);
    }
    
    // Check if we should send flow control updates
    if (flow_controller_.ShouldSendMaxData()) {
        SendMaxDataFrame();
    }
    if (flow_controller_.ShouldSendMaxStreamData(stream_id)) {
        SendMaxStreamDataFrame(stream_id);
    }
}

void QuicConnection::Impl::OnFrameMaxData(uint64_t max_data) {
    flow_controller_.OnMaxDataReceived(max_data);
    // Flow control window updated, immediately try to send blocked data
    ProcessWriteQueue();
}

void QuicConnection::Impl::OnFrameMaxStreamData(uint64_t stream_id, uint64_t max_data) {
    flow_controller_.OnMaxStreamDataReceived(stream_id, max_data);
    // Flow control window updated, immediately try to send blocked data
    ProcessWriteQueue();
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
    
    // Build NEW_CONNECTION_ID frame
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
    
    if (config_.enable_debug) {
        ESP_LOGI(TAG, "Sending NEW_CONNECTION_ID seq=%llu, cid=%02x%02x%02x%02x...",
                 (unsigned long long)seq,
                 info.cid.data[0], info.cid.data[1], info.cid.data[2], info.cid.data[3]);
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
    // Check if this matches our pending PATH_CHALLENGE
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

bool QuicConnection::WriteStream(int stream_id, const uint8_t* data, size_t len) {
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

void QuicConnection::SetOnWriteComplete(OnWriteCompleteCallback cb) {
    impl_->SetOnWriteComplete(std::move(cb));
}

void QuicConnection::SetOnWriteError(OnWriteErrorCallback cb) {
    impl_->SetOnWriteError(std::move(cb));
}

bool QuicConnection::QueueWrite(int stream_id, const uint8_t* data, size_t size, std::function<void()> deleter) {
    return impl_->QueueWrite(stream_id, data, size, std::move(deleter));
}

bool QuicConnection::QueueFinish(int stream_id) {
    return impl_->QueueFinish(stream_id);
}

size_t QuicConnection::GetQueuedBytes(int stream_id) const {
    return impl_->GetQueuedBytes(stream_id);
}

bool QuicConnection::IsQueueEmpty(int stream_id) const {
    return impl_->IsQueueEmpty(stream_id);
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

