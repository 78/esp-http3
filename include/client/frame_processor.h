/**
 * @file frame_processor.h
 * @brief QUIC Frame Processor - Parse and dispatch incoming frames
 * 
 * Handles parsing of all QUIC frame types from decrypted packet payloads
 * and dispatches to appropriate handlers via callbacks.
 * 
 * This separates low-level parsing from business logic, making the code
 * more modular and testable.
 */

#pragma once

#include "quic/quic_types.h"
#include "quic/quic_constants.h"
#include <cstdint>
#include <cstddef>
#include <functional>
#include <string>
#include <vector>

namespace esp_http3 {

//=============================================================================
// Frame Data Structures
//=============================================================================

/**
 * @brief Parsed ACK frame data
 */
struct AckFrameData {
    uint64_t largest_ack = 0;
    uint64_t ack_delay = 0;
    uint64_t first_ack_range = 0;
    std::vector<std::pair<uint64_t, uint64_t>> ack_ranges;  // (gap, ack_range) pairs
    // ECN counts (for ACK_ECN frame)
    uint64_t ect0_count = 0;
    uint64_t ect1_count = 0;
    uint64_t ecn_ce_count = 0;
};

/**
 * @brief Parsed STREAM frame data
 */
struct StreamFrameData {
    uint64_t stream_id = 0;
    uint64_t offset = 0;
    const uint8_t* data = nullptr;
    size_t length = 0;
    bool fin = false;
};

/**
 * @brief Parsed CRYPTO frame data
 */
struct CryptoFrameData {
    uint64_t offset = 0;
    const uint8_t* data = nullptr;
    size_t length = 0;
};

/**
 * @brief Parsed CONNECTION_CLOSE frame data
 */
struct ConnectionCloseData {
    uint64_t error_code = 0;
    uint64_t frame_type = 0;  // Only for QUIC-level close
    std::string reason;
    bool is_application = false;
};

/**
 * @brief Parsed NEW_CONNECTION_ID frame data
 */
struct NewConnectionIdData {
    uint64_t sequence_number = 0;
    uint64_t retire_prior_to = 0;
    quic::ConnectionId connection_id;
    uint8_t stateless_reset_token[16];
};

/**
 * @brief Parsed RESET_STREAM frame data
 */
struct ResetStreamData {
    uint64_t stream_id = 0;
    uint64_t error_code = 0;
    uint64_t final_size = 0;
};

/**
 * @brief Parsed STOP_SENDING frame data
 */
struct StopSendingData {
    uint64_t stream_id = 0;
    uint64_t error_code = 0;
};

//=============================================================================
// Callback Types
//=============================================================================

/// ACK frame callback: (ack_data)
using OnAckCallback = std::function<void(const AckFrameData& ack_data)>;

/// CRYPTO frame callback: (offset, data, len)
using OnCryptoCallback = std::function<void(uint64_t offset, 
                                             const uint8_t* data, size_t len)>;

/// STREAM frame callback: (stream_id, offset, data, len, fin)
using OnStreamCallback = std::function<void(uint64_t stream_id, uint64_t offset,
                                             const uint8_t* data, size_t len, bool fin)>;

/// MAX_DATA frame callback: (max_data)
using OnMaxDataCallback = std::function<void(uint64_t max_data)>;

/// MAX_STREAM_DATA frame callback: (stream_id, max_data)
using OnMaxStreamDataCallback = std::function<void(uint64_t stream_id, 
                                                    uint64_t max_data)>;

/// MAX_STREAMS frame callback: (max_streams, is_bidi)
using OnMaxStreamsCallback = std::function<void(uint64_t max_streams, bool is_bidi)>;

/// DATA_BLOCKED frame callback: (blocked_at)
using OnDataBlockedCallback = std::function<void(uint64_t blocked_at)>;

/// STREAM_DATA_BLOCKED frame callback: (stream_id, blocked_at)
using OnStreamDataBlockedCallback = std::function<void(uint64_t stream_id, 
                                                        uint64_t blocked_at)>;

/// STREAMS_BLOCKED frame callback: (blocked_at, is_bidi)
using OnStreamsBlockedCallback = std::function<void(uint64_t blocked_at, bool is_bidi)>;

/// NEW_CONNECTION_ID frame callback: (data)
using OnNewConnectionIdCallback = std::function<void(const NewConnectionIdData& data)>;

/// RETIRE_CONNECTION_ID frame callback: (sequence_number)
using OnRetireConnectionIdCallback = std::function<void(uint64_t sequence_number)>;

/// CONNECTION_CLOSE frame callback: (data)
using OnConnectionCloseCallback = std::function<void(const ConnectionCloseData& data)>;

/// HANDSHAKE_DONE frame callback: ()
using OnHandshakeDoneCallback = std::function<void()>;

/// PING frame callback: ()
using OnPingCallback = std::function<void()>;

/// PATH_CHALLENGE frame callback: (8-byte data)
using OnPathChallengeCallback = std::function<void(const uint8_t* data)>;

/// PATH_RESPONSE frame callback: (8-byte data)
using OnPathResponseCallback = std::function<void(const uint8_t* data)>;

/// RESET_STREAM frame callback: (data)
using OnResetStreamCallback = std::function<void(const ResetStreamData& data)>;

/// STOP_SENDING frame callback: (data)
using OnStopSendingCallback = std::function<void(const StopSendingData& data)>;

/// NEW_TOKEN frame callback: (token, len)
using OnNewTokenCallback = std::function<void(const uint8_t* token, size_t len)>;

/// DATAGRAM frame callback: (data, len)
using OnDatagramCallback = std::function<void(const uint8_t* data, size_t len)>;

//=============================================================================
// FrameProcessor Class
//=============================================================================

/**
 * @brief Parses QUIC frames from decrypted payloads
 * 
 * Dispatches parsed frames to registered callbacks for handling.
 * This separates low-level parsing from business logic.
 * 
 * Usage:
 * @code
 * FrameProcessor processor;
 * processor.SetOnStream([](uint64_t id, uint64_t off, const uint8_t* d, size_t l, bool f) {
 *     // Handle STREAM frame
 * });
 * processor.ProcessPayload(data, len, PacketType::k1Rtt);
 * @endcode
 */
class FrameProcessor {
public:
    FrameProcessor();
    ~FrameProcessor() = default;
    
    /**
     * @brief Enable/disable debug logging
     */
    void SetDebug(bool enable) { debug_ = enable; }
    
    //=========================================================================
    // Callback Registration
    //=========================================================================
    
    void SetOnAck(OnAckCallback cb) { on_ack_ = std::move(cb); }
    void SetOnCrypto(OnCryptoCallback cb) { on_crypto_ = std::move(cb); }
    void SetOnStream(OnStreamCallback cb) { on_stream_ = std::move(cb); }
    void SetOnMaxData(OnMaxDataCallback cb) { on_max_data_ = std::move(cb); }
    void SetOnMaxStreamData(OnMaxStreamDataCallback cb) { on_max_stream_data_ = std::move(cb); }
    void SetOnMaxStreams(OnMaxStreamsCallback cb) { on_max_streams_ = std::move(cb); }
    void SetOnDataBlocked(OnDataBlockedCallback cb) { on_data_blocked_ = std::move(cb); }
    void SetOnStreamDataBlocked(OnStreamDataBlockedCallback cb) { on_stream_data_blocked_ = std::move(cb); }
    void SetOnStreamsBlocked(OnStreamsBlockedCallback cb) { on_streams_blocked_ = std::move(cb); }
    void SetOnNewConnectionId(OnNewConnectionIdCallback cb) { on_new_connection_id_ = std::move(cb); }
    void SetOnRetireConnectionId(OnRetireConnectionIdCallback cb) { on_retire_connection_id_ = std::move(cb); }
    void SetOnConnectionClose(OnConnectionCloseCallback cb) { on_connection_close_ = std::move(cb); }
    void SetOnHandshakeDone(OnHandshakeDoneCallback cb) { on_handshake_done_ = std::move(cb); }
    void SetOnPing(OnPingCallback cb) { on_ping_ = std::move(cb); }
    void SetOnPathChallenge(OnPathChallengeCallback cb) { on_path_challenge_ = std::move(cb); }
    void SetOnPathResponse(OnPathResponseCallback cb) { on_path_response_ = std::move(cb); }
    void SetOnResetStream(OnResetStreamCallback cb) { on_reset_stream_ = std::move(cb); }
    void SetOnStopSending(OnStopSendingCallback cb) { on_stop_sending_ = std::move(cb); }
    void SetOnNewToken(OnNewTokenCallback cb) { on_new_token_ = std::move(cb); }
    void SetOnDatagram(OnDatagramCallback cb) { on_datagram_ = std::move(cb); }
    
    //=========================================================================
    // Processing
    //=========================================================================
    
    /**
     * @brief Parse all frames from a decrypted packet payload
     * 
     * Parses frames sequentially and dispatches to registered callbacks.
     * 
     * @param data Decrypted packet payload
     * @param len Payload length
     * @param pkt_type Packet type (for logging context)
     * @return true if any ack-eliciting frames were found
     */
    bool ProcessPayload(const uint8_t* data, size_t len, quic::PacketType pkt_type);
    
    /**
     * @brief Get the number of ack-eliciting frames in last ProcessPayload call
     */
    uint32_t GetAckElicitingCount() const { return ack_eliciting_count_; }

private:
    // Individual frame parsers (return new offset, or 0 on error)
    size_t ParseAckFrame(quic::BufferReader* reader, bool has_ecn);
    size_t ParseCryptoFrame(quic::BufferReader* reader);
    size_t ParseStreamFrame(quic::BufferReader* reader, uint8_t frame_type);
    size_t ParseResetStreamFrame(quic::BufferReader* reader);
    size_t ParseStopSendingFrame(quic::BufferReader* reader);
    size_t ParseNewConnectionIdFrame(quic::BufferReader* reader);
    size_t ParseRetireConnectionIdFrame(quic::BufferReader* reader);
    size_t ParseConnectionCloseFrame(quic::BufferReader* reader, bool is_app);
    size_t ParseNewTokenFrame(quic::BufferReader* reader);
    size_t ParseDatagramFrame(quic::BufferReader* reader, bool has_length);
    
    // Callbacks
    OnAckCallback on_ack_;
    OnCryptoCallback on_crypto_;
    OnStreamCallback on_stream_;
    OnMaxDataCallback on_max_data_;
    OnMaxStreamDataCallback on_max_stream_data_;
    OnMaxStreamsCallback on_max_streams_;
    OnDataBlockedCallback on_data_blocked_;
    OnStreamDataBlockedCallback on_stream_data_blocked_;
    OnStreamsBlockedCallback on_streams_blocked_;
    OnNewConnectionIdCallback on_new_connection_id_;
    OnRetireConnectionIdCallback on_retire_connection_id_;
    OnConnectionCloseCallback on_connection_close_;
    OnHandshakeDoneCallback on_handshake_done_;
    OnPingCallback on_ping_;
    OnPathChallengeCallback on_path_challenge_;
    OnPathResponseCallback on_path_response_;
    OnResetStreamCallback on_reset_stream_;
    OnStopSendingCallback on_stop_sending_;
    OnNewTokenCallback on_new_token_;
    OnDatagramCallback on_datagram_;
    
    // State
    bool debug_ = false;
    uint32_t ack_eliciting_count_ = 0;
};

} // namespace esp_http3

