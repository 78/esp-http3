/**
 * @file h3_handler.h
 * @brief HTTP/3 Request/Response Handler
 */

#pragma once

#include "h3/h3_frame.h"
#include "quic/quic_types.h"
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

namespace esp_http3 {
namespace h3 {

/**
 * @brief HTTP/3 response data
 */
struct H3Response {
    int status = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<uint8_t> body;
    bool complete = false;
    std::string error;
};

/**
 * @brief Stream state
 */
enum class StreamState {
    kIdle,
    kOpen,
    kHalfClosedLocal,
    kHalfClosedRemote,
    kClosed,
};

/**
 * @brief Pending chunk for out-of-order stream reassembly
 */
struct PendingChunk {
    uint64_t offset;
    std::vector<uint8_t> data;
};

/**
 * @brief HTTP/3 stream info
 */
struct H3Stream {
    uint64_t stream_id = 0;
    StreamState state = StreamState::kIdle;
    bool is_control = false;
    bool is_qpack_encoder = false;
    bool is_qpack_decoder = false;
    
    // For request streams
    std::string method;
    std::string path;
    
    // Response data
    H3Response response;
    
    // Stream reassembly (like Python's H3StreamManager)
    std::vector<uint8_t> recv_buffer;      // Contiguous data buffer
    uint64_t contiguous_end = 0;           // End of contiguous data
    std::vector<PendingChunk> pending_chunks;  // Out-of-order data chunks
    uint64_t fin_offset = UINT64_MAX;      // Final offset if FIN received
    size_t parsed_offset = 0;              // Offset of parsed H3 frames
    
    // Send data
    std::vector<uint8_t> send_buffer;
    size_t send_offset = 0;
};

/**
 * @brief Callback for sending QUIC stream data
 */
using SendStreamCallback = std::function<bool(uint64_t stream_id, 
                                               const uint8_t* data, 
                                               size_t len, 
                                               bool fin)>;

/**
 * @brief Callback when response is complete
 */
using OnResponseCallback = std::function<void(uint64_t stream_id, 
                                               const H3Response& response)>;

/**
 * @brief Callback for streaming data
 */
using OnStreamDataCallback = std::function<void(uint64_t stream_id,
                                                 const uint8_t* data,
                                                 size_t len,
                                                 bool fin)>;

/**
 * @brief HTTP/3 handler
 * 
 * Manages HTTP/3 streams and request/response processing.
 */
class H3Handler {
public:
    H3Handler();
    ~H3Handler() = default;
    
    /**
     * @brief Set callbacks
     */
    void SetSendStream(SendStreamCallback cb) { send_stream_ = std::move(cb); }
    void SetOnResponse(OnResponseCallback cb) { on_response_ = std::move(cb); }
    void SetOnStreamData(OnStreamDataCallback cb) { on_stream_data_ = std::move(cb); }
    
    /**
     * @brief Initialize control streams
     * 
     * Call this when QUIC connection is established.
     * Creates control stream and QPACK streams.
     * 
     * @param next_bidi_stream_id Starting bidirectional stream ID (client: 0)
     * @param next_uni_stream_id Starting unidirectional stream ID (client: 2)
     */
    void Initialize(uint64_t next_bidi_stream_id, uint64_t next_uni_stream_id);
    
    /**
     * @brief Send SETTINGS on control stream
     */
    bool SendSettings();
    
    /**
     * @brief Create new request stream
     * 
     * @return Stream ID, or -1 on failure
     */
    int64_t CreateRequestStream();
    
    /**
     * @brief Send HTTP request
     * 
     * @param stream_id Stream ID from CreateRequestStream
     * @param method HTTP method
     * @param path Request path
     * @param authority Host
     * @param headers Additional headers
     * @param body Request body (may be empty)
     * @return true on success
     */
    bool SendRequest(uint64_t stream_id,
                     const std::string& method,
                     const std::string& path,
                     const std::string& authority,
                     const std::vector<std::pair<std::string, std::string>>& headers,
                     const std::vector<uint8_t>& body);
    
    /**
     * @brief Process received stream data with offset for reassembly
     * 
     * @param stream_id Stream ID
     * @param offset Byte offset in stream (for reassembly)
     * @param data Data
     * @param len Length
     * @param fin FIN flag
     */
    void OnStreamData(uint64_t stream_id, uint64_t offset, 
                      const uint8_t* data, size_t len, bool fin);
    
    /**
     * @brief Get stream by ID
     */
    H3Stream* GetStream(uint64_t stream_id);
    
    /**
     * @brief Check if stream exists
     */
    bool HasStream(uint64_t stream_id) const;
    
    /**
     * @brief Close stream
     */
    void CloseStream(uint64_t stream_id);
    
    /**
     * @brief Get next bidirectional stream ID (for request streams)
     */
    uint64_t GetNextBidiStreamId() const { return next_bidi_stream_id_; }
    
    /**
     * @brief Get control stream ID
     */
    uint64_t GetControlStreamId() const { return control_stream_id_; }
    
    /**
     * @brief Reset all state
     */
    void Reset();
    
    /**
     * @brief Set peer settings
     */
    void SetPeerSettings(const SettingsFrame& settings);
    
    /**
     * @brief Get our settings
     */
    const SettingsFrame& GetLocalSettings() const { return local_settings_; }

private:
    // Process frames in receive buffer
    void ProcessReceivedData(uint64_t stream_id);
    
    // Handle control stream data
    void HandleControlStream(uint64_t stream_id, const uint8_t* data, size_t len);
    
    // Handle request stream data
    void HandleRequestStream(uint64_t stream_id, const uint8_t* data, size_t len, bool fin);
    
    // Handle unidirectional stream type
    void HandleUniStreamType(uint64_t stream_id);
    
    // Merge pending out-of-order chunks into contiguous buffer
    void MergePendingChunks(H3Stream* stream);

private:
    SendStreamCallback send_stream_;
    OnResponseCallback on_response_;
    OnStreamDataCallback on_stream_data_;
    
    std::unordered_map<uint64_t, std::unique_ptr<H3Stream>> streams_;
    
    uint64_t next_bidi_stream_id_ = 0;    // Client: 0, 4, 8, ...
    uint64_t next_uni_stream_id_ = 2;     // Client: 2, 6, 10, ...
    
    uint64_t control_stream_id_ = UINT64_MAX;
    uint64_t qpack_encoder_stream_id_ = UINT64_MAX;
    uint64_t qpack_decoder_stream_id_ = UINT64_MAX;
    
    uint64_t peer_control_stream_id_ = UINT64_MAX;
    
    SettingsFrame local_settings_;
    SettingsFrame peer_settings_;
    bool peer_settings_received_ = false;
    bool initialized_ = false;
};

} // namespace h3
} // namespace esp_http3

