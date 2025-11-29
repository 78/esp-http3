/**
 * @file quic_connection.h
 * @brief QUIC Connection - Main orchestrator class
 * 
 * QuicConnection is the primary interface for QUIC/HTTP3 communication.
 * It composes specialized components:
 * - CryptoManager: Key derivation and encryption
 * - FlowController: Send/receive flow control
 * - AckManager: ACK generation
 * - H3Handler: HTTP/3 protocol layer
 * - LossDetector: Loss detection and congestion control
 * 
 * Design: Single-threaded event-driven model
 * - No std::thread, std::mutex, std::condition_variable needed
 * - All operations are synchronous in caller's context
 * - User provides Send callback for outgoing data
 * - User calls ProcessReceivedData() for incoming data
 */

#pragma once

#include "quic/quic_constants.h"
#include <memory>
#include <functional>
#include <string>
#include <vector>
#include <cstdint>

namespace esp_http3 {

//=============================================================================
// Enums and Types
//=============================================================================

/**
 * @brief Connection state
 */
enum class ConnectionState {
    kIdle,                  ///< Initial state, not connected
    kHandshakeInProgress,   ///< QUIC handshake in progress
    kConnected,             ///< Handshake complete, ready for requests
    kClosing,               ///< Graceful close in progress
    kClosed,                ///< Connection closed normally
    kFailed                 ///< Connection failed with error
};

/**
 * @brief HTTP/3 response data
 */
struct H3Response {
    int status = 0;                                             ///< HTTP status code
    std::vector<std::pair<std::string, std::string>> headers;   ///< Response headers
    std::vector<uint8_t> body;                                  ///< Response body
    std::string error;                                          ///< Error message (if any)
    bool complete = false;                                      ///< True if response is complete
};

/**
 * @brief Connection configuration
 */
struct QuicConfig {
    std::string hostname;                   ///< Target hostname (for SNI)
    uint16_t port = 443;                    ///< Target port (not used internally, for reference)
    
    // Timeouts
    uint32_t handshake_timeout_ms = 5000;   ///< Handshake timeout in milliseconds
    uint32_t idle_timeout_ms = 60000;       ///< Idle timeout in milliseconds
    uint32_t response_timeout_ms = 30000;   ///< Response timeout in milliseconds
    
    // Flow control (optimized for embedded, 2Mbps link)
    uint32_t max_data = quic::defaults::kInitialMaxData;              ///< Connection-level flow control limit
    uint32_t max_stream_data = quic::defaults::kInitialMaxStreamDataBidiRemote;       ///< Per-stream flow control limit
    uint32_t max_streams_bidi = quic::defaults::kInitialMaxStreamsBidi;          ///< Max concurrent bidirectional streams
    uint32_t max_streams_uni = quic::defaults::kInitialMaxStreamsUni;           ///< Max concurrent unidirectional streams
    
    // Debug
    bool enable_debug = false;              ///< Enable debug logging
};

//=============================================================================
// Transport Callbacks (provided by user)
//=============================================================================

/**
 * @brief Callback to send UDP data
 * 
 * User must implement this to send data over the network.
 * Called synchronously when QUIC needs to send a packet.
 * 
 * @param data Pointer to data to send
 * @param len Length of data
 * @return Number of bytes sent, or -1 on error
 */
using SendCallback = std::function<int(const uint8_t* data, size_t len)>;

//=============================================================================
// Event Callbacks (notifications to user)
//=============================================================================

/// Called when handshake completes successfully
using OnConnectedCallback = std::function<void()>;

/// Called when connection is closed or fails
using OnDisconnectedCallback = std::function<void(int error_code, const std::string& reason)>;

/// Called when HTTP/3 response is received (complete or partial)
using OnResponseCallback = std::function<void(int stream_id, const H3Response& response)>;

/// Called when stream data is received (for streaming responses)
using OnStreamDataCallback = std::function<void(int stream_id, const uint8_t* data, 
                                                  size_t len, bool fin)>;

//=============================================================================
// QuicConnection Class
//=============================================================================

/**
 * @brief Main QUIC/HTTP3 connection class
 * 
 * This class manages the entire lifecycle of a QUIC connection:
 * - TLS 1.3 handshake
 * - QUIC packet encryption/decryption
 * - HTTP/3 request/response handling
 * - Flow control and congestion control
 * 
 * Threading model:
 * - Single-threaded, no internal threads
 * - All callbacks are invoked synchronously
 * - User is responsible for calling ProcessReceivedData() and OnTimerTick()
 * 
 * @note Uses Pimpl idiom to hide implementation details
 */
class QuicConnection {
public:
    /**
     * @brief Construct a new QUIC connection
     * 
     * @param send_cb Callback for sending UDP data (must remain valid)
     * @param config Connection configuration
     */
    explicit QuicConnection(SendCallback send_cb, const QuicConfig& config);
    
    /**
     * @brief Destructor
     */
    ~QuicConnection();
    
    // Non-copyable
    QuicConnection(const QuicConnection&) = delete;
    QuicConnection& operator=(const QuicConnection&) = delete;
    
    // Movable
    QuicConnection(QuicConnection&&) noexcept;
    QuicConnection& operator=(QuicConnection&&) noexcept;
    
    //=========================================================================
    // Connection Lifecycle
    //=========================================================================
    
    /**
     * @brief Start the QUIC handshake
     * 
     * Sends the Initial packet (ClientHello) and starts the handshake.
     * Progress is reported via OnConnected/OnDisconnected callbacks.
     * 
     * Caller must:
     * 1. Call OnTimerTick() periodically for timeout handling
     * 2. Call ProcessReceivedData() when UDP data arrives
     * 
     * @return true if handshake was initiated (Initial packet sent)
     * @return false if failed to start (e.g., invalid config, send failed)
     */
    bool StartHandshake();
    
    /**
     * @brief Close the connection gracefully
     * 
     * @param error_code QUIC error code (0 = no error)
     * @param reason Human-readable reason string
     */
    void Close(int error_code = 0, const std::string& reason = "");
    
    /**
     * @brief Get current connection state
     */
    ConnectionState GetState() const;
    
    /**
     * @brief Check if connection is established and ready for requests
     */
    bool IsConnected() const;
    
    //=========================================================================
    // Event Processing (must be called by application)
    //=========================================================================
    
    /**
     * @brief Process received UDP data
     * 
     * Call this when data is received from the UDP socket.
     * 
     * @param data Pointer to received data (mutable, will be modified in-place for decryption)
     * @param len Length of received data
     */
    void ProcessReceivedData(uint8_t* data, size_t len);
    
    /**
     * @brief Timer tick for internal state management
     * 
     * Call this periodically (e.g., every 10-100ms) to:
     * - Check for PTO timeouts
     * - Perform loss detection
     * - Send flow control updates
     * 
     * @param elapsed_ms Milliseconds since last call
     */
    void OnTimerTick(uint32_t elapsed_ms);
    
    //=========================================================================
    // HTTP/3 Requests
    //=========================================================================
    
    /**
     * @brief Send an HTTP/3 request
     * 
     * @param method HTTP method (GET, POST, etc.)
     * @param path Request path (e.g., "/api/data")
     * @param headers Additional request headers
     * @param body Request body (optional)
     * @param body_len Length of request body
     * @return Stream ID (>= 0) on success, -1 on failure
     */
    int SendRequest(const std::string& method, 
                    const std::string& path,
                    const std::vector<std::pair<std::string, std::string>>& headers = {},
                    const uint8_t* body = nullptr, 
                    size_t body_len = 0);
    
    /**
     * @brief Open a stream for chunked upload
     * 
     * Use this for large uploads. After opening, call WriteStream() to send
     * data, then FinishStream() to complete.
     * 
     * @param method HTTP method (typically POST or PUT)
     * @param path Request path
     * @param headers Request headers
     * @return Stream ID (>= 0) on success, -1 on failure
     */
    int OpenStream(const std::string& method, 
                   const std::string& path,
                   const std::vector<std::pair<std::string, std::string>>& headers = {});
    
    /**
     * @brief Write data to an open stream
     * 
     * @param stream_id Stream ID from OpenStream()
     * @param data Data to send
     * @param len Length of data
     * @return true on success, false on failure
     */
    bool WriteStream(int stream_id, const uint8_t* data, size_t len);
    
    /**
     * @brief Finish writing to a stream (send FIN)
     * 
     * @param stream_id Stream ID from OpenStream()
     * @return true on success, false on failure
     */
    bool FinishStream(int stream_id);
    
    /**
     * @brief Get response for a stream (if available)
     * 
     * @param stream_id Stream ID
     * @return Pointer to response, or nullptr if not available
     */
    const H3Response* GetResponse(int stream_id) const;
    
    //=========================================================================
    // Callback Registration
    //=========================================================================
    
    void SetOnConnected(OnConnectedCallback cb);
    void SetOnDisconnected(OnDisconnectedCallback cb);
    void SetOnResponse(OnResponseCallback cb);
    void SetOnStreamData(OnStreamDataCallback cb);
    
    //=========================================================================
    // Statistics
    //=========================================================================
    
    /**
     * @brief Connection statistics
     */
    struct Stats {
        uint32_t packets_sent = 0;
        uint32_t packets_received = 0;
        uint32_t bytes_sent = 0;
        uint32_t bytes_received = 0;
        uint32_t handshake_time_ms = 0;
        uint32_t rtt_ms = 0;
        uint32_t cwnd = 0;
        uint32_t bytes_in_flight = 0;
    };
    
    /**
     * @brief Get connection statistics
     */
    Stats GetStats() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace esp_http3

