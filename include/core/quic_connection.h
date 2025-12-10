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
 * 
 * Note: Body data is not stored here to save memory. Use OnStreamData callback
 * to receive body data in a streaming fashion.
 */
struct H3Response {
    int status = 0;                                             ///< HTTP status code
    std::vector<std::pair<std::string, std::string>> headers;   ///< Response headers
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
    
    // DATAGRAM (RFC 9221)
    bool enable_datagram = false;           ///< Enable DATAGRAM frame support
    uint32_t max_datagram_frame_size = 65535;  ///< Max DATAGRAM frame size (0 = disabled)
    
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

/// Called when a stream becomes writable (flow control window available)
/// This is called when MAX_STREAM_DATA is received for the stream.
using OnStreamWritableCallback = std::function<void(int stream_id)>;

/// Called when connection becomes writable (MAX_DATA received or ACK frees congestion window)
/// Upper layer should retry any blocked writes.
using OnWritableCallback = std::function<void()>;

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
     * @return Time in milliseconds until the next timer should fire.
     *         Returns 0 if timer processing is not needed (e.g., disconnected).
     *         Returns a maximum of 60000ms (1 minute) as an upper bound.
     */
    uint32_t OnTimerTick(uint32_t elapsed_ms);
    
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
     * @brief Write data to an open stream (synchronous, may be flow-control limited)
     * 
     * @param stream_id Stream ID from OpenStream()
     * @param data Data to send
     * @param len Length of data
     * @return Number of bytes written (may be less than len if flow-control limited)
     *         0 if flow-control blocked (no bytes could be sent)
     *         -1 on error (stream doesn't exist or connection error)
     * 
     * @note Caller should retry with remaining data when flow control allows.
     *       Use GetSendableBytes() to check available window before calling.
     */
    ssize_t WriteStream(int stream_id, const uint8_t* data, size_t len);
    
    /**
     * @brief Finish writing to a stream (send FIN)
     * 
     * @param stream_id Stream ID from OpenStream()
     * @return true on success, false on failure
     */
    bool FinishStream(int stream_id);
    
    /**
     * @brief Reset a stream by sending RESET_STREAM frame
     * 
     * This abruptly terminates the stream, discarding any queued data.
     * Use this when you want to abort an ongoing request/upload.
     * The peer will receive RESET_STREAM frame with the specified error code.
     * 
     * @param stream_id Stream ID to reset
     * @param error_code Application error code (default: H3_REQUEST_CANCELLED = 0x10c)
     * @return true on success, false if stream doesn't exist or already closed
     */
    bool ResetStream(int stream_id, uint64_t error_code = 0x10c);
    
    //=========================================================================
    // Flow Control (borrowed from Python version)
    //=========================================================================
    
    /**
     * @brief Check if data can be sent on a stream
     * 
     * Checks both connection-level and stream-level flow control limits.
     * Use this before WriteStream() to avoid blocking or failures.
     * 
     * @param stream_id Stream ID
     * @param len Desired send length
     * @return true if len bytes can be sent, false if flow control blocked
     */
    bool CanSend(int stream_id, size_t len) const;
    
    /**
     * @brief Get the number of bytes that can be sent on a stream
     * 
     * Returns the minimum of connection and stream send windows.
     * 
     * @param stream_id Stream ID
     * @return Number of bytes that can be sent (may be 0 if blocked)
     */
    size_t GetSendableBytes(int stream_id) const;
    
    /**
     * @brief Check if connection-level flow control is blocked
     */
    bool IsConnectionBlocked() const;
    
    /**
     * @brief Check if a stream is flow control blocked
     * 
     * @param stream_id Stream ID
     */
    bool IsStreamBlocked(int stream_id) const;
    
    /**
     * @brief Check if a stream was reset by the server
     * 
     * @param stream_id Stream ID
     * @return true if stream was reset
     */
    bool IsStreamReset(int stream_id) const;
    
    /**
     * @brief Acknowledge that bytes have been consumed by upper layer
     * 
     * This is used for receive-side flow control with backpressure support.
     * MAX_STREAM_DATA is only sent based on consumed bytes, allowing the
     * upper layer to control the receive rate by delaying this call.
     * 
     * Call this when data has been read from the receive buffer and processed.
     * 
     * @param stream_id Stream ID
     * @param bytes Number of bytes consumed
     */
    void AcknowledgeStreamData(int stream_id, size_t bytes);
    
    //=========================================================================
    // Callback Registration
    //=========================================================================
    
    void SetOnConnected(OnConnectedCallback cb);
    void SetOnDisconnected(OnDisconnectedCallback cb);
    void SetOnResponse(OnResponseCallback cb);
    void SetOnStreamData(OnStreamDataCallback cb);
    
    /// Set callback for stream becoming writable (MAX_STREAM_DATA received)
    void SetOnStreamWritable(OnStreamWritableCallback cb);
    
    /// Set callback for connection becoming writable (MAX_DATA or ACK frees window)
    void SetOnWritable(OnWritableCallback cb);
    
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
    
    //=========================================================================
    // Key Update (RFC 9001 Section 6)
    //=========================================================================
    
    /**
     * @brief Initiate a Key Update
     * 
     * Derives next generation application secrets and switches to them.
     * Only call after handshake is complete.
     * 
     * @return true if key update was initiated
     */
    bool InitiateKeyUpdate();
    
    /**
     * @brief Get current key phase (0 or 1)
     */
    uint8_t GetKeyPhase() const;
    
    /**
     * @brief Get key update generation count
     */
    uint32_t GetKeyUpdateGeneration() const;
    
    //=========================================================================
    // Path Validation
    //=========================================================================
    
    /**
     * @brief Send PATH_CHALLENGE to validate path
     * 
     * The 8-byte challenge data is randomly generated.
     * Response will be received via ProcessReceivedData.
     * 
     * @return true if PATH_CHALLENGE was sent
     */
    bool SendPathChallenge();
    
    /**
     * @brief Check if path is validated
     */
    bool IsPathValidated() const;
    
    /**
     * @brief Get RTT measured from last PATH_CHALLENGE/RESPONSE (in ms)
     * 
     * @return RTT in milliseconds, or 0 if not measured
     */
    uint32_t GetPathValidationRtt() const;
    
    //=========================================================================
    // Connection Migration
    //=========================================================================
    
    /**
     * @brief Initiate connection migration to a new network path
     * 
     * This method triggers an active connection migration, which involves:
     * 1. Selecting a new peer connection ID
     * 2. Sending PATH_CHALLENGE on the new path
     * 3. Waiting for PATH_RESPONSE to validate the path
     * 
     * Use this when the local network changes (e.g., WiFi to cellular).
     * The current connection state and streams are preserved.
     * 
     * Prerequisites:
     * - Connection must be established (IsConnected() returns true)
     * - Server must not have disabled migration (IsMigrationAllowed() returns true)
     * - At least one peer connection ID must be available
     * 
     * @return true if migration was initiated, false on failure
     * 
     * @note Migration result is reported via OnMigrationComplete callback.
     *       On failure, the connection automatically rolls back to the old path.
     */
    bool MigrateConnection();
    
    /**
     * @brief Check if connection migration is allowed
     * 
     * Returns false if the server sent disable_active_migration transport parameter.
     * 
     * @return true if migration is allowed by the server
     */
    bool IsMigrationAllowed() const;
    
    /**
     * @brief Check if migration is currently in progress
     * 
     * @return true if migration is in progress (waiting for path validation)
     */
    bool IsMigrationInProgress() const;
    
    /**
     * @brief Get number of available peer connection IDs for migration
     * 
     * At least one connection ID is needed to migrate. If this returns 0,
     * migration cannot be performed until the server provides more IDs.
     * 
     * @return Number of non-retired peer connection IDs available
     */
    size_t GetAvailablePeerConnectionIdCount() const;
    
    /**
     * @brief Set callback for migration completion
     * 
     * @param cb Callback function (success: true if migration succeeded)
     */
    using OnMigrationCompleteCallback = std::function<void(bool success)>;
    void SetOnMigrationComplete(OnMigrationCompleteCallback cb);
    
    //=========================================================================
    // DATAGRAM (RFC 9221)
    //=========================================================================
    
    /**
     * @brief Check if DATAGRAM can be sent
     * 
     * DATAGRAM can only be sent if:
     * 1. We have enabled DATAGRAM support (enable_datagram=true in config)
     * 2. Peer has advertised max_datagram_frame_size > 0
     * 3. (Optional) The data size fits within peer's limit
     * 
     * @param size Size of data to send (0 to just check if enabled)
     * @return true if DATAGRAM can be sent
     */
    bool CanSendDatagram(size_t size = 0) const;
    
    /**
     * @brief Send an unreliable DATAGRAM
     * 
     * DATAGRAM frames provide unreliable delivery of application data.
     * They are ack-eliciting but NOT retransmitted on loss.
     * 
     * @param data Application data to send
     * @param len Data length
     * @return true if sent successfully, false if DATAGRAM not available
     */
    bool SendDatagram(const uint8_t* data, size_t len);
    
    /**
     * @brief Set callback for receiving DATAGRAM frames
     * 
     * @param cb Callback function (data, len)
     */
    using OnDatagramCallback = std::function<void(const uint8_t* data, size_t len)>;
    void SetOnDatagram(OnDatagramCallback cb);
    
    /**
     * @brief Get maximum DATAGRAM size that can be sent
     * 
     * Returns minimum of local and peer limits, or 0 if not available.
     */
    size_t GetMaxDatagramSize() const;
    
    /**
     * @brief Check if DATAGRAM is available (both sides support it)
     */
    bool IsDatagramAvailable() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace esp_http3

