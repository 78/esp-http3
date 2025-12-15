/*
 * HTTP/3 Client - QUIC/HTTP3 Connection Client
 * 
 * Provides synchronous blocking API for HTTP/3 requests.
 * Manages a persistent QUIC connection with background event loop.
 */

#pragma once

#include <string>
#include <memory>
#include <functional>
#include <mutex>
#include <atomic>
#include <vector>
#include <map>
#include <list>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/event_groups.h>
#include <freertos/semphr.h>
#include <freertos/queue.h>
#include "esp_http3.h"
#include "client/power_lock.h"

// Forward declarations
class Http3Client;
class Http3Stream;

/**
 * HTTP/3 Request Configuration
 */
struct Http3Request {
    std::string method = "GET";
    std::string path;
    std::vector<std::pair<std::string, std::string>> headers;
    
    // For immediate body (non-streaming)
    const uint8_t* body = nullptr;
    size_t body_size = 0;
    
    // For streaming upload
    bool streaming_upload = false;
};

/**
 * HTTP/3 Response (for simple requests)
 */
struct Http3Response {
    int status = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    bool complete = false;
    std::string error;
};

/**
 * Http3Stream - Represents an active HTTP/3 request stream
 * 
 * Provides synchronous blocking Read/Write operations.
 * Created by Http3Client::Open(), destroyed when Close() is called
 * or the unique_ptr goes out of scope.
 * 
 * Thread safety:
 * - Read(), Write(), Finish() should be called from the same task
 * - Close() can be called from any task to force-close the stream
 */
class Http3Stream {
public:
    ~Http3Stream();
    
    // Non-copyable, non-movable (prevent accidental copies)
    Http3Stream(const Http3Stream&) = delete;
    Http3Stream& operator=(const Http3Stream&) = delete;
    Http3Stream(Http3Stream&&) = delete;
    Http3Stream& operator=(Http3Stream&&) = delete;
    
    /**
     * Check if stream is valid and usable
     */
    bool IsValid() const;
    
    /**
     * Get stream ID
     */
    int GetStreamId() const { return stream_id_; }
    
    /**
     * Get HTTP status code (blocking)
     * 
     * Waits for response headers and returns HTTP status code.
     * After this returns, GetHeader() is valid.
     * 
     * @param timeout_ms Maximum time to wait (0 = use default from config)
     * @return HTTP status code (e.g., 200), or -1 on error/timeout
     */
    int GetStatus(uint32_t timeout_ms = 0);
    
    /**
     * Get response header value by name (case-insensitive)
     * Returns empty string if not found
     */
    std::string GetHeader(const std::string& name) const;
    
    /**
     * Get all response headers
     */
    const std::vector<std::pair<std::string, std::string>>& GetHeaders() const {
        return headers_;
    }
    
    /**
     * Get error message (if any)
     */
    const std::string& GetError() const { return error_; }
    
    /**
     * Read response data (blocking)
     * 
     * Blocks until data is available, EOF, or timeout.
     * 
     * @param buffer Destination buffer
     * @param size Maximum bytes to read
     * @param timeout_ms Read timeout (0 = use default from config)
     * @return >0: Bytes read
     *         0: EOF (response complete)
     *         <0: Error (check GetError())
     */
    int Read(uint8_t* buffer, size_t size, uint32_t timeout_ms = 0);
    
    /**
     * Write request data (blocking, takes ownership via move)
     * 
     * For streaming uploads. Blocks until data is sent or timeout.
     * Must call Finish() after all data is written.
     * 
     * @param data Data to send (moved, caller should not use after call)
     * @param timeout_ms Write timeout (0 = use default from config)
     * @return >0: Bytes written
     *         <0: Error (check GetError())
     */
    int Write(std::vector<uint8_t>&& data, uint32_t timeout_ms = 0);
    
    /**
     * Write request data (blocking, copies data)
     * 
     * For streaming uploads. Blocks until data is sent or timeout.
     * Must call Finish() after all data is written.
     * 
     * @param data Data to send
     * @param size Data size
     * @param timeout_ms Write timeout (0 = use default from config)
     * @return >0: Bytes written
     *         <0: Error (check GetError())
     */
    int Write(const uint8_t* data, size_t size, uint32_t timeout_ms = 0);
    
    /**
     * Finish request body (send FIN)
     * 
     * Signals end of request body for streaming uploads.
     * After calling this, Write() will fail.
     * 
     * @return true if successful
     */
    bool Finish();
    
    /**
     * Close the stream
     * 
     * Releases all resources. Can be called from any task.
     * Safe to call multiple times.
     */
    void Close();

private:
    friend class Http3Client;
    
    // Only Http3Client can create streams
    Http3Stream(Http3Client* client, int stream_id, uint32_t default_timeout_ms);
    
    // Initialize internal state
    bool Initialize(size_t receive_buffer_size);
    
    // Called by Http3Client when headers are received
    void OnHeaders(int status, 
                   const std::vector<std::pair<std::string, std::string>>& headers);
    
    // Called by Http3Client when data is received
    void OnData(const uint8_t* data, size_t length, bool finished);
    
    // Called by Http3Client on error
    void OnError(const std::string& error_message);
    
private:
    Http3Client* client_;
    int stream_id_;
    uint32_t default_timeout_ms_;
    
    // Response info
    int status_ = 0;
    std::vector<std::pair<std::string, std::string>> headers_;
    std::string error_;
    
    // Stream state
    std::atomic<bool> closed_{false};
    std::atomic<bool> headers_received_{false};
    std::atomic<bool> finished_receiving_{false};
    std::atomic<bool> finished_sending_{false};
    std::atomic<bool> has_error_{false};
    
    // Receive buffer (ring buffer in PSRAM)
    uint8_t* receive_buffer_ = nullptr;
    size_t receive_buffer_size_ = 0;
    size_t receive_head_ = 0;           // Read position
    size_t receive_tail_ = 0;           // Write position
    size_t receive_count_ = 0;          // Bytes in buffer
    std::mutex receive_mutex_;
    
    // Synchronization events
    EventGroupHandle_t event_group_ = nullptr;
    static constexpr uint32_t EVENT_HEADERS_RECEIVED = (1 << 0);
    static constexpr uint32_t EVENT_DATA_AVAILABLE = (1 << 1);
    static constexpr uint32_t EVENT_WRITE_COMPLETE = (1 << 2);
    static constexpr uint32_t EVENT_FINISHED = (1 << 3);
    static constexpr uint32_t EVENT_ERROR = (1 << 4);
    static constexpr uint32_t EVENT_CLOSED = (1 << 5);
    
    // Power management
    std::unique_ptr<ScopedPowerLock> power_lock_;
};

/**
 * Connection Configuration
 */
struct Http3ClientConfig {
    std::string hostname;
    uint16_t port = 443;
    
    // Timeouts
    uint32_t connect_timeout_ms = 10000;
    uint32_t request_timeout_ms = 30000;
    uint32_t idle_timeout_ms = 60000;
    
    // Buffer sizes
    size_t receive_buffer_size = 64 * 1024;  // Per-stream receive buffer
    
    // Keypair caching for faster reconnection
    // When enabled, the X25519 keypair is cached and reused across connections.
    // This speeds up reconnection after idle timeout (saves ~100ms of key generation).
    // client_random is still regenerated each connection for security.
    bool cache_keypair = true;
    
    // Session ticket caching for session resumption
    // When enabled, NewSessionTicket is saved for future connections.
    // This can potentially enable faster reconnection through PSK resumption.
    // Default: disabled (session tickets have limited lifetime and single-use)
    bool cache_session_ticket = false;
    
    // Debug logging
    bool enable_debug = false;
};

/**
 * Http3Client - Manages a persistent QUIC/HTTP3 connection
 * 
 * Provides synchronous blocking API for HTTP/3 requests.
 * 
 * Threading model:
 * - Background tasks handle UDP receive and QUIC event processing
 * - Public methods can be called from any task
 * - Each Http3Stream should be used from a single task (except Close)
 * 
 * Usage:
 *   Http3ClientConfig config;
 *   config.hostname = "api.example.com";
 *   config.port = 443;
 *   
 *   Http3Client client(config);
 *   auto stream = client.Open({.method="GET", .path="/api/data"});
 *   if (stream && stream->GetStatus() == 200) {
 *       // Use stream...
 *   }
 */
class Http3Client {
public:
    /**
     * Constructor - initializes the client with the given configuration
     * @param config Connection configuration
     */
    explicit Http3Client(const Http3ClientConfig& config);
    
    /**
     * Destructor - cleans up all resources
     */
    ~Http3Client();
    
    // Non-copyable and non-movable
    Http3Client(const Http3Client&) = delete;
    Http3Client& operator=(const Http3Client&) = delete;
    Http3Client(Http3Client&&) = delete;
    Http3Client& operator=(Http3Client&&) = delete;
    
    /**
     * Set power lock provider for power management
     * @param provider Power lock provider (not owned, must outlive this client)
     */
    void SetPowerLockProvider(PowerLockProvider* provider);
    
    /**
     * Get current configuration
     */
    const Http3ClientConfig& GetConfig() const { return config_; }
    
    /**
     * Check if connected to server
     */
    bool IsConnected() const;
    
    /**
     * Get the last error message from the client
     * @return Error message string, empty if no error
     */
    std::string GetLastError() const;
    
    /**
     * Disconnect from server
     */
    void Disconnect();
    
    // ==================== Stream API ====================
    
    /**
     * Open an HTTP request stream (blocking)
     * 
     * Blocks until response headers are received or timeout.
     * For streaming uploads, set request.streaming_upload = true.
     * 
     * @param request Request configuration
     * @param timeout_ms Timeout for receiving headers (0 = use config default)
     * @return Stream object, or nullptr on failure
     * 
     * Example (simple GET):
     *   auto stream = client.Open({.method="GET", .path="/api/data"});
     *   if (stream && stream->GetStatus() == 200) {
     *       uint8_t buffer[1024];
     *       while (int n = stream->Read(buffer, sizeof(buffer)) > 0) {
     *           // Process data...
     *       }
     *   }
     * 
     * Example (streaming upload):
     *   Http3Request request;
     *   request.method = "POST";
     *   request.path = "/upload";
     *   request.streaming_upload = true;
     *   
     *   auto stream = client.Open(request);
     *   if (stream) {
     *       stream->Write(data1, len1);
     *       stream->Write(data2, len2);
     *       stream->Finish();
     *       // Read response...
     *   }
     */
    std::unique_ptr<Http3Stream> Open(const Http3Request& request, 
                                       uint32_t timeout_ms = 0);
    
    // ==================== Convenience Methods ====================
    
    /**
     * Simple GET request (blocking, accumulates response body)
     * Suitable for small responses like JSON APIs.
     * @param timeout_ms Timeout (0 = use config default)
     */
    bool Get(const std::string& path, Http3Response& response,
             uint32_t timeout_ms = 0);
    
    /**
     * Simple POST request (blocking, accumulates response body)
     * @param timeout_ms Timeout (0 = use config default)
     */
    bool Post(const std::string& path, 
              const std::vector<std::pair<std::string, std::string>>& headers,
              const uint8_t* body, size_t body_size,
              Http3Response& response,
              uint32_t timeout_ms = 0);
    
    // ==================== Statistics ====================
    
    struct Statistics {
        uint32_t packets_sent = 0;
        uint32_t packets_received = 0;
        uint32_t bytes_sent = 0;
        uint32_t bytes_received = 0;
        uint32_t rtt_ms = 0;
        uint32_t active_streams = 0;
    };
    
    Statistics GetStatistics() const;

    // ==================== Low-level Stream Operations ====================
    // These are used by ApiClient for streaming upload
    
    /**
     * Write data to a stream (low-level, takes ownership)
     * @param data Data to send (moved, caller should not use after call)
     */
    bool StreamWrite(int stream_id, std::vector<uint8_t>&& data);
    
    /**
     * Finish a stream (send FIN, low-level)
     */
    bool StreamFinish(int stream_id);

private:
    // Internal stream management
    friend class Http3Stream;
    
    void RegisterStream(int stream_id, Http3Stream* stream);
    void UnregisterStream(int stream_id);
    Http3Stream* GetStream(int stream_id);
    
    // Called by Http3Stream
    // @param force_reset If true, send RESET_STREAM (for abnormal termination like timeout/cancel)
    //                    If false, just cleanup (for normal completion)
    void StreamClose(int stream_id, bool force_reset = false);
    void StreamAcknowledgeData(int stream_id, size_t bytes);
    
    // Connection management
    bool EnsureConnected(uint32_t timeout_ms = 0);
    
    // Network operations
    bool CreateSocket();
    void CloseSocket();
    bool StartBackgroundTasks();
    void StopBackgroundTasks();
    
    // Task entry points
    static void UdpReceiveTaskEntry(void* parameter);
    static void EventLoopTaskEntry(void* parameter);
    void RunUdpReceive();
    void RunEventLoop();
    void WakeEventLoop();
    
    // QUIC callbacks
    void OnConnected();
    void OnDisconnected(int error_code, const std::string& reason);
    void OnResponse(int stream_id, const esp_http3::H3Response& response);
    void OnStreamData(int stream_id, const uint8_t* data, size_t length, bool finished);

private:
    // Configuration
    Http3ClientConfig config_;
    
    // Power lock provider (not owned)
    PowerLockProvider* power_lock_provider_ = nullptr;
    
    // QUIC connection
    std::unique_ptr<esp_http3::QuicConnection> connection_;
    int udp_socket_ = -1;
    bool connected_ = false;
    bool initialized_ = false;
    std::atomic<bool> needs_cleanup_{false};
    
    // Stream management
    std::map<int, Http3Stream*> streams_;
    mutable std::mutex streams_mutex_;
    
    // Background tasks
    TaskHandle_t event_loop_task_ = nullptr;
    TaskHandle_t udp_receive_task_ = nullptr;
    EventGroupHandle_t event_group_ = nullptr;
    std::atomic<bool> stop_tasks_{false};
    
    // UDP packet queue
    struct UdpPacket {
        uint8_t data[1500];
        size_t length;
    };
    QueueHandle_t udp_queue_ = nullptr;
    static constexpr size_t UDP_QUEUE_SIZE = 64;
    
    
    // Write queue item - owns the data to avoid dangling pointers
    struct WriteQueueItem {
        std::vector<uint8_t> data;  // Owns the memory
        size_t offset = 0;          // Bytes already sent
        bool finish_after = false;  // Send FIN after this data
        
        WriteQueueItem(std::vector<uint8_t>&& d, bool fin = false)
            : data(std::move(d)), finish_after(fin) {}
    };
    
    // Per-stream write queues
    std::map<int, std::list<WriteQueueItem>> write_queues_;
    std::mutex write_queues_mutex_;
    
    // Process pending writes for a stream
    void ProcessWriteQueue(int stream_id);
    void ProcessAllWriteQueues();
    
    // Called when stream becomes writable
    void OnStreamWritable(int stream_id);
    
    // Helper to set last error message
    void SetLastError(const std::string& error);
    
    // Legacy event bits (still used for simple signaling)
    static constexpr uint32_t EVENT_UDP_DATA = (1 << 0);
    static constexpr uint32_t EVENT_WAKE = (1 << 1);
    static constexpr uint32_t EVENT_STOP = (1 << 2);
    static constexpr uint32_t EVENT_CONNECTED = (1 << 3);
    static constexpr uint32_t EVENT_DISCONNECTED = (1 << 4);
    
    // Connection mutex
    mutable std::mutex connection_mutex_;
    
    // Last error message
    mutable std::mutex error_mutex_;
    std::string last_error_;
    
    // Cached X25519 keypair for faster reconnection
    bool has_cached_keypair_ = false;
    uint8_t cached_private_key_[32] = {0};
    uint8_t cached_public_key_[32] = {0};
    
    // Session ticket caching for session resumption
    bool has_cached_session_ticket_ = false;
    esp_http3::SessionTicketData cached_session_ticket_;
};

