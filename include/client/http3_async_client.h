/*
 * HTTP/3 asynchronous client.
 *
 * Owns the QUIC connection, background event loop, stream registry, and a
 * bounded asynchronous request state machine.
 */

#pragma once

#include "client/power_lock.h"
#include "core/quic_connection.h"
#include "esp_http3_memory.h"
#include <atomic>
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

// Forward declarations
class Http3AsyncClient;
class Http3Stream;

// Readiness callbacks run on the HTTP/3 event-loop task. They must not block
// or call back into the client; use them only to wake an owning task.
using Http3ReadySink = void (*)(void*);

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

enum class Http3StreamStatusPollResult : uint8_t {
    kPending,
    kReady,
    kError,
};

enum class Http3StreamReadPollResult : uint8_t {
    kPending,
    kData,
    kFinished,
    kError,
};

/**
 * Http3Stream - Represents an active HTTP/3 request stream
 *
 * Provides synchronous blocking Read/Write operations.
 * Created by Http3AsyncClient::Open(), destroyed when Close() is called
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

    /** Poll response status without blocking. */
    Http3StreamStatusPollResult TryGetStatus(int& status_out);

    /**
   * Get response header value by name (case-insensitive)
   * Returns empty string if not found
   */
    std::string GetHeader(const std::string& name) const;

    /**
   * Get all response headers
   */
    const esp_http3::Http3Headers& GetHeaders() const { return headers_; }

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

    /** Poll response data without blocking. */
    Http3StreamReadPollResult TryRead(uint8_t* buffer, size_t size, size_t& bytes_read_out);

    /** Notify an owning task when status, data, EOF, or an error becomes observable. */
    void SetReadReadySink(Http3ReadySink sink, void* context);

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

    /** Write request data already owned by the component allocator. */
    int Write(esp_http3::Http3Vector<uint8_t>&& data, uint32_t timeout_ms = 0);

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
    friend class Http3AsyncClient;

    // Only Http3AsyncClient can create streams
    Http3Stream(Http3AsyncClient* client, int stream_id, uint32_t default_timeout_ms);

    // Initialize internal state
    bool Initialize(size_t receive_buffer_size);

    // Called by Http3AsyncClient when headers are received
    void OnHeaders(int status, const std::vector<std::pair<std::string, std::string>>& headers);

    // Called by Http3AsyncClient when data is received
    void OnData(const uint8_t* data, size_t length, bool finished);

    // Called by Http3AsyncClient on error
    void OnError(const std::string& error_message);

    // Called by Http3AsyncClient when peer sends STOP_SENDING (write-only reset)
    // This only affects writes, reads can still receive server response
    void OnWriteReset(const std::string& error_message);

    // Called by Http3AsyncClient during destruction to invalidate client pointer
    void InvalidateClient(const std::string& error_message = "Client destroyed");

    void NotifyReadReady();

private:
    std::atomic<Http3AsyncClient*> client_;
    int stream_id_;
    uint32_t default_timeout_ms_;

    // Response info
    int status_ = 0;
    esp_http3::Http3Headers headers_;
    std::string error_;
    std::string write_error_;  // Separate error for write operations

    // Stream state
    std::atomic<bool> closed_{false};
    std::atomic<bool> headers_received_{false};
    std::atomic<bool> finished_receiving_{false};
    std::atomic<bool> finished_sending_{false};
    std::atomic<bool> has_error_{false};
    std::atomic<bool> write_reset_{false};  // True if peer sent STOP_SENDING

    // Receive buffer (ring buffer in PSRAM)
    uint8_t* receive_buffer_ = nullptr;
    size_t receive_buffer_size_ = 0;
    size_t receive_head_ = 0;   // Read position
    size_t receive_tail_ = 0;   // Write position
    size_t receive_count_ = 0;  // Bytes in buffer
    std::mutex receive_mutex_;
    // Serializes client detachment with Close() event-group destruction.
    std::mutex lifecycle_mutex_;

    // Synchronization events
    EventGroupHandle_t event_group_ = nullptr;
    static constexpr uint32_t EVENT_HEADERS_RECEIVED = (1 << 0);
    static constexpr uint32_t EVENT_DATA_AVAILABLE = (1 << 1);
    static constexpr uint32_t EVENT_WRITE_COMPLETE = (1 << 2);
    static constexpr uint32_t EVENT_FINISHED = (1 << 3);
    static constexpr uint32_t EVENT_ERROR = (1 << 4);
    static constexpr uint32_t EVENT_CLOSED = (1 << 5);

    std::atomic<Http3ReadySink> read_ready_sink_{nullptr};
    std::atomic<void*> read_ready_context_{nullptr};

    // Power management
    std::unique_ptr<ScopedPowerLock> power_lock_;
};

/**
 * Connection Configuration
 */
struct Http3AsyncClientConfig {
    std::string hostname;
    uint16_t port = 443;

    // DER-encoded CA trust anchor used for server certificate chain and
    // hostname verification. Leave the development override false in product
    // builds; without a trust anchor the handshake then fails closed.
    std::vector<uint8_t> trusted_ca_der;
    bool allow_unverified_peer = false;

    // Timeouts
    uint32_t connect_timeout_ms = 10000;
    uint32_t request_timeout_ms = 30000;
    uint32_t idle_timeout_ms = 60000;

    // Buffer sizes
    size_t receive_buffer_size = 64 * 1024;  // Per-stream receive buffer
    uint32_t max_concurrent_requests = 10;   // Fixed request and connection flow-control budget
    uint32_t max_udp_payload_size = 1200;    // QUIC max_udp_payload_size transport parameter

    // Bounded asynchronous requests
    size_t max_request_body_size = 1024;
    size_t default_max_response_body_size = 64 * 1024;

    // Keypair caching for faster reconnection
    // When enabled, the X25519 keypair is cached and reused across connections.
    // This speeds up reconnection after idle timeout (saves ~100ms of key
    // generation). client_random is still regenerated each connection for
    // security.
    bool cache_keypair = true;

    // Session ticket caching for session resumption
    // When enabled, NewSessionTicket is saved for future connections.
    // This can potentially enable faster reconnection through PSK resumption.
    // Default: disabled (session tickets have limited lifetime and single-use)
    bool cache_session_ticket = false;

    // Debug logging
    bool enable_debug = false;
};

struct Http3AsyncRequestHandle final {
    uint32_t value{};

    [[nodiscard]] bool valid() const { return value != 0; }
};

struct Http3AsyncRequest final {
    esp_http3::Http3String method{"GET"};
    esp_http3::Http3String path;
    esp_http3::Http3Headers headers;
    esp_http3::Http3Vector<uint8_t> body;
    uint32_t timeout_ms{};
    size_t max_response_body_size{};
};

enum class Http3AsyncOutcome : uint8_t {
    kSucceeded,
    kTransportError,
    kTimedOut,
    kCancelled,
    kResponseTooLarge,
};

struct Http3AsyncResult final {
    Http3AsyncRequestHandle handle{};
    Http3AsyncOutcome outcome{Http3AsyncOutcome::kTransportError};
    int status{-1};
    esp_http3::Http3Headers headers;
    esp_http3::Http3Vector<uint8_t> body;
    esp_http3::Http3String error;
};

/**
 * Http3AsyncClient - owns a persistent QUIC/HTTP3 connection
 *
 * Submit(), Cancel(), and PollCompletion() never wait for network I/O. Start()
 * enables the bounded event-driven request state machine. Open() exposes a low-level stream for
 * long-lived and streaming transfers; the returned stream has blocking and
 * polling operations but does not introduce a dependency on Http3Client.
 *
 * Threading model:
 * - One background event-loop task handles UDP receive and QUIC processing
 * - Public methods can be called from any task
 * - Each Http3Stream should be used from a single task (except Close)
 *
 * Usage:
 *   Http3AsyncClientConfig config;
 *   config.hostname = "api.example.com";
 *   config.port = 443;
 *
 *   Http3AsyncClient client(config);
 *   auto stream = client.Open({.method="GET", .path="/api/data"});
 *   if (stream && stream->GetStatus() == 200) {
 *       // Use stream...
 *   }
 */
class Http3AsyncClient final {
public:
    /**
   * Constructor - initializes the client with the given configuration
   * @param config Connection configuration
   */
    explicit Http3AsyncClient(const Http3AsyncClientConfig& config);

    /**
   * Destructor - cleans up all resources
   */
    ~Http3AsyncClient();

    // Non-copyable and non-movable
    Http3AsyncClient(const Http3AsyncClient&) = delete;
    Http3AsyncClient& operator=(const Http3AsyncClient&) = delete;
    Http3AsyncClient(Http3AsyncClient&&) = delete;
    Http3AsyncClient& operator=(Http3AsyncClient&&) = delete;

    /**
   * Set power lock provider for power management
   * @param provider Power lock provider (not owned, must outlive this client)
   */
    void SetPowerLockProvider(PowerLockProvider* provider);

    /**
   * Get current configuration
   */
    const Http3AsyncClientConfig& GetConfig() const { return config_; }

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

    /** Establish the connection and enable asynchronous requests. */
    [[nodiscard]] bool Start();

    /** Stop asynchronous requests and cancel all outstanding requests. */
    void Stop();

    [[nodiscard]] Http3AsyncRequestHandle Submit(Http3AsyncRequest request);
    [[nodiscard]] bool Cancel(Http3AsyncRequestHandle handle);
    [[nodiscard]] bool PollCompletion(Http3AsyncResult& result_out);
    [[nodiscard]] size_t InFlight() const;

    /** Notify an owning task whenever PollCompletion() can consume a result. */
    void SetCompletionReadySink(Http3ReadySink sink, void* context);

    // ==================== Stream API ====================

    /**
   * Open an HTTP request stream (non-blocking)
   *
   * Opens a stream and sends the request. Returns immediately without
   * waiting for response headers. Use GetStatus()/Read()/Write() on
   * the returned stream with their own timeout parameters.
   *
   * @param request Request configuration
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
    std::unique_ptr<Http3Stream> Open(const Http3Request& request);

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
    bool StreamWrite(int stream_id, esp_http3::Http3Vector<uint8_t>&& data);

    /**
   * Finish a stream (send FIN, low-level)
   */
    bool StreamFinish(int stream_id);

private:
    enum class SlotState : uint8_t {
        kFree,
        kPending,
        kOpening,
        kActive,
        kComplete,
    };

    struct Slot final {
        Http3AsyncRequestHandle handle{};
        Http3AsyncRequest request{};
        Http3AsyncResult result{};
        std::unique_ptr<Http3Stream> stream;
        int64_t deadline_us{};
        SlotState state{SlotState::kFree};
        bool cancel_requested{};
        bool headers_received{};
    };

    void AdvanceAsyncRequests();
    void FailAsyncRequests(Http3AsyncOutcome outcome, const char* error);
    void AdvanceSlot(size_t index);
    void CompleteSlot(size_t index, Http3AsyncOutcome outcome, const char* error = nullptr);
    void NotifyCompletionReady();
    [[nodiscard]] uint32_t LimitWaitToAsyncDeadline(uint32_t wait_ms) const;
    [[nodiscard]] Slot* FindSlot(Http3AsyncRequestHandle handle);

    // Internal stream management
    friend class Http3Stream;

    void RegisterStream(int stream_id, Http3Stream* stream);
    // The connection lock must be held while validating a stream instance.
    bool IsRegisteredStream(int stream_id, const Http3Stream* stream);
    bool StreamWrite(int stream_id, esp_http3::Http3Vector<uint8_t>&& data, const Http3Stream* stream);
    bool StreamFinish(int stream_id, const Http3Stream* stream);

    // Called by Http3Stream
    // @param force_reset If true, send RESET_STREAM (for abnormal termination
    // like timeout/cancel)
    //                    If false, just cleanup (for normal completion)
    void StreamClose(int stream_id, const Http3Stream* stream, bool force_reset = false);
    void StreamAcknowledgeData(int stream_id, size_t bytes, const Http3Stream* stream);

    // Connection management
    bool EnsureConnected(uint32_t timeout_ms = 0);

    // Network operations
    bool CreateSocket();
    void CloseSocket();
    bool StartBackgroundTasks();
    void StopBackgroundTasks();

    // Task entry points
    static void EventLoopTaskEntry(void* parameter);
    void RunEventLoop();
    void WakeEventLoop();

    // QUIC callbacks
    void OnConnected();
    void OnDisconnected(int error_code, const std::string& reason);
    void OnResponse(int stream_id, const esp_http3::H3Response& response);
    void OnStreamData(int stream_id, const uint8_t* data, size_t length, bool finished);

private:
    // Configuration
    Http3AsyncClientConfig config_;

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

    // Background event loop
    TaskHandle_t event_loop_task_ = nullptr;
    EventGroupHandle_t event_group_ = nullptr;
    std::atomic<bool> stop_tasks_{false};

    // select() wakeup descriptor and reusable UDP receive buffer. The buffer
    // follows the component memory policy (PSRAM when configured), rather than
    // consuming event-loop task stack.
    int wake_event_fd_ = -1;
    uint8_t* udp_receive_buffer_ = nullptr;
    static constexpr size_t UDP_RECEIVE_BUFFER_SIZE = 1500;
    static constexpr size_t UDP_RECEIVE_BUDGET = 16;

    // Write queue item - owns the data to avoid dangling pointers
    struct WriteQueueItem {
        esp_http3::Http3Vector<uint8_t> data;  // Owns the memory in the component heap
        size_t offset = 0;                     // Bytes already sent
        bool finish_after = false;             // Send FIN after this data

        WriteQueueItem(esp_http3::Http3Vector<uint8_t>&& d, bool fin = false) : data(std::move(d)), finish_after(fin) {}
    };

    // Per-stream write queues
    std::map<int, std::list<WriteQueueItem>> write_queues_;
    std::mutex write_queues_mutex_;

    // Process pending writes for a stream
    void ProcessWriteQueue(int stream_id);
    void ProcessAllWriteQueues();

    // Called when stream becomes writable
    void OnStreamWritable(int stream_id);

    // Called when stream is reset by peer (RESET_STREAM)
    void OnStreamReset(int stream_id, uint64_t error_code);

    // Called when peer sends STOP_SENDING for request body writes
    void OnStreamStopSending(int stream_id, uint64_t error_code);

    // Helper to set last error message
    void SetLastError(const std::string& error);

    // Event-loop and task-lifecycle signals.
    static constexpr uint32_t EVENT_CONNECTED = (1 << 3);
    static constexpr uint32_t EVENT_DISCONNECTED = (1 << 4);
    static constexpr uint32_t EVENT_ASYNC_STOPPED = (1 << 5);
    static constexpr uint32_t EVENT_EVENT_LOOP_STOPPED = (1 << 6);

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

    // Bounded asynchronous request state machine
    mutable std::mutex async_mutex_;
    esp_http3::Http3Vector<Slot> async_slots_;
    uint32_t next_async_generation_{1};
    std::atomic<bool> async_started_{false};
    std::atomic<bool> async_stop_requested_{false};
    std::atomic<Http3ReadySink> completion_ready_sink_{nullptr};
    std::atomic<void*> completion_ready_context_{nullptr};
};
