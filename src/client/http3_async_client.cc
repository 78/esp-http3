/*
 * HTTP/3 asynchronous transport implementation.
 *
 * Owns connection, stream, and background event-loop resources.
 */

#include "client/http3_async_client.h"
#include "esp_http3_memory.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <errno.h>
#include <esp_err.h>
#include <esp_log.h>
#include <esp_timer.h>
#include <esp_vfs_eventfd.h>
#include <fcntl.h>
#include <lwip/netdb.h>
#include <lwip/sockets.h>
#include <sys/select.h>
#include <unistd.h>

#define TAG "Http3AsyncClient"

namespace {

int CreateWakeEventFd() {
    // eventfd is a process-wide VFS. Register it lazily and leave the VFS
    // installed for the application lifetime so multiple component instances
    // and other IDF users cannot invalidate each other's descriptors.
    static std::mutex registration_mutex;
    std::lock_guard<std::mutex> lock(registration_mutex);

    int fd = eventfd(0, 0);
    if (fd >= 0) {
        return fd;
    }
    if (errno != EACCES) {
        return -1;
    }

    esp_vfs_eventfd_config_t eventfd_config = ESP_VFS_EVENTD_CONFIG_DEFAULT();
    const esp_err_t result = esp_vfs_eventfd_register(&eventfd_config);
    if (result != ESP_OK && result != ESP_ERR_INVALID_STATE) {
        errno = ENOMEM;
        return -1;
    }
    return eventfd(0, 0);
}

}  // namespace

// ============================================================================
// Http3Stream Implementation
// ============================================================================

Http3Stream::Http3Stream(Http3AsyncClient* client, int stream_id, uint32_t default_timeout_ms)
    : client_(client), stream_id_(stream_id), default_timeout_ms_(default_timeout_ms) {}

Http3Stream::~Http3Stream() {
    Close();

    // Free receive buffer.
    if (receive_buffer_) {
        esp_http3::memory::Deallocate(receive_buffer_);
        receive_buffer_ = nullptr;
    }
}

bool Http3Stream::Initialize(size_t receive_buffer_size) {
    // Create event group for synchronization
    event_group_ = xEventGroupCreate();
    if (!event_group_) {
        ESP_LOGE(TAG, "Failed to create event group for stream %d", stream_id_);
        return false;
    }

    // Allocate receive buffer using the component memory policy.
    receive_buffer_ = static_cast<uint8_t*>(esp_http3::memory::Allocate(receive_buffer_size, alignof(uint8_t)));
    if (!receive_buffer_) {
        ESP_LOGE(TAG, "Failed to allocate receive buffer for stream %d", stream_id_);
        vEventGroupDelete(event_group_);
        event_group_ = nullptr;
        return false;
    }
    receive_buffer_size_ = receive_buffer_size;

    return true;
}

bool Http3Stream::IsValid() const { return !closed_ && !has_error_ && client_ != nullptr; }

std::string Http3Stream::GetHeader(const std::string& name) const {
    // Case-insensitive header lookup without temporary string allocations
    for (const auto& header : headers_) {
        if (header.first.size() == name.size() &&
            std::equal(header.first.begin(), header.first.end(), name.begin(), [](char a, char b) {
                return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
            })) {
            return std::string(header.second.data(), header.second.size());
        }
    }
    return "";
}

int Http3Stream::Read(uint8_t* buffer, size_t size, uint32_t timeout_ms) {
    if (closed_) {
        error_ = "Stream is closed";
        return -1;
    }

    if (!buffer || size == 0) {
        error_ = "Invalid buffer";
        return -1;
    }

    // Use default timeout if 0
    if (timeout_ms == 0) {
        timeout_ms = default_timeout_ms_;
    }

    TickType_t remaining_ticks = pdMS_TO_TICKS(timeout_ms);
    TimeOut_t timeout_state{};
    vTaskSetTimeOutState(&timeout_state);

    while (true) {
        size_t bytes_to_read = 0;

        // Check for data in buffer (hold lock only for buffer access)
        {
            std::lock_guard<std::mutex> lock(receive_mutex_);

            // Check error state
            if (has_error_) {
                return -1;
            }

            // Return data if available
            if (receive_count_ > 0) {
                bytes_to_read = std::min(size, receive_count_);

                // Copy from ring buffer using memcpy (handles wrap-around)
                size_t first_chunk = std::min(bytes_to_read, receive_buffer_size_ - receive_head_);
                memcpy(buffer, receive_buffer_ + receive_head_, first_chunk);
                if (first_chunk < bytes_to_read) {
                    // Wrap around - copy remaining from start of buffer
                    memcpy(buffer + first_chunk, receive_buffer_, bytes_to_read - first_chunk);
                }
                receive_head_ = (receive_head_ + bytes_to_read) % receive_buffer_size_;
                receive_count_ -= bytes_to_read;
            }

            // No data and finished receiving - return EOF
            if (bytes_to_read == 0 && finished_receiving_) {
                return 0;
            }
        }

        // If we got data, notify flow controller AFTER releasing receive_mutex_
        // to avoid ABBA deadlock with connection_mutex_ (event loop holds
        // connection_mutex_ while calling OnData which needs receive_mutex_)
        if (bytes_to_read > 0) {
            if (Http3AsyncClient* client = client_.load()) {
                client->StreamAcknowledgeData(stream_id_, bytes_to_read, this);
            }
            return static_cast<int>(bytes_to_read);
        }

        // Treat timeout_ms as one deadline for the whole Read() operation.
        // Empty/spurious stream notifications must not restart the timeout.
        if (xTaskCheckForTimeOut(&timeout_state, &remaining_ticks) == pdTRUE) {
            error_ = "Read timeout";
            return -1;
        }

        // Wait for data, finish, or error
        EventBits_t bits =
            xEventGroupWaitBits(event_group_, EVENT_DATA_AVAILABLE | EVENT_FINISHED | EVENT_ERROR | EVENT_CLOSED,
                                pdTRUE,   // Clear bits on exit
                                pdFALSE,  // Wait for any bit
                                remaining_ticks);

        if (bits == 0) {
            error_ = "Read timeout";
            return -1;
        }

        if (bits & EVENT_CLOSED) {
            error_ = "Stream closed";
            return -1;
        }

        if (bits & EVENT_ERROR) {
            // Error message already set by OnError
            return -1;
        }

        // Loop back to check for data
    }
}

int Http3Stream::Write(std::vector<uint8_t>&& data, uint32_t timeout_ms) {
    esp_http3::Http3Vector<uint8_t> owned(data.begin(), data.end());
    std::vector<uint8_t>().swap(data);
    return Write(std::move(owned), timeout_ms);
}

int Http3Stream::Write(esp_http3::Http3Vector<uint8_t>&& data, uint32_t timeout_ms) {
    if (closed_) {
        error_ = "Stream is closed";
        return -1;
    }

    if (finished_sending_) {
        error_ = "Stream already finished sending";
        return -1;
    }

    // Check if peer sent STOP_SENDING (write-only reset)
    if (write_reset_) {
        error_ = write_error_;
        return -1;
    }

    if (data.empty()) {
        return 0;
    }

    // Use default timeout if 0
    if (timeout_ms == 0) {
        timeout_ms = default_timeout_ms_;
    }

    size_t size = data.size();

    // Write to QUIC connection (takes ownership)
    Http3AsyncClient* client = client_.load();
    if (!client || !client->StreamWrite(stream_id_, std::move(data), this)) {
        error_ = "Write failed";
        return -1;
    }

    // Wait for write to complete (or timeout)
    EventBits_t bits = xEventGroupWaitBits(event_group_, EVENT_WRITE_COMPLETE | EVENT_ERROR | EVENT_CLOSED, pdTRUE,
                                           pdFALSE, pdMS_TO_TICKS(timeout_ms));

    if (bits == 0) {
        error_ = "Write timeout";
        return -1;
    }

    if (bits & EVENT_CLOSED) {
        error_ = "Stream closed";
        return -1;
    }

    if (bits & EVENT_ERROR) {
        return -1;
    }

    // Check again after wait - STOP_SENDING may have arrived during write
    if (write_reset_) {
        error_ = write_error_;
        return -1;
    }

    return static_cast<int>(size);
}

int Http3Stream::Write(const uint8_t* data, size_t size, uint32_t timeout_ms) {
    if (!data || size == 0) {
        return 0;
    }
    // Copy data and delegate to move version
    esp_http3::Http3Vector<uint8_t> owned(data, data + size);
    return Write(std::move(owned), timeout_ms);
}

bool Http3Stream::Finish() {
    if (closed_) {
        error_ = "Stream is closed";
        return false;
    }

    if (finished_sending_) {
        return true;  // Already finished
    }

    if (write_reset_) {
        finished_sending_ = true;
        return true;  // Peer already stopped receiving request body
    }

    Http3AsyncClient* client = client_.load();
    if (!client || !client->StreamFinish(stream_id_, this)) {
        error_ = "Finish failed";
        return false;
    }

    finished_sending_ = true;
    return true;
}

int Http3Stream::GetStatus(uint32_t timeout_ms) {
    if (closed_) {
        error_ = "Stream is closed";
        return -1;
    }

    // Already have headers?
    if (headers_received_) {
        return status_;
    }

    // Use default timeout if 0
    if (timeout_ms == 0) {
        timeout_ms = default_timeout_ms_;
    }

    // Wait for headers or error
    EventBits_t bits = xEventGroupWaitBits(event_group_, EVENT_HEADERS_RECEIVED | EVENT_ERROR | EVENT_CLOSED,
                                           pdFALSE,  // Don't clear bits (other operations may need them)
                                           pdFALSE,  // Wait for any bit
                                           pdMS_TO_TICKS(timeout_ms));

    if (bits == 0) {
        error_ = "Timeout waiting for response headers";
        return -1;
    }

    if (bits & EVENT_CLOSED) {
        error_ = "Stream closed while waiting for headers";
        return -1;
    }

    if (bits & EVENT_ERROR) {
        // Error message already set by OnError
        return -1;
    }

    if (bits & EVENT_HEADERS_RECEIVED) {
        return status_;
    }

    error_ = "Unknown error waiting for headers";
    return -1;
}

Http3StreamStatusPollResult Http3Stream::TryGetStatus(int& status_out) {
    if (closed_ || has_error_) {
        return Http3StreamStatusPollResult::kError;
    }
    if (!headers_received_) {
        return Http3StreamStatusPollResult::kPending;
    }
    status_out = status_;
    return Http3StreamStatusPollResult::kReady;
}

Http3StreamReadPollResult Http3Stream::TryRead(uint8_t* buffer, size_t size, size_t& bytes_read_out) {
    bytes_read_out = 0;
    if (closed_ || has_error_ || buffer == nullptr || size == 0) {
        return Http3StreamReadPollResult::kError;
    }

    {
        std::lock_guard<std::mutex> lock(receive_mutex_);
        if (receive_count_ > 0) {
            bytes_read_out = std::min(size, receive_count_);
            const size_t first_chunk = std::min(bytes_read_out, receive_buffer_size_ - receive_head_);
            memcpy(buffer, receive_buffer_ + receive_head_, first_chunk);
            if (first_chunk < bytes_read_out) {
                memcpy(buffer + first_chunk, receive_buffer_, bytes_read_out - first_chunk);
            }
            receive_head_ = (receive_head_ + bytes_read_out) % receive_buffer_size_;
            receive_count_ -= bytes_read_out;
        } else if (finished_receiving_) {
            return Http3StreamReadPollResult::kFinished;
        }
    }

    if (bytes_read_out == 0) {
        return Http3StreamReadPollResult::kPending;
    }
    if (Http3AsyncClient* client = client_.load()) {
        client->StreamAcknowledgeData(stream_id_, bytes_read_out, this);
    }
    return Http3StreamReadPollResult::kData;
}

void Http3Stream::SetReadReadySink(Http3ReadySink sink, void* context) {
    if (sink == nullptr) {
        read_ready_sink_.store(nullptr, std::memory_order_release);
        read_ready_context_.store(nullptr, std::memory_order_release);
        return;
    }
    read_ready_context_.store(context, std::memory_order_release);
    read_ready_sink_.store(sink, std::memory_order_release);
}

void Http3Stream::NotifyReadReady() {
    Http3ReadySink sink = read_ready_sink_.load(std::memory_order_acquire);
    if (sink != nullptr) {
        sink(read_ready_context_.load(std::memory_order_acquire));
    }
}

void Http3Stream::Close() {
    if (closed_.exchange(true)) {
        return;  // Already closed
    }

    // Detachment may run concurrently on the event-loop task.
    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        if (event_group_) {
            xEventGroupSetBits(event_group_, EVENT_CLOSED);
        }
        NotifyReadReady();
    }

    // Tell client to close the QUIC stream
    // Only send RESET_STREAM if stream is not finished normally
    bool force_reset = !finished_receiving_;
    if (Http3AsyncClient* client = client_.load()) {
        client->StreamClose(stream_id_, this, force_reset);
    }

    // A detached stream still waits for InvalidateClient() to finish before
    // deleting the synchronization object that callback is using.
    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        if (event_group_) {
            vEventGroupDelete(event_group_);
            event_group_ = nullptr;
        }
    }

    power_lock_.reset();
}

void Http3Stream::OnHeaders(int status, const std::vector<std::pair<std::string, std::string>>& headers) {
    status_ = status;
    headers_.clear();
    headers_.reserve(headers.size());
    for (const auto& [name, value] : headers) {
        headers_.emplace_back(esp_http3::Http3String(name.data(), name.size()),
                              esp_http3::Http3String(value.data(), value.size()));
    }
    headers_received_ = true;

    if (event_group_) {
        xEventGroupSetBits(event_group_, EVENT_HEADERS_RECEIVED);
    }
    NotifyReadReady();
}

void Http3Stream::OnData(const uint8_t* data, size_t length, bool finished) {
    if (closed_) {
        return;
    }

    bool data_available = false;
    if (data && length > 0) {
        std::lock_guard<std::mutex> lock(receive_mutex_);

        // Calculate available space in ring buffer
        size_t space = receive_buffer_size_ - receive_count_;
        size_t bytes_to_copy = std::min(length, space);

        if (bytes_to_copy > 0) {
            // Copy to ring buffer using memcpy (handles wrap-around)
            size_t first_chunk = std::min(bytes_to_copy, receive_buffer_size_ - receive_tail_);
            memcpy(receive_buffer_ + receive_tail_, data, first_chunk);
            if (first_chunk < bytes_to_copy) {
                // Wrap around - copy remaining to start of buffer
                memcpy(receive_buffer_, data + first_chunk, bytes_to_copy - first_chunk);
            }
            receive_tail_ = (receive_tail_ + bytes_to_copy) % receive_buffer_size_;
            receive_count_ += bytes_to_copy;
            data_available = true;
        }

        if (bytes_to_copy < length) {
            ESP_LOGW(TAG,
                     "Stream %d: receive buffer full! dropped=%zu, buf_size=%zu, "
                     "used=%zu, space=%zu",
                     stream_id_, length - bytes_to_copy, receive_buffer_size_, receive_count_, space);
        }
    }

    if (finished) {
        finished_receiving_ = true;
        if (event_group_) {
            xEventGroupSetBits(event_group_, EVENT_FINISHED);
        }
    }

    // Notify waiting Read() only when there is data to consume. QUIC may
    // report empty non-FIN fragments; waking for those creates a busy loop.
    if (data_available && event_group_) {
        xEventGroupSetBits(event_group_, EVENT_DATA_AVAILABLE);
    }
    if (data_available || finished) {
        NotifyReadReady();
    }
}

void Http3Stream::OnError(const std::string& error_message) {
    error_ = error_message;
    has_error_ = true;

    if (event_group_) {
        xEventGroupSetBits(event_group_, EVENT_ERROR);
    }
    NotifyReadReady();
}

void Http3Stream::OnWriteReset(const std::string& error_message) {
    // Only affects writes, not reads - allows receiving server response
    write_error_ = error_message;
    write_reset_ = true;

    // Signal write operations to wake up and fail
    if (event_group_) {
        xEventGroupSetBits(event_group_,
                           EVENT_WRITE_COMPLETE);  // Wake up waiting writes
    }
}

void Http3Stream::InvalidateClient(const std::string& error_message) {
    std::lock_guard<std::mutex> lock(lifecycle_mutex_);
    // Clear client pointer to prevent use-after-free
    client_ = nullptr;

    // Mark as error state
    error_ = error_message;
    has_error_ = true;

    // Wake up any waiting operations
    if (event_group_) {
        xEventGroupSetBits(event_group_, EVENT_ERROR | EVENT_CLOSED);
    }
    NotifyReadReady();
}

// ============================================================================
// Http3AsyncClient Implementation
// ============================================================================

Http3AsyncClient::Http3AsyncClient(const Http3AsyncClientConfig& config)
    : config_(config), async_slots_(std::clamp<uint32_t>(config.max_concurrent_requests, uint32_t{1}, uint32_t{100})) {
    config_.max_concurrent_requests = static_cast<uint32_t>(async_slots_.size());
    ESP_LOGI(TAG, "Initializing HTTP/3 Client for %s:%u", config.hostname.c_str(), config.port);
    ESP_LOGI(TAG, "Dynamic buffers prefer %s", esp_http3::memory::UsesPsram() ? "PSRAM" : "internal RAM");

    // Create event group
    event_group_ = xEventGroupCreate();
    if (!event_group_) {
        ESP_LOGE(TAG, "Failed to create event group");
        return;
    }

    wake_event_fd_ = CreateWakeEventFd();
    if (wake_event_fd_ < 0) {
        ESP_LOGE(TAG, "Failed to create event-loop wake descriptor: errno=%d", errno);
        vEventGroupDelete(event_group_);
        event_group_ = nullptr;
        return;
    }

    udp_receive_buffer_ = static_cast<uint8_t*>(
        esp_http3::memory::Allocate(UDP_RECEIVE_BUFFER_SIZE, alignof(uint8_t)));
    if (!udp_receive_buffer_) {
        ESP_LOGE(TAG, "Failed to allocate UDP receive buffer");
        close(wake_event_fd_);
        wake_event_fd_ = -1;
        vEventGroupDelete(event_group_);
        event_group_ = nullptr;
        return;
    }

    initialized_ = true;
}

Http3AsyncClient::~Http3AsyncClient() {
    Stop();
    if (!initialized_) {
        return;
    }

    ESP_LOGI(TAG, "Deinitializing HTTP/3 Client");

    // Stop tasks
    StopBackgroundTasks();

    // Disconnect
    Disconnect();

    // Cleanup event group
    if (event_group_) {
        vEventGroupDelete(event_group_);
        event_group_ = nullptr;
    }

    if (wake_event_fd_ >= 0) {
        close(wake_event_fd_);
        wake_event_fd_ = -1;
    }

    if (udp_receive_buffer_) {
        esp_http3::memory::Deallocate(udp_receive_buffer_);
        udp_receive_buffer_ = nullptr;
    }

    // Cleanup write queues (data is automatically freed when cleared)
    {
        std::lock_guard<std::mutex> lock(write_queues_mutex_);
        write_queues_.clear();
    }

    // Invalidate all active streams before clearing to prevent use-after-free
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        for (auto& [stream_id, stream] : streams_) {
            if (stream) {
                stream->InvalidateClient();
            }
        }
        streams_.clear();
    }

    initialized_ = false;
    ESP_LOGI(TAG, "HTTP/3 Client deinitialized");
}

void Http3AsyncClient::SetPowerLockProvider(PowerLockProvider* provider) { power_lock_provider_ = provider; }

bool Http3AsyncClient::IsConnected() const {
    std::lock_guard<std::mutex> lock(connection_mutex_);
    return connected_;
}

std::string Http3AsyncClient::GetLastError() const {
    std::lock_guard<std::mutex> lock(error_mutex_);
    return last_error_;
}

// Helper method to set last error with thread safety
void Http3AsyncClient::SetLastError(const std::string& error) {
    std::lock_guard<std::mutex> lock(error_mutex_);
    last_error_ = error;
}

bool Http3AsyncClient::EnsureConnected(uint32_t timeout_ms) {
    if (IsConnected()) {
        return true;
    }

    // Use default timeout if 0
    if (timeout_ms == 0) {
        timeout_ms = config_.connect_timeout_ms;
    }

    // Power lock for connection establishment
    std::unique_ptr<ScopedPowerLock> connection_power_lock;
    if (power_lock_provider_) {
        connection_power_lock = std::make_unique<ScopedPowerLock>(power_lock_provider_, PowerSaveLevel::BALANCED);
    }

    std::unique_lock<std::mutex> lock(connection_mutex_);

    if (connected_) {
        return true;
    }

    // Cleanup stale connection if needed
    if (needs_cleanup_.load()) {
        ESP_LOGI(TAG, "Cleaning up stale connection...");
        lock.unlock();
        StopBackgroundTasks();
        lock.lock();

        connection_.reset();
        CloseSocket();
        needs_cleanup_.store(false);
        xEventGroupClearBits(event_group_, EVENT_CONNECTED | EVENT_DISCONNECTED);

        ESP_LOGI(TAG, "Stale connection cleanup completed");
    }

    ESP_LOGI(TAG, "Establishing QUIC connection...");
    SetLastError("");

    // Create socket
    if (udp_socket_ < 0) {
        if (!CreateSocket()) {
            return false;
        }
    }

    // Create QUIC configuration
    esp_http3::QuicConfig quic_config;
    quic_config.hostname = config_.hostname;
    quic_config.port = config_.port;
    quic_config.trusted_ca_der = config_.trusted_ca_der;
    quic_config.allow_unverified_peer = config_.allow_unverified_peer;
    quic_config.handshake_timeout_ms = config_.connect_timeout_ms;
    quic_config.idle_timeout_ms = config_.idle_timeout_ms;
    quic_config.response_timeout_ms = config_.request_timeout_ms;
    quic_config.enable_debug = config_.enable_debug;

    // Set flow control limits to match receive buffer size
    // This ensures QUIC layer won't receive more data than app layer can buffer
    // Use default if receive_buffer_size is 0 or too small
    size_t effective_buffer_size = config_.receive_buffer_size;
    if (effective_buffer_size < 16 * 1024) {
        effective_buffer_size = 64 * 1024;  // Default to 64KB
    }
    constexpr uint32_t kMaximumConcurrentStreams = 100;
    const uint32_t concurrent_streams =
        std::clamp<uint32_t>(config_.max_concurrent_requests, uint32_t{1}, kMaximumConcurrentStreams);
    quic_config.max_stream_data = static_cast<uint32_t>(effective_buffer_size);
    quic_config.max_data = static_cast<uint32_t>(effective_buffer_size * concurrent_streams);
    quic_config.max_streams_bidi = concurrent_streams;
    quic_config.max_streams_uni = concurrent_streams;
    quic_config.max_udp_payload_size = config_.max_udp_payload_size;

    // Pass cached keypair if available (speeds up reconnection by ~100ms)
    if (config_.cache_keypair && has_cached_keypair_) {
        quic_config.external_private_key = cached_private_key_;
        quic_config.external_public_key = cached_public_key_;
        ESP_LOGI(TAG, "Reusing cached X25519 keypair for faster reconnection");
    }

    // Pass cached session ticket if available (for PSK resumption)
    // Note: Session ticket can only be used ONCE (TLS 1.3 anti-replay)
    if (config_.cache_session_ticket && has_cached_session_ticket_) {
        // Copy all data - PSK must be copied (not pointer) to avoid lifetime issues
        quic_config.session_ticket = cached_session_ticket_.ticket;
        quic_config.psk = cached_session_ticket_.psk;  // Vector copy for safety
        quic_config.ticket_age_add = cached_session_ticket_.ticket_age_add;
        quic_config.ticket_received_time_ms = cached_session_ticket_.received_time_ms;
        quic_config.ticket_lifetime = cached_session_ticket_.ticket_lifetime;
        ESP_LOGI(TAG,
                 "Using cached session ticket for PSK resumption (one-time use, "
                 "lifetime=%lu s)",
                 (unsigned long)cached_session_ticket_.ticket_lifetime);

        // Clear the cached ticket after copying - it can only be used once
        // Server will send a new ticket after successful connection
        has_cached_session_ticket_ = false;
        cached_session_ticket_ = esp_http3::SessionTicketData{};
    }

    connection_.reset();

    // Create QUIC connection
    connection_ = std::make_unique<esp_http3::QuicConnection>(
        [this](const uint8_t* data, size_t length) -> int {
            if (udp_socket_ < 0) {
                return -1;
            }
            int sent = send(udp_socket_, data, length, 0);
            if (sent < 0 && udp_socket_ >= 0 && errno != EBADF) {
                ESP_LOGW(TAG, "Socket send failed: %d", errno);
            }
            return sent;
        },
        quic_config);

    // Set callbacks
    connection_->SetOnConnected([this]() { OnConnected(); });

    connection_->SetOnDisconnected([this](int code, const std::string& reason) { OnDisconnected(code, reason); });

    connection_->SetOnResponse(
        [this](int stream_id, const esp_http3::H3Response& response) { OnResponse(stream_id, response); });

    connection_->SetOnStreamData([this](int stream_id, const uint8_t* data, size_t length, bool finished) {
        OnStreamData(stream_id, data, length, finished);
    });

    connection_->SetOnStreamWritable([this](int stream_id) { OnStreamWritable(stream_id); });

    connection_->SetOnWritable([this]() {
        // Connection or congestion window opened, wake event loop to retry writes
        WakeEventLoop();
    });

    // Set up session ticket callback for caching
    // Note: Server may send multiple tickets, we always keep the latest one
    // because it has a longer remaining lifetime for session resumption
    if (config_.cache_session_ticket) {
        connection_->SetOnSessionTicket([this](const esp_http3::SessionTicketData& ticket) {
            // Always cache the latest session ticket (newer = longer lifetime)
            cached_session_ticket_ = ticket;
            has_cached_session_ticket_ = true;
            ESP_LOGI(TAG, "Cached session ticket: %zu bytes, 0-RTT=%s, lifetime=%lu s", ticket.ticket.size(),
                     ticket.supports_early_data ? "supported" : "not supported", (unsigned long)ticket.ticket_lifetime);
        });
    }

    // Set up stream reset callback - notify Http3Stream when peer resets stream
    connection_->SetOnStreamReset([this](int stream_id, uint64_t error_code) { OnStreamReset(stream_id, error_code); });

    // STOP_SENDING only means the peer will not consume more request body.
    // Response headers/body on the same stream may still carry useful details.
    connection_->SetOnStreamStopSending(
        [this](int stream_id, uint64_t error_code) { OnStreamStopSending(stream_id, error_code); });

    // Start background tasks
    if (!event_loop_task_) {
        if (!StartBackgroundTasks()) {
            SetLastError("Failed to start background tasks");
            ESP_LOGE(TAG, "Failed to start background tasks");
            connection_.reset();
            CloseSocket();
            return false;
        }
    }

    // Start handshake
    ESP_LOGI(TAG, "Starting QUIC handshake...");
    if (!connection_->StartHandshake()) {
        SetLastError("Failed to start QUIC handshake");
        ESP_LOGE(TAG, "Failed to start handshake");
        StopBackgroundTasks();
        connection_.reset();
        CloseSocket();
        return false;
    }
    WakeEventLoop();

    // Release lock before waiting
    lock.unlock();

    // Wait for connection
    EventBits_t bits = xEventGroupWaitBits(event_group_, EVENT_CONNECTED | EVENT_DISCONNECTED, pdTRUE, pdFALSE,
                                           pdMS_TO_TICKS(timeout_ms));

    if (bits & EVENT_CONNECTED) {
        ESP_LOGI(TAG, "QUIC connection established");

        // Cache keypair for future reconnections (if enabled and not already
        // cached)
        if (config_.cache_keypair && !has_cached_keypair_) {
            std::lock_guard<std::mutex> conn_lock(connection_mutex_);
            if (connection_ && connection_->GetPrivateKey(cached_private_key_) &&
                connection_->GetPublicKey(cached_public_key_)) {
                has_cached_keypair_ = true;
                ESP_LOGD(TAG, "Cached X25519 keypair for future reconnections");
            }
        }

        return true;
    }

    if (bits & EVENT_DISCONNECTED) {
        if (GetLastError().empty()) {
            SetLastError("QUIC connection failed");
        }
        ESP_LOGE(TAG, "Connection failed");
    } else {
        SetLastError("Connection timeout");
        ESP_LOGE(TAG, "Connection timeout");
    }

    // Cleanup on failure
    lock.lock();
    StopBackgroundTasks();
    connection_.reset();
    CloseSocket();
    return false;
}

void Http3AsyncClient::Disconnect() {
    std::lock_guard<std::mutex> lock(connection_mutex_);

    if (connection_) {
        ESP_LOGI(TAG, "Closing QUIC connection");
        connection_->Close(0, "Client disconnect");
        connection_.reset();
    }

    CloseSocket();
    connected_ = false;
}

// ==================== Stream API ====================

std::unique_ptr<Http3Stream> Http3AsyncClient::Open(const Http3Request& request) {
    // Hold the future stream lock before connection establishment. Otherwise
    // EnsureConnected() releases its handshake-only lock just before the
    // stream acquires a new one, briefly reporting the logical request as
    // idle and allowing a policy-managed uplink hand-off in that gap.
    std::unique_ptr<ScopedPowerLock> stream_power_lock;
    if (power_lock_provider_) {
        stream_power_lock = std::make_unique<ScopedPowerLock>(power_lock_provider_, PowerSaveLevel::BALANCED);
    }

    // Ensure connected
    if (!EnsureConnected()) {
        ESP_LOGE(TAG, "Failed to connect");
        return nullptr;
    }

    // Allocate before opening the transport stream. Registration below must
    // complete before the event loop can observe a response, and allocation
    // failure must not leave an unowned QUIC stream behind.
    auto stream = std::unique_ptr<Http3Stream>(new Http3Stream(nullptr, -1, config_.request_timeout_ms));
    if (!stream->Initialize(config_.receive_buffer_size)) {
        ESP_LOGE(TAG, "Failed to initialize stream");
        return nullptr;
    }
    int stream_id;

    // Open stream in QUIC connection
    {
        std::lock_guard<std::mutex> lock(connection_mutex_);

        if (!connection_ || !connected_) {
            ESP_LOGE(TAG, "Not connected");
            return nullptr;
        }

        auto headers = request.headers;

        if (request.streaming_upload) {
            // Streaming upload - open stream only (caller will send body and FIN
            // later)
            stream_id = connection_->OpenStream(request.method, request.path, headers);
        } else if (request.body == nullptr || request.body_size == 0) {
            // GET request or request without body - send headers with FIN
            stream_id = connection_->SendRequest(request.method, request.path, headers, nullptr,
                                                 0  // Empty body, SendRequest will send FIN
            );
        } else {
            // Request with body - send headers + body + FIN
            stream_id =
                connection_->SendRequest(request.method, request.path, headers, request.body, request.body_size);
        }

        if (stream_id < 0) {
            ESP_LOGE(TAG, "Failed to open stream");
            return nullptr;
        }

        stream->stream_id_ = stream_id;
        stream->client_ = this;
        stream->power_lock_ = std::move(stream_power_lock);
        // Keep connection_mutex_ until callbacks can find their owner.
        RegisterStream(stream_id, stream.get());
    }

    // Wake event loop to process
    WakeEventLoop();

    // Return stream immediately - caller should use GetStatus() to wait for
    // headers This allows the caller to cancel the stream before headers arrive
    ESP_LOGI(TAG, "Opened stream %d: %s %s%s", stream_id, request.method.c_str(), request.path.c_str(),
             request.streaming_upload ? " (streaming upload)" : "");

    return stream;
}

Http3AsyncClient::Statistics Http3AsyncClient::GetStatistics() const {
    Statistics statistics;

    std::lock_guard<std::mutex> lock(connection_mutex_);
    if (connection_) {
        auto quic_stats = connection_->GetStats();
        statistics.packets_sent = quic_stats.packets_sent;
        statistics.packets_received = quic_stats.packets_received;
        statistics.bytes_sent = quic_stats.bytes_sent;
        statistics.bytes_received = quic_stats.bytes_received;
        statistics.rtt_ms = quic_stats.rtt_ms;
    }

    {
        std::lock_guard<std::mutex> streams_lock(streams_mutex_);
        statistics.active_streams = streams_.size();
    }

    return statistics;
}

// ==================== Internal Stream Management ====================

void Http3AsyncClient::RegisterStream(int stream_id, Http3Stream* stream) {
    std::lock_guard<std::mutex> lock(streams_mutex_);
    streams_[stream_id] = stream;
}

bool Http3AsyncClient::IsRegisteredStream(int stream_id, const Http3Stream* stream) {
    std::lock_guard<std::mutex> lock(streams_mutex_);
    auto iterator = streams_.find(stream_id);
    return iterator != streams_.end() && iterator->second == stream;
}

bool Http3AsyncClient::StreamWrite(int stream_id, std::vector<uint8_t>&& data) {
    esp_http3::Http3Vector<uint8_t> owned(data.begin(), data.end());
    std::vector<uint8_t>().swap(data);
    return StreamWrite(stream_id, std::move(owned));
}

bool Http3AsyncClient::StreamWrite(int stream_id, esp_http3::Http3Vector<uint8_t>&& data) {
    return StreamWrite(stream_id, std::move(data), nullptr);
}

bool Http3AsyncClient::StreamWrite(int stream_id, esp_http3::Http3Vector<uint8_t>&& data,
                                 const Http3Stream* stream) {
    if (data.empty()) {
        return true;  // Nothing to write
    }

    // Validate the stream and enqueue atomically with respect to disconnect.
    // A delayed call from an old connection must not write to a reused ID.
    {
        std::lock_guard<std::mutex> conn_lock(connection_mutex_);
        if (!connection_ || !connected_ || (stream && !IsRegisteredStream(stream_id, stream))) {
            return false;
        }
        std::lock_guard<std::mutex> queue_lock(write_queues_mutex_);
        write_queues_[stream_id].emplace_back(std::move(data));
    }

    // Try to send immediately (will acquire locks in correct order)
    ProcessWriteQueue(stream_id);

    return true;
}

bool Http3AsyncClient::StreamFinish(int stream_id) {
    return StreamFinish(stream_id, nullptr);
}

bool Http3AsyncClient::StreamFinish(int stream_id, const Http3Stream* stream) {
    // Must acquire locks in same order as ProcessWriteQueue: connection first,
    // then queue
    std::lock_guard<std::mutex> conn_lock(connection_mutex_);
    if (!connection_ || !connected_ || (stream && !IsRegisteredStream(stream_id, stream))) {
        return false;
    }

    // Check if there's pending data in the write queue
    bool has_pending_data = false;
    {
        std::lock_guard<std::mutex> queue_lock(write_queues_mutex_);
        auto iterator = write_queues_.find(stream_id);
        if (iterator != write_queues_.end() && !iterator->second.empty()) {
            // Mark the last item to send FIN after it
            iterator->second.back().finish_after = true;
            has_pending_data = true;
        }
    }

    if (has_pending_data) {
        // Data still pending, FIN will be sent after all data is sent
        return true;
    }

    // No pending data, send FIN immediately
    if (!connection_) {
        return false;
    }

    bool result = connection_->FinishStream(stream_id);
    if (result) {
        WakeEventLoop();
    }
    return result;
}

void Http3AsyncClient::ProcessWriteQueue(int stream_id) {
    bool item_completed = false;
    const char* write_error = nullptr;

    // Lock order: connection_mutex_ first, then write_queues_mutex_
    {
        std::lock_guard<std::mutex> conn_lock(connection_mutex_);
        if (!connection_) {
            return;
        }

        std::unique_lock<std::mutex> queue_lock(write_queues_mutex_);
        auto iterator = write_queues_.find(stream_id);
        if (iterator == write_queues_.end() || iterator->second.empty()) {
            return;
        }

        auto& queue = iterator->second;

        while (!queue.empty()) {
            auto& item = queue.front();
            size_t remaining = item.data.size() - item.offset;

            if (remaining == 0) {
                // All data sent, check if we need to send FIN
                bool should_finish = item.finish_after;
                queue.pop_front();
                item_completed = true;

                if (should_finish) {
                    if (!connection_->FinishStream(stream_id)) {
                        write_error = "Failed to finish request body";
                        queue.clear();
                        break;
                    }
                    WakeEventLoop();
                }
                continue;
            }

            // Try to write
            ssize_t bytes_written = connection_->WriteStream(stream_id, item.data.data() + item.offset, remaining);

            if (bytes_written < 0) {
                ESP_LOGE(TAG, "WriteStream failed for stream %d", stream_id);
                write_error = "Failed to write request body";
                queue.clear();
                break;
            }

            if (bytes_written == 0) {
                // Flow control blocked, wait for writable event
                ESP_LOGD(TAG, "Stream %d flow control blocked, waiting", stream_id);
                break;
            }

            // Update offset
            item.offset += static_cast<size_t>(bytes_written);
            WakeEventLoop();  // Ensure packet gets sent

            if (item.offset < item.data.size()) {
                // Not all data sent, wait for more flow control
                break;
            }
            // Data fully sent, continue to process remaining == 0 case
        }

        // Clean up empty queue
        if (queue.empty()) {
            write_queues_.erase(iterator);
        }

        // Release the queue before callbacks, but retain the connection lock
        // so reconnect cannot deliver this result to a new owner of this ID.
        queue_lock.unlock();
        if (item_completed || write_error) {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            auto iterator = streams_.find(stream_id);
            if (iterator != streams_.end()) {
                if (write_error) {
                    iterator->second->OnError(write_error);
                } else if (iterator->second->event_group_) {
                    xEventGroupSetBits(iterator->second->event_group_, Http3Stream::EVENT_WRITE_COMPLETE);
                }
            }
        }
    }
}

void Http3AsyncClient::ProcessAllWriteQueues() {
    std::vector<int> stream_ids;

    // Get list of streams with pending data
    {
        std::lock_guard<std::mutex> lock(write_queues_mutex_);
        for (const auto& pair : write_queues_) {
            if (!pair.second.empty()) {
                stream_ids.push_back(pair.first);
            }
        }
    }

    // Process each stream
    for (int stream_id : stream_ids) {
        ProcessWriteQueue(stream_id);
    }
}

void Http3AsyncClient::OnStreamWritable(int stream_id) {
    ESP_LOGD(TAG, "Stream %d became writable", stream_id);

    // Wake event loop to process write queues
    WakeEventLoop();
}

void Http3AsyncClient::OnStreamReset(int stream_id, uint64_t error_code) {
    ESP_LOGW(TAG, "Stream %d reset by peer, error=%llu", stream_id, (unsigned long long)error_code);

    // RESET_STREAM terminates the entire stream - both reads and writes should
    // fail This is different from STOP_SENDING which only affects writes
    std::lock_guard<std::mutex> lock(streams_mutex_);
    auto iterator = streams_.find(stream_id);
    if (iterator != streams_.end()) {
        Http3Stream* stream = iterator->second;
        char error_msg[64];
        snprintf(error_msg, sizeof(error_msg), "Stream reset by peer (error=%llu)", (unsigned long long)error_code);
        // Call OnError to terminate both reads and writes
        stream->OnError(error_msg);
    }

    // Wake event loop to process
    WakeEventLoop();
}

void Http3AsyncClient::OnStreamStopSending(int stream_id, uint64_t error_code) {
    ESP_LOGW(TAG, "Stream %d stopped sending by peer, error=%llu", stream_id, (unsigned long long)error_code);

    std::lock_guard<std::mutex> lock(streams_mutex_);
    auto iterator = streams_.find(stream_id);
    if (iterator != streams_.end()) {
        Http3Stream* stream = iterator->second;
        char error_msg[80];
        snprintf(error_msg, sizeof(error_msg), "Server stopped receiving request body (error=%llu)",
                 (unsigned long long)error_code);
        stream->OnWriteReset(error_msg);
    }

    WakeEventLoop();
}

void Http3AsyncClient::StreamClose(int stream_id, const Http3Stream* stream, bool force_reset) {
    // Serialize with callbacks and reconnect before checking the instance.
    // QUIC stream IDs start over on each connection.
    std::lock_guard<std::mutex> conn_lock(connection_mutex_);
    {
        std::lock_guard<std::mutex> streams_lock(streams_mutex_);
        auto iterator = streams_.find(stream_id);
        if (iterator == streams_.end() || iterator->second != stream) {
            return;
        }
        streams_.erase(iterator);
    }

    // Clean up write queue for this stream (data is automatically freed when
    // queue is erased)
    {
        std::lock_guard<std::mutex> lock(write_queues_mutex_);
        write_queues_.erase(stream_id);
    }

    // Only reset if stream is not finished normally (e.g., user cancelled,
    // timeout) Normal stream completion doesn't need RESET_STREAM
    if (force_reset && !needs_cleanup_.load()) {
        if (connection_) {
            ESP_LOGD(TAG, "Force resetting stream %d", stream_id);
            connection_->ResetStream(stream_id);
            WakeEventLoop();
        }
    }
}

void Http3AsyncClient::StreamAcknowledgeData(int stream_id, size_t bytes, const Http3Stream* stream) {
    std::lock_guard<std::mutex> lock(connection_mutex_);
    if (connection_ && IsRegisteredStream(stream_id, stream)) {
        // Notify QUIC layer that bytes have been consumed
        // This will trigger MAX_STREAM_DATA if flow control window needs updating
        connection_->AcknowledgeStreamData(stream_id, bytes);
    }
    WakeEventLoop();
}

// ==================== Network Operations ====================

bool Http3AsyncClient::CreateSocket() {
    ESP_LOGD(TAG, "Creating UDP socket for %s:%u", config_.hostname.c_str(), config_.port);

    // DNS lookup
    struct hostent* host_entry = gethostbyname(config_.hostname.c_str());
    if (!host_entry) {
        SetLastError("DNS lookup failed for " + config_.hostname);
        ESP_LOGE(TAG, "DNS lookup failed for %s", config_.hostname.c_str());
        return false;
    }

    struct in_addr* address = reinterpret_cast<struct in_addr*>(host_entry->h_addr);
    char ip_string[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, address, ip_string, sizeof(ip_string));
    ESP_LOGI(TAG, "Resolved %s to %s", config_.hostname.c_str(), ip_string);

    // Create UDP socket
    udp_socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket_ < 0) {
        SetLastError("Failed to create UDP socket");
        ESP_LOGE(TAG, "Failed to create socket: %d", errno);
        return false;
    }

    // Connect to server
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(config_.port);
    server_address.sin_addr = *address;

    if (connect(udp_socket_, reinterpret_cast<struct sockaddr*>(&server_address), sizeof(server_address)) < 0) {
        SetLastError("Failed to connect UDP socket to " + config_.hostname);
        ESP_LOGE(TAG, "Failed to connect socket: %d", errno);
        close(udp_socket_);
        udp_socket_ = -1;
        return false;
    }

    return true;
}

void Http3AsyncClient::CloseSocket() {
    if (udp_socket_ >= 0) {
        close(udp_socket_);
        udp_socket_ = -1;
        ESP_LOGD(TAG, "UDP socket closed");
    }
}

bool Http3AsyncClient::StartBackgroundTasks() {
    if (event_loop_task_) {
        return true;
    }

    stop_tasks_.store(false);
    xEventGroupClearBits(event_group_, EVENT_EVENT_LOOP_STOPPED);

    // This single task owns socket receive and all QUIC state transitions.
    BaseType_t result = xTaskCreate(EventLoopTaskEntry, "http3_event_loop", 6144, this, 6, &event_loop_task_);

    if (result != pdPASS) {
        ESP_LOGE(TAG, "Failed to create event loop task");
        return false;
    }

    return true;
}

void Http3AsyncClient::StopBackgroundTasks() {
    if (!event_loop_task_) {
        return;
    }

    ESP_LOGI(TAG, "Stopping background tasks");
    stop_tasks_.store(true);
    WakeEventLoop();

    TaskHandle_t task = event_loop_task_;
    const EventBits_t bits =
        xEventGroupWaitBits(event_group_, EVENT_EVENT_LOOP_STOPPED, pdTRUE, pdFALSE, pdMS_TO_TICKS(1000));
    if ((bits & EVENT_EVENT_LOOP_STOPPED) == 0 && task != nullptr) {
        ESP_LOGW(TAG, "Event loop task did not finish, deleting");
        vTaskDelete(task);
    }
    event_loop_task_ = nullptr;
}

void Http3AsyncClient::EventLoopTaskEntry(void* parameter) {
    Http3AsyncClient* self = static_cast<Http3AsyncClient*>(parameter);
    self->RunEventLoop();
    xEventGroupSetBits(self->event_group_, EVENT_EVENT_LOOP_STOPPED);
    vTaskDelete(nullptr);
}

void Http3AsyncClient::RunEventLoop() {
    ESP_LOGD(TAG, "Event loop started");

    static constexpr uint32_t DEFAULT_WAIT_MS = 60000;
    static constexpr uint32_t MIN_WAIT_MS = 1;

    uint32_t next_timer_ms = DEFAULT_WAIT_MS;
    int64_t last_tick_time = esp_timer_get_time() / 1000;

    while (!stop_tasks_.load()) {
        // Process pending write queues (may have been woken by OnStreamWritable)
        ProcessAllWriteQueues();

        // Scheduled requests advance only when this event loop is already
        // awake for a submission, cancellation, UDP packet, or QUIC timer.
        AdvanceAsyncRequests();

        // Calculate elapsed time
        int64_t current_time = esp_timer_get_time() / 1000;
        uint32_t elapsed_ms = static_cast<uint32_t>(current_time - last_tick_time);
        last_tick_time = current_time;
        next_timer_ms = DEFAULT_WAIT_MS;

        // Timer tick
        {
            std::lock_guard<std::mutex> lock(connection_mutex_);
            if (connection_ && !needs_cleanup_.load()) {
                next_timer_ms = connection_->OnTimerTick(elapsed_ms);
            }
        }

        next_timer_ms = LimitWaitToAsyncDeadline(next_timer_ms);

        // Wait for events
        if (next_timer_ms < MIN_WAIT_MS) {
            next_timer_ms = MIN_WAIT_MS;
        } else if (next_timer_ms > DEFAULT_WAIT_MS) {
            next_timer_ms = DEFAULT_WAIT_MS;
        }

        if (config_.enable_debug) {
            ESP_LOGI(TAG, "Waiting %u ms...", (unsigned)next_timer_ms);
        }

        if (stop_tasks_.load() || udp_socket_ < 0) {
            break;
        }

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(udp_socket_, &read_fds);
        FD_SET(wake_event_fd_, &read_fds);

        struct timeval timeout = {
            .tv_sec = static_cast<time_t>(next_timer_ms / 1000),
            .tv_usec = static_cast<suseconds_t>((next_timer_ms % 1000) * 1000),
        };
        const int max_fd = std::max(udp_socket_, wake_event_fd_);
        const int select_result = select(max_fd + 1, &read_fds, nullptr, nullptr, &timeout);

        if (select_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (!stop_tasks_.load()) {
                const int select_error = errno;
                ESP_LOGE(TAG, "Event-loop select failed: errno=%d", select_error);
                std::lock_guard<std::mutex> lock(connection_mutex_);
                OnDisconnected(select_error, "HTTP/3 event-loop select failed");
            }
            break;
        }

        if (FD_ISSET(wake_event_fd_, &read_fds)) {
            uint64_t wake_count = 0;
            if (read(wake_event_fd_, &wake_count, sizeof(wake_count)) < 0 && errno != EINTR) {
                ESP_LOGW(TAG, "Failed to drain event-loop wake descriptor: errno=%d", errno);
            }
        }

        if (!FD_ISSET(udp_socket_, &read_fds)) {
            continue;
        }

        for (size_t packet_count = 0; packet_count < UDP_RECEIVE_BUDGET; ++packet_count) {
            const int received_length =
                recv(udp_socket_, udp_receive_buffer_, UDP_RECEIVE_BUFFER_SIZE, MSG_DONTWAIT);
            if (received_length > 0) {
                std::lock_guard<std::mutex> lock(connection_mutex_);
                if (connection_) {
                    connection_->ProcessReceivedData(udp_receive_buffer_, static_cast<size_t>(received_length));
                }
                if (stop_tasks_.load()) {
                    break;
                }
                continue;
            }
            if (received_length < 0 && errno != EAGAIN && errno != EWOULDBLOCK && !stop_tasks_.load()) {
                const int receive_error = errno;
                ESP_LOGE(TAG, "UDP receive failed: errno=%d", receive_error);
                std::lock_guard<std::mutex> lock(connection_mutex_);
                OnDisconnected(receive_error, "HTTP/3 UDP receive failed");
            }
            break;
        }
    }

    // A transport shutdown may race with Stop(). Acknowledge the asynchronous
    // state-machine stop only after this task can no longer access its slots.
    if (needs_cleanup_.load()) {
        const std::string error = GetLastError();
        FailAsyncRequests(Http3AsyncOutcome::kTransportError,
                          error.empty() ? "HTTP/3 transport disconnected" : error.c_str());
    } else {
        AdvanceAsyncRequests();
    }
    xEventGroupSetBits(event_group_, EVENT_ASYNC_STOPPED);
    ESP_LOGD(TAG, "Event loop stopped");
}

void Http3AsyncClient::WakeEventLoop() {
    if (wake_event_fd_ >= 0) {
        const uint64_t wake_count = 1;
        if (write(wake_event_fd_, &wake_count, sizeof(wake_count)) < 0 && errno != EBADF) {
            ESP_LOGW(TAG, "Failed to wake event loop: errno=%d", errno);
        }
    }
}

// ==================== QUIC Callbacks ====================

void Http3AsyncClient::OnConnected() {
    connected_ = true;
    xEventGroupSetBits(event_group_, EVENT_CONNECTED);
}

void Http3AsyncClient::OnDisconnected(int error_code, const std::string& reason) {
    ESP_LOGW(TAG, "QUIC disconnected: code=%d, reason=%s", error_code, reason.c_str());
    connected_ = false;
    SetLastError(reason);
    xEventGroupSetBits(event_group_, EVENT_DISCONNECTED);

    // All callers hold connection_mutex_. Retire stream ownership and queued
    // writes before a new connection can reuse these stream IDs.
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        for (auto& [stream_id, stream] : streams_) {
            if (stream) {
                stream->InvalidateClient(reason);
            }
        }
        streams_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(write_queues_mutex_);
        write_queues_.clear();
    }

    // Mark for cleanup
    // Start() must perform a real restart after this point; leaving this true
    // would accept submissions even though the transport task is exiting.
    async_started_.store(false);
    needs_cleanup_.store(true);
    CloseSocket();
    stop_tasks_.store(true);
    WakeEventLoop();
}

void Http3AsyncClient::OnResponse(int stream_id, const esp_http3::H3Response& response) {
    ESP_LOGD(TAG, "Response on stream %d: status=%d", stream_id, response.status);

    std::lock_guard<std::mutex> lock(streams_mutex_);
    auto iterator = streams_.find(stream_id);
    if (iterator != streams_.end()) {
        Http3Stream* stream = iterator->second;
        stream->OnHeaders(response.status, response.headers);
    }
}

void Http3AsyncClient::OnStreamData(int stream_id, const uint8_t* data, size_t length, bool finished) {
    std::lock_guard<std::mutex> lock(streams_mutex_);
    auto iterator = streams_.find(stream_id);
    if (iterator != streams_.end()) {
        Http3Stream* stream = iterator->second;
        stream->OnData(data, length, finished);
    }
}
