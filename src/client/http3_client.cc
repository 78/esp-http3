/*
 * HTTP/3 Client Implementation
 * 
 * Provides synchronous blocking API for HTTP/3 requests.
 */

#include "client/http3_client.h"
#include <esp_log.h>
#include <esp_timer.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <algorithm>
#include <cctype>

#define TAG "Http3Client"

// ============================================================================
// Http3Stream Implementation
// ============================================================================

Http3Stream::Http3Stream(Http3Client* client, int stream_id, uint32_t default_timeout_ms)
    : client_(client)
    , stream_id_(stream_id)
    , default_timeout_ms_(default_timeout_ms) {
}

Http3Stream::~Http3Stream() {
    Close();
    
    // Free PSRAM buffer
    if (receive_buffer_) {
        heap_caps_free(receive_buffer_);
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
    
    // Allocate receive buffer in PSRAM
    receive_buffer_ = static_cast<uint8_t*>(
        heap_caps_malloc(receive_buffer_size, MALLOC_CAP_SPIRAM));
    if (!receive_buffer_) {
        ESP_LOGE(TAG, "Failed to allocate receive buffer in PSRAM for stream %d", stream_id_);
        vEventGroupDelete(event_group_);
        event_group_ = nullptr;
        return false;
    }
    receive_buffer_size_ = receive_buffer_size;
    
    return true;
}

bool Http3Stream::IsValid() const {
    return !closed_ && !has_error_ && client_ != nullptr;
}

std::string Http3Stream::GetHeader(const std::string& name) const {
    // Case-insensitive header lookup without temporary string allocations
    for (const auto& header : headers_) {
        if (header.first.size() == name.size() &&
            std::equal(header.first.begin(), header.first.end(), name.begin(),
                       [](char a, char b) {
                           return std::tolower(static_cast<unsigned char>(a)) ==
                                  std::tolower(static_cast<unsigned char>(b));
                       })) {
            return header.second;
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
            if (client_) {
                client_->StreamAcknowledgeData(stream_id_, bytes_to_read);
            }
            return static_cast<int>(bytes_to_read);
        }
        
        // Wait for data, finish, or error
        EventBits_t bits = xEventGroupWaitBits(
            event_group_,
            EVENT_DATA_AVAILABLE | EVENT_FINISHED | EVENT_ERROR | EVENT_CLOSED,
            pdTRUE,   // Clear bits on exit
            pdFALSE,  // Wait for any bit
            pdMS_TO_TICKS(timeout_ms)
        );
        
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
    if (closed_) {
        error_ = "Stream is closed";
        return -1;
    }
    
    if (finished_sending_) {
        error_ = "Stream already finished sending";
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
    if (!client_ || !client_->StreamWrite(stream_id_, std::move(data))) {
        error_ = "Write failed";
        return -1;
    }
    
    // Wait for write to complete (or timeout)
    EventBits_t bits = xEventGroupWaitBits(
        event_group_,
        EVENT_WRITE_COMPLETE | EVENT_ERROR | EVENT_CLOSED,
        pdTRUE,
        pdFALSE,
        pdMS_TO_TICKS(timeout_ms)
    );
    
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
    
    return static_cast<int>(size);
}

int Http3Stream::Write(const uint8_t* data, size_t size, uint32_t timeout_ms) {
    if (!data || size == 0) {
        return 0;
    }
    // Copy data and delegate to move version
    std::vector<uint8_t> owned(data, data + size);
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
    
    if (!client_ || !client_->StreamFinish(stream_id_)) {
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
    EventBits_t bits = xEventGroupWaitBits(
        event_group_,
        EVENT_HEADERS_RECEIVED | EVENT_ERROR | EVENT_CLOSED,
        pdFALSE,  // Don't clear bits (other operations may need them)
        pdFALSE,  // Wait for any bit
        pdMS_TO_TICKS(timeout_ms)
    );
    
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

void Http3Stream::Close() {
    if (closed_.exchange(true)) {
        return;  // Already closed
    }
    
    // Notify waiting operations
    if (event_group_) {
        xEventGroupSetBits(event_group_, EVENT_CLOSED);
    }
    
    // Tell client to close the QUIC stream
    // Only send RESET_STREAM if stream is not finished normally
    bool force_reset = !finished_receiving_;
    if (client_) {
        client_->StreamClose(stream_id_, force_reset);
    }
    
    // Cleanup
    if (event_group_) {
        vEventGroupDelete(event_group_);
        event_group_ = nullptr;
    }
    
    power_lock_.reset();
}

void Http3Stream::OnHeaders(int status, 
                            const std::vector<std::pair<std::string, std::string>>& headers) {
    status_ = status;
    headers_ = headers;
    headers_received_ = true;
    
    if (event_group_) {
        xEventGroupSetBits(event_group_, EVENT_HEADERS_RECEIVED);
    }
}

void Http3Stream::OnData(const uint8_t* data, size_t length, bool finished) {
    if (closed_) {
        return;
    }
    
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
        }
        
        if (bytes_to_copy < length) {
            ESP_LOGW(TAG, "Stream %d: receive buffer full! dropped=%zu, buf_size=%zu, used=%zu, space=%zu", 
                     stream_id_, length - bytes_to_copy,
                     receive_buffer_size_, receive_count_, space);
        }
    }
    
    if (finished) {
        finished_receiving_ = true;
        if (event_group_) {
            xEventGroupSetBits(event_group_, EVENT_FINISHED);
        }
    }
    
    // Notify waiting Read()
    if (event_group_) {
        xEventGroupSetBits(event_group_, EVENT_DATA_AVAILABLE);
    }
}

void Http3Stream::OnError(const std::string& error_message) {
    error_ = error_message;
    has_error_ = true;
    
    if (event_group_) {
        xEventGroupSetBits(event_group_, EVENT_ERROR);
    }
}

// ============================================================================
// Http3Client Implementation
// ============================================================================

Http3Client::Http3Client(const Http3ClientConfig& config)
    : config_(config) {
    ESP_LOGI(TAG, "Initializing HTTP/3 Client for %s:%u", 
             config.hostname.c_str(), config.port);
    
    // Create event group
    event_group_ = xEventGroupCreate();
    if (!event_group_) {
        ESP_LOGE(TAG, "Failed to create event group");
        return;
    }
    
    // Create UDP packet queue
    udp_queue_ = xQueueCreate(UDP_QUEUE_SIZE, sizeof(UdpPacket*));
    if (!udp_queue_) {
        ESP_LOGE(TAG, "Failed to create UDP queue");
        vEventGroupDelete(event_group_);
        event_group_ = nullptr;
        return;
    }
    
    initialized_ = true;
}

Http3Client::~Http3Client() {
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
    
    // Cleanup UDP queue
    if (udp_queue_) {
        vQueueDelete(udp_queue_);
        udp_queue_ = nullptr;
    }
    
    // Cleanup write queues (data is automatically freed when cleared)
    {
        std::lock_guard<std::mutex> lock(write_queues_mutex_);
        write_queues_.clear();
    }
    
    // Cleanup any remaining streams
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        streams_.clear();
    }
    
    initialized_ = false;
    ESP_LOGI(TAG, "HTTP/3 Client deinitialized");
}

void Http3Client::SetPowerLockProvider(PowerLockProvider* provider) {
    power_lock_provider_ = provider;
}

bool Http3Client::IsConnected() const {
    std::lock_guard<std::mutex> lock(connection_mutex_);
    return connected_;
}

std::string Http3Client::GetLastError() const {
    std::lock_guard<std::mutex> lock(error_mutex_);
    return last_error_;
}

// Helper method to set last error with thread safety
void Http3Client::SetLastError(const std::string& error) {
    std::lock_guard<std::mutex> lock(error_mutex_);
    last_error_ = error;
}

bool Http3Client::EnsureConnected(uint32_t timeout_ms) {
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
    quic_config.max_stream_data = static_cast<uint32_t>(effective_buffer_size);
    quic_config.max_data = static_cast<uint32_t>(effective_buffer_size * 4);  // Allow 4 concurrent streams
    
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
        ESP_LOGI(TAG, "Using cached session ticket for PSK resumption (one-time use, lifetime=%lu s)",
                 (unsigned long)cached_session_ticket_.ticket_lifetime);
        
        // Clear the cached ticket after copying - it can only be used once
        // Server will send a new ticket after successful connection
        has_cached_session_ticket_ = false;
        cached_session_ticket_ = esp_http3::SessionTicketData{};
    }
    
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
        quic_config
    );
    
    // Set callbacks
    connection_->SetOnConnected([this]() {
        OnConnected();
    });
    
    connection_->SetOnDisconnected([this](int code, const std::string& reason) {
        OnDisconnected(code, reason);
    });
    
    connection_->SetOnResponse([this](int stream_id, const esp_http3::H3Response& response) {
        OnResponse(stream_id, response);
    });
    
    connection_->SetOnStreamData([this](int stream_id, const uint8_t* data, size_t length, bool finished) {
        OnStreamData(stream_id, data, length, finished);
    });
    
    connection_->SetOnStreamWritable([this](int stream_id) {
        OnStreamWritable(stream_id);
    });
    
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
            ESP_LOGI(TAG, "Cached session ticket: %zu bytes, 0-RTT=%s, lifetime=%lu s",
                     ticket.ticket.size(),
                     ticket.supports_early_data ? "supported" : "not supported",
                     (unsigned long)ticket.ticket_lifetime);
        });
    }
    
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
    
    // Release lock before waiting
    lock.unlock();
    
    // Wait for connection
    EventBits_t bits = xEventGroupWaitBits(
        event_group_,
        EVENT_CONNECTED | EVENT_DISCONNECTED,
        pdTRUE,
        pdFALSE,
        pdMS_TO_TICKS(timeout_ms)
    );
    
    if (bits & EVENT_CONNECTED) {
        ESP_LOGI(TAG, "QUIC connection established");
        
        // Cache keypair for future reconnections (if enabled and not already cached)
        if (config_.cache_keypair && !has_cached_keypair_) {
            std::lock_guard<std::mutex> conn_lock(connection_mutex_);
            if (connection_ && 
                connection_->GetPrivateKey(cached_private_key_) &&
                connection_->GetPublicKey(cached_public_key_)) {
                has_cached_keypair_ = true;
                ESP_LOGD(TAG, "Cached X25519 keypair for future reconnections");
            }
        }
        
        return true;
    }
    
    if (bits & EVENT_DISCONNECTED) {
        SetLastError("QUIC connection failed");
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

void Http3Client::Disconnect() {
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

std::unique_ptr<Http3Stream> Http3Client::Open(const Http3Request& request, 
                                                  uint32_t timeout_ms) {
    // Use default timeout if 0
    if (timeout_ms == 0) {
        timeout_ms = config_.request_timeout_ms;
    }
    
    // Ensure connected
    if (!EnsureConnected()) {
        ESP_LOGE(TAG, "Failed to connect");
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
            // Streaming upload - open stream only (caller will send body and FIN later)
            stream_id = connection_->OpenStream(request.method, request.path, headers);
        } else if (request.body == nullptr || request.body_size == 0) {
            // GET request or request without body - send headers with FIN
            stream_id = connection_->SendRequest(
                request.method, request.path, headers,
                nullptr, 0  // Empty body, SendRequest will send FIN
            );
        } else {
            // Request with body - send headers + body + FIN
            stream_id = connection_->SendRequest(
                request.method, request.path, headers,
                request.body, request.body_size
            );
        }
        
        if (stream_id < 0) {
            ESP_LOGE(TAG, "Failed to open stream");
            return nullptr;
        }
    }
    
    // Create stream object with default timeout from config
    auto stream = std::unique_ptr<Http3Stream>(new Http3Stream(this, stream_id, config_.request_timeout_ms));
    if (!stream->Initialize(config_.receive_buffer_size)) {
        ESP_LOGE(TAG, "Failed to initialize stream");
        return nullptr;
    }
    
    // Create power lock for the stream
    if (power_lock_provider_) {
        stream->power_lock_ = std::make_unique<ScopedPowerLock>(power_lock_provider_, PowerSaveLevel::BALANCED);
    }
    
    // Register stream
    RegisterStream(stream_id, stream.get());
    
    // Wake event loop to process
    WakeEventLoop();
    
    // For non-streaming requests, wait for headers
    if (!request.streaming_upload) {
        EventBits_t bits = xEventGroupWaitBits(
            stream->event_group_,
            Http3Stream::EVENT_HEADERS_RECEIVED | Http3Stream::EVENT_ERROR | Http3Stream::EVENT_CLOSED,
            pdFALSE,  // Don't clear - let Read() see the state
            pdFALSE,
            pdMS_TO_TICKS(timeout_ms)
        );
        
        if (bits == 0) {
            ESP_LOGE(TAG, "Timeout waiting for headers");
            stream->error_ = "Timeout waiting for headers";
            stream->Close();
            return nullptr;
        }
        
        if (bits & (Http3Stream::EVENT_ERROR | Http3Stream::EVENT_CLOSED)) {
            ESP_LOGE(TAG, "Error waiting for headers: %s", stream->error_.c_str());
            return nullptr;
        }
    }
    
    // For streaming upload, don't call GetStatus() as it would block waiting for headers
    if (request.streaming_upload) {
        ESP_LOGI(TAG, "Opened stream %d: %s %s (streaming upload)", 
                 stream_id, request.method.c_str(), request.path.c_str());
    } else {
        ESP_LOGI(TAG, "Opened stream %d: %s %s -> status=%d", 
                 stream_id, request.method.c_str(), request.path.c_str(), stream->GetStatus());
    }
    
    return stream;
}

bool Http3Client::Get(const std::string& path, Http3Response& response, uint32_t timeout_ms) {
    // Use default timeout if 0
    if (timeout_ms == 0) {
        timeout_ms = config_.request_timeout_ms;
    }
    
    Http3Request request;
    request.method = "GET";
    request.path = path;
    
    auto stream = Open(request, timeout_ms);
    if (!stream) {
        response.error = "Failed to open stream";
        return false;
    }
    
    response.status = stream->GetStatus();
    response.headers = stream->GetHeaders();
    
    // Read entire response body
    std::vector<uint8_t> buffer(512);
    while (true) {
        int bytes_read = stream->Read(buffer.data(), buffer.size(), timeout_ms);
        if (bytes_read < 0) {
            response.error = stream->GetError();
            return false;
        }
        if (bytes_read == 0) {
            break;
        }
        response.body.append(reinterpret_cast<char*>(buffer.data()), bytes_read);
    }
    
    response.complete = true;
    return response.status >= 200 && response.status < 300;
}

bool Http3Client::Post(const std::string& path,
                        const std::vector<std::pair<std::string, std::string>>& headers,
                        const uint8_t* body, size_t body_size,
                        Http3Response& response,
                        uint32_t timeout_ms) {
    // Use default timeout if 0
    if (timeout_ms == 0) {
        timeout_ms = config_.request_timeout_ms;
    }
    
    Http3Request request;
    request.method = "POST";
    request.path = path;
    request.headers = headers;
    request.body = body;
    request.body_size = body_size;
    
    auto stream = Open(request, timeout_ms);
    if (!stream) {
        response.error = "Failed to open stream";
        return false;
    }
    
    response.status = stream->GetStatus();
    response.headers = stream->GetHeaders();
    
    // Read entire response body
    std::vector<uint8_t> buffer(512);
    while (true) {
        int bytes_read = stream->Read(buffer.data(), buffer.size(), timeout_ms);
        if (bytes_read < 0) {
            response.error = stream->GetError();
            return false;
        }
        if (bytes_read == 0) {
            break;
        }
        response.body.append(reinterpret_cast<char*>(buffer.data()), bytes_read);
    }
    
    response.complete = true;
    return response.status >= 200 && response.status < 300;
}

Http3Client::Statistics Http3Client::GetStatistics() const {
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

void Http3Client::RegisterStream(int stream_id, Http3Stream* stream) {
    std::lock_guard<std::mutex> lock(streams_mutex_);
    streams_[stream_id] = stream;
}

void Http3Client::UnregisterStream(int stream_id) {
    std::lock_guard<std::mutex> lock(streams_mutex_);
    streams_.erase(stream_id);
}

Http3Stream* Http3Client::GetStream(int stream_id) {
    std::lock_guard<std::mutex> lock(streams_mutex_);
    auto iterator = streams_.find(stream_id);
    return iterator != streams_.end() ? iterator->second : nullptr;
}

bool Http3Client::StreamWrite(int stream_id, std::vector<uint8_t>&& data) {
    if (data.empty()) {
        return true;  // Nothing to write
    }
    
    // Add to write queue (takes ownership, must not hold this lock when calling ProcessWriteQueue)
    {
        std::lock_guard<std::mutex> lock(write_queues_mutex_);
        write_queues_[stream_id].emplace_back(std::move(data));
    }
    
    // Try to send immediately (will acquire locks in correct order)
    ProcessWriteQueue(stream_id);
    
    return true;
}

bool Http3Client::StreamFinish(int stream_id) {
    // Must acquire locks in same order as ProcessWriteQueue: connection first, then queue
    std::lock_guard<std::mutex> conn_lock(connection_mutex_);
    
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

void Http3Client::ProcessWriteQueue(int stream_id) {
    bool item_completed = false;
    
    // Lock order: connection_mutex_ first, then write_queues_mutex_
    {
        std::lock_guard<std::mutex> conn_lock(connection_mutex_);
        if (!connection_) {
            return;
        }
        
        std::lock_guard<std::mutex> queue_lock(write_queues_mutex_);
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
                    connection_->FinishStream(stream_id);
                    WakeEventLoop();
                }
                continue;
            }
            
            // Try to write
            ssize_t bytes_written = connection_->WriteStream(
                stream_id, 
                item.data.data() + item.offset, 
                remaining
            );
            
            if (bytes_written < 0) {
                // Error - discard this item
                ESP_LOGE(TAG, "WriteStream failed for stream %d", stream_id);
                queue.pop_front();
                item_completed = true;
                continue;
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
    }
    
    // Notify stream that write completed (after releasing all locks to avoid deadlock)
    if (item_completed) {
        Http3Stream* stream = GetStream(stream_id);
        if (stream && stream->event_group_) {
            xEventGroupSetBits(stream->event_group_, Http3Stream::EVENT_WRITE_COMPLETE);
        }
    }
}

void Http3Client::ProcessAllWriteQueues() {
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

void Http3Client::OnStreamWritable(int stream_id) {
    ESP_LOGD(TAG, "Stream %d became writable", stream_id);
    
    // Wake event loop to process write queues
    WakeEventLoop();
}

void Http3Client::StreamClose(int stream_id, bool force_reset) {
    // Unregister first
    UnregisterStream(stream_id);
    
    // Clean up write queue for this stream (data is automatically freed when queue is erased)
    {
        std::lock_guard<std::mutex> lock(write_queues_mutex_);
        write_queues_.erase(stream_id);
    }
    
    // Only reset if stream is not finished normally (e.g., user cancelled, timeout)
    // Normal stream completion doesn't need RESET_STREAM
    if (force_reset) {
        std::lock_guard<std::mutex> lock(connection_mutex_);
        if (connection_) {
            ESP_LOGD(TAG, "Force resetting stream %d", stream_id);
            connection_->ResetStream(stream_id);
            WakeEventLoop();
        }
    }
}

void Http3Client::StreamAcknowledgeData(int stream_id, size_t bytes) {
    std::lock_guard<std::mutex> lock(connection_mutex_);
    if (connection_) {
        // Notify QUIC layer that bytes have been consumed
        // This will trigger MAX_STREAM_DATA if flow control window needs updating
        connection_->AcknowledgeStreamData(stream_id, bytes);
    }
    WakeEventLoop();
}

// ==================== Network Operations ====================

bool Http3Client::CreateSocket() {
    ESP_LOGD(TAG, "Creating UDP socket for %s:%u", 
             config_.hostname.c_str(), config_.port);
    
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
    
    if (connect(udp_socket_, reinterpret_cast<struct sockaddr*>(&server_address), 
                sizeof(server_address)) < 0) {
        SetLastError("Failed to connect UDP socket to " + config_.hostname);
        ESP_LOGE(TAG, "Failed to connect socket: %d", errno);
        close(udp_socket_);
        udp_socket_ = -1;
        return false;
    }
    
    return true;
}

void Http3Client::CloseSocket() {
    if (udp_socket_ >= 0) {
        close(udp_socket_);
        udp_socket_ = -1;
        ESP_LOGD(TAG, "UDP socket closed");
    }
}

bool Http3Client::StartBackgroundTasks() {
    if (event_loop_task_) {
        return true;
    }
    
    stop_tasks_.store(false);
    xEventGroupClearBits(event_group_, EVENT_STOP);
    
    // Create UDP receive task
    BaseType_t result = xTaskCreate(
        UdpReceiveTaskEntry,
        "http3_udp_recv",
        2048,
        this,
        6,
        &udp_receive_task_
    );
    
    if (result != pdPASS) {
        ESP_LOGE(TAG, "Failed to create UDP receive task");
        return false;
    }
    
    // Create event loop task
    result = xTaskCreate(
        EventLoopTaskEntry,
        "http3_event_loop",
        6144,
        this,
        5,
        &event_loop_task_
    );
    
    if (result != pdPASS) {
        ESP_LOGE(TAG, "Failed to create event loop task");
        stop_tasks_ = true;
        xEventGroupSetBits(event_group_, EVENT_STOP);
        vTaskDelay(pdMS_TO_TICKS(100));
        if (udp_receive_task_) {
            vTaskDelete(udp_receive_task_);
            udp_receive_task_ = nullptr;
        }
        return false;
    }
    
    return true;
}

void Http3Client::StopBackgroundTasks() {
    if (!event_loop_task_ && !udp_receive_task_) {
        return;
    }
    
    ESP_LOGI(TAG, "Stopping background tasks");
    stop_tasks_.store(true);
    xEventGroupSetBits(event_group_, EVENT_STOP);
    
    // Close socket to unblock recv()
    CloseSocket();
    
    // Wait for tasks to finish
    for (int i = 0; i < 100 && (event_loop_task_ || udp_receive_task_); i++) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    
    if (event_loop_task_) {
        ESP_LOGW(TAG, "Event loop task did not finish, deleting");
        vTaskDelete(event_loop_task_);
        event_loop_task_ = nullptr;
    }
    
    if (udp_receive_task_) {
        ESP_LOGW(TAG, "UDP receive task did not finish, deleting");
        vTaskDelete(udp_receive_task_);
        udp_receive_task_ = nullptr;
    }
    
    // Drain queue
    UdpPacket* packet;
    while (xQueueReceive(udp_queue_, &packet, 0) == pdTRUE) {
        heap_caps_free(packet);
    }
}

void Http3Client::UdpReceiveTaskEntry(void* parameter) {
    Http3Client* self = static_cast<Http3Client*>(parameter);
    self->RunUdpReceive();
    self->udp_receive_task_ = nullptr;
    vTaskDelete(nullptr);
}

void Http3Client::EventLoopTaskEntry(void* parameter) {
    Http3Client* self = static_cast<Http3Client*>(parameter);
    self->RunEventLoop();
    self->event_loop_task_ = nullptr;
    vTaskDelete(nullptr);
}

void Http3Client::RunUdpReceive() {
    ESP_LOGD(TAG, "UDP receive task started");
    
    while (!stop_tasks_.load()) {
        if (udp_socket_ < 0) {
            break;
        }
        
        // Allocate packet in PSRAM
        UdpPacket* packet = static_cast<UdpPacket*>(
            heap_caps_malloc(sizeof(UdpPacket), MALLOC_CAP_SPIRAM));
        if (!packet) {
            ESP_LOGW(TAG, "Failed to allocate UDP packet");
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        
        // Blocking receive
        int received_length = recv(udp_socket_, packet->data, sizeof(packet->data), 0);
        if (received_length > 0) {
            packet->length = static_cast<size_t>(received_length);
            if (xQueueSend(udp_queue_, &packet, 0) == pdTRUE) {
                xEventGroupSetBits(event_group_, EVENT_UDP_DATA);
            } else {
                ESP_LOGW(TAG, "UDP queue full, dropping packet");
                heap_caps_free(packet);
            }
        } else {
            heap_caps_free(packet);
            break;
        }
    }
    
    ESP_LOGD(TAG, "UDP receive task stopped");
}

void Http3Client::RunEventLoop() {
    ESP_LOGD(TAG, "Event loop started");
    
    static constexpr uint32_t DEFAULT_WAIT_MS = 60000;
    static constexpr uint32_t MIN_WAIT_MS = 1;
    
    uint32_t next_timer_ms = DEFAULT_WAIT_MS;
    int64_t last_tick_time = esp_timer_get_time() / 1000;
    
    const EventBits_t wait_bits = EVENT_UDP_DATA | EVENT_WAKE | EVENT_STOP;
    
    while (!stop_tasks_.load()) {
        // Process all queued UDP packets
        UdpPacket* packet;
        while (xQueueReceive(udp_queue_, &packet, 0) == pdTRUE) {
            {
                std::lock_guard<std::mutex> lock(connection_mutex_);
                if (connection_) {
                    connection_->ProcessReceivedData(packet->data, packet->length);
                }
            }
            heap_caps_free(packet);
        }
        
        // Process pending write queues (may have been woken by OnStreamWritable)
        ProcessAllWriteQueues();
        
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
        
        // Wait for events
        if (next_timer_ms < MIN_WAIT_MS) {
            next_timer_ms = MIN_WAIT_MS;
        } else if (next_timer_ms > DEFAULT_WAIT_MS) {
            next_timer_ms = DEFAULT_WAIT_MS;
        }
        
        if (config_.enable_debug) {
            ESP_LOGI(TAG, "Waiting %u ms...", (unsigned)next_timer_ms);
        }
        
        EventBits_t bits = xEventGroupWaitBits(
            event_group_,
            wait_bits,
            pdTRUE,
            pdFALSE,
            pdMS_TO_TICKS(next_timer_ms)
        );
        
        if (bits & EVENT_STOP) {
            break;
        }
    }
    
    ESP_LOGD(TAG, "Event loop stopped");
}

void Http3Client::WakeEventLoop() {
    if (event_group_) {
        xEventGroupSetBits(event_group_, EVENT_WAKE);
    }
}

// ==================== QUIC Callbacks ====================

void Http3Client::OnConnected() {
    connected_ = true;
    xEventGroupSetBits(event_group_, EVENT_CONNECTED);
}

void Http3Client::OnDisconnected(int error_code, const std::string& reason) {
    ESP_LOGW(TAG, "QUIC disconnected: code=%d, reason=%s", error_code, reason.c_str());
    connected_ = false;
    xEventGroupSetBits(event_group_, EVENT_DISCONNECTED);
    
    // Notify all active streams of disconnection
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        for (auto& [stream_id, stream] : streams_) {
            if (stream) {
                stream->OnError(reason);
            }
        }
    }
    
    // Mark for cleanup
    needs_cleanup_.store(true);
    CloseSocket();
    stop_tasks_.store(true);
    xEventGroupSetBits(event_group_, EVENT_STOP);
}

void Http3Client::OnResponse(int stream_id, const esp_http3::H3Response& response) {
    ESP_LOGD(TAG, "Response on stream %d: status=%d", stream_id, response.status);
    
    Http3Stream* stream = GetStream(stream_id);
    if (stream) {
        stream->OnHeaders(response.status, response.headers);
    }
}

void Http3Client::OnStreamData(int stream_id, const uint8_t* data, size_t length, bool finished) {
    Http3Stream* stream = GetStream(stream_id);
    if (stream) {
        stream->OnData(data, length, finished);
    }
}

