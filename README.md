# ESP-HTTP3

A QUIC/HTTP3 client library for ESP32 platform, implementing RFC 9000 (QUIC) and RFC 9114 (HTTP/3) protocols.

## Features

- ✅ QUIC v1 transport protocol
- ✅ TLS 1.3 handshake (using mbedtls)
- ✅ HTTP/3 request/response
- ✅ Stream multiplexing
- ✅ Flow control
- ✅ Packet loss detection and recovery
- ✅ Synchronous blocking API with background event loop

## Quick Start

### Simple GET Request

```cpp
#include "client/http3_client.h"

// Configure connection
Http3ClientConfig config;
config.hostname = "api.example.com";
config.port = 443;

// Create client (manages connection lifecycle)
Http3Client client(config);

// Simple GET request
Http3Response response;
if (client.Get("/api/health", response)) {
    ESP_LOGI(TAG, "Status: %d", response.status);
    ESP_LOGI(TAG, "Body: %s", response.body.c_str());
}
```

### Simple POST Request

```cpp
Http3Client client(config);

std::vector<std::pair<std::string, std::string>> headers = {
    {"content-type", "application/json"}
};
const char* body = R"({"key": "value"})";

Http3Response response;
if (client.Post("/api/data", headers, 
                (const uint8_t*)body, strlen(body), response)) {
    ESP_LOGI(TAG, "Status: %d", response.status);
}
```

### Streaming Download

```cpp
Http3Client client(config);

// Open stream
auto stream = client.Open({.method = "GET", .path = "/large-file"});
if (!stream) {
    ESP_LOGE(TAG, "Failed to open stream");
    return;
}

// Check status
if (stream->GetStatus() != 200) {
    ESP_LOGE(TAG, "HTTP error: %d", stream->GetStatus());
    return;
}

// Read response body in chunks
uint8_t buffer[4096];
int bytes_read;
while ((bytes_read = stream->Read(buffer, sizeof(buffer))) > 0) {
    // Process data...
}

// bytes_read == 0 means EOF, < 0 means error
```

### Streaming Upload

```cpp
Http3Client client(config);

Http3Request request;
request.method = "POST";
request.path = "/upload";
request.streaming_upload = true;
request.headers = {{"content-type", "application/octet-stream"}};

auto stream = client.Open(request);
if (!stream) {
    ESP_LOGE(TAG, "Failed to open stream");
    return;
}

// Write data in chunks
for (auto& chunk : data_chunks) {
    if (stream->Write(chunk.data(), chunk.size()) < 0) {
        ESP_LOGE(TAG, "Write failed: %s", stream->GetError().c_str());
        return;
    }
}

// Signal end of body
stream->Finish();

// Read response
if (stream->GetStatus() == 200) {
    ESP_LOGI(TAG, "Upload successful");
}
```

## API Reference

### Http3Client

Main client class that manages QUIC connection and HTTP/3 streams.

```cpp
class Http3Client {
    // Constructor
    explicit Http3Client(const Http3ClientConfig& config);
    
    // Connection state
    bool IsConnected() const;
    void Disconnect();
    
    // Simple request methods (blocking, accumulates body)
    bool Get(const std::string& path, Http3Response& response,
             uint32_t timeout_ms = 0);
    bool Post(const std::string& path, 
              const std::vector<std::pair<std::string, std::string>>& headers,
              const uint8_t* body, size_t body_size,
              Http3Response& response,
              uint32_t timeout_ms = 0);
    
    // Stream API (for streaming or large responses)
    std::unique_ptr<Http3Stream> Open(const Http3Request& request,
                                       uint32_t timeout_ms = 0);
    
    // Statistics
    Statistics GetStatistics() const;
};
```

### Http3Stream

Represents an active HTTP/3 request stream with blocking read/write.

```cpp
class Http3Stream {
    // Stream info
    int GetStreamId() const;
    bool IsValid() const;
    
    // Response headers (blocking wait for headers)
    int GetStatus(uint32_t timeout_ms = 0);
    std::string GetHeader(const std::string& name) const;
    
    // Read response body (blocking)
    // Returns: >0 bytes read, 0 EOF, <0 error
    int Read(uint8_t* buffer, size_t size, uint32_t timeout_ms = 0);
    
    // Write request body (for streaming uploads)
    int Write(const uint8_t* data, size_t size, uint32_t timeout_ms = 0);
    int Write(std::vector<uint8_t>&& data, uint32_t timeout_ms = 0);
    
    // Signal end of request body
    bool Finish();
    
    // Close stream
    void Close();
    
    // Error info
    const std::string& GetError() const;
};
```

### Configuration

```cpp
struct Http3ClientConfig {
    std::string hostname;
    uint16_t port = 443;
    
    // Timeouts
    uint32_t connect_timeout_ms = 10000;
    uint32_t request_timeout_ms = 30000;
    uint32_t idle_timeout_ms = 60000;
    
    // Buffer sizes
    size_t receive_buffer_size = 64 * 1024;
    
    // Performance optimizations
    bool cache_keypair = true;         // Cache X25519 keypair for faster reconnect
    bool cache_session_ticket = false; // Session resumption (experimental)
    
    // Debug
    bool enable_debug = false;
};

struct Http3Request {
    std::string method = "GET";
    std::string path;
    std::vector<std::pair<std::string, std::string>> headers;
    
    // For immediate body
    const uint8_t* body = nullptr;
    size_t body_size = 0;
    
    // For streaming upload
    bool streaming_upload = false;
};

struct Http3Response {
    int status = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    bool complete = false;
    std::string error;
};
```

## Threading Model

- `Http3Client` manages background tasks for UDP receive and QUIC event processing
- Public methods can be called from any task
- Each `Http3Stream` should be used from a single task (except `Close()`)
- Connection is established automatically on first request

## Notes

1. **Task Stack Size**: Requires at least 8KB stack size
2. **Network Required**: Ensure WiFi or other network is connected before use
3. **Resource Cleanup**: `Http3Stream` is automatically cleaned up when unique_ptr goes out of scope
4. **Connection Reuse**: Multiple requests can share the same `Http3Client` connection

## Dependencies

- ESP-IDF v5.4+
- mbedtls (for TLS 1.3)
- lwip (for network stack)

## License

Apache-2.0 License
