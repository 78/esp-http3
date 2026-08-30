# ESP-HTTP3

A QUIC/HTTP3 client library for ESP32 platform, implementing RFC 9000 (QUIC) and RFC 9114 (HTTP/3) protocols.

## Features

- ✅ QUIC v1 transport protocol
- ✅ TLS 1.3 handshake and peer authentication (using mbedtls)
- ✅ HTTP/3 request/response
- ✅ Stream multiplexing
- ✅ Flow control
- ✅ Packet loss detection and recovery
- ✅ Synchronous blocking API with background event loop
- ✅ Bounded event-driven asynchronous requests with per-instance concurrency

## Quick Start

### Simple GET Request

```cpp
#include "client/http3_client.h"

// Configure connection
Http3ClientConfig config;
config.hostname = "api.example.com";
config.port = 443;
config.trusted_ca_der.assign(ca_der, ca_der + ca_der_size);

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

### Bounded event-driven asynchronous requests

`Http3AsyncClient` owns the socket, QUIC connection, background event loop,
stream registry, and bounded request state machine. Its maximum in-flight
request count is selected when each instance is created; the default is 10 and
the state machine never grows beyond that capacity.

```cpp
#include "client/http3_async_client.h"

Http3AsyncClientConfig config;
config.hostname = "api.example.com";
config.max_concurrent_requests = 10;
Http3AsyncClient requests(config);
requests.Start();

Http3AsyncRequest request;
request.method = "POST";
request.path = "/api/data";
request.headers = {{"content-type", "application/json"}};
request.body.assign(body, body + body_size);
Http3AsyncRequestHandle handle = requests.Submit(std::move(request));

Http3AsyncResult result;
if (requests.PollCompletion(result)) {
    ESP_LOGI(TAG, "request=%lu status=%d", (unsigned long)result.handle.value, result.status);
}
```

`Start()` performs the one-time connection establishment. After that,
`Submit()`, `Cancel()`, and `PollCompletion()` do not wait for network I/O.
If the transport disconnects, outstanding requests complete with a transport
error and the asynchronous scheduler stops accepting submissions. The owning
task must call `Start()` again before resubmitting; that call performs the
reconnection and may wait up to `connect_timeout_ms`.
There is no periodic request scan: state advances only on submission,
cancellation, incoming UDP data, a QUIC protocol timer, or a request deadline.
Scheduled request methods, paths, headers (including header strings), request
bodies, response headers, response bodies, errors, and slot storage use the
component allocator (PSRAM when configured). Use `Http3AsyncClient::Open()` for
a long-lived control stream or a large streaming upload/download.
`Http3Client` remains available as a synchronous compatibility adapter and can
either own an asynchronous client or borrow one whose lifetime is managed by
the application. The adapter copies final headers/body into the original
standard-library response types at that compatibility boundary.

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

Synchronous compatibility adapter over `Http3AsyncClient`.

```cpp
class Http3Client {
    // Constructor
    explicit Http3Client(const Http3ClientConfig& config);
    explicit Http3Client(Http3AsyncClient& async_client); // non-owning adapter
    
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
    std::unique_ptr<Http3Stream> Open(const Http3Request& request);
    
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
    uint32_t max_concurrent_requests = 10;

    // TLS peer authentication. The vector contains the application's trust root.
    std::vector<uint8_t> trusted_ca_der;
    bool allow_unverified_peer = false; // Development only; see below.
    
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

### TLS peer authentication

Connections fail closed unless `hostname` is non-empty and
`trusted_ca_der` contains one DER-encoded trust anchor. The client verifies
the certificate chain, validity period, hostname, server-auth/key-usage
constraints, TLS 1.3 CertificateVerify signature, Finished MAC, handshake
message order, and the expected QUIC encryption level. The application must
establish trustworthy wall-clock time before connecting so certificate dates
can be evaluated.

`allow_unverified_peer` is a development-only escape hatch. It skips chain,
date, and hostname verification, but still requires a suitable leaf
certificate and validates CertificateVerify and Finished. Do not enable it in
released firmware or over an untrusted network.

## Threading Model

- `Http3AsyncClient` uses one `select()`-driven background task for UDP receive,
  QUIC timers, and event processing
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

## Memory allocation

`CONFIG_ESP_HTTP3_USE_PSRAM_ALLOCATOR` is enabled by default when PSRAM is
available. It places the component's large stream receive buffers, HTTP/3
reassembly buffers, QUIC handshake caches, and retransmission data in PSRAM.
`CONFIG_ESP_HTTP3_PSRAM_ALLOCATOR_FALLBACK` is also enabled by default and
retries failed PSRAM allocations from internal RAM.

The allocator intentionally does not redirect FreeRTOS objects, task stacks,
lwIP-owned buffers, or memory with DMA/internal-RAM capability requirements.
Disabling the allocator keeps the same container types but backs them with the
internal byte-addressable heap.

## License

Apache-2.0 License
