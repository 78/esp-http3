/*
 * HTTP/3 synchronous compatibility client.
 *
 * This adapter depends on Http3AsyncClient. The asynchronous client owns the
 * connection and transport lifecycle; this class only adds blocking convenience
 * operations and preserves the original public API.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "client/http3_async_client.h"

using Http3ClientConfig = Http3AsyncClientConfig;

struct Http3Response {
    int status = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    bool complete = false;
    std::string error;
};

class Http3Client final {
public:
    using Statistics = Http3AsyncClient::Statistics;

    explicit Http3Client(const Http3ClientConfig& config);
    explicit Http3Client(Http3AsyncClient& async_client);
    ~Http3Client();

    Http3Client(const Http3Client&) = delete;
    Http3Client& operator=(const Http3Client&) = delete;
    Http3Client(Http3Client&&) = delete;
    Http3Client& operator=(Http3Client&&) = delete;

    void SetPowerLockProvider(PowerLockProvider* provider);
    [[nodiscard]] const Http3ClientConfig& GetConfig() const;
    [[nodiscard]] bool IsConnected() const;
    [[nodiscard]] std::string GetLastError() const;
    void Disconnect();

    [[nodiscard]] std::unique_ptr<Http3Stream> Open(const Http3Request& request);
    [[nodiscard]] bool Get(const std::string& path, Http3Response& response, uint32_t timeout_ms = 0);
    [[nodiscard]] bool Post(const std::string& path, const std::vector<std::pair<std::string, std::string>>& headers,
                            const uint8_t* body, size_t body_size, Http3Response& response, uint32_t timeout_ms = 0);

    [[nodiscard]] Statistics GetStatistics() const;
    [[nodiscard]] bool StreamWrite(int stream_id, std::vector<uint8_t>&& data);
    [[nodiscard]] bool StreamFinish(int stream_id);

    [[nodiscard]] Http3AsyncClient& async_client() { return *async_client_; }
    [[nodiscard]] const Http3AsyncClient& async_client() const { return *async_client_; }

private:
    std::unique_ptr<Http3AsyncClient> owned_async_client_;
    Http3AsyncClient* async_client_{};
};
