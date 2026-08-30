#include "client/http3_client.h"

#include <algorithm>
#include <utility>
#include <vector>

namespace {

std::vector<std::pair<std::string, std::string>> CopyStandardHeaders(const esp_http3::Http3Headers& headers) {
    std::vector<std::pair<std::string, std::string>> result;
    result.reserve(headers.size());
    for (const auto& [name, value] : headers) {
        result.emplace_back(std::string(name.data(), name.size()), std::string(value.data(), value.size()));
    }
    return result;
}

bool ReadResponseBody(Http3Stream& stream, uint32_t timeout_ms, Http3Response& response) {
    esp_http3::Http3Vector<uint8_t> buffer(512);
    esp_http3::Http3String body;
    while (true) {
        const int bytes_read = stream.Read(buffer.data(), buffer.size(), timeout_ms);
        if (bytes_read < 0) {
            response.error = stream.GetError();
            return false;
        }
        if (bytes_read == 0) {
            break;
        }
        body.append(reinterpret_cast<const char*>(buffer.data()), static_cast<size_t>(bytes_read));
    }
    response.body.assign(body.data(), body.size());
    return true;
}

}  // namespace

Http3Client::Http3Client(const Http3ClientConfig& config)
    : owned_async_client_(std::make_unique<Http3AsyncClient>(config)), async_client_(owned_async_client_.get()) {}

Http3Client::Http3Client(Http3AsyncClient& async_client) : async_client_(&async_client) {}

Http3Client::~Http3Client() = default;

void Http3Client::SetPowerLockProvider(PowerLockProvider* provider) { async_client_->SetPowerLockProvider(provider); }

const Http3ClientConfig& Http3Client::GetConfig() const { return async_client_->GetConfig(); }

bool Http3Client::IsConnected() const { return async_client_->IsConnected(); }

std::string Http3Client::GetLastError() const { return async_client_->GetLastError(); }

void Http3Client::Disconnect() { async_client_->Disconnect(); }

std::unique_ptr<Http3Stream> Http3Client::Open(const Http3Request& request) { return async_client_->Open(request); }

bool Http3Client::Get(const std::string& path, Http3Response& response, uint32_t timeout_ms) {
    if (timeout_ms == 0) {
        timeout_ms = GetConfig().request_timeout_ms;
    }

    Http3Request request;
    request.method = "GET";
    request.path = path;

    auto stream = async_client_->Open(request);
    if (!stream) {
        response.error = async_client_->GetLastError();
        if (response.error.empty()) {
            response.error = "Failed to open stream";
        }
        return false;
    }

    response.status = stream->GetStatus(timeout_ms);
    response.headers = CopyStandardHeaders(stream->GetHeaders());
    if (response.status < 0) {
        response.error = stream->GetError();
        return false;
    }

    if (!ReadResponseBody(*stream, timeout_ms, response)) {
        return false;
    }

    response.complete = true;
    return response.status >= 200 && response.status < 300;
}

bool Http3Client::Post(const std::string& path, const std::vector<std::pair<std::string, std::string>>& headers,
                       const uint8_t* body, size_t body_size, Http3Response& response, uint32_t timeout_ms) {
    if (timeout_ms == 0) {
        timeout_ms = GetConfig().request_timeout_ms;
    }
    if (body_size != 0 && body == nullptr) {
        response.error = "Request body is null";
        return false;
    }

    Http3Request request;
    request.method = "POST";
    request.path = path;
    request.headers = headers;

    constexpr size_t kImmediateBodyLimit = 1024;
    const bool streaming_upload = body_size > kImmediateBodyLimit;
    request.streaming_upload = streaming_upload;
    if (!streaming_upload) {
        request.body = body;
        request.body_size = body_size;
    }

    auto stream = async_client_->Open(request);
    if (!stream) {
        response.error = async_client_->GetLastError();
        if (response.error.empty()) {
            response.error = "Failed to open stream";
        }
        return false;
    }

    if (streaming_upload) {
        constexpr size_t kUploadChunkSize = 1024;
        size_t offset = 0;
        while (offset < body_size) {
            const size_t chunk_size = std::min(kUploadChunkSize, body_size - offset);
            const int written = stream->Write(body + offset, chunk_size, timeout_ms);
            if (written != static_cast<int>(chunk_size)) {
                response.error = stream->GetError();
                if (response.error.empty()) {
                    response.error = "Failed to stream request body";
                }
                return false;
            }
            offset += chunk_size;
        }
        if (!stream->Finish()) {
            response.error = stream->GetError();
            if (response.error.empty()) {
                response.error = "Failed to finish request body";
            }
            return false;
        }
    }

    response.status = stream->GetStatus(timeout_ms);
    response.headers = CopyStandardHeaders(stream->GetHeaders());
    if (response.status < 0) {
        response.error = stream->GetError();
        return false;
    }

    if (!ReadResponseBody(*stream, timeout_ms, response)) {
        return false;
    }

    response.complete = true;
    return response.status >= 200 && response.status < 300;
}

Http3Client::Statistics Http3Client::GetStatistics() const { return async_client_->GetStatistics(); }

bool Http3Client::StreamWrite(int stream_id, std::vector<uint8_t>&& data) {
    return async_client_->StreamWrite(stream_id, std::move(data));
}

bool Http3Client::StreamFinish(int stream_id) { return async_client_->StreamFinish(stream_id); }
