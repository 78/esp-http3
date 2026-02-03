/**
 * @file h3_handler.cc
 * @brief HTTP/3 Handler Implementation
 */

#include "h3/h3_handler.h"
#include "h3/h3_constants.h"
#include "esp_log.h"

#include <algorithm>
#include <cstring>

static const char* TAG = "H3Handler";

namespace esp_http3 {
namespace h3 {

H3Handler::H3Handler() {
    Reset();
}

void H3Handler::Reset() {
    streams_.clear();
    next_bidi_stream_id_ = 0;
    next_uni_stream_id_ = 2;
    control_stream_id_ = UINT64_MAX;
    qpack_encoder_stream_id_ = UINT64_MAX;
    qpack_decoder_stream_id_ = UINT64_MAX;
    peer_control_stream_id_ = UINT64_MAX;
    peer_settings_received_ = false;
    initialized_ = false;
    
    // Set local settings
    local_settings_.max_field_section_size = 16384;
    local_settings_.qpack_max_table_capacity = 0;
    local_settings_.qpack_blocked_streams = 0;
}

void H3Handler::Initialize(uint64_t next_bidi_stream_id, uint64_t next_uni_stream_id) {
    next_bidi_stream_id_ = next_bidi_stream_id;
    next_uni_stream_id_ = next_uni_stream_id;
    
    // Create client control stream (unidirectional)
    control_stream_id_ = next_uni_stream_id_;
    next_uni_stream_id_ += 4;
    
    auto control = std::make_unique<H3Stream>();
    control->stream_id = control_stream_id_;
    control->state = StreamState::kOpen;
    control->is_control = true;
    streams_[control_stream_id_] = std::move(control);
    
    // Create QPACK encoder stream
    qpack_encoder_stream_id_ = next_uni_stream_id_;
    next_uni_stream_id_ += 4;
    
    auto encoder = std::make_unique<H3Stream>();
    encoder->stream_id = qpack_encoder_stream_id_;
    encoder->state = StreamState::kOpen;
    encoder->is_qpack_encoder = true;
    streams_[qpack_encoder_stream_id_] = std::move(encoder);
    
    // Create QPACK decoder stream
    qpack_decoder_stream_id_ = next_uni_stream_id_;
    next_uni_stream_id_ += 4;
    
    auto decoder = std::make_unique<H3Stream>();
    decoder->stream_id = qpack_decoder_stream_id_;
    decoder->state = StreamState::kOpen;
    decoder->is_qpack_decoder = true;
    streams_[qpack_decoder_stream_id_] = std::move(decoder);
    
    initialized_ = true;
}

bool H3Handler::SendSettings() {
    if (!initialized_ || !send_stream_) {
        ESP_LOGE(TAG, "SendSettings failed: not initialized or send_stream_ not set");
        return false;
    }
    
    // Control stream type (0x00)
    uint8_t stream_type[1] = {0x00};
    if (!send_stream_(control_stream_id_, stream_type, 1, false)) {
        ESP_LOGE(TAG, "SendSettings failed: failed to send control stream type");
        return false;
    }
    
    // SETTINGS frame
    uint8_t settings[64];
    size_t settings_len = BuildDefaultSettingsFrame(settings, sizeof(settings));
    if (settings_len == 0) {
        ESP_LOGE(TAG, "SendSettings failed: BuildDefaultSettingsFrame returned 0");
        return false;
    }
    
    if (!send_stream_(control_stream_id_, settings, settings_len, false)) {
        ESP_LOGE(TAG, "SendSettings failed: failed to send SETTINGS frame");
        return false;
    }
    
    // QPACK encoder stream type (0x02)
    uint8_t encoder_type[1] = {0x02};
    if (!send_stream_(qpack_encoder_stream_id_, encoder_type, 1, false)) {
        ESP_LOGE(TAG, "SendSettings failed: failed to send QPACK encoder stream type");
        return false;
    }
    
    // QPACK decoder stream type (0x03)
    uint8_t decoder_type[1] = {0x03};
    if (!send_stream_(qpack_decoder_stream_id_, decoder_type, 1, false)) {
        ESP_LOGE(TAG, "SendSettings failed: failed to send QPACK decoder stream type");
        return false;
    }
    
    return true;
}

int64_t H3Handler::CreateRequestStream() {
    if (!initialized_) {
        ESP_LOGE(TAG, "CreateRequestStream failed: handler not initialized");
        return -1;
    }
    
    uint64_t stream_id = next_bidi_stream_id_;
    next_bidi_stream_id_ += 4;
    
    auto stream = std::make_unique<H3Stream>();
    stream->stream_id = stream_id;
    stream->state = StreamState::kOpen;
    streams_[stream_id] = std::move(stream);
    
    return static_cast<int64_t>(stream_id);
}

bool H3Handler::SendRequest(uint64_t stream_id,
                            const std::string& method,
                            const std::string& path,
                            const std::string& authority,
                            const std::vector<std::pair<std::string, std::string>>& headers,
                            const std::vector<uint8_t>& body) {
    auto* stream = GetStream(stream_id);
    if (!stream || stream->state != StreamState::kOpen) {
        ESP_LOGE(TAG, "SendRequest failed: stream %llu not found or not open (state=%d)",
                 (unsigned long long)stream_id, 
                 stream ? static_cast<int>(stream->state) : -1);
        return false;
    }
    
    stream->method = method;
    stream->path = path;
    
    // Build QPACK-encoded headers
    std::vector<uint8_t> qpack_headers(1024);
    size_t qpack_len = BuildQpackRequestHeaders(
        method, path, authority, "https", headers,
        qpack_headers.data(), qpack_headers.size());
    
    if (qpack_len == 0) {
        ESP_LOGE(TAG, "SendRequest failed: BuildQpackRequestHeaders returned 0 for stream %llu",
                 (unsigned long long)stream_id);
        return false;
    }
    
    // Build HEADERS frame
    std::vector<uint8_t> encoded_headers(qpack_headers.data(), qpack_headers.data() + qpack_len);
    std::vector<uint8_t> headers_frame(1024);
    size_t headers_frame_len = BuildHeadersFrame(encoded_headers, 
                                                  headers_frame.data(), 
                                                  headers_frame.size());
    if (headers_frame_len == 0) {
        ESP_LOGE(TAG, "SendRequest failed: BuildHeadersFrame returned 0 for stream %llu",
                 (unsigned long long)stream_id);
        return false;
    }
    
    // Send HEADERS frame
    bool has_body = !body.empty();
    if (!send_stream_(stream_id, headers_frame.data(), headers_frame_len, !has_body)) {
        ESP_LOGE(TAG, "SendRequest failed: failed to send HEADERS frame for stream %llu",
                 (unsigned long long)stream_id);
        return false;
    }
    
    // Send DATA frame if body exists
    if (has_body) {
        std::vector<uint8_t> data_frame(2048);
        size_t data_frame_len = BuildDataFrame(body.data(), body.size(),
                                                data_frame.data(), data_frame.size());
        if (data_frame_len == 0) {
            ESP_LOGE(TAG, "SendRequest failed: BuildDataFrame returned 0 for stream %llu",
                     (unsigned long long)stream_id);
            return false;
        }
        
        if (!send_stream_(stream_id, data_frame.data(), data_frame_len, true)) {
            ESP_LOGE(TAG, "SendRequest failed: failed to send DATA frame for stream %llu",
                     (unsigned long long)stream_id);
            return false;
        }
    }
    
    stream->state = StreamState::kHalfClosedLocal;
    return true;
}

void H3Handler::MergePendingChunks(H3Stream* stream) {
    // Try to merge pending chunks into contiguous buffer
    bool merged = true;
    
    while (merged && !stream->pending_chunks.empty()) {
        merged = false;
        
        // Find chunks that can be merged (sorted by offset)
        for (auto it = stream->pending_chunks.begin(); 
             it != stream->pending_chunks.end(); ) {
            if (it->offset <= stream->contiguous_end) {
                uint64_t end_offset = it->offset + it->data.size();
                
                if (end_offset > stream->contiguous_end) {
                    // Append the non-overlapping part
                    size_t new_start = stream->contiguous_end - it->offset;
                    stream->recv_buffer.insert(stream->recv_buffer.end(),
                                               it->data.begin() + new_start,
                                               it->data.end());
                    stream->contiguous_end = end_offset;
                    merged = true;
                    
                    ESP_LOGD(TAG, "  Merged buffered chunk at offset %llu, contiguous_end now %llu",
                             (unsigned long long)it->offset, 
                             (unsigned long long)stream->contiguous_end);
                }
                
                it = stream->pending_chunks.erase(it);
            } else {
                ++it;
            }
        }
    }
}

void H3Handler::OnStreamData(uint64_t stream_id, uint64_t offset,
                              const uint8_t* data, size_t len, bool fin) {
    ESP_LOGD(TAG, "OnStreamData: stream=%llu, offset=%llu, len=%zu, fin=%d", 
             (unsigned long long)stream_id, (unsigned long long)offset, 
             len, fin ? 1 : 0);
    
    // Check if this is a new unidirectional stream from server
    if (stream_id % 4 == 3) {  // Server-initiated unidirectional
        ESP_LOGD(TAG, "  Server-initiated unidirectional stream");
        auto* stream = GetStream(stream_id);
        if (!stream) {
            // New stream, create it
            ESP_LOGD(TAG, "  Creating new uni stream %llu", (unsigned long long)stream_id);
            auto new_stream = std::make_unique<H3Stream>();
            new_stream->stream_id = stream_id;
            new_stream->state = StreamState::kOpen;
            new_stream->contiguous_end = 0;
            streams_[stream_id] = std::move(new_stream);
            stream = streams_[stream_id].get();
        }
        
        // Unidirectional streams are typically small, use simple append for now
        stream->recv_buffer.insert(stream->recv_buffer.end(), data, data + len);
        stream->contiguous_end = stream->recv_buffer.size();
        
        // Handle unidirectional stream
        HandleUniStreamType(stream_id);
        return;
    }
    
    auto* stream = GetStream(stream_id);
    if (!stream) {
        ESP_LOGW(TAG, "  Stream %llu not found!", (unsigned long long)stream_id);
        return;
    }
    
    // Store FIN offset if received
    if (fin) {
        stream->fin_offset = offset + len;
        ESP_LOGD(TAG, "  FIN received at offset %llu", 
                 (unsigned long long)stream->fin_offset);
    }
    
    // Handle data reassembly (like Python's H3StreamManager)
    uint64_t end_offset = offset + len;
    
    if (offset == stream->contiguous_end) {
        // Data is in order - append directly
        stream->recv_buffer.insert(stream->recv_buffer.end(), data, data + len);
        stream->contiguous_end = end_offset;
        
        // Check if any pending chunks can now be merged
        MergePendingChunks(stream);
        
    } else if (offset > stream->contiguous_end) {
        // Out of order - store for later
        ESP_LOGD(TAG, "  Buffering out-of-order data at offset %llu (expecting %llu)",
                 (unsigned long long)offset, 
                 (unsigned long long)stream->contiguous_end);
        
        // Check for duplicates before adding
        bool is_dup = false;
        for (const auto& chunk : stream->pending_chunks) {
            if (chunk.offset == offset && chunk.data.size() == len) {
                is_dup = true;
                break;
            }
        }
        
        if (!is_dup) {
            PendingChunk chunk;
            chunk.offset = offset;
            chunk.data.assign(data, data + len);
            stream->pending_chunks.push_back(std::move(chunk));
            
            // Sort pending chunks by offset for efficient merging
            std::sort(stream->pending_chunks.begin(), stream->pending_chunks.end(),
                      [](const PendingChunk& a, const PendingChunk& b) {
                          return a.offset < b.offset;
                      });
        }
        
    } else {
        // Overlapping or duplicate data - check for gaps
        if (end_offset > stream->contiguous_end) {
            // Partial new data
            size_t new_start = stream->contiguous_end - offset;
            stream->recv_buffer.insert(stream->recv_buffer.end(), 
                                       data + new_start, 
                                       data + len);
            stream->contiguous_end = end_offset;
            MergePendingChunks(stream);
        } else {
            ESP_LOGD(TAG, "  Ignoring duplicate data at offset %llu",
                     (unsigned long long)offset);
        }
    }
    
    ESP_LOGD(TAG, "  recv_buffer contiguous: %zu bytes, pending chunks: %zu",
             stream->recv_buffer.size(), stream->pending_chunks.size());
    
    // Process based on stream type
    if (stream->is_control) {
        ESP_LOGD(TAG, "  Processing as control stream");
        HandleControlStream(stream_id, stream->recv_buffer.data(), 
                           stream->recv_buffer.size());
    } else {
        ESP_LOGD(TAG, "  Processing as request stream");
        // Check if all data is contiguous before processing
        bool all_data_received = (stream->fin_offset != UINT64_MAX && 
                                  stream->contiguous_end >= stream->fin_offset &&
                                  stream->pending_chunks.empty());
        HandleRequestStream(stream_id, stream->recv_buffer.data(), 
                           stream->recv_buffer.size(), 
                           all_data_received);
    }
    
    // Update stream state if FIN received and all data processed
    if (stream->fin_offset != UINT64_MAX && 
        stream->contiguous_end >= stream->fin_offset) {
        if (stream->state == StreamState::kHalfClosedLocal) {
            stream->state = StreamState::kClosed;
            ESP_LOGD(TAG, "  Stream %llu closed", (unsigned long long)stream_id);
        } else {
            stream->state = StreamState::kHalfClosedRemote;
            ESP_LOGD(TAG, "  Stream %llu half-closed remote", (unsigned long long)stream_id);
        }
    }
}

void H3Handler::HandleUniStreamType(uint64_t stream_id) {
    auto* stream = GetStream(stream_id);
    if (!stream || stream->recv_buffer.empty()) {
        return;
    }
    
    // Skip if stream type already identified - forward to appropriate handler
    if (stream->is_control) {
        // Already identified as control stream, forward new data
        HandleControlStream(stream_id, 
                            stream->recv_buffer.data(),
                            stream->recv_buffer.size());
        return;
    }
    if (stream->is_qpack_encoder || stream->is_qpack_decoder) {
        // QPACK streams data is ignored (we don't use dynamic table)
        stream->recv_buffer.clear();
        return;
    }
    
    // First byte is stream type (only for new streams)
    uint8_t stream_type = stream->recv_buffer[0];
    
    switch (stream_type) {
        case 0x00:  // Control stream
            peer_control_stream_id_ = stream_id;
            stream->is_control = true;
            // Remove stream type byte and process remaining
            if (stream->recv_buffer.size() > 1) {
                HandleControlStream(stream_id, 
                                    stream->recv_buffer.data() + 1,
                                    stream->recv_buffer.size() - 1);
            }
            break;
            
        case 0x02:  // QPACK encoder stream
            stream->is_qpack_encoder = true;
            // We don't use dynamic table, so ignore encoder instructions
            stream->recv_buffer.clear();
            break;
            
        case 0x03:  // QPACK decoder stream
            stream->is_qpack_decoder = true;
            // Ignore decoder instructions
            stream->recv_buffer.clear();
            break;
            
        default:
            // Unknown stream type, ignore
            ESP_LOGW(TAG, "HandleUniStreamType: unknown stream type 0x%02x on stream %llu",
                     stream_type, (unsigned long long)stream_id);
            stream->recv_buffer.clear();
            break;
    }
}

void H3Handler::HandleControlStream(uint64_t stream_id, 
                                     const uint8_t* data, size_t len) {
    auto* stream = GetStream(stream_id);
    if (!stream) {
        ESP_LOGW(TAG, "HandleControlStream: stream %llu not found", 
                 (unsigned long long)stream_id);
        return;
    }
    
    // Skip stream type if present
    size_t offset = 0;
    if (!stream->recv_buffer.empty() && stream->recv_buffer[0] == 0x00) {
        offset = 1;
    }
    
    // Parse frames
    while (offset < stream->recv_buffer.size()) {
        H3FrameHeader header;
        if (!ParseH3FrameHeader(stream->recv_buffer.data() + offset,
                                 stream->recv_buffer.size() - offset,
                                 &header)) {
            break;  // Need more data
        }
        
        size_t frame_total = header.header_size + header.length;
        if (offset + frame_total > stream->recv_buffer.size()) {
            break;  // Need more data
        }
        
        const uint8_t* payload = stream->recv_buffer.data() + offset + header.header_size;
        
        switch (header.type) {
            case H3FrameType::kSettings:
                if (!peer_settings_received_) {
                    ParseSettingsFrame(payload, header.length, &peer_settings_);
                    peer_settings_received_ = true;
                }
                break;
                
            case H3FrameType::kGoaway:
                // Handle GOAWAY
                break;
                
            default:
                // Unknown frame, skip
                break;
        }
        
        offset += frame_total;
    }
    
    // Remove processed data
    if (offset > 0) {
        stream->recv_buffer.erase(stream->recv_buffer.begin(),
                                   stream->recv_buffer.begin() + offset);
    }
}

void H3Handler::HandleRequestStream(uint64_t stream_id, 
                                      const uint8_t* data, size_t len, bool fin) {
    auto* stream = GetStream(stream_id);
    if (!stream) {
        ESP_LOGW(TAG, "HandleRequestStream: stream %llu not found", 
                 (unsigned long long)stream_id);
        return;
    }
    
    ESP_LOGD(TAG, "HandleRequestStream: stream=%llu, buffer_size=%zu, pending_data=%llu, fin=%d",
             (unsigned long long)stream_id, stream->recv_buffer.size(),
             (unsigned long long)stream->pending_data_frame_remaining, fin ? 1 : 0);
    
    // Parse frames from buffer
    size_t offset = 0;
    int frame_count = 0;
    
    while (offset < stream->recv_buffer.size()) {
        // Check if we're in the middle of a large DATA frame
        if (stream->pending_data_frame_remaining > 0) {
            // Continue processing the pending DATA frame incrementally
            size_t available = stream->recv_buffer.size() - offset;
            size_t to_deliver = std::min(available, 
                                         static_cast<size_t>(stream->pending_data_frame_remaining));
            
            ESP_LOGD(TAG, "  Continuing DATA frame: delivering %zu bytes, %llu remaining after",
                     to_deliver, 
                     (unsigned long long)(stream->pending_data_frame_remaining - to_deliver));
            
            if (on_stream_data_ && to_deliver > 0) {
                on_stream_data_(stream_id, stream->recv_buffer.data() + offset, to_deliver, false);
            }
            
            stream->pending_data_frame_remaining -= to_deliver;
            offset += to_deliver;
            continue;
        }
        
        // Parse new frame header
        H3FrameHeader header;
        if (!ParseH3FrameHeader(stream->recv_buffer.data() + offset,
                                 stream->recv_buffer.size() - offset,
                                 &header)) {
            ESP_LOGD(TAG, "  Need more data for H3 frame header (offset=%zu, remaining=%zu)",
                     offset, stream->recv_buffer.size() - offset);
            break;
        }
        
        size_t frame_total = header.header_size + header.length;
        size_t available_after_header = stream->recv_buffer.size() - offset - header.header_size;
        
        // For DATA frames, support incremental delivery (don't wait for complete frame)
        if (header.type == H3FrameType::kData) {
            ESP_LOGD(TAG, "  H3 Frame: DATA (len=%llu bytes, available=%zu)", 
                     (unsigned long long)header.length, available_after_header);
            
            const uint8_t* payload = stream->recv_buffer.data() + offset + header.header_size;
            size_t to_deliver = std::min(available_after_header, 
                                         static_cast<size_t>(header.length));
            
            // Deliver available data immediately
            if (on_stream_data_ && to_deliver > 0) {
                on_stream_data_(stream_id, payload, to_deliver, false);
            }
            
            // Track remaining bytes if frame is incomplete
            if (to_deliver < header.length) {
                stream->pending_data_frame_remaining = header.length - to_deliver;
                ESP_LOGD(TAG, "  DATA frame incomplete, %llu bytes remaining",
                         (unsigned long long)stream->pending_data_frame_remaining);
            }
            
            // Consume header + delivered data
            offset += header.header_size + to_deliver;
            frame_count++;
            continue;
        }
        
        // For non-DATA frames (HEADERS, etc.), wait for complete frame
        if (offset + frame_total > stream->recv_buffer.size()) {
            ESP_LOGD(TAG, "  Need more data for H3 frame body (need=%zu, have=%zu)",
                     frame_total, stream->recv_buffer.size() - offset);
            break;
        }
        
        const uint8_t* payload = stream->recv_buffer.data() + offset + header.header_size;
        frame_count++;
        
        switch (header.type) {
            case H3FrameType::kHeaders: {
                ESP_LOGD(TAG, "  H3 Frame: HEADERS (len=%llu)", (unsigned long long)header.length);
                std::vector<HeaderField> headers;
                if (DecodeQpackHeaderBlock(payload, header.length, &headers)) {
                    ESP_LOGD(TAG, "    Decoded %zu headers", headers.size());
                    for (const auto& h : headers) {
                        ESP_LOGD(TAG, "      %s: %s", h.name.c_str(), h.value.c_str());
                        if (h.name == ":status") {
                            stream->response.status = std::atoi(h.value.c_str());
                            ESP_LOGD(TAG, "    Status: %d", stream->response.status);
                        } else if (h.name[0] != ':') {
                            // Pass header value as-is, let application layer handle decoding if needed
                            stream->response.headers.push_back({h.name, h.value});
                        }
                    }
                    
                    // Trigger OnResponse callback immediately after headers are parsed
                    // Since H3Response no longer contains body, we can notify early
                    if (on_response_ && !stream->response_headers_sent) {
                        stream->response_headers_sent = true;
                        ESP_LOGD(TAG, "    Triggering OnResponse callback (headers received)");
                        on_response_(stream_id, stream->response);
                    }
                } else {
                    ESP_LOGW(TAG, "    Failed to decode QPACK headers");
                }
                break;
            }
                
            default:
                ESP_LOGW(TAG, "  H3 Frame: Unknown type 0x%02x (len=%llu)", 
                         static_cast<int>(header.type), (unsigned long long)header.length);
                break;
        }
        
        offset += frame_total;
    }
    
    ESP_LOGD(TAG, "  Processed %d H3 frames, consumed %zu bytes", frame_count, offset);
    
    // Remove processed data
    if (offset > 0) {
        stream->recv_buffer.erase(stream->recv_buffer.begin(),
                                   stream->recv_buffer.begin() + offset);
    }
    
    // Check if response is complete
    if (fin) {
        stream->response.complete = true;
        ESP_LOGD(TAG, "  Response complete! status=%d", stream->response.status);
        
        // OnResponse callback should have been triggered when headers were received
        // Only trigger here if headers were never received (edge case)
        if (on_response_ && !stream->response_headers_sent) {
            ESP_LOGW(TAG, "  Stream finished but headers never received, triggering OnResponse anyway");
            stream->response_headers_sent = true;
            on_response_(stream_id, stream->response);
        }
        
        // NOTE: Do NOT release buffers here!
        // The on_stream_data_ callback (below) may trigger CleanupStream -> CloseStream,
        // which deletes the entire H3Stream object. Accessing stream-> after the callback
        // would cause use-after-free.
        // Buffer memory is released when CloseStream deletes the H3Stream object.
        
        // Notify stream data callback that stream is finished (MUST be last!)
        if (on_stream_data_) {
            on_stream_data_(stream_id, nullptr, 0, true);
        }
    }
}

H3Stream* H3Handler::GetStream(uint64_t stream_id) {
    auto it = streams_.find(stream_id);
    return it != streams_.end() ? it->second.get() : nullptr;
}

bool H3Handler::HasStream(uint64_t stream_id) const {
    return streams_.find(stream_id) != streams_.end();
}

void H3Handler::CloseStream(uint64_t stream_id) {
    auto it = streams_.find(stream_id);
    if (it != streams_.end()) {
        it->second->state = StreamState::kClosed;
        streams_.erase(it);
    }
}

void H3Handler::SetPeerSettings(const SettingsFrame& settings) {
    peer_settings_ = settings;
    peer_settings_received_ = true;
}

} // namespace h3
} // namespace esp_http3

