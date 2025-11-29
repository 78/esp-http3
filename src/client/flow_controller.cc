/**
 * @file flow_controller.cc
 * @brief Flow Control Implementation
 */

#include "client/flow_controller.h"
#include "quic/quic_frame.h"

#include <algorithm>
#include "esp_log.h"

#define TAG "FlowController"

namespace esp_http3 {

FlowController::FlowController() {
    Reset();
}

void FlowController::Initialize(uint64_t initial_max_data, 
                                 uint64_t initial_max_stream_data) {
    initial_max_data_ = initial_max_data;
    initial_max_stream_data_ = initial_max_stream_data;
    conn_recv_max_ = initial_max_data;
    conn_recv_max_sent_ = initial_max_data;
}

void FlowController::Reset() {
    conn_send_offset_ = 0;
    conn_send_max_ = 0;
    conn_recv_offset_ = 0;
    conn_recv_max_ = quic::defaults::kInitialMaxData;
    conn_recv_max_sent_ = quic::defaults::kInitialMaxData;
    streams_.clear();
}

//=============================================================================
// Connection-level
//=============================================================================

void FlowController::OnMaxDataReceived(uint64_t max_data) {
    if (max_data > conn_send_max_) {
        conn_send_max_ = max_data;
    }
}

bool FlowController::IsConnectionBlocked() const {
    return conn_send_offset_ >= conn_send_max_;
}

uint64_t FlowController::GetConnectionSendWindow() const {
    return conn_send_max_ > conn_send_offset_ ? 
           conn_send_max_ - conn_send_offset_ : 0;
}

void FlowController::OnBytesSent(uint64_t bytes) {
    conn_send_offset_ += bytes;
}

void FlowController::OnBytesReceived(uint64_t bytes) {
    conn_recv_offset_ += bytes;
}

bool FlowController::ShouldSendMaxData() const {
    // Send MAX_DATA when we've consumed more than half the window
    // Compare against the last MAX_DATA we sent (conn_recv_max_sent_),
    // not the current limit (conn_recv_max_), to match Python implementation
    uint64_t consumed = conn_recv_offset_;
    uint64_t current_limit = conn_recv_max_sent_;
    return consumed >= current_limit * kUpdateThreshold;
}

bool FlowController::BuildMaxDataFrame(quic::BufferWriter* writer) {
    // Calculate new limit matching Python implementation:
    // new_limit = max(current_limit + initial_max_data, consumed + initial_max_data)
    uint64_t consumed = conn_recv_offset_;
    uint64_t current_limit = conn_recv_max_sent_;
    
    uint64_t new_limit = std::max(
        current_limit + initial_max_data_,
        consumed + initial_max_data_
    );
    
    if (!quic::BuildMaxDataFrame(writer, new_limit)) {
        return false;
    }
    
    conn_recv_max_ = new_limit;
    conn_recv_max_sent_ = new_limit;
    return true;
}

//=============================================================================
// Stream-level
//=============================================================================

void FlowController::CreateStream(uint64_t stream_id, uint64_t initial_max) {
    if (streams_.find(stream_id) != streams_.end()) {
        return;  // Already exists
    }
    
    StreamFlowState state;
    state.send_max = initial_max;
    state.recv_max = initial_max_stream_data_;
    state.recv_max_sent = initial_max_stream_data_;
    streams_[stream_id] = state;
}

void FlowController::OnMaxStreamDataReceived(uint64_t stream_id, uint64_t max_data) {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        CreateStream(stream_id, max_data);
        return;
    }
    
    if (max_data > it->second.send_max) {
        it->second.send_max = max_data;
    }
}

bool FlowController::IsStreamBlocked(uint64_t stream_id) const {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        return true;
    }
    return it->second.IsSendBlocked();
}

uint64_t FlowController::GetStreamSendWindow(uint64_t stream_id) const {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        return 0;
    }
    return it->second.SendWindow();
}

void FlowController::OnStreamBytesSent(uint64_t stream_id, uint64_t bytes) {
    auto it = streams_.find(stream_id);
    if (it != streams_.end()) {
        it->second.send_offset += bytes;
    }
    OnBytesSent(bytes);
}

void FlowController::OnStreamBytesReceived(uint64_t stream_id, uint64_t bytes) {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        // Create stream state if it doesn't exist (e.g., server-initiated streams)
        CreateStream(stream_id, 0);
        it = streams_.find(stream_id);
    }
    if (it != streams_.end()) {
        it->second.recv_offset += bytes;
    }
    OnBytesReceived(bytes);
}

bool FlowController::ShouldSendMaxStreamData(uint64_t stream_id) const {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        return false;
    }
    
    // Compare against the last MAX_STREAM_DATA we sent (recv_max_sent),
    // not the current limit (recv_max), to match Python implementation
    uint64_t consumed = it->second.recv_offset;
    uint64_t current_limit = it->second.recv_max_sent;
    // Use >= instead of > to trigger earlier (at exactly 50% instead of 50%+1)
    return consumed >= current_limit * kUpdateThreshold;
}

bool FlowController::BuildMaxStreamDataFrame(quic::BufferWriter* writer, 
                                              uint64_t stream_id) {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        return false;
    }
    
    // Calculate new limit matching Python implementation:
    // new_limit = max(current_limit + initial_max_stream_data, consumed + initial_max_stream_data)
    uint64_t consumed = it->second.recv_offset;
    uint64_t current_limit = it->second.recv_max_sent;
    
    uint64_t new_limit = std::max(
        current_limit + initial_max_stream_data_,
        consumed + initial_max_stream_data_
    );
    
    if (!quic::BuildMaxStreamDataFrame(writer, stream_id, new_limit)) {
        return false;
    }
    
    it->second.recv_max = new_limit;
    it->second.recv_max_sent = new_limit;
    return true;
}

StreamFlowState* FlowController::GetStreamState(uint64_t stream_id) {
    auto it = streams_.find(stream_id);
    return it != streams_.end() ? &it->second : nullptr;
}

const StreamFlowState* FlowController::GetStreamState(uint64_t stream_id) const {
    auto it = streams_.find(stream_id);
    return it != streams_.end() ? &it->second : nullptr;
}

void FlowController::RemoveStream(uint64_t stream_id) {
    streams_.erase(stream_id);
}

} // namespace esp_http3

