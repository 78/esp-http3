/**
 * @file flow_controller.h
 * @brief QUIC Flow Control Management
 */

#pragma once

#include "quic/quic_types.h"
#include "quic/quic_constants.h"
#include <cstdint>
#include <unordered_map>

namespace esp_http3 {

/**
 * @brief Per-stream flow control state
 */
struct StreamFlowState {
    // Send side
    uint64_t send_offset = 0;       // Next offset to send
    uint64_t send_max = 0;          // Peer's MAX_STREAM_DATA
    
    // Receive side
    uint64_t recv_offset = 0;       // Highest offset received
    uint64_t recv_max = 0;          // Our MAX_STREAM_DATA sent
    uint64_t recv_max_sent = 0;     // Last MAX_STREAM_DATA we sent
    
    bool IsSendBlocked() const {
        return send_offset >= send_max;
    }
    
    uint64_t SendWindow() const {
        return send_max > send_offset ? send_max - send_offset : 0;
    }
};

/**
 * @brief Flow controller for connection and streams
 */
class FlowController {
public:
    FlowController();
    ~FlowController() = default;
    
    /**
     * @brief Initialize with limits
     * 
     * @param initial_max_data Initial connection-level MAX_DATA
     * @param initial_max_stream_data Initial per-stream MAX_STREAM_DATA
     */
    void Initialize(uint64_t initial_max_data, uint64_t initial_max_stream_data);
    
    //=========================================================================
    // Connection-level flow control
    //=========================================================================
    
    /**
     * @brief Update peer's connection-level MAX_DATA
     */
    void OnMaxDataReceived(uint64_t max_data);
    
    /**
     * @brief Check if connection is send-blocked
     */
    bool IsConnectionBlocked() const;
    
    /**
     * @brief Get available connection send window
     */
    uint64_t GetConnectionSendWindow() const;
    
    /**
     * @brief Record bytes sent (connection level)
     */
    void OnBytesSent(uint64_t bytes);
    
    /**
     * @brief Record bytes received (connection level)
     */
    void OnBytesReceived(uint64_t bytes);
    
    /**
     * @brief Check if we should send MAX_DATA
     */
    bool ShouldSendMaxData() const;
    
    /**
     * @brief Build MAX_DATA frame
     */
    bool BuildMaxDataFrame(quic::BufferWriter* writer);
    
    //=========================================================================
    // Stream-level flow control
    //=========================================================================
    
    /**
     * @brief Create flow state for new stream
     */
    void CreateStream(uint64_t stream_id, uint64_t initial_max = 0);
    
    /**
     * @brief Update peer's MAX_STREAM_DATA for a stream
     */
    void OnMaxStreamDataReceived(uint64_t stream_id, uint64_t max_data);
    
    /**
     * @brief Check if stream is send-blocked
     */
    bool IsStreamBlocked(uint64_t stream_id) const;
    
    /**
     * @brief Get available stream send window
     */
    uint64_t GetStreamSendWindow(uint64_t stream_id) const;
    
    /**
     * @brief Record bytes sent on stream
     */
    void OnStreamBytesSent(uint64_t stream_id, uint64_t bytes);
    
    /**
     * @brief Record bytes received on stream
     */
    void OnStreamBytesReceived(uint64_t stream_id, uint64_t bytes);
    
    /**
     * @brief Check if we should send MAX_STREAM_DATA
     */
    bool ShouldSendMaxStreamData(uint64_t stream_id) const;
    
    /**
     * @brief Build MAX_STREAM_DATA frame
     */
    bool BuildMaxStreamDataFrame(quic::BufferWriter* writer, uint64_t stream_id);
    
    /**
     * @brief Get stream flow state
     */
    StreamFlowState* GetStreamState(uint64_t stream_id);
    const StreamFlowState* GetStreamState(uint64_t stream_id) const;
    
    /**
     * @brief Remove stream state
     */
    void RemoveStream(uint64_t stream_id);
    
    /**
     * @brief Reset all state
     */
    void Reset();

private:
    // Connection-level state
    uint64_t conn_send_offset_ = 0;      // Total bytes sent
    uint64_t conn_send_max_ = 0;         // Peer's MAX_DATA
    uint64_t conn_recv_offset_ = 0;      // Total bytes received
    uint64_t conn_recv_max_ = 0;         // Our MAX_DATA
    uint64_t conn_recv_max_sent_ = 0;    // Last MAX_DATA we sent
    
    // Per-stream state
    std::unordered_map<uint64_t, StreamFlowState> streams_;
    
    // Initial limits
    uint64_t initial_max_data_ = quic::defaults::kInitialMaxData;
    uint64_t initial_max_stream_data_ = quic::defaults::kInitialMaxStreamDataBidiRemote;
    
    // Threshold for sending flow control updates (percentage of window consumed)
    static constexpr double kUpdateThreshold = 0.5;
};

} // namespace esp_http3

