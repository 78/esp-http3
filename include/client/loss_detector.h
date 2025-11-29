/**
 * @file loss_detector.h
 * @brief QUIC Loss Detection and Congestion Control (RFC 9002)
 */

#pragma once

#include "client/ack_manager.h"
#include <cstdint>
#include <functional>

namespace esp_http3 {

/**
 * @brief Simple congestion controller (NewReno-like)
 */
class CongestionController {
public:
    CongestionController();
    ~CongestionController() = default;
    
    /**
     * @brief Reset to initial state
     */
    void Reset();
    
    /**
     * @brief Check if we can send bytes
     */
    bool CanSend(size_t bytes) const;
    
    /**
     * @brief Get available congestion window
     */
    size_t GetCongestionWindow() const;
    
    /**
     * @brief Record bytes sent
     */
    void OnPacketSent(size_t bytes);
    
    /**
     * @brief Record bytes acknowledged
     */
    void OnPacketAcked(size_t bytes);
    
    /**
     * @brief Record packet lost
     */
    void OnPacketLost(size_t bytes);
    
    /**
     * @brief Get bytes in flight
     */
    size_t GetBytesInFlight() const { return bytes_in_flight_; }

private:
    size_t cwnd_;                    // Congestion window
    size_t bytes_in_flight_;         // Bytes in flight
    size_t ssthresh_;                // Slow start threshold
    
    static constexpr size_t kInitialCwnd = 14720;  // 10 * 1472
    static constexpr size_t kMinCwnd = 2944;       // 2 * 1472
    static constexpr size_t kMaxDatagramSize = 1472;
};

/**
 * @brief RTT estimator
 */
class RttEstimator {
public:
    RttEstimator();
    ~RttEstimator() = default;
    
    /**
     * @brief Update RTT with new sample
     */
    void OnRttSample(uint64_t rtt_us, uint64_t ack_delay_us);
    
    /**
     * @brief Get smoothed RTT (microseconds)
     */
    uint64_t GetSmoothedRtt() const { return smoothed_rtt_; }
    
    /**
     * @brief Get RTT variance (microseconds)
     */
    uint64_t GetRttVar() const { return rttvar_; }
    
    /**
     * @brief Get minimum RTT (microseconds)
     */
    uint64_t GetMinRtt() const { return min_rtt_; }
    
    /**
     * @brief Get latest RTT (microseconds)
     */
    uint64_t GetLatestRtt() const { return latest_rtt_; }
    
    /**
     * @brief Reset state
     */
    void Reset();
    
    /**
     * @brief Check if RTT has been sampled
     */
    bool HasRttSample() const { return has_sample_; }

private:
    uint64_t smoothed_rtt_;    // Smoothed RTT
    uint64_t rttvar_;          // RTT variance
    uint64_t min_rtt_;         // Minimum RTT
    uint64_t latest_rtt_;      // Latest RTT sample
    bool has_sample_;
    
    static constexpr uint64_t kInitialRtt = 333000;  // 333ms initial
};

/**
 * @brief Loss detector
 */
class LossDetector {
public:
    using OnLossCallback = std::function<void(const std::vector<SentPacketInfo*>&)>;
    using OnPtoCallback = std::function<void()>;
    
    LossDetector();
    ~LossDetector() = default;
    
    /**
     * @brief Set callbacks
     */
    void SetOnLoss(OnLossCallback cb) { on_loss_ = std::move(cb); }
    void SetOnPto(OnPtoCallback cb) { on_pto_ = std::move(cb); }
    
    /**
     * @brief Record packet sent
     */
    void OnPacketSent(uint64_t pn, uint64_t sent_time_us, size_t bytes, 
                      bool ack_eliciting);
    
    /**
     * @brief Process ACK and detect losses
     */
    void OnAckReceived(uint64_t largest_acked, uint64_t ack_delay_us,
                       uint64_t recv_time_us,
                       SentPacketTracker* tracker);
    
    /**
     * @brief Timer tick - check for PTO
     * 
     * @param current_time_us Current time
     * @return true if PTO fired
     */
    bool OnTimerTick(uint64_t current_time_us);
    
    /**
     * @brief Get PTO timeout value (microseconds)
     */
    uint64_t GetPtoTimeout() const;
    
    /**
     * @brief Get RTT estimator
     */
    RttEstimator& GetRttEstimator() { return rtt_; }
    const RttEstimator& GetRttEstimator() const { return rtt_; }
    
    /**
     * @brief Get congestion controller
     */
    CongestionController& GetCongestionController() { return cc_; }
    const CongestionController& GetCongestionController() const { return cc_; }
    
    /**
     * @brief Reset state
     */
    void Reset();
    
    /**
     * @brief Set peer max_ack_delay
     */
    void SetMaxAckDelay(uint64_t max_ack_delay_ms) {
        max_ack_delay_us_ = max_ack_delay_ms * 1000;
    }

private:
    RttEstimator rtt_;
    CongestionController cc_;
    
    OnLossCallback on_loss_;
    OnPtoCallback on_pto_;
    
    uint64_t last_ack_eliciting_time_us_ = 0;
    uint64_t pto_count_ = 0;
    uint64_t max_ack_delay_us_ = 25000;  // 25ms default
    
    // Loss detection constants (RFC 9002)
    static constexpr uint64_t kPacketThreshold = 3;
    static constexpr double kTimeThreshold = 9.0 / 8.0;
};

} // namespace esp_http3

