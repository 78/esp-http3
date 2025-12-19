/**
 * @file loss_detector.cc
 * @brief Loss Detection Implementation
 */

#include "core/loss_detector.h"

#include <algorithm>
#include <cmath>
#include <esp_log.h>

#define TAG "LossDetector"

namespace esp_http3 {

//=============================================================================
// CongestionController
//=============================================================================

CongestionController::CongestionController() {
    Reset();
}

void CongestionController::Reset() {
    cwnd_ = kInitialCwnd;
    bytes_in_flight_ = 0;
    ssthresh_ = SIZE_MAX;
}

bool CongestionController::CanSend(size_t bytes) const {
    return bytes_in_flight_ + bytes <= cwnd_;
}

size_t CongestionController::GetCongestionWindow() const {
    return cwnd_ > bytes_in_flight_ ? cwnd_ - bytes_in_flight_ : 0;
}

void CongestionController::OnPacketSent(size_t bytes) {
    bytes_in_flight_ += bytes;
}

void CongestionController::OnPacketAcked(size_t bytes) {
    if (bytes > bytes_in_flight_) {
        bytes_in_flight_ = 0;
    } else {
        bytes_in_flight_ -= bytes;
    }
    
    // Increase congestion window
    if (cwnd_ < ssthresh_) {
        // Slow start
        cwnd_ += bytes;
    } else {
        // Congestion avoidance
        cwnd_ += kMaxDatagramSize * bytes / cwnd_;
    }
}

void CongestionController::OnPacketLost(size_t bytes) {
    if (bytes > bytes_in_flight_) {
        bytes_in_flight_ = 0;
    } else {
        bytes_in_flight_ -= bytes;
    }
    
    // Multiplicative decrease
    ssthresh_ = cwnd_ / 2;
    if (ssthresh_ < kMinCwnd) {
        ssthresh_ = kMinCwnd;
    }
    cwnd_ = ssthresh_;
}

//=============================================================================
// RttEstimator
//=============================================================================

RttEstimator::RttEstimator() {
    Reset();
}

void RttEstimator::Reset() {
    smoothed_rtt_ = kInitialRtt;
    rttvar_ = kInitialRtt / 2;
    min_rtt_ = UINT64_MAX;
    latest_rtt_ = 0;
    has_sample_ = false;
}

void RttEstimator::OnRttSample(uint64_t rtt_us, uint64_t ack_delay_us) {
    latest_rtt_ = rtt_us;
    
    // Update min_rtt
    if (rtt_us < min_rtt_) {
        min_rtt_ = rtt_us;
    }
    
    // Adjust for ack_delay
    uint64_t adjusted_rtt = rtt_us;
    if (rtt_us > min_rtt_ + ack_delay_us) {
        adjusted_rtt = rtt_us - ack_delay_us;
    }
    
    if (!has_sample_) {
        // First sample
        smoothed_rtt_ = adjusted_rtt;
        rttvar_ = adjusted_rtt / 2;
        has_sample_ = true;
    } else {
        // EWMA update (RFC 9002)
        // rttvar = 3/4 * rttvar + 1/4 * |smoothed_rtt - adjusted_rtt|
        int64_t diff = static_cast<int64_t>(smoothed_rtt_) - 
                       static_cast<int64_t>(adjusted_rtt);
        if (diff < 0) diff = -diff;
        rttvar_ = (3 * rttvar_ + static_cast<uint64_t>(diff)) / 4;
        
        // smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
        smoothed_rtt_ = (7 * smoothed_rtt_ + adjusted_rtt) / 8;
    }
}

//=============================================================================
// LossDetector
//=============================================================================

LossDetector::LossDetector() {
    Reset();
}

void LossDetector::Reset() {
    rtt_.Reset();
    cc_.Reset();
    last_ack_eliciting_time_us_ = 0;
    pto_count_ = 0;
}

void LossDetector::OnPacketSent(uint64_t pn, uint64_t sent_time_us, 
                                 size_t bytes, bool ack_eliciting) {
    if (ack_eliciting) {
        // RFC 9002: PTO is based on the EARLIEST unacked ACK-eliciting packet.
        // Only update last_ack_eliciting_time_us_ when there are NO unacked
        // ACK-eliciting packets (i.e., this is the first in a new burst).
        // 
        // When there are already unacked packets, we should keep the earliest
        // time to ensure proper PTO timeout calculation.
        bool is_first_in_burst = (last_ack_eliciting_time_us_ == 0);
        bool should_reset_rtt = false;
        
        if (is_first_in_burst) {
            // First ACK-eliciting packet after all previous have been ACKed
            pto_count_ = 0;
            last_ack_eliciting_time_us_ = sent_time_us;
            
            // Check if RTT is unreasonably high (> 5 seconds) and reset
            constexpr uint64_t kMaxReasonableRttUs = 5 * 1000 * 1000;  // 5 seconds
            if (rtt_.GetSmoothedRtt() > kMaxReasonableRttUs) {
                should_reset_rtt = true;
            }
        } else if (sent_time_us > last_ack_eliciting_time_us_) {
            // Check if idle for too long - reset RTT to avoid stale estimates
            uint64_t elapsed = sent_time_us - last_ack_eliciting_time_us_;
            constexpr uint64_t kIdleRttResetThresholdUs = 10 * 1000 * 1000;  // 10 seconds
            if (elapsed > kIdleRttResetThresholdUs) {
                should_reset_rtt = true;
            }
            // Do NOT update last_ack_eliciting_time_us_ here!
            // PTO must be based on the earliest unacked packet.
        }
        
        if (should_reset_rtt) {
            rtt_.Reset();
        }
        
        cc_.OnPacketSent(bytes);
    }
}

void LossDetector::OnAckReceived(uint64_t largest_acked, uint64_t ack_delay_us,
                                  uint64_t recv_time_us,
                                  SentPacketTracker* tracker) {
    // Reset PTO count on ACK
    pto_count_ = 0;
    
    // Find the sent packet info for RTT calculation
    auto unacked = tracker->GetUnackedPackets();
    for (auto* pkt : unacked) {
        if (pkt->packet_number == largest_acked) {
            // Calculate RTT
            if (recv_time_us > pkt->sent_time_us) {
                uint64_t rtt_sample = recv_time_us - pkt->sent_time_us;
                rtt_.OnRttSample(rtt_sample, ack_delay_us);
            }
            break;
        }
    }
    
    // Detect lost packets
    std::vector<SentPacketInfo*> lost_packets;
    
    uint64_t loss_delay = static_cast<uint64_t>(
        std::max(rtt_.GetLatestRtt(), rtt_.GetSmoothedRtt()) * kTimeThreshold);
    if (loss_delay < 1000) {  // Minimum 1ms
        loss_delay = 1000;
    }
    
    for (auto* pkt : unacked) {
        if (pkt->packet_number >= largest_acked) {
            continue;  // Not yet acked, check later
        }
        
        // Packet threshold loss
        if (largest_acked >= pkt->packet_number + kPacketThreshold) {
            lost_packets.push_back(pkt);
            continue;
        }
        
        // Time threshold loss
        if (recv_time_us > pkt->sent_time_us + loss_delay) {
            lost_packets.push_back(pkt);
        }
    }
    
    // Process losses
    for (auto* pkt : lost_packets) {
        tracker->MarkLost(pkt->packet_number);
        cc_.OnPacketLost(pkt->sent_bytes);
    }
    
    if (!lost_packets.empty() && on_loss_) {
        on_loss_(lost_packets);
    }
    
    // RFC 9002: Update PTO timer based on the earliest unacked ACK-eliciting packet
    // After processing ACK, find the earliest remaining unacked ACK-eliciting packet
    // to set the correct PTO base time
    auto remaining_unacked = tracker->GetUnackedPackets();
    uint64_t earliest_ack_eliciting_time = 0;
    
    for (auto* pkt : remaining_unacked) {
        // Only consider ACK-eliciting packets that are still in flight
        // Also check if frames are not empty (cleared frames = cancelled stream)
        if (pkt->ack_eliciting && pkt->in_flight && !pkt->lost && !pkt->frames.empty()) {
            if (earliest_ack_eliciting_time == 0 || 
                pkt->sent_time_us < earliest_ack_eliciting_time) {
                earliest_ack_eliciting_time = pkt->sent_time_us;
            }
        }
    }
    
    // Update or clear PTO timer
    // If no more ACK-eliciting packets in flight, clear PTO state completely
    if (earliest_ack_eliciting_time == 0) {
        ClearPtoTimer();
    } else {
    last_ack_eliciting_time_us_ = earliest_ack_eliciting_time;
    }
}

bool LossDetector::OnTimerTick(uint64_t current_time_us) {
    if (last_ack_eliciting_time_us_ == 0) {
        return false;
    }
    
    uint64_t pto = GetPtoTimeout();
    uint64_t deadline = last_ack_eliciting_time_us_ + pto * (1ULL << pto_count_);
    
    if (current_time_us >= deadline) {
        pto_count_++;
        if (on_pto_) {
            on_pto_();
        }
        return true;
    }
    
    return false;
}

uint64_t LossDetector::GetPtoTimeout() const {
    // PTO = smoothed_rtt + max(4*rttvar, 1ms) + max_ack_delay
    uint64_t srtt = rtt_.GetSmoothedRtt();
    uint64_t rttvar = rtt_.GetRttVar();
    
    uint64_t rttvar_contribution = 4 * rttvar;
    if (rttvar_contribution < 1000) {
        rttvar_contribution = 1000;  // Minimum 1ms
    }
    
    uint64_t pto = srtt + rttvar_contribution + max_ack_delay_us_;
    
    return pto;
}

uint64_t LossDetector::GetTimeUntilNextPto(uint64_t current_time_us) const {
    if (last_ack_eliciting_time_us_ == 0) {
        return 0;  // No pending PTO
    }
    
    uint64_t pto = GetPtoTimeout();
    uint64_t deadline = last_ack_eliciting_time_us_ + pto * (1ULL << pto_count_);
    
    if (current_time_us >= deadline) {
        return 0;  // PTO already expired
    }
    
    return deadline - current_time_us;
}

} // namespace esp_http3

