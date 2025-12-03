/**
 * @file ack_manager.cc
 * @brief ACK Management Implementation
 * 
 * Refactored to match Python implementation with proper:
 * - Duplicate packet detection
 * - ACK delay encoding with ack_delay_exponent
 * - Multi-range ACK support
 */

#include "client/ack_manager.h"
#include "quic/quic_frame.h"

#include <algorithm>

namespace esp_http3 {

//=============================================================================
// AckManager
//=============================================================================

AckManager::AckManager() {
    Reset();
}

void AckManager::Reset() {
    received_packets_.clear();
    largest_received_ = -1;
    largest_received_time_us_ = 0;
    ack_eliciting_count_ = 0;
    ack_delay_exponent_ = 3;  // Default: 2^3 = 8 microseconds
}

void AckManager::OnPacketReceived(uint64_t pn, uint64_t recv_time_us) {
    // Check for duplicate packet (like Python version)
    if (received_packets_.count(pn) > 0) {
        return;  // Duplicate packet, ignore
    }
    
    // Track packet number
    received_packets_.insert(pn);
    
    // Update largest received (only for new packets)
    if (static_cast<int64_t>(pn) > largest_received_) {
        largest_received_ = static_cast<int64_t>(pn);
        largest_received_time_us_ = recv_time_us;
    }
    
    // Prune old packets if needed
    while (received_packets_.size() > kMaxTrackedPackets) {
        received_packets_.erase(received_packets_.begin());
    }
    
    // Increment ack-eliciting count (only for non-duplicate packets)
    ack_eliciting_count_++;
}

bool AckManager::ShouldSendAck() const {
    // Send ACK after receiving 2 ack-eliciting packets (RFC 9002)
    return ack_eliciting_count_ >= 2;
}

bool AckManager::ShouldSendAck(uint64_t current_time_us) const {
    // RFC 9002: Send ACK after receiving 2+ ack-eliciting packets
    if (ack_eliciting_count_ >= 2) {
        return true;
    }
    
    // RFC 9002: Send ACK after max_ack_delay if 1+ ack-eliciting packet received
    if (ack_eliciting_count_ >= 1 && largest_received_time_us_ > 0) {
        if (current_time_us >= largest_received_time_us_ + kMaxAckDelayUs) {
            return true;
        }
    }
    
    return false;
}

uint64_t AckManager::GetAckDeadlineUs() const {
    if (ack_eliciting_count_ == 0 || largest_received_time_us_ == 0) {
        return 0;  // No pending ACK
    }
    
    // If 2+ packets, ACK should be sent immediately
    if (ack_eliciting_count_ >= 2) {
        return largest_received_time_us_;  // Already past deadline
    }
    
    // Return the time when max_ack_delay will expire
    return largest_received_time_us_ + kMaxAckDelayUs;
}

int64_t AckManager::GetLargestReceived() const {
    return largest_received_;
}

/**
 * @brief Get ACK ranges sorted by descending packet number
 * 
 * Returns ranges as vector of (largest, smallest) tuples.
 * Matches Python's PacketTracker.get_ack_ranges() implementation.
 */
static std::vector<std::pair<uint64_t, uint64_t>> GetAckRanges(
    const std::set<uint64_t>& received_packets) {
    
    std::vector<std::pair<uint64_t, uint64_t>> ranges;
    
    if (received_packets.empty()) {
        return ranges;
    }
    
    // Convert to sorted vector (descending order)
    std::vector<uint64_t> sorted_pns(received_packets.rbegin(), received_packets.rend());
    
    uint64_t range_largest = sorted_pns[0];
    uint64_t range_smallest = sorted_pns[0];
    
    for (size_t i = 1; i < sorted_pns.size(); i++) {
        if (sorted_pns[i] == range_smallest - 1) {
            // Contiguous - extend range
            range_smallest = sorted_pns[i];
        } else {
            // Gap found - save current range and start new one
            ranges.push_back({range_largest, range_smallest});
            range_largest = sorted_pns[i];
            range_smallest = sorted_pns[i];
        }
    }
    
    // Don't forget the last range
    ranges.push_back({range_largest, range_smallest});
    
    return ranges;
}

bool AckManager::BuildAckFrame(quic::BufferWriter* writer, uint64_t current_time_us) {
    if (largest_received_ < 0 || received_packets_.empty()) {
        return false;
    }
    
    // Calculate ACK delay with ack_delay_exponent encoding (like Python version)
    uint64_t ack_delay_us = 0;
    if (current_time_us > largest_received_time_us_) {
        ack_delay_us = current_time_us - largest_received_time_us_;
    }
    // Encode ACK delay: delay_microseconds >> ack_delay_exponent
    uint64_t encoded_ack_delay = ack_delay_us >> ack_delay_exponent_;
    
    // Get ACK ranges (like Python's get_ack_ranges)
    std::vector<std::pair<uint64_t, uint64_t>> ranges = GetAckRanges(received_packets_);
    
    if (ranges.empty()) {
        return false;
    }
    
    // First ACK range: largest - smallest in first range
    // This is: largest_ack - first_ack_range = smallest in first range
    uint64_t first_ack_range = ranges[0].first - ranges[0].second;
    
    // Build additional ACK ranges for QUIC frame format
    // QUIC ACK frame format uses (gap, ack_range_length) pairs
    // Gap = packets NOT received between ranges
    // ack_range_length = packets in range - 1
    std::vector<std::pair<uint64_t, uint64_t>> ack_ranges;
    
    for (size_t i = 1; i < ranges.size(); i++) {
        // Previous range ends at ranges[i-1].second
        // Current range starts at ranges[i].first
        // Gap = (prev_smallest - 1) - current_largest - 1
        //     = prev_smallest - current_largest - 2
        uint64_t prev_smallest = ranges[i - 1].second;
        uint64_t curr_largest = ranges[i].first;
        
        // Gap is number of missing packets minus 2 (RFC 9000)
        uint64_t gap = prev_smallest - curr_largest - 2;
        
        // ACK range length = largest - smallest in this range
        uint64_t ack_range_len = ranges[i].first - ranges[i].second;
        
        ack_ranges.push_back({gap, ack_range_len});
    }
    
    return quic::BuildAckFrame(writer,
                               static_cast<uint64_t>(largest_received_),
                               encoded_ack_delay,
                               first_ack_range,
                               ack_ranges);
}

void AckManager::OnAckSent() {
    ack_eliciting_count_ = 0;
    
    // Prune old packet numbers to reduce memory usage
    // Keep a reasonable window for duplicate detection (peer may retransmit if ACK was lost)
    // Use half of kMaxTrackedPackets to balance memory usage and duplicate detection
    constexpr size_t kPruneThreshold = kMaxTrackedPackets / 2;  // 128
    
    if (largest_received_ >= 0 && received_packets_.size() > kPruneThreshold) {
        // Keep packets within a window from largest_received_
        // This handles: duplicate detection, out-of-order ACKs, and reordering
        uint64_t threshold = static_cast<uint64_t>(largest_received_) > kPruneThreshold 
                           ? static_cast<uint64_t>(largest_received_) - kPruneThreshold 
                           : 0;
        auto it = received_packets_.begin();
        while (it != received_packets_.end() && *it < threshold) {
            it = received_packets_.erase(it);
        }
    }
}

//=============================================================================
// SentPacketTracker
//=============================================================================

SentPacketTracker::SentPacketTracker() {
    Reset();
}

void SentPacketTracker::Reset() {
    sent_packets_.clear();
    next_packet_number_ = 0;
    largest_acked_ = -1;
    latest_rtt_us_ = 0;
}

void SentPacketTracker::OnPacketSent(uint64_t pn, uint64_t sent_time_us,
                                      size_t sent_bytes, bool ack_eliciting,
                                      std::vector<uint8_t> frames) {
    SentPacketInfo info;
    info.packet_number = pn;
    info.sent_time_us = sent_time_us;
    info.sent_bytes = sent_bytes;
    info.ack_eliciting = ack_eliciting;
    info.in_flight = ack_eliciting;
    info.frames = std::move(frames);
    
    sent_packets_.push_back(std::move(info));
    
    // Update next packet number
    if (pn >= next_packet_number_) {
        next_packet_number_ = pn + 1;
    }
    
    // Prune old packets
    if (sent_packets_.size() > kMaxSentPackets) {
        PruneOldPackets();
    }
}

bool SentPacketTracker::OnAckReceived(uint64_t largest_acked,
                                       uint64_t ack_delay,
                                       uint64_t first_ack_range,
                                       const std::vector<std::pair<uint64_t, uint64_t>>& ack_ranges,
                                       uint64_t current_time_us,
                                       size_t* newly_acked_bytes) {
    *newly_acked_bytes = 0;
    bool any_acked = false;
    
    // Calculate range of acknowledged packets
    uint64_t ack_start = largest_acked;
    uint64_t ack_end = largest_acked >= first_ack_range ? 
                       largest_acked - first_ack_range : 0;
    
    for (auto& pkt : sent_packets_) {
        if (pkt.acknowledged || pkt.lost) {
            continue;
        }
        
        // Check if packet is in first ACK range
        if (pkt.packet_number >= ack_end && pkt.packet_number <= ack_start) {
            pkt.acknowledged = true;
            pkt.in_flight = false;
            *newly_acked_bytes += pkt.sent_bytes;
            any_acked = true;
            
            // Release frames data to free memory (no longer needed for retransmission)
            // Use swap trick for guaranteed memory release (shrink_to_fit is non-binding)
            std::vector<uint8_t>().swap(pkt.frames);
            
            // Update RTT from largest acked
            if (pkt.packet_number == largest_acked) {
                if (current_time_us > pkt.sent_time_us) {
                    latest_rtt_us_ = current_time_us - pkt.sent_time_us;
                }
            }
        }
        
        // TODO: Handle additional ACK ranges
    }
    
    // Update largest acked
    if (static_cast<int64_t>(largest_acked) > largest_acked_) {
        largest_acked_ = static_cast<int64_t>(largest_acked);
    }
    
    // Note: PruneOldPackets is called in OnPacketSent when exceeding kMaxSentPackets.
    // The main memory (frames) is already released above via swap trick.
    
    return any_acked;
}

std::vector<SentPacketInfo*> SentPacketTracker::GetUnackedPackets() {
    std::vector<SentPacketInfo*> result;
    for (auto& pkt : sent_packets_) {
        if (!pkt.acknowledged && !pkt.lost && pkt.in_flight) {
            result.push_back(&pkt);
        }
    }
    return result;
}

void SentPacketTracker::MarkLost(uint64_t pn) {
    for (auto& pkt : sent_packets_) {
        if (pkt.packet_number == pn) {
            pkt.lost = true;
            pkt.in_flight = false;
            break;
        }
    }
}

void SentPacketTracker::PruneOldPackets() {
    // Remove acknowledged/lost packets
    sent_packets_.erase(
        std::remove_if(sent_packets_.begin(), sent_packets_.end(),
                       [](const SentPacketInfo& p) {
                           return p.acknowledged || p.lost;
                       }),
        sent_packets_.end());
}

} // namespace esp_http3

