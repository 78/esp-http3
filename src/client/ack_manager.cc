/**
 * @file ack_manager.cc
 * @brief ACK Management Implementation
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
}

void AckManager::OnPacketReceived(uint64_t pn, uint64_t recv_time_us) {
    // Update largest received
    if (static_cast<int64_t>(pn) > largest_received_) {
        largest_received_ = static_cast<int64_t>(pn);
        largest_received_time_us_ = recv_time_us;
    }
    
    // Track packet number
    received_packets_.insert(pn);
    
    // Prune old packets if needed
    while (received_packets_.size() > kMaxTrackedPackets) {
        received_packets_.erase(received_packets_.begin());
    }
    
    // Increment ack-eliciting count (assuming all packets are ack-eliciting)
    ack_eliciting_count_++;
}

bool AckManager::ShouldSendAck() const {
    // Send ACK after receiving 2 ack-eliciting packets (RFC 9002)
    return ack_eliciting_count_ >= 2;
}

int64_t AckManager::GetLargestReceived() const {
    return largest_received_;
}

bool AckManager::BuildAckFrame(quic::BufferWriter* writer, uint64_t current_time_us) {
    if (largest_received_ < 0 || received_packets_.empty()) {
        return false;
    }
    
    // Calculate ACK delay
    uint64_t ack_delay_us = 0;
    if (current_time_us > largest_received_time_us_) {
        ack_delay_us = current_time_us - largest_received_time_us_;
    }
    
    // Build ACK ranges from received packets
    std::vector<std::pair<uint64_t, uint64_t>> ack_ranges;
    uint64_t first_ack_range = 0;
    
    // Convert set to sorted vector (descending order)
    std::vector<uint64_t> packets(received_packets_.rbegin(), received_packets_.rend());
    
    if (!packets.empty()) {
        // First range: from largest_received
        uint64_t range_start = packets[0];
        uint64_t range_end = packets[0];
        
        for (size_t i = 1; i < packets.size(); i++) {
            if (packets[i] == range_end - 1) {
                // Contiguous
                range_end = packets[i];
            } else {
                // Gap found
                if (ack_ranges.empty()) {
                    // First range
                    first_ack_range = range_start - range_end;
                } else {
                    // Additional range
                    uint64_t prev_end = ack_ranges.empty() ? 
                                        (static_cast<uint64_t>(largest_received_) - first_ack_range) :
                                        (ack_ranges.back().first - ack_ranges.back().second - 1);
                    uint64_t gap = prev_end - range_start - 1;
                    ack_ranges.push_back({gap, range_start - range_end});
                }
                range_start = packets[i];
                range_end = packets[i];
            }
        }
        
        // Handle last range
        if (ack_ranges.empty()) {
            first_ack_range = range_start - range_end;
        }
    }
    
    // Use simplified single-range ACK for now
    first_ack_range = 0;
    for (auto it = received_packets_.rbegin(); it != received_packets_.rend(); ++it) {
        if (*it == static_cast<uint64_t>(largest_received_) - first_ack_range) {
            first_ack_range++;
        } else {
            break;
        }
    }
    if (first_ack_range > 0) first_ack_range--;
    
    return quic::BuildAckFrame(writer,
                               static_cast<uint64_t>(largest_received_),
                               ack_delay_us,
                               first_ack_range,
                               {});  // Simplified: no additional ranges
}

void AckManager::OnAckSent() {
    ack_eliciting_count_ = 0;
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

