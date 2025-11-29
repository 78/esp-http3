/**
 * @file ack_manager.h
 * @brief QUIC ACK Management
 * 
 * Tracks received packet numbers and generates ACK frames.
 */

#pragma once

#include "quic/quic_types.h"
#include "quic/quic_constants.h"
#include <cstdint>
#include <vector>
#include <set>

namespace esp_http3 {

/**
 * @brief Manages ACK state for one packet number space
 */
class AckManager {
public:
    AckManager();
    ~AckManager() = default;
    
    /**
     * @brief Record a received packet number
     * 
     * @param pn Packet number
     * @param recv_time_us Receive time in microseconds
     */
    void OnPacketReceived(uint64_t pn, uint64_t recv_time_us);
    
    /**
     * @brief Check if ACK should be sent
     * 
     * @return true if ACK is needed
     */
    bool ShouldSendAck() const;
    
    /**
     * @brief Get largest received packet number
     * 
     * @return Largest PN, or -1 if none received
     */
    int64_t GetLargestReceived() const;
    
    /**
     * @brief Build ACK frame for received packets
     * 
     * @param writer Buffer writer
     * @param current_time_us Current time in microseconds
     * @return true on success
     */
    bool BuildAckFrame(quic::BufferWriter* writer, uint64_t current_time_us);
    
    /**
     * @brief Mark that ACK was sent
     */
    void OnAckSent();
    
    /**
     * @brief Set ACK delay exponent (default: 3)
     */
    void SetAckDelayExponent(uint64_t exponent) { ack_delay_exponent_ = exponent; }
    
    /**
     * @brief Get ACK delay exponent
     */
    uint64_t GetAckDelayExponent() const { return ack_delay_exponent_; }
    
    /**
     * @brief Reset state
     */
    void Reset();

private:
    // Received packet numbers (for generating ACK ranges)
    std::set<uint64_t> received_packets_;
    
    // Largest received packet number
    int64_t largest_received_ = -1;
    
    // Time when largest_received was received (microseconds)
    uint64_t largest_received_time_us_ = 0;
    
    // Number of ack-eliciting packets received since last ACK
    uint32_t ack_eliciting_count_ = 0;
    
    // ACK delay exponent
    uint64_t ack_delay_exponent_ = 3;
    
    // Maximum packet numbers to track
    static constexpr size_t kMaxTrackedPackets = 256;
};

/**
 * @brief Manages sent packets for ACK processing and loss detection
 */
struct SentPacketInfo {
    uint64_t packet_number = 0;
    uint64_t sent_time_us = 0;
    size_t sent_bytes = 0;
    bool ack_eliciting = false;
    bool in_flight = true;
    bool acknowledged = false;
    bool lost = false;
    
    // Frames in this packet (for retransmission)
    std::vector<uint8_t> frames;
};

/**
 * @brief Sent packet tracker for one packet number space
 */
class SentPacketTracker {
public:
    SentPacketTracker();
    ~SentPacketTracker() = default;
    
    /**
     * @brief Record a sent packet
     * 
     * @param pn Packet number
     * @param sent_time_us Send time
     * @param sent_bytes Bytes sent
     * @param ack_eliciting True if packet is ack-eliciting
     * @param frames Frames in the packet (for potential retransmission)
     */
    void OnPacketSent(uint64_t pn, uint64_t sent_time_us, 
                      size_t sent_bytes, bool ack_eliciting,
                      std::vector<uint8_t> frames = {});
    
    /**
     * @brief Process received ACK frame
     * 
     * @param largest_acked Largest acknowledged packet number
     * @param ack_delay ACK delay from peer
     * @param first_ack_range First ACK range
     * @param ack_ranges Additional ACK ranges
     * @param current_time_us Current time
     * @param newly_acked_bytes Output: bytes newly acknowledged
     * @return true if any packets were newly acknowledged
     */
    bool OnAckReceived(uint64_t largest_acked, 
                       uint64_t ack_delay,
                       uint64_t first_ack_range,
                       const std::vector<std::pair<uint64_t, uint64_t>>& ack_ranges,
                       uint64_t current_time_us,
                       size_t* newly_acked_bytes);
    
    /**
     * @brief Get largest acked packet number
     */
    int64_t GetLargestAcked() const { return largest_acked_; }
    
    /**
     * @brief Get next packet number to send
     */
    uint64_t GetNextPacketNumber() const { return next_packet_number_; }
    
    /**
     * @brief Increment and return next packet number
     */
    uint64_t AllocatePacketNumber() { return next_packet_number_++; }
    
    /**
     * @brief Get sent packets that may need retransmission
     */
    std::vector<SentPacketInfo*> GetUnackedPackets();
    
    /**
     * @brief Mark packet as lost
     */
    void MarkLost(uint64_t pn);
    
    /**
     * @brief Remove acknowledged/lost packets older than threshold
     */
    void PruneOldPackets();
    
    /**
     * @brief Reset state
     */
    void Reset();
    
    /**
     * @brief Get RTT sample from last ACK (0 if none)
     */
    uint64_t GetLatestRttUs() const { return latest_rtt_us_; }

private:
    std::vector<SentPacketInfo> sent_packets_;
    uint64_t next_packet_number_ = 0;
    int64_t largest_acked_ = -1;
    uint64_t latest_rtt_us_ = 0;
    
    static constexpr size_t kMaxSentPackets = 256;
};

} // namespace esp_http3

