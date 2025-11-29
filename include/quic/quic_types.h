/**
 * @file quic_types.h
 * @brief QUIC Basic Types and Utilities
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <string>

namespace esp_http3 {
namespace quic {

//=============================================================================
// Crypto Types
//=============================================================================

/// AES-128-GCM key (16 bytes)
using AeadKey = std::array<uint8_t, 16>;

/// AES-GCM IV/Nonce (12 bytes)
using AeadIv = std::array<uint8_t, 12>;

/// Header protection key (16 bytes)
using HpKey = std::array<uint8_t, 16>;

/// Traffic secret (32 bytes, SHA-256)
using TrafficSecret = std::array<uint8_t, 32>;

/// X25519 public key (32 bytes)
using X25519PublicKey = std::array<uint8_t, 32>;

/// X25519 private key (32 bytes)
using X25519PrivateKey = std::array<uint8_t, 32>;

/// Client random (32 bytes)
using ClientRandom = std::array<uint8_t, 32>;

/**
 * @brief Crypto secrets for one direction (client or server)
 */
struct CryptoSecrets {
    AeadKey key{};
    AeadIv iv{};
    HpKey hp{};
    TrafficSecret traffic_secret{};
    bool valid = false;
    
    void Clear() {
        key.fill(0);
        iv.fill(0);
        hp.fill(0);
        traffic_secret.fill(0);
        valid = false;
    }
};

//=============================================================================
// Connection ID
//=============================================================================

/// Maximum connection ID length
constexpr size_t kMaxConnectionIdLen = 20;

/**
 * @brief QUIC Connection ID
 */
struct ConnectionId {
    std::array<uint8_t, kMaxConnectionIdLen> data{};
    uint8_t length = 0;
    
    ConnectionId() = default;
    
    ConnectionId(const uint8_t* bytes, size_t len) {
        Set(bytes, len);
    }
    
    void Set(const uint8_t* bytes, size_t len) {
        length = static_cast<uint8_t>(len <= kMaxConnectionIdLen ? len : kMaxConnectionIdLen);
        for (size_t i = 0; i < length; ++i) {
            data[i] = bytes[i];
        }
    }
    
    const uint8_t* Data() const { return data.data(); }
    size_t Length() const { return length; }
    bool Empty() const { return length == 0; }
    
    bool operator==(const ConnectionId& other) const {
        if (length != other.length) return false;
        for (size_t i = 0; i < length; ++i) {
            if (data[i] != other.data[i]) return false;
        }
        return true;
    }
};

//=============================================================================
// Buffer Utilities
//=============================================================================

/**
 * @brief Simple buffer writer for building packets
 */
class BufferWriter {
public:
    explicit BufferWriter(uint8_t* buffer, size_t capacity)
        : buffer_(buffer), capacity_(capacity), offset_(0) {}
    
    bool WriteUint8(uint8_t value) {
        if (offset_ + 1 > capacity_) return false;
        buffer_[offset_++] = value;
        return true;
    }
    
    bool WriteUint16(uint16_t value) {
        if (offset_ + 2 > capacity_) return false;
        buffer_[offset_++] = static_cast<uint8_t>(value >> 8);
        buffer_[offset_++] = static_cast<uint8_t>(value & 0xFF);
        return true;
    }
    
    bool WriteUint32(uint32_t value) {
        if (offset_ + 4 > capacity_) return false;
        buffer_[offset_++] = static_cast<uint8_t>(value >> 24);
        buffer_[offset_++] = static_cast<uint8_t>((value >> 16) & 0xFF);
        buffer_[offset_++] = static_cast<uint8_t>((value >> 8) & 0xFF);
        buffer_[offset_++] = static_cast<uint8_t>(value & 0xFF);
        return true;
    }
    
    bool WriteBytes(const uint8_t* data, size_t len) {
        if (offset_ + len > capacity_) return false;
        for (size_t i = 0; i < len; ++i) {
            buffer_[offset_++] = data[i];
        }
        return true;
    }
    
    bool WriteVarint(uint64_t value);  // Implemented in quic_varint.cc
    
    size_t Offset() const { return offset_; }
    size_t Remaining() const { return capacity_ - offset_; }
    uint8_t* Data() { return buffer_; }
    const uint8_t* Data() const { return buffer_; }
    
    void Reset() { offset_ = 0; }
    void Seek(size_t offset) { offset_ = offset; }

private:
    uint8_t* buffer_;
    size_t capacity_;
    size_t offset_;
};

/**
 * @brief Simple buffer reader for parsing packets
 */
class BufferReader {
public:
    BufferReader(const uint8_t* data, size_t len)
        : data_(data), len_(len), offset_(0) {}
    
    bool ReadUint8(uint8_t* out) {
        if (offset_ + 1 > len_) return false;
        *out = data_[offset_++];
        return true;
    }
    
    bool ReadUint16(uint16_t* out) {
        if (offset_ + 2 > len_) return false;
        *out = (static_cast<uint16_t>(data_[offset_]) << 8) |
               static_cast<uint16_t>(data_[offset_ + 1]);
        offset_ += 2;
        return true;
    }
    
    bool ReadUint32(uint32_t* out) {
        if (offset_ + 4 > len_) return false;
        *out = (static_cast<uint32_t>(data_[offset_]) << 24) |
               (static_cast<uint32_t>(data_[offset_ + 1]) << 16) |
               (static_cast<uint32_t>(data_[offset_ + 2]) << 8) |
               static_cast<uint32_t>(data_[offset_ + 3]);
        offset_ += 4;
        return true;
    }
    
    bool ReadBytes(uint8_t* out, size_t len) {
        if (offset_ + len > len_) return false;
        for (size_t i = 0; i < len; ++i) {
            out[i] = data_[offset_++];
        }
        return true;
    }
    
    bool ReadVarint(uint64_t* out);  // Implemented in quic_varint.cc
    
    bool Skip(size_t len) {
        if (offset_ + len > len_) return false;
        offset_ += len;
        return true;
    }
    
    size_t Offset() const { return offset_; }
    size_t Remaining() const { return len_ - offset_; }
    const uint8_t* Current() const { return data_ + offset_; }
    const uint8_t* Data() const { return data_; }
    size_t Length() const { return len_; }
    
    void Seek(size_t offset) { offset_ = offset; }

private:
    const uint8_t* data_;
    size_t len_;
    size_t offset_;
};

//=============================================================================
// Time Utilities
//=============================================================================

/**
 * @brief Get current time in microseconds
 * 
 * Platform-specific implementation required.
 */
uint64_t GetCurrentTimeUs();

/**
 * @brief Get current time in milliseconds
 */
inline uint64_t GetCurrentTimeMs() {
    return GetCurrentTimeUs() / 1000;
}

} // namespace quic
} // namespace esp_http3

