/**
 * @file quic_constants.h
 * @brief QUIC Protocol Constants (RFC 9000, RFC 9001)
 */

#pragma once

#include <cstdint>
#include <array>
#include <cstddef>

namespace esp_http3 {
namespace quic {

//=============================================================================
// QUIC Version
//=============================================================================

constexpr uint32_t kQuicVersion1 = 0x00000001;

//=============================================================================
// QUIC Initial Salt (RFC 9001)
//=============================================================================

// QUIC v1 initial salt for key derivation
constexpr std::array<uint8_t, 20> kQuicV1InitialSalt = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
};

//=============================================================================
// TLS 1.3 Fixed Constants
//=============================================================================

// Early Secret = HKDF-Extract(salt=0, IKM=0)
constexpr std::array<uint8_t, 32> kTls13EarlySecret = {
    0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b, 0x09, 0xe6,
    0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2, 0x10, 0xad, 0xf3, 0x00,
    0xaa, 0x1f, 0x26, 0x60, 0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70,
    0xf9, 0x2a
};

// Derived Secret = HKDF-Expand-Label(early_secret, "derived", empty_hash, 32)
constexpr std::array<uint8_t, 32> kTls13DerivedSecret = {
    0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5, 0x67, 0x8f,
    0x54, 0xfc, 0x9d, 0xba, 0xb6, 0x97, 0x16, 0xc0, 0x76, 0x18,
    0x9c, 0x48, 0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36,
    0x11, 0xba
};

//=============================================================================
// Packet Types
//=============================================================================

enum class PacketType : uint8_t {
    kInitial = 0,
    k0Rtt = 1,
    kHandshake = 2,
    kRetry = 3,
    k1Rtt = 4   // Short header (not a long header type)
};

//=============================================================================
// Frame Types (RFC 9000)
//=============================================================================

namespace frame {
    constexpr uint8_t kPadding = 0x00;
    constexpr uint8_t kPing = 0x01;
    constexpr uint8_t kAck = 0x02;
    constexpr uint8_t kAckEcn = 0x03;
    constexpr uint8_t kResetStream = 0x04;
    constexpr uint8_t kStopSending = 0x05;
    constexpr uint8_t kCrypto = 0x06;
    constexpr uint8_t kNewToken = 0x07;
    constexpr uint8_t kStreamBase = 0x08;
    constexpr uint8_t kMaxData = 0x10;
    constexpr uint8_t kMaxStreamData = 0x11;
    constexpr uint8_t kMaxStreamsBidi = 0x12;
    constexpr uint8_t kMaxStreamsUni = 0x13;
    constexpr uint8_t kDataBlocked = 0x14;
    constexpr uint8_t kStreamDataBlocked = 0x15;
    constexpr uint8_t kNewConnectionId = 0x18;
    constexpr uint8_t kRetireConnectionId = 0x19;
    constexpr uint8_t kPathChallenge = 0x1a;
    constexpr uint8_t kPathResponse = 0x1b;
    constexpr uint8_t kConnectionClose = 0x1c;
    constexpr uint8_t kConnectionCloseApp = 0x1d;
    constexpr uint8_t kHandshakeDone = 0x1e;
    constexpr uint8_t kDatagram = 0x30;
    constexpr uint8_t kDatagramLen = 0x31;
}

//=============================================================================
// Transport Parameters (RFC 9000 Section 18)
//=============================================================================

namespace transport_param {
    constexpr uint8_t kOriginalDestinationConnectionId = 0x00;
    constexpr uint8_t kMaxIdleTimeout = 0x01;
    constexpr uint8_t kStatelessResetToken = 0x02;
    constexpr uint8_t kMaxUdpPayloadSize = 0x03;
    constexpr uint8_t kInitialMaxData = 0x04;
    constexpr uint8_t kInitialMaxStreamDataBidiLocal = 0x05;
    constexpr uint8_t kInitialMaxStreamDataBidiRemote = 0x06;
    constexpr uint8_t kInitialMaxStreamDataUni = 0x07;
    constexpr uint8_t kInitialMaxStreamsBidi = 0x08;
    constexpr uint8_t kInitialMaxStreamsUni = 0x09;
    constexpr uint8_t kAckDelayExponent = 0x0a;
    constexpr uint8_t kMaxAckDelay = 0x0b;
    constexpr uint8_t kDisableActiveMigration = 0x0c;
    constexpr uint8_t kActiveConnectionIdLimit = 0x0e;
    constexpr uint8_t kInitialSourceConnectionId = 0x0f;
    constexpr uint8_t kMaxDatagramFrameSize = 0x20;
}

//=============================================================================
// Default Transport Parameter Values (optimized for embedded)
//=============================================================================

namespace defaults {
    // For embedded devices: BDP = 2Mbps × 200ms = 50KB, use 2×BDP = ~64KB
    constexpr uint32_t kMaxIdleTimeoutMs = 60000;
    constexpr uint32_t kInitialMaxData = 256*1024;
    constexpr uint32_t kInitialMaxStreamDataBidiLocal = kInitialMaxData;
    constexpr uint32_t kInitialMaxStreamDataBidiRemote = kInitialMaxData;
    constexpr uint32_t kInitialMaxStreamDataUni = kInitialMaxData;
    constexpr uint32_t kInitialMaxStreamsBidi = 8;
    constexpr uint32_t kInitialMaxStreamsUni = 8;
    constexpr uint8_t kAckDelayExponent = 3;
    constexpr uint32_t kMaxAckDelayMs = 25;
    constexpr uint32_t kActiveConnectionIdLimit = 2;
}

//=============================================================================
// Crypto Constants
//=============================================================================

constexpr size_t kAeadKeyLen = 16;       // AES-128-GCM key length
constexpr size_t kAeadIvLen = 12;        // AES-GCM nonce length
constexpr size_t kAeadTagLen = 16;       // AES-GCM auth tag length
constexpr size_t kHpKeyLen = 16;         // Header protection key length
constexpr size_t kTrafficSecretLen = 32; // SHA-256 output
constexpr size_t kMinPacketSize = 1200;  // Minimum QUIC packet size

} // namespace quic
} // namespace esp_http3

