/**
 * @file h3_constants.h
 * @brief HTTP/3 Protocol Constants (RFC 9114, RFC 9204)
 */

#pragma once

#include <cstdint>

namespace esp_http3 {
namespace h3 {

//=============================================================================
// HTTP/3 Frame Types (RFC 9114 Section 7.2)
//=============================================================================

namespace frame_type {
    constexpr uint64_t kData = 0x00;
    constexpr uint64_t kHeaders = 0x01;
    constexpr uint64_t kCancelPush = 0x03;
    constexpr uint64_t kSettings = 0x04;
    constexpr uint64_t kPushPromise = 0x05;
    constexpr uint64_t kGoaway = 0x07;
    constexpr uint64_t kMaxPushId = 0x0d;
}

//=============================================================================
// HTTP/3 Settings (RFC 9114 Section 7.2.4.1)
//=============================================================================

namespace settings {
    constexpr uint64_t kQpackMaxTableCapacity = 0x01;
    constexpr uint64_t kMaxFieldSectionSize = 0x06;
    constexpr uint64_t kQpackBlockedStreams = 0x07;
    constexpr uint64_t kEnableExtendedConnect = 0x08;  // RFC 9220
}

//=============================================================================
// HTTP/3 Stream Types (RFC 9114 Section 6.2)
//=============================================================================

namespace stream_type {
    constexpr uint64_t kControl = 0x00;
    constexpr uint64_t kPush = 0x01;
    constexpr uint64_t kQpackEncoder = 0x02;
    constexpr uint64_t kQpackDecoder = 0x03;
}

//=============================================================================
// HTTP/3 Error Codes (RFC 9114 Section 8.1)
//=============================================================================

namespace error {
    constexpr uint64_t kNoError = 0x100;
    constexpr uint64_t kGeneralProtocolError = 0x101;
    constexpr uint64_t kInternalError = 0x102;
    constexpr uint64_t kStreamCreationError = 0x103;
    constexpr uint64_t kClosedCriticalStream = 0x104;
    constexpr uint64_t kFrameUnexpected = 0x105;
    constexpr uint64_t kFrameError = 0x106;
    constexpr uint64_t kExcessiveLoad = 0x107;
    constexpr uint64_t kIdError = 0x108;
    constexpr uint64_t kSettingsError = 0x109;
    constexpr uint64_t kMissingSettings = 0x10a;
    constexpr uint64_t kRequestRejected = 0x10b;
    constexpr uint64_t kRequestCancelled = 0x10c;
    constexpr uint64_t kRequestIncomplete = 0x10d;
    constexpr uint64_t kMessageError = 0x10e;
    constexpr uint64_t kConnectError = 0x10f;
    constexpr uint64_t kVersionFallback = 0x110;
}

//=============================================================================
// QPACK Static Table (RFC 9204 Appendix A)
// Only includes commonly used entries for embedded use
//=============================================================================

struct QpackStaticEntry {
    const char* name;
    const char* value;
};

// First 15 entries of QPACK static table (most commonly used)
constexpr QpackStaticEntry kQpackStaticTable[] = {
    {":authority", ""},                   // 0
    {":path", "/"},                       // 1
    {"age", "0"},                         // 2
    {"content-disposition", ""},          // 3
    {"content-length", "0"},              // 4
    {"cookie", ""},                       // 5
    {"date", ""},                         // 6
    {"etag", ""},                         // 7
    {"if-modified-since", ""},            // 8
    {"if-none-match", ""},                // 9
    {"last-modified", ""},                // 10
    {"link", ""},                         // 11
    {"location", ""},                     // 12
    {"referer", ""},                      // 13
    {"set-cookie", ""},                   // 14
    {":method", "CONNECT"},               // 15
    {":method", "DELETE"},                // 16
    {":method", "GET"},                   // 17
    {":method", "HEAD"},                  // 18
    {":method", "OPTIONS"},               // 19
    {":method", "POST"},                  // 20
    {":method", "PUT"},                   // 21
    {":scheme", "http"},                  // 22
    {":scheme", "https"},                 // 23
    {":status", "103"},                   // 24
    {":status", "200"},                   // 25
    {":status", "304"},                   // 26
    {":status", "404"},                   // 27
    {":status", "503"},                   // 28
    {"accept", "*/*"},                    // 29
    {"accept", "application/dns-message"},// 30
    {"accept-encoding", "gzip, deflate, br"}, // 31
    {"accept-ranges", "bytes"},           // 32
    {"access-control-allow-headers", "cache-control"},  // 33
    {"access-control-allow-headers", "content-type"},   // 34
    {"access-control-allow-origin", "*"}, // 35
    {"cache-control", "max-age=0"},       // 36
    {"cache-control", "max-age=2592000"}, // 37
    {"cache-control", "max-age=604800"},  // 38
    {"cache-control", "no-cache"},        // 39
    {"cache-control", "no-store"},        // 40
    {"cache-control", "public, max-age=31536000"}, // 41
    {"content-encoding", "br"},           // 42
    {"content-encoding", "gzip"},         // 43
    {"content-type", "application/dns-message"}, // 44
    {"content-type", "application/javascript"}, // 45
    {"content-type", "application/json"}, // 46
    {"content-type", "application/x-www-form-urlencoded"}, // 47
    {"content-type", "image/gif"},        // 48
    {"content-type", "image/jpeg"},       // 49
    {"content-type", "image/png"},        // 50
    {"content-type", "text/css"},         // 51
    {"content-type", "text/html; charset=utf-8"}, // 52
    {"content-type", "text/plain"},       // 53
    {"content-type", "text/plain;charset=utf-8"}, // 54
    {"range", "bytes=0-"},                // 55
    {"strict-transport-security", "max-age=31536000"}, // 56
    {"strict-transport-security", "max-age=31536000; includesubdomains"}, // 57
    {"strict-transport-security", "max-age=31536000; includesubdomains; preload"}, // 58
    {"vary", "accept-encoding"},          // 59
    {"vary", "origin"},                   // 60
    {"x-content-type-options", "nosniff"}, // 61
    {"x-xss-protection", "1; mode=block"}, // 62
    {":status", "100"},                   // 63
    {":status", "204"},                   // 64
    {":status", "206"},                   // 65
    {":status", "302"},                   // 66
    {":status", "400"},                   // 67
    {":status", "403"},                   // 68
    {":status", "421"},                   // 69
    {":status", "425"},                   // 70
    {":status", "500"},                   // 71
    {"accept-language", ""},              // 72
    {"access-control-allow-credentials", "FALSE"}, // 73
    {"access-control-allow-credentials", "TRUE"},  // 74
    {"access-control-allow-methods", "get"},       // 75
    {"access-control-allow-methods", "get, post, options"}, // 76
    {"access-control-allow-methods", "options"},   // 77
    {"access-control-expose-headers", "content-length"}, // 78
    {"access-control-request-headers", "content-type"}, // 79
    {"access-control-request-method", "get"},      // 80
    {"access-control-request-method", "post"},     // 81
    {"alt-svc", "clear"},                 // 82
    {"authorization", ""},                // 83
    {"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"}, // 84
    {"early-data", "1"},                  // 85
    {"expect-ct", ""},                    // 86
    {"forwarded", ""},                    // 87
    {"if-range", ""},                     // 88
    {"origin", ""},                       // 89
    {"purpose", "prefetch"},              // 90
    {"server", ""},                       // 91
    {"timing-allow-origin", "*"},         // 92
    {"upgrade-insecure-requests", "1"},   // 93
    {"user-agent", ""},                   // 94
    {"x-forwarded-for", ""},              // 95
    {"x-frame-options", "deny"},          // 96
    {"x-frame-options", "sameorigin"},    // 97
};

constexpr size_t kQpackStaticTableSize = sizeof(kQpackStaticTable) / sizeof(kQpackStaticTable[0]);

} // namespace h3
} // namespace esp_http3

