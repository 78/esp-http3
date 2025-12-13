/**
 * @file esp_http3.h
 * @brief ESP32 QUIC/HTTP3 Client - Main Public API
 * 
 * This library provides a QUIC (RFC 9000) and HTTP/3 (RFC 9114) client
 * implementation for ESP32 platforms.
 * 
 * Features:
 * - QUIC v1 transport protocol
 * - TLS 1.3 handshake (using mbedtls)
 * - HTTP/3 request/response
 * - Stream multiplexing
 * - Flow control
 * - Loss detection and recovery
 * 
 * Design:
 * - Single-threaded event-driven model
 * - No std::thread, std::mutex, std::condition_variable needed
 * - User provides SendCallback for outgoing UDP data
 * - User calls ProcessReceivedData() for incoming UDP data
 * - User calls OnTimerTick() periodically for timeout handling
 * 
 * Usage:
 * @code
 * #include "esp_http3.h"
 * 
 * // Connect UDP first (external to this library)
 * auto udp = modem->CreateUdp(0);
 * udp->Connect("1.2.3.4", 443);
 * 
 * // Create QUIC connection with send callback
 * Udp* udp_ptr = udp.get();
 * esp_http3::QuicConfig config;
 * config.hostname = "example.com";
 * 
 * auto conn = std::make_unique<esp_http3::QuicConnection>(
 *     [udp_ptr](const uint8_t* data, size_t len) {
 *         return udp_ptr->Send(std::string((char*)data, len));
 *     },
 *     config
 * );
 * 
 * // Set callbacks
 * conn->SetOnConnected([]() { printf("Connected!\n"); });
 * conn->SetOnResponse([](int sid, const H3Response& r) { ... });
 * 
 * // Forward received UDP data to QUIC
 * udp->OnMessage([&conn](const std::string& data) {
 *     conn->ProcessReceivedData((uint8_t*)data.data(), data.size());
 * });
 * 
 * // Start handshake
 * conn->StartHandshake();
 * 
 * // Event loop
 * while (!connected) {
 *     conn->OnTimerTick(50);
 *     vTaskDelay(50);
 * }
 * 
 * // Send request
 * conn->SendRequest("GET", "/api/endpoint");
 * @endcode
 * 
 * @note This implementation does not support 0-RTT in v1.0
 * @note QPACK dynamic table is not used in v1.0
 */

#pragma once

#include "core/quic_connection.h"
#include "client/power_lock.h"
#include "client/http3_client.h"

// Re-export main types for convenience
namespace esp_http3 {

// Version information
constexpr uint32_t kQuicVersion = 0x00000001;  // QUIC v1

} // namespace esp_http3

