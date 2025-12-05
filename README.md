# ESP-HTTP3

A QUIC/HTTP3 client library for ESP32 platform, implementing RFC 9000 (QUIC) and RFC 9114 (HTTP/3) protocols.

## Features

- ✅ QUIC v1 transport protocol
- ✅ TLS 1.3 handshake (using mbedtls)
- ✅ HTTP/3 request/response
- ✅ Stream multiplexing
- ✅ Flow control
- ✅ Packet loss detection and recovery
- ✅ Single-threaded event-driven model, no multi-threading required

## Design Principles

- **User-provided transport layer**: Send UDP data through callback functions
- **User-driven event loop**: Call `ProcessReceivedData()` to process received data, call `OnTimerTick()` to drive timers

## Concurrent Test Example

The following is a concurrent test output example, demonstrating the ability to send two HTTP/3 requests simultaneously (`GET /` and `GET /pocket-sage/health`) on the same QUIC connection:

```
I (5003) HTTPS_DEMO: === QUIC/HTTP3 WiFi Concurrent Test Start ===
I (5003) HTTPS_DEMO: Target: api.tenclass.net:443
I (5003) HTTPS_DEMO: Testing concurrent requests: / and /pocket-sage/health
I (5013) HTTPS_DEMO: Resolved api.tenclass.net to 112.74.84.224
I (5013) HTTPS_DEMO: UDP socket connected
I (5013) HTTPS_DEMO: Starting QUIC handshake...
I (5093) HTTPS_DEMO: Waiting for handshake...
I (5123) wifi:<ba-add>idx:0 (ifx:0, c2:3d:2a:62:7b:3c), tid:0, ssn:1, winSize:64
I (5293) HTTPS_DEMO: >>> QUIC Connection established!
I (5303) HTTPS_DEMO: Sending concurrent HTTP/3 GET requests...
I (5303) HTTPS_DEMO: Sending request 1: GET /
I (5303) HTTPS_DEMO: Request 1 sent on stream 0
I (5303) HTTPS_DEMO: Sending request 2: GET /pocket-sage/health
I (5303) HTTPS_DEMO: Request 2 sent on stream 4
I (5303) HTTPS_DEMO: Waiting for responses (need 2 streams)...
I (5323) HTTPS_DEMO: >>> HTTP/3 Response on stream 0
I (5323) HTTPS_DEMO:     Status: 200
I (5323) HTTPS_DEMO:     Headers: 6
I (5323) HTTPS_DEMO:       date: Sat, 29 Nov 2025 02:55:28 GMT
I (5323) HTTPS_DEMO:       content-type: text/html
I (5323) HTTPS_DEMO:       content-length: 452
I (5323) HTTPS_DEMO:       last-modified: Thu
I (5323) HTTPS_DEMO:       etag: "60dd8909-1c4"
I (5323) HTTPS_DEMO:       accept-ranges: bytes
I (5323) HTTPS_DEMO:     Body size: 452 bytes
I (5323) HTTPS_DEMO:     Body preview: <!DOCTYPE html>
<html>
<head>
<title>HTTP Server Test Page</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</styl...
I (5323) HTTPS_DEMO:     Received responses: 1/2
I (5323) HTTPS_DEMO: >>> HTTP/3 Response on stream 4
I (5323) HTTPS_DEMO:     Status: 200
I (5323) HTTPS_DEMO:     Headers: 3
I (5323) HTTPS_DEMO:       date: Sat, 29 Nov 2025 02:55:28 GMT
I (5323) HTTPS_DEMO:       content-type: application/json; charset=utf-8
I (5323) HTTPS_DEMO:       content-length: 67
I (5323) HTTPS_DEMO:     Body size: 67 bytes
I (5323) HTTPS_DEMO:     Body preview: {"status":"ok","timestamp":1764384928659,"uptime":467252.919434436}
I (5323) HTTPS_DEMO:     Received responses: 2/2
I (5333) HTTPS_DEMO: === Connection Stats ===
I (5333) HTTPS_DEMO:   Packets sent: 13
I (5333) HTTPS_DEMO:   Packets received: 10
I (5333) HTTPS_DEMO:   Bytes sent: 1868
I (5333) HTTPS_DEMO:   Bytes received: 5881
I (5333) HTTPS_DEMO:   RTT: 72 ms
I (5333) HTTPS_DEMO: === Concurrent Test Results ===
I (5333) HTTPS_DEMO: === Test PASSED (both responses received) ===
I (5333) HTTPS_DEMO: Stream 0 (GET /): Status 200, Body size: 452 bytes
I (5333) HTTPS_DEMO: Stream 4 (GET /pocket-sage/health): Status 200, Body size: 67 bytes
I (5333) HTTPS_DEMO: >>> Disconnected: code=0, reason=
I (5333) HTTPS_DEMO: === QUIC/HTTP3 WiFi Concurrent Test Complete ===
```

Test results show:
- ✅ Successfully established QUIC connection
- ✅ Concurrently sent two requests on the same connection (Stream 0 and Stream 4)
- ✅ Both responses successfully received (both completed within 20ms)
- ✅ Connection statistics: 13 packets sent, 10 packets received

## WiFi Usage Example

The following example demonstrates how to use WiFi connection for QUIC/HTTP3 communication on ESP32:

```cpp
#include "esp_http3.h"
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <nvs_flash.h>
#include <esp_wifi.h>
#include <esp_netif.h>
#include <esp_event.h>
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>

static const char *TAG = "QUIC_DEMO";

// WiFi event group bit definitions
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static EventGroupHandle_t s_wifi_event_group;
static int s_retry_num = 0;
static const int WIFI_MAX_RETRY = 5;
static char s_ip_str[16] = {0};

/**
 * WiFi event handler
 */
static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < WIFI_MAX_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "Retry to connect to the AP");
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
        ESP_LOGI(TAG, "Connect to the AP fail");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        snprintf(s_ip_str, sizeof(s_ip_str), IPSTR, IP2STR(&event->ip_info.ip));
        ESP_LOGI(TAG, "Got IP: %s", s_ip_str);
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

/**
 * Initialize WiFi and wait for connection (using ESP-IDF standard API)
 */
static bool InitWifi(const char* ssid, const char* password) {
    ESP_LOGI(TAG, "Initializing WiFi...");
    
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    // Create event group
    s_wifi_event_group = xEventGroupCreate();
    
    // Initialize network interface
    ESP_ERROR_CHECK(esp_netif_init());
    
    // Create default event loop
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    // Create default WiFi Station network interface
    esp_netif_create_default_wifi_sta();
    
    // Initialize WiFi configuration
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    
    // Register event handlers
    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_got_ip));
    
    // Configure WiFi Station mode
    wifi_config_t wifi_config = {};
    strlcpy((char*)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
    strlcpy((char*)wifi_config.sta.password, password, sizeof(wifi_config.sta.password));
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wifi_config.sta.pmf_cfg.capable = true;
    wifi_config.sta.pmf_cfg.required = false;
    
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    
    ESP_LOGI(TAG, "WiFi initialization finished. Connecting to %s...", ssid);
    
    // Wait for connection to complete (30 second timeout)
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
                                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                           pdFALSE,
                                           pdFALSE,
                                           pdMS_TO_TICKS(30000));
    
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "WiFi connected! IP: %s", s_ip_str);
        return true;
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGE(TAG, "WiFi connection failed");
        return false;
    } else {
        ESP_LOGE(TAG, "WiFi connection timeout");
        return false;
    }
}

/**
 * QUIC/HTTP3 WiFi test function
 * 
 * Uses standard lwip socket for UDP communication
 */
void TestQuicHttp3Wifi(const char* hostname, uint16_t port, const char* path) {
    using namespace esp_http3;
    
    ESP_LOGI(TAG, "=== QUIC/HTTP3 WiFi Test Start ===");
    ESP_LOGI(TAG, "Target: %s:%u%s", hostname, port, path);
    
    // 1. DNS resolution
    struct hostent* he = gethostbyname(hostname);
    if (!he) {
        ESP_LOGE(TAG, "DNS lookup failed for %s", hostname);
        return;
    }
    
    struct in_addr* addr = (struct in_addr*)he->h_addr;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, addr, ip_str, sizeof(ip_str));
    ESP_LOGI(TAG, "Resolved %s to %s", hostname, ip_str);
    
    // 2. Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to create socket: %d", errno);
        return;
    }
    
    // Set non-blocking mode
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    // Server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr = *addr;
    
    // Connect (for UDP, this just sets the default destination address)
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "Failed to connect socket: %d", errno);
        close(sock);
        return;
    }
    ESP_LOGI(TAG, "UDP socket connected");
    
    // 3. Configure QUIC
    QuicConfig config;
    config.hostname = hostname;
    config.port = port;
    config.handshake_timeout_ms = 10000;
    config.idle_timeout_ms = 60000;
    config.enable_debug = false;
    
    // 4. Create QUIC connection, pass send callback
    auto conn = std::make_unique<QuicConnection>(
        // SendCallback: Send UDP data through socket
        [sock](const uint8_t* data, size_t len) -> int {
            int sent = send(sock, data, len, 0);
            if (sent < 0) {
                ESP_LOGW(TAG, "Socket send failed: %d", errno);
            }
            return sent;
        },
        config
    );
    
    // 5. Set event callbacks
    bool connected = false;
    bool response_received = false;
    int response_status = 0;
    std::string response_body;
    
    conn->SetOnConnected([&connected]() {
        ESP_LOGI(TAG, ">>> QUIC Connection established!");
        connected = true;
    });
    
    conn->SetOnResponse([&](int stream_id, const H3Response& resp) {
        ESP_LOGI(TAG, ">>> HTTP/3 Response on stream %d", stream_id);
        ESP_LOGI(TAG, "    Status: %d", resp.status);
        ESP_LOGI(TAG, "    Headers: %zu", resp.headers.size());
        for (const auto& h : resp.headers) {
            ESP_LOGI(TAG, "      %s: %s", h.first.c_str(), h.second.c_str());
        }
        ESP_LOGI(TAG, "    Body size: %zu bytes", resp.body.size());
        
        response_status = resp.status;
        if (!resp.body.empty()) {
            response_body.assign(resp.body.begin(), resp.body.end());
            std::string preview = response_body.substr(0, 200);
            ESP_LOGI(TAG, "    Body preview: %s%s", 
                     preview.c_str(), 
                     response_body.size() > 200 ? "..." : "");
        }
        response_received = true;
    });
    
    conn->SetOnDisconnected([](int code, const std::string& reason) {
        ESP_LOGI(TAG, ">>> Disconnected: code=%d, reason=%s", code, reason.c_str());
    });
    
    // 6. Start handshake
    ESP_LOGI(TAG, "Starting QUIC handshake...");
    if (!conn->StartHandshake()) {
        ESP_LOGE(TAG, "Failed to start handshake");
        close(sock);
        return;
    }
    
    // 7. Event loop parameters
    const int tick_interval_ms = 10;
    const TickType_t tick_wait = pdMS_TO_TICKS(tick_interval_ms);
    uint8_t recv_buffer[1500];
    
    // Helper: Execute one event loop iteration
    auto run_event_loop_once = [&]() {
        // Receive UDP data (non-blocking)
        while (true) {
            int recv_len = recv(sock, recv_buffer, sizeof(recv_buffer), 0);
            if (recv_len > 0) {
                conn->ProcessReceivedData(recv_buffer, recv_len);
            } else if (recv_len < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                ESP_LOGW(TAG, "Socket recv error: %d", errno);
                break;
            } else {
                break;  // No more data
            }
        }
        
        // Wait for one tick interval
        vTaskDelay(tick_wait);
        
        // Execute timer tick
        conn->OnTimerTick(tick_interval_ms);
    };
    
    // 8. Event loop: Wait for connection
    ESP_LOGI(TAG, "Waiting for handshake...");
    for (int wait_ms = 0; !connected && wait_ms < 20000; wait_ms += tick_interval_ms) {
        run_event_loop_once();
        if (wait_ms > 0 && wait_ms % 1000 == 0) {
            ESP_LOGI(TAG, "  Waiting... %d ms", wait_ms);
        }
    }
    
    if (!connected) {
        ESP_LOGE(TAG, "Handshake timeout");
        conn->Close();
        close(sock);
        return;
    }
    
    // 9. Send HTTP/3 GET request
    ESP_LOGI(TAG, "Sending HTTP/3 GET request to %s", path);
    int stream_id = conn->SendRequest("GET", path);
    if (stream_id < 0) {
        ESP_LOGE(TAG, "Failed to send request");
        conn->Close();
        close(sock);
        return;
    }
    ESP_LOGI(TAG, "Request sent on stream %d", stream_id);
    
    // 10. Event loop: Wait for response
    ESP_LOGI(TAG, "Waiting for response...");
    for (int wait_ms = 0; !response_received && wait_ms < 10000; wait_ms += tick_interval_ms) {
        run_event_loop_once();
        if (wait_ms > 0 && wait_ms % 1000 == 0) {
            ESP_LOGI(TAG, "  Waiting... %d ms", wait_ms);
        }
    }
    
    // 11. Print statistics
    auto stats = conn->GetStats();
    ESP_LOGI(TAG, "=== Connection Stats ===");
    ESP_LOGI(TAG, "  Packets sent: %lu", stats.packets_sent);
    ESP_LOGI(TAG, "  Packets received: %lu", stats.packets_received);
    ESP_LOGI(TAG, "  Bytes sent: %lu", stats.bytes_sent);
    ESP_LOGI(TAG, "  Bytes received: %lu", stats.bytes_received);
    ESP_LOGI(TAG, "  RTT: %lu ms", stats.rtt_ms);
    
    // 12. Check results
    if (response_received) {
        ESP_LOGI(TAG, "=== Test PASSED ===");
        ESP_LOGI(TAG, "HTTP Status: %d", response_status);
    } else {
        ESP_LOGW(TAG, "=== Test INCOMPLETE (no response) ===");
    }
    
    // 13. Graceful shutdown
    conn->Close();
    close(sock);
    
    ESP_LOGI(TAG, "=== QUIC/HTTP3 WiFi Test Complete ===");
}

extern "C" void app_main(void) {
    // Note: The stack size of the app_main task needs to be configured in sdkconfig
    // Set CONFIG_ESP_MAIN_TASK_STACK_SIZE to at least 8192 (8KB)
    // Or when creating an independent task, use xTaskCreate() and specify at least 8192 bytes of stack
    
    ESP_LOGI(TAG, "QUIC/HTTP3 Demo Starting...");
    
    // Initialize and connect WiFi (using ESP-IDF standard API)
    if (!InitWifi("YOUR_SSID", "YOUR_PASSWORD")) {
        ESP_LOGE(TAG, "Failed to connect WiFi");
        return;
    }
    
    // Test QUIC/HTTP3 client (using WiFi + BSD socket)
    TestQuicHttp3Wifi("api.tenclass.net", 443, "/pocket-sage/health");
    
    ESP_LOGI(TAG, "Demo completed");
    
    // Keep running
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
```

## Key Steps Explanation

1. **WiFi Initialization**: Initialize and connect WiFi using ESP-IDF standard WiFi API (`esp_wifi_init`, `esp_wifi_set_config`, `esp_wifi_start`, `esp_wifi_connect`)
2. **DNS Resolution**: Use `gethostbyname()` to resolve hostname
3. **UDP Socket Creation**: Create non-blocking UDP socket and connect to server
4. **QUIC Connection Configuration**: Create `QuicConfig` and set hostname, port, and other parameters
5. **Create QuicConnection**: Pass send callback function (send data through socket)
6. **Set Event Callbacks**: Set callbacks for connection, response, and disconnection
7. **Start Handshake**: Call `StartHandshake()` to initiate QUIC handshake
8. **Event Loop**:
   - Receive UDP data and call `ProcessReceivedData()`
   - Periodically call `OnTimerTick()` to drive timers
   - Wait for handshake completion
9. **Send Request**: After handshake completes, call `SendRequest()` to send HTTP/3 request
10. **Wait for Response**: Wait for response callback in event loop
11. **Cleanup Resources**: Close connection and socket

## Output Example

```
I (3993) QUIC_DEMO: === QUIC/HTTP3 WiFi Test Start ===
I (3993) QUIC_DEMO: Target: api.tenclass.net:443/pocket-sage/health
I (3993) QUIC_DEMO: Resolved api.tenclass.net to 112.74.84.224
I (3993) QUIC_DEMO: UDP socket connected
I (3993) QUIC_DEMO: Starting QUIC handshake...
I (4213) QUIC_DEMO: >>> QUIC Connection established!
I (4233) QUIC_DEMO: Sending HTTP/3 GET request to /pocket-sage/health
I (4233) QUIC_DEMO: Request sent on stream 0
I (4253) QUIC_DEMO: >>> HTTP/3 Response on stream 0
I (4253) QUIC_DEMO:     Status: 200
I (4253) QUIC_DEMO:     Headers: 3
I (4253) QUIC_DEMO:       date: Sat, 29 Nov 2025 02:38:53 GMT
I (4253) QUIC_DEMO:       content-type: application/json; charset=utf-8
I (4253) QUIC_DEMO:       content-length: 67
I (4253) QUIC_DEMO:     Body size: 67 bytes
I (4253) QUIC_DEMO:     Body preview: {"status":"ok","timestamp":1764383933053,"uptime":466257.313353636}
I (4263) QUIC_DEMO: === Connection Stats ===
I (4263) QUIC_DEMO:   Packets sent: 11
I (4263) QUIC_DEMO:   Packets received: 8
I (4263) QUIC_DEMO:   Bytes sent: 1759
I (4263) QUIC_DEMO:   Bytes received: 5248
I (4263) QUIC_DEMO:   RTT: 74 ms
I (4263) QUIC_DEMO: === Test PASSED ===
I (4263) QUIC_DEMO: HTTP Status: 200
```

## API Reference

Main API interfaces:

- `QuicConnection`: Main QUIC connection class
  - `StartHandshake()`: Start QUIC handshake
  - `SendRequest(method, path)`: Send HTTP/3 request
  - `ProcessReceivedData(data, len)`: Process received UDP data
  - `OnTimerTick(ms)`: Drive timers (needs to be called periodically)
  - `GetStats()`: Get connection statistics
  - `Close()`: Close connection

- `QuicConfig`: Connection configuration
  - `hostname`: Target hostname (for SNI)
  - `port`: Target port
  - `handshake_timeout_ms`: Handshake timeout
  - `idle_timeout_ms`: Idle timeout

- Event callbacks:
  - `SetOnConnected(callback)`: Connection established callback
  - `SetOnResponse(callback)`: HTTP/3 response callback
  - `SetOnDisconnected(callback)`: Disconnection callback

For detailed API documentation, please refer to header file comments.

## Notes

1. **Task Stack Size**: The task stack size for calling QUIC/HTTP3 library needs to be set to at least **8KB**. If using the `app_main()` task, set `CONFIG_ESP_MAIN_TASK_STACK_SIZE` in `sdkconfig` to at least 8192 bytes, or when creating an independent task, use `xTaskCreate()` and specify at least 8192 bytes of stack size
2. **Event Loop**: Must periodically call `OnTimerTick()` (recommended every 10-50ms) to drive internal timers
3. **Non-blocking I/O**: UDP socket should be set to non-blocking mode
4. **Data Reception**: Need to continuously receive UDP data in the event loop and call `ProcessReceivedData()`
5. **Single-threaded Model**: All operations execute synchronously in the caller's thread, no additional threads or locks required
6. **Resource Cleanup**: Should call `Close()` to close the connection after use

## Dependencies

- ESP-IDF v5.4+
- mbedtls (for TLS 1.3)
- lwip (for network stack)

## License

Apache-2.0 License
