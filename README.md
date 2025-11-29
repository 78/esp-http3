# ESP-HTTP3

ESP32 平台的 QUIC/HTTP3 客户端库，实现了 RFC 9000 (QUIC) 和 RFC 9114 (HTTP/3) 协议。

## 特性

- ✅ QUIC v1 传输协议
- ✅ TLS 1.3 握手（使用 mbedtls）
- ✅ HTTP/3 请求/响应
- ✅ 流多路复用
- ✅ 流控
- ✅ 丢包检测与恢复
- ✅ 单线程事件驱动模型，无需多线程

## 设计原则

- **用户提供传输层**：通过回调函数发送 UDP 数据
- **用户驱动事件循环**：调用 `ProcessReceivedData()` 处理接收的数据，调用 `OnTimerTick()` 驱动定时器

## WiFi 使用示例

以下示例展示如何在 ESP32 上使用 WiFi 连接进行 QUIC/HTTP3 通信：

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

// WiFi 事件组位定义
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static EventGroupHandle_t s_wifi_event_group;
static int s_retry_num = 0;
static const int WIFI_MAX_RETRY = 5;
static char s_ip_str[16] = {0};

/**
 * WiFi 事件处理器
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
 * 初始化 WiFi 并等待连接（使用 ESP-IDF 标准 API）
 */
static bool InitWifi(const char* ssid, const char* password) {
    ESP_LOGI(TAG, "Initializing WiFi...");
    
    // 初始化 NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    // 创建事件组
    s_wifi_event_group = xEventGroupCreate();
    
    // 初始化网络接口
    ESP_ERROR_CHECK(esp_netif_init());
    
    // 创建默认事件循环
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    // 创建默认 WiFi Station 网络接口
    esp_netif_create_default_wifi_sta();
    
    // 初始化 WiFi 配置
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    
    // 注册事件处理器
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
    
    // 配置 WiFi Station 模式
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
    
    // 等待连接完成（超时 30 秒）
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
 * QUIC/HTTP3 WiFi 测试函数
 * 
 * 使用标准 lwip socket 进行 UDP 通信
 */
void TestQuicHttp3Wifi(const char* hostname, uint16_t port, const char* path) {
    using namespace esp_http3;
    
    ESP_LOGI(TAG, "=== QUIC/HTTP3 WiFi Test Start ===");
    ESP_LOGI(TAG, "Target: %s:%u%s", hostname, port, path);
    
    // 1. DNS 解析
    struct hostent* he = gethostbyname(hostname);
    if (!he) {
        ESP_LOGE(TAG, "DNS lookup failed for %s", hostname);
        return;
    }
    
    struct in_addr* addr = (struct in_addr*)he->h_addr;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, addr, ip_str, sizeof(ip_str));
    ESP_LOGI(TAG, "Resolved %s to %s", hostname, ip_str);
    
    // 2. 创建 UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to create socket: %d", errno);
        return;
    }
    
    // 设置非阻塞模式
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    // 服务器地址
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr = *addr;
    
    // 连接 (对于 UDP，这只是设置默认目标地址)
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "Failed to connect socket: %d", errno);
        close(sock);
        return;
    }
    ESP_LOGI(TAG, "UDP socket connected");
    
    // 3. 配置 QUIC
    QuicConfig config;
    config.hostname = hostname;
    config.port = port;
    config.handshake_timeout_ms = 10000;
    config.idle_timeout_ms = 60000;
    config.enable_debug = false;
    
    // 4. 创建 QUIC 连接，传入发送回调
    auto conn = std::make_unique<QuicConnection>(
        // SendCallback: 通过 socket 发送 UDP 数据
        [sock](const uint8_t* data, size_t len) -> int {
            int sent = send(sock, data, len, 0);
            if (sent < 0) {
                ESP_LOGW(TAG, "Socket send failed: %d", errno);
            }
            return sent;
        },
        config
    );
    
    // 5. 设置事件回调
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
    
    // 6. 开始握手
    ESP_LOGI(TAG, "Starting QUIC handshake...");
    if (!conn->StartHandshake()) {
        ESP_LOGE(TAG, "Failed to start handshake");
        close(sock);
        return;
    }
    
    // 7. 事件循环参数
    const int tick_interval_ms = 10;
    const TickType_t tick_wait = pdMS_TO_TICKS(tick_interval_ms);
    uint8_t recv_buffer[1500];
    
    // Helper: 执行一次事件循环迭代
    auto run_event_loop_once = [&]() {
        // 接收 UDP 数据（非阻塞）
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
        
        // 等待一个 tick 间隔
        vTaskDelay(tick_wait);
        
        // 执行定时器 tick
        conn->OnTimerTick(tick_interval_ms);
    };
    
    // 8. 事件循环：等待连接
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
    
    // 9. 发送 HTTP/3 GET 请求
    ESP_LOGI(TAG, "Sending HTTP/3 GET request to %s", path);
    int stream_id = conn->SendRequest("GET", path);
    if (stream_id < 0) {
        ESP_LOGE(TAG, "Failed to send request");
        conn->Close();
        close(sock);
        return;
    }
    ESP_LOGI(TAG, "Request sent on stream %d", stream_id);
    
    // 10. 事件循环：等待响应
    ESP_LOGI(TAG, "Waiting for response...");
    for (int wait_ms = 0; !response_received && wait_ms < 10000; wait_ms += tick_interval_ms) {
        run_event_loop_once();
        if (wait_ms > 0 && wait_ms % 1000 == 0) {
            ESP_LOGI(TAG, "  Waiting... %d ms", wait_ms);
        }
    }
    
    // 11. 打印统计信息
    auto stats = conn->GetStats();
    ESP_LOGI(TAG, "=== Connection Stats ===");
    ESP_LOGI(TAG, "  Packets sent: %lu", stats.packets_sent);
    ESP_LOGI(TAG, "  Packets received: %lu", stats.packets_received);
    ESP_LOGI(TAG, "  Bytes sent: %lu", stats.bytes_sent);
    ESP_LOGI(TAG, "  Bytes received: %lu", stats.bytes_received);
    ESP_LOGI(TAG, "  RTT: %lu ms", stats.rtt_ms);
    
    // 12. 检查结果
    if (response_received) {
        ESP_LOGI(TAG, "=== Test PASSED ===");
        ESP_LOGI(TAG, "HTTP Status: %d", response_status);
    } else {
        ESP_LOGW(TAG, "=== Test INCOMPLETE (no response) ===");
    }
    
    // 13. 优雅关闭
    conn->Close();
    close(sock);
    
    ESP_LOGI(TAG, "=== QUIC/HTTP3 WiFi Test Complete ===");
}

extern "C" void app_main(void) {
    // 注意：app_main 任务的堆栈大小需要在 sdkconfig 中配置
    // 设置 CONFIG_ESP_MAIN_TASK_STACK_SIZE 至少为 8192 (8KB)
    // 或者创建独立任务时使用 xTaskCreate() 并指定至少 8192 字节的堆栈
    
    ESP_LOGI(TAG, "QUIC/HTTP3 Demo Starting...");
    
    // 初始化并连接 WiFi（使用 ESP-IDF 标准 API）
    if (!InitWifi("YOUR_SSID", "YOUR_PASSWORD")) {
        ESP_LOGE(TAG, "Failed to connect WiFi");
        return;
    }
    
    // 测试 QUIC/HTTP3 客户端 (使用 WiFi + BSD socket)
    TestQuicHttp3Wifi("api.tenclass.net", 443, "/pocket-sage/health");
    
    ESP_LOGI(TAG, "Demo completed");
    
    // 保持运行
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
```

## 关键步骤说明

1. **WiFi 初始化**：使用 ESP-IDF 标准 WiFi API (`esp_wifi_init`, `esp_wifi_set_config`, `esp_wifi_start`, `esp_wifi_connect`) 初始化并连接 WiFi
2. **DNS 解析**：使用 `gethostbyname()` 解析主机名
3. **UDP Socket 创建**：创建非阻塞 UDP socket 并连接到服务器
4. **QUIC 连接配置**：创建 `QuicConfig` 并设置主机名、端口等参数
5. **创建 QuicConnection**：传入发送回调函数（通过 socket 发送数据）
6. **设置事件回调**：设置连接、响应、断开连接的回调函数
7. **开始握手**：调用 `StartHandshake()` 启动 QUIC 握手
8. **事件循环**：
   - 接收 UDP 数据并调用 `ProcessReceivedData()`
   - 定期调用 `OnTimerTick()` 驱动定时器
   - 等待握手完成
9. **发送请求**：握手完成后调用 `SendRequest()` 发送 HTTP/3 请求
10. **等待响应**：在事件循环中等待响应回调
11. **清理资源**：关闭连接和 socket

## 输出示例

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

## API 参考

主要 API 接口：

- `QuicConnection`: QUIC 连接主类
  - `StartHandshake()`: 开始 QUIC 握手
  - `SendRequest(method, path)`: 发送 HTTP/3 请求
  - `ProcessReceivedData(data, len)`: 处理接收到的 UDP 数据
  - `OnTimerTick(ms)`: 驱动定时器（需要定期调用）
  - `GetStats()`: 获取连接统计信息
  - `Close()`: 关闭连接

- `QuicConfig`: 连接配置
  - `hostname`: 目标主机名（用于 SNI）
  - `port`: 目标端口
  - `handshake_timeout_ms`: 握手超时时间
  - `idle_timeout_ms`: 空闲超时时间

- 事件回调：
  - `SetOnConnected(callback)`: 连接建立回调
  - `SetOnResponse(callback)`: HTTP/3 响应回调
  - `SetOnDisconnected(callback)`: 断开连接回调

详细 API 文档请参考头文件注释。

## 注意事项

1. **任务堆栈大小**：调用 QUIC/HTTP3 库的任务堆栈需要设置为至少 **8KB**。如果使用 `app_main()` 任务，需要在 `sdkconfig` 中设置 `CONFIG_ESP_MAIN_TASK_STACK_SIZE` 至少为 8192 字节，或者创建独立任务时使用 `xTaskCreate()` 并指定至少 8192 字节的堆栈大小
2. **事件循环**：必须定期调用 `OnTimerTick()`（建议每 10-50ms）以驱动内部定时器
3. **非阻塞 I/O**：UDP socket 应设置为非阻塞模式
4. **数据接收**：需要在事件循环中持续接收 UDP 数据并调用 `ProcessReceivedData()`
5. **单线程模型**：所有操作都在调用者线程中同步执行，无需额外的线程或锁
6. **资源清理**：使用完毕后应调用 `Close()` 关闭连接

## 依赖

- ESP-IDF v5.4+
- mbedtls (用于 TLS 1.3)
- lwip (用于网络栈)

## 许可证

[根据项目许可证]

