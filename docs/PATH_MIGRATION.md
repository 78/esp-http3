# 4G 出口变化与 QUIC 路径验证

## 修复范围

1.6.2 候选版本补齐客户端实际接收路径中的 `RETIRE_CONNECTION_ID`
(`0x19`)、`PATH_CHALLENGE` (`0x1a`) 和 `PATH_RESPONSE` (`0x1b`)。
此前这些帧进入未知帧分支，会停止解析当前包剩余的帧；另一个
`FrameProcessor` 中虽然有对应回调，实际连接未通过它分发。

收到合法的 challenge 后，客户端回送相同的 8 字节数据，UDP 数据报填充至
1200 字节。当前连接使用连向服务器的单个 UDP socket，响应也从这个 socket
发出，覆盖本次客户端 NAT 公网地址/端口变化的场景。响应不进入自动重传队列；
服务器用新包再次发来 challenge 时，可以再次响应。没有发起验证时收到的
`PATH_RESPONSE` 不会误将路径标记为已验证。

握手的初始 SCID 按序号 0 登记。握手完成后，客户端维持最多 4 个活跃的本地
连接 ID，且不超过服务器声明的 `active_connection_id_limit`。收到退役请求时
补充新 ID，重复退役不会重复分配。退役未发行的序号、或退役承载该请求的包
所用的 DCID，会关闭连接并报告协议错误。

`NEW_CONNECTION_ID` 和 `RETIRE_CONNECTION_ID` 保存到可靠帧队列，支持丢包和
PTO 重传，包括随 HTTP/3 SETTINGS 发出的握手初始化包。已经退役的本地 ID
从重传内容中移除。取消请求流 0 不会清除这些连接级控制帧。

这些规则对应 [RFC 9000 连接 ID 管理](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.1)、
[路径验证响应](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.2) 和
[RETIRE_CONNECTION_ID](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.16)。

## 设备复测

使用本次构建的固件，在原来的 4G 网络下连续请求、取消和重试，并保留从建立
连接开始的串口日志。沿用原来的超时和重试策略，以便观察旧连接是否能够恢复。

以下信息在 INFO 级别输出，不依赖 `Http3Config::enable_debug`：

```text
Issuing local CID: seq=... active=... peer_limit=...
Peer retired local CID: seq=... rx_pn=... active=...
PATH_CHALLENGE received: rx_pn=... data=...
PATH_RESPONSE sent: rx_pn=... tx_pn=... bytes=1200 data=...
```

- 建立连接后应看到备用 ID 的发行；收到退役后应有新的序号补充。
- 收到 challenge 时，响应的 `rx_pn` 和 `data` 应与该 challenge 一致。
- 最有价值的成功样本是在旧连接上出现这组 challenge/response，随后同一连接
  收到 HTTP 响应，期间没有重新握手。
- 若再次卡住，保留最后正常接收、超时重试、最终恢复的完整日志，以及请求 ID
  和大致墙钟时间。开启模组调试时，同时观察是否出现 `RX type=0` 以太网数据。

`PATH_RESPONSE sent` 只证明客户端成功交给本地 socket，不能证明服务器已收到
或完成验证。没有 challenge 日志，也不能单凭这一点断言运营商拦截：需要结合
模组接收日志和服务器的 UDP/QUIC 路径日志判断。HTTP access log 的 `remote_ip`
是请求解析时连接的活动地址，不能代替逐个 UDP 包的实际源地址记录。

重建 QUIC 后恢复说明新连接当时可用；DNS、NAT 状态、无线网络状态也可能同时
变化，因此这个现象本身不能唯一证明旧连接的 PATH 验证失败。

## 验证边界

`bash tests/host/run.sh path` 从真实连接实现提取方法，并结合实际的帧、ACK 和
丢包跟踪代码执行回归。测试中的 socket/加密边界使用主机替身；它不模拟真实
运营商网络，也不替代设备复测。

本次没有修改模组 AT 状态解析、请求重试策略或 QUIC 空闲超时策略。
