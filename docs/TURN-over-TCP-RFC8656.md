# 使用 stice 实现 TURN over TCP 控制连接（RFC 8656）

## 1. 背景与动机

在典型的 WebRTC 场景中，ICE 代理通过 UDP 与 TURN 服务器通信，获取中继候选者（relayed candidate）来穿透对称 NAT。然而，在某些网络环境中——企业防火墙、公共 WiFi、移动运营商的受限网络——UDP 可能被完全封锁或严重限速，而 TCP 443/80 端口通常是开放的。

RFC 8656（Traversal Using Relays around NAT）定义了 TURN 协议可以在 **TCP 或 TLS 之上运行控制连接**。这意味着客户端与 TURN 服务器之间的 Allocate、Refresh、CreatePermission、ChannelBind 等 STUN 事务，以及 Send/Data 指示和 ChannelData 帧，都可以通过一条 TCP 连接传输。这使得 TURN 能够穿透只允许 TCP 的防火墙。

需要区分两个容易混淆的概念：

| 概念 | 规范 | 控制连接 | REQUESTED-TRANSPORT | Relay 传输 |
|------|------|---------|---------------------|-----------|
| TURN over TCP (control) | RFC 8656 | TCP/TLS | 17 (UDP) | UDP |
| TURN TCP Allocation | RFC 6062 | TCP | 6 (TCP) | TCP |

本文聚焦前者：**控制连接运行在 TCP 上，中继传输仍然是 UDP**。stice 的实现中，当传输配置为 `STICE_TURN_TRANSPORT_TCP` 时，会同时启用 RFC 6062 TCP allocation（`REQUESTED-TRANSPORT=6`），因为这是 ICE-TCP 场景的典型需求；而 `STICE_TURN_TRANSPORT_TLS` 则使用标准的 UDP relay（`REQUESTED-TRANSPORT=17`）。

## 2. RFC 8656 中的关键规范

### 2.1 传输层与帧定界

TURN over UDP 时，每个 UDP 数据报天然就是一个完整的 STUN 消息或 ChannelData 帧，不需要额外的定界信息。

TURN over TCP 时，情况完全不同。TCP 是一个面向字节流的协议，接收方无法仅凭 TCP 层知道一条 STUN 消息从哪里开始、到哪里结束。RFC 8656 规定 TURN over TCP **不使用 RFC 4571 的 2 字节长度前缀**，而是依赖 STUN 消息和 ChannelData 帧本身的**自定界**（self-delimiting）特性：

- **STUN 消息**：20 字节固定头部，其中第 2-3 字节是 16 位的 `MESSAGE LENGTH` 字段，表示头部之后的载荷字节数。因此一帧的总长度 = `20 + length`。
- **ChannelData 帧**：4 字节头部，其中第 2-3 字节是 16 位长度字段。在 TCP 上，数据部分会被填充到 4 字节边界。总长度 = `4 + padded(length)`。

### 2.2 流上的多路分解

在同一条 TCP 连接上，STUN 消息和 ChannelData 帧可能交错到达。接收方需要根据首字节判断当前帧的类型：

- STUN 消息的首字节高 2 位为 `00`（RFC 5389 §6），因此首字节范围是 `0x00-0x3F`。
- ChannelData 的首字节是通道号的高字节，通道号范围为 `0x4000-0x7FFF`，因此首字节范围是 `0x40-0x7F`。

这两个范围互不重叠，使得在 TCP 字节流上可以无歧义地分解帧。

### 2.3 长期凭证认证

TURN over TCP 使用与 UDP 相同的长期凭证机制（long-term credential）：

1. 客户端发送不带认证的 Allocate 请求。
2. 服务器返回 `401 Unauthorized`，携带 `REALM` 和 `NONCE` 属性。
3. 客户端使用 `username:realm:password` 计算 MD5 作为密钥，在后续请求中携带 `USERNAME`、`REALM`、`NONCE` 和 `MESSAGE-INTEGRITY`。
4. 如果服务器返回 `438 Stale Nonce`，客户端使用新的 NONCE 重试（最多 3 次，防止无限循环）。

### 2.4 重传与超时

TCP 提供可靠传输，因此 TURN over TCP **不需要应用层重传**。但 stice 仍然维护事务 ID 映射和超时机制，用于：
- 检测服务器无响应（连接可能半开）。
- 在 UDP 和 TCP 之间统一状态机代码路径。

## 3. stice 的架构设计

stice 将 TURN 客户端的职责清晰地划分为三层：

```
┌─────────────────────────────────────────────────┐
│                   Agent (ICE)                     │
│  拥有 socket / TcpTransport，驱动事件循环        │
├─────────────────────────────────────────────────┤
│  turnTcpTransport_ (TcpTransport, Raw framing)  │
│  turnStunConn_    (StunConn, 自定界解析)         │
├─────────────────────────────────────────────────┤
│              turn::Client (状态机)                │
│  Allocate / Refresh / Permission / Channel       │
│  不拥有 socket，通过 TurnSink 回调发送原始字节    │
└─────────────────────────────────────────────────┘
```

### 3.1 turn::Client — 无 socket 的状态机

`turn::Client` 是纯状态机，不拥有任何网络 socket。它通过 `TurnSink` 回调与上层通信：

```cpp
struct TurnSink {
    // 发送原始 STUN 消息或 ChannelData 帧到 TURN 服务器
    std::function<void(const unsigned char *data, std::size_t size)> sendRaw;
    // 分配成功，提供中继地址和生命周期
    std::function<void(const net::AddrRecord &relayed, std::uint32_t lifetime)> onAllocated;
    // 分配永久失败
    std::function<void(int errorCode, const std::string &reason)> onFailed;
    // 通过中继收到应用数据
    std::function<void(const net::AddrRecord &peer, const unsigned char *data, std::size_t size)> onData;
    // ...
};
```

这种设计使得 `turn::Client` 可以复用于 UDP、TCP、TLS 三种传输，上层只需要提供不同的 `sendRaw` 实现。

### 3.2 turn::StunConn — TCP 流的自定界解析器

`StunConn` 是 TURN over TCP 的核心组件，负责从连续的 TCP 字节流中提取完整的 STUN 消息或 ChannelData 帧。

```cpp
class StunConn {
public:
    void feed(const unsigned char *data, std::size_t size);
    std::size_t readFrame(const unsigned char *&out);
    std::size_t buffered() const;
private:
    bytes buf_;
    std::size_t consumed_ = 0;
};
```

**工作流程：**

1. `feed()`：将从 TCP 连接收到的原始字节追加到内部缓冲区。
2. `readFrame()`：尝试从缓冲区头部提取一帧：
   - 检查首字节：`< 0x40` 是 STUN 消息，`0x40-0x7F` 是 ChannelData。
   - 对于 STUN：读取 20 字节头部中的 length 字段，总长度 = 20 + length。
   - 对于 ChannelData：读取 4 字节头部中的 length 字段，总长度 = 4 + 向上取整到 4 的倍数(length)。
   - 如果缓冲区数据不足一帧，返回 0（等待更多数据）。
   - 如果首字节既不是 STUN 也不是 ChannelData，返回 `SIZE_MAX`（致命流错误，应关闭连接）。
3. 消费已读取的帧，推进 `consumed_` 偏移。

### 3.3 TcpTransport — Raw 帧模式

stice 的 `TcpTransport` 支持两种帧模式：
- `FramingMode::RFC4571`：每帧前加 2 字节大端长度前缀（用于 ICE-TCP 数据通道）。
- `FramingMode::Raw`：不加任何前缀，直接写入原始字节（用于 TURN over TCP 控制连接）。

TURN over TCP 控制连接必须使用 `Raw` 模式，因为 STUN/ChannelData 已经是自定界的，再加长度前缀会导致服务器无法解析。

## 4. 核心实现分析

### 4.1 建立 TCP 控制连接

当 Agent 检测到 TURN 服务器配置为 TCP/TLS 传输时，调用 `beginTurnTcpConnect()`：

```cpp
bool Agent::beginTurnTcpConnect(const net::AddrRecord &turnServer, bool useTls,
                                const std::string &sni, bool skipVerify) {
    turnTcpTransport_ = std::make_unique<net::TcpTransport>();
    // 关键：使用 Raw 帧模式，不加 RFC 4571 前缀
    turnTcpTransport_->setFramingMode(net::FramingMode::Raw);
    if (!turnTcpTransport_->beginConnect(turnServer, sni, useTls, skipVerify)) {
        turnTcpTransport_.reset();
        // 通知 TURN Client 分配失败
        return false;
    }
    return true;
}
```

`TcpTransport::beginConnect()` 发起非阻塞 connect，通过 `PollRegistry` 的 `onWritable` 回调检测连接完成。TLS 模式下，连接建立后立即执行 TLS 握手。

### 4.2 发送路径

`turn::Client` 构建 STUN 消息后，通过 `TurnSink::sendRaw` 回调发送。Agent 的回调实现根据传输类型路由：

```cpp
sink.sendRaw = [this, useTcp](const unsigned char *data, std::size_t size) {
    if (useTcp) {
        // TCP/TLS：通过 turnTcpTransport_ 发送原始字节
        // Raw 模式下直接写入，不加任何前缀
        turnTcpTransport_->send(data, size);
    } else {
        // UDP：通过 UDP socket 或共享 UDPMux 发送
        sock_.sendto(data, size, turnServerAddr);
    }
};
```

对于 TCP 传输，`TcpTransport::send()` 将原始字节写入发送缓冲区，由 `PollRegistry` 的 `onWritable` 回调逐步 flush 到内核。

### 4.3 接收路径

TCP 数据到达时，`PollRegistry` 触发 `onTurnTcpReadable()`：

```cpp
void Agent::onTurnTcpReadable() {
    char buf[4096];
    net::AddrRecord peer; // TCP 上不需要对端地址
    while (true) {
        int n = turnTcpTransport_->recv(buf, sizeof(buf), peer);
        if (n <= 0) break;
        // 将原始字节喂给 StunConn 解析器
        turnStunConn_.feed(reinterpret_cast<const unsigned char *>(buf),
                           static_cast<std::size_t>(n));
    }
    // 从 StunConn 中提取完整帧，路由到 TURN Client
    const unsigned char *frame = nullptr;
    while (true) {
        std::size_t frameSize = turnStunConn_.readFrame(frame);
        if (frameSize == 0 || !frame) break;
        if (frameSize == static_cast<std::size_t>(-1)) {
            // 致命流错误：关闭连接，通知 TURN Client 失败
            turnTcpTransport_.reset();
            return;
        }
        // 将完整帧交给 TURN Client 处理（STUN 响应 / Data 指示 / ChannelData）
        for (auto &e : entries_) {
            if (e.type == StunEntryType::Relay && e.turn) {
                e.turn->handleInbound(frame, frameSize);
            }
        }
    }
}
```

这个流程体现了 TURN over TCP 的核心设计：**TCP 层只负责字节流传输，StunConn 负责帧定界，turn::Client 负责协议语义**。

### 4.4 Allocate 事务

`turn::Client::allocate()` 构建 Allocate 请求：

```cpp
void Client::allocate() {
    state_ = AllocState::Allocating;
    // RFC 8656：TLS 控制连接使用 UDP relay (17)
    // RFC 6062：TCP 控制连接使用 TCP allocation (6)
    isTcpAllocation_ = (cfg_.transport == TurnTransport::TCP);
    std::uint8_t proto = isTcpAllocation_ ? 6 : 17;

    stun::Message m;
    m.method = stun::Method::Allocate;
    m.cls = stun::Class::Request;
    m.newTransactionID();
    allocateTid_ = m.transactionID;
    stun::addRequestedTransport(m, proto);
    sendRequest(m);  // 通过 TurnSink::sendRaw 发送
    // 注册待处理事务，用于响应分发和超时
}
```

`sendRequest()` 在没有长期凭证时发送不带认证的请求。收到 `401` 响应后，`handleAllocateResponse()` 捕获 `REALM` 和 `NONCE`，然后用凭证重新发送：

```cpp
void Client::handleAllocateResponse(const stun::Message &msg, bool isError) {
    if (isError) {
        int code = 0;
        stun::readErrorCode(msg, code, reason);
        if (code == 401) {
            // 捕获 realm/nonce，用长期凭证重试
            creds_ = stun::Credentials{...};
            sendRequest(allocateMsgAgain);
            return;
        }
        if (code == 438 && nonceRetries_ < MaxNonceRetries) {
            // Stale Nonce：刷新 nonce 重试
            nonceRetries_++;
            sendRequest(allocateMsgAgain);
            return;
        }
        sink_.onFailed(code, reason);
        return;
    }
    // 成功：提取 XOR-RELAYED-ADDRESS 和 LIFETIME
    stun::readXorAddress(msg, stun::AttrType::XorRelayedAddress, relayedAddr_, msg.transactionID);
    stun::readLifetime(msg, lifetime_);
    state_ = AllocState::Allocated;
    sink_.onAllocated(relayedAddr_, lifetime_);
}
```

### 4.5 数据传输：Send 指示与 ChannelData

分配成功后，应用数据通过两种方式传输：

1. **Send 指示**（Send Indication）：STUN 消息，方法为 Send，携带 `XOR-PEER-ADDRESS` 和 `DATA` 属性。不需要通道绑定，适用于偶尔发送数据。
2. **ChannelData 帧**：4 字节头部（通道号 + 长度）+ 数据。需要先通过 ChannelBind 请求绑定通道号，适用于持续传输，开销更小。

`turn::Client::sendData()` 自动管理这个状态机：如果对端已绑定通道，使用 ChannelData；否则使用 Send 指示，并在后台发起 CreatePermission + ChannelBind。

在 TCP 控制连接上，这两种帧都通过 `turnTcpTransport_` 发送，由 `StunConn` 在接收端解析。

## 5. 使用示例（C API）

### 5.1 配置 TURN over TCP

```c
#include <stice/stice.h>

static void on_state_changed(stice_agent_t *agent, stice_state_t state, void *user) {
    printf("ICE state: %s\n", stice_state_to_string(state));
}

static void on_candidate(stice_agent_t *agent, const char *sdp, void *user) {
    // 通过信令发送给对端
    printf("Local candidate: %s\n", sdp);
}

int main(void) {
    stice_config_t config = {0};

    // 配置 TURN over TCP 控制连接
    stice_turn_server_t turn = {0};
    turn.host = "turn.example.com";
    turn.port = 3478;
    turn.username = "user";
    turn.password = "pass";
    turn.transport = STICE_TURN_TRANSPORT_TCP;  // TCP 控制连接

    config.turn_servers = &turn;
    config.turn_servers_count = 1;
    config.cb_state_changed = on_state_changed;
    config.cb_candidate = on_candidate;

    stice_agent_t *agent = stice_create(&config);
    stice_gather_candidates(agent);
    // ... 交换 SDP 和候选者 ...
    stice_destroy(agent);
    return 0;
}
```

### 5.2 配置 TURN over TLS（TCP 控制连接 + TLS 加密）

```c
stice_turn_server_t turn = {0};
turn.host = "turn.example.com";
turn.port = 5349;           // TURN/TLS 标准端口
turn.username = "user";
turn.password = "pass";
turn.transport = STICE_TURN_TRANSPORT_TLS;  // TLS 控制连接
turn.tls_skip_verify = 0;   // 验证服务器证书（默认，安全）
```

TLS 模式下，控制连接被 TLS 加密，可以穿透对明文 TCP 进行 DPI 检测的防火墙。`REQUESTED-TRANSPORT` 仍然是 UDP(17)，中继传输是 UDP。

### 5.3 通过 stserver 测试

stice 内置的 `stserver` 支持 TCP 控制连接。使用测试配置启动：

```bash
# 启动 stserver（监听 UDP 3478 + TCP 3478）
./stserver --config stserver.test.conf

# 运行 TURN relay 测试（TCP 模式）
./test_stserver_relay.exe 127.0.0.1 3478 tcp
```

测试输出示例：
```
[stice/INF] TURN TCP: beginning TCP connect to 127.0.0.1:3478
[stice/INF] TURN allocate: called state=0
[stice/INF] TURN: allocation success relayed=127.0.0.1:50123 lifetime=600
=== PASS: relay data exchange OK ===
```

## 6. 与 UDP 控制连接的对比

| 维度 | UDP 控制连接 | TCP/TLS 控制连接 |
|------|-------------|-----------------|
| 帧定界 | 数据报天然定界 | StunConn 自定界解析 |
| 帧前缀 | 无 | 无（Raw 模式，不加 RFC 4571） |
| 应用层重传 | 需要（RTO 200ms，指数退避） | 不需要（TCP 可靠传输） |
| 穿透能力 | 差（UDP 常被封） | 好（TCP 443/80 通常开放） |
| 延迟 | 低（无连接建立） | 稍高（TCP 握手 + TLS 握手） |
| 头部开销 | 20 字节 STUN / 4 字节 ChannelData | 相同（TCP 头部由内核处理） |
| 多路分解 | 按源地址+端口 | 按首字节（STUN vs ChannelData） |
| 适用场景 | 普通 NAT 穿透 | 企业防火墙 / 受限网络 |

## 7. 注意事项与最佳实践

### 7.1 不要在 TURN over TCP 上使用 RFC 4571 前缀

这是最常见的实现错误。ICE-TCP（RFC 6544）的数据通道使用 RFC 4571 的 2 字节长度前缀，但 TURN over TCP 控制连接（RFC 8656）明确不使用。stice 通过 `TcpTransport::setFramingMode(FramingMode::Raw)` 确保这一点。

### 7.2 StunConn 的错误恢复

如果 `StunConn::readFrame()` 返回 `SIZE_MAX`，说明 TCP 流上出现了既不是 STUN 也不是 ChannelData 的数据。这通常意味着：
- 对端不是合法的 TURN 服务器。
- 连接被中间盒篡改。
- 帧解析状态不同步（理论上不应发生，因为帧是自定界的）。

正确的处理方式是**关闭 TCP 连接并标记分配失败**，而不是尝试跳过字节重新同步——因为无法确定从哪里开始重新同步。

### 7.3 TCP 连接的保活与超时

虽然 TCP 提供可靠传输，但 TURN 分配仍然需要定期 Refresh（默认 600 秒生命周期，提前刷新）。此外，stice 在应用层维护事务超时，用于检测半开连接（TCP 连接看似建立但服务器无响应）。

### 7.4 TLS 证书验证

生产环境中务必保持 `tls_skip_verify = 0`，验证 TURN 服务器的 TLS 证书。跳过验证虽然方便测试，但容易受到中间人攻击。stice 使用系统信任存储验证证书。

### 7.5 端口选择

TURN over TCP 标准端口是 3478，TURN/TLS 是 5349。但在受限网络中，建议使用 443 端口（TLS），因为 443 几乎总是开放的，且 TLS 加密使得 DPI 无法区分 TURN 流量与 HTTPS 流量。

## 8. 总结

stice 对 TURN over TCP 控制连接的实现遵循 RFC 8656 规范，核心设计要点包括：

1. **分层架构**：`turn::Client`（无 socket 状态机）+ `StunConn`（自定界解析）+ `TcpTransport`（Raw 帧模式），职责清晰，易于测试和维护。
2. **自定界帧解析**：利用 STUN 消息和 ChannelData 帧头部的 length 字段，在 TCP 字节流上无歧义地分解帧，不需要额外的长度前缀。
3. **统一的状态机**：`turn::Client` 的 Allocate/Refresh/Permission/Channel 状态机在 UDP 和 TCP 上完全复用，仅 `sendRaw` 回调不同。
4. **长期凭证认证**：401/438 处理、nonce 刷新限制、MESSAGE-INTEGRITY 验证，与 UDP 路径一致。
5. **错误处理**：StunConn 流错误 → 关闭连接 → 标记分配失败，避免在损坏的流上继续操作。

通过 TURN over TCP/TLS，stice 能够在 UDP 被封锁的网络环境中仍然完成 ICE 连接建立，为 WebRTC 应用提供更广泛的网络适应性。
