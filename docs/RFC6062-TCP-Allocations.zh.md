# 使用 stice 实现 RFC 6062 TCP Allocations

## 1. 概述

RFC 6062（Traversal Using Relays around NAT (TURN) Extensions for TCP Allocations）扩展了 TURN 协议，使中继分配（allocation）能够使用 TCP 作为中继传输协议。这使得 WebRTC 的 ICE-TCP（RFC 6544）候选者可以通过 TURN 中继建立端到端 TCP 连接，适用于 UDP 被完全封锁的网络环境。

### 1.1 与标准 TURN UDP 中继的区别

| 维度 | 标准 TURN (RFC 8656) | RFC 6062 TCP Allocation |
|------|----------------------|-------------------------|
| REQUESTED-TRANSPORT | 17 (UDP) | 6 (TCP) |
| 控制连接 | UDP 或 TCP/TLS | TCP（Mode-A） |
| 数据传输 | UDP Send/Data 指示 + ChannelData | TCP 数据连接（Mode-B） |
| 对端连接建立 | 无需（UDP 无连接） | CONNECT / CONNECTION-ATTEMPT |
| 数据连接绑定 | 无需 | CONNECTION-BIND + CONNECTION-ID |
| 适用场景 | 普通 NAT 穿透 | ICE-TCP / UDP 封锁环境 |

### 1.2 stice 中的实现架构

stice 将 RFC 6062 的实现分为两个 TCP 连接：

```
┌──────────────┐  Mode-A (控制)   ┌──────────────┐
│              │ ◄──────────────► │              │
│  stice Agent │   STUN 事务       │  TURN Server │
│              │  (Allocate/Refresh│              │
│              │   /CONNECT/Creds) │              │
│              │                    │              │
│              │  Mode-B (数据)    │              │
│              │ ◄──────────────► │              │
│              │   应用数据 + STUN  │              │
│              │   连接检查(RFC4571)│              │
└──────────────┘                    └──────────────┘
```

- **Mode-A 控制连接**（`turnTcpTransport_`）：使用 `FramingMode::Raw`，传输 Allocate、Refresh、CreatePermission、CONNECT 等 STUN 事务，由 `StunConn` 自定界解析。
- **Mode-B 数据连接**（`turnDataConn_`）：使用 `FramingMode::RFC4571`，在 CONNECTION-BIND 成功后透传应用数据和 STUN 连接性检查。

## 2. 协议流程详解

### 2.1 分配建立（Allocate）

客户端通过 Mode-A 控制连接发送 Allocate 请求，`REQUESTED-TRANSPORT` 属性值为 6（TCP）：

```
Client (Mode-A)                          TURN Server
     │                                        │
     │── Allocate Request ──────────────────►│
     │   REQUESTED-TRANSPORT: TCP(6)         │
     │                                        │
     │◄── 401 Unauthorized ──────────────────│
     │   REALM, NONCE                         │
     │                                        │
     │── Allocate Request ──────────────────►│
     │   USERNAME, REALM, NONCE, MI          │
     │                                        │
     │◄── Allocate Success Response ─────────│
     │   XOR-RELAYED-ADDRESS (TCP passive)   │
     │   LIFETIME                              │
```

分配成功后，客户端获得一个 TCP 类型的中继候选者（`tcptype=passive`），通过 SDP 信令发送给对端。

### 2.2 权限创建（CreatePermission）

RFC 6062 仍然需要 CreatePermission。当对端尝试连接到本地中继地址时，TURN 服务器会检查是否已为该对端创建权限。如果没有权限，服务器会关闭入站 TCP 连接且**不发送** CONNECTION-ATTEMPT 指示（RFC 6062 §4.4）。

stice 在 `formPairs()` 阶段就提前为每个对端中继候选者调用 `ensurePermission()`，确保权限在 CONNECT 之前就绪。

### 2.3 主动模式：CONNECT 请求

当双方都获得 TCP 中继候选者后，需要建立端到端 TCP 数据连接。RFC 6062 定义了两种角色：

- **主动方（Active）**：发送 CONNECT 请求，要求 TURN 服务器与对端中继地址建立 TCP 连接。
- **被动方（Passive）**：等待对端连接，收到 CONNECTION-ATTEMPT 指示后建立数据连接。

stice 使用 **ufrag 字典序比较**来确定性地选择主动方（`shouldInitiateTcpConnect()`）：`local_ufrag >= remote_ufrag` 的一方为主动方。这避免了在 ICE 角色冲突（487）解决之前双方同时发送 CONNECT 的问题。

```
主动方 (Mode-A)              TURN Server              被动方 (Mode-A)
     │                            │                            │
     │── CONNECT Request ───────►│                            │
     │   XOR-PEER-ADDRESS         │── TCP connect ──────────►│
     │                            │                            │
     │                            │◄── CONNECTION-ATTEMPT ────│
     │                            │   Indication               │
     │                            │   XOR-PEER-ADDRESS         │
     │                            │   CONNECTION-ID            │
     │◄── CONNECT Success ────────│                            │
     │    CONNECTION-ID            │                            │
```

### 2.4 数据连接建立与 CONNECTION-BIND

无论是主动方收到 CONNECT 成功响应，还是被动方收到 CONNECTION-ATTEMPT 指示，双方都需要：

1. 打开一条新的 TCP 连接到 TURN 服务器（Mode-B 数据连接）。
2. 在该连接上发送 CONNECTION-BIND 请求，携带从 CONNECT 响应或 CONNECTION-ATTEMPT 指示中获得的 `CONNECTION-ID`。
3. 收到 CONNECTION-BIND 成功响应后，数据连接绑定完成，可以传输应用数据。

```
客户端 (Mode-B)                         TURN Server
     │                                        │
     │── TCP connect ───────────────────────►│
     │                                        │
     │── CONNECTION-BIND Request ───────────►│
     │   CONNECTION-ID: <id>                  │
     │   (RFC 4571 framing)                   │
     │                                        │
     │◄── CONNECTION-BIND Success ───────────│
     │                                        │
     │◄════ 应用数据 / STUN 检查 ═══════════►│
     │   (RFC 4571 framing, transparent)      │
```

**关键区别**：Mode-A 控制连接使用 `Raw` 帧模式（STUN/ChannelData 自定界），而 Mode-B 数据连接使用 `RFC4571` 帧模式（每帧前加 2 字节长度前缀），因为数据连接上传输的是原始应用数据和 STUN 消息的混合流，需要长度前缀来定界。

### 2.5 数据传输与 STUN 连接检查

数据连接绑定完成后，stice 将该对的所有 STUN 连接性检查和应用数据都路由到 Mode-B 数据连接：

- `sendStunBinding()` 中检测到 `pairIsTurnTcpRelay(e.pair)` 时，通过 `sendTurnDataConn()` 发送 STUN Binding 请求。
- `sendBindingResponse()` 中检测到请求来自数据连接时，响应也通过同一数据连接发回。
- 应用数据通过 `stice_send()` → `sendViaSelectedPair()` → `sendTurnDataConn()` 发送。

## 3. stice API 使用指南

### 3.1 启用 RFC 6062 TCP Allocation

在 stice 中，启用 RFC 6062 TCP allocation 只需将 TURN 服务器的传输类型设置为 `STICE_TURN_TRANSPORT_TCP`：

```c
#include <stice/stice.h>

stice_config_t config = {0};

stice_turn_server_t turn = {0};
turn.host = "turn.example.com";
turn.port = 3478;
turn.username = "user";
turn.password = "pass";
// 关键：设置为 TCP 传输，stice 将自动使用 RFC 6062 TCP allocation
turn.transport = STICE_TURN_TRANSPORT_TCP;

config.turn_servers = &turn;
config.turn_servers_count = 1;

stice_agent_t *agent = stice_create(&config);
stice_gather_candidates(agent);
```

设置 `transport = STICE_TURN_TRANSPORT_TCP` 后，stice 内部会：
1. `turn::Client` 设置 `isTcpAllocation_ = true`，Allocate 请求中 `REQUESTED-TRANSPORT = 6`。
2. `Agent` 创建 `turnTcpTransport_`（Mode-A 控制连接，Raw 帧模式）。
3. 收集到的中继候选者类型为 `relayed`，`tcptype=passive`。
4. `formPairs()` 时自动调用 `ensurePermission()` 和 `sendConnect()`（主动方）。
5. CONNECT 成功或 CONNECTION-ATTEMPT 到达时自动创建 `turnDataConn_`（Mode-B 数据连接，RFC4571 帧模式）并发送 CONNECTION-BIND。

### 3.2 启用 ICE-TCP

RFC 6062 TCP relay 通常与 ICE-TCP（RFC 6544）配合使用。启用 ICE-TCP：

```c
// 启用 ICE-TCP（active + passive 模式）
stice_set_ice_tcp_mode(agent, STICE_ICE_TCP_MODE_ACTIVE_PASSIVE);
```

可选模式：
- `STICE_ICE_TCP_MODE_NONE`：禁用 ICE-TCP（默认）
- `STICE_ICE_TCP_MODE_ACTIVE`：仅主动模式
- `STICE_ICE_TCP_MODE_PASSIVE`：仅被动模式
- `STICE_ICE_TCP_MODE_ACTIVE_PASSIVE`：主动+被动（推荐）

### 3.3 中继候选者的 SDP 格式

RFC 6062 TCP 中继候选者在 SDP 中的格式：

```
a=candidate:1 1 tcp 1673026431 192.0.2.1 50000 typ relay tcptype passive raddr 0.0.0.0 rport 0
```

关键字段：
- 传输协议为 `tcp`（而非 `udp`）
- `typ relay`：中继类型
- `tcptype passive`：TCP 候选者类型为 passive（RFC 6062 中继候选者总是 passive）

### 3.4 回调与事件

stice 的标准回调在 RFC 6062 场景下正常工作：

```c
static void on_state_changed(stice_agent_t *agent, stice_state_t state, void *user) {
    // STICE_STATE_GATHERING → 收集中继候选者
    // STICE_STATE_CONNECTING → CONNECT / CONNECTION-BIND 进行中
    // STICE_STATE_CONNECTED  → 数据连接绑定完成，可传输数据
    // STICE_STATE_COMPLETED  → ICE 完成
}

static void on_candidate(stice_agent_t *agent, const char *sdp, void *user) {
    // sdp 包含 tcptype=passive 的中继候选者
    // 通过信令发送给对端
}

static void on_recv(stice_agent_t *agent, const char *data, size_t size, void *user) {
    // 通过 Mode-B 数据连接收到的应用数据
}
```

## 4. 内置测试与验证

### 4.1 test_turn 中的 RFC 6062 专项测试

```bash
# 运行所有 TURN 测试（含 RFC 6062）
./build/Release/test_turn.exe

# 仅运行 RFC 6062 标签的测试
./build/Release/test_turn.exe "[rfc6062]"
```

覆盖内容：
- CONNECT 请求构建与发送
- CONNECTION-BIND 请求构建
- CONNECT 成功响应解析（提取 CONNECTION-ID）
- CONNECTION-ATTEMPT 指示解析
- CONNECT 失败处理（447 等错误码）
- 主动+被动双模式状态机

### 4.2 test_candidate_pair 中的 TCP 中继对过滤

```bash
./build/Release/test_candidate_pair.exe "[pair]"
```

验证 RFC 6544 §5.2 的 TCP 候选对过滤规则，特别是 RFC 6062 的例外：两个 `relayed passive` 候选者**可以**配对（通过 CONNECT/CONNECTION-ATTEMPT 建立端到端连接），而非中继的 passive-passive 对被过滤。

### 4.3 stserver 联合测试

```bash
# 启动 stserver
./stserver --config stserver.test.conf

# 运行 TURN TCP relay 测试（RFC 6062 Mode-B）
./test_stserver_all.exe 127.0.0.1 3478 turn-tcp

# 运行 TURN relay 测试（TCP 传输）
./test_stserver_relay.exe 127.0.0.1 3478 tcp
```

`turn-tcp` 模式测试完整流程：分配 → CreatePermission → CONNECT → CONNECTION-BIND → 数据交换。

## 5. 常见问题与排错

### 5.1 CONNECT 失败（错误码 447 Connection Timeout or Failure）

**原因**：TURN 服务器无法与对端中继地址建立 TCP 连接。

**排查**：
1. 确认对端已完成 TURN 分配并获得中继候选者。
2. 确认对端已为本地中继地址创建 CreatePermission（RFC 6062 §4.4：无权限时服务器不发送 CONNECTION-ATTEMPT）。
3. 检查防火墙是否允许 TURN 服务器的出站 TCP 连接到中继端口范围。
4. stice 会自动重试 CONNECT 最多 3 次（间隔 500ms），超过后标记候选对失败。

### 5.2 数据连接建立后无数据传输

**原因**：CONNECTION-BIND 未成功，或 STUN 连接检查未通过数据连接发送。

**排查**：
1. 检查日志中是否有 `TURN data: opening data connection connId=...`。
2. 检查 `CONNECTION-BIND` 是否收到成功响应。
3. 确认 `turnDataConn_->bound == true`（STUN 检查仅在绑定完成后通过数据连接发送）。
4. 检查候选对是否被识别为 `pairIsTurnTcpRelay`（本地候选者为 `relayed` 且 `transport=TCPPassive`）。

### 5.3 双方同时发送 CONNECT

**原因**：RFC 6062 要求只有一方发送 CONNECT，另一方等待 CONNECTION-ATTEMPT。

**stice 的处理**：使用 `shouldInitiateTcpConnect()` 基于 ufrag 字典序确定性选择主动方，避免双方同时发送。如果 ufrag 尚未交换（`remote_.iceUfrag.empty()`），则回退到 ICE 角色（Controlling 方为主动）。

### 5.4 与 coturn 的兼容性

stice 的 RFC 6062 实现与 [coturn](https://github.com/coturn/coturn) 服务器兼容。使用 coturn 时确保：
- 服务器配置中启用 TCP 中继（`listening-port` 同时监听 TCP）。
- 中继端口范围（`min-port`/`max-port`）有足够的 TCP 端口。
- 长期凭证认证配置正确。

## 6. 设计决策与限制

### 6.1 单数据连接限制

当前 stice 每个 Agent 仅维护一个 `turnDataConn_`（Mode-B 数据连接）。这意味着在多对场景下，同一时间只能有一个 TCP 中继对处于活跃数据传输状态。这是 ICE 场景的典型限制（通常只有一个 selected pair），但在需要同时维护多个 TCP 中继连接的场景下需要扩展。

### 6.2 ufrag 排序选择主动方

RFC 6062 规范未规定如何选择 CONNECT 发起方。stice 采用 ufrag 字典序比较（与 libjuice 一致），优点是在 ICE 角色冲突解决之前就能确定性地选择主动方，确保 CONNECT 在 STUN 检查之前完成。

### 6.3 CreatePermission 仍然需要

RFC 6062 场景下 CreatePermission 不是可选的。被动方的 TURN 服务器在接受入站 TCP 连接时会检查权限，无权限时关闭连接且不发送 CONNECTION-ATTEMPT。stice 在 `formPairs()` 阶段提前调用 `ensurePermission()` 确保权限就绪。

## 7. 参考资料

- RFC 6062: Traversal Using Relays around NAT (TURN) Extensions for TCP Allocations
- RFC 8656: Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)
- RFC 6544: TCP Candidates with Interactive Connectivity Establishment (ICE)
- RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
- pion/turn: Go 语言 TURN 实现（stice 的移植参考）
- libjuice: C 语言 ICE 库（stice 的 API 兼容目标）
