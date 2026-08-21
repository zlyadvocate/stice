# stice

[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)
[![Version](https://img.shields.io/badge/version-0.10.0-blue.svg)]()
[![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C.svg)]()

**C++17 ICE + TURN 客户端库，从 [pion/webrtc](https://github.com/pion/webrtc) (Go) 移植，设计为 [libjuice](https://github.com/paullouisageneau/libjuice) 的 drop-in 替代品。**

stice 用现代 C++17 实现了 ICE（Interactive Connectivity Establishment，RFC 8445）代理和 TURN（Traversal Using Relays around NAT，RFC 8656、RFC 6062）客户端，提供稳定的 C ABI。它同时提供原生 `stice_*` API 和完整的 `juice_*` 兼容层，允许现有 libjuice 用户（如 [libdatachannel](https://github.com/paullouisageneau/libdatachannel)）通过机械重命名进行切换。

> **注意**：本 README 的英文版见 [README.md](README.md)

## 协议支持

| 协议 | 规范 | 客户端 (stice) | 服务端 (stserver) |
|------|------|:--------------:|:-----------------:|
| STUN Message | RFC 8489 | ✅ | ✅ |
| ICE Agent | RFC 8445 | ✅ | — |
| ICE-TCP (TCP 候选者) | RFC 6544 | ✅ active/passive/SO | ✅ passive (via TCPMux) |
| TURN (UDP 中继) | RFC 8656 | ✅ | ✅ |
| TURN over TCP (控制) | RFC 8656 | ✅ | ✅ |
| TURN over TLS | RFC 8656 | ✅ | — |
| TURN TCP Allocations (Mode-A/B) | RFC 6062 | ✅ CONNECT/CONNECTION-ATTEMPT/CONNECTION-BIND | ✅ data pipe relay |
| mDNS 候选者 | draft-ietf-rtcweb-mdns-ice-candidates | ✅ query/gather | — |
| Trickle ICE | draft-ietf-ice-trickle | ✅ | — |

## 特性

- **ICE Agent (RFC 8445)** — 完整连接性检查、aggressive/regular 提名、trickle ICE、ICE restart、controlled/controlling 角色
- **STUN client (RFC 8489)** — server-reflexive 候选者收集、多 STUN 并行查询、认证
- **TURN client (RFC 8656 + RFC 6062)** — UDP/TCP/TLS 传输；channel data；permissions；**RFC 6062 TCP allocations**，含 Mode-A 控制连接和 Mode-B 数据管道（CONNECT / CONNECTION-ATTEMPT / CONNECTION-BIND / CONNECTION-ID）
- **ICE-TCP (RFC 6544)** — active / passive / simultaneous-open 模式、TCP 优先级偏移、per-pair TCPMux 被动监听
- **Multicast DNS (mDNS)** — query-only 和 query-and-gather 模式，保护本地候选者隐私
- **NAT 1:1 地址重写** — replace 或 append 外部 IP 映射，支持 host/srflx/relay 候选者
- **UDP / TCP 多路复用** — 多个 agent 共享单个 socket（UDPMux / TCPMux）
- **可配置配对策略** — RFC 8445 strict、serial、limited-concurrent、phased-UDP-first 调度；aggressive / regular / stable 提名；RFC 6062 TCP-relay 回退策略；lazy Mode-B 预分配
- **内置 TURN 服务器 (`stserver`)** — UDP + TCP 监听、STUN binding、TURN UDP 中继、TURN TCP 中继（RFC 6062 Mode-B 数据管道）、ICE-TCP 被动候选者支持；epoll / IOCP / select 后端
- **libjuice 兼容** — 通过 `juice_compat.cpp` 实现 `juice_*` C API 的 drop-in 替换
- **跨平台** — Windows (MSVC/MinGW)、Linux、macOS

## 项目结构

```
stice/
├── CMakeLists.txt          # 构建配置 (CMake 3.13+)
├── LICENSE                 # Mozilla Public License 2.0
├── README.md               # 英文文档
├── README.zh.md            # 中文文档（本文件）
├── CHANGELOG.md
├── .gitignore
├── stserver.conf.example   # stserver 配置模板
├── stserver.test.conf      # 运行测试套件的 stserver 配置 (testuser/123456)
├── docs/                   # 深度技术文档（中英文）
├── include/
│   ├── stice/
│   │   ├── stice.h         # 公共 C ABI (stice_*)
│   │   ├── crypto.hpp
│   │   ├── log.hpp
│   │   ├── types.hpp
│   │   ├── ice/            # ICE agent、候选者、SDP、配对策略、地址重写
│   │   ├── net/            # UDP、TCP、poll、mux、mDNS、addr、platform
│   │   ├── stun/           # STUN 消息、属性、客户端
│   │   ├── turn/           # TURN 客户端、channel data、stun connection (RFC 6062)
│   │   └── stserver/       # 内置 TURN 服务器 (config, turn_server, io_backend)
│   └── juice/
│       └── juice.h         # libjuice 兼容 C API (juice_*)
├── src/
│   ├── c_api.cpp           # stice_* C ABI 实现
│   ├── juice_compat.cpp    # juice_* 兼容层
│   ├── log.cpp
│   ├── crypto/
│   ├── ice/
│   ├── net/
│   ├── stun/
│   ├── turn/
│   └── stserver/           # TURN 服务器 (main, config, turn_server, io_iocp/epoll/select)
├── tests/
│   ├── test_*.cpp          # 单元/集成/性能测试 (Catch2)
│   └── libjuice_compat/    # libjuice API 兼容性测试
└── third_party/
    └── Catch2/             # 测试框架
```

## 构建

### 前置条件

- CMake ≥ 3.13
- C++17 编译器 (MSVC 2019+, GCC 8+, Clang 7+)
- OpenSSL（可选，用于 TURN/TLS 和 HMAC-SHA；默认 `STICE_USE_OPENSSL=ON`）

### 快速开始

```bash
# 配置
cmake -B build -S .

# 构建
cmake --build build --config Release

# 运行测试
ctest --test-dir build --output-on-failure
```

### CMake 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `STICE_BUILD_TESTS` | `ON` | 构建单元和集成测试 |
| `STICE_BUILD_STSERVER` | `ON` | 构建内置 TURN/STUN 服务器 (`stserver`) |
| `STICE_USE_OPENSSL` | `ON` | 使用 OpenSSL 进行加密和 TURN/TLS |
| `BUILD_SHARED_LIBS` | `OFF` | 构建共享库（默认：静态库） |

### 作为子项目集成

stice 设计为可通过 `add_subdirectory()` 直接嵌入：

```cmake
add_subdirectory(third_party/stice)
target_link_libraries(myapp PRIVATE LibJuice::LibJuice)
```

`juice` 目标别名为 `LibJuice::LibJuice`，`juice-static` 别名为 `LibJuice::LibJuiceStatic`，与 libjuice 的 CMake 包名一致。

## 使用

### 原生 stice API

```c
#include <stice/stice.h>

static void on_state_changed(stice_agent_t *agent, stice_state_t state, void *user) {
    printf("ICE state: %s\n", stice_state_to_string(state));
}

static void on_candidate(stice_agent_t *agent, const char *sdp, void *user) {
    // 通过信令发送候选者给对端
    printf("Local candidate: %s\n", sdp);
}

int main(void) {
    stice_config_t config = {0};
    config.stun_server_host = "stun.l.google.com";
    config.stun_server_port = 19302;
    config.cb_state_changed = on_state_changed;
    config.cb_candidate = on_candidate;

    stice_agent_t *agent = stice_create(&config);
    stice_gather_candidates(agent);

    // ... 与对端交换 SDP 和候选者 ...

    char local_sdp[4096];
    stice_get_local_description(agent, local_sdp, sizeof(local_sdp));
    stice_set_remote_description(agent, remote_sdp);

    // 连接后发送数据
    stice_send(agent, "hello", 5);

    stice_destroy(agent);
    return 0;
}
```

### libjuice 兼容

只需将 `juice.h` 替换为 stice 的 `juice/juice.h` 并链接 `LibJuice::LibJuice`。所有 `juice_*` 函数均受支持。

### TURN 服务器 (stserver)

内置 TURN/STUN 服务器 (`stserver`) 提供完整的中继实现：

- **UDP 监听** — STUN Binding 请求 + TURN UDP 分配 (RFC 8656)
- **TCP 监听** — TURN over TCP 控制连接 + RFC 6062 Mode-B TCP 分配，含 CONNECT/CONNECTION-ATTEMPT/CONNECTION-BIND 和原始数据管道中继
- **ICE-TCP passive** — 接受 RFC 6544 被动候选者的入站 TCP 连接（当客户端使用 TCPMux 时）
- **长期凭证认证** — 通过配置的 user/password 数据库
- **IO 后端** — IOCP (Windows)、epoll (Linux)、select (跨平台回退)

```bash
# 构建服务器 (由 STICE_BUILD_STSERVER=ON 启用，默认 ON)
cmake --build build --target stserver

# 复制并编辑示例配置
cp stserver.conf.example stserver.conf

# 运行
./build/stserver --config stserver.conf
```

## 配对策略配置

stice 通过 `stice_ice_pairing_config_t` 暴露运行时可配置的 ICE 配对策略：

| 配置 | 适用场景 |
|------|----------|
| `STICE_PAIRING_RFC8445_COMPAT` | 标准 RFC 8445 行为，最大互操作性 |
| `STICE_PAIRING_EMBEDDED_STABLE` | 嵌入式/IoT 设备，资源受限，稳定提名 |
| `STICE_PAIRING_DEBUG_FAST` | 开发阶段，激进检查，快速收敛 |
| `STICE_PAIRING_MINIMAL_RESOURCE` | 超低内存/CPU 占用 |

```c
stice_ice_pairing_config_t cfg;
stice_make_pairing_config(STICE_PAIRING_EMBEDDED_STABLE, &cfg);
stice_set_pairing_config(agent, &cfg);
```

## 测试

测试套件使用 [Catch2](https://github.com/catchorg/Catch2) 进行单元测试，使用独立二进制进行集成/压力测试。测试按外部依赖分为四个层级。

### 测试层级

#### 层级 1：核心单元测试（无外部依赖）

可在任何环境运行，覆盖协议逻辑、数据结构和算法。

| 测试 | 框架 | 说明 |
|------|------|------|
| `test_candidate` | Catch2 | ICE 候选者优先级 (RFC 8445 §5.1.2)、SDP 序列化/解析、TCPType 合法性 (RFC 6544) |
| `test_candidate_pair` | Catch2 | 候选者对优先级 (RFC 8445 §6.1.2.3)、TCP 对过滤 (RFC 6544 §5.2 + RFC 6062 中继例外) |
| `test_stun` | Catch2 | STUN 消息编解码、属性解析、FINGERPRINT、MESSAGE-INTEGRITY |
| `test_turn` | Catch2 | TURN 分配状态机、channel data、permissions；**RFC 6062** TCP 分配 (CONNECT/CONNECTION-ATTEMPT/CONNECTION-BIND/CONNECTION-ID)、active+passive 双模式 |
| `test_pairing_strategy` | Catch2 | ICE 检查调度、提名模式、RFC 6062 TCP-relay 回退、链路重选 |
| `test_functional` | Catch2 | 端到端 ICE agent 功能测试（回环 UDP 对） |
| `test_debug` | Catch2 | 内部调试工具和日志 |
| `test_performance` | Catch2 | 微基准：候选者排序、对形成、STUN 解析吞吐量 |
| `test_stress` | Catch2 | Agent 生命周期压力：create/gather/destroy 循环、资源泄漏检查 |

运行所有层级 1 测试：

```bash
ctest --test-dir build -C Release --output-on-failure \
  -E "test_conn|test_integration|test_stserver"
```

#### 层级 2：网络连通性测试

| 测试 | 说明 |
|------|------|
| `test_conn` | 独立 STUN 连通性测试 — 通过双栈 IPv6 socket 向 STUN 服务器发送 Binding Request 并验证响应。默认目标 `192.168.3.223:3478`。 |

```bash
# 使用默认 STUN 服务器
./build/Release/test_conn.exe

# 或指定公共 STUN 服务器（修改源码自定义目标）
```

#### 层级 3：stserver 集成与压力测试（需要运行 stserver）

这些测试启动成对的 stice agent，通过本地 `stserver` 实例驱动。端到端验证 STUN、TURN-UDP、TURN-TCP (RFC 6062) 和 ICE-TCP (RFC 6544)。

| 测试 | 说明 | 默认参数 |
|------|------|----------|
| `test_stserver_all` | 综合 4 模式测试：`ice-udp`、`ice-tcp`、`turn-udp`、`turn-tcp` (RFC 6062 Mode-B)。每种模式创建一对 agent，收集、连接、交换数据。 | `[host] [port] [mode]` → `127.0.0.1 3478 turn-udp` |
| `test_stserver_relay` | 纯 TURN 中继测试：强制双方使用中继候选者，验证 UDP 或 TCP 上的分配+数据交换。 | `[host] [port] [transport]` → `127.0.0.1 13478 udp` |
| `test_stserver_tcp_diag` | TCP 中继诊断，含详细客户端日志 — 捕获 TURN-over-TCP 状态转换用于调试。 | `127.0.0.1 3478` |
| `test_stserver_stress_tcp` | 高并发 TCP 压力：N 对 agent 全部通过 stserver 使用 TURN over TCP (RFC 6062 Mode-B)。报告成功率和每对耗时。 | `[host] [port] [pairs] [timeout_ms]` → `127.0.0.1 13478 20 20000` |
| `test_stserver_stress_mixed` | 混合负载压力：N ICE-UDP 对 + M1 TURN-UDP + M2 TURN-TCP 后台会话同时运行。验证混合负载下 stserver D-plan (IOCP/epoll)。 | `[host] [port] [icePairs] [turnUdpBg] [turnTcpBg] [timeoutMs]` → `127.0.0.1 3478 1000 20 20 30000` |

##### 运行 stserver 集成测试

**步骤 1：准备测试配置**

测试使用用户名 `testuser` / 密码 `123456` 连接。提供了现成配置：

```bash
# stserver.test.conf 已包含 users = testuser:123456
# 复制到 stserver 二进制旁边（或通过 --config 指定）
cp stserver.test.conf build/Release/stserver.conf
```

**步骤 2：启动 stserver**

```bash
# 终端 1：启动服务器
./build/Release/stserver.exe --config stserver.test.conf
# [stserver/INF] stserver: running (config=stserver.test.conf)
```

**步骤 3：运行集成测试**

```bash
# 终端 2：通过 stserver 运行全部 4 种传输模式
./build/Release/test_stserver_all.exe 127.0.0.1 3478 ice-udp
./build/Release/test_stserver_all.exe 127.0.0.1 3478 ice-tcp
./build/Release/test_stserver_all.exe 127.0.0.1 3478 turn-udp
./build/Release/test_stserver_all.exe 127.0.0.1 3478 turn-tcp

# TURN 中继测试 (UDP 和 TCP)
./build/Release/test_stserver_relay.exe 127.0.0.1 3478 udp
./build/Release/test_stserver_relay.exe 127.0.0.1 3478 tcp

# TCP 中继诊断 (详细日志)
./build/Release/test_stserver_tcp_diag.exe 127.0.0.1 3478

# 压力：50 对 TCP 中继
./build/Release/test_stserver_stress_tcp.exe 127.0.0.1 3478 50 30000

# 混合压力：100 ICE-UDP + 10 TURN-UDP + 10 TURN-TCP
./build/Release/test_stserver_stress_mixed.exe 127.0.0.1 3478 100 10 10 30000
```

每个测试成功时打印 `=== PASS: ... ===`，失败时打印 `=== FAIL: ... ===` 及诊断信息。

#### 层级 4：外部 coturn 集成测试

| 测试 | 说明 |
|------|------|
| `test_integration` | 基于 Catch2 的外部 [coturn](https://github.com/coturn/coturn) 服务器集成测试。覆盖 TURN 中继 (UDP+TCP)、多 ICE 服务器并行收集、RFC 6062 TURN-over-TCP。需要可达的 coturn 实例（默认 `192.168.3.223:3478`，凭据 `testuser`/`123456`）。 |

```bash
# 指向你的 coturn 服务器（修改源码或使用默认）
ctest --test-dir build -C Release -R test_integration --output-on-failure --timeout 120
```

### 运行完整套件

```bash
# 构建所有内容（库 + stserver + 全部测试）
cmake --build build --config Release

# 层级 1 + 2（无需服务器）
ctest --test-dir build -C Release --output-on-failure -E "test_integration|test_stserver"

# 层级 3（先启动 stserver，见上文）
ctest --test-dir build -C Release -R "test_stserver" --output-on-failure --timeout 60

# 层级 4（需要外部 coturn）
ctest --test-dir build -C Release -R test_integration --output-on-failure --timeout 120
```

### Catch2 测试过滤

基于 Catch2 的测试支持标签过滤：

```bash
# 仅运行 RFC 6062 测试
./build/Release/test_turn.exe "[rfc6062]"

# 仅运行候选者对测试
./build/Release/test_candidate_pair.exe "[pair]"

# 列出所有测试
./build/Release/test_stun.exe --list-tests
```

## 文档

`docs/` 目录提供深度技术文档，所有文档均提供中英文版本。

| 文档 | 英文 | 中文 | 说明 |
|------|------|------|------|
| TURN over TCP 控制连接 (RFC 8656) | [EN](docs/TURN-over-TCP-RFC8656.en.md) | [ZH](docs/TURN-over-TCP-RFC8656.md) | 自定界 STUN/ChannelData 帧、StunConn 解析器、Mode-A 控制连接、长期凭证认证、C API 使用 |
| RFC 6062 TCP Allocations | [EN](docs/RFC6062-TCP-Allocations.en.md) | [ZH](docs/RFC6062-TCP-Allocations.zh.md) | Mode-A/B 架构、CONNECT/CONNECTION-ATTEMPT/CONNECTION-BIND 流程、CONNECTION-ID、RFC 4571 帧数据连接、基于 ufrag 的发起方选择 |
| 与 libdatachannel 集成 | [EN](docs/Integration-with-libdatachannel.en.md) | [ZH](docs/Integration-with-libdatachannel.zh.md) | Drop-in 替换指南、add_subdirectory/find_package/FetchContent 方法、兼容性保证、功能差异、FAQ |

## 许可证

本项目采用 **Mozilla Public License 2.0 (MPL-2.0)** 许可证。

```
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.
```

MPL-2.0 是弱 copyleft 许可证：对 stice 源文件的修改必须在 MPL-2.0 下共享，但该库可以链接到专有应用中而不影响更大作品的许可证。完整文本见 [LICENSE](LICENSE) 文件。

## 作者

- **zlyadvocate** — 原作者和维护者

## 致谢

- [pion/webrtc](https://github.com/pion/webrtc) — stice 移植自的 Go 实现
- [libjuice](https://github.com/paullouisageneau/libjuice) — stice 镜像其 API 的库
- [libdatachannel](https://github.com/paullouisageneau/libdatachannel) — 主要集成目标
