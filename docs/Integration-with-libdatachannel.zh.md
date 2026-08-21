# 在 libdatachannel 中集成 stice

## 1. 概述

stice 是一个 C++17 实现的 ICE + TURN 客户端库，从 pion/webrtc (Go) 移植，设计为 [libjuice](https://github.com/paullouisageneau/libjuice) 的 **drop-in 替代品**。[libdatachannel](https://github.com/paullouisageneau/libdatachannel) 原本使用 libjuice 作为 ICE 后端，通过 stice 提供的 `juice_*` 兼容层和 CMake 目标别名，可以**零源码修改**地将 libdatachannel 的 ICE 后端切换为 stice。

### 1.1 兼容性保证

| 维度 | 兼容方式 |
|------|---------|
| C API | `juice_compat.cpp` 实现全部 `juice_*` 函数，转发到 `stice_*` |
| 头文件 | `include/juice/juice.h` 与 libjuice 头文件签名完全一致 |
| 枚举值 | `juice_state_t`、`juice_turn_transport_t`、`juice_concurrency_mode_t` 等与 stice 对应枚举二进制兼容（相同整数值） |
| CMake 目标 | `juice` → 别名 `LibJuice::LibJuice`；`juice-static` → 别名 `LibJuice::LibJuiceStatic` |
| CMake 包名 | `EXPORT_NAME LibJuice`，`find_package(LibJuice)` 可直接找到 |
| 回调签名 | `juice_cb_*_t` 与 `stice_cb_*_t` 参数类型完全相同，通过 `reinterpret_cast` 转换 |

### 1.2 stice 相比 libjuice 的增强

| 特性 | libjuice | stice |
|------|----------|-------|
| ICE-TCP (RFC 6544) | 仅 active 模式 | active / passive / simultaneous-open |
| TURN over TCP (RFC 8656) | ✅ | ✅ |
| TURN TCP Allocation (RFC 6062) | ❌ | ✅ Mode-A + Mode-B |
| mDNS 候选者 | ❌ | ✅ query-only / query-and-gather |
| NAT 1:1 地址重写 | ❌ | ✅ replace / append |
| UDP/TCP 多路复用 | 基础 | ✅ UDPMux + TCPMux |
| 可配置配对策略 | 固定 | ✅ 4 种预设 + 运行时调参 |
| 内置 TURN 服务器 | ❌ | ✅ stserver (IOCP/epoll/select) |
| 语言 | C | C++17 (提供 C ABI) |

## 2. 集成方式

### 2.1 方式一：add_subdirectory（推荐）

将 stice 源码作为子目录嵌入 libdatachannel 项目，无需预先安装。

**步骤 1：获取 stice 源码**

```bash
# 方式 A：git submodule
cd libdatachannel
git submodule add https://github.com/zlyadvocate/stice.git deps/stice

# 方式 B：直接克隆
git clone https://github.com/zlyadvocate/stice.git deps/stice
```

**步骤 2：修改 libdatachannel 的 CMakeLists.txt**

找到 libdatachannel 中引用 libjuice 的部分，通常是：

```cmake
# 原配置（使用系统 libjuice或 FetchContent）
find_package(LibJuice REQUIRED)
target_link_libraries(datachannel PRIVATE LibJuice::LibJuice)
```

替换为：

```cmake
# 使用 stice 作为 libjuice 替代品
set(STICE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(STICE_BUILD_STSERVER OFF CACHE BOOL "" FORCE)
add_subdirectory(deps/stice)

# stice 的 juice 目标别名为 LibJuice::LibJuice，与 libjuice 完全兼容
# datachannel 的 target_link_libraries 无需修改
```

如果 libdatachannel 使用静态链接（`datachannel-static`），确保链接 `LibJuice::LibJuiceStatic`：

```cmake
target_link_libraries(datachannel-static PRIVATE LibJuice::LibJuiceStatic)
```

**步骤 3：构建**

```bash
cmake -B build -S . -DUSE_GNUTLS=OFF -DUSE_MBEDTLS=OFF
cmake --build build --config Release
```

> **注意**：stice 使用 OpenSSL 进行加密和 TURN/TLS。如果 libdatachannel 原本使用 GnuTLS 或 MbedTLS，需要确保 OpenSSL 可用，或在 stice 中设置 `STICE_USE_OPENSSL=OFF`（将禁用 TURN/TLS 和部分加密功能）。

### 2.2 方式二：find_package（安装后使用）

先构建并安装 stice，然后通过 `find_package` 找到。

**步骤 1：构建并安装 stice**

```bash
git clone https://github.com/zlyadvocate/stice.git
cd stice
cmake -B build -S . -DCMAKE_INSTALL_PREFIX=/usr/local -DSTICE_BUILD_TESTS=OFF -DSTICE_BUILD_STSERVER=OFF
cmake --build build --config Release
cmake --install build
```

安装后文件布局：
```
/usr/local/
├── include/
│   ├── stice/stice.h      # stice 原生 C API
│   └── juice/juice.h      # libjuice 兼容 C API
├── lib/
│   ├── libjuice.so        # 共享库（EXPORT_NAME=LibJuice）
│   ├── cmake/LibJuice/
│   │   ├── LibJuiceConfig.cmake
│   │   └── LibJuiceTargets.cmake
```

**步骤 2：在 libdatachannel 中使用**

libdatachannel 的 CMakeLists.txt **无需任何修改**，因为 stice 的安装包名就是 `LibJuice`：

```cmake
find_package(LibJuice REQUIRED)
target_link_libraries(datachannel PRIVATE LibJuice::LibJuice)
```

构建时指定安装前缀：

```bash
cmake -B build -S . -DCMAKE_PREFIX_PATH=/usr/local
cmake --build build --config Release
```

### 2.3 方式三：FetchContent

在 libdatachannel 的 CMakeLists.txt 中使用 FetchContent 自动下载 stice：

```cmake
include(FetchContent)
set(STICE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(STICE_BUILD_STSERVER OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    stice
    GIT_REPOSITORY https://github.com/zlyadvocate/stice.git
    GIT_TAG        v0.10.0
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(stice)
# LibJuice::LibJuice 目标自动可用
```

## 3. CMake 配置选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `STICE_BUILD_TESTS` | `ON` | 构建单元测试。集成到 libdatachannel 时建议设为 `OFF` |
| `STICE_BUILD_STSERVER` | `ON` | 构建内置 TURN 服务器 stserver。集成时建议设为 `OFF` |
| `STICE_USE_OPENSSL` | `ON` | 使用 OpenSSL 进行加密和 TURN/TLS。设为 `OFF` 将禁用 TLS |
| `BUILD_SHARED_LIBS` | `OFF` | 构建共享库。默认静态库 |

在 libdatachannel 集成中，推荐配置：

```cmake
set(STICE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(STICE_BUILD_STSERVER OFF CACHE BOOL "" FORCE)
set(STICE_USE_OPENSSL ON CACHE BOOL "" FORCE)
```

## 4. 功能差异与注意事项

### 4.1 juice_mux_listen 是 no-op

stice 提供了 `juice_mux_listen()` 的实现，但它是一个 **no-op stub**（返回 0 表示成功）。stice 使用不同的 UDPMux API（`stice_create_udp_mux` / `stice_agent_use_udp_mux`），与 libjuice 的 `juice_mux_listen` 设计不同。

libdatachannel 的 `IceUdpMuxListener` 功能在启用 `enableIceUdpMux` 时会调用此函数。libdatachannel 的测试套件默认不启用此功能，因此 no-op 不影响常规使用。

**如果需要 UDPMux 功能**：使用 stice 原生 API 替代，或等待后续版本在兼容层中实现完整的 UDPMux 支持。

### 4.2 juice_server_* 是 stub

`juice_server_create`、`juice_server_destroy`、`juice_server_get_port`、`juice_server_add_credentials` 均为 stub 实现（返回 nullptr / 0 / -1）。libdatachannel 不使用这些函数（它有自己的测试服务器），因此不影响集成。

stice 提供了独立的 `stserver` 可执行文件作为内置 TURN 服务器，功能更完整。

### 4.3 ICE-TCP 模式扩展

libjuice 的 `juice_ice_tcp_mode_t` 仅定义了 `NONE=0` 和 `ACTIVE=1`。stice 的 `stice_ice_tcp_mode_t` 扩展了 `PASSIVE=2` 和 `SO=3`（simultaneous-open）。

兼容层的 `juice_set_ice_tcp_mode()` 直接将值转发给 stice，因此 libdatachannel 只能使用 NONE 和 ACTIVE 两种模式。要使用 passive 或 SO 模式，需要使用 stice 原生 API `stice_set_ice_tcp_mode()`。

### 4.4 TURN 服务器配置的 skip_tls_verify

libjuice 的 `juice_turn_server_t` 没有 `skip_tls_verify` 字段。stice 的 `stice_turn_server_t` 有此字段。兼容层在转换时默认设置 `skip_tls_verify = 0`（验证证书，安全默认）。

如果需要跳过 TLS 证书验证（测试自签名证书），使用 stice 原生 API `stice_add_turn_server()` 并设置 `skip_tls_verify = 1`。

### 4.5 并发模式

libjuice 的 `juice_concurrency_mode_t` 定义了 `POLL=0`、`MUX=1`、`THREAD=2`。stice 的 `stice_concurrency_mode_t` 值相同，兼容层直接转换。libdatachannel 默认使用 POLL 模式。

### 4.6 日志系统

`juice_set_log_level()` 和 `juice_set_log_handler()` 完全转发到 stice 的对应函数。日志级别枚举值二进制兼容。libdatachannel 的日志配置无需修改。

## 5. 验证集成

### 5.1 编译验证

构建成功后，检查链接的库：

```bash
# Linux
ldd build/libdatachannel.so | grep juice

# Windows (PowerShell)
Get-Content build/Release/datachannel.dir/link.rule | Select-String juice
```

应该看到链接到 stice 构建的 `libjuice.so`（或 `juice.lib`），而不是系统的 libjuice。

### 5.2 运行时验证

运行 libdatachannel 的示例程序，检查 ICE 连接建立：

```bash
# 运行 peerconnection 示例（两个终端）
./build/examples/peerconnection server
./build/examples/peerconnection client
```

观察日志中是否有 stice 的输出（如 `TURN allocate`、`ICE state changed` 等）。

### 5.3 功能验证清单

- [ ] STUN 服务器反射候选者收集
- [ ] TURN 中继候选者收集（UDP）
- [ ] TURN over TCP 控制连接
- [ ] ICE 连接建立（host/srflx/relay）
- [ ] Trickle ICE 候选者交换
- [ ] 数据通道建立与数据传输
- [ ] ICE 断开与重连
- [ ] 日志输出正常

## 6. 常见问题

### Q1：链接错误 "undefined reference to juice_create"

**原因**：没有正确链接 `LibJuice::LibJuice` 目标。

**解决**：确认 CMakeLists.txt 中有：
```cmake
target_link_libraries(datachannel PRIVATE LibJuice::LibJuice)
```
并且 stice 已通过 `add_subdirectory`、`find_package` 或 `FetchContent` 正确引入。

### Q2：编译错误 "juice/juice.h: No such file or directory"

**原因**：stice 的 include 目录没有被添加到包含路径。

**解决**：`LibJuice::LibJuice` 目标应该自动传递 include 目录。如果使用手动链接，确认：
```cmake
target_include_directories(datachannel PRIVATE deps/stice/include)
```

### Q3：TURN/TLS 连接失败

**原因**：stice 的 TURN/TLS 依赖 OpenSSL，可能没有找到 OpenSSL 或证书验证失败。

**解决**：
1. 确认系统安装了 OpenSSL 开发包（`libssl-dev` / `openssl-devel`）。
2. 检查 CMake 配置输出中是否有 `OpenSSL found`。
3. 测试自签名证书时，使用 stice 原生 API 设置 `skip_tls_verify = 1`。

### Q4：Windows 上链接错误 LNK2019

**原因**：Windows 上需要额外链接 `ws2_32` 和（如果使用 OpenSSL）`crypt32`。

**解决**：stice 的 `stice_apply_common()` 函数应该自动处理这些依赖。如果手动链接，确认：
```cmake
if(WIN32)
    target_link_libraries(datachannel PRIVATE ws2_32 crypt32)
endif()
```

### Q5：如何确认运行时使用的是 stice 而非 libjuice

**方法**：
1. 检查日志前缀：stice 的日志包含 `[stice/...]` 前缀。
2. 检查中继候选者：stice 支持 RFC 6062 TCP 中继（`tcptype=passive`），libjuice 不支持。
3. 使用 `stice_get_version()`（原生 API）获取版本号，应返回 `0.10.0`。

### Q6：性能对比

stice 从 pion/webrtc 移植，配对策略和调度算法与 pion 一致。在高并发场景下，stice 的可配置配对策略（如 `PHASED_UDP_FIRST`、`LIMITED_CONCURRENT`）可以提供比 libjuice 固定策略更好的性能。建议根据场景通过 `stice_set_pairing_config()` 调优。

## 7. 参考链接

- stice 仓库：https://github.com/zlyadvocate/stice
- libdatachannel 仓库：https://github.com/paullouisageneau/libdatachannel
- libjuice 仓库：https://github.com/paullouisageneau/libjuice
- pion/webrtc（stice 移植来源）：https://github.com/pion/webrtc
- RFC 8445 ICE：https://tools.ietf.org/html/rfc8445
- RFC 8656 TURN：https://tools.ietf.org/html/rfc8656
- RFC 6062 TURN TCP Allocations：https://tools.ietf.org/html/rfc6062
- RFC 6544 ICE-TCP：https://tools.ietf.org/html/rfc6544
