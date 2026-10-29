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
| TURN over TLS 后端 | 仅 OpenSSL | ✅ OpenSSL / GnuTLS / Mbed TLS |
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
# 默认：OpenSSL
cmake -B build -S .

# 与 libdatachannel 的主加密后端保持一致
cmake -B build -S . -DUSE_GNUTLS=ON      # 或 -DUSE_MBEDTLS=ON
cmake --build build --config Release
```

> **注意**：stice 的 TLS 后端与 libdatachannel 使用**同一组 CMake 缓存变量**（`USE_GNUTLS` / `USE_MBEDTLS`）。父工程（libdatachannel）选定哪个后端，stice 就自动使用同一个，无需额外配置，详见 2.4 节。

### 2.4 TLS 后端一致性（OpenSSL / GnuTLS / Mbed TLS）

stice 的 TURN over TLS（RFC 8656 §4）走一层可插拔的 TLS 抽象（`src/net/tls_*.cpp`），
在编译期三选一，选择方式与 libdatachannel 完全一致：

| CMake 变量 | 使用的库 | 依赖查找 | 传给编译器的定义 |
|-----------|---------|---------|----------------|
| `USE_GNUTLS=ON` | GnuTLS | `find_package(GnuTLS)` → `GnuTLS::GnuTLS` | `USE_GNUTLS=1` |
| `USE_MBEDTLS=ON` | Mbed TLS（2.x / 3.x） | `find_package(MbedTLS)` → `MbedTLS::MbedTLS` | `USE_MBEDTLS=1` |
| 两者都不设置（默认） | OpenSSL | `find_package(OpenSSL)` | `USE_GNUTLS=0` |

要点：

- 同时打开 `USE_GNUTLS` 与 `USE_MBEDTLS` 会直接 configure 失败（与 libdatachannel 行为一致）。
- 使用 `add_subdirectory(deps/stice)` 时**不需要**再传任何参数：stice 直接读取父工程的同名缓存变量。
- 独立构建 stice 时也可用别名 `STICE_USE_GNUTLS` / `STICE_USE_MBEDTLS`；
  `STICE_USE_OPENSSL=OFF` 且两者都不开时则不编译任何 TLS 后端（TURN over TLS 自动退化为明文 TCP，并打印警告）。
- `stice_get_tls_backend()` 返回 `"openssl"` / `"gnutls"` / `"mbedtls"` / `"none"`，可用于运行时自检。
- Windows 上 GnuTLS 没有 MSVC 版本（与 libdatachannel 的处境相同）：要么用 MinGW-w64 工具链
  （MSYS2 的 `mingw-w64-x86_64-gnutls`，已实测可编译并跑通全回归），要么在 Windows 上选 OpenSSL 或 Mbed TLS。
- ICE/STUN/TURN 的密码学原语（MD5/SHA-1/SHA-256/HMAC/CRC32/CSPRNG）始终是 stice 自带的实现，
  不依赖任何 TLS 库；换后端只影响 TLS 记录层。

**证书验证策略（三个后端一致）**

| 场景 | 行为 |
|------|------|
| 默认（`skip_tls_verify = 0`） | 用平台信任库验证服务器证书，并做 SNI/主机名校验 |
| 该 TURN 服务器设置了 `ca_file`（非空） | **只**用这个 PEM 证书包验证这一台服务器（优先级最高） |
| 设置了 `STICE_TLS_CA_FILE` | 用该 PEM 证书包替代平台信任库（便于固定自签 CA） |
| `skip_tls_verify = 1`（如 `juice` 的 `JUICE_TURN_TLS_NO_VERIFY`） | 关闭验证，仅用于测试 |
| Mbed TLS 且未设置 `STICE_TLS_CA_FILE` | Mbed TLS 不提供系统信任库，此时回落到 `VERIFY_NONE` 并打印告警 |
| **Windows + OpenSSL 且未设置 `STICE_TLS_CA_FILE`** | OpenSSL 不读 Windows 证书存储，`SSL_CTX_set_default_verify_paths()` 在该平台通常为空，因此**私有 CA / 自签证书的握手会验证失败**；请设置 `STICE_TLS_CA_FILE`（或仅在测试中 `skip_tls_verify = 1`） |
| **Mbed TLS 2.x + TURN 服务器用 IP 地址** | 已支持：2.x 不解析 `iPAddress` 类 SAN，stice 会自行解析对端证书的 subjectAltName 扩展来比对（3.x 由库自身完成）。地址不匹配时按失败处理，不会退化成“通过” |

> 简单记忆：能自动用平台信任库的只有 Linux/macOS 上的 OpenSSL 与 GnuTLS；**Windows 上的 OpenSSL、以及任何平台上的 Mbed TLS，都要显式给 `STICE_TLS_CA_FILE` 或 per-server `ca_file` 才能验证**。
>
> 信任锚的优先级是：**per-server `ca_file`（非空）> `STICE_TLS_CA_FILE` > 平台信任库**。`ca_file` 为 `NULL`/空串时才回落到环境变量，所以同一个 agent 可以同时连多台各用不同私有 CA 的 TURN 服务器——每台服务器在 `stice_turn_server_t.ca_file` 里写自己的证书包即可（字符串在该服务器被加入时深拷贝，调用方随后可以释放）。该字段是 0.13.0 在结构体尾部新增的：零初始化的结构体保持旧行为，二进制需重新编译。

**密码套件（三个后端一致，RFC 8656 §4）**

stice 主动配置只允许「前向保密密钥交换 + AEAD」的套件，而不是依赖各库默认值：TLS 1.2 下限、禁止静态 RSA 密钥交换、禁止 CBC 与 SHA-1 MAC。三后端分别用 `SSL_CTX_set_cipher_list` / `SSL_CTX_set_ciphersuites`（OpenSSL）、`gnutls_priority_set_direct`（GnuTLS，`NORMAL:-RSA:-VERS-TLS-ALL:+VERS-TLS1.3:+VERS-TLS1.2`）、`mbedtls_ssl_conf_ciphersuites` + TLS 1.3 仅 ephemeral 密钥交换（Mbed TLS）。若对端只支持旧套件（例如仅 CBC-SHA1 或纯 RSA 密钥交换的老设备），握手会被拒绝——这是有意的取舍；确实需要兼容时请改用不支持 TLS 的 TURN 端口（3478）或由运维侧代理。

**失败行为：严格合规，不自动降级**

握手失败时该 tls-turn 候选直接失败，ICE 按 RFC 8445 的失败分支继续尝试其它候选；stice **不会**把这条连接悄悄降级成明文 TCP。因此若某个 TURN 端点只支持已被剔除的旧套件，它对 stice 就是不可达的，通话可能因此失败——这是与 RFC 8445（候选失败处理）和 RFC 8656（端点按配置使用）一致的预期行为。需要排查时看 WARN 日志里的 `TLS handshake failed` / `certificate verification failed`，它指向具体原因（套件、信任锚或超时）。

### 2.5 方式二：find_package（安装后使用）

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

### 2.6 方式三：FetchContent

在 libdatachannel 的 CMakeLists.txt 中使用 FetchContent 自动下载 stice：

```cmake
include(FetchContent)
set(STICE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(STICE_BUILD_STSERVER OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    stice
    GIT_REPOSITORY https://github.com/zlyadvocate/stice.git
    GIT_TAG        v0.11.0
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(stice)
# LibJuice::LibJuice 目标自动可用
```

> `USE_GNUTLS` / `USE_MBEDTLS` 同样是缓存变量，FetchContent 子工程会自动继承父工程的选择，无需重复传递。

## 3. CMake 配置选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `STICE_BUILD_TESTS` | `ON` | 构建单元测试。集成到 libdatachannel 时建议设为 `OFF` |
| `STICE_BUILD_STSERVER` | `ON` | 构建内置 TURN 服务器 stserver。集成时建议设为 `OFF` |
| `STICE_USE_OPENSSL` | `ON` | 使用 OpenSSL 作为 TLS 后端（默认）。设为 `OFF` 且未选 GnuTLS/Mbed TLS 时不编译 TLS |
| `STICE_USE_GNUTLS` | `OFF` | 使用 GnuTLS 作为 TLS 后端，等价于 libdatachannel 的 `USE_GNUTLS` |
| `STICE_USE_MBEDTLS` | `OFF` | 使用 Mbed TLS 作为 TLS 后端，等价于 libdatachannel 的 `USE_MBEDTLS` |
| `USE_GNUTLS` / `USE_MBEDTLS` | `OFF` | 与 libdatachannel 同名的缓存变量，父工程设置后 stice 自动跟随 |
| `BUILD_SHARED_LIBS` | `OFF` | 构建共享库。默认静态库 |

在 libdatachannel 集成中，推荐配置：

```cmake
set(STICE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(STICE_BUILD_STSERVER OFF CACHE BOOL "" FORCE)
# TLS 后端不用显式设置：继承 libdatachannel 的 USE_GNUTLS / USE_MBEDTLS
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

libjuice 的 `juice_turn_server_t` 没有 `skip_tls_verify` 字段。stice 的 `stice_turn_server_t` 有此字段。

兼容层转换时的取值规则（`juice_create()` 与 `juice_add_turn_server()` 两条入口一致）：

| 条件 | 结果 |
| --- | --- |
| 未设置 `JUICE_TURN_TLS_NO_VERIFY`（默认） | `skip_tls_verify = 0`，验证证书 |
| `JUICE_TURN_TLS_NO_VERIFY` 为 `1` / `t` / `T` | `skip_tls_verify = 1`，**关闭验证**，并打印一条 WARN |

注意这是**进程级、无差别**的开关：只要环境里存在该变量，所有经兼容层建立的 TURN/TLS 连接都不再校验证书。它由 stice 提供（`JUICE_TURN_TLS_NO_VERIFY` 并非上游 libjuice 的实现——仓库内的 libjuice 参考副本既没有 `src/tls.c`，全文也没有任何 `getenv()` 调用），目的是让依赖自签名测试台的示例程序原样可用。生产环境请不要设置它；需要固定私有 CA 时用 `STICE_TLS_CA_FILE`。

如果只想对单个 TURN 服务器跳过验证，使用 stice 原生 API `stice_add_turn_server()` 并设置 `skip_tls_verify = 1`。

同一入口还支持 per-server 证书包：`stice_turn_server_t.ca_file` 非空时，该服务器**只**用这个 PEM 验证（优先于 `STICE_TLS_CA_FILE`）。兼容层不设置该字段（`juice_turn_server_t` 没有对应字段），所以经 `juice_*` 建立的连接走进程级环境变量 / 平台信任库。

### 4.5 并发模式

libjuice 的 `juice_concurrency_mode_t` 定义了 `POLL=0`、`MUX=1`、`THREAD=2`。stice 的 `stice_concurrency_mode_t` 值相同，兼容层直接转换。libdatachannel 默认使用 POLL 模式。

### 4.6 日志系统

`juice_set_log_level()` 和 `juice_set_log_handler()` 完全转发到 stice 的对应函数。日志级别枚举值二进制兼容。libdatachannel 的日志配置无需修改。

### 4.7 stserver 与 TLS 后端

`stserver`（内置 TURN/STUN 服务器）只提供 **UDP/TCP** 监听，不做 TLS 终结：它的控制面
（STUN Binding / TURN Allocate、Refresh、CreatePermission、ChannelBind、RFC 6062 CONNECT）
都是明文，和 coturn 的 3478 端口一致。因此：

- `stserver` 可以用三个 TLS 后端中的任意一个构建（它链接按该后端编译的 stice 静态库），
  三种构建的功能与吞吐行为一致——后端选择只影响 stice 客户端侧的 TURN over TLS。
- 需要端到端 TURN/TLS（RFC 8656 §4）验证时，用支持 TLS 的 TURN 服务（如 coturn 的
  `tls-listening-port`）；stice 客户端侧已支持 OpenSSL / GnuTLS / Mbed TLS 三种后端。
- `stserver` 与本机（或同平台）stice 客户端组合做长稳测试时，与后端选择无关，
  可用来验证「任选一个 TLS 后端都能正常构建并整链路工作」。

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

**原因**：所选 TLS 后端没找到 / 证书验证失败 / 后端未编译进库。

**解决**：
1. 确认对应开发包存在：OpenSSL 用 `libssl-dev`，GnuTLS 用 `libgnutls28-dev`，Mbed TLS 用 `libmbedtls-dev`。
2. 检查 CMake 配置输出里的 `stice: TLS backend = ...` 一行，或用 `stice_get_tls_backend()` 在运行时确认。
   若显示 `none`，说明没有编译任何 TLS 后端（此时 TURN/TLS 会退化成明文 TCP）。
3. 测试自签名证书时，使用 stice 原生 API 设置 `skip_tls_verify = 1`；或设置 `STICE_TLS_CA_FILE`
   指向该自签证书以保持验证开启。Mbed TLS 不读系统信任库，必须用 `STICE_TLS_CA_FILE` 才能验证。

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
3. 使用 `stice_get_version()`（原生 API）获取版本号，应返回 `0.11.0`。

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
