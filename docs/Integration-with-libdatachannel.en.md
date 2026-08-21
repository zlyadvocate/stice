# Integrating stice with libdatachannel

## 1. Overview

stice is a C++17 ICE + TURN client library ported from pion/webrtc (Go), designed as a **drop-in replacement** for [libjuice](https://github.com/paullouisageneau/libjuice). [libdatachannel](https://github.com/paullouisageneau/libdatachannel) originally uses libjuice as its ICE backend. Through stice's `juice_*` compatibility layer and CMake target aliases, you can switch libdatachannel's ICE backend to stice with **zero source code changes**.

### 1.1 Compatibility Guarantees

| Dimension | Compatibility Mechanism |
|-----------|------------------------|
| C API | `juice_compat.cpp` implements all `juice_*` functions, forwarding to `stice_*` |
| Header | `include/juice/juice.h` has identical signatures to libjuice's header |
| Enum values | `juice_state_t`, `juice_turn_transport_t`, `juice_concurrency_mode_t`, etc. are binary-compatible with stice equivalents (same integer values) |
| CMake targets | `juice` → alias `LibJuice::LibJuice`; `juice-static` → alias `LibJuice::LibJuiceStatic` |
| CMake package name | `EXPORT_NAME LibJuice`, directly found by `find_package(LibJuice)` |
| Callback signatures | `juice_cb_*_t` and `stice_cb_*_t` have identical parameter types, converted via `reinterpret_cast` |

### 1.2 stice Enhancements Over libjuice

| Feature | libjuice | stice |
|---------|----------|-------|
| ICE-TCP (RFC 6544) | Active only | active / passive / simultaneous-open |
| TURN over TCP (RFC 8656) | ✅ | ✅ |
| TURN TCP Allocation (RFC 6062) | ❌ | ✅ Mode-A + Mode-B |
| mDNS candidates | ❌ | ✅ query-only / query-and-gather |
| NAT 1:1 address rewrite | ❌ | ✅ replace / append |
| UDP/TCP multiplexing | Basic | ✅ UDPMux + TCPMux |
| Configurable pairing strategy | Fixed | ✅ 4 presets + runtime tuning |
| Built-in TURN server | ❌ | ✅ stserver (IOCP/epoll/select) |
| Language | C | C++17 (provides C ABI) |

## 2. Integration Methods

### 2.1 Method 1: add_subdirectory (Recommended)

Embed stice source as a subdirectory in the libdatachannel project, no pre-installation required.

**Step 1: Obtain stice source**

```bash
# Option A: git submodule
cd libdatachannel
git submodule add https://github.com/zlyadvocate/stice.git deps/stice

# Option B: direct clone
git clone https://github.com/zlyadvocate/stice.git deps/stice
```

**Step 2: Modify libdatachannel's CMakeLists.txt**

Find the part in libdatachannel that references libjuice, typically:

```cmake
# Original config (using system libjuice or FetchContent)
find_package(LibJuice REQUIRED)
target_link_libraries(datachannel PRIVATE LibJuice::LibJuice)
```

Replace with:

```cmake
# Use stice as libjuice replacement
set(STICE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(STICE_BUILD_STSERVER OFF CACHE BOOL "" FORCE)
add_subdirectory(deps/stice)

# stice's juice target is aliased as LibJuice::LibJuice, fully compatible with libjuice
# datachannel's target_link_libraries requires no modification
```

If libdatachannel uses static linking (`datachannel-static`), ensure it links `LibJuice::LibJuiceStatic`:

```cmake
target_link_libraries(datachannel-static PRIVATE LibJuice::LibJuiceStatic)
```

**Step 3: Build**

```bash
cmake -B build -S . -DUSE_GNUTLS=OFF -DUSE_MBEDTLS=OFF
cmake --build build --config Release
```

> **Note**: stice uses OpenSSL for cryptography and TURN/TLS. If libdatachannel originally uses GnuTLS or MbedTLS, ensure OpenSSL is available, or set `STICE_USE_OPENSSL=OFF` in stice (which will disable TURN/TLS and some crypto features).

### 2.2 Method 2: find_package (After Installation)

Build and install stice first, then find it via `find_package`.

**Step 1: Build and install stice**

```bash
git clone https://github.com/zlyadvocate/stice.git
cd stice
cmake -B build -S . -DCMAKE_INSTALL_PREFIX=/usr/local -DSTICE_BUILD_TESTS=OFF -DSTICE_BUILD_STSERVER=OFF
cmake --build build --config Release
cmake --install build
```

Post-installation file layout:
```
/usr/local/
├── include/
│   ├── stice/stice.h      # stice native C API
│   └── juice/juice.h      # libjuice-compatible C API
├── lib/
│   ├── libjuice.so        # Shared library (EXPORT_NAME=LibJuice)
│   ├── cmake/LibJuice/
│   │   ├── LibJuiceConfig.cmake
│   │   └── LibJuiceTargets.cmake
```

**Step 2: Use in libdatachannel**

libdatachannel's CMakeLists.txt **requires no modification**, because stice's install package name is `LibJuice`:

```cmake
find_package(LibJuice REQUIRED)
target_link_libraries(datachannel PRIVATE LibJuice::LibJuice)
```

Specify the install prefix when building:

```bash
cmake -B build -S . -DCMAKE_PREFIX_PATH=/usr/local
cmake --build build --config Release
```

### 2.3 Method 3: FetchContent

Use FetchContent in libdatachannel's CMakeLists.txt to automatically download stice:

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
# LibJuice::LibJuice target is automatically available
```

## 3. CMake Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `STICE_BUILD_TESTS` | `ON` | Build unit tests. Recommended `OFF` when integrating into libdatachannel |
| `STICE_BUILD_STSERVER` | `ON` | Build built-in TURN server stserver. Recommended `OFF` when integrating |
| `STICE_USE_OPENSSL` | `ON` | Use OpenSSL for cryptography and TURN/TLS. `OFF` disables TLS |
| `BUILD_SHARED_LIBS` | `OFF` | Build shared library. Default is static library |

Recommended configuration for libdatachannel integration:

```cmake
set(STICE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(STICE_BUILD_STSERVER OFF CACHE BOOL "" FORCE)
set(STICE_USE_OPENSSL ON CACHE BOOL "" FORCE)
```

## 4. Feature Differences and Caveats

### 4.1 juice_mux_listen is a no-op

stice provides an implementation of `juice_mux_listen()`, but it is a **no-op stub** (returns 0 for success). stice uses a different UDPMux API (`stice_create_udp_mux` / `stice_agent_use_udp_mux`), with a design different from libjuice's `juice_mux_listen`.

libdatachannel's `IceUdpMuxListener` feature calls this function when `enableIceUdpMux` is enabled. libdatachannel's test suite does not enable this feature by default, so the no-op does not affect regular usage.

**If UDPMux functionality is needed**: Use stice's native API instead, or wait for full UDPMux support in the compatibility layer in a future version.

### 4.2 juice_server_* are stubs

`juice_server_create`, `juice_server_destroy`, `juice_server_get_port`, and `juice_server_add_credentials` are all stub implementations (returning nullptr / 0 / -1). libdatachannel does not use these functions (it has its own test server), so integration is unaffected.

stice provides a standalone `stserver` executable as a built-in TURN server with more complete functionality.

### 4.3 ICE-TCP Mode Extension

libjuice's `juice_ice_tcp_mode_t` only defines `NONE=0` and `ACTIVE=1`. stice's `stice_ice_tcp_mode_t` extends with `PASSIVE=2` and `SO=3` (simultaneous-open).

The compatibility layer's `juice_set_ice_tcp_mode()` directly forwards the value to stice, so libdatachannel can only use NONE and ACTIVE modes. To use passive or SO modes, use stice's native API `stice_set_ice_tcp_mode()`.

### 4.4 skip_tls_verify in TURN Server Config

libjuice's `juice_turn_server_t` does not have a `skip_tls_verify` field. stice's `stice_turn_server_t` has this field. The compatibility layer defaults to `skip_tls_verify = 0` (certificate verification, secure default) during conversion.

If you need to skip TLS certificate verification (for testing self-signed certificates), use stice's native API `stice_add_turn_server()` and set `skip_tls_verify = 1`.

### 4.5 Concurrency Mode

libjuice's `juice_concurrency_mode_t` defines `POLL=0`, `MUX=1`, `THREAD=2`. stice's `stice_concurrency_mode_t` has the same values, and the compatibility layer converts directly. libdatachannel uses POLL mode by default.

### 4.6 Logging System

`juice_set_log_level()` and `juice_set_log_handler()` fully forward to stice's corresponding functions. Log level enum values are binary-compatible. libdatachannel's logging configuration requires no modification.

## 5. Verifying Integration

### 5.1 Compilation Verification

After a successful build, check the linked library:

```bash
# Linux
ldd build/libdatachannel.so | grep juice

# Windows (PowerShell)
Get-Content build/Release/datachannel.dir/link.rule | Select-String juice
```

You should see linking to stice-built `libjuice.so` (or `juice.lib`), not the system's libjuice.

### 5.2 Runtime Verification

Run libdatachannel's example programs and check ICE connection establishment:

```bash
# Run peerconnection example (two terminals)
./build/examples/peerconnection server
./build/examples/peerconnection client
```

Observe whether the logs contain stice output (e.g., `TURN allocate`, `ICE state changed`, etc.).

### 5.3 Feature Verification Checklist

- [ ] STUN server reflexive candidate gathering
- [ ] TURN relayed candidate gathering (UDP)
- [ ] TURN over TCP control connection
- [ ] ICE connection establishment (host/srflx/relay)
- [ ] Trickle ICE candidate exchange
- [ ] Data channel establishment and data transmission
- [ ] ICE disconnection and reconnection
- [ ] Normal log output

## 6. FAQ

### Q1: Link error "undefined reference to juice_create"

**Cause**: The `LibJuice::LibJuice` target is not properly linked.

**Solution**: Confirm CMakeLists.txt contains:
```cmake
target_link_libraries(datachannel PRIVATE LibJuice::LibJuice)
```
And stice is properly introduced via `add_subdirectory`, `find_package`, or `FetchContent`.

### Q2: Compile error "juice/juice.h: No such file or directory"

**Cause**: stice's include directory is not added to the include path.

**Solution**: The `LibJuice::LibJuice` target should automatically propagate include directories. If using manual linking, confirm:
```cmake
target_include_directories(datachannel PRIVATE deps/stice/include)
```

### Q3: TURN/TLS connection failure

**Cause**: stice's TURN/TLS depends on OpenSSL; OpenSSL may not be found or certificate verification fails.

**Solution**:
1. Confirm OpenSSL development package is installed (`libssl-dev` / `openssl-devel`).
2. Check CMake configure output for `OpenSSL found`.
3. When testing self-signed certificates, use stice's native API to set `skip_tls_verify = 1`.

### Q4: Windows link error LNK2019

**Cause**: On Windows, additional linking of `ws2_32` and (if using OpenSSL) `crypt32` is required.

**Solution**: stice's `stice_apply_common()` function should automatically handle these dependencies. If linking manually, confirm:
```cmake
if(WIN32)
    target_link_libraries(datachannel PRIVATE ws2_32 crypt32)
endif()
```

### Q5: How to confirm stice (not libjuice) is used at runtime

**Methods**:
1. Check log prefix: stice's logs contain the `[stice/...]` prefix.
2. Check relayed candidates: stice supports RFC 6062 TCP relay (`tcptype=passive`), libjuice does not.
3. Use `stice_get_version()` (native API) to get the version number, should return `0.10.0`.

### Q6: Performance comparison

stice is ported from pion/webrtc, with pairing strategy and scheduling algorithms consistent with pion. In high-concurrency scenarios, stice's configurable pairing strategies (e.g., `PHASED_UDP_FIRST`, `LIMITED_CONCURRENT`) can provide better performance than libjuice's fixed strategy. It is recommended to tune via `stice_set_pairing_config()` according to the scenario.

## 7. References

- stice repository: https://github.com/zlyadvocate/stice
- libdatachannel repository: https://github.com/paullouisageneau/libdatachannel
- libjuice repository: https://github.com/paullouisageneau/libjuice
- pion/webrtc (stice porting source): https://github.com/pion/webrtc
- RFC 8445 ICE: https://tools.ietf.org/html/rfc8445
- RFC 8656 TURN: https://tools.ietf.org/html/rfc8656
- RFC 6062 TURN TCP Allocations: https://tools.ietf.org/html/rfc6062
- RFC 6544 ICE-TCP: https://tools.ietf.org/html/rfc6544
