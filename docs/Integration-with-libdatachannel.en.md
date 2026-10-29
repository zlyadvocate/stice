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
| TURN over TLS backend | OpenSSL only | ✅ OpenSSL / GnuTLS / Mbed TLS |
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
# Default: OpenSSL
cmake -B build -S .

# Match the crypto backend libdatachannel itself was configured with
cmake -B build -S . -DUSE_GNUTLS=ON      # or -DUSE_MBEDTLS=ON
cmake --build build --config Release
```

> **Note**: stice selects its TLS backend with the **same CMake cache variables** libdatachannel uses (`USE_GNUTLS` / `USE_MBEDTLS`). Whatever the parent project picks, stice follows with no extra flags — see 2.4.

### 2.4 TLS backend parity (OpenSSL / GnuTLS / Mbed TLS)

TURN over TLS (RFC 8656 §4) goes through a pluggable TLS layer (`src/net/tls_*.cpp`).
Exactly one backend is compiled in, selected exactly the way libdatachannel does it:

| CMake variable | Library | Dependency lookup | Compile definition |
|----------------|---------|-------------------|--------------------|
| `USE_GNUTLS=ON` | GnuTLS | `find_package(GnuTLS)` → `GnuTLS::GnuTLS` | `USE_GNUTLS=1` |
| `USE_MBEDTLS=ON` | Mbed TLS (2.x / 3.x) | `find_package(MbedTLS)` → `MbedTLS::MbedTLS` | `USE_MBEDTLS=1` |
| neither (default) | OpenSSL | `find_package(OpenSSL)` | `USE_GNUTLS=0` |

Key points:

- Enabling both `USE_GNUTLS` and `USE_MBEDTLS` is a configure-time error, as in libdatachannel.
- With `add_subdirectory(deps/stice)` **no extra flags are needed**: stice reads the parent's cache variables directly.
- Standalone builds may use the `STICE_USE_GNUTLS` / `STICE_USE_MBEDTLS` aliases. With `STICE_USE_OPENSSL=OFF` and neither of them, stice builds without TLS (TURN over TLS then degrades to plain TCP with a warning).
- `stice_get_tls_backend()` returns `"openssl"`, `"gnutls"`, `"mbedtls"` or `"none"` for runtime self-checks.
- On Windows GnuTLS has no MSVC build (same situation as libdatachannel): use a MinGW-w64 toolchain (MSYS2's `mingw-w64-x86_64-gnutls`; verified to build and pass the full regression), or pick OpenSSL / Mbed TLS on Windows.
- The ICE/STUN/TURN crypto primitives (MD5/SHA-1/SHA-256/HMAC/CRC32/CSPRNG) are always stice's own implementation and never depended on a TLS library; swapping backends only affects the TLS record layer.

**Certificate verification policy (identical across backends)**

| Situation | Behavior |
|-----------|----------|
| Default (`skip_tls_verify = 0`) | Verify the server certificate against the platform trust store, plus SNI/hostname verification |
| That TURN server sets `ca_file` (non-empty) | Verify **only** that server against that PEM bundle (highest priority) |
| `STICE_TLS_CA_FILE` set | Use that PEM bundle instead of the platform trust store (pins a private CA) |
| `skip_tls_verify = 1` (e.g. libjuice's `JUICE_TURN_TLS_NO_VERIFY`) | Verification off, test rigs only |
| Mbed TLS, no `STICE_TLS_CA_FILE` | Mbed TLS has no platform trust store: falls back to `VERIFY_NONE` and logs a warning |
| **Windows + OpenSSL, no `STICE_TLS_CA_FILE`** | OpenSSL does not read the Windows certificate store and `SSL_CTX_set_default_verify_paths()` is usually empty there, so **handshakes against a private CA / self-signed certificate fail verification**; set `STICE_TLS_CA_FILE` (or use `skip_tls_verify = 1` in tests only) |
| **Mbed TLS 2.x + a TURN server addressed by IP** | Supported: 2.x does not parse `iPAddress` SANs, so stice reads the peer certificate's subjectAltName extension itself and compares the address (3.x does it inside the library). A mismatch fails the handshake instead of quietly passing |

> Rule of thumb: only OpenSSL on Linux/macOS and GnuTLS pick up the platform trust store automatically. **OpenSSL on Windows, and Mbed TLS on every platform, need an explicit `STICE_TLS_CA_FILE` or a per-server `ca_file` to verify.**
>
> Trust anchor precedence: **per-server `ca_file` (non-empty) > `STICE_TLS_CA_FILE` > platform store**. The environment variable is only consulted when `ca_file` is `NULL`/empty, so one agent can talk to several TURN servers that each use a different private CA — write that server's bundle into `stice_turn_server_t.ca_file` (the string is deep-copied when the server is added, so the caller may free it). The field was appended in 0.13.0: zero-initialised structs keep the old behaviour, but binaries must be recompiled.

**Cipher suites (identical across backends, RFC 8656 §4)**

stice configures an explicit "forward-secret key exchange + AEAD only" profile instead of trusting each library's defaults: TLS 1.2 floor, no static RSA key exchange, no CBC, no SHA-1 MACs. The backends use `SSL_CTX_set_cipher_list` / `SSL_CTX_set_ciphersuites` (OpenSSL), `gnutls_priority_set_direct` (GnuTLS, `NORMAL:-RSA:-VERS-TLS-ALL:+VERS-TLS1.3:+VERS-TLS1.2`) and `mbedtls_ssl_conf_ciphersuites` plus ephemeral-only TLS 1.3 key exchange (Mbed TLS). A peer that only offers legacy suites (CBC-SHA1 only, or pure RSA key exchange) will fail the handshake — that is deliberate; for such devices use a non-TLS TURN port (3478) or an operator-side proxy.

**Failure behavior: strict, no automatic downgrade**

When the handshake fails, that tls-turn candidate simply fails and ICE moves on to the other candidates per RFC 8445; stice never silently downgrades the connection to plaintext TCP. A TURN endpoint that only offers the removed legacy suites is therefore unreachable for stice, and the call may fail — that is the RFC 8445 (candidate failure) / RFC 8656 (use the endpoint as configured) branch, not a silent fallback. For diagnosis, the WARN log line (`TLS handshake failed` / `certificate verification failed`) points at the actual cause: cipher suite, trust anchor, or timeout.

### 2.5 Method 2: find_package (After Installation)

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

### 2.6 Method 3: FetchContent

Use FetchContent in libdatachannel's CMakeLists.txt to automatically download stice:

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
# LibJuice::LibJuice target is automatically available
```

> `USE_GNUTLS` / `USE_MBEDTLS` are cache variables too, so the FetchContent subproject inherits the parent's choice automatically.

## 3. CMake Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `STICE_BUILD_TESTS` | `ON` | Build unit tests. Recommended `OFF` when integrating into libdatachannel |
| `STICE_BUILD_STSERVER` | `ON` | Build built-in TURN server stserver. Recommended `OFF` when integrating |
| `STICE_USE_OPENSSL` | `ON` | Use OpenSSL as the TLS backend (default). With `OFF` and no GnuTLS/Mbed TLS, no TLS is compiled |
| `STICE_USE_GNUTLS` | `OFF` | Use GnuTLS as the TLS backend; same as libdatachannel's `USE_GNUTLS` |
| `STICE_USE_MBEDTLS` | `OFF` | Use Mbed TLS as the TLS backend; same as libdatachannel's `USE_MBEDTLS` |
| `USE_GNUTLS` / `USE_MBEDTLS` | `OFF` | libdatachannel's own cache variables; stice follows them when set by the parent |
| `BUILD_SHARED_LIBS` | `OFF` | Build shared library. Default is static library |

Recommended configuration for libdatachannel integration:

```cmake
set(STICE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(STICE_BUILD_STSERVER OFF CACHE BOOL "" FORCE)
# No TLS backend to set: it follows libdatachannel's USE_GNUTLS / USE_MBEDTLS
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

libjuice's `juice_turn_server_t` does not have a `skip_tls_verify` field. stice's `stice_turn_server_t` has this field.

The compatibility layer resolves it identically on both entry points (`juice_create()` and `juice_add_turn_server()`):

| Situation | Result |
|-----------|--------|
| `JUICE_TURN_TLS_NO_VERIFY` unset (default) | `skip_tls_verify = 0`, certificates are verified |
| `JUICE_TURN_TLS_NO_VERIFY` is `1` / `t` / `T` | `skip_tls_verify = 1`, verification **off**, plus a WARN |

This is a process-wide, all-or-nothing switch: while the variable is present, every TURN/TLS connection created through the compatibility layer stops verifying certificates. It is provided by stice — `JUICE_TURN_TLS_NO_VERIFY` is not an upstream libjuice feature (the libjuice snapshot vendored in this repo has neither `src/tls.c` nor any `getenv()` call) — so that example programs built around a self-signed test server keep working unchanged. Do not set it in production; use `STICE_TLS_CA_FILE` to pin a private CA instead.

To skip verification for one TURN server only, use stice's native API `stice_add_turn_server()` and set `skip_tls_verify = 1`.

The same entry point carries a per-server trust bundle: when `stice_turn_server_t.ca_file` is non-empty, that server is verified **only** against that PEM (it wins over `STICE_TLS_CA_FILE`). The compatibility layer leaves the field `NULL` (there is no corresponding `juice_turn_server_t` field), so connections created through `juice_*` use the process-wide variable / platform store.

### 4.5 Concurrency Mode

libjuice's `juice_concurrency_mode_t` defines `POLL=0`, `MUX=1`, `THREAD=2`. stice's `stice_concurrency_mode_t` has the same values, and the compatibility layer converts directly. libdatachannel uses POLL mode by default.

### 4.6 Logging System

`juice_set_log_level()` and `juice_set_log_handler()` fully forward to stice's corresponding functions. Log level enum values are binary-compatible. libdatachannel's logging configuration requires no modification.

### 4.7 stserver and the TLS backends

`stserver` (the built-in TURN/STUN server) only listens on **UDP/TCP** and does not
terminate TLS: its control plane (STUN Binding, TURN Allocate/Refresh/
CreatePermission/ChannelBind, RFC 6062 CONNECT) is plaintext, matching coturn's
3478 port. Consequently:

- `stserver` builds against any of the three TLS backends (it links the stice
  static library compiled with that backend) and behaves identically in all
  three builds — the backend choice only affects TURN over TLS on the stice
  client side.
- For end-to-end TURN/TLS (RFC 8656 §4) verification, use a TLS-capable TURN
  server (e.g. coturn's `tls-listening-port`); the stice client side already
  supports OpenSSL, GnuTLS and Mbed TLS.
- Pairing `stserver` with a stice client on the same host (or same platform) for
  a long-running soak is backend-independent and is exactly how "any TLS
  backend builds and works end to end" is verified here.

## 5. Verifying the Integration

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

**Cause**: the selected TLS backend was not found, certificate verification failed, or no backend was compiled in.

**Solution**:
1. Install the matching development package: `libssl-dev` for OpenSSL, `libgnutls28-dev` for GnuTLS, `libmbedtls-dev` for Mbed TLS.
2. Check the `stice: TLS backend = ...` line in the CMake configure output, or call `stice_get_tls_backend()` at runtime. `none` means no backend was compiled and TURN/TLS falls back to plain TCP.
3. For self-signed certificates either set `skip_tls_verify = 1` through stice's native API, or point `STICE_TLS_CA_FILE` at that certificate to keep verification on. Mbed TLS does not read the platform trust store, so `STICE_TLS_CA_FILE` is required for a verifying handshake there.

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
3. Use `stice_get_version()` (native API) to get the version number, should return `0.11.0`.

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
