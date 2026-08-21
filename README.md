# stice

[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)
[![Version](https://img.shields.io/badge/version-0.10.0-blue.svg)]()
[![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C.svg)]()

**C++17 ICE + TURN client library, ported from [pion/webrtc](https://github.com/pion/webrtc) (Go), designed as a drop-in replacement for [libjuice](https://github.com/paullouisageneau/libjuice).**

stice implements the ICE (Interactive Connectivity Establishment, RFC 8445) agent and TURN (Traversal Using Relays around NAT, RFC 8656，RFC 6062) client in modern C++17, with a stable C ABI. It provides both a native `stice_*` API and a full `juice_*` compatibility layer, allowing existing libjuice consumers (such as [libdatachannel](https://github.com/paullouisageneau/libdatachannel)) to switch with a mechanical rename.

## Protocol Support

| Protocol | Specification | Client (stice) | Server (stserver) |
|----------|--------------|:--------------:|:-----------------:|
| STUN Message | RFC 8489 | ✅ | ✅ |
| ICE Agent | RFC 8445 | ✅ | — |
| ICE-TCP (TCP candidates) | RFC 6544 | ✅ active/passive/SO | ✅ passive (via TCPMux) |
| TURN (UDP relay) | RFC 8656 | ✅ | ✅ |
| TURN over TCP (control) | RFC 8656 | ✅ | ✅ |
| TURN over TLS | RFC 8656 | ✅ | — |
| TURN TCP Allocations (Mode-A/B) | RFC 6062 | ✅ CONNECT/CONNECTION-ATTEMPT/CONNECTION-BIND | ✅ data pipe relay |
| mDNS Candidates | draft-ietf-rtcweb-mdns-ice-candidates | ✅ query/gather | — |
| Trickle ICE | draft-ietf-ice-trickle | ✅ | — |

## Features

- **ICE Agent (RFC 8445)** — full connectivity checks, aggressive/regular nomination, trickle ICE, ICE restart, controlled/controlling role
- **STUN client (RFC 8489)** — server-reflexive candidate gathering, multi-STUN parallel queries, authentication
- **TURN client (RFC 8656 + RFC 6062)** — UDP/TCP/TLS transports; channel data; permissions; **RFC 6062 TCP allocations** with Mode-A control connection and Mode-B data pipe (CONNECT / CONNECTION-ATTEMPT / CONNECTION-BIND / CONNECTION-ID)
- **ICE-TCP (RFC 6544)** — active / passive / simultaneous-open modes, TCP priority offset, per-pair TCPMux for passive listeners
- **Multicast DNS (mDNS)** — query-only and query-and-gather modes for local candidate privacy
- **NAT 1:1 Address Rewrite** — replace or append external IP mappings for host/srflx/relay candidates
- **UDP / TCP Multiplexing** — share a single socket across multiple agents (UDPMux / TCPMux)
- **Configurable Pairing Strategy** — RFC 8445 strict, serial, limited-concurrent, phased-UDP-first scheduling; aggressive / regular / stable nomination; RFC 6062 TCP-relay fallback policies; lazy Mode-B pre-allocation
- **Built-in TURN Server (`stserver`)** — UDP + TCP listeners, STUN binding, TURN UDP relay, TURN TCP relay (RFC 6062 Mode-B data piping), ICE-TCP passive candidate support; epoll / IOCP / select backends
- **libjuice Compatibility** — `juice_*` C API drop-in replacement via `juice_compat.cpp`
- **Cross-platform** — Windows (MSVC/MinGW), Linux, macOS

## Project Structure

```
stice/
├── CMakeLists.txt          # Build configuration (CMake 3.13+)
├── LICENSE                 # Mozilla Public License 2.0
├── README.md
├── CHANGELOG.md
├── .gitignore
├── stserver.conf.example   # stserver configuration template
├── stserver.test.conf      # stserver config for running the test suite (testuser/123456)
├── include/
│   ├── stice/
│   │   ├── stice.h         # Public C ABI (stice_*)
│   │   ├── crypto.hpp
│   │   ├── log.hpp
│   │   ├── types.hpp
│   │   ├── ice/            # ICE agent, candidates, SDP, pairing strategy, addr_rewrite
│   │   ├── net/            # UDP, TCP, poll, mux, mDNS, addr, platform
│   │   ├── stun/           # STUN message, attributes, client
│   │   ├── turn/           # TURN client, channel data, stun connection (RFC 6062)
│   │   └── stserver/       # Built-in TURN server (config, turn_server, io_backend)
│   └── juice/
│       └── juice.h         # libjuice-compatible C API (juice_*)
├── src/
│   ├── c_api.cpp           # stice_* C ABI implementation
│   ├── juice_compat.cpp    # juice_* compatibility shim
│   ├── log.cpp
│   ├── crypto/
│   ├── ice/
│   ├── net/
│   ├── stun/
│   ├── turn/
│   └── stserver/           # TURN server (main, config, turn_server, io_iocp/epoll/select)
├── tests/
│   ├── test_*.cpp          # Unit / integration / performance tests (Catch2)
│   └── libjuice_compat/    # libjuice API compatibility tests
└── third_party/
    └── Catch2/             # Test framework
```

## Building

### Prerequisites

- CMake ≥ 3.13
- C++17 compiler (MSVC 2019+, GCC 8+, Clang 7+)
- OpenSSL (optional, for TURN/TLS and HMAC-SHA; `STICE_USE_OPENSSL=ON` by default)

### Quick Start

```bash
# Configure
cmake -B build -S .

# Build
cmake --build build --config Release

# Run tests
ctest --test-dir build --output-on-failure
```

### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `STICE_BUILD_TESTS` | `ON` | Build unit and integration tests |
| `STICE_BUILD_STSERVER` | `ON` | Build the built-in TURN/STUN server (`stserver`) |
| `STICE_USE_OPENSSL` | `ON` | Use OpenSSL for crypto and TURN/TLS |
| `BUILD_SHARED_LIBS` | `OFF` | Build shared library (default: static) |

### Integration as a Subproject

stice is designed to be embedded directly via `add_subdirectory()`:

```cmake
add_subdirectory(third_party/stice)
target_link_libraries(myapp PRIVATE LibJuice::LibJuice)
```

The `juice` target is aliased as `LibJuice::LibJuice`, and `juice-static` as `LibJuice::LibJuiceStatic`, matching libjuice's CMake package names.

## Usage

### Native stice API

```c
#include <stice/stice.h>

static void on_state_changed(stice_agent_t *agent, stice_state_t state, void *user) {
    printf("ICE state: %s\n", stice_state_to_string(state));
}

static void on_candidate(stice_agent_t *agent, const char *sdp, void *user) {
    // Send candidate to peer via signaling
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

    // ... exchange SDP and candidates with peer ...

    char local_sdp[4096];
    stice_get_local_description(agent, local_sdp, sizeof(local_sdp));
    stice_set_remote_description(agent, remote_sdp);

    // Send data once connected
    stice_send(agent, "hello", 5);

    stice_destroy(agent);
    return 0;
}
```

### libjuice Compatibility

Simply replace `juice.h` with stice's `juice/juice.h` and link against `LibJuice::LibJuice`. All `juice_*` functions are supported.

### TURN Server (stserver)

The built-in TURN/STUN server (`stserver`) provides a full relay implementation:

- **UDP listener** — STUN Binding requests + TURN UDP allocations (RFC 8656)
- **TCP listener** — TURN over TCP control connections + RFC 6062 Mode-B TCP allocations with CONNECT/CONNECTION-ATTEMPT/CONNECTION-BIND and raw data pipe relay
- **ICE-TCP passive** — accepts incoming TCP connections for RFC 6544 passive candidates (when clients use TCPMux)
- **Long-term credential authentication** — user/password database via config
- **IO backends** — IOCP (Windows), epoll (Linux), select (cross-platform fallback)

```bash
# Build the server (enabled by STICE_BUILD_STSERVER=ON, default ON)
cmake --build build --target stserver

# Copy and edit the example config
cp stserver.conf.example stserver.conf

# Run
./build/stserver --config stserver.conf
```

## Pairing Strategy Profiles

stice exposes runtime-configurable ICE pairing strategies via `stice_ice_pairing_config_t`:

| Profile | Use Case |
|---------|----------|
| `STICE_PAIRING_RFC8445_COMPAT` | Standard RFC 8445 behavior, maximum interoperability |
| `STICE_PAIRING_EMBEDDED_STABLE` | Embedded / IoT devices, resource-constrained, stable nomination |
| `STICE_PAIRING_DEBUG_FAST` | Development, aggressive checks, fast convergence |
| `STICE_PAIRING_MINIMAL_RESOURCE` | Ultra-low memory / CPU footprint |

```c
stice_ice_pairing_config_t cfg;
stice_make_pairing_config(STICE_PAIRING_EMBEDDED_STABLE, &cfg);
stice_set_pairing_config(agent, &cfg);
```

## Testing

The test suite uses [Catch2](https://github.com/catchorg/Catch2) for unit tests and standalone binaries for integration / stress tests. Tests are divided into three tiers based on external dependencies.

### Test Tiers

#### Tier 1: Core Unit Tests (no external dependencies)

These run anywhere and cover protocol logic, data structures, and algorithms.

| Test | Framework | Description |
|------|-----------|-------------|
| `test_candidate` | Catch2 | ICE candidate priority (RFC 8445 §5.1.2), SDP serialization/parsing, TCPType legality (RFC 6544) |
| `test_candidate_pair` | Catch2 | Candidate pair priority (RFC 8445 §6.1.2.3), TCP pair filtering (RFC 6544 §5.2 + RFC 6062 relay exception) |
| `test_stun` | Catch2 | STUN message encoding/decoding, attribute parsing, FINGERPRINT, MESSAGE-INTEGRITY |
| `test_turn` | Catch2 | TURN allocation state machine, channel data, permissions; **RFC 6062** TCP allocation (CONNECT/CONNECTION-ATTEMPT/CONNECTION-BIND/CONNECTION-ID), active+passive dual mode |
| `test_pairing_strategy` | Catch2 | ICE check scheduling, nomination modes, RFC 6062 TCP-relay fallback, link reselection |
| `test_functional` | Catch2 | End-to-end ICE agent functional tests (loopback UDP pairs) |
| `test_debug` | Catch2 | Internal debug utilities and logging |
| `test_performance` | Catch2 | Micro-benchmarks: candidate sorting, pair formation, STUN parse throughput |
| `test_stress` | Catch2 | Agent lifecycle stress: create/gather/destroy cycles, resource leak checks |

Run all Tier-1 tests:

```bash
ctest --test-dir build -C Release --output-on-failure \
  -E "test_conn|test_integration|test_stserver"
```

#### Tier 2: Network Connectivity Test

| Test | Description |
|------|-------------|
| `test_conn` | Standalone STUN connectivity test — sends a Binding Request to a STUN server over a dual-stack IPv6 socket and verifies the response. Default target `192.168.3.223:3478`. |

```bash
# Uses default STUN server
./build/Release/test_conn.exe

# Or specify a public STUN server (edit source for custom target)
```

#### Tier 3: stserver Integration & Stress Tests (require running stserver)

These tests launch pairs of stice agents and drive them through a local `stserver` instance. They verify STUN, TURN-UDP, TURN-TCP (RFC 6062), and ICE-TCP (RFC 6544) end-to-end.

| Test | Description | Default Args |
|------|-------------|--------------|
| `test_stserver_all` | Comprehensive 4-mode test: `ice-udp`, `ice-tcp`, `turn-udp`, `turn-tcp` (RFC 6062 Mode-B). Each mode creates an agent pair, gathers, connects, and exchanges data. | `[host] [port] [mode]` → `127.0.0.1 3478 turn-udp` |
| `test_stserver_relay` | TURN relay-only test: forces both agents to use relay candidates, verifies allocation + data exchange over UDP or TCP. | `[host] [port] [transport]` → `127.0.0.1 13478 udp` |
| `test_stserver_tcp_diag` | TCP relay diagnostics with verbose client logging — captures TURN-over-TCP state transitions for debugging. | `127.0.0.1 3478` |
| `test_stserver_stress_tcp` | High-concurrency TCP stress: N agent pairs all using TURN over TCP (RFC 6062 Mode-B) through stserver. Reports success rate and per-pair timing. | `[host] [port] [pairs] [timeout_ms]` → `127.0.0.1 13478 20 20000` |
| `test_stserver_stress_mixed` | Mixed workload stress: N ICE-UDP pairs + M1 TURN-UDP + M2 TURN-TCP background sessions simultaneously. Validates stserver D-plan (IOCP/epoll) under mixed load. | `[host] [port] [icePairs] [turnUdpBg] [turnTcpBg] [timeoutMs]` → `127.0.0.1 3478 1000 20 20 30000` |

##### Running stserver Integration Tests

**Step 1: Prepare the test config**

The tests connect with username `testuser` / password `123456`. A ready config is provided:

```bash
# stserver.test.conf already has users = testuser:123456
# Copy it next to the stserver binary (or pass --config)
cp stserver.test.conf build/Release/stserver.conf
```

**Step 2: Start stserver**

```bash
# Terminal 1: start the server
./build/Release/stserver.exe --config stserver.test.conf
# [stserver/INF] stserver: running (config=stserver.test.conf)
```

**Step 3: Run the integration tests**

```bash
# Terminal 2: run all 4 transport modes through stserver
./build/Release/test_stserver_all.exe 127.0.0.1 3478 ice-udp
./build/Release/test_stserver_all.exe 127.0.0.1 3478 ice-tcp
./build/Release/test_stserver_all.exe 127.0.0.1 3478 turn-udp
./build/Release/test_stserver_all.exe 127.0.0.1 3478 turn-tcp

# TURN relay test (UDP and TCP)
./build/Release/test_stserver_relay.exe 127.0.0.1 3478 udp
./build/Release/test_stserver_relay.exe 127.0.0.1 3478 tcp

# TCP relay diagnostics (verbose logging)
./build/Release/test_stserver_tcp_diag.exe 127.0.0.1 3478

# Stress: 50 TCP relay pairs
./build/Release/test_stserver_stress_tcp.exe 127.0.0.1 3478 50 30000

# Mixed stress: 100 ICE-UDP + 10 TURN-UDP + 10 TURN-TCP
./build/Release/test_stserver_stress_mixed.exe 127.0.0.1 3478 100 10 10 30000
```

Each test prints `=== PASS: ... ===` on success and `=== FAIL: ... ===` with a diagnostic on failure.

#### Tier 4: External coturn Integration Test

| Test | Description |
|------|-------------|
| `test_integration` | Catch2-based integration against an external [coturn](https://github.com/coturn/coturn) server. Covers TURN relay (UDP+TCP), multi-ICE-server parallel gathering, and RFC 6062 TURN-over-TCP. Requires a reachable coturn instance (default `192.168.3.223:3478` with `testuser`/`123456`). |

```bash
# Point to your coturn server (edit source or rely on default)
ctest --test-dir build -C Release -R test_integration --output-on-failure --timeout 120
```

### Running the Full Suite

```bash
# Build everything (library + stserver + all tests)
cmake --build build --config Release

# Tier 1 + 2 (no server needed)
ctest --test-dir build -C Release --output-on-failure -E "test_integration|test_stserver"

# Tier 3 (start stserver first, see above)
ctest --test-dir build -C Release -R "test_stserver" --output-on-failure --timeout 60

# Tier 4 (requires external coturn)
ctest --test-dir build -C Release -R test_integration --output-on-failure --timeout 120
```

### Catch2 Test Filtering

Catch2-based tests support tag filtering:

```bash
# Run only RFC 6062 tests
./build/Release/test_turn.exe "[rfc6062]"

# Run only candidate pair tests
./build/Release/test_candidate_pair.exe "[pair]"

# List all tests
./build/Release/test_stun.exe --list-tests
```

## Documentation

In-depth technical documentation is available in the `docs/` directory. All documents are provided in both English and Chinese.

| Document | English | Chinese | Description |
|----------|---------|---------|-------------|
| TURN over TCP Control Connection (RFC 8656) | [EN](docs/TURN-over-TCP-RFC8656.en.md) | [ZH](docs/TURN-over-TCP-RFC8656.md) | Self-delimiting STUN/ChannelData framing, StunConn parser, Mode-A control connection, long-term credential auth, C API usage |
| RFC 6062 TCP Allocations | [EN](docs/RFC6062-TCP-Allocations.en.md) | [ZH](docs/RFC6062-TCP-Allocations.zh.md) | Mode-A/B architecture, CONNECT/CONNECTION-ATTEMPT/CONNECTION-BIND flow, CONNECTION-ID, data connection with RFC 4571 framing, ufrag-based initiator selection |
| Integration with libdatachannel | [EN](docs/Integration-with-libdatachannel.en.md) | [ZH](docs/Integration-with-libdatachannel.zh.md) | Drop-in replacement guide, add_subdirectory/find_package/FetchContent methods, compatibility guarantees, feature differences, FAQ |

> **Note**: This README is also available in Chinese: [README.zh.md](README.zh.md)

## License

This project is licensed under the **Mozilla Public License 2.0 (MPL-2.0)**.

```
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.
```

MPL-2.0 is a weak copyleft license: modifications to stice source files must be shared under MPL-2.0, but the library may be linked into proprietary applications without affecting the larger work's license. See the [LICENSE](LICENSE) file for the full text.

## Author

- **zlyadvocate** — original author and maintainer

## Acknowledgments

- [pion/webrtc](https://github.com/pion/webrtc) — the Go implementation that stice was ported from
- [libjuice](https://github.com/paullouisageneau/libjuice) — the library whose API stice mirrors
- [libdatachannel](https://github.com/paullouisageneau/libdatachannel) — the primary integration target
