# Implementing TURN over TCP Control Connection with stice (RFC 8656)

## 1. Background and Motivation

In typical WebRTC scenarios, the ICE agent communicates with the TURN server over UDP to obtain relayed candidates for traversing symmetric NATs. However, in certain network environments—corporate firewalls, public WiFi, restricted mobile carrier networks—UDP may be entirely blocked or severely throttled, while TCP ports 443/80 are almost always open.

RFC 8656 (Traversal Using Relays around NAT) defines that the TURN protocol can run its **control connection over TCP or TLS**. This means that STUN transactions between the client and the TURN server—Allocate, Refresh, CreatePermission, ChannelBind—as well as Send/Data indications and ChannelData frames—can all traverse a single TCP connection. This enables TURN to penetrate firewalls that only permit TCP.

Two easily confused concepts must be distinguished:

| Concept | Specification | Control Connection | REQUESTED-TRANSPORT | Relay Transport |
|---------|--------------|-------------------|---------------------|-----------------|
| TURN over TCP (control) | RFC 8656 | TCP/TLS | 17 (UDP) | UDP |
| TURN TCP Allocation | RFC 6062 | TCP | 6 (TCP) | TCP |

This article focuses on the former: **the control connection runs over TCP, while the relay transport remains UDP**. In stice's implementation, when the transport is configured as `STICE_TURN_TRANSPORT_TCP`, RFC 6062 TCP allocation (`REQUESTED-TRANSPORT=6`) is also enabled, as this is the typical requirement for ICE-TCP scenarios; `STICE_TURN_TRANSPORT_TLS` uses standard UDP relay (`REQUESTED-TRANSPORT=17`).

## 2. Key Specifications in RFC 8656

### 2.1 Transport and Framing

When TURN runs over UDP, each UDP datagram is naturally a complete STUN message or ChannelData frame, requiring no additional framing information.

When TURN runs over TCP, the situation is entirely different. TCP is a byte-stream protocol; the receiver cannot determine from the TCP layer alone where one STUN message begins and ends. RFC 8656 specifies that TURN over TCP **does not use the RFC 4571 2-byte length prefix**. Instead, it relies on the **self-delimiting** nature of STUN messages and ChannelData frames:

- **STUN messages**: A fixed 20-byte header, where bytes 2-3 contain a 16-bit `MESSAGE LENGTH` field indicating the number of payload bytes following the header. Thus the total frame length = `20 + length`.
- **ChannelData frames**: A 4-byte header, where bytes 2-3 contain a 16-bit length field. Over TCP, the data portion is padded to a 4-byte boundary. Total length = `4 + padded(length)`.

### 2.2 Demultiplexing on the Stream

On the same TCP connection, STUN messages and ChannelData frames may arrive interleaved. The receiver determines the current frame type based on the first byte:

- The first byte of a STUN message has its top 2 bits set to `00` (RFC 5389 §6), so the first byte ranges from `0x00` to `0x3F`.
- The first byte of ChannelData is the high byte of the channel number, which ranges from `0x4000` to `0x7FFF`, so the first byte ranges from `0x40` to `0x7F`.

These two ranges do not overlap, allowing unambiguous frame demultiplexing on a TCP byte stream.

### 2.3 Long-Term Credential Authentication

TURN over TCP uses the same long-term credential mechanism as UDP:

1. The client sends an Allocate request without authentication.
2. The server returns `401 Unauthorized`, carrying `REALM` and `NONCE` attributes.
3. The client computes an MD5 key using `username:realm:password`, and includes `USERNAME`, `REALM`, `NONCE`, and `MESSAGE-INTEGRITY` in subsequent requests.
4. If the server returns `438 Stale Nonce`, the client retries with the new NONCE (up to 3 times, preventing infinite loops).

### 2.4 Retransmission and Timeout

TCP provides reliable delivery, so TURN over TCP **does not require application-layer retransmission**. However, stice still maintains transaction ID mapping and timeout mechanisms for:
- Detecting unresponsive servers (half-open connections).
- Unifying the state machine code path across UDP and TCP.

## 3. Architecture Design in stice

stice cleanly separates TURN client responsibilities into three layers:

```
┌─────────────────────────────────────────────────┐
│                   Agent (ICE)                     │
│  Owns socket / TcpTransport, drives event loop  │
├─────────────────────────────────────────────────┤
│  turnTcpTransport_ (TcpTransport, Raw framing)  │
│  turnStunConn_    (StunConn, self-delimiting)   │
├─────────────────────────────────────────────────┤
│              turn::Client (state machine)         │
│  Allocate / Refresh / Permission / Channel       │
│  Socket-less; sends raw bytes via TurnSink cb    │
└─────────────────────────────────────────────────┘
```

### 3.1 turn::Client — Socket-less State Machine

`turn::Client` is a pure state machine that does not own any network socket. It communicates with the upper layer through `TurnSink` callbacks:

```cpp
struct TurnSink {
    // Send a raw STUN message or ChannelData frame to the TURN server
    std::function<void(const unsigned char *data, std::size_t size)> sendRaw;
    // Allocation succeeded; provides relayed address and lifetime
    std::function<void(const net::AddrRecord &relayed, std::uint32_t lifetime)> onAllocated;
    // Allocation failed permanently
    std::function<void(int errorCode, const std::string &reason)> onFailed;
    // Application data arrived via the relay
    std::function<void(const net::AddrRecord &peer, const unsigned char *data, std::size_t size)> onData;
    // ...
};
```

This design allows `turn::Client` to be reused across UDP, TCP, and TLS transports—the upper layer only needs to provide a different `sendRaw` implementation.

### 3.2 turn::StunConn — Self-Delimiting Parser for TCP Streams

`StunConn` is the core component for TURN over TCP, responsible for extracting complete STUN messages or ChannelData frames from a continuous TCP byte stream.

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

**Workflow:**

1. `feed()`: Appends raw bytes received from the TCP connection to the internal buffer.
2. `readFrame()`: Attempts to extract one frame from the head of the buffer:
   - Check the first byte: `< 0x40` is a STUN message, `0x40-0x7F` is ChannelData.
   - For STUN: Read the length field in the 20-byte header; total length = 20 + length.
   - For ChannelData: Read the length field in the 4-byte header; total length = 4 + round-up-to-4(length).
   - If the buffer does not contain enough data for one frame, return 0 (wait for more data).
   - If the first byte is neither STUN nor ChannelData, return `SIZE_MAX` (fatal stream error; close the connection).
3. Consume the read frame and advance the `consumed_` offset.

### 3.3 TcpTransport — Raw Frame Mode

stice's `TcpTransport` supports two framing modes:
- `FramingMode::RFC4571`: Prepend a 2-byte big-endian length prefix to each frame (used for ICE-TCP data channels).
- `FramingMode::Raw`: Write raw bytes directly without any prefix (used for TURN over TCP control connections).

TURN over TCP control connections must use `Raw` mode, because STUN/ChannelData are already self-delimiting—adding a length prefix would cause the server to fail parsing.

## 4. Core Implementation Analysis

### 4.1 Establishing the TCP Control Connection

When the Agent detects that a TURN server is configured for TCP/TLS transport, it calls `beginTurnTcpConnect()`:

```cpp
bool Agent::beginTurnTcpConnect(const net::AddrRecord &turnServer, bool useTls,
                                const std::string &sni, bool skipVerify) {
    turnTcpTransport_ = std::make_unique<net::TcpTransport>();
    // Critical: use Raw framing mode, no RFC 4571 prefix
    turnTcpTransport_->setFramingMode(net::FramingMode::Raw);
    if (!turnTcpTransport_->beginConnect(turnServer, sni, useTls, skipVerify)) {
        turnTcpTransport_.reset();
        // Notify TURN Client of allocation failure
        return false;
    }
    return true;
}
```

`TcpTransport::beginConnect()` initiates a non-blocking connect, detecting connection completion via the `PollRegistry` `onWritable` callback. In TLS mode, a TLS handshake is performed immediately after connection establishment.

### 4.2 Send Path

After `turn::Client` constructs a STUN message, it sends it through the `TurnSink::sendRaw` callback. The Agent's callback implementation routes based on transport type:

```cpp
sink.sendRaw = [this, useTcp](const unsigned char *data, std::size_t size) {
    if (useTcp) {
        // TCP/TLS: send raw bytes through turnTcpTransport_
        // In Raw mode, write directly without any prefix
        turnTcpTransport_->send(data, size);
    } else {
        // UDP: send through UDP socket or shared UDPMux
        sock_.sendto(data, size, turnServerAddr);
    }
};
```

For TCP transport, `TcpTransport::send()` writes raw bytes into the send buffer, which is gradually flushed to the kernel by the `PollRegistry` `onWritable` callback.

### 4.3 Receive Path

When TCP data arrives, `PollRegistry` triggers `onTurnTcpReadable()`:

```cpp
void Agent::onTurnTcpReadable() {
    char buf[4096];
    net::AddrRecord peer; // Peer address not needed over TCP
    while (true) {
        int n = turnTcpTransport_->recv(buf, sizeof(buf), peer);
        if (n <= 0) break;
        // Feed raw bytes into the StunConn parser
        turnStunConn_.feed(reinterpret_cast<const unsigned char *>(buf),
                           static_cast<std::size_t>(n));
    }
    // Extract complete frames from StunConn and route to TURN Client
    const unsigned char *frame = nullptr;
    while (true) {
        std::size_t frameSize = turnStunConn_.readFrame(frame);
        if (frameSize == 0 || !frame) break;
        if (frameSize == static_cast<std::size_t>(-1)) {
            // Fatal stream error: close connection, notify TURN Client of failure
            turnTcpTransport_.reset();
            return;
        }
        // Hand the complete frame to the TURN Client (STUN response / Data indication / ChannelData)
        for (auto &e : entries_) {
            if (e.type == StunEntryType::Relay && e.turn) {
                e.turn->handleInbound(frame, frameSize);
            }
        }
    }
}
```

This flow embodies the core design of TURN over TCP: **the TCP layer only handles byte-stream transport, StunConn handles frame delimiting, and turn::Client handles protocol semantics**.

### 4.4 Allocate Transaction

`turn::Client::allocate()` constructs the Allocate request:

```cpp
void Client::allocate() {
    state_ = AllocState::Allocating;
    // RFC 8656: TLS control connection uses UDP relay (17)
    // RFC 6062: TCP control connection uses TCP allocation (6)
    isTcpAllocation_ = (cfg_.transport == TurnTransport::TCP);
    std::uint8_t proto = isTcpAllocation_ ? 6 : 17;

    stun::Message m;
    m.method = stun::Method::Allocate;
    m.cls = stun::Class::Request;
    m.newTransactionID();
    allocateTid_ = m.transactionID;
    stun::addRequestedTransport(m, proto);
    sendRequest(m);  // Send via TurnSink::sendRaw
    // Register pending transaction for response dispatch and timeout
}
```

`sendRequest()` sends an unauthenticated request when no long-term credentials are available. Upon receiving a `401` response, `handleAllocateResponse()` captures `REALM` and `NONCE`, then resends with credentials:

```cpp
void Client::handleAllocateResponse(const stun::Message &msg, bool isError) {
    if (isError) {
        int code = 0;
        stun::readErrorCode(msg, code, reason);
        if (code == 401) {
            // Capture realm/nonce, retry with long-term credentials
            creds_ = stun::Credentials{...};
            sendRequest(allocateMsgAgain);
            return;
        }
        if (code == 438 && nonceRetries_ < MaxNonceRetries) {
            // Stale Nonce: refresh nonce and retry
            nonceRetries_++;
            sendRequest(allocateMsgAgain);
            return;
        }
        sink_.onFailed(code, reason);
        return;
    }
    // Success: extract XOR-RELAYED-ADDRESS and LIFETIME
    stun::readXorAddress(msg, stun::AttrType::XorRelayedAddress, relayedAddr_, msg.transactionID);
    stun::readLifetime(msg, lifetime_);
    state_ = AllocState::Allocated;
    sink_.onAllocated(relayedAddr_, lifetime_);
}
```

### 4.5 Data Transmission: Send Indication vs ChannelData

After allocation succeeds, application data is transmitted via two methods:

1. **Send Indication**: A STUN message with method Send, carrying `XOR-PEER-ADDRESS` and `DATA` attributes. No channel binding required; suitable for occasional data transmission.
2. **ChannelData Frame**: A 4-byte header (channel number + length) followed by data. Requires a prior ChannelBind request to bind the channel number; suitable for continuous transmission with lower overhead.

`turn::Client::sendData()` automatically manages this state machine: if the peer has a bound channel, it uses ChannelData; otherwise it uses a Send indication and initiates CreatePermission + ChannelBind in the background.

On a TCP control connection, both frame types are sent through `turnTcpTransport_` and parsed by `StunConn` on the receiving end.

## 5. Usage Examples (C API)

### 5.1 Configuring TURN over TCP

```c
#include <stice/stice.h>

static void on_state_changed(stice_agent_t *agent, stice_state_t state, void *user) {
    printf("ICE state: %s\n", stice_state_to_string(state));
}

static void on_candidate(stice_agent_t *agent, const char *sdp, void *user) {
    // Send to peer via signaling
    printf("Local candidate: %s\n", sdp);
}

int main(void) {
    stice_config_t config = {0};

    // Configure TURN over TCP control connection
    stice_turn_server_t turn = {0};
    turn.host = "turn.example.com";
    turn.port = 3478;
    turn.username = "user";
    turn.password = "pass";
    turn.transport = STICE_TURN_TRANSPORT_TCP;  // TCP control connection

    config.turn_servers = &turn;
    config.turn_servers_count = 1;
    config.cb_state_changed = on_state_changed;
    config.cb_candidate = on_candidate;

    stice_agent_t *agent = stice_create(&config);
    stice_gather_candidates(agent);
    // ... exchange SDP and candidates ...
    stice_destroy(agent);
    return 0;
}
```

### 5.2 Configuring TURN over TLS (TCP Control Connection + TLS Encryption)

```c
stice_turn_server_t turn = {0};
turn.host = "turn.example.com";
turn.port = 5349;           // Standard TURN/TLS port
turn.username = "user";
turn.password = "pass";
turn.transport = STICE_TURN_TRANSPORT_TLS;  // TLS control connection
turn.tls_skip_verify = 0;   // Verify server certificate (default, secure)
```

In TLS mode, the control connection is encrypted with TLS, allowing penetration of firewalls that perform DPI on plaintext TCP. `REQUESTED-TRANSPORT` remains UDP(17), and the relay transport is UDP.

### 5.3 Testing with stserver

stice's built-in `stserver` supports TCP control connections. Start it with the test configuration:

```bash
# Start stserver (listens on UDP 3478 + TCP 3478)
./stserver --config stserver.test.conf

# Run TURN relay test (TCP mode)
./test_stserver_relay.exe 127.0.0.1 3478 tcp
```

Example test output:
```
[stice/INF] TURN TCP: beginning TCP connect to 127.0.0.1:3478
[stice/INF] TURN allocate: called state=0
[stice/INF] TURN: allocation success relayed=127.0.0.1:50123 lifetime=600
=== PASS: relay data exchange OK ===
```

## 6. Comparison with UDP Control Connection

| Dimension | UDP Control Connection | TCP/TLS Control Connection |
|-----------|----------------------|---------------------------|
| Frame delimiting | Datagram naturally delimited | StunConn self-delimiting parser |
| Frame prefix | None | None (Raw mode, no RFC 4571) |
| App-layer retransmission | Required (RTO 200ms, exponential backoff) | Not needed (TCP reliable delivery) |
| Traversal capability | Poor (UDP often blocked) | Good (TCP 443/80 usually open) |
| Latency | Low (no connection setup) | Slightly higher (TCP handshake + TLS handshake) |
| Header overhead | 20 bytes STUN / 4 bytes ChannelData | Same (TCP headers handled by kernel) |
| Demultiplexing | By source address + port | By first byte (STUN vs ChannelData) |
| Use case | General NAT traversal | Corporate firewalls / restricted networks |

## 7. Notes and Best Practices

### 7.1 Do Not Use RFC 4571 Prefix on TURN over TCP

This is the most common implementation error. ICE-TCP (RFC 6544) data channels use the RFC 4571 2-byte length prefix, but TURN over TCP control connections (RFC 8656) explicitly do not. stice ensures this via `TcpTransport::setFramingMode(FramingMode::Raw)`.

### 7.2 Error Recovery in StunConn

If `StunConn::readFrame()` returns `SIZE_MAX`, it indicates that data on the TCP stream is neither STUN nor ChannelData. This typically means:
- The peer is not a legitimate TURN server.
- The connection has been tampered with by a middlebox.
- Frame parsing state is desynchronized (theoretically should not happen, as frames are self-delimiting).

The correct handling is to **close the TCP connection and mark the allocation as failed**, rather than attempting to skip bytes and resynchronize—because there is no way to determine where to begin resynchronization.

### 7.3 Keepalive and Timeout for TCP Connections

Although TCP provides reliable delivery, TURN allocations still require periodic Refresh (default 600-second lifetime, refreshed in advance). Additionally, stice maintains application-layer transaction timeouts to detect half-open connections (TCP connections that appear established but the server is unresponsive).

### 7.4 TLS Certificate Verification

In production, always keep `tls_skip_verify = 0` to verify the TURN server's TLS certificate. Skipping verification is convenient for testing but exposes the connection to man-in-the-middle attacks. stice uses the system trust store for certificate verification.

### 7.5 Port Selection

The standard port for TURN over TCP is 3478, and for TURN/TLS is 5349. However, in restricted networks, port 443 (TLS) is recommended, as 443 is almost always open and TLS encryption prevents DPI from distinguishing TURN traffic from HTTPS traffic.

## 8. Summary

stice's implementation of TURN over TCP control connections follows the RFC 8656 specification, with the following core design points:

1. **Layered architecture**: `turn::Client` (socket-less state machine) + `StunConn` (self-delimiting parser) + `TcpTransport` (Raw framing mode), with clear separation of responsibilities for ease of testing and maintenance.
2. **Self-delimiting frame parsing**: Leverages the length field in STUN message and ChannelData frame headers to unambiguously demarcate frames on a TCP byte stream, without requiring an additional length prefix.
3. **Unified state machine**: `turn::Client`'s Allocate/Refresh/Permission/Channel state machine is fully reused across UDP and TCP, differing only in the `sendRaw` callback.
4. **Long-term credential authentication**: 401/438 handling, nonce refresh limits, MESSAGE-INTEGRITY verification—consistent with the UDP path.
5. **Error handling**: StunConn stream error → close connection → mark allocation failed, avoiding continued operation on a corrupted stream.

Through TURN over TCP/TLS, stice can complete ICE connection establishment even in network environments where UDP is blocked, providing broader network adaptability for WebRTC applications.
