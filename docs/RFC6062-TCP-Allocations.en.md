# Implementing RFC 6062 TCP Allocations with stice

## 1. Overview

RFC 6062 (Traversal Using Relays around NAT (TURN) Extensions for TCP Allocations) extends the TURN protocol to enable relay allocations using TCP as the relay transport protocol. This allows WebRTC ICE-TCP (RFC 6544) candidates to establish end-to-end TCP connections through a TURN relay, suitable for network environments where UDP is completely blocked.

### 1.1 Differences from Standard TURN UDP Relay

| Dimension | Standard TURN (RFC 8656) | RFC 6062 TCP Allocation |
|-----------|--------------------------|-------------------------|
| REQUESTED-TRANSPORT | 17 (UDP) | 6 (TCP) |
| Control connection | UDP or TCP/TLS | TCP (Mode-A) |
| Data transmission | UDP Send/Data indications + ChannelData | TCP data connection (Mode-B) |
| Peer connection setup | None (UDP connectionless) | CONNECT / CONNECTION-ATTEMPT |
| Data connection binding | None | CONNECTION-BIND + CONNECTION-ID |
| Use case | General NAT traversal | ICE-TCP / UDP-blocked environments |

### 1.2 Implementation Architecture in stice

stice divides the RFC 6062 implementation into two TCP connections:

```
┌──────────────┐  Mode-A (Control)  ┌──────────────┐
│              │ ◄──────────────► │              │
│  stice Agent │   STUN transactions│  TURN Server │
│              │  (Allocate/Refresh│              │
│              │   /CONNECT/Creds) │              │
│              │                    │              │
│              │  Mode-B (Data)     │              │
│              │ ◄──────────────► │              │
│              │   App data + STUN  │              │
│              │   checks (RFC4571) │              │
└──────────────┘                    └──────────────┘
```

- **Mode-A control connection** (`turnTcpTransport_`): Uses `FramingMode::Raw`, transmits STUN transactions such as Allocate, Refresh, CreatePermission, and CONNECT, parsed by `StunConn` with self-delimiting.
- **Mode-B data connection** (`turnDataConn_`): Uses `FramingMode::RFC4571`, transparently passes application data and STUN connectivity checks after CONNECTION-BIND succeeds.

## 2. Protocol Flow Details

### 2.1 Allocation Setup (Allocate)

The client sends an Allocate request through the Mode-A control connection, with the `REQUESTED-TRANSPORT` attribute set to 6 (TCP):

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

After allocation succeeds, the client obtains a TCP-type relayed candidate (`tcptype=passive`), which is sent to the peer through SDP signaling.

### 2.2 Permission Creation (CreatePermission)

RFC 6062 still requires CreatePermission. When a peer attempts to connect to the local relayed address, the TURN server checks whether a permission has been created for that peer. Without permission, the server closes the inbound TCP connection and does **not** send a CONNECTION-ATTEMPT indication (RFC 6062 §4.4).

stice proactively calls `ensurePermission()` for each peer relayed candidate during the `formPairs()` phase, ensuring permissions are ready before CONNECT.

### 2.3 Active Mode: CONNECT Request

After both parties obtain TCP relayed candidates, an end-to-end TCP data connection must be established. RFC 6062 defines two roles:

- **Active side**: Sends a CONNECT request, asking the TURN server to establish a TCP connection with the peer's relayed address.
- **Passive side**: Waits for the peer connection, then establishes a data connection upon receiving a CONNECTION-ATTEMPT indication.

stice uses **ufrag lexicographic comparison** to deterministically select the active side (`shouldInitiateTcpConnect()`): the party with `local_ufrag >= remote_ufrag` is the active side. This avoids both sides sending CONNECT simultaneously before ICE role conflict (487) is resolved.

```
Active (Mode-A)              TURN Server              Passive (Mode-A)
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

### 2.4 Data Connection Setup and CONNECTION-BIND

Whether the active side receives a CONNECT success response or the passive side receives a CONNECTION-ATTEMPT indication, both parties need to:

1. Open a new TCP connection to the TURN server (Mode-B data connection).
2. Send a CONNECTION-BIND request on that connection, carrying the `CONNECTION-ID` obtained from the CONNECT response or CONNECTION-ATTEMPT indication.
3. After receiving the CONNECTION-BIND success response, the data connection binding is complete and application data can be transmitted.

```
Client (Mode-B)                         TURN Server
     │                                        │
     │── TCP connect ───────────────────────►│
     │                                        │
     │── CONNECTION-BIND Request ───────────►│
     │   CONNECTION-ID: <id>                  │
     │   (RFC 4571 framing)                   │
     │                                        │
     │◄── CONNECTION-BIND Success ───────────│
     │                                        │
     │◄════ Application data / STUN checks ══►│
     │   (RFC 4571 framing, transparent)      │
```

**Key difference**: The Mode-A control connection uses `Raw` framing (STUN/ChannelData self-delimiting), while the Mode-B data connection uses `RFC4571` framing (2-byte length prefix before each frame), because the data connection carries a mixed stream of raw application data and STUN messages that require length prefixes for delimiting.

### 2.5 Data Transmission and STUN Connectivity Checks

After the data connection binding is complete, stice routes all STUN connectivity checks and application data for that pair through the Mode-B data connection:

- In `sendStunBinding()`, when `pairIsTurnTcpRelay(e.pair)` is detected, the STUN Binding request is sent via `sendTurnDataConn()`.
- In `sendBindingResponse()`, when the request is detected to have come from the data connection, the response is also sent back through the same data connection.
- Application data is sent via `stice_send()` → `sendViaSelectedPair()` → `sendTurnDataConn()`.

## 3. stice API Usage Guide

### 3.1 Enabling RFC 6062 TCP Allocation

In stice, enabling RFC 6062 TCP allocation simply requires setting the TURN server transport type to `STICE_TURN_TRANSPORT_TCP`:

```c
#include <stice/stice.h>

stice_config_t config = {0};

stice_turn_server_t turn = {0};
turn.host = "turn.example.com";
turn.port = 3478;
turn.username = "user";
turn.password = "pass";
// Key: set to TCP transport, stice will automatically use RFC 6062 TCP allocation
turn.transport = STICE_TURN_TRANSPORT_TCP;

config.turn_servers = &turn;
config.turn_servers_count = 1;

stice_agent_t *agent = stice_create(&config);
stice_gather_candidates(agent);
```

After setting `transport = STICE_TURN_TRANSPORT_TCP`, stice internally will:
1. `turn::Client` sets `isTcpAllocation_ = true`, and `REQUESTED-TRANSPORT = 6` in the Allocate request.
2. `Agent` creates `turnTcpTransport_` (Mode-A control connection, Raw framing mode).
3. The gathered relayed candidate is of type `relayed` with `tcptype=passive`.
4. During `formPairs()`, it automatically calls `ensurePermission()` and `sendConnect()` (active side).
5. When CONNECT succeeds or CONNECTION-ATTEMPT arrives, it automatically creates `turnDataConn_` (Mode-B data connection, RFC4571 framing mode) and sends CONNECTION-BIND.

### 3.2 Enabling ICE-TCP

RFC 6062 TCP relay is typically used in conjunction with ICE-TCP (RFC 6544). To enable ICE-TCP:

```c
// Enable ICE-TCP (active + passive mode)
stice_set_ice_tcp_mode(agent, STICE_ICE_TCP_MODE_ACTIVE_PASSIVE);
```

Available modes:
- `STICE_ICE_TCP_MODE_NONE`: Disable ICE-TCP (default)
- `STICE_ICE_TCP_MODE_ACTIVE`: Active mode only
- `STICE_ICE_TCP_MODE_PASSIVE`: Passive mode only
- `STICE_ICE_TCP_MODE_ACTIVE_PASSIVE`: Active + passive (recommended)

### 3.3 SDP Format for Relayed Candidates

RFC 6062 TCP relayed candidates in SDP format:

```
a=candidate:1 1 tcp 1673026431 192.0.2.1 50000 typ relay tcptype passive raddr 0.0.0.0 rport 0
```

Key fields:
- Transport protocol is `tcp` (not `udp`)
- `typ relay`: Relayed type
- `tcptype passive`: TCP candidate type is passive (RFC 6062 relayed candidates are always passive)

### 3.4 Callbacks and Events

stice's standard callbacks work normally in RFC 6062 scenarios:

```c
static void on_state_changed(stice_agent_t *agent, stice_state_t state, void *user) {
    // STICE_STATE_GATHERING → Gathering relayed candidates
    // STICE_STATE_CONNECTING → CONNECT / CONNECTION-BIND in progress
    // STICE_STATE_CONNECTED  → Data connection binding complete, ready for data
    // STICE_STATE_COMPLETED  → ICE completed
}

static void on_candidate(stice_agent_t *agent, const char *sdp, void *user) {
    // sdp contains relayed candidate with tcptype=passive
    // Send to peer via signaling
}

static void on_recv(stice_agent_t *agent, const char *data, size_t size, void *user) {
    // Application data received through Mode-B data connection
}
```

## 4. Built-in Tests and Verification

### 4.1 RFC 6062 Specific Tests in test_turn

```bash
# Run all TURN tests (including RFC 6062)
./build/Release/test_turn.exe

# Run only tests tagged with rfc6062
./build/Release/test_turn.exe "[rfc6062]"
```

Coverage:
- CONNECT request construction and sending
- CONNECTION-BIND request construction
- CONNECT success response parsing (extracting CONNECTION-ID)
- CONNECTION-ATTEMPT indication parsing
- CONNECT failure handling (error codes such as 447)
- Active + passive dual-mode state machine

### 4.2 TCP Relay Pair Filtering in test_candidate_pair

```bash
./build/Release/test_candidate_pair.exe "[pair]"
```

Verifies the TCP candidate pair filtering rules of RFC 6544 §5.2, especially the RFC 6062 exception: two `relayed passive` candidates **can** be paired (end-to-end connection established via CONNECT/CONNECTION-ATTEMPT), while non-relayed passive-passive pairs are filtered.

### 4.3 stserver Integration Tests

```bash
# Start stserver
./stserver --config stserver.test.conf

# Run TURN TCP relay test (RFC 6062 Mode-B)
./test_stserver_all.exe 127.0.0.1 3478 turn-tcp

# Run TURN relay test (TCP transport)
./test_stserver_relay.exe 127.0.0.1 3478 tcp
```

The `turn-tcp` mode tests the complete flow: allocation → CreatePermission → CONNECT → CONNECTION-BIND → data exchange.

## 5. FAQ and Troubleshooting

### 5.1 CONNECT Failure (Error Code 447 Connection Timeout or Failure)

**Cause**: The TURN server cannot establish a TCP connection with the peer's relayed address.

**Troubleshooting**:
1. Confirm the peer has completed TURN allocation and obtained a relayed candidate.
2. Confirm the peer has created CreatePermission for the local relayed address (RFC 6062 §4.4: without permission, the server does not send CONNECTION-ATTEMPT).
3. Check whether the firewall allows the TURN server's outbound TCP connections to the relay port range.
4. stice automatically retries CONNECT up to 3 times (500ms interval); after that, the candidate pair is marked as failed.

### 5.2 No Data Transmission After Data Connection Established

**Cause**: CONNECTION-BIND did not succeed, or STUN connectivity checks are not sent through the data connection.

**Troubleshooting**:
1. Check the logs for `TURN data: opening data connection connId=...`.
2. Check whether CONNECTION-BIND received a success response.
3. Confirm `turnDataConn_->bound == true` (STUN checks are only sent through the data connection after binding is complete).
4. Check whether the candidate pair is recognized as `pairIsTurnTcpRelay` (local candidate is `relayed` and `transport=TCPPassive`).

### 5.3 Both Sides Send CONNECT Simultaneously

**Cause**: RFC 6062 requires only one side to send CONNECT, while the other waits for CONNECTION-ATTEMPT.

**stice's handling**: Uses `shouldInitiateTcpConnect()` based on ufrag lexicographic comparison to deterministically select the active side, avoiding both sides sending simultaneously. If ufrag has not been exchanged yet (`remote_.iceUfrag.empty()`), it falls back to the ICE role (the Controlling side is active).

### 5.4 Compatibility with coturn

stice's RFC 6062 implementation is compatible with the [coturn](https://github.com/coturn/coturn) server. When using coturn, ensure:
- The server configuration enables TCP relay (`listening-port` listens on TCP simultaneously).
- The relay port range (`min-port`/`max-port`) has sufficient TCP ports.
- Long-term credential authentication is configured correctly.

## 6. Design Decisions and Limitations

### 6.1 Single Data Connection Limitation

Currently stice maintains only one `turnDataConn_` (Mode-B data connection) per Agent. This means in multi-pair scenarios, only one TCP relay pair can be in active data transmission at a time. This is a typical limitation for ICE scenarios (usually only one selected pair), but it needs to be extended in scenarios requiring simultaneous maintenance of multiple TCP relay connections.

### 6.2 Ufrag Ordering for Active Side Selection

The RFC 6062 specification does not define how to select the CONNECT initiator. stice uses ufrag lexicographic comparison (consistent with libjuice), with the advantage that the active side can be deterministically selected before ICE role conflict resolution, ensuring CONNECT completes before STUN checks.

### 6.3 CreatePermission Still Required

CreatePermission is not optional in RFC 6062 scenarios. The passive side's TURN server checks permissions when accepting inbound TCP connections; without permission, it closes the connection and does not send CONNECTION-ATTEMPT. stice proactively calls `ensurePermission()` during the `formPairs()` phase to ensure permissions are ready.

## 7. References

- RFC 6062: Traversal Using Relays around NAT (TURN) Extensions for TCP Allocations
- RFC 8656: Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)
- RFC 6544: TCP Candidates with Interactive Connectivity Establishment (ICE)
- RFC 8445: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal
- pion/turn: Go language TURN implementation (porting reference for stice)
- libjuice: C language ICE library (API compatibility target for stice)
