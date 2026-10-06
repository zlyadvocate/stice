# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.11.0] - 2026-10-06

### Added
- `turn-tcp-suite` (libdatachannel integration suite) case 8: STUN 10% packet-loss
  stress test (netem `loss 10%` filtered to the STUN path, 100 concurrent pairs)
  validating stice gathering and STUN retransmission under loss; case 7 build
  retried 3× and open timeout raised for high-concurrency coturn queuing.


### Fixed
- ICE: link-local candidates no longer break direct connections. Chrome on a
  multi-adapter host (VMware / disconnected Ethernet) exposes `169.254.x.x`
  APIPA host candidates; same-host loopback made STUN checks succeed over a
  self-loop path and the pair got nominated before healthy pairs, after which
  DTLS could never complete its handshake (30 s timeout, no video). Fixes:
  - `addrIsLocal`/new `addrIsLinkLocal` recognize IPv4-mapped IPv6
    addresses, closing a leak where dual-stack sockets enumerate `169.254.x.x`
    as `::ffff:169.254.x.x` and bypassed the IPv4 link-local checks.
  - `formPairs` skips link-local remote candidates, and `findOrCreatePair`
    refuses link-local peer-reflexive sources (loopback is deliberately still
    allowed — local test topologies use it).
- TURN over TCP: the relayed candidate now follows the **allocation protocol**
  rather than the control-connection transport, completing the 0.10.1 RFC 8656
  default: a UDP-relay allocation carried over a TCP/TLS control connection
  emits a UDP `typ relay` candidate (previously emitted `tcptype passive` TCP,
  so two stice agents paired passive↔passive and never connected —
  `test_integration` TURN-TCP and the stserver TURN-TCP stress were stuck).
- `STICE_TURN_TCP_RFC6062=1` is now actually read (was documented but never
  implemented): it opts a TCP/TLS-controlled TURN server into an RFC 6062
  TCP allocation (`REQUESTED-TRANSPORT=6`); `test_coturn_bench`'s `turn-tcp`
  mode relies on it.
- stserver: RFC 8656 over a TCP/TLS control connection now works end to end.
  A UDP-relay allocation created on a TCP control connection is additionally
  keyed by that control socket (control-plane requests — CreatePermission,
  ChannelBind, Refresh, Send, ChannelData — previously failed with
  `437 Allocation Mismatch`), keeps its control socket, and peer data is
  forwarded back over the control connection instead of a UDP path the client
  never had.

- ICE gathering could wedge indefinitely under load: when `gatherCandidates`
  hit an early-return or `onBookkeeping` ran before a deadline was seeded, the
  soft-gathering timeout never armed, so a stream waiting on an srflx response
  stayed in `GATHERING` until the caller's own timeout. Now `gatherStartedAt_`
  is seeded on both paths and the poll wake interval is clamped to 1 s (was
  15/60 s), so a wedged stream is force-completed after `GatherTimeoutMs` (15 s).
- Diagnostic logging to locate wedged streams: `GATHER-DONE` (pending/relay/
  cand/state/remote_set), extended `GATHER-CHECK`, `SOFT-TIMEOUT`, and
  `STUN-RESP` `MATCH`/`NO-MATCH` on the agent's STUN socket.
- UDP sockets now raise `SO_RCVBUF`/`SO_SNDBUF` to 4 MiB; `udp_mux` logs
  `UDPMUX-ROUTE` and broadcasts STUN without a USERNAME to listening agents.

### Changed
- `test_turn.cpp`: the two RFC 6062 wire-format tests now opt in via
  `cfg.tcpAllocation = true` (transport=TCP alone means RFC 8656 since 0.10.1).
- `test_coturn_bench.cpp`: default coturn host updated to `192.168.3.223`.

- `DEBUG_FAST` ICE check RTO initial 400→500 ms (RFC 5389 recommended minimum),
  more robust under congestion.
- `test_pairing_strategy.cpp`: DEBUG_FAST `rto_initial` assertion synced
  400→500 to match the RTO change.

## [0.10.1] - 2026-08-31

### Added
- `test_coturn_bench.cpp`: reference benchmark for the stice TURN client against
  coturn, covering `ice-udp` / `ice-tcp` / `turn-udp` / `turn-tcp` (RFC 6062) modes.
  Each mode measures RTT (64-byte ping-pong) plus windowed bulk goodput (1200 B),
  with a receive-driven condition-variable window gate so throughput reaches the
  relay path's real limit instead of being bounded by sleep granularity.
- `test_coturn_bench.cpp` CLI knobs for long-duration / window tuning: positional
  args 8–10 now select the bulk UDP packet count (`udpPkts`), bulk TCP packet
  count (`tcpPkts`), and the relayed-TCP in-flight window (`turnTcpWindow`).
- `test_libjuice_simple/test_libjuice_bench.c`: libjuice dual-agent reference
  benchmark that exchanges only relay candidates (forces the coturn relay path),
  measures relay RTT, then runs a fixed-window throughput/loss sweep — used as the
  gold-standard comparison against stice flow control.

### Changed
- TURN-over-TCP now follows **RFC 8656** by default: with `STICE_TURN_TRANSPORT_TCP`
  the allocation is a **UDP relay** (`REQUESTED-TRANSPORT=17`) carried over the TCP
  control connection, with media sent as ChannelData over that same connection —
  matching browser native WebRTC and coturn, and fixing the former
  `ChannelBind failed: 403` failure that blocked the turnstreamer "Use TURN relay
  tcp" web test. The relayed candidate is now a UDP relay candidate (not TCPPassive).
  RFC 6062 (TCP relayed-transport allocation, `REQUESTED-TRANSPORT=6`, CONNECT /
  CONNECTION-BIND machinery) is retained as an opt-in via `STICE_TURN_TCP_RFC6062=1`
  for stice↔stice interop only; `test_coturn_bench`'s `turn-tcp` mode enables it
  automatically.
- TURN-UDP flow control: derive the in-flight window from the **p95** RTT
  (BDP = target-rate × RTT) instead of the average RTT. coturn's relay path
  delivers latency in bursts (p95 ≫ avg), so an avg-derived window under-fills
  and triggers spurious stall-breaks; a p95-derived window sustains the target
  rate across latency spikes.
- TURN-UDP stall-breaker: on a stalled window, **reset the in-flight counter and
  enter a 100 ms cooldown** instead of retransmitting the whole window. Immediate
  full-window resend over-drove coturn's relay buffers and caused 1–4 % packet
  loss; cooldown lets the pipe and relay buffers drain before resuming.
- `test_libjuice_bench.c`: batched relay-only candidate forwarding after
  gathering (instead of per-candidate echo), fixed a window-variable shadowing bug
  that used the wrong window size, removed send-from-within-recv-callback echo
  reentrancy (a libjuice thread-safety crash), and added a no-progress deadlock
  guard (fills with `Sleep(1)` when the window is open but no frames are
  delivering).
- `src/ice/agent.cpp` — resilience / gather-path hardening:
  - Server-reflexive gathering is now asynchronous via a Server-type StunEntry
    delivered by the PollRegistry, instead of a blocking Binding request. This
    avoids a Windows `WSAPoll` race where a socket is polled by two waiters but
    only one is notified, which previously stalled server-reflexive gathering.
  - STUN/TURN server DNS is resolved in parallel via per-item `std::async`
    (numeric-IP fast path first), eliminating serial `getaddrinfo` blocking that
    stalled the poll thread during gathering.
  - The UDP receive path uses a 64 KB buffer so jumbo TURN-relayed datagrams
    (ChannelData beyond the 1500-B MTU) do not fail with `EMSGSIZE` on Windows
    and get silently dropped.
  - TCP-relay (RFC 6062) nomination gained a stability precheck window under
    `REGULAR_STABLE_CHECK`: a relayed Mode-B pair is only nominated after
    `tcp_nomination_precheck` elapses since success, so flaky links aren't
    brought up prematurely — unless application data has already flowed over the
    pair within the window, in which case the precheck ends early.
- `src/net/tcp.cpp` — raised TCP socket buffers to 512 KiB
  (`SO_SNDBUF`/`SO_RCVBUF`) on both the connect path (`beginConnect`) and
  accepted sockets (`attach`), alongside `TCP_NODELAY`. The OS default
  (64 KiB on Windows) is too small for relayed bulk transfers: an over-buffer
  burst overflows the kernel queue, drops segments, and triggers exponential
  RTO backoff across the multi-hop relay (measured 11 Mbps with 10 s stalls vs
  344 Mbps raised).
- `src/net/udp_mux.cpp` — shared-socket multiplexing hardening:
  - 64 KB receive buffer for jumbo TURN-relayed datagrams (as in `agent.cpp`).
  - Loopback routing compares by port only (the mux may bind to `0.0.0.0`),
    always updates the sender address-map entry, and broadcasts non-STUN
    loopback packets to all agents except the sender to avoid echo.
  - The `onPacket`/agent callbacks now run outside the mux mutex, preventing a
    deadlock when an agent callback re-enters `sendto` on the same mux
    (`std::mutex` is non-recursive).
  - `removeAgent` cleans up every address-map entry pointing at the removed
    agent, avoiding dangling references.

### Fixed
- **15-second relay-only connection delay** (browsers stuck in `checking` /
  DTLS-SCTP handshake stalled after ICE connected). Three stacked causes, all
  in `src/ice/agent.cpp`:
  1. `armKeepalive` treated `lastAppDataAt_ == 0` (no application data yet —
     the normal state right after a pair succeeds, before the DTLS handshake
     starts) as "idle session" and stretched the first post-connect keepalive
     to `IdleConsentCheckMs` (15 s).
  2. `Agent::nextTimestampMs()` did not account for the controlling-side
     nomination deadline. With every entry in `SucceededKeepalive` and the
     controlled peer silent while awaiting `USE-CANDIDATE`, no inbound traffic
     woke the poll thread, so nomination (armed only inside bookkeeping) sat
     out the full 15 s keepalive timeout.
  3. The remaining ~2 s was the `NominationDelayRelayMs` (2000 ms) acceptance
     wait. Added early locking: once every other connectivity check has
     concluded (no Pending/unarmed Check entries), no better pair can appear
     from the current candidate set, so nomination proceeds immediately;
     draft-thatcher renomination still migrates to a higher-priority pair if
     one succeeds later (e.g. via trickle), so early locking never pins a
     suboptimal link.
  Measured with Firefox over coturn relay-only (both UDP and TCP TURN):
  checking→connected went from **15.1 s → ~71 ms** (2.0 s between fixes 1+2
  and 3). Host-direct connections (streamer example) verified unaffected.
- Spurious packet loss (1–4 %) in TURN-UDP bulk transfers caused by the
  stall-breaker misreading latency spikes as loss and immediately overfilling the
  window, overflowing coturn's relay buffer.
- Wrong benchmark window size in `test_libjuice_bench.c` caused by a local
  `window` shadowing the command-line argument.
- `Agent::addTurnServer` kept the `host`/`username`/`password` C strings by
  shallow-copying the `stice_turn_server_t` struct, so the raw pointers dangled
  once the caller's `IceServer` copy went out of scope (e.g. libdatachannel's
  `addIceServer`). TURN gathering then read garbage as the host and failed to
  resolve/allocate a relay. `addTurnServer` now deep-copies the three strings
  into the agent's own backing storage, matching `addStunServer`/`addIceServer`.
  Verified end-to-end with libdatachannel's `turnstreamer` example (relay
  allocation succeeds) and `test_coturn_bench` turn-udp (zero loss).
- **Multi-TURN-server deployments failed or stalled** (garbage hosts, 10 s
  gather stalls, one-way black holes). Fixes across `src/ice/agent.cpp`,
  `src/ice/sdp.cpp`, and `include/stice/ice/{agent,sdp}.hpp`:
  1. The TURN-server host/username/password backing storage (and
     `Description::candidates`) were `std::vector`s: adding a second server
     reallocated the vectors and left every previously-registered server's
     strings — and every formed candidate pair's `local`/`remote` pointers —
     dangling (garbage hosts such as `could not resolve <mojibake>`). Both
     now use `std::deque`, whose `push_back` never invalidates references to
     existing elements; `addLocalCandidate` also no longer re-sorts the
     candidate list after pairs exist (permutation would silently re-bind
     pair pointers).
  2. `setRemoteDescription`/`addRemoteCandidate` waited for gathering to
     complete before forming pairs, so one dead TURN server's ~10 s allocate
     timeout stalled the whole checking phase (the controlled peer times out
     waiting for our checks). Pairs are now formed as soon as a remote
     description/candidate is available; relay candidates from slow servers
     are paired incrementally on arrival.
  3. `sendBindingResponse` routed through the first Relay entry regardless
     of allocation state: with a dead server's entry preceding the live
     one, binding responses were sent into an unallocated TURN and silently
     dropped, leaving the peer's connectivity checks unanswered (ICE stuck
     in `checking`, disconnect after consent timeout). All relay routing now
     requires `AllocState::Allocated`.
  4. STUN servers registered via multiple `turn:`/`stun:` URLs are
     deduplicated by host:port (previously each variant gathered a redundant
     server-reflexive candidate).
  5. `addTurnServer`/`addIceServer` now allow up to 8 TURN servers each.
  Verified with coturn (live 3478 + dead 3479 server), Firefox relay-only
  through libdatachannel's `turnstreamer`: checking→connected **61 ms** —
  indistinguishable from the single-server case; the dead server fails in
  the background without blocking establishment.
- `turnstreamer` example: server-side trickle ICE. The offer is sent
  immediately after `setLocalDescription` and candidates are forwarded as
  gathered (previously the offer waited for gathering-complete, so a dead
  co-registered TURN server delayed the offer by its full allocate timeout).
  Candidates are sent in `RTCIceCandidateInit` form — the bare
  `candidate:...` line, not the `a=`-prefixed SDP attribute (Firefox's
  `addIceCandidate` rejects the prefixed form; Chrome is lenient). Client
  `client.js` buffers server candidates that arrive before
  `setRemoteDescription` settles and fills `sdpMLineIndex: 0` when the
  server's `sdpMid` is empty. The example now accepts a comma-separated
  TURN host list (`host1,host2[:port]`).

### Notes
- Regression verified against the coturn/VM relay path ceiling (~175 Mbps for
  zero packet loss; single-path ceiling ~250–270 Mbps). With window ≈ RTT × target
  bandwidth kept within the physical limit, TURN-UDP achieves zero packet loss at
  ≥ target rates, and TURN-TCP sustains stable throughput with zero loss over long
  runs (e.g. 3 M packets).

## [0.10.0] - 2026-08-19

### Added
- Initial public release under MPL-2.0 license
- C++17 ICE + TURN client library ported from pion/webrtc
- Native `stice_*` C ABI with full feature parity
- `juice_*` libjuice compatibility layer (drop-in replacement)
- ICE Agent (RFC 8445): connectivity checks, nomination, trickle ICE, ICE restart
- STUN client (RFC 8489): multi-STUN parallel server-reflexive gathering
- TURN client (RFC 8656): UDP / TCP / TLS transports, channel data, permissions
- TURN TCP Allocations (RFC 6062): Mode-A control + Mode-B data pipe, CONNECT/CONNECTION-ATTEMPT/CONNECTION-BIND/CONNECTION-ID, active+passive dual mode
- ICE-TCP (RFC 6544): active / passive / simultaneous-open candidates, TCP priority offset, TCPMux
- mDNS support: query-only and query-and-gather modes
- NAT 1:1 address rewrite: replace / append external IP mappings
- UDP and TCP multiplexing across multiple agents
- Runtime-configurable ICE pairing strategies (4 preset profiles), RFC 6062 TCP-relay fallback
- Built-in TURN/STUN server (`stserver`): UDP + TCP listeners, TURN UDP relay, TURN TCP relay (RFC 6062 Mode-B), ICE-TCP passive support; epoll / IOCP / select backends
- Comprehensive test suite using Catch2 (unit, integration, performance, stress, RFC 6062-specific)
- libjuice API compatibility test suite

### Changed
- Version bumped from 0.1.0 to 0.10.0 for first public release
- Project metadata: author zlyadvocate, license MPL-2.0

### Notes
- This is the first release intended for public consumption and integration
  with libdatachannel as a libjuice replacement.
