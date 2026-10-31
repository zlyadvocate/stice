## [0.13.1] - 2026-10-30

TCP relay media is sharded across dedicated data threads on the server, and a
round of transport/relay fixes lands on top. No API or ABI change.

### Fixed

- **TURN over TLS lost the tail of a data stream.**
  `TcpTransport::onReadable()` returned as soon as one TLS record had been read:
  the "short read" exit compared against the 64 KiB buffer while the record
  layer caps a read at 16 KiB, so it fired on *every* event. The UDP path has
  always drained its socket completely on each readable event — that is what the
  wepoll/epoll rework made reliable — but the TLS path handed the rest back to
  the event loop, which cannot re-notify for records the record layer has
  already pulled out of the kernel socket buffer. Once the sender went silent
  nothing ever woke the loop again, so the last 1-13 ChannelData frames were
  stranded and reported as loss. Reproduced deterministically: one readable
  event moved 16,384 of 28,896 bytes. The read pump now drains until the backend
  reports would-block, matching the UDP path, and the new test
  `TLS: a burst followed by silence is drained by one readable event` fails on
  the old behaviour and passes on the new one (all three backends).
- **Buffered TURN data was discarded on transport backpressure.** When a
  CreatePermission completed, the flush ignored `sendRaw`'s return value and
  cleared the buffer unconditionally, so a refused write (EWOULDBLOCK/ENOBUFS)
  silently dropped data `stice_send` had already reported as accepted. Unsent
  packets now stay queued in order and are retried from the client tick.
- **An interrupted `SSL_write` could be resumed with a different length.** The
  length was recomputed from the queue on each retry, and the queue can grow
  while the write is pending (OpenSSL then fails with "bad write retry"). The
  length of the interrupted call is now remembered per queue and reused.
- **The UDP listener was capped at one in-flight receive per socket.** A single
  `WSARecvFrom` per socket limits drain to one completion-and-repost round trip
  per datagram: measured ~53k pps on the listener, i.e. ~63 MiB/s at 1200-byte
  blocks, and every client's media arrives on that ONE socket. Past that point
  the kernel queue overflowed while `RELAY-STAT` still reported `drop=0`. A
  pool of receives is now armed per socket (32 on the listener, 8 on relay
  sockets) so several workers drain the same socket concurrently; each
  completion owns its own buffer, so pending ops never alias.
- **stserver counted refused relay sends as successes.** `logSendToFailure()`
  logged EWOULDBLOCK/ENOBUFS at DEBUG and the caller still counted the frame as
  forwarded, so a full send buffer was invisible in `RELAY-STAT`. The helper
  now returns whether the send actually succeeded and refused sends are counted
  as `sendFail`, which is what made the listener ceiling above measurable.

### Changed

- **TCP media no longer funnels through the single business thread.** TURN-over-
  TCP control-connection frames and both RFC 6062 data pipes used to be
  serialized in `businessThread_` under `stateMutex_`, which capped TCP relay
  throughput at one core and let bulk data starve control transactions
  (CreatePermission timed out once the in-flight window filled). Sockets are
  now hashed to N data shards (`shardIndexFor`), each shard owning its own FIFO
  queue and thread, so a connection is always handled by the same thread and
  per-connection byte order is preserved without cross-thread parse buffers.
  Media frames take a fast path that holds only `connMapMutex_` (shared) plus a
  `TcpConn::ioUsers` reference instead of `stateMutex_`; only STUN control
  frames still take the global lock. Teardown never waits for in-flight IO:
  `closeTcpConn()` moves the object to `pendingFreeConns_` and the business
  thread reaps it once the reference count drains. Lock order is unchanged
  (`stateMutex_ -> connMapMutex_ -> Allocation::mtx -> TcpConn::writeMtx`).
  `RELAY-STAT` gained a `pipe` field for RFC 6062 data-pipe bytes.
- **`test_longrun_4mode` no longer ratchets the flow down.** In-flight depth
  alone no longer throttles the sender while the receiver is still advancing;
  the old gate froze 128 MiB/s at 1200-byte blocks down to ~2 MiB/s as soon as
  the window first filled.

### Verified

- `test_tls_transport` 7/7 on OpenSSL, GnuTLS and Mbed TLS (2.28 + 3.x), Windows
  and Linux.
- `turns` soak, 8 clients x 300 s at 512 KiB/s against coturn over TLS:
  **47 client-runs, 0 bytes lost** (24 at INFO level, 23 at WARN level), against
  roughly one losing client per 5-minute round before the fix. The new
  per-connection counters (`TcpTransport: closed tls=1 tx=... rx=...`, INFO) show
  the sender's `tx` and the peer's `rx` agreeing to within control-frame traffic,
  so the record layer is no longer stranding anything on either end.
- One client in one round lost its *connection* instead (`SSL_read failed` ->
  `TURN TCP: connection lost` -> `stice_send rc=-2`). That is an explicit
  transport failure, not silent loss, and is tracked separately from this fix.
- `tcpturn` 128 MiB/s, Windows, 32 clients x 4 MiB/s x 900 s (1200-byte blocks):
  **120.79 GB relayed, 0 bytes lost**, `drop=0 sendFail=0`, `qS` in single
  digits. This is the load that failed on control-plane starvation before the
  sharding rework.
- `tcpturn` 128 MiB/s, Linux, 16 clients x 8 MiB/s x 900 s (8 KiB blocks):
  **120.79 GB relayed, 0 bytes lost**, server RSS 10.6 MB -> 9.8 MB, client RSS
  flat at 7 MB.
- Linux `udpturn` 100 MiB/s (10 x 10 MiB/s) and 32 concurrent TCP connections at
  32 MiB/s: 0 bytes lost, confirming the UDP path and the 32-connection shard
  distribution are unaffected.
- 32 concurrent TCP clients on a 4-core VM at 128 MiB/s aggregate fails inside
  the *client* (32 driver processes starve, `stice_send rc=-2` at the window
  edge, mid-run `lag=0`) while the server still reports `drop=0 sendFail=0`; the
  same aggregate passes with 16 clients, so this is test-host CPU density, not a
  relay defect.

## [0.13.0] - 2026-10-28

Pluggable TLS backend: TURN over TLS no longer requires OpenSSL. stice now
builds against OpenSSL, GnuTLS or Mbed TLS, selected with **the same CMake
variables libdatachannel uses**, so an existing libdatachannel integration keeps
its crypto backend without extra configuration.

### Added

- **TLS record-layer abstraction** (`include/stice/net/tls.hpp`,
  `src/net/tls_{openssl,gnutls,mbedtls,none}.cpp`). `TcpTransport` no longer
  talks to OpenSSL directly; it drives a `TlsSession` with one non-blocking
  contract (Ok / WantRead / WantWrite / Closed / Failed) implemented by each
  backend. Client and server modes are both supported (server mode backs the
  in-process TLS echo server used by the new tests).
- **libdatachannel-compatible backend selection**: `USE_GNUTLS=ON` →
  `find_package(GnuTLS)` + `GnuTLS::GnuTLS` + `USE_GNUTLS=1`; `USE_MBEDTLS=ON`
  → `find_package(MbedTLS)` + `MbedTLS::MbedTLS` + `USE_MBEDTLS=1`; otherwise
  OpenSSL + `USE_GNUTLS=0`. Enabling both is a configure-time error, exactly as
  in libdatachannel. Standalone builds may use `STICE_USE_GNUTLS` /
  `STICE_USE_MBEDTLS`; `STICE_USE_OPENSSL=OFF` with neither builds without TLS
  (TURN/TLS then degrades to plain TCP with a warning, as before).
- **`stice_get_tls_backend()`** (C API) returns `"openssl"`, `"gnutls"`,
  `"mbedtls"` or `"none"` for the compiled-in backend.
- **`STICE_TLS_CA_FILE`** environment variable: pin an explicit PEM trust bundle
  instead of the platform trust store, for deployments (and tests) with a
  private CA. Honored by all three backends.
- **`stice_turn_server_t::ca_file`** — per-server trust anchor. Non-empty means
  that TURN server's TLS control connection (and the RFC 6062 data connection
  that inherits its TLS parameters) is verified **only** against that PEM
  bundle; `NULL`/empty falls back to `STICE_TLS_CA_FILE` and then to the
  platform store. Precedence is therefore per-server field > process-wide
  variable > platform store, which is what lets one agent hold allocations on
  several TURN servers with different private CAs (up to 8 servers). The string
  is deep-copied when the server is added, like host/username/password. It was
  appended as a trailing struct field, so zero-initialised configs keep the old
  behaviour but binaries must be recompiled. The juice compatibility layer
  leaves it `NULL` (no counterpart upstream); use `stice_add_turn_server()` for
  per-server anchors. `test_longrun_4mode` gained `--turn-ca-file` to exercise
  the path end to end.
- **`tests/test_tls_transport.cpp`** + `tests/data/` (two-level test PKI): an
  in-process TLS echo server exercises handshake, byte-exact echo, rejection of
  an untrusted peer, and pinned-CA acceptance, for whichever backend the build
  selected.
- **`turns` mode** in `tests/test_longrun_4mode.cpp` (TURN control connection
  over TLS, UDP-relayed media) and per-mode TLS endpoint overrides in the soak
  drivers (`-TlsTurnHost` / `-TlsTurnPort` / `-TurnSkipVerify`, plus
  `TLS_TURN_HOST` / `TLS_TURN_PORT` / `TURN_SKIP_VERIFY`).

### Changed

- Certificate verification semantics are identical across backends: verify
  against the platform store by default, honor `skip_tls_verify`, and use
  `STICE_TLS_CA_FILE` when set. Mbed TLS has no platform trust store, so without
  a bundle it falls back to `VERIFY_NONE` and logs a warning rather than
  pretending to verify.
- TLS 1.2 is the floor on every backend.

### Fixed

- OpenSSL backend checked `SSL_get_verify_result()` even with
  `skip_tls_verify`, rejecting every self-signed peer regardless of the flag.
- GnuTLS verification now runs explicitly after the handshake
  (`gnutls_certificate_verify_peers3`) because the session-level hook
  (`gnutls_session_set_verify_cert`) rejected chains that the same API accepts
  on the mingw-w64 build.
- **TURN over TLS could never connect when the TCP connect was asynchronous**:
  `Agent::onTurnTcpEventsSock` only ran the "transport reached Connected" step
  from the POLLOUT branch. A TLS handshake finishes on a READABLE event, so the
  transport stayed in `TlsHandshaking`, the ALLOCATE was never sent, and
  gathering eventually reported `connect timeout`. The transition is now
  detected after either drive (plain TCP and TLS both covered).
- Stale TLS `WANT_READ`/`WANT_WRITE` hints are cleared as soon as a read or
  write makes progress; previously one transient `WANT_WRITE` kept POLLOUT
  armed for the rest of the connection (poll-loop spin).
- MinGW-w64 portability (needed for GnuTLS-on-Windows, which has no MSVC build):
  `ssize_t` is no longer redeclared when the toolchain provides it, `bcrypt` is
  linked explicitly for `BCryptGenRandom`, and `wepoll_poll.cpp` includes
  `<cstdint>`.
- **SIGPIPE could kill the host process** when a TURN/TCP/TLS peer went away
  mid-write (POSIX default action; found by the new ca_file test). Every send
  path now passes `MSG_NOSIGNAL` (`STICE_MSG_NOSIGNAL`: plain TCP,
  `TcpTransport`; GnuTLS `tlsPush`; Mbed TLS `tlsSend`) and macOS/BSD also get
  `SO_NOSIGPIPE` on the socket — the same treatment libjuice (`tcp.c`) and
  libdatachannel (`tcptransport.cpp`) give their sockets. The OpenSSL backend
  stopped using `SSL_set_fd()` altogether in favour of a small socket BIO whose
  writes carry `MSG_NOSIGNAL`; that also removes the `int` truncation of a
  64-bit Windows `SOCKET` (the earlier range check is gone because the handle
  now travels in a pointer-sized slot, guarded by the `socketToUserPtr`
  `static_assert`).
- **TURN servers addressed by IP failed verification.** OpenSSL checked the
  literal with `X509_VERIFY_PARAM_set1_host()`, i.e. as a *DNS name*, so even a
  certificate carrying `IP:192.0.2.1` was rejected. It now uses
  `set1_ip_asc()` for IPv4/IPv6 literals and omits SNI for them (RFC 6066 §3
  forbids IP literals in SNI); a shared `isIpLiteral()` in `tls.hpp` makes the
  distinction for every backend. GnuTLS the same way: no SNI for a literal, the
  chain is verified without a hostname and the address is matched with
  `gnutls_x509_crt_check_ip()`. Mbed TLS 3.x handles IP SANs natively. Mbed TLS
  2.x does not keep `iPAddress` entries in `mbedtls_x509_crt::subject_alt_names`
  (only `dNSName`/`otherName`), so stice parses the subjectAltName extension out
  of the peer certificate's DER itself and compares the 4/16-byte address — an
  IP-addressed TURN server now verifies on 2.28 as well, and a mismatch fails
  closed.

### Security hardening (post-review)

- **Contract violation in `TcpTransport::flushSends`** (TLS branch): a
  `TlsStatus::Ok` result with `n == 0` — which `tls.hpp` documents as
  "nothing transferred, try again" — was classified as Failed and tore the
  connection down, while the read path handled the same case correctly. No
  current backend returns `Ok`+`n == 0` on write, so this was latent, but any
  future backend or library version permitted to do so (for example a TLS 1.3
  post-handshake record) would have had its connection closed under it. The
  write path now fails only on `st != Ok` and treats `n == 0` as "keep the rest
  queued", mirroring `onReadable`.
- **Explicit modern-only cipher suites** on all three backends (RFC 8656 §4
  recommends configuring this rather than relying on defaults):
  - OpenSSL: `SSL_CTX_set_cipher_list("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:"
    "!aNULL:!eNULL:!MD5:!RC4:!3DES:!DES:!EXPORT:!PSK:!SRP:!DSS:!kRSA")` plus
    `SSL_CTX_set_ciphersuites` for TLS 1.3. Note `!kRSA` (key exchange), not
    `!RSA`, which is shorthand for `kRSA|aRSA` and would also drop every
    ECDHE-RSA suite.
  - GnuTLS: `NORMAL:-RSA:-VERS-TLS-ALL:+VERS-TLS1.3:+VERS-TLS1.2`, with
    `NORMAL:-RSA` and then `NORMAL` as fallbacks if the installed priority
    string rejects the version tokens.
  - Mbed TLS: numeric IANA suite list (TLS 1.3 AEAD suites + ECDHE-AEAD for TLS
    1.2, no static RSA, no CBC, no SHA-1 MACs) and
    `mbedtls_ssl_conf_tls13_key_exchange_modes(..., EPHEMERAL)` so TLS 1.3 uses
    pure-ephemeral key exchange only. One list has to cover both versions here
    because Mbed TLS 3.x has no per-version setter — handing it 1.2-only IDs
    makes every handshake fail with "handshake negotiation failed".
- **`SSL_set_fd` range check**: `windows SOCKET` is a 64-bit `UINT_PTR` and the
  OpenSSL API takes an `int`, so `attach()` now rejects handles above
  `INT_MAX` instead of silently truncating them.
- **Windows + OpenSSL trust store documented**: OpenSSL does not read the
  Windows certificate store and `SSL_CTX_set_default_verify_paths()` is usually
  empty there, so a verifying handshake against a private/self-signed CA fails
  unless `STICE_TLS_CA_FILE` is set. Both integration guides now say so
  explicitly; previously only the Mbed TLS limitation was called out.

### Review round 2 (compatibility layer, diagnostics, hygiene)

- **`JUICE_TURN_TLS_NO_VERIFY` is now honest about itself.** The compatibility
  layer honours the variable (as before) but logs a one-time WARN when it
  engages, because it is a process-wide switch that disables certificate
  verification for every connection: "certificate verification is DISABLED …
  test rigs only". The code comment no longer claims libjuice's `src/tls.c`
  implements it — the vendored libjuice snapshot has neither that file nor a
  single `getenv()` call, so it is documented as a stice extension added for
  self-signed test rigs. Integration guides §4.4 now describe the real
  behaviour (both entry points, table of conditions) instead of claiming a
  hard-coded `skip_tls_verify = 0`.
- **"No trust store" is now a WARN, not a DEBUG line.** This is the most common
  cause of a failed TURN/TLS handshake, and the user used to see only
  "certificate verify failed". OpenSSL now inspects the store after
  `SSL_CTX_set_default_verify_paths()` (success does not imply any anchor was
  loaded; on Windows the default path is empty) and GnuTLS warns when
  `gnutls_certificate_set_x509_system_trust()` returns 0 anchors. Both point at
  `STICE_TLS_CA_FILE`, matching what the Mbed TLS backend already did.
- **GnuTLS priority fallbacks keep the TLS 1.2 floor** and are no longer silent:
  `NORMAL:-RSA:-VERS-TLS-ALL:+VERS-TLS1.2`, then
  `NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2`, each with a WARN; the bare `NORMAL`
  escape hatch is gone, so a rejected priority string can no longer re-admit TLS
  1.0/1.1 behind the documentation's back.
- **GnuTLS peer-initiated renegotiation is refused** (`GNUTLS_E_REHANDSHAKE` →
  Failed + `errorString`). Mapping it to WantRead made `TcpTransport` re-arm
  POLLIN forever without resuming the handshake; `tls.hpp` now also states that
  WantRead never asks the caller to re-drive `handshake()`.
- **Socket-handle width is asserted in one place**: `socketToUserPtr()` /
  `userPtrToSocket()` in `tls.hpp` carry a `static_assert` that the handle fits
  in a pointer, used by the GnuTLS and Mbed TLS backends (OpenSSL keeps its
  runtime `int` range check). Previously both cast blindly.
- **Soak drivers refuse to run `turns` without a TLS endpoint**: the Linux and
  Windows long-test scripts now exit with an explanation instead of pointing the
  TLS mode at stserver's plaintext port (stserver terminates no TLS, docs §4.7).
  The Linux driver also builds its optional args as an array instead of relying
  on unquoted word splitting.
- **Closing a session no longer reallocates**: `TlsSession::close()` frees the
  backend state in place (each `Impl` grew a `reset()`), so shutdown does not
  allocate a throw-away `Impl` per connection and `errorString()` stays valid.
- **Hygiene**: the duplicated "clear the TLS want-hints on progress" logic in
  `TcpTransport` is one private helper (`clearTlsWantHints()`); duplicated
  OpenSSL error text is separated from the backend's own message with `": "`;
  `tests/data/README.md` states that the test PKI is test-only and must not be
  reused; `regress/bump_version_comments.py` replaces the one-off version-bump
  script (`--check` for CI), and the five `src/stserver` files still reading
  `// Version: 0.12.3` are stamped 0.13.0; the outer workspace README/CHANGELOG
  now state which of the two changelogs owns which history.
- **Documented trade-off (strict compliance)**: the modern-only cipher profile
  is not weakened by a fallback switch — when the handshake fails, that
  tls-turn candidate fails, ICE moves on per RFC 8445, and stice never silently
  downgrades to plaintext TCP. A legacy-only TURN endpoint is therefore
  unreachable, which the integration guides now spell out.

### Verified (all three backends, both platforms)

- TLS transport suite (`test_tls_transport`: handshake, byte-exact echo,
  untrusted peer rejected, pinned CA accepted) passes on OpenSSL 3.6 (vcpkg,
  MSVC x64), Mbed TLS 3.6 (vcpkg, MSVC x64) and GnuTLS 3.8 (MSYS2 mingw-w64) on
  Windows, and on OpenSSL 3.0.2, GnuTLS 3.7.3 and Mbed TLS 2.28 on Ubuntu 22.04.
- Full ctest regression per backend (25 tests each): Linux OpenSSL / GnuTLS /
  Mbed TLS and Windows OpenSSL / Mbed TLS / GnuTLS. Pass counts: 17/25 on Linux
  (all three), 17/25 (OpenSSL), 20/25 (Mbed TLS) and 19/25 (GnuTLS) on Windows.
  Every failure belongs to the same set of tests that need an externally
  started TURN server (`test_integration`, `test_libjuice_bench`,
  `test_stserver_*`), and a worktree of the pre-change commit fails that same
  set for the same reasons — the TLS work introduces no regression.
- 3 h soak, 5 transports (udp-ice, udpturn, tcpturn, tcp-ice and `turns`),
  4 clients x 512 KiB/s, zero-loss policy:
  - Linux / GnuTLS 3.7.3: 10,544 s, every mode 4/4 pass, `rx == sent`
    byte-for-byte, loss 0, including TURN over TLS.
  - Windows / OpenSSL 3.6 (MSVC): 10,606 s, udp-ice/udpturn/tcpturn/tcp-ice
    4/4 pass with loss 0; `turns` 3/4 pass. The one failure lost 81,600 bytes of
    4.40 GB (0.002 %) on a single client across the wireless link to the TLS
    TURN server — UDP loss on the WiFi hop, not a TLS error (the same mode is
    byte-exact on the loopback leg above).
- Sustained TURN-over-TLS runs (10 min, 4 clients, zero-loss policy) for the
  backends that did not drive the full 3 h TLS leg: Windows Mbed TLS, Windows
  GnuTLS and Linux Mbed TLS all reported `rx == sent`, loss 0.
- `stserver` build matrix: the server builds and serves with every backend on
  both platforms — Windows OpenSSL (MSVC) / Mbed TLS (MSVC) / GnuTLS
  (mingw-w64) and Linux OpenSSL / GnuTLS / Mbed TLS. Each combination was run
  through all four local transports (udp-ice, udpturn, tcpturn, tcp-ice) with
  `rx == sent`, loss 0. `stserver` itself terminates no TLS (its control plane is
  plaintext UDP/TCP like coturn's 3478), so the backend selection shows up only
  in what it links.
- 2 h local soak on both platforms (stice client + `stserver` on the same host,
  no cross-platform traffic), 8 clients x 512 KiB/s, 4 transports, 1740 s each:
  Windows/OpenSSL 7,054 s and Linux/GnuTLS 6,991 s, all modes 8/8 pass with
  `rx == sent` byte-for-byte, loss 0, and `stserver` reporting `drop=0`
  (7.30 GB per mode, ~29.2 GB per platform).
- 1 h local soak on both platforms, Mbed TLS only, 8 clients x 512 KiB/s,
  4 transports: Windows/Mbed TLS 3.6 (MSVC) 3,456 s and Linux/Mbed TLS 2.28
  3,393 s, all four modes 8/8 pass with `rx == sent`, loss 0.
- Re-validated after the post-review hardening above: `test_tls_transport`
  passes on all three backends on both platforms (19 assertions on
  OpenSSL/GnuTLS, 15 on Mbed TLS — the untrusted-peer case is skipped there for
  lack of a trust store), and a `turns` interop run against the local coturn
  (clients 2 x 256 KiB/s, 20 s) reports `rx == sent`, loss 0 on every backend.
- Full local ctest after the hardening: 17/17 on all six builds (Windows
  OpenSSL / Mbed TLS / GnuTLS and Linux OpenSSL / GnuTLS / Mbed TLS), excluding
  only the tests that need an externally started TURN server
  (`test_integration`, `test_libjuice_bench`, `test_stserver_*`) and the long
  soak. The OpenSSL cipher list was additionally checked against coturn with
  `openssl s_client`, which negotiated `ECDHE-RSA-AES256-GCM-SHA384` over TLS
  1.2 — i.e. `!kRSA` removed static RSA key exchange without touching the
  ECDHE-RSA suites.
- Re-run after review round 2: the same 17/17 on all six builds, plus a short
  4-mode soak (8 clients x 512 KiB/s, 40 s per mode) that exercises the changed
  close/hint paths — Windows/OpenSSL and Linux/GnuTLS both 4/4 with
  `rx == sent`, loss 0, and `stserver ... drop=0`. The new diagnostic was
  checked live: Windows + OpenSSL without `STICE_TLS_CA_FILE` now prints
  "no CA bundle loaded … set STICE_TLS_CA_FILE" *before* the generic
  "certificate verify failed" when connecting to coturn. The soak driver's new
  guard was exercised on Linux (`mode=turns` with no TLS endpoint exits 2 with
  an explanation).

## [0.12.4] - 2026-10-15

Negative packet loss elimination and backend hardening: the 4-mode soak
(udp-ice/udpturn/tcpturn/tcp-ice) is now byte-exact loss=0 on both Linux and
Windows, with the accelerated poll backends (epoll/IOCP) as platform defaults.

### Added

- **Native epoll event loop on Linux** for the stice client, unified with the
  Windows wepoll path behind one PollRegistry interface; the backend is
  selected per platform at compile time.

### Fixed

- **Negative packet loss on tcpturn (epoll backend)**: concurrent workers
  could drain the same TCP socket and enqueue out of order; recv+dispatch is
  now serialized per socket, restoring FIFO order of the RFC 6062 data pipe.
- **IOCP backend: one in-flight WSARecvFrom per socket** (completion identity
  guard + CancelIoEx on teardown); stserver now defaults to IocpBackend on
  Windows and EpollBackend on Linux (SelectBackend remains opt-in).
- **RFC 6062 §5.4: buffer pre-bind data-connection bytes.** Bytes arriving on
  the peer data connection before CONNECTION-BIND pairing are buffered
  (256 KiB cap, disconnect above it per §7) and flushed once paired, instead
  of being silently dropped (which lost ICE consent checks).
- **CONNECTION-BIND response ordering**: the response is sent before the data
  pipe is published, and post-bind leftover bytes are preserved.
- **Data-connection STUN frames stay inside the framed FIFO** so RFC 4571
  framing and STUN self-delimiting can never interleave out of order.
- **PollRegistry/participant lock-order inversion** that could wedge tcp-ice
  establishment (ABBA deadlock): the poll thread snapshots participants
  before calling getters without holding the registry lock.
- **TURN bookkeeping spin**: a past-due `nextTransmission` left behind by an
  empty `turn::Client::tick()` kept pollers at `timeout=0` (100% CPU spin on
  unreachable TURN servers); "nothing scheduled" now maps to `time_point::max()`.
- **stserver**: dispatch-queue sizes are read under the queue mutex; UDP
  sockets allow IP fragmentation (`IP_PMTUDISC_DONT`) to avoid PMTUD
  blackholes on relayed paths.

## [0.12.3] - 2026-10-13

Cross-machine TURN validation release: makes stserver usable from off-host
clients (relay address advertisement was loopback-bound), and clears the
platform-audit P1 findings.

### Added

- **stserver `relayAddress` config** (coturn `external-ip` equivalent): the IP
  advertised in XOR-RELAYED-ADDRESS, decoupled from the listener bind address.
  Precedence: explicit `relayAddress` > specific `listenAddress` > `127.0.0.1`
  fallback for any-address binds. Cross-machine deployments can now keep
  `listenAddress = 0.0.0.0` and set `relayAddress = <LAN IP>`.
- **Startup log prints the advertised relay IP**
  (`listening UDP ... relay=<ip> ...`) - the exact value an off-host client
  will receive, making this class of misconfiguration visible at a glance.
- Long-run driver accepts `-TurnHost`/`-TurnPort` (+ `-SkipServerStart`) so
  the 4-mode soak can be pointed at an external TURN server for interop runs.

### Fixed

- **RFC 6062 §4.3 CONNECT retry pacing (MUST)**: the client re-issues a failed
  CONNECT every 10 s (was 5 s) with `MaxConnectRetries` 3 -> 2, keeping the
  worst-case dead-pair budget at ~20 s. The previous 5 s spacing re-issued
  CONNECT faster than the RFC's client retry floor allows.
- **stserver config: UTF-8 BOM stripped before parsing.** A BOM-saved first
  line prefixed the first key's name and silently fell through to the
  unknown-key branch (logged only as WARN), leaving the server running on
  defaults while the file looked correct. This is what kept the VM test server
  advertising 127.0.0.1 despite a seemingly correct config.
- **`UdpSocket::recvfrom` uses platform macros only**: added `STICE_SENETRESET`
  and `STICE_SECONNREFUSED` to `platform.hpp`, dropped the `#ifdef _WIN32`
  around `WSAENETRESET`. Side fix: the Windows path now actually matches
  connection-refused (it previously compared against the CRT `ECONNREFUSED`,
  a different error domain from the WSA codes `recvfrom` reports).
- Platform audit triage (verified, no change needed): `udp.cpp` and
  `tcp_mux.cpp` `localAddrs()` already carry complete Linux `getifaddrs()`
  implementations; `mdns.cpp` already has a portable `poll()` receive branch
  and no Windows-only socket APIs; `CMakeLists.txt` IO backend selection is
  correct (select always available, IOCP/epoll compiled when
  `STICE_STSERVER_USE_SELECT=OFF` - the select default is deliberate, see the
  IOCP OVERLAPPED-lifetime notes).

### Known limitation (unchanged)

- Client-side `poll.cpp` keeps `poll()`/wepoll (O(n) fd scan). Acceptable at
  the 50-100 agent scale this release targets; an epoll backend remains a
  future optimization.

## [0.12.2] - 2026-10-13

First release verified by a full **3-hour, 4-transport soak**: 100 concurrent
clients x 10 MiB/s each (1 GiB/s aggregate) exchanging data for 44 minutes per
transport, with **byte-exact zero packet loss** (rx == sent) on `udp-ice`,
`udpturn`, `tcpturn` and `tcp-ice` - `PASS total_s=10762`. The run also drove the
remediation of every protocol/inspection finding raised since 0.12.1.

### Added

- **Long-term soak test**: `tests/test_longrun_4mode.cpp` plus the driver
  `regress/longtest_4mode_100x10mbs_3h.ps1`. One process per client, sustained
  rate-limited streaming, per-byte receiver verification, stall/setup watchdogs,
  and a stop-on-first-problem policy.
- **Unit tests**: `tests/test_mdns.cpp` (mDNS answer source filter),
  `tests/test_addr_util.cpp` (IPv4/IPv6 address helpers), and
  `tests/test_rfc_consent_pac.cpp` (RFC 7675 consent transaction IDs and RFC 8863
  Patiently Awaiting Connectivity) - the last two cover behaviour that had **no
  test coverage at all** before (the whole suite ran in unchanged wall time).

### Fixed - protocol MUSTs

- **RFC 7675 §5.1 (MUST)**: each consent binding request now carries a **new
  transaction ID**. A keepalive reused the entry that carried the last
  connectivity check, whose fresh ID had already been consumed, so every consent
  request replayed one ID - breaking the MUST, weakening replay protection, and
  letting a peer that de-duplicates on transaction ID drop the requests (consent
  then expires at 30 s).
- **RFC 8863 §4 (MUST)**: **Patiently Awaiting Connectivity** is now implemented.
  `IcePacTimeoutMs` was declared but never referenced, so a checklist with no
  pairs left to check while Running moved to Failed immediately, giving a
  peer-reflexive pair no chance to be discovered. The agent now waits one
  connectivity-check transaction timeout (39.5 s), cancels the wait as soon as
  any pair is still being attempted, and the poll timer is exposed to the PAC
  deadline so the transition still happens without other traffic.
- **RFC 7675 §5.1 (SHOULD)**: the consent period is randomized within
  [0.8, 1.2] x the 5 s basic period (**strictly 4-6 s**; previously the base was
  itself randomized 4-6 s and then jittered +/-1 s, giving 4-7 s and breaking the
  6 s bound). The idle backoff was reduced 15 s -> 10 s so at least three checks
  land in the 30 s consent window under loss.

### Fixed - data path

- **TURN nonce rotation (root cause of the 3 h `udpturn` failure)**. The server
  rotated its nonce on every request, producing a REFRESH -> 438 storm that ended
  in 100/100 clients failing with `stice_send rc=-2` at ~951 s. The nonce is now
  rotated only when it expires (anti-stampede, RFC 8656), and the client counts
  only **consecutive** nonce failures, so the budget is cleared on success.
- **TURN refresh storm**: in-flight guard (`refreshTidFresh_`) so the
  transaction timer owns retransmission and a tick cannot re-send a Refresh each
  period.
- **RFC 6062 TCP relay data plane**: relayed TCP data is forwarded by a parallel
  fast path on the IO thread instead of being pushed through the single business
  thread under the state mutex (which serialized every chunk). stserver TCP-relay
  throughput at 100 clients: **795 -> 1000 MiB/s**.
- **`stice_send` default path never took the lock-free fast path**: it passed a
  diffserv value of `0`, which failed the `ds < 0` test in the fast path and sent
  every packet down the double-locked slow path with a `setsockopt` per packet.
  It now passes `-1` ("do not touch TOS").
- **Pacing**: 8 KiB application chunks by default in the soak test - per-datagram
  cost, not bandwidth, is the loopback limit at 1200-byte MTU sized sends.

### Fixed - correctness / robustness

- **mDNS**: AAAA queries are actually sent (the comment claimed "both A and
  AAAA", the code only ever sent A), so IPv6 `.local` resolution works. The
  answer source filter now covers **IPv4 and IPv6** - rejecting `0.0.0.0`,
  `224.0.0.0/3` (multicast plus the reserved class E block, which contains the
  limited broadcast) and, for IPv6, `ff00::/8`, `::`, IPv4-mapped and the
  deprecated IPv4-compatible forms, with **unknown address families rejected
  instead of accepted** (any non-IPv4 family used to fall through).
- **ICE server URL parsing**: bracketed IPv6 is supported
  (`turn:[2001:db8::1]:3478`, the WebRTC convention - the `]` used to be left in
  the host so resolution failed) and a bare IPv6 literal no longer has its last
  group mistaken for a port (`turn:2001:db8::1` used to become host `2001:db8:`
  plus port 1).
- **`addrToString()`** brackets IPv6 (RFC 5952 §6 / RFC 3986 §3.2.2) and falls
  back to `inet_ntop()` when `getnameinfo()` refuses to render an address (a
  link-local IPv6 without a scope id used to collapse the whole string to empty,
  blanking every log line about that peer).
- **`addrEqual()` / `AddrRecord::hash()`** normalize IPv4-mapped IPv6 to the
  IPv4 address it embeds, so a dual-stack peer compares (and hashes) as the same
  peer - previously "equal" and "same hash" could disagree for container keys.
- **Interface whitelist/blacklist** are compared semantically (IP literals,
  zone id stripped) instead of by exact string, so `::1` vs `0:0:0:0:0:0:0:1`
  no longer silently fails to match.
- **`pendingServerReflexive_` could be driven negative** by a replayed/retransmitted
  Server-Reflexive response (the handler had no terminal-state guard, unlike
  `relayCounted`/`failedEmitted_`), which could stall gathering-complete.
- **A Failed check pair could be revived** by a late success response (now
  ignored once terminal).
- **`Message::isMessage()`** tolerates trailing bytes instead of rejecting a
  legal UDP datagram as "not STUN" and routing it to the application path.
- **TURN channel bindings are keyed by IP+port** while permissions stay IP-only
  (RFC 5766/8656 granularity), so same-IP/different-port peers can no longer
  share a channel and cross-talk. The permission-failure path now clears the
  pending data buffer instead of flushing stale data after recovery.
- **Teardown hang**: `LifetimeGuard::shutdown()` is a bounded drain (5 s, then
  ERROR + in-flight count) and the gather worker takes the agent lock with a
  bounded `try_lock` budget, removing the permanent "tearing down A" hang.
- **RFC 6062 CONNECT retry window**: `ConnectRetryDelayMs` 500 ms -> 5 s
  (3 attempts, >= 10 s total). A 1.5 s window was too short for the peer to
  finish its own allocation/permission/CONNECTION-ATTEMPT handling, so the first
  447 was already terminal and the relay pair failed although the peer became
  ready moments later. A flat 10 s was rejected because it would stretch the
  worst-case failure detection to 30 s, fighting the profile's fast-failure
  tuning.
- **Hot-path logging**: normal per-packet send/receive paths (`BINDING-OUT`,
  `ICE-STUN-IN`, `STUN-RESP`, `AGENT-RECV`, `TURN-SEND`, ...) dropped from WARN
  to DEBUG so WARN is reserved for anomalies; WARN-level production logging was
  a measurable hot-path cost and buried real alarms.

### Documentation

- **TCP-relay is not standard RFC 6062 - stated where it matters.** The CONNECT
  initiator is chosen by a stice/libjuice **ufrag comparison**, not by the
  candidate roles, and the server resolves the peer by scanning **its own**
  allocation table, so both peers must be allocated on the **same** stserver and
  an unallocated peer is answered with **403** where RFC 6062 §5.3.5 specifies
  447. Documented on `Agent::shouldInitiateTcpConnect()` and the stserver CONNECT
  section (single-server assumption, non-standard error mapping, no
  server-initiated dial).
- **`STICE_SDP_RADDR_HACK=0`** opts out of the libjuice `raddr 0.0.0.0 rport 0`
  Firefox-compatibility hack (RFC 8839 §5.1.1 wants the real base address, or no
  raddr/rport at all). Default remains compatible.

### Verification

- **3 h soak, 4 transports, zero loss** (this is the release's headline result):
  `udp-ice`, `udpturn`, `tcpturn`, `tcp-ice` each `pass=100 fail=0 loss=0
  agg_mibs=1000` (2.77 TB sent == 2.77 TB received per transport),
  `PASS total_s=10762`. Zero packet loss, zero client failures, no runaway RSS.
- Full Catch2 regression green: `test_stun` 1333/41, `test_turn` 637/52,
  `test_functional` 280/28, `test_pairing_strategy` 259/8, `test_performance`
  114/6, `test_candidate_pair` 66/26, `test_candidate` 61/23, `test_addr_util`
  49/5, `test_mdns` 98/9, `test_rfc_consent_pac` 23/2, `test_stress`,
  `wepoll_selftest`, `test_stserver_all` PASS.
- The soak binary predates the RFC 7675/8863, mDNS, URL and F4 changes (those
  landed after the soak started); they are covered by the new unit tests plus the
  full regression, and a fresh 3 h soak on the consolidated build is the next
  step.

## [0.12.1] - 2026-10-12

100/200 concurrent `udpturn` big-data clients with **zero packet loss**, with
the stserver relay CPU cut by roughly two thirds. The loss was NOT caused by the
relay logic but by CPU starvation of the single-threaded data-plane entry point,
aggravated by per-packet logging work. This release also fixes a genuine
data race on the allocation channel/permission tables and an unbounded teardown
join that made `stice_destroy` hang forever.

### Fixed (client)

- **`stice_destroy()` could hang forever.** `Agent::~Agent()` joined the gather
  worker thread **unbounded**; whenever that worker got stuck, teardown never
  returned (reproduced on `tcp-ice`/`tcpturn`: the process stayed alive past
  50 s while its own agent threads kept running — a TURN Refresh fired 36 s into
  the "destroy"). The join is now bounded (`GatherWorkerJoinTimeoutMs`), the
  worker is cooperatively cancellable, and the cancel/done flags are
  `shared_ptr`s handed to the worker **by value** so they remain valid even if a
  wedged worker must be detached. On timeout an ERROR is logged and the worker
  is detached — safe because the DNS phase runs on detached resolver threads
  that capture only by-value copies and never touch the Agent, and the
  entry-building phase is short, non-blocking and re-checks cancellation before
  every item.
- **The gather worker's DNS phase was unbounded.** It collected `std::async`
  results with a blocking `f.get()` (and `std::future`'s destructor also blocks),
  so an unresponsive resolver could pin the worker — and therefore
  `stice_destroy` — indefinitely; `getaddrinfo` has no timeout of its own. Each
  item is now resolved on a detached thread writing into its own heap slot, and
  the worker waits at most `GatherDnsTimeoutMs` before abandoning stragglers.
- **Misleading `GATHER: gatherStartedAt_ was NOT SET (gatherCandidates likely
  never ran)` error.** The bookkeeping tick seeded `gatherStartedAt_` whenever it
  happened to fire *before* `gatherCandidates()`, which logged an alarming ERROR
  (and started the soft-gather deadline early) on agents that simply had not
  gathered yet. Seeding is now gated on `state_ == STICE_STATE_GATHERING` — i.e.
  reachable only when gathering really is in progress.
- **P0 data race: `Allocation::mtx` was held by the readers only.** The IO
  fast path (`handleChannelDataFrame` / `forwardToClient`, on reader threads)
  traverses `Allocation::channels` / `Allocation::permissions` under
  `alloc->mtx`, but every writer — `handleCreatePermission`, `handleChannelBind`,
  `expireStale`'s per-allocation cleanup and `handleSendIndication`'s permission
  scan — mutated them **without** it. Since the fast path never takes
  `stateMutex_`, `stateMutex_` alone could not serialize against it: a concurrent
  write-vs-traverse of the same `std::vector` (UB, iterator invalidation). All
  writers now take `alloc->mtx`; lock order is `stateMutex_ -> alloc->mtx`, and
  `destroyAllocation()` is never called while holding it.

### Performance (stserver relay data plane)

- **Lazy logging macros** (`log.hpp`/`log.cpp`): `STICE_LOG_*` now tests the
  level *before* evaluating its arguments, and the level is read lock-freely
  (`Logger::shouldLog`). Previously every `STICE_LOG_*` argument was built
  unconditionally and `log()` took a global mutex. Hot-path arguments such as
  `AddrRecord::toString()` call `getnameinfo()`, so the relay paid two
  `getnameinfo()` syscalls + string allocations **per relayed datagram** even at
  the default WARN level. The same fix removes the identical cost from the client
  ICE send/recv paths.
- **UDP-listener reader pool** (`io_select.cpp`): the shared UDP listener is the
  single funnel for every client's ChannelData; with one reader it could not
  drain fast enough and silently dropped ~9-22% of datagrams under 50-200-way
  concurrency. The listener is now drained by a small pool of reader threads
  (default `min(8, workerCount)`, overridable with `STSERVER_UDP_READERS`).
  Concurrent `recvfrom()` on one UDP socket is supported and `ioOnUdpData()` is
  thread-safe. The control thread no longer touches the listener, so a saturated
  data plane cannot starve TCP accept/the timer.
- **Local-relay hairpin shortcut** (`turn_server.cpp`): when a relaying client's
  peer address is one of *this* server's own relayed addresses, the datagram is
  delivered straight to the destination allocation instead of being sent out and
  received back through the kernel loopback — removing two of the four syscalls
  the relay performed per frame. Both TURN authorization checks are preserved
  (sender channel binding + destination channel/permission). Disable with
  `STICE_TURN_NO_LOCAL_SHORTCUT=1`. Measured at 200 concurrent clients x 10 MiB:
  server CPU 209 s -> 77 s (with the further io_select fixes below: 51 s), wall
  40.0 s -> 23.0 s, still zero loss.
- **64 MiB socket buffers** for the listener and relay sockets (was 4/16 MiB) so
  the initial burst of many simultaneously-starting clients is absorbed.
- Hot diagnostic counters are cache-line padded and use `memory_order_relaxed`
  (`relayReadBytes_`, `forwardBytes_`, ...), removing false sharing between the
  relay worker threads.
- **TCP data path no longer contends on `stateMutex_`**: `connIsDataSock()` is
  consulted per inbound TCP packet by the IO thread, while `stateMutex_` is held
  by the business thread for the whole duration of each item. The data-pipe
  classification now lives in a dedicated tiny map/mutex (`dataConns_`).
- The **business (control-plane) thread is raised to the same priority** as the
  IO threads, so the boosted data plane cannot starve
  Allocate/Refresh/ChannelBind.

### Fixed (stserver)

- **`FD_SETSIZE` was only raised in `turn_server.cpp`/`main.cpp`.** `#define` is
  per translation unit, so `io_select.cpp` still built 64-slot `fd_set`s and the
  select backend's real per-worker socket limit was an undocumented 63 — past
  which `FD_SET` (which bounds-checks) *silently ignores* extra sockets, turning
  those allocations into one-way black holes with no other symptom.
  `io_select.cpp` now raises it locally and CMake defines it for every stserver
  TU; the effective cap is logged at startup and a loud ERROR is emitted when a
  worker's set is full.
- `FD_SET` of an invalid (failed-creation) interrupt socket is skipped instead of
  poisoning `select()` with `WSAENOTSOCK` and killing the worker.
- `acceptTcp()` backs off on fd/table exhaustion instead of spinning the control
  thread at 100% while the backlog keeps the listener readable.
- The UDP reader pool no longer creates an interrupt socket that nothing ever
  wakes.
- `addRelaySocket()`/`addTcpConn()` reject calls made before `start()` instead of
  indexing an empty worker vector.
- The TCP worker re-checks socket ownership before `recv`, mirroring the relay
  worker's fd-reuse guard.
- `expireStale()`: the orphaned-relay-port sweep was nested **inside** the
  allocation loop, making it O(allocations x ports) every 50 ms tick (and reading
  as an independent loop because of misleading indentation). It now runs once per
  tick, after the allocation sweep.
- `sendMutex_` usage was inconsistent: `sendUdp()` took it while
  `forwardToClient()`'s ChanUdp/PermUdp paths sent on the same `udpListener_`
  without it. The mutex implied protection it did not provide and only
  serialized control responses against the data plane; it is removed (Winsock
  `sendto` on a UDP socket is thread-safe, which the data plane already relied
  on).
- `destroyAllocation()`'s wait for in-flight IO references
  (`Allocation::ioUsers_`) was an unbounded `yield()` spin that could wedge the
  business thread (and thus the whole control plane) if an IO worker stalled. It
  is now event-driven (condition variable), signals only when a waiter is present
  so the per-packet `allocUnref()` stays a single atomic op, and logs an error
  each second if an IO worker really is stuck. It deliberately does not "give up"
  and free anyway — that would be a use-after-free.
- Hot-path logging that formatted `toString()`/`addrPort()` **while holding the
  per-allocation lock** was moved outside the critical section.
- Removed the per-packet `ctlHandleNs_` DIAG timing (two `steady_clock::now()`
  per ChannelData frame) and its `ctlH=` RELAY-STAT column.
- `PollRegistry`'s pool grew its threads eagerly to `hardware_concurrency()` per
  process; it now grows lazily, so a process hosting few agents runs few poll
  threads. With 100-200 client *processes* the eager sizing created ~12 idle poll
  threads each (~1200-2400 threads total) whose scheduling pressure starved the
  server thread.

### Tests

- `test_agent_4mode_bigdata`: added `--spawn N --spawn-out <dir>` (fork N aligned
  clients via `CreateProcess` and aggregate), `--start-at <epoch_ms>` (wall-clock
  start barrier) and `--out-file <path>`. Launching 100-200 clients from a shell
  is serialized and slow (~0.5-0.7 s each), which made the clients run almost
  sequentially and silently under-tested the relay (measured: only 1 of 200 was
  receiving at the window midpoint).
- `test_agent_4mode_bigdata` also got unbuffered stdout and `[phase]` progress
  markers, so a run that has to be killed still reports how far it got (buffered
  output was lost on kill, which is why the teardown wedge was previously
  undiagnosable). Its gather wait now exceeds stice's internal soft-gathering
  fallback (`GatherTimeoutMs` = 15 s) so the test no longer tears down in the
  middle of a legitimately slow gather.

## [0.12.0] - 2026-10-11

### Fixed (Windows select-backend 100x10MB udpturn 2h long-test stability)
- **stserver relay socket now binds the advertised relayed address (relayIp_)**
  instead of INADDR_ANY. Under 0.0.0.0/:: listeners the relayed address is the
  loopback 127.0.0.1; binding the relay socket to 0.0.0.0 let the loopback stack
  mis-deliver UDP to sibling sockets under concurrent allocations (cross-talk),
  causing intermittent one-way data-path black holes and server crashes.
- **TURN client `handleChannelData` falls back to the sole binding when the
  incoming channel number is not in the local table.** RFC 8656 channel numbers
  are assigned per sending client; in ICE-over-TURN each peer picks its own
  channel, so the receiving client cannot look up the peer's channel. Falling
  back to the unique binding (per-agent single-peer ICE) restores one-way data.
- **stserver SEH crash dump** (`stserver_crash.txt`) to localize Windows
  access violations on long runs.
- Lowered `allocationLifetime` default to 60s to bound orphaned allocation
  residue after hard-killed clients (fixes intermittent 437 Allocation
  Mismatch on OS port reuse).
- SelectBackend worker startup data race (two-phase vector fill before thread
  spawn, atomic running flags), fd-reuse guards, interrupt-driven snapshot
  invalidation; client-side poll generation/sync hardening and loopback
  self-loop defenses (from the earlier TSan/ASan audit).

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.11.3] - 2026-10-10

### Fixed
- RFC 6062 (TURN-over-TCP): defer the data-connection CONNECT until the local
  CreatePermission for the peer completes (pion-mode). Mirrors pion's
  createPermission-before-Connect so the TURN server has the permission it
  needs to forward CONNECTION-ATTEMPT (RFC 6062 §4.4), eliminating the race
  where coturn returns CONNECT success but never forwards the ATTEMPT because
  the permission was not yet installed. VM coturn tcpturn: 100/100 pass (was
  ~1-4.4% intermittent failures).
- udp-ice/udpturn send path: snapshot destination / framed ChannelData under
  the ICE lock and perform the socket write outside it (mirrors libjuice's
  independent send_mutex), removing lock contention between the send loop and
  the poll thread.
## [0.11.2] - 2026-10-09

### Added
- TCP/TLS TURN multi-server support: per-relay TURN TCP transport, STUN
  connection, and data connection instead of single-instance members (A1).
  RFC 6062 data connection inherits the control connection's TLS settings (B2).
- Control-frame priority queue (`TcpTransport::sendControl`): STUN connectivity
  checks and TURN Refresh / CreatePermission / ChannelBind / CONNECTION-BIND
  are flushed ahead of bulk application data, eliminating head-of-line blocking
  where a saturated stream starved protocol keepalives (9s+ Binding RTT and
  "connection lost state=4" under 100 MiB floods).

### Fixed
- Windows `tcp-ice`: a corrupted `TcpTransport::send()` (probe leftover made it
  return `false` unconditionally) broke every ICE-TCP write; the correct state
  guard is restored. Smoke: udp-ice / tcp-ice 1 MiB PASS.
- Windows PollRegistry: `WSAPoll` returned `WSANOTINITIALISED` (10093) under
  connection floods because the file-scope `WSAStartup` static could be elided;
  the PollRegistry ctor now calls `WSAStartup` explicitly (idempotent).
- A2: dangling `turnTcpEntry_` after `entries_.erase()` replaced by a lookup
  (`findTcpTurnEntry`); StunEntry lifetime is now stable.
- B1: no application-layer retransmission of the same transaction over reliable
  TCP/TLS transports (RFC 8656 §7); only the failure timeout applies.
- C1: `pendingRelayAllocations_` double-decrement when a relay entry's TCP
  connection drops after a successful Allocate is prevented by a per-entry
  `relayCounted` flag (at-most-once accounting).
- C2: deallocate now transitions to a terminal `AllocState::Deallocated`;
  refresh/retransmission stop instead of resurrecting a destroyed allocation.
- D1: `PeerBinding.pendingData` bounded (512 packets); excess drops oldest with
  backpressure instead of unbounded growth.
- D2: `TcpTransport::sendQueue_` bounded at a 16 MiB high watermark; exceeding
  it propagates EAGAIN-like backpressure to the application (aligned with UDP).
- E1: TLS handshake on `WANT_WRITE` now registers POLLOUT (was stuck waiting for
  a POLLOUT that never arrived until connect timeout).
- F1: frame length fields guarded against >0xFFFF truncation (reject oversized
  writes instead of silent corruption).
- F2: 438 Stale Nonce retries now converge under a unified limit for
  refresh/permission/channelbind, not only Allocate.
- F3: ChannelData channel-number range comment corrected (0x4000..0x7FFF).

### Changed
- Bump version to 0.11.2.
## [0.11.1] - 2026-10-08

### Fixed
- RFC 6062 TURN-over-TCP: fix intermittent data-connection (CONNECTION-BIND)
  failures against coturn. coturn can close the data TCP connection before the
  peer's CREATE_PERMISSION is processed
  ("tcp_peer_accept_connection: peer has no permission to connect"), leaving
  the old connectionId/pending dead. On an unbound data-connection loss the
  agent now re-issues CONNECT to obtain a fresh connectionId + pending before
  retrying the data connection (agent.hpp / agent.cpp), eliminating intermittent
  tcpturn connect failures. Verified: VM four-mode 100MB long-run 976 PASS / 0 FAIL
  (~40 min), Windows tcpturn 8/8, VM tcpturn 10/10.

### Changed
- Bump version to 0.11.1.
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
