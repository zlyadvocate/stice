# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
