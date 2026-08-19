// SPDX-License-Identifier: MPL-2.0
// ICE pairing-strategy layer.
//
// Encapsulates the four orthogonal dimensions of pair scheduling,
// nomination, RFC 6062 TCP-relay fallback, and link reselection so the
// upper application can switch behavior profiles without touching the
// scheduler source. All strategy switches only alter *local* behavior
// (which pair to arm, when to send USE-CANDIDATE, when to create a
// Mode-B allocation, which valid pair to reselect); the wire protocol,
// pair-priority formula, and candidate gathering are unchanged, so
// interoperability with standard WebRTC peers (browsers, pion, etc.)
// is preserved.
//
// See docs/pairing-strategy.md for the full rationale.

#ifndef STICE_ICE_PAIRING_STRATEGY_HPP
#define STICE_ICE_PAIRING_STRATEGY_HPP

#include <chrono>
#include <cstddef>
#include <cstdint>

namespace stice::ice {

// ---------------------------------------------------------------------------
// Check-List scheduling mode.
// ---------------------------------------------------------------------------
enum class IceCheckScheduleMode {
	// RFC 8445 standard behavior: all pairs are checked in priority order
	// with as much concurrency as the implementation allows. Used to match
	// pion-ice for interop regression.
	RFC8445_STRICT,
	// str0m-style: strictly one pair at a time. Lowest STUN traffic;
	// slowest setup. Suitable for extremely resource-constrained MCUs.
	SERIAL,
	// Limited concurrency (optimized default): at most max_concurrent_check
	// pairs are InProgress simultaneously.
	LIMITED_CONCURRENT,
	// Phased: UDP pairs are checked first. TCP-relay pairs are added to the
	// check-list but NOT armed until the UDP phase expires (udp_phase_timeout)
	// or every UDP pair has failed. Tailored for embedded devices that want
	// to avoid TCP-relay overhead unless UDP is unavailable.
	PHASED_UDP_FIRST,
};

// ---------------------------------------------------------------------------
// Nomination mode.
// ---------------------------------------------------------------------------
enum class IceNominationMode {
	// pion/Chrome style: every connectivity check carries USE-CANDIDATE.
	AGGRESSIVE,
	// str0m/RFC 8445 classic: a valid pair is selected first, then a
	// separate USE-CANDIDATE check is sent.
	REGULAR,
	// Improved Regular: TCP-relay pairs undergo a short stability precheck
	// (tcp_nomination_precheck) before USE-CANDIDATE is sent, to avoid
	// nominating a flaky Mode-B link. UDP pairs behave as REGULAR.
	REGULAR_STABLE_CHECK,
};

// ---------------------------------------------------------------------------
// RFC 6062 TCP-relay fallback policy.
// ---------------------------------------------------------------------------
enum class TcpRelayFallbackMode {
	// Disable RFC 6062 TCP allocations entirely; only UDP is used.
	DISABLE,
	// Default: create a Mode-B allocation only after all UDP pairs fail
	// (or the UDP phase of PHASED_UDP_FIRST times out). Conserves TURN
	// TCP resources.
	ON_ALL_UDP_FAIL,
	// Debug: create the Mode-B allocation eagerly at gather time so
	// TCP-relay candidates participate in the first check wave.
	ALWAYS_ENABLE,
};

// ---------------------------------------------------------------------------
// Link reselection policy (after the selected/nominated pair fails).
// ---------------------------------------------------------------------------
enum class LinkReselectPolicy {
	// RFC 8445: pick the highest-priority pair from the valid list,
	// regardless of transport. UDP may reclaim a TCP-relay link.
	RFC8445,
	// Embedded optimization: once a TCP-relay link is selected, prefer
	// remaining TCP-relay pairs on reselection; only fall back to UDP
	// when every TCP-relay pair has failed. A full re-evaluation of all
	// candidates happens only on ICE-Restart.
	STICKY_SELECTED,
};

// ---------------------------------------------------------------------------
// Pairing configuration.
// ---------------------------------------------------------------------------
// All durations are in milliseconds. Defaults match the EMBEDDED_STABLE
// profile; use makeIcePairingConfig() to obtain a preset.
struct IcePairingConfig {
	// --- Check scheduling ---
	IceCheckScheduleMode schedule_mode{IceCheckScheduleMode::PHASED_UDP_FIRST};
	// LIMITED_CONCURRENT: maximum simultaneously InProgress checks.
	// 0 means unlimited (RFC8445_STRICT semantics).
	std::size_t max_concurrent_check{2};
	// PHASED_UDP_FIRST: how long the UDP phase lasts before TCP pairs
	// are armed. 0 means "wait until all UDP pairs fail".
	std::chrono::milliseconds udp_phase_timeout{3000};

	// --- Nomination ---
	IceNominationMode nomination_mode{IceNominationMode::REGULAR_STABLE_CHECK};
	// REGULAR_STABLE_CHECK: stability precheck duration before nominating
	// a TCP-relay pair.
	std::chrono::milliseconds tcp_nomination_precheck{500};

	// --- RFC 6062 TCP-relay ---
	TcpRelayFallbackMode tcp_relay_fallback{TcpRelayFallbackMode::ON_ALL_UDP_FAIL};

	// --- Link reselection ---
	LinkReselectPolicy reselect_policy{LinkReselectPolicy::STICKY_SELECTED};

	// --- Timeout / keepalive tuning ---
	// These values are honored by the Agent (replacing the compiled-in
	// defaults) when set via setPairingConfig before gatherCandidates.
	std::chrono::milliseconds rto_initial{600};
	int max_check_retransmit{4};
	std::chrono::milliseconds keepalive_udp{10000};
	std::chrono::milliseconds keepalive_tcp_relay{5000};

	// --- Speed optimization (local behavior only) ---
	// Trickle-ICE: push each local candidate to the application as soon as
	// it is gathered, instead of waiting for gathering to complete. The
	// application is responsible for reliable signaling of trickle
	// candidates; disable on lossy signaling paths.
	bool enable_trickle{true};
	// RFC 6062 Mode-B pre-allocation: when true, start the TCP-relay
	// Allocate in the background during the UDP phase (parallel with UDP
	// connectivity checks) so the relayed TCP endpoint is already
	// available when UDP fails. Trades coturn TCP listen-socket
	// resources for faster fallback. Default false (lazy allocation).
	bool pre_allocate_tcp_relay{false};
	// Early-phase dynamic concurrency: during the first
	// early_phase_duration of the checking phase, allow up to
	// early_phase_max_concurrent simultaneous InProgress checks
	// (overriding max_concurrent_check). After the window elapses the
	// concurrency falls back to max_concurrent_check to suppress STUN
	// storms on embedded CPUs. Set early_phase_max_concurrent=0 (or
	// equal to max_concurrent_check) to disable.
	std::size_t early_phase_max_concurrent{3};
	std::chrono::milliseconds early_phase_duration{1200};

	// --- Internal state (not user-configurable) ---
	// Timestamp (steady_clock) when the UDP phase started. Set by the
	// Agent when PHASED_UDP_FIRST begins arming UDP pairs.
	std::chrono::steady_clock::time_point udp_phase_start{};
	// Whether the TCP phase has been entered (PHASED_UDP_FIRST only).
	bool tcp_phase_entered{false};
	// Whether a Mode-B allocation has been requested for this session.
	bool tcp_relay_allocation_created{false};
	// Timestamp (steady_clock) when the checking phase started. Set by
	// the Agent on transition to CONNECTING; used for early-phase
	// concurrency and nomination acceptance-min-wait calculations.
	std::chrono::steady_clock::time_point checking_start{};
	// Whether the early-phase concurrency window is still active.
	bool early_phase_active{false};
};

// ---------------------------------------------------------------------------
// Preset profiles.
// ---------------------------------------------------------------------------
enum class IcePairingProfile {
	// Standard RFC 8445 behavior aligned with pion-ice; for interop
	// regression testing.
	RFC8445_COMPAT,
	// Product default for AX620E embedded devices: UDP-first, sticky
	// TCP-relay, stable-check nomination.
	EMBEDDED_STABLE,
	// Debug: fast setup, TCP-relay participates in the first wave.
	DEBUG_FAST,
	// Extreme resource-constrained: serial checks, minimal traffic.
	MINIMAL_RESOURCE,
};

// Build a config from a preset profile. The returned struct can be
// further customized before being applied to the Agent.
IcePairingConfig makeIcePairingConfig(IcePairingProfile profile);

// Convenience predicates used by the Agent. Defined inline for hot-path
// callers; the Agent still owns the decision of *when* to call them.
inline bool scheduleArmsTcp(const IcePairingConfig &c) {
	return c.schedule_mode != IceCheckScheduleMode::PHASED_UDP_FIRST ||
	       c.tcp_phase_entered;
}

inline bool nominationIsAggressive(const IcePairingConfig &c) {
	return c.nomination_mode == IceNominationMode::AGGRESSIVE;
}

} // namespace stice::ice

#endif // STICE_ICE_PAIRING_STRATEGY_HPP
