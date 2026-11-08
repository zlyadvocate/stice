/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// ICE pairing-strategy implementation: preset profile factory.

#include "stice/ice/pairing_strategy.hpp"

namespace stice::ice {

IcePairingConfig makeIcePairingConfig(IcePairingProfile profile) {
	IcePairingConfig c;
	switch (profile) {
	case IcePairingProfile::RFC8445_COMPAT:
		// Standard RFC 8445 behavior: regular nomination (§8.1.1 removed
		// aggressive nomination), Ta=50 ms check pacing (§14.2) and the
		// §14.3 RTO-N retransmission formula. Full concurrency, eager
		// TCP-relay so all candidates compete in the first wave, standard
		// reselection.
		c.schedule_mode = IceCheckScheduleMode::RFC8445_STRICT;
		c.max_concurrent_check = 0; // unlimited
		c.udp_phase_timeout = std::chrono::milliseconds(0);
		c.nomination_mode = IceNominationMode::REGULAR;
		c.tcp_nomination_precheck = std::chrono::milliseconds(0);
		c.tcp_relay_fallback = TcpRelayFallbackMode::ALWAYS_ENABLE;
		c.reselect_policy = LinkReselectPolicy::RFC8445;
		c.rto_initial = std::chrono::milliseconds(500);
		// Rc=7: RFC 5389 §7.2.1 default retransmission count (31.5 s budget).
		c.max_check_retransmit = 7;
		c.ta = std::chrono::milliseconds(50);
		c.use_rfc8445_rto = true;
		c.keepalive_udp = std::chrono::milliseconds(5000);
		c.keepalive_tcp_relay = std::chrono::milliseconds(10000);
		// Standard behavior: no early-phase boost, trickle enabled.
		c.enable_trickle = true;
		c.pre_allocate_tcp_relay = true; // ALWAYS_ENABLE implies eager allocation
		c.early_phase_max_concurrent = 0; // disabled (RFC8445_STRICT is already unlimited)
		c.early_phase_duration = std::chrono::milliseconds(0);
		break;
	case IcePairingProfile::EMBEDDED_STABLE:
		// Product default for AX620E. UDP-first phased scheduling,
		// stable-check nomination for TCP-relay, lazy Mode-B
		// allocation, sticky reselection. Speed optimizations:
		// early-phase concurrency boost (3 for first 1200ms then
		// fall back to 2), tightened RTO/retransmit for faster pair
		// failure detection.
		c.schedule_mode = IceCheckScheduleMode::PHASED_UDP_FIRST;
		c.max_concurrent_check = 2;
		c.udp_phase_timeout = std::chrono::milliseconds(3000);
		c.nomination_mode = IceNominationMode::REGULAR_STABLE_CHECK;
		c.tcp_nomination_precheck = std::chrono::milliseconds(500);
		c.tcp_relay_fallback = TcpRelayFallbackMode::ON_ALL_UDP_FAIL;
		c.reselect_policy = LinkReselectPolicy::STICKY_SELECTED;
		c.rto_initial = std::chrono::milliseconds(500);
		c.max_check_retransmit = 3;
		c.ta = std::chrono::milliseconds(50); // §14.2 default pacing
		c.use_rfc8445_rto = false;           // tuned fixed RTO for fast failure
		c.keepalive_udp = std::chrono::milliseconds(5000);
		c.keepalive_tcp_relay = std::chrono::milliseconds(5000);
		c.enable_trickle = true;
		c.pre_allocate_tcp_relay = false; // lazy: conserve coturn TCP resources
		c.early_phase_max_concurrent = 3; // boost during early window
		c.early_phase_duration = std::chrono::milliseconds(1200);
		break;
	case IcePairingProfile::DEBUG_FAST:
		// Local debug: fast setup. TCP-relay candidates participate in
		// the first wave, aggressive nomination, standard reselection.
		// Pre-allocate Mode-B so the relayed TCP endpoint is ready
		// immediately.
		c.schedule_mode = IceCheckScheduleMode::LIMITED_CONCURRENT;
		c.max_concurrent_check = 4;
		c.udp_phase_timeout = std::chrono::milliseconds(0);
		c.nomination_mode = IceNominationMode::AGGRESSIVE;
		c.tcp_nomination_precheck = std::chrono::milliseconds(0);
		c.tcp_relay_fallback = TcpRelayFallbackMode::ALWAYS_ENABLE;
		c.reselect_policy = LinkReselectPolicy::RFC8445;
		c.rto_initial = std::chrono::milliseconds(500); // >= RFC 5389 min RTO; 400ms too aggressive under load
		c.max_check_retransmit = 3;
		c.ta = std::chrono::milliseconds(50);
		c.use_rfc8445_rto = false;
		c.keepalive_udp = std::chrono::milliseconds(5000);
		c.keepalive_tcp_relay = std::chrono::milliseconds(4000);
		c.enable_trickle = true;
		c.pre_allocate_tcp_relay = true; // speed priority
		c.early_phase_max_concurrent = 4;
		c.early_phase_duration = std::chrono::milliseconds(1500);
		break;
	case IcePairingProfile::MINIMAL_RESOURCE:
		// Extreme resource-constrained MCU. Serial checks, regular
		// nomination, lazy TCP-relay, sticky reselection. No early-
		// phase boost (concurrency stays at 1 to minimize traffic).
		c.schedule_mode = IceCheckScheduleMode::SERIAL;
		c.max_concurrent_check = 1;
		c.udp_phase_timeout = std::chrono::milliseconds(5000);
		c.nomination_mode = IceNominationMode::REGULAR;
		c.tcp_nomination_precheck = std::chrono::milliseconds(0);
		c.tcp_relay_fallback = TcpRelayFallbackMode::ON_ALL_UDP_FAIL;
		c.reselect_policy = LinkReselectPolicy::STICKY_SELECTED;
		c.rto_initial = std::chrono::milliseconds(1000);
		c.max_check_retransmit = 5;
		c.ta = std::chrono::milliseconds(50);
		c.use_rfc8445_rto = false;
		c.keepalive_udp = std::chrono::milliseconds(5000);
		c.keepalive_tcp_relay = std::chrono::milliseconds(8000);
		c.enable_trickle = false; // minimize signaling traffic
		c.pre_allocate_tcp_relay = false;
		c.early_phase_max_concurrent = 0; // disabled
		c.early_phase_duration = std::chrono::milliseconds(0);
		break;
	}
	return c;
}

} // namespace stice::ice
