// SPDX-License-Identifier: MPL-2.0
// Unit + integration tests for the stice ICE pairing-strategy layer.
//
// Covers:
//   - Preset profile factory (makeIcePairingConfig) for all 4 profiles.
//   - Inline predicate helpers (scheduleArmsTcp, nominationIsAggressive).
//   - C API config factory (stice_make_pairing_config) and round-trip
//     conversion (stice_set_pairing_config -> Agent::pairingConfig()).
//   - Integration: UDP loopback connectivity is preserved when each profile
//     is applied before gather (no TURN server needed — only host UDP
//     candidates are gathered, so PHASED_UDP_FIRST never enters the TCP
//     phase and the session connects normally).
//   - Integration: profile hot-update via setPairingConfig is accepted on a
//     running agent and reflected by pairingConfig().

#include <catch2/catch_all.hpp>

#include "stice/stice.h"
#include "stice/ice/agent.hpp"
#include "stice/ice/pairing_strategy.hpp"
#include "stice/log.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace stice;
using namespace stice::ice;

namespace {

// Per-test state shared between the two agents (mirrors test_integration.cpp).
struct AgentState {
	std::atomic<stice_state_t> state{STICE_STATE_DISCONNECTED};
	std::vector<std::string> candidates;
	std::atomic<bool> gatheringDone{false};
	std::vector<std::string> received;
	std::mutex candidatesMutex;
	std::mutex receivedMutex;
};

stice_config_t makeConfig(AgentState &s) {
	stice_config_t cfg{};
	cfg.cb_state_changed = [](stice_agent_t *, stice_state_t state, void *user_ptr) {
		auto *s = static_cast<AgentState *>(user_ptr);
		s->state.store(state);
	};
	cfg.cb_candidate = [](stice_agent_t *, const char *cand, void *user_ptr) {
		auto *s = static_cast<AgentState *>(user_ptr);
		std::lock_guard<std::mutex> lk(s->candidatesMutex);
		s->candidates.emplace_back(cand);
	};
	cfg.cb_gathering_done = [](stice_agent_t *, void *user_ptr) {
		auto *s = static_cast<AgentState *>(user_ptr);
		s->gatheringDone.store(true);
	};
	cfg.cb_recv = [](stice_agent_t *, const char *data, size_t size, void *user_ptr) {
		auto *s = static_cast<AgentState *>(user_ptr);
		std::lock_guard<std::mutex> lk(s->receivedMutex);
		s->received.emplace_back(data, size);
	};
	cfg.user_ptr = &s;
	cfg.bind_address = nullptr;
	cfg.local_port_range_begin = 0;
	cfg.local_port_range_end = 0;
	return cfg;
}

bool waitFor(std::function<bool()> cond, int timeoutMs) {
	auto start = std::chrono::steady_clock::now();
	while (true) {
		if (cond()) return true;
		auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
		    std::chrono::steady_clock::now() - start);
		if (elapsed.count() >= timeoutMs) return false;
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
}

void trickleExchange(stice_agent_t *a, AgentState &sa, stice_agent_t *b, AgentState &sb) {
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 3000));
	char bufA[4096], bufB[4096];
	REQUIRE(stice_get_local_description(a, bufA, sizeof(bufA)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b, bufB, sizeof(bufB)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(a, bufB) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(b, bufA) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);
}

} // namespace

// ---------------------------------------------------------------------------
// Profile factory: each preset must produce the documented field values.
// ---------------------------------------------------------------------------
TEST_CASE("Pairing profile factory produces expected configs", "[pairing][profile]") {
	SECTION("RFC8445_COMPAT mirrors pion-ice") {
		auto c = makeIcePairingConfig(IcePairingProfile::RFC8445_COMPAT);
		REQUIRE(c.schedule_mode == IceCheckScheduleMode::RFC8445_STRICT);
		REQUIRE(c.nomination_mode == IceNominationMode::AGGRESSIVE);
		REQUIRE(c.tcp_relay_fallback == TcpRelayFallbackMode::ALWAYS_ENABLE);
		REQUIRE(c.reselect_policy == LinkReselectPolicy::RFC8445);
		// max_concurrent_check == 0 means unlimited under RFC8445_STRICT.
		REQUIRE(c.max_concurrent_check == 0);
		// Speed optimization fields: eager pre-alignment, no early-phase
		// boost (RFC8445_STRICT is already unlimited).
		REQUIRE(c.enable_trickle == true);
		REQUIRE(c.pre_allocate_tcp_relay == true);
		REQUIRE(c.early_phase_max_concurrent == 0);
		REQUIRE(c.early_phase_duration.count() == 0);
	}

	SECTION("EMBEDDED_STABLE is the product default") {
		auto c = makeIcePairingConfig(IcePairingProfile::EMBEDDED_STABLE);
		REQUIRE(c.schedule_mode == IceCheckScheduleMode::PHASED_UDP_FIRST);
		REQUIRE(c.nomination_mode == IceNominationMode::REGULAR_STABLE_CHECK);
		REQUIRE(c.tcp_relay_fallback == TcpRelayFallbackMode::ON_ALL_UDP_FAIL);
		REQUIRE(c.reselect_policy == LinkReselectPolicy::STICKY_SELECTED);
		REQUIRE(c.max_concurrent_check == 2);
		REQUIRE(c.udp_phase_timeout.count() == 3000);
		REQUIRE(c.tcp_nomination_precheck.count() == 500);
		REQUIRE(c.keepalive_udp.count() == 10000);
		REQUIRE(c.keepalive_tcp_relay.count() == 5000);
		// Speed optimization: tightened RTO/retransmit for faster pair
		// failure detection; early-phase concurrency boost (3 for first
		// 1200ms, then fall back to 2); lazy Mode-B allocation.
		REQUIRE(c.rto_initial.count() == 500);
		REQUIRE(c.max_check_retransmit == 3);
		REQUIRE(c.enable_trickle == true);
		REQUIRE(c.pre_allocate_tcp_relay == false);
		REQUIRE(c.early_phase_max_concurrent == 3);
		REQUIRE(c.early_phase_duration.count() == 1200);
	}

	SECTION("DEBUG_FAST uses eager TCP-relay and aggressive nomination") {
		auto c = makeIcePairingConfig(IcePairingProfile::DEBUG_FAST);
		REQUIRE(c.schedule_mode == IceCheckScheduleMode::LIMITED_CONCURRENT);
		REQUIRE(c.nomination_mode == IceNominationMode::AGGRESSIVE);
		REQUIRE(c.tcp_relay_fallback == TcpRelayFallbackMode::ALWAYS_ENABLE);
		REQUIRE(c.reselect_policy == LinkReselectPolicy::RFC8445);
		REQUIRE(c.max_concurrent_check == 4);
		// Speed optimization: pre-allocate Mode-B for fastest fallback,
		// early-phase boost to 4 for 1500ms.
		REQUIRE(c.pre_allocate_tcp_relay == true);
		REQUIRE(c.early_phase_max_concurrent == 4);
		REQUIRE(c.early_phase_duration.count() == 1500);
		REQUIRE(c.rto_initial.count() == 400);
		REQUIRE(c.max_check_retransmit == 3);
	}

	SECTION("MINIMAL_RESOURCE uses serial checks") {
		auto c = makeIcePairingConfig(IcePairingProfile::MINIMAL_RESOURCE);
		REQUIRE(c.schedule_mode == IceCheckScheduleMode::SERIAL);
		REQUIRE(c.nomination_mode == IceNominationMode::REGULAR);
		REQUIRE(c.tcp_relay_fallback == TcpRelayFallbackMode::ON_ALL_UDP_FAIL);
		REQUIRE(c.reselect_policy == LinkReselectPolicy::STICKY_SELECTED);
		REQUIRE(c.max_concurrent_check == 1);
		// Speed optimization: all optimizations off — no trickle, no
		// pre-allocation, no early-phase boost, conservative RTO.
		REQUIRE(c.enable_trickle == false);
		REQUIRE(c.pre_allocate_tcp_relay == false);
		REQUIRE(c.early_phase_max_concurrent == 0);
		REQUIRE(c.early_phase_duration.count() == 0);
		REQUIRE(c.rto_initial.count() == 1000);
		REQUIRE(c.max_check_retransmit == 5);
	}
}

// ---------------------------------------------------------------------------
// Speed-optimization field defaults on the raw IcePairingConfig struct.
// The struct defaults (without a profile) must match EMBEDDED_STABLE's
// optimization choices so callers who default-construct get the safe
// product defaults.
// ---------------------------------------------------------------------------
TEST_CASE("IcePairingConfig struct defaults match product defaults", "[pairing][default]") {
	IcePairingConfig c;
	REQUIRE(c.enable_trickle == true);
	REQUIRE(c.pre_allocate_tcp_relay == false);
	REQUIRE(c.early_phase_max_concurrent == 3);
	REQUIRE(c.early_phase_duration.count() == 1200);
	// Internal state initialized to zero/false.
	REQUIRE(!c.tcp_phase_entered);
	REQUIRE(!c.tcp_relay_allocation_created);
	REQUIRE(!c.early_phase_active);
	REQUIRE(c.udp_phase_start.time_since_epoch().count() == 0);
	REQUIRE(c.checking_start.time_since_epoch().count() == 0);
}

// ---------------------------------------------------------------------------
// Predicate helpers.
// ---------------------------------------------------------------------------
TEST_CASE("Pairing predicates", "[pairing][predicate]") {
	SECTION("scheduleArmsTcp respects PHASED_UDP_FIRST phase flag") {
		IcePairingConfig c;
		c.schedule_mode = IceCheckScheduleMode::PHASED_UDP_FIRST;
		c.tcp_phase_entered = false;
		REQUIRE(!scheduleArmsTcp(c));
		c.tcp_phase_entered = true;
		REQUIRE(scheduleArmsTcp(c));
	}
	SECTION("scheduleArmsTcp is true for non-phased modes") {
		IcePairingConfig c;
		c.schedule_mode = IceCheckScheduleMode::RFC8445_STRICT;
		REQUIRE(scheduleArmsTcp(c));
		c.schedule_mode = IceCheckScheduleMode::SERIAL;
		REQUIRE(scheduleArmsTcp(c));
		c.schedule_mode = IceCheckScheduleMode::LIMITED_CONCURRENT;
		REQUIRE(scheduleArmsTcp(c));
	}
	SECTION("nominationIsAggressive") {
		IcePairingConfig c;
		c.nomination_mode = IceNominationMode::AGGRESSIVE;
		REQUIRE(nominationIsAggressive(c));
		c.nomination_mode = IceNominationMode::REGULAR;
		REQUIRE(!nominationIsAggressive(c));
		c.nomination_mode = IceNominationMode::REGULAR_STABLE_CHECK;
		REQUIRE(!nominationIsAggressive(c));
	}
}

// ---------------------------------------------------------------------------
// C API: stice_make_pairing_config round-trips each profile.
// ---------------------------------------------------------------------------
TEST_CASE("C API pairing config factory", "[pairing][capi]") {
	stice_ice_pairing_config_t cfg{};

	SECTION("RFC8445_COMPAT") {
		REQUIRE(stice_make_pairing_config(STICE_PAIRING_RFC8445_COMPAT, &cfg) == STICE_ERR_SUCCESS);
		REQUIRE(cfg.schedule_mode == STICE_SCHEDULE_RFC8445_STRICT);
		REQUIRE(cfg.nomination_mode == STICE_NOMINATION_AGGRESSIVE);
		REQUIRE(cfg.tcp_relay_fallback == STICE_TCP_RELAY_ALWAYS_ENABLE);
		REQUIRE(cfg.reselect_policy == STICE_RESELECT_RFC8445);
	}
	SECTION("EMBEDDED_STABLE") {
		REQUIRE(stice_make_pairing_config(STICE_PAIRING_EMBEDDED_STABLE, &cfg) == STICE_ERR_SUCCESS);
		REQUIRE(cfg.schedule_mode == STICE_SCHEDULE_PHASED_UDP_FIRST);
		REQUIRE(cfg.nomination_mode == STICE_NOMINATION_REGULAR_STABLE_CHECK);
		REQUIRE(cfg.tcp_relay_fallback == STICE_TCP_RELAY_ON_ALL_UDP_FAIL);
		REQUIRE(cfg.reselect_policy == STICE_RESELECT_STICKY_SELECTED);
		REQUIRE(cfg.udp_phase_timeout_ms == 3000);
		REQUIRE(cfg.tcp_nomination_precheck_ms == 500);
		REQUIRE(cfg.keepalive_udp_ms == 10000);
		REQUIRE(cfg.keepalive_tcp_relay_ms == 5000);
		// Speed optimization fields round-trip through the C ABI.
		REQUIRE(cfg.enable_trickle == true);
		REQUIRE(cfg.pre_allocate_tcp_relay == false);
		REQUIRE(cfg.early_phase_max_concurrent == 3);
		REQUIRE(cfg.early_phase_duration_ms == 1200);
		REQUIRE(cfg.rto_initial_ms == 500);
		REQUIRE(cfg.max_check_retransmit == 3);
	}
	SECTION("DEBUG_FAST") {
		REQUIRE(stice_make_pairing_config(STICE_PAIRING_DEBUG_FAST, &cfg) == STICE_ERR_SUCCESS);
		REQUIRE(cfg.schedule_mode == STICE_SCHEDULE_LIMITED_CONCURRENT);
		REQUIRE(cfg.nomination_mode == STICE_NOMINATION_AGGRESSIVE);
		REQUIRE(cfg.tcp_relay_fallback == STICE_TCP_RELAY_ALWAYS_ENABLE);
		REQUIRE(cfg.reselect_policy == STICE_RESELECT_RFC8445);
	}
	SECTION("MINIMAL_RESOURCE") {
		REQUIRE(stice_make_pairing_config(STICE_PAIRING_MINIMAL_RESOURCE, &cfg) == STICE_ERR_SUCCESS);
		REQUIRE(cfg.schedule_mode == STICE_SCHEDULE_SERIAL);
		REQUIRE(cfg.nomination_mode == STICE_NOMINATION_REGULAR);
		REQUIRE(cfg.tcp_relay_fallback == STICE_TCP_RELAY_ON_ALL_UDP_FAIL);
		REQUIRE(cfg.reselect_policy == STICE_RESELECT_STICKY_SELECTED);
	}
	SECTION("null out_config rejected") {
		REQUIRE(stice_make_pairing_config(STICE_PAIRING_EMBEDDED_STABLE, nullptr) == STICE_ERR_INVALID);
	}
}

// ---------------------------------------------------------------------------
// C API: stice_set_pairing_config is accepted by a fresh agent. The config
// is applied to the C++ Agent (verified behaviorally by the integration
// tests below); here we only check the API contract (return codes, null
// rejection). A direct C++ Agent round-trip is covered separately.
// ---------------------------------------------------------------------------
TEST_CASE("C API set_pairing_config API contract", "[pairing][capi]") {
	AgentState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	stice_ice_pairing_config_t pc{};
	REQUIRE(stice_make_pairing_config(STICE_PAIRING_EMBEDDED_STABLE, &pc) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_pairing_config(a, &pc) == STICE_ERR_SUCCESS);

	SECTION("null agent rejected") {
		REQUIRE(stice_set_pairing_config(nullptr, &pc) == STICE_ERR_INVALID);
	}
	SECTION("null config rejected") {
		REQUIRE(stice_set_pairing_config(a, nullptr) == STICE_ERR_INVALID);
	}

	stice_destroy(a);
}

// ---------------------------------------------------------------------------
// C++ API: Agent::setPairingConfig stores the config and resets phase state.
// Uses the C++ Agent directly (no C ABI opaque-handle barrier).
// ---------------------------------------------------------------------------
TEST_CASE("C++ Agent setPairingConfig stores config", "[pairing][cpp]") {
	ice::Agent agent;
	IcePairingConfig cfg = makeIcePairingConfig(IcePairingProfile::EMBEDDED_STABLE);
	REQUIRE(agent.setPairingConfig(cfg) == STICE_ERR_SUCCESS);

	const auto &applied = agent.pairingConfig();
	REQUIRE(applied.schedule_mode == IceCheckScheduleMode::PHASED_UDP_FIRST);
	REQUIRE(applied.nomination_mode == IceNominationMode::REGULAR_STABLE_CHECK);
	REQUIRE(applied.tcp_relay_fallback == TcpRelayFallbackMode::ON_ALL_UDP_FAIL);
	REQUIRE(applied.reselect_policy == LinkReselectPolicy::STICKY_SELECTED);
	// Speed optimization fields are stored.
	REQUIRE(applied.pre_allocate_tcp_relay == false);
	REQUIRE(applied.early_phase_max_concurrent == 3);
	REQUIRE(applied.early_phase_duration.count() == 1200);
	REQUIRE(applied.rto_initial.count() == 500);
	REQUIRE(applied.max_check_retransmit == 3);
	// setPairingConfig resets all phase-tracking / early-phase state
	// regardless of the input values, so a fresh gather starts clean.
	REQUIRE(!applied.tcp_phase_entered);
	REQUIRE(!applied.tcp_relay_allocation_created);
	REQUIRE(!applied.early_phase_active);
	REQUIRE(applied.udp_phase_start.time_since_epoch().count() == 0);
	REQUIRE(applied.checking_start.time_since_epoch().count() == 0);

	SECTION("partial override is honored") {
		cfg.udp_phase_timeout = std::chrono::milliseconds(4000);
		cfg.max_concurrent_check = 8;
		cfg.pre_allocate_tcp_relay = true;
		cfg.early_phase_max_concurrent = 5;
		REQUIRE(agent.setPairingConfig(cfg) == STICE_ERR_SUCCESS);
		const auto &applied2 = agent.pairingConfig();
		REQUIRE(applied2.udp_phase_timeout.count() == 4000);
		REQUIRE(applied2.max_concurrent_check == 8);
		REQUIRE(applied2.pre_allocate_tcp_relay == true);
		REQUIRE(applied2.early_phase_max_concurrent == 5);
	}
}

// ---------------------------------------------------------------------------
// Integration: each profile preserves UDP loopback connectivity.
// No TURN server is configured, so only host UDP candidates are gathered.
// PHASED_UDP_FIRST never enters the TCP phase (no TCP-relay pairs exist),
// and every nomination mode must still complete a UDP loopback session.
// ---------------------------------------------------------------------------
TEST_CASE("Pairing profiles preserve UDP loopback connectivity", "[pairing][integration]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	auto runWithProfile = [](stice_ice_pairing_profile_t profA, stice_ice_pairing_profile_t profB) {
		AgentState sa, sb;
		auto cfgA = makeConfig(sa);
		auto cfgB = makeConfig(sb);

		stice_agent_t *a = stice_create(&cfgA);
		stice_agent_t *b = stice_create(&cfgB);
		REQUIRE(a != nullptr);
		REQUIRE(b != nullptr);

		stice_ice_pairing_config_t pa{}, pb{};
		REQUIRE(stice_make_pairing_config(profA, &pa) == STICE_ERR_SUCCESS);
		REQUIRE(stice_make_pairing_config(profB, &pb) == STICE_ERR_SUCCESS);
		REQUIRE(stice_set_pairing_config(a, &pa) == STICE_ERR_SUCCESS);
		REQUIRE(stice_set_pairing_config(b, &pb) == STICE_ERR_SUCCESS);

		REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
		REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
		trickleExchange(a, sa, b, sb);

		bool ok = waitFor([&] {
			auto as = sa.state.load();
			auto bs = sb.state.load();
			return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
			       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
		}, 5000);
		REQUIRE(ok);

		const char *msg = "profile-ping";
		REQUIRE(stice_send(a, msg, std::strlen(msg)) == STICE_ERR_SUCCESS);
		REQUIRE(waitFor([&] { return sb.received.size() >= 1; }, 2000));
		REQUIRE(sb.received[0] == msg);

		stice_destroy(a);
		stice_destroy(b);
	};

	SECTION("EMBEDDED_STABLE on both sides") {
		runWithProfile(STICE_PAIRING_EMBEDDED_STABLE, STICE_PAIRING_EMBEDDED_STABLE);
	}
	SECTION("RFC8445_COMPAT on both sides") {
		runWithProfile(STICE_PAIRING_RFC8445_COMPAT, STICE_PAIRING_RFC8445_COMPAT);
	}
	SECTION("DEBUG_FAST on both sides") {
		runWithProfile(STICE_PAIRING_DEBUG_FAST, STICE_PAIRING_DEBUG_FAST);
	}
	SECTION("MINIMAL_RESOURCE on both sides") {
		runWithProfile(STICE_PAIRING_MINIMAL_RESOURCE, STICE_PAIRING_MINIMAL_RESOURCE);
	}
	SECTION("mixed: EMBEDDED_STABLE controlling <-> RFC8445_COMPAT controlled") {
		runWithProfile(STICE_PAIRING_EMBEDDED_STABLE, STICE_PAIRING_RFC8445_COMPAT);
	}
	SECTION("mixed: MINIMAL_RESOURCE controlling <-> EMBEDDED_STABLE controlled") {
		runWithProfile(STICE_PAIRING_MINIMAL_RESOURCE, STICE_PAIRING_EMBEDDED_STABLE);
	}
}

// ---------------------------------------------------------------------------
// Integration: a custom config (partially overriding a preset) is honored.
// Start from EMBEDDED_STABLE but shorten udp_phase_timeout to 1ms; with only
// UDP candidates the TCP phase is irrelevant, but the override must not break
// connectivity.
// ---------------------------------------------------------------------------
TEST_CASE("Pairing config partial override preserves connectivity", "[pairing][integration]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);

	stice_ice_pairing_config_t pa{};
	REQUIRE(stice_make_pairing_config(STICE_PAIRING_EMBEDDED_STABLE, &pa) == STICE_ERR_SUCCESS);
	pa.udp_phase_timeout_ms = 1; // override
	pa.max_concurrent_check = 4; // override
	REQUIRE(stice_set_pairing_config(a, &pa) == STICE_ERR_SUCCESS);

	stice_ice_pairing_config_t pb{};
	REQUIRE(stice_make_pairing_config(STICE_PAIRING_RFC8445_COMPAT, &pb) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_pairing_config(b, &pb) == STICE_ERR_SUCCESS);

	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	trickleExchange(a, sa, b, sb);

	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 5000));

	const char *msg = "override-ok";
	REQUIRE(stice_send(a, msg, std::strlen(msg)) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sb.received.size() >= 1; }, 2000));
	REQUIRE(sb.received[0] == msg);

	stice_destroy(a);
	stice_destroy(b);
}
