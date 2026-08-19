// SPDX-License-Identifier: MPL-2.0
// Functional / API-level tests for stice's C ABI.
//
// These tests exercise the public stice_* API surface without requiring
// external STUN/TURN servers. They cover:
//   - Agent lifecycle (create/destroy, idempotent destroy)
//   - NULL / invalid parameter handling
//   - stice_set_local_ice_attributes validation
//   - stice_get_local_description format (ice-ufrag/ice-pwd presence)
//   - stice_get_state before/after gather
//   - stice_get_selected_candidates before connection (NOT_AVAIL)
//   - stice_state_to_string mapping
//   - stice_make_pairing_config for all 4 preset profiles
//   - stice_set_pairing_config acceptance
//   - stice_add_stun_server / stice_add_turn_server / stice_add_ice_server
//   - stice_set_ice_tcp_mode / stice_set_multicast_dns_mode
//   - UDPMux / TCPMux create/destroy
//   - stice_send before connection (returns FAILED)
//   - stice_set_remote_gathering_done without remote description

#include <catch2/catch_all.hpp>

#include "stice/stice.h"
#include "stice/log.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

// Minimal callback wiring: just track state and gathering-done.
struct FuncState {
	std::atomic<stice_state_t> state{STICE_STATE_DISCONNECTED};
	std::atomic<bool> gatheringDone{false};
	std::vector<std::string> candidates;
	std::mutex candMutex;
};

stice_config_t makeConfig(FuncState &s) {
	stice_config_t cfg{};
	cfg.cb_state_changed = [](stice_agent_t *, stice_state_t st, void *p) {
		static_cast<FuncState *>(p)->state.store(st);
	};
	cfg.cb_candidate = [](stice_agent_t *, const char *c, void *p) {
		auto *s = static_cast<FuncState *>(p);
		std::lock_guard<std::mutex> lk(s->candMutex);
		s->candidates.emplace_back(c);
	};
	cfg.cb_gathering_done = [](stice_agent_t *, void *p) {
		static_cast<FuncState *>(p)->gatheringDone.store(true);
	};
	cfg.cb_recv = [](stice_agent_t *, const char *, size_t, void *) {};
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
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
}

} // namespace

// ---------------------------------------------------------------------------
// Section 1: Agent lifecycle and NULL/invalid parameter handling
// ---------------------------------------------------------------------------

TEST_CASE("Functional: stice_create with default config returns valid agent", "[functional][lifecycle]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	stice_config_t cfg{};
	// Zero-initialized config: no callbacks, no servers. Should still work.
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);
	REQUIRE(stice_get_state(a) == STICE_STATE_DISCONNECTED);
	stice_destroy(a);
}

TEST_CASE("Functional: stice_destroy(NULL) is safe", "[functional][lifecycle]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);
	stice_destroy(nullptr); // must not crash
	REQUIRE(true);
}

TEST_CASE("Functional: stice_destroy is idempotent", "[functional][lifecycle]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	FuncState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	stice_destroy(a);
	stice_destroy(a); // double destroy must not crash
	REQUIRE(true);
}

TEST_CASE("Functional: NULL agent returns STICE_ERR_INVALID", "[functional][error]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	REQUIRE(stice_gather_candidates(nullptr) == STICE_ERR_INVALID);
	REQUIRE(stice_get_local_description(nullptr, nullptr, 0) == STICE_ERR_INVALID);
	REQUIRE(stice_set_remote_description(nullptr, "") == STICE_ERR_INVALID);
	REQUIRE(stice_add_remote_candidate(nullptr, "") == STICE_ERR_INVALID);
	REQUIRE(stice_set_remote_gathering_done(nullptr) == STICE_ERR_INVALID);
	REQUIRE(stice_send(nullptr, "", 0) == STICE_ERR_INVALID);
	REQUIRE(stice_get_selected_candidates(nullptr, nullptr, 0, nullptr, 0) == STICE_ERR_INVALID);
	REQUIRE(stice_set_local_ice_attributes(nullptr, "u", "p") == STICE_ERR_INVALID);
	REQUIRE(stice_set_ice_tcp_mode(nullptr, STICE_ICE_TCP_MODE_NONE) == STICE_ERR_INVALID);
	REQUIRE(stice_set_multicast_dns_mode(nullptr, STICE_MDNS_MODE_DISABLED) == STICE_ERR_INVALID);
	REQUIRE(stice_add_stun_server(nullptr, "host", 3478) == STICE_ERR_INVALID);
	REQUIRE(stice_add_turn_server(nullptr, nullptr) == STICE_ERR_INVALID);
	REQUIRE(stice_add_ice_server(nullptr, nullptr) == STICE_ERR_INVALID);
	REQUIRE(stice_set_pairing_config(nullptr, nullptr) == STICE_ERR_INVALID);
	REQUIRE(stice_agent_use_udp_mux(nullptr, nullptr) == STICE_ERR_INVALID);
	REQUIRE(stice_agent_use_tcp_mux(nullptr, nullptr) == STICE_ERR_INVALID);
}

TEST_CASE("Functional: NULL string params return STICE_ERR_INVALID", "[functional][error]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	FuncState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	REQUIRE(stice_set_remote_description(a, nullptr) == STICE_ERR_INVALID);
	REQUIRE(stice_add_remote_candidate(a, nullptr) == STICE_ERR_INVALID);
	REQUIRE(stice_set_local_ice_attributes(a, nullptr, "pwd") == STICE_ERR_INVALID);
	REQUIRE(stice_set_local_ice_attributes(a, "ufrag", nullptr) == STICE_ERR_INVALID);
	REQUIRE(stice_add_stun_server(a, nullptr, 3478) == STICE_ERR_INVALID);
	REQUIRE(stice_add_turn_server(a, nullptr) == STICE_ERR_INVALID);
	REQUIRE(stice_add_ice_server(a, nullptr) == STICE_ERR_INVALID);

	stice_destroy(a);
}

// ---------------------------------------------------------------------------
// Section 2: stice_state_to_string
// ---------------------------------------------------------------------------

TEST_CASE("Functional: stice_state_to_string covers all states", "[functional][state]") {
	REQUIRE(std::string(stice_state_to_string(STICE_STATE_DISCONNECTED)) == "disconnected");
	REQUIRE(std::string(stice_state_to_string(STICE_STATE_GATHERING)) == "gathering");
	REQUIRE(std::string(stice_state_to_string(STICE_STATE_CONNECTING)) == "connecting");
	REQUIRE(std::string(stice_state_to_string(STICE_STATE_CONNECTED)) == "connected");
	REQUIRE(std::string(stice_state_to_string(STICE_STATE_COMPLETED)) == "completed");
	REQUIRE(std::string(stice_state_to_string(STICE_STATE_FAILED)) == "failed");
	// Unknown state should return "unknown", not crash.
	REQUIRE(std::string(stice_state_to_string(static_cast<stice_state_t>(99))) == "unknown");
}

// ---------------------------------------------------------------------------
// Section 3: stice_set_local_ice_attributes and local description format
// ---------------------------------------------------------------------------

TEST_CASE("Functional: set_local_ice_attributes with valid ufrag/pwd", "[functional][ufrag]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	FuncState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	// Valid: ufrag 4-256 chars, pwd 22-256 chars (RFC 8445).
	REQUIRE(stice_set_local_ice_attributes(a, "abcd", "0123456789012345678901") == STICE_ERR_SUCCESS);

	// The custom ufrag/pwd must appear in the local description.
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return s.gatheringDone.load(); }, 3000));

	char buf[4096];
	REQUIRE(stice_get_local_description(a, buf, sizeof(buf)) == STICE_ERR_SUCCESS);
	std::string sdp(buf);
	REQUIRE(sdp.find("ice-ufrag:abcd") != std::string::npos);
	REQUIRE(sdp.find("ice-pwd:0123456789012345678901") != std::string::npos);

	stice_destroy(a);
}

TEST_CASE("Functional: set_local_ice_attributes with too-short ufrag fails", "[functional][ufrag]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	FuncState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	// ufrag too short (< 4 chars).
	REQUIRE(stice_set_local_ice_attributes(a, "ab", "0123456789012345678901") != STICE_ERR_SUCCESS);

	stice_destroy(a);
}

TEST_CASE("Functional: set_local_ice_attributes with too-short pwd fails", "[functional][ufrag]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	FuncState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	// pwd too short (< 22 chars).
	REQUIRE(stice_set_local_ice_attributes(a, "abcd", "short") != STICE_ERR_SUCCESS);

	stice_destroy(a);
}

TEST_CASE("Functional: local description contains ice-ufrag and ice-pwd", "[functional][sdp]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	FuncState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return s.gatheringDone.load(); }, 3000));

	char buf[4096];
	REQUIRE(stice_get_local_description(a, buf, sizeof(buf)) == STICE_ERR_SUCCESS);
	std::string sdp(buf);

	// SDP must contain the mandatory ICE attributes.
	REQUIRE(sdp.find("ice-ufrag:") != std::string::npos);
	REQUIRE(sdp.find("ice-pwd:") != std::string::npos);
	// Must contain at least one candidate (host candidate on loopback).
	REQUIRE(sdp.find("a=candidate:") != std::string::npos);
	// Must contain end-of-candidates marker (gathering is done).
	REQUIRE(sdp.find("a=end-of-candidates") != std::string::npos);

	stice_destroy(a);
}

TEST_CASE("Functional: get_local_description with tiny buffer returns TOO_LARGE", "[functional][sdp]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	FuncState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return s.gatheringDone.load(); }, 3000));

	char tiny[8];
	REQUIRE(stice_get_local_description(a, tiny, sizeof(tiny)) == STICE_ERR_TOO_LARGE);

	stice_destroy(a);
}

// ---------------------------------------------------------------------------
// Section 4: stice_get_selected_candidates before connection
// ---------------------------------------------------------------------------

TEST_CASE("Functional: get_selected_candidates returns NOT_AVAIL before connection", "[functional][selected]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	FuncState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return s.gatheringDone.load(); }, 3000));

	char local[512], remote[512];
	REQUIRE(stice_get_selected_candidates(a, local, sizeof(local), remote, sizeof(remote)) ==
	       STICE_ERR_NOT_AVAIL);

	stice_destroy(a);
}

// ---------------------------------------------------------------------------
// Section 5: stice_send before connection
// ---------------------------------------------------------------------------

TEST_CASE("Functional: stice_send before connection returns FAILED", "[functional][send]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	FuncState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	const char msg[] = "hello";
	REQUIRE(stice_send(a, msg, sizeof(msg)) == STICE_ERR_FAILED);

	stice_destroy(a);
}

// ---------------------------------------------------------------------------
// Section 6: Pairing config profiles
// ---------------------------------------------------------------------------

TEST_CASE("Functional: stice_make_pairing_config for all 4 profiles", "[functional][pairing]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	stice_ice_pairing_config_t cfg;

	SECTION("RFC8445_COMPAT") {
		REQUIRE(stice_make_pairing_config(STICE_PAIRING_RFC8445_COMPAT, &cfg) == STICE_ERR_SUCCESS);
		// RFC8445_COMPAT mirrors pion-ice: strict scheduling, aggressive nomination.
		REQUIRE(cfg.schedule_mode == STICE_SCHEDULE_RFC8445_STRICT);
		REQUIRE(cfg.nomination_mode == STICE_NOMINATION_AGGRESSIVE);
	}

	SECTION("EMBEDDED_STABLE") {
		REQUIRE(stice_make_pairing_config(STICE_PAIRING_EMBEDDED_STABLE, &cfg) == STICE_ERR_SUCCESS);
		// EMBEDDED_STABLE uses phased UDP-first and regular-stable-check nomination.
		REQUIRE(cfg.schedule_mode == STICE_SCHEDULE_PHASED_UDP_FIRST);
		REQUIRE(cfg.nomination_mode == STICE_NOMINATION_REGULAR_STABLE_CHECK);
	}

	SECTION("DEBUG_FAST") {
		REQUIRE(stice_make_pairing_config(STICE_PAIRING_DEBUG_FAST, &cfg) == STICE_ERR_SUCCESS);
		REQUIRE(cfg.enable_trickle == true);
		REQUIRE(cfg.pre_allocate_tcp_relay == true);
	}

	SECTION("MINIMAL_RESOURCE") {
		REQUIRE(stice_make_pairing_config(STICE_PAIRING_MINIMAL_RESOURCE, &cfg) == STICE_ERR_SUCCESS);
		REQUIRE(cfg.schedule_mode == STICE_SCHEDULE_SERIAL);
	}

	SECTION("NULL out_config returns INVALID") {
		REQUIRE(stice_make_pairing_config(STICE_PAIRING_RFC8445_COMPAT, nullptr) == STICE_ERR_INVALID);
	}
}

TEST_CASE("Functional: stice_set_pairing_config accepts all profiles", "[functional][pairing]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	FuncState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	stice_ice_pairing_config_t pc;
	for (int i = 0; i < 4; ++i) {
		REQUIRE(stice_make_pairing_config(static_cast<stice_ice_pairing_profile_t>(i), &pc) ==
		       STICE_ERR_SUCCESS);
		REQUIRE(stice_set_pairing_config(a, &pc) == STICE_ERR_SUCCESS);
	}

	// NULL config should fail.
	REQUIRE(stice_set_pairing_config(a, nullptr) == STICE_ERR_INVALID);

	stice_destroy(a);
}

// ---------------------------------------------------------------------------
// Section 7: stice_add_stun_server / stice_add_turn_server / stice_add_ice_server
// ---------------------------------------------------------------------------

TEST_CASE("Functional: stice_add_stun_server accepts valid host", "[functional][config]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	FuncState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	REQUIRE(stice_add_stun_server(a, "192.168.1.1", 3478) == STICE_ERR_SUCCESS);
	REQUIRE(stice_add_stun_server(a, "stun.example.com", 19302) == STICE_ERR_SUCCESS);

	stice_destroy(a);
}

TEST_CASE("Functional: stice_add_turn_server accepts valid server", "[functional][config]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	FuncState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	stice_turn_server_t turn{};
	turn.host = "192.168.1.1";
	turn.port = 3478;
	turn.username = "user";
	turn.password = "pass";
	turn.transport = STICE_TURN_TRANSPORT_UDP;
	REQUIRE(stice_add_turn_server(a, &turn) == STICE_ERR_SUCCESS);

	// TCP transport.
	turn.transport = STICE_TURN_TRANSPORT_TCP;
	REQUIRE(stice_add_turn_server(a, &turn) == STICE_ERR_SUCCESS);

	stice_destroy(a);
}

TEST_CASE("Functional: stice_add_ice_server parses URL formats", "[functional][config]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	FuncState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	// stun: URL (no credentials needed).
	stice_ice_server_t srv1{};
	srv1.url = "stun:192.168.1.1:3478";
	REQUIRE(stice_add_ice_server(a, &srv1) == STICE_ERR_SUCCESS);

	// turn: URL with credentials.
	stice_ice_server_t srv2{};
	srv2.url = "turn:192.168.1.1:3478";
	srv2.username = "user";
	srv2.password = "pass";
	REQUIRE(stice_add_ice_server(a, &srv2) == STICE_ERR_SUCCESS);

	// turn: URL with TCP transport.
	stice_ice_server_t srv3{};
	srv3.url = "turn:192.168.1.1:3478?transport=tcp";
	srv3.username = "user";
	srv3.password = "pass";
	REQUIRE(stice_add_ice_server(a, &srv3) == STICE_ERR_SUCCESS);

	stice_destroy(a);
}

// ---------------------------------------------------------------------------
// Section 8: stice_set_ice_tcp_mode / stice_set_multicast_dns_mode
// ---------------------------------------------------------------------------

TEST_CASE("Functional: stice_set_ice_tcp_mode accepts all modes", "[functional][config]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	FuncState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	REQUIRE(stice_set_ice_tcp_mode(a, STICE_ICE_TCP_MODE_NONE) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_ice_tcp_mode(a, STICE_ICE_TCP_MODE_ACTIVE) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_ice_tcp_mode(a, STICE_ICE_TCP_MODE_PASSIVE) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_ice_tcp_mode(a, STICE_ICE_TCP_MODE_SO) == STICE_ERR_SUCCESS);

	stice_destroy(a);
}

TEST_CASE("Functional: stice_set_multicast_dns_mode accepts all modes", "[functional][config]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	FuncState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	REQUIRE(stice_set_multicast_dns_mode(a, STICE_MDNS_MODE_DISABLED) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_multicast_dns_mode(a, STICE_MDNS_MODE_QUERY_ONLY) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_multicast_dns_mode(a, STICE_MDNS_MODE_QUERY_AND_GATHER) == STICE_ERR_SUCCESS);

	stice_destroy(a);
}

// ---------------------------------------------------------------------------
// Section 9: UDPMux / TCPMux create/destroy
// ---------------------------------------------------------------------------

TEST_CASE("Functional: UDPMux create and destroy", "[functional][mux]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	stice_udp_mux_t *mux = stice_create_udp_mux(nullptr, 0, 0);
	REQUIRE(mux != nullptr);
	stice_destroy_udp_mux(mux);
	stice_destroy_udp_mux(nullptr); // idempotent
	REQUIRE(true);
}

TEST_CASE("Functional: TCPMux create and destroy", "[functional][mux]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	stice_tcp_mux_t *mux = stice_create_tcp_mux(nullptr, 0);
	REQUIRE(mux != nullptr);
	stice_destroy_tcp_mux(mux);
	stice_destroy_tcp_mux(nullptr); // idempotent
	REQUIRE(true);
}

TEST_CASE("Functional: agent_use_udp_mux before gather", "[functional][mux]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	stice_udp_mux_t *mux = stice_create_udp_mux(nullptr, 0, 0);
	REQUIRE(mux != nullptr);

	FuncState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	REQUIRE(stice_agent_use_udp_mux(a, mux) == STICE_ERR_SUCCESS);

	stice_destroy(a);
	stice_destroy_udp_mux(mux);
}

// ---------------------------------------------------------------------------
// Section 10: stice_set_tcp_priority_offset (global setting)
// ---------------------------------------------------------------------------

TEST_CASE("Functional: stice_set_tcp_priority_offset accepts values", "[functional][config]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	// This is a global setting; just verify it doesn't crash.
	stice_set_tcp_priority_offset(0);   // restore default
	stice_set_tcp_priority_offset(27);  // pion default
	stice_set_tcp_priority_offset(50);  // custom
	stice_set_tcp_priority_offset(0);   // restore default
	REQUIRE(true);
}

// ---------------------------------------------------------------------------
// Section 11: stice_set_remote_gathering_done without remote description
// ---------------------------------------------------------------------------

TEST_CASE("Functional: set_remote_gathering_done without remote description is accepted", "[functional][error]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	FuncState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	// set_remote_gathering_done just marks a flag; it succeeds even without
	// a prior remote description. The agent won't start checking until both
	// remote description and gathering-done are set.
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);

	stice_destroy(a);
}

// ---------------------------------------------------------------------------
// Section 12: State machine — gather transitions to GATHERING
// ---------------------------------------------------------------------------

TEST_CASE("Functional: gather_candidates transitions state to GATHERING", "[functional][state]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	FuncState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	REQUIRE(stice_get_state(a) == STICE_STATE_DISCONNECTED);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return s.state.load() == STICE_STATE_GATHERING; }, 500));
	REQUIRE(waitFor([&] { return s.gatheringDone.load(); }, 3000));

	// After gathering completes, state should still be GATHERING (waiting
	// for remote description) — not CONNECTING or FAILED.
	REQUIRE(s.state.load() == STICE_STATE_GATHERING);

	stice_destroy(a);
}

// ---------------------------------------------------------------------------
// Section 13: Candidate SDP format validation
// ---------------------------------------------------------------------------

TEST_CASE("Functional: gathered host candidates have correct SDP format", "[functional][candidate]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	FuncState s;
	auto cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return s.gatheringDone.load(); }, 3000));

	REQUIRE(!s.candidates.empty());
	for (const auto &c : s.candidates) {
		INFO("Candidate: " << c);
		// Each candidate must start with "a=candidate:".
		REQUIRE(c.rfind("a=candidate:", 0) == 0);
		// Must contain "typ host" for host candidates.
		REQUIRE(c.find("typ host") != std::string::npos);
		// Must contain "UDP" transport (uppercase per RFC 5245).
		REQUIRE(c.find(" UDP ") != std::string::npos);
	}

	stice_destroy(a);
}

// ---------------------------------------------------------------------------
// Section 14: Repeated create/destroy cycle (resource leak check)
// ---------------------------------------------------------------------------

TEST_CASE("Functional: 50 create/destroy cycles — no resource leak", "[functional][resource]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	for (int i = 0; i < 50; ++i) {
		FuncState s;
		auto cfg = makeConfig(s);
		stice_agent_t *a = stice_create(&cfg);
		REQUIRE(a != nullptr);
		REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
		REQUIRE(waitFor([&] { return s.gatheringDone.load(); }, 3000));
		stice_destroy(a);
	}
	REQUIRE(true);
}
