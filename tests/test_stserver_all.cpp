// SPDX-License-Identifier: MPL-2.0
// Comprehensive stserver test: covers all 4 ICE/TURN transport combinations.
// Usage: test_stserver_all [host] [port] [mode]
//   mode = ice-udp  : direct UDP ICE (no TURN, STUN only for srflx)
//   mode = ice-tcp  : direct TCP ICE (passive TCPMux + active)
//   mode = turn-udp : TURN relay over UDP (relay-only SDP)
//   mode = turn-tcp : TURN relay over TCP / RFC 6062 Mode-B (relay-only SDP)
// Default: host=127.0.0.1 port=3478 mode=turn-udp

#ifndef STICE_STATIC
#define STICE_STATIC
#endif

#include "stice/stice.h"
#include "stice/log.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

struct AgentState {
	std::atomic<stice_state_t> state{STICE_STATE_DISCONNECTED};
	std::vector<std::string> candidates;
	std::atomic<bool> gatheringDone{false};
	std::vector<std::string> received;
	std::mutex candidatesMutex;
	std::mutex receivedMutex;
};

static stice_config_t makeConfig(AgentState &s) {
	stice_config_t cfg{};
	cfg.cb_state_changed = [](stice_agent_t *, stice_state_t st, void *u) {
		static_cast<AgentState *>(u)->state.store(st);
	};
	cfg.cb_candidate = [](stice_agent_t *, const char *c, void *u) {
		auto &s = *static_cast<AgentState *>(u);
		std::lock_guard<std::mutex> lk(s.candidatesMutex);
		s.candidates.emplace_back(c);
	};
	cfg.cb_gathering_done = [](stice_agent_t *, void *u) {
		static_cast<AgentState *>(u)->gatheringDone.store(true);
	};
	cfg.cb_recv = [](stice_agent_t *, const char *d, size_t n, void *u) {
		auto &s = *static_cast<AgentState *>(u);
		std::lock_guard<std::mutex> lk(s.receivedMutex);
		s.received.emplace_back(d, n);
	};
	cfg.user_ptr = &s;
	cfg.bind_address = nullptr;
	cfg.local_port_range_begin = 0;
	cfg.local_port_range_end = 0;
	return cfg;
}

static bool waitFor(std::function<bool()> cond, int timeoutMs) {
	auto start = std::chrono::steady_clock::now();
	while (true) {
		if (cond()) return true;
		auto el = std::chrono::duration_cast<std::chrono::milliseconds>(
		              std::chrono::steady_clock::now() - start);
		if (el.count() >= timeoutMs) return false;
		std::this_thread::sleep_for(10ms);
	}
}

// Filter SDP to relay-only candidates (for TURN relay tests).
static std::string filterRelayOnly(const std::string &sdp) {
	std::string out;
	std::string line;
	std::istringstream iss(sdp);
	while (std::getline(iss, line)) {
		if (line.rfind("a=ice-ufrag:", 0) == 0 ||
		    line.rfind("a=ice-pwd:", 0) == 0 ||
		    line.rfind("a=end-of-candidates", 0) == 0 ||
		    line.rfind("a=ice-options:", 0) == 0) {
			out += line + "\n";
		} else if (line.rfind("a=candidate:", 0) == 0) {
			if (line.find("typ relay") != std::string::npos)
				out += line + "\n";
		}
	}
	return out;
}

// Filter SDP to TCP-only candidates (for direct ICE-TCP tests).
static std::string filterTcpOnly(const std::string &sdp) {
	std::string out;
	std::string line;
	std::istringstream iss(sdp);
	while (std::getline(iss, line)) {
		if (line.rfind("a=ice-ufrag:", 0) == 0 ||
		    line.rfind("a=ice-pwd:", 0) == 0 ||
		    line.rfind("a=end-of-candidates", 0) == 0 ||
		    line.rfind("a=ice-options:", 0) == 0) {
			out += line + "\n";
		} else if (line.rfind("a=candidate:", 0) == 0) {
			if (line.find(" tcp ") != std::string::npos)
				out += line + "\n";
		}
	}
	return out;
}

int main(int argc, char **argv) {
	const char *host = argc > 1 ? argv[1] : "127.0.0.1";
	uint16_t port = argc > 2 ? static_cast<uint16_t>(std::atoi(argv[2])) : 3478;
	std::string mode = argc > 3 ? argv[3] : "turn-udp";

	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	bool useTurn = (mode == "turn-udp" || mode == "turn-tcp");
	bool useTcp = (mode == "ice-tcp" || mode == "turn-tcp");

	std::fprintf(stderr, "=== stserver test: %s:%u mode=%s ===\n", host, port, mode.c_str());

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);

	// TCP transport (both ICE-TCP and TURN-TCP) requires POLL concurrency.
	if (useTcp) {
		cfgA.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
		cfgB.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
	}

	// STUN server (for srflx in all modes except pure ICE-TCP).
	if (mode != "ice-tcp") {
		cfgA.stun_server_host = host;
		cfgA.stun_server_port = port;
		cfgB.stun_server_host = host;
		cfgB.stun_server_port = port;
	}

	// ICE-TCP: A is passive (TCPMux), B is active.
	stice_tcp_mux_t *mux = nullptr;
	if (mode == "ice-tcp") {
		mux = stice_create_tcp_mux("127.0.0.1", 0);
		if (!mux) { std::fprintf(stderr, "FAIL: create_tcp_mux\n"); return 1; }
	}

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	if (!a || !b) { std::fprintf(stderr, "FAIL: create\n"); return 1; }

	// TURN relay tests: add TURN server.
	if (useTurn) {
		stice_turn_server_t turn{};
		turn.host = const_cast<char *>(host);
		turn.port = port;
		turn.username = const_cast<char *>("testuser");
		turn.password = const_cast<char *>("123456");
		turn.transport = (mode == "turn-tcp")
		                     ? STICE_TURN_TRANSPORT_TCP
		                     : STICE_TURN_TRANSPORT_UDP;
		stice_add_turn_server(a, &turn);
		stice_add_turn_server(b, &turn);
	}

	// ICE-TCP: set modes.
	if (mode == "ice-tcp") {
		stice_set_ice_tcp_mode(a, STICE_ICE_TCP_MODE_PASSIVE);
		stice_agent_use_tcp_mux(a, mux);
		stice_set_ice_tcp_mode(b, STICE_ICE_TCP_MODE_ACTIVE);
		// Exchange SDP before gathering for ICE-TCP.
		char sdpA[4096], sdpB[4096];
		stice_get_local_description(a, sdpA, sizeof(sdpA));
		stice_get_local_description(b, sdpB, sizeof(sdpB));
		stice_set_remote_description(a, sdpB);
		stice_set_remote_description(b, sdpA);
	}

	stice_gather_candidates(b);
	stice_gather_candidates(a);

	if (!waitFor([&] { return sa.gatheringDone.load(); }, 15000)) {
		std::fprintf(stderr, "FAIL: A gathering timeout\n"); return 1;
	}
	if (!waitFor([&] { return sb.gatheringDone.load(); }, 15000)) {
		std::fprintf(stderr, "FAIL: B gathering timeout\n"); return 1;
	}

	std::fprintf(stderr, "A candidates: %zu  B candidates: %zu\n",
	             sa.candidates.size(), sb.candidates.size());
	{
		std::lock_guard<std::mutex> lk(sa.candidatesMutex);
		for (const auto &c : sa.candidates) std::fprintf(stderr, "  A: %s\n", c.c_str());
	}
	{
		std::lock_guard<std::mutex> lk(sb.candidatesMutex);
		for (const auto &c : sb.candidates) std::fprintf(stderr, "  B: %s\n", c.c_str());
	}

	// Exchange SDP.
	char bufA[4096], bufB[4096];
	stice_get_local_description(a, bufA, sizeof(bufA));
	stice_get_local_description(b, bufB, sizeof(bufB));

	if (mode == "turn-udp" || mode == "turn-tcp") {
		// Relay-only: force traffic through TURN.
		std::string sdpA = filterRelayOnly(bufA);
		std::string sdpB = filterRelayOnly(bufB);
		stice_set_remote_description(a, sdpB.c_str());
		stice_set_remote_description(b, sdpA.c_str());
	} else if (mode == "ice-tcp") {
		// ICE-TCP: use trickle. Exchange ufrag/pwd via set_remote_description
		// (already done before gathering), then forward only TCP candidates.
		// The initial set_remote_description was done before gathering with
		// just ufrag/pwd (no candidates). Now trickle TCP candidates.
		// Match "tcptype" (case-insensitive fallback to "tcp") since SDP
		// uses uppercase "TCP" in the protocol field but lowercase "tcptype".
		std::lock_guard<std::mutex> lka(sa.candidatesMutex);
		for (const auto &c : sa.candidates) {
			if (c.find("tcptype") != std::string::npos)
				stice_add_remote_candidate(b, c.c_str());
		}
		std::lock_guard<std::mutex> lkb(sb.candidatesMutex);
		for (const auto &c : sb.candidates) {
			if (c.find("tcptype") != std::string::npos)
				stice_add_remote_candidate(a, c.c_str());
		}
	} else {
		// ice-udp: full SDP (host + srflx).
		stice_set_remote_description(a, bufB);
		stice_set_remote_description(b, bufA);
	}
	stice_set_remote_gathering_done(a);
	stice_set_remote_gathering_done(b);

	// Wait for CONNECTED/COMPLETED.
	int connectTimeout = (mode == "turn-tcp") ? 20000 : 15000;
	if (!waitFor([&] {
		auto as = sa.state.load(), bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, connectTimeout)) {
		std::fprintf(stderr, "FAIL: connect timeout (A=%d B=%d)\n",
		             (int)sa.state.load(), (int)sb.state.load());
		stice_destroy(a); stice_destroy(b);
		if (mux) stice_destroy_tcp_mux(mux);
		return 1;
	}
	std::fprintf(stderr, "CONNECTED: A=%d B=%d\n", (int)sa.state.load(), (int)sb.state.load());

	// Data exchange.
	const char *msgA = "hello-from-A";
	const char *msgB = "hello-from-B";
	stice_send(a, msgA, std::strlen(msgA));
	stice_send(b, msgB, std::strlen(msgB));

	waitFor([&] { return sb.received.size() >= 1; }, 5000);
	waitFor([&] { return sa.received.size() >= 1; }, 5000);

	bool ok = !sb.received.empty() && !sa.received.empty() &&
	          sb.received[0] == msgA && sa.received[0] == msgB;
	std::fprintf(stderr, "A received %zu: %s\n", sa.received.size(),
	             sa.received.empty() ? "(none)" : sa.received[0].c_str());
	std::fprintf(stderr, "B received %zu: %s\n", sb.received.size(),
	             sb.received.empty() ? "(none)" : sb.received[0].c_str());

	stice_destroy(a);
	stice_destroy(b);
	if (mux) stice_destroy_tcp_mux(mux);

	if (ok) {
		std::fprintf(stderr, "=== PASS: %s data exchange OK ===\n", mode.c_str());
		return 0;
	}
	std::fprintf(stderr, "=== FAIL: %s data exchange ===\n", mode.c_str());
	return 1;
}
