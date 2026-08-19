// SPDX-License-Identifier: MPL-2.0
// Standalone test: stserver STUN+TURN relay functionality.
// Usage: stserver_relay_test [host] [port]
// Defaults: host=127.0.0.1 port=13478

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

// Filter SDP to relay-only candidates.
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

int main(int argc, char **argv) {
	const char *host = argc > 1 ? argv[1] : "127.0.0.1";
	uint16_t port = argc > 2 ? static_cast<uint16_t>(std::atoi(argv[2])) : 13478;
	const char *transport = argc > 3 ? argv[3] : "udp";

	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	std::fprintf(stderr, "=== stserver relay test: %s:%u (%s) ===\n", host, port, transport);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);

	// STUN+TURN server = stserver
	cfgA.stun_server_host = host;
	cfgA.stun_server_port = port;
	cfgB.stun_server_host = host;
	cfgB.stun_server_port = port;

	stice_turn_server_t turn{};
	turn.host = const_cast<char *>(host);
	turn.port = port;
	turn.username = const_cast<char *>("testuser");
	turn.password = const_cast<char *>("123456");
	turn.transport = (std::string(transport) == "tcp")
	                     ? STICE_TURN_TRANSPORT_TCP
	                     : STICE_TURN_TRANSPORT_UDP;

	// TCP transport requires POLL concurrency mode.
	if (turn.transport == STICE_TURN_TRANSPORT_TCP) {
		cfgA.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
		cfgB.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
	}

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	if (!a || !b) { std::fprintf(stderr, "FAIL: create\n"); return 1; }
	stice_add_turn_server(a, &turn);
	stice_add_turn_server(b, &turn);

	stice_gather_candidates(b);
	stice_gather_candidates(a);

	if (!waitFor([&] { return sa.gatheringDone.load(); }, 10000)) {
		std::fprintf(stderr, "FAIL: A gathering timeout\n"); return 1;
	}
	if (!waitFor([&] { return sb.gatheringDone.load(); }, 10000)) {
		std::fprintf(stderr, "FAIL: B gathering timeout\n"); return 1;
	}

	// Check relay candidates
	bool hasRelayA = false, hasRelayB = false;
	for (auto &c : sa.candidates) if (c.find("typ relay") != std::string::npos) hasRelayA = true;
	for (auto &c : sb.candidates) if (c.find("typ relay") != std::string::npos) hasRelayB = true;
	std::fprintf(stderr, "A candidates: %zu  relay=%d\n", sa.candidates.size(), hasRelayA);
	std::fprintf(stderr, "B candidates: %zu  relay=%d\n", sb.candidates.size(), hasRelayB);
	if (!hasRelayA || !hasRelayB) {
		std::fprintf(stderr, "FAIL: no relay candidates\n"); return 1;
	}

	// Exchange relay-only SDP
	char bufA[4096], bufB[4096];
	stice_get_local_description(a, bufA, sizeof(bufA));
	stice_get_local_description(b, bufB, sizeof(bufB));
	std::string sdpA = filterRelayOnly(bufA);
	std::string sdpB = filterRelayOnly(bufB);
	stice_set_remote_description(a, sdpB.c_str());
	stice_set_remote_description(b, sdpA.c_str());
	stice_set_remote_gathering_done(a);
	stice_set_remote_gathering_done(b);

	// Wait for CONNECTED/COMPLETED
	if (!waitFor([&] {
		auto as = sa.state.load(), bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 15000)) {
		std::fprintf(stderr, "FAIL: connect timeout (A=%d B=%d)\n",
		             (int)sa.state.load(), (int)sb.state.load());
		stice_destroy(a); stice_destroy(b);
		return 1;
	}
	std::fprintf(stderr, "CONNECTED: A=%d B=%d\n", (int)sa.state.load(), (int)sb.state.load());

	// Data exchange through relay
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

	if (ok) {
		std::fprintf(stderr, "=== PASS: relay data exchange OK ===\n");
		return 0;
	}
	std::fprintf(stderr, "=== FAIL: data exchange ===\n");
	return 1;
}
