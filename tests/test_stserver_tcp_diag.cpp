// SPDX-License-Identifier: MPL-2.0
// Diagnostics: stserver TCP relay with verbose client logging.
// Captures client-side TURN-over-TCP state transitions to diagnose why
// the ICE agent enters FAILED after server-side CONNECTION-BIND succeeds.

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
	std::mutex stateMutex;
	std::vector<std::string> stateLog;
};

static stice_config_t makeConfig(AgentState &s) {
	stice_config_t cfg{};
	cfg.cb_state_changed = [](stice_agent_t *, stice_state_t st, void *u) {
		auto &s = *static_cast<AgentState *>(u);
		s.state.store(st);
		std::lock_guard<std::mutex> lk(s.stateMutex);
		s.stateLog.push_back("state=" + std::to_string((int)st));
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
	cfg.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
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

static void logHandler(stice_log_level_t level, const char *message) {
	const char *tag = "?";
	switch (level) {
	case STICE_LOG_LEVEL_VERBOSE: tag = "VRB"; break;
	case STICE_LOG_LEVEL_DEBUG:   tag = "DBG"; break;
	case STICE_LOG_LEVEL_INFO:    tag = "INF"; break;
	case STICE_LOG_LEVEL_WARN:    tag = "WRN"; break;
	case STICE_LOG_LEVEL_ERROR:   tag = "ERR"; break;
	case STICE_LOG_LEVEL_FATAL:   tag = "FTL"; break;
	default: break;
	}
	std::fprintf(stderr, "[stice/%s] %s\n", tag, message ? message : "");
}

int main(int argc, char **argv) {
	const char *host = argc > 1 ? argv[1] : "127.0.0.1";
	uint16_t port = argc > 2 ? static_cast<uint16_t>(std::atoi(argv[2])) : 3478;
	const char *transport = argc > 3 ? argv[3] : "tcp";

	stice_set_log_level(STICE_LOG_LEVEL_VERBOSE);
	stice_set_log_handler(logHandler);

	std::fprintf(stderr, "=== stserver relay diag: %s:%u (%s) ===\n", host, port, transport);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);

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

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	if (!a || !b) { std::fprintf(stderr, "FAIL: create\n"); return 1; }
	stice_add_turn_server(a, &turn);
	stice_add_turn_server(b, &turn);

	stice_gather_candidates(b);
	stice_gather_candidates(a);

	if (!waitFor([&] { return sa.gatheringDone.load(); }, 15000)) {
		std::fprintf(stderr, "FAIL: A gathering timeout\n"); return 1;
	}
	if (!waitFor([&] { return sb.gatheringDone.load(); }, 15000)) {
		std::fprintf(stderr, "FAIL: B gathering timeout\n"); return 1;
	}

	bool hasRelayA = false, hasRelayB = false;
	for (auto &c : sa.candidates) if (c.find("typ relay") != std::string::npos) hasRelayA = true;
	for (auto &c : sb.candidates) if (c.find("typ relay") != std::string::npos) hasRelayB = true;
	std::fprintf(stderr, "A candidates: %zu  relay=%d\n", sa.candidates.size(), hasRelayA);
	for (auto &c : sa.candidates) std::fprintf(stderr, "  A cand: %s\n", c.c_str());
	std::fprintf(stderr, "B candidates: %zu  relay=%d\n", sb.candidates.size(), hasRelayB);
	for (auto &c : sb.candidates) std::fprintf(stderr, "  B cand: %s\n", c.c_str());
	if (!hasRelayA || !hasRelayB) {
		std::fprintf(stderr, "FAIL: no relay candidates\n"); return 1;
	}

	char bufA[4096], bufB[4096];
	stice_get_local_description(a, bufA, sizeof(bufA));
	stice_get_local_description(b, bufB, sizeof(bufB));
	std::string sdpA = filterRelayOnly(bufA);
	std::string sdpB = filterRelayOnly(bufB);
	std::fprintf(stderr, "SDP A (relay-only):\n%s\n", sdpA.c_str());
	std::fprintf(stderr, "SDP B (relay-only):\n%s\n", sdpB.c_str());
	stice_set_remote_description(a, sdpB.c_str());
	stice_set_remote_description(b, sdpA.c_str());
	stice_set_remote_gathering_done(a);
	stice_set_remote_gathering_done(b);

	if (!waitFor([&] {
		auto as = sa.state.load(), bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 15000)) {
		std::fprintf(stderr, "FAIL: connect timeout (A=%d B=%d)\n",
		             (int)sa.state.load(), (int)sb.state.load());
		std::fprintf(stderr, "A state log:\n");
		for (auto &l : sa.stateLog) std::fprintf(stderr, "  A %s\n", l.c_str());
		std::fprintf(stderr, "B state log:\n");
		for (auto &l : sb.stateLog) std::fprintf(stderr, "  B %s\n", l.c_str());
		stice_destroy(a); stice_destroy(b);
		return 1;
	}

	std::fprintf(stderr, "CONNECTED: A=%d B=%d\n", (int)sa.state.load(), (int)sb.state.load());
	stice_destroy(a);
	stice_destroy(b);
	return 0;
}
