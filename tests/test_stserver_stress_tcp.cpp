// SPDX-License-Identifier: MPL-2.0
// High-concurrency stserver TCP stability test.
// Creates N pairs of stice agents, all using TURN over TCP (RFC 6062 Mode-B)
// through stserver, and verifies every pair reaches CONNECTED and exchanges
// data. Reports success rate, timing, and per-pair failures.
//
// Usage: stserver_stress_tcp [host] [port] [pairs] [connect_timeout_ms]
// Defaults: host=127.0.0.1 port=13478 pairs=20 connect_timeout_ms=20000

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
	std::chrono::steady_clock::time_point createdAt;
	std::chrono::steady_clock::time_point connectedAt;
};

static stice_config_t makeConfig(AgentState &s) {
	stice_config_t cfg{};
	cfg.cb_state_changed = [](stice_agent_t *, stice_state_t st, void *u) {
		auto *s = static_cast<AgentState *>(u);
		s->state.store(st);
		if (st == STICE_STATE_CONNECTED || st == STICE_STATE_COMPLETED) {
			s->connectedAt = std::chrono::steady_clock::now();
		}
	};
	cfg.cb_candidate = [](stice_agent_t *, const char *c, void *u) {
		auto *s = static_cast<AgentState *>(u);
		std::lock_guard<std::mutex> lk(s->candidatesMutex);
		s->candidates.emplace_back(c);
	};
	cfg.cb_gathering_done = [](stice_agent_t *, void *u) {
		static_cast<AgentState *>(u)->gatheringDone.store(true);
	};
	cfg.cb_recv = [](stice_agent_t *, const char *d, size_t n, void *u) {
		auto *s = static_cast<AgentState *>(u);
		std::lock_guard<std::mutex> lk(s->receivedMutex);
		s->received.emplace_back(d, n);
	};
	cfg.user_ptr = &s;
	cfg.bind_address = nullptr;
	cfg.local_port_range_begin = 0;
	cfg.local_port_range_end = 0;
	// POLL mode is mandatory for TURN over TCP (per-agent thread model).
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

struct PairResult {
	bool gatherOk = false;
	bool connectOk = false;
	bool dataOk = false;
	int connectMs = 0;
	std::string failReason;
};

int main(int argc, char **argv) {
	const char *host = argc > 1 ? argv[1] : "127.0.0.1";
	uint16_t port = argc > 2 ? static_cast<uint16_t>(std::atoi(argv[2])) : 13478;
	int pairs = argc > 3 ? std::atoi(argv[3]) : 20;
	int connectTimeoutMs = argc > 4 ? std::atoi(argv[4]) : 20000;

	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	std::fprintf(stderr, "=== stserver TCP stress: %s:%u pairs=%d timeout=%dms ===\n",
	             host, port, pairs, connectTimeoutMs);

	stice_turn_server_t turn{};
	turn.host = const_cast<char *>(host);
	turn.port = port;
	turn.username = const_cast<char *>("testuser");
	turn.password = const_cast<char *>("123456");
	turn.transport = STICE_TURN_TRANSPORT_TCP;

	std::vector<std::unique_ptr<AgentState>> statesA, statesB;
	std::vector<stice_agent_t *> agentsA, agentsB;
	std::vector<PairResult> results(pairs);

	statesA.reserve(pairs);
	statesB.reserve(pairs);
	agentsA.reserve(pairs);
	agentsB.reserve(pairs);

	auto t0 = std::chrono::steady_clock::now();

	// Phase 1: create all agents concurrently.
	std::fprintf(stderr, "[phase1] creating %d agent pairs...\n", pairs);
	for (int i = 0; i < pairs; ++i) {
		statesA.push_back(std::make_unique<AgentState>());
		statesB.push_back(std::make_unique<AgentState>());
		auto cfgA = makeConfig(*statesA[i]);
		auto cfgB = makeConfig(*statesB[i]);
		cfgA.stun_server_host = host;
		cfgA.stun_server_port = port;
		cfgB.stun_server_host = host;
		cfgB.stun_server_port = port;
		statesA[i]->createdAt = std::chrono::steady_clock::now();
		statesB[i]->createdAt = std::chrono::steady_clock::now();
		agentsA.push_back(stice_create(&cfgA));
		agentsB.push_back(stice_create(&cfgB));
		if (!agentsA[i] || !agentsB[i]) {
			results[i].failReason = "create failed";
			std::fprintf(stderr, "  pair %d: CREATE FAILED\n", i);
			continue;
		}
		stice_add_turn_server(agentsA[i], &turn);
		stice_add_turn_server(agentsB[i], &turn);
	}
	std::fprintf(stderr, "[phase1] done in %lldms\n",
	             (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
	                 std::chrono::steady_clock::now() - t0).count());

	// Phase 2: gather candidates on all agents simultaneously.
	auto t1 = std::chrono::steady_clock::now();
	std::fprintf(stderr, "[phase2] gathering candidates on %d agents...\n", pairs * 2);
	for (int i = 0; i < pairs; ++i) {
		if (!agentsA[i] || !agentsB[i]) continue;
		stice_gather_candidates(agentsB[i]);
		stice_gather_candidates(agentsA[i]);
	}

	// Wait for all gatherings to complete.
	int gatherOkCount = 0;
	for (int i = 0; i < pairs; ++i) {
		if (!agentsA[i] || !agentsB[i]) continue;
		bool ga = waitFor([&] { return statesA[i]->gatheringDone.load(); }, 15000);
		bool gb = waitFor([&] { return statesB[i]->gatheringDone.load(); }, 15000);
		if (ga && gb) {
			results[i].gatherOk = true;
			++gatherOkCount;
		} else {
			results[i].failReason = "gather timeout";
		}
	}
	std::fprintf(stderr, "[phase2] done in %lldms  gatherOk=%d/%d\n",
	             (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
	                 std::chrono::steady_clock::now() - t1).count(),
	             gatherOkCount, pairs);

	// Phase 3: exchange relay-only SDP and wait for CONNECTED.
	auto t2 = std::chrono::steady_clock::now();
	std::fprintf(stderr, "[phase3] exchanging SDP and connecting %d pairs...\n", pairs);
	for (int i = 0; i < pairs; ++i) {
		if (!results[i].gatherOk) continue;
		char bufA[4096], bufB[4096];
		stice_get_local_description(agentsA[i], bufA, sizeof(bufA));
		stice_get_local_description(agentsB[i], bufB, sizeof(bufB));
		std::string sdpA = filterRelayOnly(bufA);
		std::string sdpB = filterRelayOnly(bufB);
		if (sdpA.find("typ relay") == std::string::npos ||
		    sdpB.find("typ relay") == std::string::npos) {
			results[i].failReason = "no relay candidate";
			continue;
		}
		stice_set_remote_description(agentsA[i], sdpB.c_str());
		stice_set_remote_description(agentsB[i], sdpA.c_str());
		stice_set_remote_gathering_done(agentsA[i]);
		stice_set_remote_gathering_done(agentsB[i]);
	}

	// Wait for all pairs to reach CONNECTED/COMPLETED.
	int connectOkCount = 0;
	for (int i = 0; i < pairs; ++i) {
		if (!results[i].gatherOk) continue;
		bool ok = waitFor([&] {
			auto as = statesA[i]->state.load();
			auto bs = statesB[i]->state.load();
			return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
			       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
		}, connectTimeoutMs);
		if (ok) {
			results[i].connectOk = true;
			auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(
			               statesA[i]->connectedAt - statesA[i]->createdAt);
			results[i].connectMs = static_cast<int>(dur.count());
			++connectOkCount;
		} else {
			results[i].failReason = "connect timeout A=" +
			    std::to_string(static_cast<int>(statesA[i]->state.load())) +
			    " B=" + std::to_string(static_cast<int>(statesB[i]->state.load()));
		}
	}
	std::fprintf(stderr, "[phase3] done in %lldms  connectOk=%d/%d\n",
	             (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
	                 std::chrono::steady_clock::now() - t2).count(),
	             connectOkCount, pairs);

	// Phase 4: bidirectional data exchange on all connected pairs.
	auto t3 = std::chrono::steady_clock::now();
	std::fprintf(stderr, "[phase4] data exchange on %d pairs...\n", connectOkCount);
	for (int i = 0; i < pairs; ++i) {
		if (!results[i].connectOk) continue;
		std::string msgA = "pair-" + std::to_string(i) + "-A";
		std::string msgB = "pair-" + std::to_string(i) + "-B";
		stice_send(agentsA[i], msgA.data(), msgA.size());
		stice_send(agentsB[i], msgB.data(), msgB.size());
	}
	// Wait for data to arrive.
	int dataOkCount = 0;
	for (int i = 0; i < pairs; ++i) {
		if (!results[i].connectOk) continue;
		bool ra = waitFor([&] { return statesA[i]->received.size() >= 1; }, 5000);
		bool rb = waitFor([&] { return statesB[i]->received.size() >= 1; }, 5000);
		if (ra && rb) {
			results[i].dataOk = true;
			++dataOkCount;
		} else {
			results[i].failReason = "data timeout A=" +
			    std::to_string(statesA[i]->received.size()) +
			    " B=" + std::to_string(statesB[i]->received.size());
		}
	}
	std::fprintf(stderr, "[phase4] done in %lldms  dataOk=%d/%d\n",
	             (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
	                 std::chrono::steady_clock::now() - t3).count(),
	             dataOkCount, pairs);

	// Phase 5: cleanup all agents.
	auto t4 = std::chrono::steady_clock::now();
	std::fprintf(stderr, "[phase5] destroying %d agents...\n", pairs * 2);
	for (int i = 0; i < pairs; ++i) {
		if (agentsA[i]) stice_destroy(agentsA[i]);
		if (agentsB[i]) stice_destroy(agentsB[i]);
	}
	std::fprintf(stderr, "[phase5] done in %lldms\n",
	             (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
	                 std::chrono::steady_clock::now() - t4).count());

	// Summary
	auto totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(
	                   std::chrono::steady_clock::now() - t0).count();
	std::fprintf(stderr, "\n=== SUMMARY ===\n");
	std::fprintf(stderr, "pairs:       %d\n", pairs);
	std::fprintf(stderr, "gatherOk:    %d / %d  (%.1f%%)\n", gatherOkCount, pairs,
	             pairs ? 100.0 * gatherOkCount / pairs : 0);
	std::fprintf(stderr, "connectOk:   %d / %d  (%.1f%%)\n", connectOkCount, pairs,
	             pairs ? 100.0 * connectOkCount / pairs : 0);
	std::fprintf(stderr, "dataOk:      %d / %d  (%.1f%%)\n", dataOkCount, pairs,
	             pairs ? 100.0 * dataOkCount / pairs : 0);
	std::fprintf(stderr, "totalTime:   %lldms\n", (long long)totalMs);

	if (connectOkCount > 0) {
		long long sumMs = 0;
		int minMs = INT32_MAX, maxMs = 0;
		for (int i = 0; i < pairs; ++i) {
			if (!results[i].connectOk) continue;
			sumMs += results[i].connectMs;
			if (results[i].connectMs < minMs) minMs = results[i].connectMs;
			if (results[i].connectMs > maxMs) maxMs = results[i].connectMs;
		}
		std::fprintf(stderr, "connectLatency: min=%dms avg=%lldms max=%dms\n",
		             minMs, sumMs / connectOkCount, maxMs);
	}

	// Per-pair failure details (if any)
	int failures = pairs - dataOkCount;
	if (failures > 0) {
		std::fprintf(stderr, "\n=== FAILURES (%d) ===\n", failures);
		for (int i = 0; i < pairs; ++i) {
			if (results[i].dataOk) continue;
			std::fprintf(stderr, "  pair %d: %s\n", i, results[i].failReason.c_str());
		}
	}

	std::fprintf(stderr, "\n=== %s: %d/%d pairs fully OK ===\n",
	             dataOkCount == pairs ? "PASS" : "FAIL", dataOkCount, pairs);
	return dataOkCount == pairs ? 0 : 1;
}
