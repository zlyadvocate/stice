// SPDX-License-Identifier: MPL-2.0
// Mixed stress test: N ICE-UDP pairs + M1 TURN-UDP + M2 TURN-TCP background.
// Verifies stserver D-plan (IOCP/epoll) handles mixed workloads where many
// direct ICE pairs coexist with TURN relay sessions.
//
// Usage: test_stserver_stress_mixed [host] [port] [icePairs] [turnUdpBg] [turnTcpBg] [timeoutMs]
// Defaults: host=127.0.0.1 port=3478 icePairs=1000 turnUdpBg=20 turnTcpBg=20 timeoutMs=30000

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
#include <vector>

using namespace std::chrono_literals;

// ---- Per-agent state ----
struct AgentState {
	std::atomic<stice_state_t> state{STICE_STATE_DISCONNECTED};
	std::atomic<bool> gatheringDone{false};
	std::vector<std::string> candidates;
	std::mutex candidatesMutex;
	std::vector<std::string> received;
	std::mutex receivedMutex;
	std::chrono::steady_clock::time_point createdAt;
	std::chrono::steady_clock::time_point connectedAt;
	// ICE 连接真正的起点：remote gathering done 被设置之后。
	// 之前测量 createdAt → connectedAt 包含了串行 create/gather/SDP 开销，
	// 不能反映真实的 ICE connectivity check 延迟。
	std::chrono::steady_clock::time_point connectStartAt;
};

static stice_config_t makeConfig(AgentState &s, bool usePoll) {
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
	if (usePoll) {
		cfg.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
	}
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

// Filter SDP to TCP-only candidates (for ICE-TCP tests).
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
			if (line.find("tcptype") != std::string::npos)
				out += line + "\n";
		}
	}
	return out;
}

// ---- A "pair group" bundles a set of agent pairs of the same transport kind ----
enum class GroupKind { IceUdp, IceTcp, TurnUdp, TurnTcp };

struct PairResult {
	bool gatherOk = false;
	bool connectOk = false;
	bool dataOk = false;
	int connectMs = 0;
	std::string failReason;
};

struct PairGroup {
	GroupKind kind;
	std::vector<std::unique_ptr<AgentState>> statesA, statesB;
	std::vector<stice_agent_t *> agentsA, agentsB;
	std::vector<PairResult> results;
	int connectOkCount = 0;
	int gatherOkCount = 0;
	int dataOkCount = 0;

	void reserve(int n) {
		statesA.reserve(n);
		statesB.reserve(n);
		agentsA.reserve(n);
		agentsB.reserve(n);
		results.resize(n);
	}

	const char *name() const {
		switch (kind) {
		case GroupKind::IceUdp:  return "ICE-UDP";
		case GroupKind::IceTcp:  return "ICE-TCP";
		case GroupKind::TurnUdp: return "TURN-UDP";
		case GroupKind::TurnTcp: return "TURN-TCP";
		}
		return "?";
	}
};

int main(int argc, char **argv) {
	const char *host = argc > 1 ? argv[1] : "127.0.0.1";
	uint16_t port = argc > 2 ? static_cast<uint16_t>(std::atoi(argv[2])) : 3478;
	int icePairs   = argc > 3 ? std::atoi(argv[3]) : 1000;
	int iceTcpPairs= argc > 4 ? std::atoi(argv[4]) : 0;        // ICE-TCP pairs
	int turnUdpBg  = argc > 5 ? std::atoi(argv[5]) : 20;
	int turnTcpBg  = argc > 6 ? std::atoi(argv[6]) : 20;
	int timeoutMs  = argc > 7 ? std::atoi(argv[7]) : 30000;
	int batchSize  = argc > 8 ? std::atoi(argv[8]) : 0;        // 0 = 全部一次加载
	int batchDelayMs = argc > 9 ? std::atoi(argv[9]) : 0;      // 批间延时

	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	int totalPairs = icePairs + iceTcpPairs + turnUdpBg + turnTcpBg;
	std::fprintf(stderr,
	    "=== stserver mixed stress: %s:%u  ICE-UDP=%d  ICE-TCP=%d  TURN-UDP=%d  TURN-TCP=%d  timeout=%dms\n"
	    "    batchSize=%d  batchDelay=%dms ===\n",
	    host, port, icePairs, iceTcpPairs, turnUdpBg, turnTcpBg, timeoutMs,
	    batchSize, batchDelayMs);

	// Build the four groups.
	PairGroup iceGroup;   iceGroup.kind = GroupKind::IceUdp;  iceGroup.reserve(icePairs);
	PairGroup itGroup;    itGroup.kind  = GroupKind::IceTcp;  itGroup.reserve(iceTcpPairs);
	PairGroup tuGroup;    tuGroup.kind  = GroupKind::TurnUdp; tuGroup.reserve(turnUdpBg);
	PairGroup ttGroup;    ttGroup.kind  = GroupKind::TurnTcp; ttGroup.reserve(turnTcpBg);

	// Per-pair TCPMux for ICE-TCP passive agents. Shared TCPMux has concurrency
	// limits with multiple simultaneous TCP connections; per-pair mux is more
	// realistic and avoids races in high-concurrency stress tests.
	std::vector<stice_tcp_mux_t *> itMuxes;

	// TURN server config for relay groups.
	auto addTurnServer = [&](stice_agent_t *a, stice_turn_transport_t t) {
		stice_turn_server_t turn{};
		turn.host = const_cast<char *>(host);
		turn.port = port;
		turn.username = const_cast<char *>("testuser");
		turn.password = const_cast<char *>("123456");
		turn.transport = t;
		stice_add_turn_server(a, &turn);
	};

	auto t0 = std::chrono::steady_clock::now();

	// Helper: create + gather for a single pair. ICE-TCP needs special handling
	// (TCPMux + pre-gather SDP exchange for ufrag/pwd).
	auto setupOnePair = [&](PairGroup &g, int idx, bool useTurn, bool useTcp, bool relayOnly) {
		g.statesA.push_back(std::make_unique<AgentState>());
		g.statesB.push_back(std::make_unique<AgentState>());
		bool poll = useTcp;
		auto cfgA = makeConfig(*g.statesA[idx], poll);
		auto cfgB = makeConfig(*g.statesB[idx], poll);
		bool isIceTcp = (g.kind == GroupKind::IceTcp);
		if (!isIceTcp) {
			cfgA.stun_server_host = host;
			cfgA.stun_server_port = port;
			cfgB.stun_server_host = host;
			cfgB.stun_server_port = port;
		}
		g.statesA[idx]->createdAt = std::chrono::steady_clock::now();
		g.statesB[idx]->createdAt = std::chrono::steady_clock::now();
		g.agentsA.push_back(stice_create(&cfgA));
		g.agentsB.push_back(stice_create(&cfgB));
		if (!g.agentsA[idx] || !g.agentsB[idx]) {
			g.results[idx].failReason = "create failed";
			return;
		}
		if (useTurn) {
			auto t = useTcp ? STICE_TURN_TRANSPORT_TCP : STICE_TURN_TRANSPORT_UDP;
			addTurnServer(g.agentsA[idx], t);
			addTurnServer(g.agentsB[idx], t);
		}
		// ICE-TCP: A=passive (per-pair TCPMux), B=active. Must exchange ufrag/pwd
		// BEFORE gathering so the passive side can route incoming TCP connections.
		if (isIceTcp) {
			stice_tcp_mux_t *mux = stice_create_tcp_mux("127.0.0.1", 0);
			itMuxes.push_back(mux);
			stice_set_ice_tcp_mode(g.agentsA[idx], STICE_ICE_TCP_MODE_PASSIVE);
			stice_agent_use_tcp_mux(g.agentsA[idx], mux);
			stice_set_ice_tcp_mode(g.agentsB[idx], STICE_ICE_TCP_MODE_ACTIVE);
			char sdpA[4096], sdpB[4096];
			stice_get_local_description(g.agentsA[idx], sdpA, sizeof(sdpA));
			stice_get_local_description(g.agentsB[idx], sdpB, sizeof(sdpB));
			stice_set_remote_description(g.agentsA[idx], sdpB);
			stice_set_remote_description(g.agentsB[idx], sdpA);
		}
		// Gather
		stice_gather_candidates(g.agentsB[idx]);
		stice_gather_candidates(g.agentsA[idx]);
	};

	// Helper: wait for gather + exchange SDP for a single pair.
	// relayOnly=true → TURN groups (filter to relay candidates)
	// isIceTcp=true  → trickle only TCP candidates (ufrag/pwd already exchanged)
	auto finalizeOnePair = [&](PairGroup &g, int idx, bool relayOnly) {
		if (!g.agentsA[idx] || !g.agentsB[idx]) return;
		bool ga = waitFor([&] { return g.statesA[idx]->gatheringDone.load(); }, 15000);
		bool gb = waitFor([&] { return g.statesB[idx]->gatheringDone.load(); }, 15000);
		if (ga && gb) {
			g.results[idx].gatherOk = true;
			++g.gatherOkCount;
		} else {
			g.results[idx].failReason = "gather timeout";
			return;
		}
		bool isIceTcp = (g.kind == GroupKind::IceTcp);
		if (isIceTcp) {
			// ICE-TCP: candidates are only available via cb_candidate callback.
			// A=passive has TCP candidates (tcptype passive). B=active has none
			// (it initiates connections, doesn't listen). Forward A's TCP
			// candidates to B; B doesn't need to send any to A.
			std::vector<std::string> aTcpCands, bTcpCands;
			{
				std::lock_guard<std::mutex> lk(g.statesA[idx]->candidatesMutex);
				for (const auto &c : g.statesA[idx]->candidates) {
					if (c.find("tcptype") != std::string::npos)
						aTcpCands.push_back(c);
				}
			}
			{
				std::lock_guard<std::mutex> lk(g.statesB[idx]->candidatesMutex);
				for (const auto &c : g.statesB[idx]->candidates) {
					if (c.find("tcptype") != std::string::npos)
						bTcpCands.push_back(c);
				}
			}
			if (aTcpCands.empty() && bTcpCands.empty()) {
				g.results[idx].failReason = "no tcp candidate";
				return;
			}
			// Trickle: A's TCP candidates → B, B's → A (B may have none)
			for (const auto &c : bTcpCands)
				stice_add_remote_candidate(g.agentsA[idx], c.c_str());
			for (const auto &c : aTcpCands)
				stice_add_remote_candidate(g.agentsB[idx], c.c_str());
		} else {
			// Exchange SDP / trickle candidates
			char bufA[4096], bufB[4096];
			stice_get_local_description(g.agentsA[idx], bufA, sizeof(bufA));
			stice_get_local_description(g.agentsB[idx], bufB, sizeof(bufB));
			std::string sdpA = relayOnly ? filterRelayOnly(bufA) : std::string(bufA);
			std::string sdpB = relayOnly ? filterRelayOnly(bufB) : std::string(bufB);
			if (relayOnly) {
				if (sdpA.find("typ relay") == std::string::npos ||
				    sdpB.find("typ relay") == std::string::npos) {
					g.results[idx].failReason = "no relay candidate";
					return;
				}
			}
			stice_set_remote_description(g.agentsA[idx], sdpB.c_str());
			stice_set_remote_description(g.agentsB[idx], sdpA.c_str());
		}
		stice_set_remote_gathering_done(g.agentsA[idx]);
		stice_set_remote_gathering_done(g.agentsB[idx]);
		g.statesA[idx]->connectStartAt = std::chrono::steady_clock::now();
	};

	if (batchSize <= 0) {
		// ---- 全量模式 (原逻辑) ----
		std::fprintf(stderr, "[phase1-3] full-load: create+gather+SDP all %d pairs...\n", totalPairs);

		auto createGroup = [&](PairGroup &g, int n, bool useTurn, bool useTcp) {
			for (int i = 0; i < n; ++i) {
				setupOnePair(g, i, useTurn, useTcp, false);
			}
		};
		createGroup(iceGroup, icePairs, false, false);
		if (iceTcpPairs > 0) createGroup(itGroup, iceTcpPairs, false, true);
		createGroup(tuGroup,  turnUdpBg, true, false);
		createGroup(ttGroup,  turnTcpBg, true, true);

		std::fprintf(stderr, "[phase1] create done in %lldms\n",
		    (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
		        std::chrono::steady_clock::now() - t0).count());

		// Wait for all gatherings + exchange SDP
		auto t1 = std::chrono::steady_clock::now();
		auto finalizeGroup = [&](PairGroup &g, bool relayOnly) {
			for (size_t i = 0; i < g.agentsA.size(); ++i) {
				finalizeOnePair(g, static_cast<int>(i), relayOnly);
			}
		};
		finalizeGroup(iceGroup, false);
		if (iceTcpPairs > 0) finalizeGroup(itGroup, false);
		finalizeGroup(tuGroup, true);
		finalizeGroup(ttGroup, true);

		std::fprintf(stderr, "[phase2-3] gather+SDP done in %lldms  gather: ICE=%d/%d IT=%d/%d TU=%d/%d TT=%d/%d\n",
		    (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
		        std::chrono::steady_clock::now() - t1).count(),
		    iceGroup.gatherOkCount, icePairs,
		    itGroup.gatherOkCount, iceTcpPairs,
		    tuGroup.gatherOkCount, turnUdpBg,
		    ttGroup.gatherOkCount, turnTcpBg);
	} else {
		// ---- 分批模式 ----
		// 每批: 创建 batchSize 个 ICE-UDP pair → gather → SDP → 延时 → 下一批
		// ICE-TCP + TURN bg pairs 在第一批一起创建。
		std::fprintf(stderr, "[batch] loading ICE-UDP in batches of %d (delay=%dms)...\n",
		    batchSize, batchDelayMs);

		int iceCreated = 0;
		int batchNum = 0;
		while (iceCreated < icePairs) {
			int thisBatch = std::min(batchSize, icePairs - iceCreated);
			auto batchStart = std::chrono::steady_clock::now();

			// First batch: also create ICE-TCP + TURN bg pairs.
			if (batchNum == 0) {
				for (int i = 0; i < iceTcpPairs; ++i)
					setupOnePair(itGroup, i, false, true, false);
				for (int i = 0; i < turnUdpBg; ++i)
					setupOnePair(tuGroup, i, true, false, false);
				for (int i = 0; i < turnTcpBg; ++i)
					setupOnePair(ttGroup, i, true, true, false);
			}

			// Create this batch of ICE-UDP pairs.
			for (int i = 0; i < thisBatch; ++i) {
				setupOnePair(iceGroup, iceCreated + i, false, false, false);
			}

			// Finalize (gather + SDP) this batch.
			for (int i = 0; i < thisBatch; ++i) {
				finalizeOnePair(iceGroup, iceCreated + i, false);
			}
			// First batch: finalize ICE-TCP + TURN pairs too.
			if (batchNum == 0) {
				for (int i = 0; i < iceTcpPairs; ++i)
					finalizeOnePair(itGroup, i, false);
				for (int i = 0; i < turnUdpBg; ++i)
					finalizeOnePair(tuGroup, i, true);
				for (int i = 0; i < turnTcpBg; ++i)
					finalizeOnePair(ttGroup, i, true);
			}

			auto batchMs = std::chrono::duration_cast<std::chrono::milliseconds>(
			    std::chrono::steady_clock::now() - batchStart).count();
			std::fprintf(stderr, "  batch %d: ICE-UDP %d-%d/%d  (%lldms)\n",
			    batchNum, iceCreated, iceCreated + thisBatch - 1, icePairs, (long long)batchMs);

			iceCreated += thisBatch;
			++batchNum;
			if (iceCreated < icePairs && batchDelayMs > 0) {
				std::this_thread::sleep_for(std::chrono::milliseconds(batchDelayMs));
			}
		}
		std::fprintf(stderr, "[batch] all %d batches done in %lldms\n",
		    batchNum, (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
		        std::chrono::steady_clock::now() - t0).count());
	}

	// Wait for all pairs to reach CONNECTED/COMPLETED — global concurrent wait
	// with a single deadline, so failing pairs don't each block for timeoutMs.
	auto waitConnectAll = [&](PairGroup &g, int globalTimeoutMs) {
		auto deadline = std::chrono::steady_clock::now() +
		    std::chrono::milliseconds(globalTimeoutMs);
		// Mark candidates: pairs eligible for connect wait.
		std::vector<size_t> pending;
		for (size_t i = 0; i < g.agentsA.size(); ++i) {
			if (!g.results[i].gatherOk) continue;
			if (!g.results[i].failReason.empty()) continue; // e.g. "no relay candidate"
			pending.push_back(i);
		}
		// Poll loop: check all pending pairs each tick.
		while (!pending.empty()) {
			auto now = std::chrono::steady_clock::now();
			if (now >= deadline) break;
			for (auto it = pending.begin(); it != pending.end(); ) {
				size_t i = *it;
				auto as = g.statesA[i]->state.load();
				auto bs = g.statesB[i]->state.load();
				if ((as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
				    (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED)) {
					g.results[i].connectOk = true;
					// 真实 ICE 连接延迟 = connectedAt - connectStartAt
					// (不含串行 create/gather/SDP 交换开销)
					auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(
					    g.statesA[i]->connectedAt - g.statesA[i]->connectStartAt);
					g.results[i].connectMs = static_cast<int>(dur.count());
					++g.connectOkCount;
					it = pending.erase(it);
				} else {
					++it;
				}
			}
			if (!pending.empty()) std::this_thread::sleep_for(10ms);
		}
		// Remaining pending pairs timed out.
		for (size_t i : pending) {
			g.results[i].failReason = "connect timeout A=" +
			    std::to_string(static_cast<int>(g.statesA[i]->state.load())) +
			    " B=" + std::to_string(static_cast<int>(g.statesB[i]->state.load()));
		}
	};
	waitConnectAll(iceGroup, timeoutMs);
	if (iceTcpPairs > 0) waitConnectAll(itGroup, timeoutMs);
	waitConnectAll(tuGroup, timeoutMs);
	waitConnectAll(ttGroup, timeoutMs);

	std::fprintf(stderr,
	    "[connect] done in %lldms  connect: ICE=%d/%d IT=%d/%d TU=%d/%d TT=%d/%d\n",
	    (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
	        std::chrono::steady_clock::now() - t0).count(),
	    iceGroup.connectOkCount, icePairs,
	    itGroup.connectOkCount, iceTcpPairs,
	    tuGroup.connectOkCount, turnUdpBg,
	    ttGroup.connectOkCount, turnTcpBg);

	// ---- Phase 4: data exchange ----
	auto t3 = std::chrono::steady_clock::now();
	std::fprintf(stderr, "[phase4] data exchange...\n");

	auto dataExchange = [&](PairGroup &g) {
		// Send data on all connected pairs first.
		for (size_t i = 0; i < g.agentsA.size(); ++i) {
			if (!g.results[i].connectOk) continue;
			std::string msgA = "p" + std::to_string(i) + "A";
			std::string msgB = "p" + std::to_string(i) + "B";
			stice_send(g.agentsA[i], msgA.data(), msgA.size());
			stice_send(g.agentsB[i], msgB.data(), msgB.size());
		}
		// Wait for data on all connected pairs concurrently (global 5s deadline).
		std::vector<size_t> pending;
		for (size_t i = 0; i < g.agentsA.size(); ++i) {
			if (!g.results[i].connectOk) continue;
			pending.push_back(i);
		}
		auto deadline = std::chrono::steady_clock::now() + 5s;
		while (!pending.empty()) {
			if (std::chrono::steady_clock::now() >= deadline) break;
			for (auto it = pending.begin(); it != pending.end(); ) {
				size_t i = *it;
				if (g.statesA[i]->received.size() >= 1 && g.statesB[i]->received.size() >= 1) {
					g.results[i].dataOk = true;
					++g.dataOkCount;
					it = pending.erase(it);
				} else {
					++it;
				}
			}
			if (!pending.empty()) std::this_thread::sleep_for(5ms);
		}
		for (size_t i : pending) {
			g.results[i].failReason = "data timeout A=" +
			    std::to_string(g.statesA[i]->received.size()) +
			    " B=" + std::to_string(g.statesB[i]->received.size());
		}
	};
	dataExchange(iceGroup);
	if (iceTcpPairs > 0) dataExchange(itGroup);
	dataExchange(tuGroup);
	dataExchange(ttGroup);

	std::fprintf(stderr,
	    "[phase4] done in %lldms  data: ICE=%d/%d IT=%d/%d TU=%d/%d TT=%d/%d\n",
	    (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
	        std::chrono::steady_clock::now() - t3).count(),
	    iceGroup.dataOkCount, icePairs,
	    itGroup.dataOkCount, iceTcpPairs,
	    tuGroup.dataOkCount, turnUdpBg,
	    ttGroup.dataOkCount, turnTcpBg);

	// ---- Phase 5: cleanup ----
	auto t4 = std::chrono::steady_clock::now();
	std::fprintf(stderr, "[phase5] destroying %d agents...\n", totalPairs * 2);
	auto cleanupGroup = [&](PairGroup &g) {
		for (size_t i = 0; i < g.agentsA.size(); ++i) {
			if (g.agentsA[i]) stice_destroy(g.agentsA[i]);
			if (g.agentsB[i]) stice_destroy(g.agentsB[i]);
		}
	};
	cleanupGroup(iceGroup);
	if (iceTcpPairs > 0) cleanupGroup(itGroup);
	cleanupGroup(tuGroup);
	cleanupGroup(ttGroup);
	for (auto *mux : itMuxes) {
		if (mux) stice_destroy_tcp_mux(mux);
	}
	std::fprintf(stderr, "[phase5] done in %lldms\n",
	    (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
	        std::chrono::steady_clock::now() - t4).count());

	// ---- Summary ----
	auto totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(
	    std::chrono::steady_clock::now() - t0).count();

	auto printLatency = [](PairGroup &g) {
		if (g.connectOkCount == 0) return;
		long long sum = 0;
		int mn = INT32_MAX, mx = 0;
		for (auto &r : g.results) {
			if (!r.connectOk) continue;
			sum += r.connectMs;
			if (r.connectMs < mn) mn = r.connectMs;
			if (r.connectMs > mx) mx = r.connectMs;
		}
		std::fprintf(stderr, "  %s latency: min=%dms avg=%lldms max=%dms\n",
		    g.name(), mn, sum / g.connectOkCount, mx);
	};

	int totalDataOk = iceGroup.dataOkCount + itGroup.dataOkCount +
	    tuGroup.dataOkCount + ttGroup.dataOkCount;
	std::fprintf(stderr, "\n=== SUMMARY ===\n");
	std::fprintf(stderr, "totalPairs:  %d (%d ICE-UDP + %d ICE-TCP + %d TU + %d TT)\n",
	    totalPairs, icePairs, iceTcpPairs, turnUdpBg, turnTcpBg);
	std::fprintf(stderr, "ICE-UDP:  gather=%d/%d connect=%d/%d data=%d/%d\n",
	    iceGroup.gatherOkCount, icePairs, iceGroup.connectOkCount, icePairs,
	    iceGroup.dataOkCount, icePairs);
	if (iceTcpPairs > 0)
	std::fprintf(stderr, "ICE-TCP:  gather=%d/%d connect=%d/%d data=%d/%d\n",
	    itGroup.gatherOkCount, iceTcpPairs, itGroup.connectOkCount, iceTcpPairs,
	    itGroup.dataOkCount, iceTcpPairs);
	std::fprintf(stderr, "TURN-UDP: gather=%d/%d connect=%d/%d data=%d/%d\n",
	    tuGroup.gatherOkCount, turnUdpBg, tuGroup.connectOkCount, turnUdpBg,
	    tuGroup.dataOkCount, turnUdpBg);
	std::fprintf(stderr, "TURN-TCP: gather=%d/%d connect=%d/%d data=%d/%d\n",
	    ttGroup.gatherOkCount, turnTcpBg, ttGroup.connectOkCount, turnTcpBg,
	    ttGroup.dataOkCount, turnTcpBg);
	std::fprintf(stderr, "totalDataOk: %d / %d\n", totalDataOk, totalPairs);
	std::fprintf(stderr, "totalTime:   %lldms\n", (long long)totalMs);
	printLatency(iceGroup);
	if (iceTcpPairs > 0) printLatency(itGroup);
	printLatency(tuGroup);
	printLatency(ttGroup);

	// Print failures (limited to first 10 per group).
	auto printFailures = [](PairGroup &g) {
		int shown = 0;
		for (size_t i = 0; i < g.results.size() && shown < 10; ++i) {
			if (g.results[i].dataOk) continue;
			std::fprintf(stderr, "  %s pair %zu: %s\n", g.name(), i, g.results[i].failReason.c_str());
			++shown;
		}
	};
	int totalFail = totalPairs - totalDataOk;
	if (totalFail > 0) {
		std::fprintf(stderr, "\n=== FAILURES (%d) ===\n", totalFail);
		printFailures(iceGroup);
		if (iceTcpPairs > 0) printFailures(itGroup);
		printFailures(tuGroup);
		printFailures(ttGroup);
	}

	std::fprintf(stderr, "\n=== %s: %d/%d pairs fully OK ===\n",
	    totalDataOk == totalPairs ? "PASS" : "FAIL", totalDataOk, totalPairs);
	return totalDataOk == totalPairs ? 0 : 1;
}
