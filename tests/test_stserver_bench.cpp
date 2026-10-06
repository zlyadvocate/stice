// SPDX-License-Identifier: MPL-2.0
// stserver benchmark + demux regression test.
//
// Usage: test_stserver_bench [host] [port]
// Defaults: host=127.0.0.1 port=13478 (run stserver there first).
//
// Phases:
//   1. Demux regression: application payloads whose first bytes look like a
//      ChannelData frame ('ABCD' = 0x41 0x42 0x43 0x44, length field
//      0x4344 = 17220) must be delivered, not dropped. Before the
//      source-address demux fix, any payload >= 17224 bytes whose first 4
//      bytes matched was misparsed as ChannelData and silently discarded.
//      Tests A(relay) -> B(host) at 8KB / 20KB / 32KB and B -> A at 20KB.
//   2. Forwarding latency: 64-byte ping-pong through the relay, N rounds,
//      RTT/2 histogram (min/avg/median/p95/max). Includes agent poll
//      granularity (event-driven, not timer-quantized).
//   3. Throughput: windowed bulk transfer A -> B (1200-byte datagrams),
//      loss-free sustained goodput in Mbps.
//
// Agent topology: A = TURN relay-only candidate; B = host candidate only.
// A -> B traffic reaches B from A's relayed address (NOT the TURN control
// endpoint), exercising the peer-data demux path on B.

#ifndef STICE_STATIC
#define STICE_STATIC
#endif

#include "stice/stice.h"
#include "stice/log.hpp"

#include <algorithm>
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
	std::mutex recvMutex;
	std::vector<std::string> received;
	std::atomic<size_t> recvCount{0};
	std::atomic<size_t> recvBytes{0};
	stice_agent_t *agent = nullptr;
	// Echo mode: bounce every received message back (set on B only).
	bool echo = false;
};

static stice_config_t makeConfig(AgentState &s) {
	stice_config_t cfg{};
	cfg.cb_state_changed = [](stice_agent_t *, stice_state_t st, void *u) {
		static_cast<AgentState *>(u)->state.store(st);
	};
	cfg.cb_candidate = [](stice_agent_t *, const char *c, void *u) {
		static_cast<AgentState *>(u)->candidates.emplace_back(c);
	};
	cfg.cb_gathering_done = [](stice_agent_t *, void *u) {
		static_cast<AgentState *>(u)->gatheringDone.store(true);
	};
	cfg.cb_recv = [](stice_agent_t *, const char *d, size_t n, void *u) {
		auto *s = static_cast<AgentState *>(u);
		{
			std::lock_guard<std::mutex> lk(s->recvMutex);
			s->received.emplace_back(d, n);
		}
		s->recvBytes.fetch_add(n);
		s->recvCount.fetch_add(1);
		if (s->echo && s->agent) stice_send(s->agent, d, n);
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
		std::this_thread::sleep_for(5ms);
	}
}

// Spin-wait (yield) for low-latency phases: no sleep quantization.
static bool spinFor(std::atomic<size_t> &counter, size_t target, int timeoutMs) {
	auto start = std::chrono::steady_clock::now();
	while (counter.load(std::memory_order_acquire) < target) {
		std::this_thread::yield();
		auto el = std::chrono::duration_cast<std::chrono::milliseconds>(
		              std::chrono::steady_clock::now() - start);
		if (el.count() >= timeoutMs) return false;
	}
	return true;
}

// Filter SDP to relay-only candidates (agent A).
static std::string filterRelayOnly(const std::string &sdp) {
	std::string out, line;
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

// Host-only candidates (agent B).
static std::string filterHostOnly(const std::string &sdp) {
	std::string out, line;
	std::istringstream iss(sdp);
	while (std::getline(iss, line)) {
		if (line.rfind("a=ice-ufrag:", 0) == 0 ||
		    line.rfind("a=ice-pwd:", 0) == 0 ||
		    line.rfind("a=end-of-candidates", 0) == 0 ||
		    line.rfind("a=ice-options:", 0) == 0) {
			out += line + "\n";
		} else if (line.rfind("a=candidate:", 0) == 0) {
			if (line.find("typ host") != std::string::npos)
				out += line + "\n";
		}
	}
	return out;
}

static std::string makePayload(size_t size, char fill) {
	std::string s(size, fill);
	// 'ABCD' prefix: 0x41 0x42 0x43 0x44 — channel number 0x4142 (valid
	// range) and length field 0x4344 = 17220. A payload >= 17224 bytes
	// looks like a syntactically valid ChannelData frame.
	if (size >= 4) {
		s[0] = 'A';
		s[1] = 'B';
		s[2] = 'C';
		s[3] = 'D';
	}
	return s;
}

static void reportLatency(std::vector<double> &ms) {
	if (ms.empty()) {
		std::fprintf(stderr, "  latency: NO SAMPLES\n");
		return;
	}
	std::sort(ms.begin(), ms.end());
	double sum = 0;
	for (double v : ms) sum += v;
	size_t p95idx = ms.size() * 95 / 100;
	if (p95idx >= ms.size()) p95idx = ms.size() - 1;
	std::fprintf(stderr, "  latency (RTT/2, %zu samples): min=%.3f avg=%.3f median=%.3f p95=%.3f max=%.3f ms\n",
	             ms.size(), ms.front(), sum / ms.size(),
	             ms[ms.size() / 2], ms[p95idx], ms.back());
}

int main(int argc, char **argv) {
	const char *host = argc > 1 ? argv[1] : "127.0.0.1";
	uint16_t port = argc > 2 ? static_cast<uint16_t>(std::atoi(argv[2])) : 13478;

	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	std::fprintf(stderr, "=== stserver bench: %s:%u ===\n", host, port);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);

	cfgA.stun_server_host = host;
	cfgA.stun_server_port = port;

	stice_turn_server_t turn{};
	turn.host = const_cast<char *>(host);
	turn.port = port;
	turn.username = const_cast<char *>("testuser");
	turn.password = const_cast<char *>("123456");
	turn.transport = STICE_TURN_TRANSPORT_UDP;

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	if (!a || !b) { std::fprintf(stderr, "FAIL: create\n"); return 1; }
	sa.agent = a;
	sb.agent = b;
	sb.echo = true; // B echoes everything back
	stice_add_turn_server(a, &turn);

	stice_gather_candidates(b);
	stice_gather_candidates(a);

	if (!waitFor([&] { return sa.gatheringDone.load(); }, 10000)) {
		std::fprintf(stderr, "FAIL: A gathering timeout (no relay?)\n");
		return 1;
	}
	if (!waitFor([&] { return sb.gatheringDone.load(); }, 10000)) {
		std::fprintf(stderr, "FAIL: B gathering timeout\n");
		return 1;
	}

	char bufA[4096], bufB[4096];
	stice_get_local_description(a, bufA, sizeof(bufA));
	stice_get_local_description(b, bufB, sizeof(bufB));
	std::string sdpA = filterRelayOnly(bufA);
	std::string sdpB = filterHostOnly(bufB);
	if (sdpA.find("a=candidate:") == std::string::npos) {
		std::fprintf(stderr, "FAIL: A has no relay candidate\n");
		return 1;
	}
	if (sdpB.find("a=candidate:") == std::string::npos) {
		std::fprintf(stderr, "FAIL: B has no host candidate\n");
		return 1;
	}
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
		return 1;
	}
	std::fprintf(stderr, "CONNECTED (A=relay, B=host)\n");

	bool allOk = true;

	// ---- Phase 1: demux regression (ChannelData-lookalike payloads) ----
	std::fprintf(stderr, "--- phase 1: demux regression ---\n");
	struct DemuxCase { size_t size; const char *name; };
	const DemuxCase cases[] = {
		{8 * 1024, "8KB"},
		{20 * 1024, "20KB"},
		{32 * 1024, "32KB"},
	};
	size_t baseA = sa.recvCount.load(), baseB = sb.recvCount.load();
	for (const auto &c : cases) {
		std::string payload = makePayload(c.size, 'x');
		size_t bBefore = sb.recvCount.load();
		stice_send(a, payload.data(), payload.size());
		bool got = waitFor([&] { return sb.recvCount.load() > bBefore; }, 8000);
		bool ok = false;
		if (got) {
			std::lock_guard<std::mutex> lk(sb.recvMutex);
			for (size_t i = 0; i < sb.received.size(); ++i) {
				const auto &r = sb.received[sb.received.size() - 1 - i];
				if (r == payload) { ok = true; break; }
			}
		}
		std::fprintf(stderr, "  A->B %s 'ABCD'-prefixed payload: %s\n", c.name,
		             ok ? "delivered" : "DROPPED/MISMATCH");
		if (!ok) allOk = false;
	}
	// Reverse direction (genuine ChannelData path, must keep working).
	{
		std::string payload = makePayload(20 * 1024, 'y');
		size_t aBefore = sa.recvCount.load();
		stice_send(b, payload.data(), payload.size());
		bool got = waitFor([&] { return sa.recvCount.load() > aBefore; }, 8000);
		bool ok = false;
		if (got) {
			std::lock_guard<std::mutex> lk(sa.recvMutex);
			for (size_t i = 0; i < sa.received.size(); ++i) {
				const auto &r = sa.received[sa.received.size() - 1 - i];
				if (r == payload) { ok = true; break; }
			}
		}
		std::fprintf(stderr, "  B->A 20KB 'ABCD'-prefixed payload: %s\n",
		             ok ? "delivered" : "DROPPED/MISMATCH");
		if (!ok) allOk = false;
	}
	(void)baseA; (void)baseB;

	// ---- Phase 2: forwarding latency (ping-pong) ----
	std::fprintf(stderr, "--- phase 2: forwarding latency ---\n");
	{
		const int rounds = 200;
		std::vector<double> lat;
		lat.reserve(rounds);
		std::string ping = makePayload(64, 'p');
		size_t count = sb.recvCount.load();
		for (int i = 0; i < rounds; ++i) {
			auto t0 = std::chrono::steady_clock::now();
			stice_send(a, ping.data(), ping.size());
			// Wait for the echo to come back (B echoes in cb_recv).
			if (!spinFor(sa.recvCount, count + 1, 5000)) {
				std::fprintf(stderr, "  round %d: echo timeout\n", i);
				allOk = false;
				break;
			}
			auto t1 = std::chrono::steady_clock::now();
			lat.push_back(
			    std::chrono::duration<double, std::milli>(t1 - t0).count() / 2.0);
			++count;
		}
		reportLatency(lat);
		if (lat.size() < (size_t)rounds) allOk = false;
	}

	// ---- Phase 3: throughput (windowed bulk A -> B) ----
	std::fprintf(stderr, "--- phase 3: throughput (A -> B) ---\n");
	{
		const size_t pktSize = 1200;
		const int totalPkts = 2000;
		const int window = 64;
		std::string payload(pktSize, 't');
		size_t sent = 0;
		size_t b0 = sb.recvBytes.load();
		auto t0 = std::chrono::steady_clock::now();
		auto lastReport = t0;
		while (sent < (size_t)totalPkts) {
			long long recvdPkts = (long long)sb.recvCount.load();
			if ((long long)sent - recvdPkts < (long long)window) {
				stice_send(a, payload.data(), payload.size());
				++sent;
			} else {
				std::this_thread::yield();
			}
			auto now = std::chrono::steady_clock::now();
			if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastReport)
			        .count() > 5000) {
				std::fprintf(stderr, "  ... %zu/%d sent, %zu received\n",
				             sent, totalPkts, sb.recvCount.load());
				lastReport = now;
			}
		}
		bool done = waitFor([&] { return sb.recvCount.load() >= (size_t)totalPkts; }, 30000);
		auto t1 = std::chrono::steady_clock::now();
		size_t bytes = sb.recvBytes.load() - b0;
		double secs = std::chrono::duration<double>(t1 - t0).count();
		double mbps = (bytes * 8.0 / 1e6) / secs;
		std::fprintf(stderr, "  sent=%d received=%zu bytes=%zu time=%.3fs goodput=%.2f Mbps\n",
		             totalPkts, done ? (size_t)totalPkts : sb.recvCount.load(),
		             bytes, secs, mbps);
		if (!done) allOk = false;
	}

	stice_destroy(a);
	stice_destroy(b);

	std::fprintf(stderr, "=== %s ===\n", allOk ? "PASS" : "FAIL");
	return allOk ? 0 : 1;
}
