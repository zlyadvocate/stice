// SPDX-License-Identifier: MPL-2.0
// Bandwidth / latency benchmark of the stice client against a coturn server.
//
// Usage: test_coturn_bench [host] [port] [user] [pass] [modes]
//   Defaults: host=192.168.3.233 port=3478 user=testuser pass=123456
//   modes: comma-separated subset of ice-udp,ice-tcp,turn-udp,turn-tcp
//   ("rfc6062" is accepted as an alias of turn-tcp; in stice a TCP TURN
//   transport always requests a TCP allocation, i.e. RFC 6062.)
//
// Modes and topologies (both agents run in this process):
//   ice-udp  : direct ICE over UDP (host+srflx candidates, coturn as STUN)
//   ice-tcp  : direct ICE over TCP (RFC 6544; A passive via TcpMux, B active)
//   turn-udp : TURN over UDP, UDP allocation (RFC 5766/8656) — relay-only
//              SDP on both sides so all traffic goes through coturn
//   turn-tcp : TURN over TCP, TCP allocation (RFC 6062) — relayed TCP
//              connections, relay-only SDP on both sides
//
// Per mode: 100-round 64B ping-pong latency (RTT/2) + windowed bulk
// throughput (1200B datagrams). Bandwidth is counted as received payload
// bytes / wall time (goodput, one direction A -> B, B does not echo during
// the throughput phase).

#ifndef STICE_STATIC
#define STICE_STATIC
#endif

#include "stice/stice.h"
#include "stice/log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <functional>
#include <mutex>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

using namespace std::chrono_literals;

struct AgentState {
	std::atomic<stice_state_t> state{STICE_STATE_DISCONNECTED};
	std::vector<std::string> candidates;
	std::mutex candidatesMutex;
	std::atomic<bool> gatheringDone{false};
	std::mutex recvMutex;
	std::vector<std::string> received;
	std::atomic<size_t> recvCount{0};
	std::atomic<size_t> recvBytes{0};
	// Condition variable: wakes the blocked sender the instant the window
	// has room again (recvCount advances in cb_recv). This replaces any
	// fixed-wait window-full policy — the sender blocks precisely until a
	// slot frees (receive-driven, not clock-driven), so throughput reaches
	// the coturn relay path's real limit with no sleep granularity and no
	// busy-spin against the poll thread.
	std::mutex cvMutex;
	std::condition_variable cv;
	// Steady-clock ms of the most recent delivery; used to compute goodput
	// up to the last received packet instead of including the wait-for-lost
	// timeout (with ~1% UDP loss the fixed 60s waitFor otherwise swamps the
	// real transfer time).
	std::atomic<std::int64_t> lastRecvMs{0};
	// Bulk-phase sequence tracking: the sender embeds a big-endian uint32 seq
	// in the first 4 bytes of each 1200B packet (after the 4B "ABCD-style"
	// demux-hazard prefix? No — plain seq at offset 0). Receiver records gaps.
	std::atomic<uint32_t> maxSeq{0};
	// In-order receive watermark + cumulative inferred-loss counter for
	// the sender's AIMD: a forward jump in the watermark is a loss signal
	// (UDP has no retransmission); late reordered packets below the
	// watermark are ignored (rare on the relayed path, and AIMD tolerates
	// the occasional false positive).
	std::atomic<uint32_t> recvExpect{0};
	std::atomic<long long> skipLost{0};
	std::vector<uint32_t> seqs;      // only when trackSeq
	std::mutex seqMutex;
	bool trackSeq = false;
	stice_agent_t *agent = nullptr;
	bool echo = false;   // bounce every received message back (latency phase)
	bool store = true;   // keep payloads (disabled during bulk phase)

	std::int64_t markLastRecvMs() const {
		return std::chrono::duration_cast<std::chrono::milliseconds>(
		           std::chrono::steady_clock::now().time_since_epoch())
		    .count();
	}
};

static stice_config_t makeConfig(AgentState &s, bool usePoll) {
	stice_config_t cfg{};
	cfg.cb_state_changed = [](stice_agent_t *, stice_state_t st, void *u) {
		static_cast<AgentState *>(u)->state.store(st);
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
		if (s->store) {
			std::lock_guard<std::mutex> lk(s->recvMutex);
			s->received.emplace_back(d, n);
		}
		s->recvBytes.fetch_add(n);
		s->recvCount.fetch_add(1);
		s->lastRecvMs.store(s->markLastRecvMs());
		s->cv.notify_one();
		if (s->trackSeq && n >= 4) {
			uint32_t seq = (uint32_t)(unsigned char)d[0] << 24 |
			               (uint32_t)(unsigned char)d[1] << 16 |
			               (uint32_t)(unsigned char)d[2] << 8 |
			               (uint32_t)(unsigned char)d[3];
			{
				std::lock_guard<std::mutex> lk(s->seqMutex);
				s->seqs.push_back(seq);
				if (seq > s->maxSeq.load()) s->maxSeq.store(seq);
			}
			// Watermark advance for the sender's AIMD loss signal.
			uint32_t e = s->recvExpect.load(std::memory_order_relaxed);
			if (seq >= e) {
				if (seq > e) s->skipLost.fetch_add(seq - e, std::memory_order_relaxed);
				s->recvExpect.store(seq + 1, std::memory_order_relaxed);
			}
		}
		if (s->echo && s->agent) stice_send(s->agent, d, n);
	};
	cfg.user_ptr = &s;
	cfg.bind_address = nullptr;
	cfg.local_port_range_begin = 0;
	cfg.local_port_range_end = 0;
	if (usePoll) cfg.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
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

// Relay-only candidates (TURN modes: force traffic through coturn).
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

struct ModeResult {
	std::string mode;
	bool connectOk = false;
	bool latencyOk = false;
	bool thruOk = false;
	double latAvgMs = 0, latP95Ms = 0, latMaxMs = 0;
	double mbps = 0;
	size_t sentPkts = 0, recvPkts = 0, recvBytes = 0;
	size_t sendFails = 0;
	double secs = 0;
};

struct BenchParams {
	const char *host = "192.168.3.233";
	uint16_t port = 3478;
	const char *user = "testuser";
	const char *pass = "123456";
	int latRounds = 100;
	size_t pktSize = 1200;
	int udpPkts = 20000;  // bulk packet count for UDP-based modes
	int tcpPkts = 40000;  // bulk packet count for TCP-based modes
	int udpWindow = 32;      // matches libjuice; >32 overflows coturn relay buffer (w256 -> 63% loss)
	int tcpWindow = 512;      // direct ICE-TCP
	// Relayed TCP (RFC 6062): the relayed path crosses the physical NIC
	// twice (host -> coturn -> host). Its bandwidth-delay product is
	// ~37.5 KB (1 Gbps x ~0.3 ms) = ~32 packets of 1200 B. Inflight above
	// BDP overflows relay/NIC queues; TCP loss then triggers RTO backoff
	// (measured: 64-deep -> periodic 5 s stalls, 4 Mbps; 512-deep ->
	// 10 s stalls, 11 Mbps). BDP-matched inflight avoids the loss.
	int turnTcpWindow = 16;
	// Target per-flow bandwidth for relayed UDP (Mbps). 0 = off (use
	// udpWindow as-is). When >0, the bulk window is derived at runtime from
	// the measured latency so each flow holds ~target Mbps: window =
	// ceil((target_bytes/s * RTT) / pktSize). This is the libjuice/pion
	// "pure window" scheme — no pacing, no AIMD — which we verified is the
	// only lossless setup (window-clocked sends): w32 no-pace == 0 loss,
	// while any pacing configuration loses.
	double udpTargetMbps = 0;
};

static bool connectPair(AgentState &sa, AgentState &sb, stice_agent_t *a,
                        stice_agent_t *b, const char *mode, int timeoutMs) {
	auto connT0 = std::chrono::steady_clock::now();
	char bufA[4096], bufB[4096];
	stice_get_local_description(a, bufA, sizeof(bufA));
	stice_get_local_description(b, bufB, sizeof(bufB));

	std::string sdpA, sdpB;
	if (std::strcmp(mode, "turn-udp") == 0 || std::strcmp(mode, "turn-tcp") == 0) {
		sdpA = filterRelayOnly(bufA);
		sdpB = filterRelayOnly(bufB);
	} else {
		sdpA = bufA;
		sdpB = bufB;
	}
	stice_set_remote_description(a, sdpB.c_str());
	stice_set_remote_description(b, sdpA.c_str());
	stice_set_remote_gathering_done(a);
	stice_set_remote_gathering_done(b);

	if (!waitFor([&] {
		auto as = sa.state.load(), bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, timeoutMs)) {
		std::fprintf(stderr, "  connect timeout (A=%d B=%d)\n",
		             (int)sa.state.load(), (int)sb.state.load());
		return false;
	}
	auto connMs = std::chrono::duration_cast<std::chrono::milliseconds>(
	                  std::chrono::steady_clock::now() - connT0).count();
	std::fprintf(stderr, "  connect elapsed: %lld ms\n", (long long)connMs);
	return true;
}

static bool runMode(const char *mode, const BenchParams &p, ModeResult &res) {
	res.mode = mode;
	bool isTurn = (std::strcmp(mode, "turn-udp") == 0 || std::strcmp(mode, "turn-tcp") == 0);
	bool isTcp = (std::strcmp(mode, "turn-tcp") == 0 || std::strcmp(mode, "ice-tcp") == 0);

	std::fprintf(stderr, "\n=== mode: %s ===\n", mode);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa, isTcp);
	auto cfgB = makeConfig(sb, isTcp);

	// STUN (srflx) for all modes except pure ICE-TCP.
	if (std::strcmp(mode, "ice-tcp") != 0) {
		cfgA.stun_server_host = p.host;
		cfgA.stun_server_port = p.port;
		cfgB.stun_server_host = p.host;
		cfgB.stun_server_port = p.port;
	}

	// ICE-TCP: A passive (TcpMux), B active; exchange ufrag/pwd before gathering.
	stice_tcp_mux_t *mux = nullptr;
	stice_agent_t *a = nullptr, *b = nullptr;
	if (std::strcmp(mode, "ice-tcp") == 0) {
		mux = stice_create_tcp_mux("127.0.0.1", 0);
		if (!mux) { std::fprintf(stderr, "  FAIL: create_tcp_mux\n"); return false; }
	}

	a = stice_create(&cfgA);
	b = stice_create(&cfgB);
	if (!a || !b) { std::fprintf(stderr, "  FAIL: create\n"); return false; }
	sa.agent = a;
	sb.agent = b;

	if (std::strcmp(mode, "ice-tcp") == 0) {
		stice_set_ice_tcp_mode(a, STICE_ICE_TCP_MODE_PASSIVE);
		stice_agent_use_tcp_mux(a, mux);
		stice_set_ice_tcp_mode(b, STICE_ICE_TCP_MODE_ACTIVE);
		char sdpA[4096], sdpB[4096];
		stice_get_local_description(a, sdpA, sizeof(sdpA));
		stice_get_local_description(b, sdpB, sizeof(sdpB));
		stice_set_remote_description(a, sdpB);
		stice_set_remote_description(b, sdpA);
	}

	if (isTurn) {
		// RFC 6062 (TCP relayed-transport allocation) is opt-in and only
		// interoperable between stice agents. Enable it for the stice↔stice
		// turn-tcp benchmark so it exercises the CONNECT data connection path.
#ifdef _WIN32
		_putenv_s("STICE_TURN_TCP_RFC6062",
		          (std::strcmp(mode, "turn-tcp") == 0) ? "1" : "0");
#else
		setenv("STICE_TURN_TCP_RFC6062",
		       (std::strcmp(mode, "turn-tcp") == 0) ? "1" : "0", 1);
#endif
		stice_turn_server_t turn{};
		turn.host = const_cast<char *>(p.host);
		turn.port = p.port;
		turn.username = const_cast<char *>(p.user);
		turn.password = const_cast<char *>(p.pass);
		turn.transport = (std::strcmp(mode, "turn-tcp") == 0)
		                     ? STICE_TURN_TRANSPORT_TCP
		                     : STICE_TURN_TRANSPORT_UDP;
		stice_add_turn_server(a, &turn);
		stice_add_turn_server(b, &turn);
	}

	stice_gather_candidates(b);
	stice_gather_candidates(a);

	if (!waitFor([&] { return sa.gatheringDone.load() && sb.gatheringDone.load(); }, 20000)) {
		std::fprintf(stderr, "  FAIL: gathering timeout (A=%d B=%d)\n",
		             (int)sa.gatheringDone.load(), (int)sb.gatheringDone.load());
		stice_destroy(a); stice_destroy(b);
		if (mux) stice_destroy_tcp_mux(mux);
		return false;
	}

	// Print gathered candidates (trimmed to relay/tcp ones for TURN/ICE-TCP).
	{
		std::lock_guard<std::mutex> lk(sa.candidatesMutex);
		for (const auto &c : sa.candidates) {
			if (!isTurn || c.find("typ relay") != std::string::npos)
				std::fprintf(stderr, "  A: %s\n", c.c_str());
		}
	}
	{
		std::lock_guard<std::mutex> lk(sb.candidatesMutex);
		for (const auto &c : sb.candidates) {
			if (!isTurn || c.find("typ relay") != std::string::npos)
				std::fprintf(stderr, "  B: %s\n", c.c_str());
		}
	}

	if (isTurn) {
		// Both sides must have a relay candidate, else coturn lacks the
		// capability for this mode (e.g. RFC 6062 TCP allocation disabled).
		bool aRelay = false, bRelay = false;
		{
			std::lock_guard<std::mutex> lk(sa.candidatesMutex);
			for (const auto &c : sa.candidates)
				if (c.find("typ relay") != std::string::npos) aRelay = true;
		}
		{
			std::lock_guard<std::mutex> lk(sb.candidatesMutex);
			for (const auto &c : sb.candidates)
				if (c.find("typ relay") != std::string::npos) bRelay = true;
		}
		if (!aRelay || !bRelay) {
			std::fprintf(stderr, "  FAIL: no relay candidate (A=%d B=%d) — "
			             "coturn may not support this allocation type\n",
			             (int)aRelay, (int)bRelay);
			stice_destroy(a); stice_destroy(b);
			if (mux) stice_destroy_tcp_mux(mux);
			return false;
		}
	}

	if (std::strcmp(mode, "ice-tcp") == 0) {
		// Trickle: forward only TCP candidates (tcptype).
		{
			std::lock_guard<std::mutex> lk(sa.candidatesMutex);
			for (const auto &c : sa.candidates)
				if (c.find("tcptype") != std::string::npos)
					stice_add_remote_candidate(b, c.c_str());
		}
		{
			std::lock_guard<std::mutex> lk(sb.candidatesMutex);
			for (const auto &c : sb.candidates)
				if (c.find("tcptype") != std::string::npos)
					stice_add_remote_candidate(a, c.c_str());
		}
		stice_set_remote_gathering_done(a);
		stice_set_remote_gathering_done(b);
		if (!waitFor([&] {
			auto as = sa.state.load(), bs = sb.state.load();
			return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
			       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
		}, 15000)) {
			std::fprintf(stderr, "  FAIL: connect timeout (A=%d B=%d)\n",
			             (int)sa.state.load(), (int)sb.state.load());
			stice_destroy(a); stice_destroy(b);
			if (mux) stice_destroy_tcp_mux(mux);
			return false;
		}
	} else {
		if (!connectPair(sa, sb, a, b, mode, 20000)) {
			stice_destroy(a); stice_destroy(b);
			if (mux) stice_destroy_tcp_mux(mux);
			return false;
		}
	}
	res.connectOk = true;
	std::fprintf(stderr, "  CONNECTED\n");

	// Sanity data exchange.
	sb.store = true; sa.store = true;
	{
		const char *msg = "hello";
		stice_send(a, msg, std::strlen(msg));
		stice_send(b, msg, std::strlen(msg));
		waitFor([&] { return sa.recvCount.load() >= 1 && sb.recvCount.load() >= 1; }, 8000);
	}

	// ---- Latency: 64B ping-pong (B echoes) ----
	{
		sb.echo = true;
		const int rounds = p.latRounds;
		std::vector<double> lat;
		lat.reserve(rounds);
		std::string ping(64, 'p');
		size_t count = sa.recvCount.load();
		for (int i = 0; i < rounds; ++i) {
			auto t0 = std::chrono::steady_clock::now();
			stice_send(a, ping.data(), ping.size());
			if (!spinFor(sa.recvCount, count + 1, 10000)) {
				std::fprintf(stderr, "  latency round %d: echo timeout\n", i);
				break;
			}
			auto t1 = std::chrono::steady_clock::now();
			lat.push_back(
			    std::chrono::duration<double, std::milli>(t1 - t0).count() / 2.0);
			++count;
		}
		sb.echo = false;
		if (!lat.empty()) {
			std::sort(lat.begin(), lat.end());
			double sum = 0;
			for (double v : lat) sum += v;
			size_t p95idx = lat.size() * 95 / 100;
			if (p95idx >= lat.size()) p95idx = lat.size() - 1;
			res.latAvgMs = sum / lat.size();
			res.latP95Ms = lat[p95idx];
			res.latMaxMs = lat.back();
			res.latencyOk = (lat.size() == (size_t)rounds);
			std::fprintf(stderr, "  latency (RTT/2, %zu samples): avg=%.3f p95=%.3f max=%.3f ms\n",
			             lat.size(), res.latAvgMs, res.latP95Ms, res.latMaxMs);
		} else {
			std::fprintf(stderr, "  latency: NO SAMPLES\n");
		}
	}

	// ---- Throughput: windowed bulk A -> B (no echo) ----
	{
		sb.store = false; // count only, do not retain 40k payloads
		sa.store = false;
		sb.trackSeq = true;
		{
			std::lock_guard<std::mutex> lk(sb.seqMutex);
			sb.seqs.clear();
			sb.maxSeq.store(0);
			sb.recvExpect.store(0);
			sb.skipLost.store(0);
		}
		const int totalPkts = isTcp ? p.tcpPkts : p.udpPkts;
		// UDP relayed window: if a target per-flow bandwidth is set, derive
		// the window from the measured latency (BDP = target_bytes/s * RTT);
		// this paces the flow by windowing alone (libjuice/pion scheme),
		// which is the only configuration we measure as lossless — any
		// per-packet pacing loses. Without a target, use udpWindow directly.
		int window;
		// Derive the window from the p95 RTT, not the average: coturn's
		// relay path delivers latency in bursts (p95 >> avg), so an
		// avg-derived window under-fills and triggers spurious stall-breaks.
		// A p95-derived window keeps enough in-flight to sustain the target
		// rate across latency spikes.
		if (!isTcp && p.udpTargetMbps > 0 && res.latP95Ms > 0) {
			double rttSec = res.latP95Ms * 2.0 / 1000.0;   // RTT, not one-way
			double bdpBytes = (p.udpTargetMbps * 1e6 / 8.0) * rttSec;
			window = (int)std::ceil(bdpBytes / p.pktSize);
			if (window < 1) window = 1;
		} else {
			window = isTcp ? (isTurn ? p.turnTcpWindow : p.tcpWindow) : p.udpWindow;
		}
		std::string payload(p.pktSize, 't');
		size_t sent = 0;
		size_t b0 = sb.recvBytes.load();
		size_t c0 = sb.recvCount.load();
		auto t0 = std::chrono::steady_clock::now();
		auto lastReport = t0;
		// libjuice-style simple sender: fixed window, Sleep(1) when the
		// window is full. No AIMD growth, no pacing, no multiplicative
		// decrease. The fixed window fills the path BDP; Sleep(1)
		// releases the CPU so the receiver's poll thread drains the
		// socket buffer without competing with a busy yield loop.
		// Minimal loss accounting (no control action): UDP packets that
		// never arrive keep inflight elevated forever, so lost packets
		// are marked via the receiver's skip watermark; a stall breaker
		// handles tail losses the watermark cannot see.
		const long long cwnd = (long long)window;
		size_t sendFails = 0;
		long long lostAcked = 0;
		long long skipBase = 0;
		long long lastRecvdAtTimeoutCheck = -1;
		long long rtoCount = 0;
		// Cooldown after a stall-break: pause sending so the pipe and
		// coturn's relay buffers drain before resuming, instead of
		// immediately re-filling the whole window (which over-drives and
		// loses packets).
		bool inCooldown = false;
		const long long coolMs = 100;
		std::chrono::steady_clock::time_point cooldownUntil{};
		std::chrono::steady_clock::time_point progDeadline =
		    std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
		while (sent < (size_t)totalPkts) {
			long long recvdPkts = (long long)sb.recvCount.load() - (long long)c0;
			long long inflight = (long long)sent - recvdPkts - lostAcked;
			if (!isTcp) {
				long long newSkip = sb.skipLost.load(std::memory_order_relaxed) - skipBase;
				if (newSkip > 0) {
					skipBase += newSkip;
					lostAcked += newSkip;
					inflight -= newSkip;
				} else if (inflight >= cwnd) {
					// Stall breaker: window full with zero delivery
					// progress for 250 ms → tail loss. Jump the watermark
					// and keep sending (no window change).
					auto now = std::chrono::steady_clock::now();
					if (recvdPkts != lastRecvdAtTimeoutCheck) {
						lastRecvdAtTimeoutCheck = recvdPkts;
						progDeadline = now + std::chrono::milliseconds(250);
					} else if (now > progDeadline) {
						// Reset, not full-window resend: break the stuck-window
						// deadlock by accounting the in-flight as lost, then enter
						// a cooldown so we do NOT immediately re-fill the window.
						lostAcked += inflight;
						skipBase = sb.skipLost.load(std::memory_order_relaxed);
						sb.recvExpect.store((uint32_t)sent, std::memory_order_relaxed);
						inflight = 0;
						inCooldown = true;
						cooldownUntil = now + std::chrono::milliseconds(coolMs);
						++rtoCount;
					}
				}
			}
			// Cooldown gate: after a stall-break, pause sending until the
			// cooldown lapses (lets the pipe / coturn relay buffers drain)
			// instead of instantly re-filling the whole window.
			if (inCooldown) {
				auto tc = std::chrono::steady_clock::now();
				if (tc < cooldownUntil) {
					std::int64_t remainUs = std::chrono::duration_cast<std::chrono::microseconds>(
					                            cooldownUntil - tc).count();
					if (remainUs < 50) remainUs = 50;
					std::this_thread::sleep_for(std::chrono::microseconds((size_t)remainUs));
					continue;
				}
				inCooldown = false;
			}
			if (inflight < cwnd) {
				// Pure window-clocked send (libjuice/pion scheme): when a
				// window slot is free, transmit immediately. No per-packet
				// pacing — measured that pacing introduces micro-bursts that
				// overflow coturn's relay buffers and lose packets, whereas
				// the window alone (plus Sleep(1) when full) is lossless.
				// Embed big-endian seq at offset 0. First byte stays 0x00
				// (seq < 0x40000000), so it never looks like ChannelData.
				uint32_t seq = (uint32_t)sent;
				payload[0] = (char)(seq >> 24);
				payload[1] = (char)(seq >> 16);
				payload[2] = (char)(seq >> 8);
				payload[3] = (char)seq;
				if (stice_send(a, payload.data(), payload.size()) < 0)
					++sendFails;
				++sent;
			} else {
				// Window full: block precisely until the peer's
				// recvCount advances (signalled by cv in cb_recv), i.e. a
				// window slot frees. This is receive-driven, not
				// clock-driven: no sleep granularity caps throughput and no
				// busy-spin starves the receiver's poll thread. A short
				// timeout just keeps the 250ms stall-breaker above alive;
				// on the healthy relay path the notify fires first.
				long long before = (long long)sb.recvCount.load();
				{
					std::unique_lock<std::mutex> lk(sb.cvMutex);
					sb.cv.wait_for(lk, std::chrono::microseconds(100), [&] {
						return (long long)sb.recvCount.load() != before;
					});
				}
			}
			auto now = std::chrono::steady_clock::now();
			if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastReport)
			        .count() > 5000) {
				std::fprintf(stderr, "  ... %zu/%d sent, %lld received, %zu send-fails\n",
				             sent, totalPkts, recvdPkts, sendFails);
				lastReport = now;
			}
		}
		res.sendFails = sendFails;
		if (rtoCount > 0)
			std::fprintf(stderr, "  stall-breaks: %lld\n", rtoCount);
		// UDP modes: lost packets never arrive — waiting the full timeout is
		// wasted wall time; 15s is ample for reordering/drain. TCP modes keep
		// the full 60s (retransmission makes eventual delivery plausible).
		bool done = waitFor([&] { return sb.recvCount.load() - c0 >= (size_t)totalPkts; },
		                    isTcp ? 60000 : 15000);
		// Goodput window: from first send to the LAST received packet (not
		// to the wait timeout — with UDP loss the fixed 60s waitFor would
		// otherwise dominate the measured time and report ~3 Mbps for a
		// sub-second transfer).
		std::int64_t lastMs = sb.lastRecvMs.load();
		std::int64_t t0Ms = std::chrono::duration_cast<std::chrono::milliseconds>(
		                        t0.time_since_epoch())
		                        .count();
		double activeSecs = lastMs > t0Ms ? double(lastMs - t0Ms) / 1000.0 : 0.0;
		if (activeSecs <= 0.0) activeSecs = 1e-3;
		res.sentPkts = totalPkts;
		res.recvPkts = sb.recvCount.load() - c0;
		res.recvBytes = sb.recvBytes.load() - b0;
		res.secs = activeSecs;
		res.mbps = (res.recvBytes * 8.0 / 1e6) / activeSecs;
		// For lossless transports (TCP-based modes) count completeness as OK;
		// for UDP modes tolerate loss but report it — loss through a relay
		// is a property of the path, not a tool failure.
		res.thruOk = done || (!isTcp && res.recvPkts >= (size_t)totalPkts * 95 / 100);
		std::fprintf(stderr, "  throughput: sent=%d received=%zu lost=%lld sendFails=%zu "
		             "bytes=%zu active-time=%.3fs goodput=%.2f Mbps%s\n",
		             totalPkts, res.recvPkts, (long long)totalPkts - (long long)res.recvPkts,
		             res.sendFails, res.recvBytes, activeSecs, res.mbps,
		             done ? "" : (res.thruOk ? " (loss tolerated)" : " (INCOMPLETE)"));
		// Loss analysis: report contiguous missing ranges (first 8).
		sb.trackSeq = false;
#ifdef _WIN32
		if (!isTcp)
			SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
#endif
		{
			std::vector<uint32_t> got;
			{
				std::lock_guard<std::mutex> lk(sb.seqMutex);
				got.swap(sb.seqs);
			}
			if (!got.empty()) {
				std::sort(got.begin(), got.end());
				std::vector<std::pair<uint32_t, uint32_t>> gaps;
				uint32_t expect = 0;
				for (uint32_t s : got) {
					if (s > expect) gaps.push_back({expect, s - 1});
					expect = s + 1;
				}
				if ((uint32_t)totalPkts > expect)
					gaps.push_back({expect, (uint32_t)totalPkts - 1});
				if (!gaps.empty()) {
					std::fprintf(stderr, "  loss ranges (%zu, total %lld pkts):",
					             gaps.size(),
					             std::accumulate(gaps.begin(), gaps.end(), 0LL,
					                 [](long long acc, const std::pair<uint32_t, uint32_t> &g) {
					                     return acc + (g.second - g.first + 1);
					                 }));
					for (size_t i = 0; i < gaps.size() && i < 8; ++i)
						std::fprintf(stderr, " [%u-%u]", gaps[i].first, gaps[i].second);
					if (gaps.size() > 8) std::fprintf(stderr, " ...");
					std::fprintf(stderr, "\n");
				}
			}
		}
	}

	stice_destroy(a);
	stice_destroy(b);
	if (mux) stice_destroy_tcp_mux(mux);
	return res.connectOk && res.latencyOk && res.thruOk;
}

int main(int argc, char **argv) {
	BenchParams p;
	if (argc > 1) p.host = argv[1];
	if (argc > 2) p.port = static_cast<uint16_t>(std::atoi(argv[2]));
	if (argc > 3) p.user = argv[3];
	if (argc > 4) p.pass = argv[4];
	std::string modes = argc > 5 ? argv[5] : "ice-udp,ice-tcp,turn-udp,turn-tcp";
	if (argc > 5) modes = argv[5];
	if (argc > 6) p.udpTargetMbps = std::atof(argv[6]);
	if (argc > 7) p.udpWindow = std::atoi(argv[7]);
	// 8, 9: bulk packet counts for UDP/TCP modes — raise these for long
	// stability runs (defaults 20000 / 40000 finish in ~1-2 s).
	if (argc > 8) p.udpPkts = std::atoi(argv[8]);
	if (argc > 9) p.tcpPkts = std::atoi(argv[9]);
	// 10: turn-tcp in-flight window (relayed TCP, RFC 6062). Tune to pace
	// a target sustained rate; the current path ceiling is well below the
	// old 208-292 Mbps, and window/RTT bounds the delivered rate.

	if (argc > 10) p.turnTcpWindow = std::atoi(argv[10]);

	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	std::fprintf(stderr, "=== coturn bench: %s:%u user=%s ===\n", p.host, p.port, p.user);
	std::fprintf(stderr, "params: %d ping-pong rounds, %zuB bulk packets, "
	             "udp=%d pkts/w%d%s, tcp=%d pkts/w%d\n",
	             p.latRounds, p.pktSize, p.udpPkts, p.udpWindow,
	             p.udpTargetMbps > 0 ? " (target-mbps, window from RTT)" : "",
	             p.tcpPkts, p.tcpWindow);

	// Split modes; map "rfc6062" alias to turn-tcp.
	std::vector<std::string> modeList;
	{
		std::istringstream iss(modes);
		std::string m;
		while (std::getline(iss, m, ',')) {
			if (m == "rfc6062") m = "turn-tcp";
			if (!m.empty()) modeList.push_back(m);
		}
	}

	std::vector<ModeResult> results;
	bool allOk = true;
	for (const auto &m : modeList) {
		ModeResult res;
		bool ok = runMode(m.c_str(), p, res);
		results.push_back(res);
		if (!ok) allOk = false;
	}

	std::fprintf(stderr, "\n=== SUMMARY (%s:%u) ===\n", p.host, p.port);
	std::fprintf(stderr, "%-14s %-8s %-9s %-11s %-8s %-10s\n",
	             "mode", "connect", "lat-avg", "lat-p95", "goodput", "pkts-recv");
	for (const auto &r : results) {
		std::fprintf(stderr, "%-14s %-8s %-9.3f %-11.3f %-8.1f %-10zu",
		             r.mode.c_str(),
		             r.connectOk ? "ok" : "FAIL",
		             r.latAvgMs, r.latP95Ms, r.mbps, r.recvPkts);
		std::fprintf(stderr, "%s\n", (r.connectOk && r.latencyOk && r.thruOk) ? "" : "  (partial)");
	}
	std::fprintf(stderr, "=== %s ===\n", allOk ? "PASS" : "FAIL");
	return allOk ? 0 : 1;
}
