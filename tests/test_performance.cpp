// SPDX-License-Identifier: MPL-2.0
// Performance tests for stice ICE agent.
//
// Measures:
//   - TTU (Time-To-Use): elapsed time from agent creation to first data
//     received, for N sequential UDP loopback sessions.
//   - Throughput: data transfer rate over an established ICE connection.
//
// Reports avg / p50 / p99 connect times. These are in-process measurements
// over UDP loopback, so absolute numbers reflect stice's processing overhead
// rather than real-network latency.

#include <catch2/catch_all.hpp>

#include "stice/stice.h"
#include "stice/log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

struct PairState {
	std::atomic<stice_state_t> stateA{STICE_STATE_DISCONNECTED};
	std::atomic<stice_state_t> stateB{STICE_STATE_DISCONNECTED};
	std::atomic<bool> gatheringDoneA{false};
	std::atomic<bool> gatheringDoneB{false};
	std::atomic<bool> dataReceived{false};
	std::atomic<size_t> bytesReceived{0};
};

stice_config_t makeConfig(PairState &s, bool isA) {
	stice_config_t cfg{};
	if (isA) {
		cfg.cb_state_changed = [](stice_agent_t *, stice_state_t st, void *p) {
			static_cast<PairState *>(p)->stateA.store(st);
		};
		cfg.cb_candidate = [](stice_agent_t *, const char *, void *) {};
		cfg.cb_gathering_done = [](stice_agent_t *, void *p) {
			static_cast<PairState *>(p)->gatheringDoneA.store(true);
		};
		cfg.cb_recv = [](stice_agent_t *, const char *, size_t, void *) {};
		cfg.user_ptr = &s;
	} else {
		cfg.cb_state_changed = [](stice_agent_t *, stice_state_t st, void *p) {
			static_cast<PairState *>(p)->stateB.store(st);
		};
		cfg.cb_candidate = [](stice_agent_t *, const char *, void *) {};
		cfg.cb_gathering_done = [](stice_agent_t *, void *p) {
			static_cast<PairState *>(p)->gatheringDoneB.store(true);
		};
		cfg.cb_recv = [](stice_agent_t *, const char *data, size_t size, void *p) {
			auto *s = static_cast<PairState *>(p);
			s->dataReceived.store(true);
			s->bytesReceived.fetch_add(size);
		};
		cfg.user_ptr = &s;
	}
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
		std::this_thread::sleep_for(std::chrono::milliseconds(2));
	}
}

// Run one ICE pair and return the connect time in ms (-1 on failure).
// Connect time = time from stice_create to first data received.
long long measureTTU() {
	PairState s;
	auto cfgA = makeConfig(s, true);
	auto cfgB = makeConfig(s, false);

	auto t0 = std::chrono::steady_clock::now();

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	if (!a || !b) {
		if (a) stice_destroy(a);
		if (b) stice_destroy(b);
		return -1;
	}

	stice_gather_candidates(b);
	stice_gather_candidates(a);

	if (!waitFor([&] { return s.gatheringDoneA.load() && s.gatheringDoneB.load(); }, 3000)) {
		stice_destroy(a);
		stice_destroy(b);
		return -1;
	}

	char bufA[4096], bufB[4096];
	stice_get_local_description(a, bufA, sizeof(bufA));
	stice_get_local_description(b, bufB, sizeof(bufB));
	stice_set_remote_description(a, bufB);
	stice_set_remote_description(b, bufA);
	stice_set_remote_gathering_done(a);
	stice_set_remote_gathering_done(b);

	if (!waitFor([&] {
		auto as = s.stateA.load();
		auto bs = s.stateB.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 5000)) {
		stice_destroy(a);
		stice_destroy(b);
		return -1;
	}

	// Send 1 byte to measure TTU (time to first data).
	const char ping = 'x';
	stice_send(a, &ping, 1);

	bool gotData = waitFor([&] { return s.dataReceived.load(); }, 2000);
	auto t1 = std::chrono::steady_clock::now();

	stice_destroy(a);
	stice_destroy(b);

	if (!gotData) return -1;
	return std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
}

// Compute percentiles from a vector of values.
struct Stats {
	double avg;
	long long p50;
	long long p99;
	long long minVal;
	long long maxVal;
};

Stats computeStats(std::vector<long long> &vals) {
	if (vals.empty()) return {0, 0, 0, 0, 0};
	std::sort(vals.begin(), vals.end());
	double sum = 0;
	for (auto v : vals) sum += v;
	Stats st;
	st.avg = sum / vals.size();
	st.p50 = vals[vals.size() / 2];
	st.p99 = vals[vals.size() > 1 ? vals.size() - 1 : 0];
	st.minVal = vals.front();
	st.maxVal = vals.back();
	return st;
}

} // namespace

TEST_CASE("Performance: TTU 20 sequential UDP ICE sessions", "[performance]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	const int N = 20;
	std::vector<long long> times;
	times.reserve(N);

	for (int i = 0; i < N; ++i) {
		long long ms = measureTTU();
		if (ms >= 0) times.push_back(ms);
	}

	REQUIRE(times.size() >= N * 0.9); // at least 90% must succeed

	auto st = computeStats(times);
	INFO("TTU " << times.size() << "/" << N << " sessions: "
	     << "avg=" << st.avg << "ms p50=" << st.p50 << "ms p99=" << st.p99 << "ms "
	     << "min=" << st.minVal << "ms max=" << st.maxVal << "ms");
	// TTU over loopback should be well under 500ms.
	REQUIRE(st.p99 < 1000);
}

// ---------------------------------------------------------------------------
// Helper: establish one ICE pair and return both agents + state by reference.
// Used by throughput / latency tests that need an already-connected pair.
// ---------------------------------------------------------------------------
struct EstablishedPair {
	stice_agent_t *a;
	stice_agent_t *b;
	PairState *state;
};

bool establishPair(EstablishedPair &out, int timeoutMs = 5000) {
	auto *s = new PairState;
	auto cfgA = makeConfig(*s, true);
	auto cfgB = makeConfig(*s, false);

	out.a = stice_create(&cfgA);
	out.b = stice_create(&cfgB);
	if (!out.a || !out.b) {
		if (out.a) stice_destroy(out.a);
		if (out.b) stice_destroy(out.b);
		delete s;
		return false;
	}
	out.state = s;

	stice_gather_candidates(out.b);
	stice_gather_candidates(out.a);

	if (!waitFor([&] { return s->gatheringDoneA.load() && s->gatheringDoneB.load(); }, 3000))
		return false;

	char bufA[4096], bufB[4096];
	stice_get_local_description(out.a, bufA, sizeof(bufA));
	stice_get_local_description(out.b, bufB, sizeof(bufB));
	stice_set_remote_description(out.a, bufB);
	stice_set_remote_description(out.b, bufA);
	stice_set_remote_gathering_done(out.a);
	stice_set_remote_gathering_done(out.b);

	return waitFor([&] {
		auto as = s->stateA.load();
		auto bs = s->stateB.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, timeoutMs);
}

void teardownPair(EstablishedPair &p) {
	stice_destroy(p.a);
	stice_destroy(p.b);
	delete p.state;
}

TEST_CASE("Performance: Throughput 64KB data transfer", "[performance]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	PairState s;
	auto cfgA = makeConfig(s, true);
	auto cfgB = makeConfig(s, false);

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);

	stice_gather_candidates(b);
	stice_gather_candidates(a);

	REQUIRE(waitFor([&] { return s.gatheringDoneA.load() && s.gatheringDoneB.load(); }, 3000));

	char bufA[4096], bufB[4096];
	REQUIRE(stice_get_local_description(a, bufA, sizeof(bufA)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b, bufB, sizeof(bufB)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(a, bufB) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(b, bufA) == STICE_ERR_SUCCESS);
	stice_set_remote_gathering_done(a);
	stice_set_remote_gathering_done(b);

	REQUIRE(waitFor([&] {
		auto as = s.stateA.load();
		auto bs = s.stateB.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 5000));

	// Send 64KB in 1KB chunks.
	const int chunkSize = 1024;
	const int totalChunks = 64;
	std::vector<char> payload(chunkSize, 'T');

	auto t0 = std::chrono::steady_clock::now();
	for (int i = 0; i < totalChunks; ++i) {
		stice_send(a, payload.data(), chunkSize);
	}
	// Wait for all data to arrive.
	REQUIRE(waitFor([&] { return s.bytesReceived.load() >= static_cast<size_t>(chunkSize * totalChunks); }, 5000));
	auto t1 = std::chrono::steady_clock::now();

	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
	double bytesPerSec = (chunkSize * totalChunks) / (ms / 1000.0);
	double mbps = (bytesPerSec * 8) / (1024 * 1024);

	INFO("Throughput: " << (chunkSize * totalChunks / 1024) << "KB in " << ms << "ms = "
	     << mbps << " Mbps");
	REQUIRE(s.bytesReceived.load() >= static_cast<size_t>(chunkSize * totalChunks));

	stice_destroy(a);
	stice_destroy(b);
}

// ---------------------------------------------------------------------------
// Performance: candidate gathering time.
// Measures how long stice_gather_candidates takes for host-only candidates
// (no STUN/TURN). This is the pure local-gathering overhead.
// ---------------------------------------------------------------------------
TEST_CASE("Performance: host candidate gathering time", "[performance][gathering]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	const int N = 10;
	std::vector<long long> times;
	times.reserve(N);

	for (int i = 0; i < N; ++i) {
		PairState s;
		auto cfg = makeConfig(s, true);

		auto t0 = std::chrono::steady_clock::now();
		stice_agent_t *a = stice_create(&cfg);
		REQUIRE(a != nullptr);
		REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
		REQUIRE(waitFor([&] { return s.gatheringDoneA.load(); }, 3000));
		auto t1 = std::chrono::steady_clock::now();

		times.push_back(
		    std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
		stice_destroy(a);
	}

	auto st = computeStats(times);
	// Report in microseconds for finer granularity.
	INFO("Host gathering " << N << " runs: "
	     << "avg=" << st.avg << "us p50=" << st.p50 << "us p99=" << st.p99 << "us "
	     << "min=" << st.minVal << "us max=" << st.maxVal << "us");
	// Host candidate gathering should complete well under 500ms on loopback.
	REQUIRE(st.p99 < 500000);
}

// ---------------------------------------------------------------------------
// Performance: round-trip latency.
// Measures the time for a request-response cycle over an established ICE
// connection: A sends a byte, B echoes it back, A receives it.
// ---------------------------------------------------------------------------
TEST_CASE("Performance: round-trip latency (50 RTT samples)", "[performance][latency]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	// LatencyState: A tracks reply arrival; B echoes received data back via
	// the agent handle passed as the first callback argument.
	struct LatencyState {
		std::atomic<stice_state_t> stateA{STICE_STATE_DISCONNECTED};
		std::atomic<stice_state_t> stateB{STICE_STATE_DISCONNECTED};
		std::atomic<bool> gatheringDoneA{false};
		std::atomic<bool> gatheringDoneB{false};
		std::atomic<bool> replyReceived{false};
	};

	LatencyState s;
	stice_config_t cfgA{};
	cfgA.cb_state_changed = [](stice_agent_t *, stice_state_t st, void *p) {
		static_cast<LatencyState *>(p)->stateA.store(st);
	};
	cfgA.cb_gathering_done = [](stice_agent_t *, void *p) {
		static_cast<LatencyState *>(p)->gatheringDoneA.store(true);
	};
	cfgA.cb_recv = [](stice_agent_t *, const char *, size_t, void *p) {
		static_cast<LatencyState *>(p)->replyReceived.store(true);
	};
	cfgA.user_ptr = &s;
	cfgA.bind_address = nullptr;

	stice_config_t cfgB{};
	cfgB.cb_state_changed = [](stice_agent_t *, stice_state_t st, void *p) {
		static_cast<LatencyState *>(p)->stateB.store(st);
	};
	cfgB.cb_gathering_done = [](stice_agent_t *, void *p) {
		static_cast<LatencyState *>(p)->gatheringDoneB.store(true);
	};
	// B echoes received data back to the sender. The agent handle is the
	// first callback argument, so we can call stice_send directly.
	cfgB.cb_recv = [](stice_agent_t *agent, const char *data, size_t size, void *) {
		stice_send(agent, data, size);
	};
	cfgB.user_ptr = &s;
	cfgB.bind_address = nullptr;

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);

	stice_gather_candidates(b);
	stice_gather_candidates(a);
	REQUIRE(waitFor([&] { return s.gatheringDoneA.load() && s.gatheringDoneB.load(); }, 3000));

	char bufA[4096], bufB[4096];
	REQUIRE(stice_get_local_description(a, bufA, sizeof(bufA)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b, bufB, sizeof(bufB)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(a, bufB) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(b, bufA) == STICE_ERR_SUCCESS);
	stice_set_remote_gathering_done(a);
	stice_set_remote_gathering_done(b);

	REQUIRE(waitFor([&] {
		auto as = s.stateA.load();
		auto bs = s.stateB.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 5000));

	// Measure 50 round-trips.
	const int samples = 50;
	std::vector<long long> rtts;
	rtts.reserve(samples);
	const char ping = 'P';

	for (int i = 0; i < samples; ++i) {
		s.replyReceived.store(false);
		auto t0 = std::chrono::steady_clock::now();
		REQUIRE(stice_send(a, &ping, 1) == STICE_ERR_SUCCESS);
		bool ok = waitFor([&] { return s.replyReceived.load(); }, 1000);
		auto t1 = std::chrono::steady_clock::now();
		if (!ok) break;
		rtts.push_back(
		    std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
	}

	REQUIRE(rtts.size() >= samples * 0.9);
	auto st = computeStats(rtts);
	INFO("RTT " << rtts.size() << "/" << samples << " samples: "
	     << "avg=" << st.avg << "us p50=" << st.p50 << "us p99=" << st.p99 << "us "
	     << "min=" << st.minVal << "us max=" << st.maxVal << "us");
	// Loopback RTT includes polling overhead (waitFor polls at 2ms intervals
	// plus the agent's own background poll cycle). Relax to 50ms.
	REQUIRE(st.p99 < 50000);

	stice_destroy(a);
	stice_destroy(b);
}

// ---------------------------------------------------------------------------
// Performance: throughput at multiple payload sizes.
// Sends 256KB total at different chunk sizes (256B, 512B, 1KB) to measure how
// payload size affects throughput over UDP loopback ICE. Chunk sizes are kept
// within the typical ICE/UDP MTU (~1400 bytes after STUN header overhead).
// ---------------------------------------------------------------------------
TEST_CASE("Performance: throughput vs payload size (256B/512B/1KB)", "[performance][throughput]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	const int totalBytes = 256 * 1024; // 256 KB per chunk-size run
	// Chunk sizes within typical ICE/UDP MTU (~1400 bytes after STUN overhead).
	const int chunkSizes[] = {256, 512, 1024};

	for (int chunkSize : chunkSizes) {
		EstablishedPair p;
		REQUIRE(establishPair(p));

		const int totalChunks = totalBytes / chunkSize;
		std::vector<char> payload(chunkSize, 'X');

		auto t0 = std::chrono::steady_clock::now();
		// Send in batches with a short drain pause between batches to avoid
		// overflowing the receiver's UDP socket buffer on loopback.
		const int batchSize = 64;
		for (int i = 0; i < totalChunks; ++i) {
			stice_send(p.a, payload.data(), chunkSize);
			if (i > 0 && (i + 1) % batchSize == 0 && i + 1 < totalChunks)
				std::this_thread::sleep_for(std::chrono::microseconds(200));
		}
		bool ok = waitFor([&] {
			return p.state->bytesReceived.load() >= static_cast<size_t>(totalBytes);
		}, 30000);
		auto t1 = std::chrono::steady_clock::now();

		auto received = p.state->bytesReceived.load();
		auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
		double effectiveBytes = static_cast<double>(received);
		double bytesPerSec = effectiveBytes / (ms / 1000.0);
		double mbps = (bytesPerSec * 8) / (1024 * 1024);
		double deliveryRatio = static_cast<double>(received) / static_cast<double>(totalBytes);

		INFO("Throughput @ " << chunkSize << "B chunks: " << (totalBytes / 1024)
		     << "KB sent, " << (received / 1024) << "KB received (" << (deliveryRatio * 100)
		     << "%) in " << ms << "ms = " << mbps << " Mbps");
		// At least 80% of data must arrive (UDP loopback may drop under burst).
		REQUIRE(deliveryRatio >= 0.8);
		REQUIRE(mbps > 1.0);

		teardownPair(p);
	}
}

// ---------------------------------------------------------------------------
// Performance: concurrent session establishment rate.
// Spawns N pairs concurrently and measures total wall-clock time. Reports
// sessions/sec to characterize the agent's scaling behavior.
// ---------------------------------------------------------------------------
TEST_CASE("Performance: concurrent session establishment rate (20 pairs)", "[performance][concurrent]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	const int N = 20;
	std::vector<std::thread> threads;
	std::atomic<int> successes{0};
	std::vector<long long> connectTimes(N, 0);

	auto t0 = std::chrono::steady_clock::now();

	threads.reserve(N);
	for (int i = 0; i < N; ++i) {
		threads.emplace_back([i, &successes, &connectTimes] {
			auto start = std::chrono::steady_clock::now();

			PairState s;
			auto cfgA = makeConfig(s, true);
			auto cfgB = makeConfig(s, false);

			stice_agent_t *a = stice_create(&cfgA);
			stice_agent_t *b = stice_create(&cfgB);
			if (!a || !b) {
				if (a) stice_destroy(a);
				if (b) stice_destroy(b);
				return;
			}

			stice_gather_candidates(b);
			stice_gather_candidates(a);

			if (!waitFor([&] { return s.gatheringDoneA.load() && s.gatheringDoneB.load(); }, 3000)) {
				stice_destroy(a);
				stice_destroy(b);
				return;
			}

			char bufA[4096], bufB[4096];
			stice_get_local_description(a, bufA, sizeof(bufA));
			stice_get_local_description(b, bufB, sizeof(bufB));
			stice_set_remote_description(a, bufB);
			stice_set_remote_description(b, bufA);
			stice_set_remote_gathering_done(a);
			stice_set_remote_gathering_done(b);

			if (waitFor([&] {
				auto as = s.stateA.load();
				auto bs = s.stateB.load();
				return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
				       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
			}, 8000)) {
				successes.fetch_add(1);
				auto end = std::chrono::steady_clock::now();
				connectTimes[i] = std::chrono::duration_cast<std::chrono::milliseconds>(
				    end - start).count();
			}

			stice_destroy(a);
			stice_destroy(b);
		});
	}
	for (auto &t : threads) t.join();

	auto t1 = std::chrono::steady_clock::now();
	auto totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

	std::vector<long long> validTimes;
	for (auto t : connectTimes)
		if (t > 0) validTimes.push_back(t);
	auto st = computeStats(validTimes);

	double sessionsPerSec = (successes.load() * 1000.0) / totalMs;
	INFO("Concurrent " << N << " pairs: " << successes.load() << "/" << N
	     << " succeeded in " << totalMs << "ms = " << sessionsPerSec << " sessions/sec"
	     << " | per-pair connect: avg=" << st.avg << "ms p50=" << st.p50
	     << "ms p99=" << st.p99 << "ms");

	REQUIRE(successes.load() >= N * 0.9);
	REQUIRE(sessionsPerSec > 1.0);
}
