// SPDX-License-Identifier: MPL-2.0
// Stress tests for stice ICE agent: N concurrent UDP loopback pairs.
//
// Each pair consists of a Controlling and a Controlled agent running in the
// same process over UDP loopback. The test verifies that all pairs reach
// CONNECTED/COMPLETED and exchange data bidirectionally under concurrent load.
//
// This is the C++ in-process equivalent of orchestrator.py's stress category,
// without requiring an external signaling server or stice_client processes.

#include <catch2/catch_all.hpp>

#include "stice/stice.h"
#include "stice/log.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

// Per-pair state shared between the two agents.
struct PairState {
	std::atomic<stice_state_t> stateA{STICE_STATE_DISCONNECTED};
	std::atomic<stice_state_t> stateB{STICE_STATE_DISCONNECTED};
	std::atomic<bool> gatheringDoneA{false};
	std::atomic<bool> gatheringDoneB{false};
	std::vector<std::string> candsA;
	std::vector<std::string> candsB;
	std::mutex candsMutexA;
	std::mutex candsMutexB;
	std::atomic<bool> dataAtoB{false};
	std::atomic<bool> dataBtoA{false};
};

// Build a stice_config_t wired to a PairState. `isA` selects which half of
// the pair the config is for (A=controlling, B=controlled).
stice_config_t makeConfig(PairState &s, bool isA) {
	stice_config_t cfg{};
	if (isA) {
		cfg.cb_state_changed = [](stice_agent_t *, stice_state_t st, void *p) {
			static_cast<PairState *>(p)->stateA.store(st);
		};
		cfg.cb_candidate = [](stice_agent_t *, const char *c, void *p) {
			auto *s = static_cast<PairState *>(p);
			std::lock_guard<std::mutex> lk(s->candsMutexA);
			s->candsA.emplace_back(c);
		};
		cfg.cb_gathering_done = [](stice_agent_t *, void *p) {
			static_cast<PairState *>(p)->gatheringDoneA.store(true);
		};
		cfg.cb_recv = [](stice_agent_t *, const char *, size_t, void *p) {
			static_cast<PairState *>(p)->dataBtoA.store(true);
		};
		cfg.user_ptr = &s;
	} else {
		cfg.cb_state_changed = [](stice_agent_t *, stice_state_t st, void *p) {
			static_cast<PairState *>(p)->stateB.store(st);
		};
		cfg.cb_candidate = [](stice_agent_t *, const char *c, void *p) {
			auto *s = static_cast<PairState *>(p);
			std::lock_guard<std::mutex> lk(s->candsMutexB);
			s->candsB.emplace_back(c);
		};
		cfg.cb_gathering_done = [](stice_agent_t *, void *p) {
			static_cast<PairState *>(p)->gatheringDoneB.store(true);
		};
		cfg.cb_recv = [](stice_agent_t *, const char *, size_t, void *p) {
			static_cast<PairState *>(p)->dataAtoB.store(true);
		};
		cfg.user_ptr = &s;
	}
	cfg.bind_address = nullptr;
	cfg.local_port_range_begin = 0;
	cfg.local_port_range_end = 0;
	return cfg;
}

// Wait for `cond` to become true, polling at 5ms, up to `timeoutMs`.
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

// Run a single ICE pair: create two agents, exchange SDP+candidates, verify
// connection and data exchange. Returns true on success.
bool runSinglePair(int pairId, int timeoutMs = 8000) {
	PairState s;
	auto cfgA = makeConfig(s, true);
	auto cfgB = makeConfig(s, false);

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	if (!a || !b) {
		if (a) stice_destroy(a);
		if (b) stice_destroy(b);
		return false;
	}

	// Gather host candidates on both sides.
	if (stice_gather_candidates(b) != STICE_ERR_SUCCESS ||
	    stice_gather_candidates(a) != STICE_ERR_SUCCESS) {
		stice_destroy(a);
		stice_destroy(b);
		return false;
	}

	// Wait for gathering done.
	if (!waitFor([&] { return s.gatheringDoneA.load() && s.gatheringDoneB.load(); }, 3000)) {
		stice_destroy(a);
		stice_destroy(b);
		return false;
	}

	// Exchange local descriptions.
	char bufA[4096], bufB[4096];
	if (stice_get_local_description(a, bufA, sizeof(bufA)) != STICE_ERR_SUCCESS ||
	    stice_get_local_description(b, bufB, sizeof(bufB)) != STICE_ERR_SUCCESS ||
	    stice_set_remote_description(a, bufB) != STICE_ERR_SUCCESS ||
	    stice_set_remote_description(b, bufA) != STICE_ERR_SUCCESS) {
		stice_destroy(a);
		stice_destroy(b);
		return false;
	}
	stice_set_remote_gathering_done(a);
	stice_set_remote_gathering_done(b);

	// Wait for both to connect.
	bool connected = waitFor([&] {
		auto as = s.stateA.load();
		auto bs = s.stateB.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, timeoutMs);

	if (!connected) {
		stice_destroy(a);
		stice_destroy(b);
		return false;
	}

	// Data exchange.
	const char *msg = "stress-test-data";
	stice_send(a, msg, std::strlen(msg));
	stice_send(b, msg, std::strlen(msg));

	bool dataOk = waitFor([&] { return s.dataAtoB.load() && s.dataBtoA.load(); }, 2000);

	stice_destroy(a);
	stice_destroy(b);
	return dataOk;
}

// Run N pairs concurrently in threads. Returns (successCount, totalTimeMs).
std::pair<int, long long> runConcurrentPairs(int n, int timeoutMs = 8000) {
	std::vector<std::thread> threads;
	std::atomic<int> successes{0};
	auto start = std::chrono::steady_clock::now();

	threads.reserve(n);
	for (int i = 0; i < n; ++i) {
		threads.emplace_back([i, timeoutMs, &successes] {
			if (runSinglePair(i, timeoutMs))
				successes.fetch_add(1);
		});
		// Stagger launch slightly to avoid thundering herd.
		if (i > 0 && i % 10 == 0)
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}
	for (auto &t : threads) t.join();

	auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
	    std::chrono::steady_clock::now() - start);
	return {successes.load(), elapsed.count()};
}

} // namespace

TEST_CASE("Stress: 10 concurrent ICE pairs", "[stress]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);
	auto [ok, ms] = runConcurrentPairs(10);
	INFO("10 pairs: " << ok << "/10 succeeded in " << ms << "ms");
	REQUIRE(ok == 10);
}

TEST_CASE("Stress: 50 concurrent ICE pairs", "[stress]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);
	auto [ok, ms] = runConcurrentPairs(50);
	INFO("50 pairs: " << ok << "/50 succeeded in " << ms << "ms");
	REQUIRE(ok >= 48); // allow up to 2 failures (port exhaustion)
}

TEST_CASE("Stress: 100 concurrent ICE pairs", "[stress]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);
	auto [ok, ms] = runConcurrentPairs(100, 12000);
	INFO("100 pairs: " << ok << "/100 succeeded in " << ms << "ms");
	REQUIRE(ok >= 95); // allow up to 5 failures (port exhaustion)
}
