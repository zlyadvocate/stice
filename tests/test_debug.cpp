// Debug test: ICE UDP loopback with verbose logging.
#include <catch2/catch_all.hpp>

#include "stice/stice.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {
struct AgentState {
	std::atomic<stice_state_t> state{STICE_STATE_DISCONNECTED};
	std::vector<std::string> candidates;
	std::atomic<bool> gatheringDone{false};
	std::vector<std::string> received;
	std::mutex candidatesMutex;
	std::mutex receivedMutex;
};

stice_config_t makeConfig(AgentState &s) {
	stice_config_t cfg{};
	cfg.cb_state_changed = [](stice_agent_t *, stice_state_t state, void *user_ptr) {
		auto *s = static_cast<AgentState *>(user_ptr);
		s->state.store(state);
		fprintf(stderr, "[STATE] -> %d\n", static_cast<int>(state));
	};
	cfg.cb_candidate = [](stice_agent_t *, const char *cand, void *user_ptr) {
		auto *s = static_cast<AgentState *>(user_ptr);
		std::lock_guard<std::mutex> lk(s->candidatesMutex);
		s->candidates.emplace_back(cand);
		fprintf(stderr, "[CAND] %s\n", cand);
	};
	cfg.cb_gathering_done = [](stice_agent_t *, void *user_ptr) {
		auto *s = static_cast<AgentState *>(user_ptr);
		s->gatheringDone.store(true);
		fprintf(stderr, "[GATHERING DONE]\n");
	};
	cfg.cb_recv = [](stice_agent_t *, const char *data, size_t size, void *user_ptr) {
		auto *s = static_cast<AgentState *>(user_ptr);
		std::lock_guard<std::mutex> lk(s->receivedMutex);
		s->received.emplace_back(data, size);
	};
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
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
}
} // namespace

TEST_CASE("Debug ICE UDP loopback", "[debug]") {
	stice_set_log_level(STICE_LOG_LEVEL_VERBOSE);
	stice_set_log_handler([](stice_log_level_t level, const char *msg) {
		fprintf(stderr, "[LOG %d] %s\n", static_cast<int>(level), msg);
	});

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);

	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);

	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 3000));

	char bufA[4096], bufB[4096];
	REQUIRE(stice_get_local_description(a, bufA, sizeof(bufA)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b, bufB, sizeof(bufB)) == STICE_ERR_SUCCESS);
	fprintf(stderr, "[SDP A] %s\n", bufA);
	fprintf(stderr, "[SDP B] %s\n", bufB);
	REQUIRE(stice_set_remote_description(a, bufB) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(b, bufA) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);

	bool ok = waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 5000);
	fprintf(stderr, "[RESULT] %s\n", ok ? "SUCCESS" : "TIMEOUT");
	REQUIRE(ok);

	stice_destroy(a);
	stice_destroy(b);
}
