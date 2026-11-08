// SPDX-License-Identifier: MPL-2.0
// Regression for the ICE-restart data race on Agent::turnDataConn_ (found by
// TSAN; it only surfaced once the fixture lock discipline changed scheduling):
//
//   writer (main thread): Agent::restart() -> turnDataConn_.reset()   (mutex_ held)
//   reader (poll thread): PollRegistry::epollSync -> Agent::hasTurnDataTcp()
//                         / turnDataTcpSocket() / turnDataDesiredEvents()
//
// The three getters read the unique_ptr with no lock at all while the writer
// destroyed it under mutex_, so a restart landing between the null check and
// the dereference was a use-after-free window. They now take mutex_ like the
// sibling turnTcp* getters, and the passive RFC 6062 path
// (turn::Client onConnectionAttempt -> beginTurnDataConnect) takes it too.
//
// The concurrency assertions below cannot fail on a benign scheduler - the
// actual detector is TSAN, where dropping the lock makes this case report
// immediately. The deterministic assertions pin the getters' contract: before
// any RFC 6062 data connection exists (and after a restart tears the
// generation down) all three must report "no data socket".

#include <catch2/catch_test_macros.hpp>

#include "stice/ice/agent.hpp"
#include "stice/stice.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>

using namespace stice;

namespace {
stice_config_t emptyConfig() {
	stice_config_t cfg{};
	cfg.bind_address = nullptr;
	cfg.local_port_range_begin = 0;
	cfg.local_port_range_end = 0;
	return cfg;
}
} // namespace

TEST_CASE("TURN data getters report no connection before RFC 6062 setup",
          "[turn][rfc6062][concurrency]") {
	stice_config_t cfg = emptyConfig();
	ice::Agent agent;
	REQUIRE(agent.init(&cfg, nullptr));

	REQUIRE_FALSE(agent.hasTurnDataTcp());
	REQUIRE(agent.turnDataTcpSocket() == STICE_INVALID_SOCKET);
	REQUIRE(agent.turnDataDesiredEvents() == 0);
}

TEST_CASE("TURN data getters are race-free against an ICE restart",
          "[turn][rfc6062][concurrency]") {
	stice_config_t cfg = emptyConfig();
	ice::Agent agent;
	REQUIRE(agent.init(&cfg, nullptr));

	// reader models the poll thread: PollRegistry::epollSync calls exactly
	// these three getters on every resync while the main thread may be
	// restarting the agent.
	std::atomic<bool> stop{false};
	std::atomic<std::uint64_t> reads{0};
	std::thread reader([&] {
		while (!stop.load(std::memory_order_relaxed)) {
			(void)agent.hasTurnDataTcp();
			(void)agent.turnDataTcpSocket();
			(void)agent.turnDataDesiredEvents();
			reads.fetch_add(1, std::memory_order_relaxed);
		}
	});

	for (int i = 0; i < 16; ++i) {
		REQUIRE(agent.restart() == STICE_ERR_SUCCESS);
		std::this_thread::sleep_for(std::chrono::milliseconds(2));
	}
	stop.store(true, std::memory_order_relaxed);
	reader.join();

	REQUIRE(reads.load() > 0);
	// restart() drops the old generation's data connection; once it returns the
	// getters must agree that no data socket is registered.
	REQUIRE_FALSE(agent.hasTurnDataTcp());
	REQUIRE(agent.turnDataTcpSocket() == STICE_INVALID_SOCKET);
	REQUIRE(agent.turnDataDesiredEvents() == 0);
}
