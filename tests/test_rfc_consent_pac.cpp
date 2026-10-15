// test_rfc_consent_pac.cpp
//
// Regression tests for the two RFC "ICE extension" MUSTs that no other suite
// covered (the whole existing suite still ran in the same wall time after both
// were fixed - i.e. nothing observed this behaviour at all):
//
//   RFC 7675 §5.1 - "Each STUN binding request for consent MUST use a new STUN
//                   transaction identifier". The bug: a keepalive reuses the
//                   entry that carried the last connectivity check, whose fresh
//                   ID had already been consumed, so every consent request
//                   replayed one TID - breaking the MUST, weakening replay
//                   protection, and letting a peer that de-duplicates on TID
//                   drop the requests (consent then expires at 30 s).
//
//   RFC 8863 §4   - while Running, an agent whose checklist has no pairs left to
//                   check MUST NOT move to Failed immediately (the PAC timer).
//                   The bug: IcePacTimeoutMs was declared but never referenced,
//                   so an all-pairs-failed checklist failed instantly and a
//                   peer-reflexive pair had no chance to be discovered.
//
// Both are timing behaviours, so both are [slow] (together ~2 minutes). Run the
// fast suites with "~[slow]".
#include <catch2/catch_all.hpp>

#include "stice/stice.h"
#include "stice/log.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace {

struct AgentState {
	std::atomic<stice_state_t> state{STICE_STATE_DISCONNECTED};
	std::atomic<bool> gatheringDone{false};
	std::vector<std::string> candidates;
	std::mutex candidatesMutex;
};

stice_config_t makeConfig(AgentState &s) {
	stice_config_t cfg{};
	cfg.cb_state_changed = [](stice_agent_t *, stice_state_t state, void *user_ptr) {
		static_cast<AgentState *>(user_ptr)->state.store(state);
	};
	cfg.cb_candidate = [](stice_agent_t *, const char *cand, void *user_ptr) {
		auto *s = static_cast<AgentState *>(user_ptr);
		std::lock_guard<std::mutex> lk(s->candidatesMutex);
		s->candidates.emplace_back(cand);
	};
	cfg.cb_gathering_done = [](stice_agent_t *, void *user_ptr) {
		static_cast<AgentState *>(user_ptr)->gatheringDone.store(true);
	};
	cfg.cb_recv = [](stice_agent_t *, const char *, size_t, void *) {};
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

void exchangeDescriptions(stice_agent_t *a, AgentState &sa, stice_agent_t *b, AgentState &sb) {
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 5000));
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 5000));
	char bufA[4096], bufB[4096];
	REQUIRE(stice_get_local_description(a, bufA, sizeof(bufA)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b, bufB, sizeof(bufB)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(a, bufB) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(b, bufA) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);
}

// --- log capture -----------------------------------------------------------
// stice_set_log_handler() takes a plain function pointer (no user pointer), so
// the capture state has to live at namespace scope. Catch2 runs test cases
// sequentially, which is all this needs.
std::mutex g_logMutex;
std::string g_logText;
// The handler runs on agent threads, so this must be atomic (benign race otherwise).
std::atomic<bool> g_capture{false};

void captureLog(stice_log_level_t, const char *message) {
	if (!g_capture || !message) return;
	std::lock_guard<std::mutex> lk(g_logMutex);
	g_logText += message;
	g_logText += '\n';
}

// Transaction IDs of every outbound STUN Binding *request*
// ("sendStunBinding: ... cls=0 ... tid=xxxxxxxx ..."). Request class is 0 in
// STUN's two-bit class field, so cls=0 isolates checks and consent requests.
std::vector<std::string> outboundRequestTids() {
	std::lock_guard<std::mutex> lk(g_logMutex);
	std::vector<std::string> out;
	std::size_t pos = 0;
	while ((pos = g_logText.find("sendStunBinding:", pos)) != std::string::npos) {
		std::size_t eol = g_logText.find('\n', pos);
		std::string line = g_logText.substr(pos, eol == std::string::npos ? std::string::npos : eol - pos);
		pos = (eol == std::string::npos) ? g_logText.size() : eol + 1;
		if (line.find("cls=0") == std::string::npos) continue;
		std::size_t tp = line.find("tid=");
		if (tp == std::string::npos || tp + 12 > line.size()) continue;
		out.push_back(line.substr(tp + 4, 8));
	}
	return out;
}

} // namespace

// ---------------------------------------------------------------------------
// RFC 7675 §5.1: consent requests must each carry a fresh transaction ID
// ---------------------------------------------------------------------------
TEST_CASE("RFC 7675: consent requests never reuse a transaction ID", "[consent][rfc7675][slow]") {
	stice_set_log_level(STICE_LOG_LEVEL_DEBUG);
	{
		std::lock_guard<std::mutex> lk(g_logMutex);
		g_logText.clear();
	}
	g_capture = true;
	stice_set_log_handler(captureLog);

	AgentState sa, sb;
	stice_config_t ca = makeConfig(sa);
	stice_config_t cb = makeConfig(sb);
	stice_agent_t *a = stice_create(&ca);
	stice_agent_t *b = stice_create(&cb);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	exchangeDescriptions(a, sa, b, sb);

	// Wait for connectivity, then long enough that at least two consent
	// keepalives have gone out (the pairing profiles use 4-12 s periods, so 30 s
	// covers the slowest of them).
	REQUIRE(waitFor([&] {
		return sa.state.load() == STICE_STATE_CONNECTED ||
		       sa.state.load() == STICE_STATE_COMPLETED;
	}, 15000));
	std::this_thread::sleep_for(std::chrono::seconds(30));

	g_capture = false;
	stice_set_log_handler(nullptr);
	stice_destroy(a);
	stice_destroy(b);

	auto tids = outboundRequestTids();
	// At least the initial connectivity check plus one consent keepalive.
	REQUIRE(tids.size() >= 2);
	// The MUST: every request a new transaction ID. Before the fix these were
	// all the same value, so this is the assertion that pins the behaviour down.
	std::set<std::string> distinct(tids.begin(), tids.end());
	CHECK(distinct.size() == tids.size());
}

// ---------------------------------------------------------------------------
// RFC 8863 §4: Patiently Awaiting Connectivity
// ---------------------------------------------------------------------------
TEST_CASE("RFC 8863: an all-failed checklist while connecting does not fail immediately",
          "[pac][rfc8863][slow]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	AgentState s;
	stice_config_t cfg = makeConfig(s);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return s.gatheringDone.load(); }, 5000));

	// A single unroutable remote host candidate (192.0.2.0/24 is TEST-NET-1,
	// RFC 5737) with syntactically valid credentials. Every connectivity check
	// is black-holed, so every pair fails and nothing can ever succeed.
	const char *remote =
	    "a=ice-ufrag:abcd\r\n"
	    "a=ice-pwd:0123456789012345678901\r\n"
	    "a=candidate:1 1 udp 2130706431 192.0.2.1 9999 typ host\r\n"
	    "a=end-of-candidates\r\n";
	REQUIRE(stice_set_remote_description(a, remote) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return s.state.load() == STICE_STATE_CONNECTING; }, 5000));

	// The pairs give up within a few seconds (the product profile retransmits
	// 3x from a 500 ms RTO), so without a PAC gate the agent would already be
	// FAILED here. It must still be waiting instead.
	std::this_thread::sleep_for(std::chrono::seconds(20));
	CHECK(s.state.load() != STICE_STATE_FAILED);

	// But the patience is bounded - the agent must reach FAILED once the PAC
	// timer (39.5 s) has expired, i.e. it is not wedged in CONNECTING forever.
	CHECK(waitFor([&] { return s.state.load() == STICE_STATE_FAILED; }, 60000));
	stice_destroy(a);
}
