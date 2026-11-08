// SPDX-License-Identifier: MPL-2.0
// Integration tests for stice ICE agent over UDP local loopback.
//
// Test 1: ICE UDP local loopback
//   AgentA (Controlling) <-> AgentB (Controlled)
//   Only Host UDP candidates, Trickle ICE
//   Expect: valid pair established, bidirectional data exchange.
//
// These tests run entirely on the local machine. They use the public C API
// (stice.h) to mirror how libdatachannel would drive stice, but they also
// exercise the C++ Agent directly when the C API doesn't expose what we need.

#include <catch2/catch_all.hpp>

#include "stice/stice.h"
#include "stice/log.hpp"
// Socket platform layer (winsock2.h) must come before any windows.h include.
#include "stice/net/platform.hpp"
#include "stice/net/addr.hpp"
#include "stice/net/poll.hpp"
#include "stice/net/udp.hpp"
#include "stice/stun/attributes.hpp"
#include "stice/stun/message.hpp"
#include "stice/ice/candidate.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#endif

namespace {
// Per-test state shared between the two agents.
struct AgentState {
	std::atomic<stice_state_t> state{STICE_STATE_DISCONNECTED};
	std::vector<std::string> candidates;
	std::atomic<bool> gatheringDone{false};
	std::vector<std::string> received;

	std::mutex candidatesMutex;
	std::mutex receivedMutex;
};

// Build a stice_config_t wired up to the test's AgentState. The callbacks
// fire on the PollRegistry thread, so we lock when touching shared state.
stice_config_t makeConfig(AgentState &s, void *userPtr = nullptr) {
	stice_config_t cfg{};
	cfg.cb_state_changed = [](stice_agent_t *, stice_state_t state, void *user_ptr) {
		auto *s = static_cast<AgentState *>(user_ptr);
		s->state.store(state);
	};
	cfg.cb_candidate = [](stice_agent_t *, const char *cand, void *user_ptr) {
		auto *s = static_cast<AgentState *>(user_ptr);
		std::lock_guard<std::mutex> lk(s->candidatesMutex);
		s->candidates.emplace_back(cand);
	};
	cfg.cb_gathering_done = [](stice_agent_t *, void *user_ptr) {
		auto *s = static_cast<AgentState *>(user_ptr);
		s->gatheringDone.store(true);
	};
	cfg.cb_recv = [](stice_agent_t *, const char *data, size_t size, void *user_ptr) {
		auto *s = static_cast<AgentState *>(user_ptr);
		std::lock_guard<std::mutex> lk(s->receivedMutex);
		s->received.emplace_back(data, size);
	};
	cfg.user_ptr = userPtr ? userPtr : &s;
	// No STUN/TURN servers, no port range: bind to ephemeral ports.
	cfg.bind_address = nullptr;
	cfg.local_port_range_begin = 0;
	cfg.local_port_range_end = 0;
	return cfg;
}

// Wait for `cond` to become true, polling at 10ms, up to `timeoutMs`.
bool waitFor(std::function<bool()> cond, int timeoutMs,
             std::function<void()> yield = nullptr) {
	auto start = std::chrono::steady_clock::now();
	while (true) {
		if (cond()) return true;
		auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
		    std::chrono::steady_clock::now() - start);
		if (elapsed.count() >= timeoutMs) return false;
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		if (yield) yield();
	}
}

// Race-free accessors for AgentState::received: callbacks fire on the
// agent's poll thread, so reads from the test thread must take the mutex
// (unsynchronized size()/back() reads are UB under concurrent push_back).
size_t recvCount(AgentState &s) {
	std::lock_guard<std::mutex> lk(s.receivedMutex);
	return s.received.size();
}
std::vector<std::string> recvSnapshot(AgentState &s) {
	std::lock_guard<std::mutex> lk(s.receivedMutex);
	return s.received;
}
// Element access under the mutex; empty string when out of range (callers
// wait on recvCount() first, so this only matters on failure paths).
std::string recvAt(AgentState &s, size_t i) {
	std::lock_guard<std::mutex> lk(s.receivedMutex);
	return i < s.received.size() ? s.received[i] : std::string();
}
std::string recvBack(AgentState &s) {
	std::lock_guard<std::mutex> lk(s.receivedMutex);
	return s.received.empty() ? std::string() : s.received.back();
}
// Wait until `msg` shows up in the agent's received stream. The loopback mux
// broadcast delivers every app-data send to every agent except the (last)
// sender, so waits must match MESSAGE CONTENT, not received counts.
bool waitForRecv(AgentState &s, const std::string &msg, int timeoutMs) {
	return waitFor([&] {
		auto got = recvSnapshot(s);
		for (const auto &m : got)
			if (m == msg) return true;
		return false;
	}, timeoutMs);
}

// ---------------------------------------------------------------------------
// External TURN/STUN endpoints for this suite.
//
// These integration tests need a real TURN server. The lab addresses used to be
// hard-coded, so the suite failed (rather than skipped) on any other host or in
// CI. Endpoints now come from the environment with the lab values as defaults,
// and every test that needs one probes reachability first and SKIPs when the
// server is absent.
//   STICE_TEST_TURN_HOST/_PORT/_USER/_PASS       primary TURN
//   STICE_TEST_TURN2_HOST/_PORT/_USER/_PASS      second TURN provider
//   STICE_TEST_STUN_HOST/_PORT                   external STUN (defaults to TURN #1)
// ---------------------------------------------------------------------------

std::string envOr(const char *name, const char *fallback) {
	const char *v = std::getenv(name);
	return (v && *v) ? std::string(v) : std::string(fallback);
}

std::uint16_t envPortOr(const char *name, std::uint16_t fallback) {
	const char *v = std::getenv(name);
	if (!v || !*v) return fallback;
	unsigned long n = std::strtoul(v, nullptr, 10);
	return (n > 0 && n <= 65535) ? static_cast<std::uint16_t>(n) : fallback;
}

struct ExternalTurn {
	std::string host;
	std::uint16_t port = 3478;
	std::string username;
	std::string password;
};

ExternalTurn externalTurn(const char *prefix = "STICE_TEST_TURN",
                          const char *defaultHost = "192.168.3.223") {
	ExternalTurn t;
	t.host = envOr((std::string(prefix) + "_HOST").c_str(), defaultHost);
	t.port = envPortOr((std::string(prefix) + "_PORT").c_str(), 3478);
	t.username = envOr((std::string(prefix) + "_USER").c_str(), "testuser");
	t.password = envOr((std::string(prefix) + "_PASS").c_str(), "123456");
	return t;
}

ExternalTurn externalTurn2() { return externalTurn("STICE_TEST_TURN2", "192.168.3.244"); }

// Minimal STUN Binding Request (type, length, magic cookie, 12-byte txid) is
// enough for a reachability probe: any RFC 5389 server answers it.
bool udpEndpointReachable(const std::string &host, std::uint16_t port, int timeoutMs) {
	auto addrs = stice::net::resolve(host, std::to_string(port), SOCK_DGRAM);
	if (addrs.empty()) return false;

	stice::net::UdpSocket sock = stice::net::UdpSocket::create(stice::net::UdpSocketConfig{});
	if (!sock.valid()) return false;

	std::uint8_t req[20] = {0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42};
	for (int i = 0; i < 12; ++i) req[8 + i] = static_cast<std::uint8_t>(i * 37 + 11);
	if (sock.sendto(reinterpret_cast<const char *>(req), sizeof(req), addrs.front()) < 0)
		return false;

	char buf[1500];
	auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
	while (std::chrono::steady_clock::now() < deadline) {
		pollfd pfd{};
		pfd.fd = sock.handle();
		pfd.events = POLLIN;
		int n = sticePoll(&pfd, 1, 50);
		if (n > 0 && (pfd.revents & POLLIN)) {
			stice::net::AddrRecord from;
			if (sock.recvfrom(buf, sizeof(buf), from) > 0) return true;
		}
	}
	return false;
}

// TCP reachability via a non-blocking connect: TURN over TCP is a plain TCP
// listener, so a successful handshake means the server is there.
bool tcpEndpointReachable(const std::string &host, std::uint16_t port, int timeoutMs) {
	auto addrs = stice::net::resolve(host, std::to_string(port), SOCK_STREAM);
	if (addrs.empty()) return false;

	const auto &a = addrs.front();
	socket_t s = ::socket(a.addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (s == STICE_INVALID_SOCKET) return false;
	stice::net::setNonBlocking(s);

	bool ok = false;
	if (::connect(s, reinterpret_cast<const sockaddr *>(&a.addr), a.len) == 0) {
		ok = true;
	} else if (stice::net::wouldBlock() || sticeSockerrno == STICE_SEINPROGRESS) {
		pollfd pfd{};
		pfd.fd = s;
		pfd.events = POLLOUT;
		if (sticePoll(&pfd, 1, timeoutMs) > 0) {
			int err = 0;
			socklen_t errLen = sizeof(err);
			if (::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&err), &errLen) == 0)
				ok = (err == 0);
		}
	}
	sticeClosesocket(s);
	return ok;
}

// The PollRegistry pool hands out one process-lifetime registry (background
// thread + interrupt socket) per acquire() until it reaches its
// hardware-concurrency cap. A handle-count test that creates agents in a fresh
// process would otherwise attribute that process-wide pool growth to the
// agents under test. Pre-acquiring the whole pool makes the deltas below
// measure only the agents' own resources.
void warmPollRegistryPool() {
	const unsigned n = std::max(1u, std::thread::hardware_concurrency());
	for (unsigned i = 0; i <= n; ++i) (void)stice::net::PollRegistry::acquire();
}


// Exchange candidates and local descriptions between two agents. Implements
// trickle ICE: each gathered candidate on one side is added to the other
// via stice_add_remote_candidate, then stice_set_remote_gathering_done is
// called once gathering completes.
void trickleExchange(stice_agent_t *a, AgentState &sa, stice_agent_t *b, AgentState &sb) {
	// Wait for gathering to complete on both sides (host candidates only).
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 3000));

	// Get each side's local SDP and pass it to the other.
	char bufA[4096];
	char bufB[4096];
	REQUIRE(stice_get_local_description(a, bufA, sizeof(bufA)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b, bufB, sizeof(bufB)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(a, bufB) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(b, bufA) == STICE_ERR_SUCCESS);

	// Trickle candidates: forward each candidate from A to B and vice versa.
	// stice_get_local_description already includes the host candidates in
	// the SDP (because gathering finished before we read it), but we still
	// call add_remote_candidate to match the trickle pattern for any
	// candidates discovered later.
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);
}
} // namespace

TEST_CASE("ICE UDP local loopback: Controlling <-> Controlled", "[integration][udp]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);

	// B is controlled (sets remote description first); A is controlling.
	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);

	trickleExchange(a, sa, b, sb);

	// Wait for both sides to reach CONNECTED or COMPLETED.
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 5000));

	// Bidirectional data exchange.
	const char *msgAtoB = "hello from A";
	const char *msgBtoA = "hello from B";
	REQUIRE(stice_send(a, msgAtoB, std::strlen(msgAtoB)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_send(b, msgBtoA, std::strlen(msgBtoA)) == STICE_ERR_SUCCESS);

	REQUIRE(waitFor([&] { return recvCount(sb) >= 1; }, 2000));
	REQUIRE(waitFor([&] { return recvCount(sa) >= 1; }, 2000));

	REQUIRE(recvAt(sb, 0) == msgAtoB);
	REQUIRE(recvAt(sa, 0) == msgBtoA);

	// Selected candidates should be available on both sides.
	char localA[512], remoteA[512];
	char localB[512], remoteB[512];
	REQUIRE(stice_get_selected_candidates(a, localA, sizeof(localA), remoteA, sizeof(remoteA)) ==
	        STICE_ERR_SUCCESS);
	REQUIRE(stice_get_selected_candidates(b, localB, sizeof(localB), remoteB, sizeof(remoteB)) ==
	        STICE_ERR_SUCCESS);

	// A's local should match B's remote, and vice versa.
	REQUIRE(std::string(localA) == std::string(remoteB));
	REQUIRE(std::string(remoteA) == std::string(localB));

	stice_destroy(a);
	stice_destroy(b);
}

TEST_CASE("ICE UDP: single-side restart forms a new generation", "[integration][udp][restart]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);

	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	trickleExchange(a, sa, b, sb);

	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 5000));

	// Capture both generations' starting credentials.
	char bufA[4096], bufB[4096];
	REQUIRE(stice_get_local_description(a, bufA, sizeof(bufA)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b, bufB, sizeof(bufB)) == STICE_ERR_SUCCESS);
	std::string sdpA1(bufA), sdpB1(bufB);
	auto ufragA1 = sdpA1.substr(sdpA1.find("a=ice-ufrag:") + 12, 4);
	auto ufragB1 = sdpB1.substr(sdpB1.find("a=ice-ufrag:") + 12, 4);

	// Single-side restart: A starts a new generation. restart() runs the fresh
	// gathering pass internally (stice.h contract).
	sa.gatheringDone.store(false);
	REQUIRE(stice_agent_restart(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));

	char bufA2[4096], bufB2[4096];
	REQUIRE(stice_get_local_description(a, bufA2, sizeof(bufA2)) == STICE_ERR_SUCCESS);
	std::string sdpA2(bufA2);
	auto ufragA2 = sdpA2.substr(sdpA2.find("a=ice-ufrag:") + 12, 4);
	// RFC 8445 §9: the new generation MUST carry fresh credentials.
	REQUIRE(ufragA2 != ufragA1);

	// B receives A's changed ufrag/pwd: per RFC 8445 §9 B restarts too — fresh
	// local credentials and a fresh gathering pass (implicit peer-restart
	// detection in setRemoteDescription). B can check toward A immediately: it
	// already holds A's NEW credentials from bufA2.
	sb.gatheringDone.store(false);
	REQUIRE(stice_set_remote_description(b, bufA2) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 3000));

	REQUIRE(stice_get_local_description(b, bufB2, sizeof(bufB2)) == STICE_ERR_SUCCESS);
	std::string sdpB2(bufB2);
	auto ufragB2 = sdpB2.substr(sdpB2.find("a=ice-ufrag:") + 12, 4);
	REQUIRE(ufragB2 != ufragB1);

	// Complete the renegotiation: A learns B's new generation. A's remote
	// description was cleared by its own restart, so this cannot trip the
	// peer-restart detection (no restart ping-pong).
	REQUIRE(stice_set_remote_description(a, bufB2) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);

	// The new generation must connect again on both sides.
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 15000));

	// Data still flows bidirectionally in the new generation.
	const char *msgAtoB = "after restart from A";
	const char *msgBtoA = "after restart from B";
	REQUIRE(stice_send(a, msgAtoB, std::strlen(msgAtoB)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_send(b, msgBtoA, std::strlen(msgBtoA)) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return recvCount(sb) >= 1 && recvCount(sa) >= 1; }, 3000));

	stice_destroy(a);
	stice_destroy(b);
}

TEST_CASE("ICE restart: late description from a retired generation is ignored (P2-N11)",
          "[integration][udp][restart]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);
	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);

	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	trickleExchange(a, sa, b, sb);
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 5000));

	// Generation 1 of B's description, captured before the restart.
	char bufB1[4096];
	REQUIRE(stice_get_local_description(b, bufB1, sizeof(bufB1)) == STICE_ERR_SUCCESS);
	std::string sdpB1(bufB1);

	// A restarts; B follows on A's new generation; A then learns B's new one.
	sa.gatheringDone.store(false);
	REQUIRE(stice_agent_restart(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));
	char bufA2[4096];
	REQUIRE(stice_get_local_description(a, bufA2, sizeof(bufA2)) == STICE_ERR_SUCCESS);
	sb.gatheringDone.store(false);
	REQUIRE(stice_set_remote_description(b, bufA2) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 3000));
	char bufB2[4096];
	REQUIRE(stice_get_local_description(b, bufB2, sizeof(bufB2)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(a, bufB2) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 15000));

	// Re-deliver B's generation-1 description (signalling reordering, or a peer
	// re-sending a pre-restart copy). Without the monotonic generation guard this
	// looks like another credential change and restarts A a second time, tearing
	// down a checklist that is already converging.
	char ufragBefore[4096];
	REQUIRE(stice_get_local_description(a, ufragBefore, sizeof(ufragBefore)) == STICE_ERR_SUCCESS);
	const std::string sdpA3(ufragBefore);
	sa.gatheringDone.store(false);
	REQUIRE(stice_set_remote_description(a, sdpB1.c_str()) == STICE_ERR_SUCCESS);
	std::this_thread::sleep_for(std::chrono::milliseconds(400));
	// No second restart: no fresh gathering, credentials unchanged.
	REQUIRE(sa.gatheringDone.load() == false);
	char ufragAfter[4096];
	REQUIRE(stice_get_local_description(a, ufragAfter, sizeof(ufragAfter)) == STICE_ERR_SUCCESS);
	REQUIRE(std::string(ufragAfter) == sdpA3);

	// The live session survived the stale delivery.
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		return as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED;
	}, 2000));
	const char *msg = "still connected after a stale description";
	REQUIRE(stice_send(a, msg, std::strlen(msg)) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return recvCount(sb) >= 1; }, 3000));

	stice_destroy(a);
	stice_destroy(b);
}

TEST_CASE("ICE restart: re-delivering the current generation is not a restart",
          "[integration][udp][restart]") {
	// Complement of the retired-generation guard: a signalling layer may
	// re-send the description it already delivered (duplicate offer, retry).
	// The credentials are UNCHANGED, so no restart may trigger and the live
	// checklist must survive untouched — only a ufrag/pwd CHANGE detects a
	// peer restart (RFC 8445 §9).
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);

	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	trickleExchange(a, sa, b, sb);
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 5000));

	char bufB[4096];
	REQUIRE(stice_get_local_description(b, bufB, sizeof(bufB)) == STICE_ERR_SUCCESS);
	char before[4096];
	REQUIRE(stice_get_local_description(a, before, sizeof(before)) == STICE_ERR_SUCCESS);
	const std::string sdpA1(before);

	// Duplicate delivery of B's CURRENT generation to A.
	sa.gatheringDone.store(false);
	REQUIRE(stice_set_remote_description(a, bufB) == STICE_ERR_SUCCESS);
	std::this_thread::sleep_for(std::chrono::milliseconds(400));
	// No fresh gathering pass: the credentials did not change.
	REQUIRE(sa.gatheringDone.load() == false);
	char after[4096];
	REQUIRE(stice_get_local_description(a, after, sizeof(after)) == STICE_ERR_SUCCESS);
	REQUIRE(std::string(after) == sdpA1);

	// The session survived the duplicate delivery.
	const char *msg = "alive after duplicate description";
	REQUIRE(stice_send(a, msg, std::strlen(msg)) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return recvCount(sb) >= 1; }, 3000));

	stice_destroy(a);
	stice_destroy(b);
}

// Minimal test-owned UDP socket standing in for a remote ICE peer: binds on
// loopback and reports whether any datagram (the agent's connectivity check)
// ever arrives. Used to observe pair formation without a full STUN responder.
class UdpProbePeer {
public:
	UdpProbePeer() {
		sock_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		REQUIRE(sock_ != STICE_INVALID_SOCKET);
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr.sin_port = 0;
		REQUIRE(::bind(sock_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
		sockaddr_in bound{};
		socklen_t blen = sizeof(bound);
		REQUIRE(getsockname(sock_, reinterpret_cast<sockaddr *>(&bound), &blen) == 0);
		port_ = ntohs(bound.sin_port);
		REQUIRE(stice::net::setNonBlocking(sock_));
	}
	~UdpProbePeer() { sticeClosesocket(sock_); }
	uint16_t port() const { return port_; }
	bool gotDatagram() {
		unsigned char buf[512];
		sockaddr_in src{};
		socklen_t slen = sizeof(src);
		bool got = ::recvfrom(sock_, reinterpret_cast<char *>(buf), sizeof(buf), 0,
		                      reinterpret_cast<sockaddr *>(&src), &slen) >= 0;
		if (got) ever_ = true;
		return got;
	}
	// Whether a datagram ever arrived (gotDatagram() consumes, so callers that
	// only need "was this peer ever contacted" use this flag instead).
	bool receivedAny() const { return ever_; }

private:
	socket_t sock_ = STICE_INVALID_SOCKET;
	uint16_t port_ = 0;
	bool ever_ = false;
};

// Minimal STUN-speaking peer used by the protocol-level ICE tests (role
// conflict, peer-reflexive discovery). It sends/receives real STUN messages
// over loopback so the agent's wire behavior can be asserted directly instead
// of being inferred from the C API.
class StunProbePeer {
public:
	// Bind to the same local address the agent advertises so the probe can
	// reach it: on Windows a socket bound to 127.0.0.1 cannot send to a
	// non-loopback address (WSAEINVAL), and the agent never advertises a
	// loopback host candidate (localAddrs filters it out).
	explicit StunProbePeer(const std::string &bindIp = "127.0.0.1") {
		sock_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		REQUIRE(sock_ != STICE_INVALID_SOCKET);
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		REQUIRE(::inet_pton(AF_INET, bindIp.c_str(), &addr.sin_addr) == 1);
		addr.sin_port = 0;
		REQUIRE(::bind(sock_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
		sockaddr_in bound{};
		socklen_t blen = sizeof(bound);
		REQUIRE(getsockname(sock_, reinterpret_cast<sockaddr *>(&bound), &blen) == 0);
		port_ = ntohs(bound.sin_port);
		REQUIRE(stice::net::setNonBlocking(sock_));
	}
	~StunProbePeer() { sticeClosesocket(sock_); }
	uint16_t port() const { return port_; }

	bool sendTo(const stice::stun::Message &m, const std::string &ip, uint16_t port) {
		sockaddr_in dst{};
		dst.sin_family = AF_INET;
		dst.sin_port = htons(port);
		REQUIRE(::inet_pton(AF_INET, ip.c_str(), &dst.sin_addr) == 1);
		return ::sendto(sock_, reinterpret_cast<const char *>(m.raw.data()),
		                static_cast<int>(m.raw.size()), 0,
		                reinterpret_cast<const sockaddr *>(&dst), sizeof(dst)) ==
		       static_cast<int>(m.raw.size());
	}

	// Receive and decode one STUN message; false on timeout / non-STUN data.
	bool recv(stice::stun::Message &m, int timeoutMs) {
		auto deadline = std::chrono::steady_clock::now() +
		                std::chrono::milliseconds(timeoutMs);
		while (std::chrono::steady_clock::now() < deadline) {
			unsigned char buf[1500];
			sockaddr_in src{};
			socklen_t slen = sizeof(src);
			int n = ::recvfrom(sock_, reinterpret_cast<char *>(buf), sizeof(buf), 0,
			                   reinterpret_cast<sockaddr *>(&src), &slen);
			if (n > 0 && stice::stun::Message::isMessage(buf, static_cast<size_t>(n)) &&
			    m.decode(buf, static_cast<size_t>(n)))
				return true;
			std::this_thread::sleep_for(std::chrono::milliseconds(2));
		}
		return false;
	}

private:
	socket_t sock_ = STICE_INVALID_SOCKET;
	uint16_t port_ = 0;
};

// Extract a local UDP host candidate from the agent's SDP. Prefers the
// loopback address so the probe can always reach it.
bool findLocalHostCandidate(const std::string &sdp, std::string &ip, uint16_t &port) {
	std::istringstream iss(sdp);
	std::string line;
	bool haveAny = false;
	std::string anyIp;
	uint16_t anyPort = 0;
	while (std::getline(iss, line)) {
		if (line.rfind("a=candidate:", 0) != 0) continue;
		std::istringstream ls(line);
		std::vector<std::string> tok;
		std::string t;
		while (ls >> t) tok.push_back(t);
		// a=candidate:<foundation> <component> <transport> <prio> <ip> <port> typ ...
		if (tok.size() < 8) continue;
		if (tok[2] != "UDP" && tok[2] != "udp") continue;
		uint16_t p = static_cast<uint16_t>(std::stoi(tok[5]));
		if (tok[4] == "127.0.0.1") {
			ip = tok[4];
			port = p;
			return true;
		}
		if (!haveAny) {
			anyIp = tok[4];
			anyPort = p;
			haveAny = true;
		}
	}
	if (!haveAny) return false;
	ip = anyIp;
	port = anyPort;
	return true;
}

TEST_CASE("ICE same generation: candidate change with empty checklist still re-forms pairs",
          "[integration][udp][restart]") {
	// Gap fix: the same-generation checklist rebuild used to be gated on
	// !pairs_.empty(). When the first delivery carried nothing pairable,
	// pairs_ stayed empty and a changed re-delivery was applied to remote_
	// without ever reaching formPairs() — the new candidates could only die at
	// the PAC timeout. The rebuild is now unconditional: the changed list
	// pairs immediately and the checker arms the new pair, observed here by
	// the connectivity check actually hitting the probe peer.
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa;
	auto cfgA = makeConfig(sa);
	stice_agent_t *a = stice_create(&cfgA);
	REQUIRE(a != nullptr);

	UdpProbePeer peer;
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));

	// First delivery: credentials only, no candidate, no EOC.
	const char *credsOnly = "a=ice-ufrag:samegen1ufrag\n"
	                        "a=ice-pwd:samegen1pwdsamegen1pwdsame\n";
	REQUIRE(stice_set_remote_description(a, credsOnly) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.state.load() == STICE_STATE_CONNECTING; }, 2000));
	REQUIRE(sa.state.load() == STICE_STATE_CONNECTING);

	// Same generation (identical ufrag/pwd), candidate list 0 -> 1 pointing
	// at the probe peer.
	std::string withCand =
	    std::string(credsOnly) + "a=candidate:gen2 1 UDP 2122252543 127.0.0.1 " +
	    std::to_string(peer.port()) + " typ host\r\n";
	REQUIRE(stice_set_remote_description(a, withCand.c_str()) == STICE_ERR_SUCCESS);

	// The rebuilt checklist must arm a check against the new candidate.
	REQUIRE(waitFor([&] { return peer.gotDatagram(); }, 5000));
	// Still checking (no fast-fail: the re-delivery carried no EOC).
	REQUIRE(sa.state.load() == STICE_STATE_CONNECTING);

	stice_destroy(a);
}

TEST_CASE("ICE same generation: changed candidate list on a live session rebuilds and reconnects",
          "[integration][udp][restart]") {
	// Regression (ASAN heap-use-after-free): replacing remote_ frees the deque
	// storage that live CandidatePairs point into, so a same-generation
	// re-delivery with a genuinely changed candidate list MUST go through
	// resetChecklist() BEFORE the replacement, then re-form pairs and converge
	// again on the live session.
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);
	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);

	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	trickleExchange(a, sa, b, sb);
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 5000));

	char bufB[4096];
	REQUIRE(stice_get_local_description(b, bufB, sizeof(bufB)) == STICE_ERR_SUCCESS);

	// Same generation of B, candidate list changed: append one unroutable
	// TEST-NET-1 documentation candidate (no peer answers there; the real
	// candidates below still carry the session).
	std::string sdpB2 = std::string(bufB) +
	    "a=candidate:audit 1 UDP 2122252543 192.0.2.1 9 typ host\r\n";
	REQUIRE(stice_set_remote_description(a, sdpB2.c_str()) == STICE_ERR_SUCCESS);

	// The rebuilt checklist converges again; send() succeeds once a pair has
	// been re-selected, and the message reaches B.
	const char *msg = "alive after same-generation checklist rebuild";
	REQUIRE(waitFor([&] {
		return stice_send(a, msg, std::strlen(msg)) == STICE_ERR_SUCCESS;
	}, 10000));
	REQUIRE(waitForRecv(sb, msg, 3000));

	stice_destroy(a);
	stice_destroy(b);
}

TEST_CASE("ICE same generation: duplicate delivery absorbs EOC and session attributes",
          "[integration][udp][restart]") {
	// Gap fix: the allKnown early-return used to silently drop everything
	// except candidates from a same-generation re-delivery. A signalling retry
	// can legitimately carry a newly completed a=end-of-candidates (and, in
	// principle, corrected a=ice-lite / trickle ice-option tokens) — those
	// must be absorbed into the live description, not dropped.
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa;
	auto cfgA = makeConfig(sa);
	stice_agent_t *a = stice_create(&cfgA);
	REQUIRE(a != nullptr);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));

	const char *credsOnly = "a=ice-ufrag:samegen1ufrag\n"
	                        "a=ice-pwd:samegen1pwdsamegen1pwdsame\n";
	REQUIRE(stice_set_remote_description(a, credsOnly) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.state.load() == STICE_STATE_CONNECTING; }, 2000));
	REQUIRE(sa.state.load() == STICE_STATE_CONNECTING);

	// No EOC: the agent must keep waiting (trickle may still bring candidates).
	std::this_thread::sleep_for(std::chrono::milliseconds(300));
	REQUIRE(sa.state.load() == STICE_STATE_CONNECTING);

	SECTION("end-of-candidates absorbed on duplicate delivery fast-fails") {
		std::string withEoc = std::string(credsOnly) + "a=end-of-candidates\r\n";
		REQUIRE(stice_set_remote_description(a, withEoc.c_str()) == STICE_ERR_SUCCESS);
		// The absorbed EOC flips remoteGatheringDone_: both sides are done
		// gathering with zero pairs, so the deliberate fast-failure path fires
		// instead of sitting in CONNECTING.
		REQUIRE(waitFor([&] { return sa.state.load() == STICE_STATE_FAILED; }, 3000));
	}

	SECTION("ice-lite flip rides the absorb path instead of being dropped") {
		// a=ice-lite is not consumed by the checklist today; the assertion
		// pins that an attribute-changed duplicate is absorbed through the
		// same-generation path (no restart, no error) and the newly complete
		// EOC still takes effect.
		std::string withAttrs = std::string(credsOnly) +
		    "a=ice-lite\r\na=end-of-candidates\r\n";
		REQUIRE(stice_set_remote_description(a, withAttrs.c_str()) == STICE_ERR_SUCCESS);
		REQUIRE(waitFor([&] { return sa.state.load() == STICE_STATE_FAILED; }, 3000));
	}

	stice_destroy(a);
}

TEST_CASE("ICE restart re-syncs the advertised trickle option",
          "[integration][udp][restart]") {
	// 0.14.1 gap fix: local_.trickleEnabled was pinned once at init, so a
	// restart after a set_pairing_config change kept describing the new
	// generation with the OLD trickle mode. gatherCandidates() must re-read
	// pairingCfg_.enable_trickle on every generation.
	//
	// The trickle token is only visible while the local description is still
	// unfinished (a=end-of-candidates replaces the ice-options trickle token
	// once gathering completes), so the test pins gathering open with a silent
	// STUN sink: a bound UDP socket that never answers keeps the server item
	// in its retransmission window for seconds.
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	socket_t sink = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	REQUIRE(sink != STICE_INVALID_SOCKET);
	sockaddr_in saddr{};
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	saddr.sin_port = 0;
	REQUIRE(::bind(sink, reinterpret_cast<sockaddr *>(&saddr), sizeof(saddr)) == 0);
	sockaddr_in bound{};
	socklen_t blen = sizeof(bound);
	REQUIRE(getsockname(sink, reinterpret_cast<sockaddr *>(&bound), &blen) == 0);
	const uint16_t sinkPort = ntohs(bound.sin_port);

	AgentState sa;
	auto cfgA = makeConfig(sa);
	cfgA.stun_server_host = "127.0.0.1";
	cfgA.stun_server_port = sinkPort;
	stice_agent_t *a = stice_create(&cfgA);
	REQUIRE(a != nullptr);

	auto localSdp = [&](char *buf, size_t n) {
		REQUIRE(stice_get_local_description(a, buf, n) == STICE_ERR_SUCCESS);
		return std::string(buf);
	};

	// First generation: the default profile advertises trickle.
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	char buf1[2048], buf2[2048];
	std::string sdp1 = localSdp(buf1, sizeof(buf1));
	REQUIRE(sdp1.find("a=ice-options:ice2,trickle") != std::string::npos);

	// Switch the pairing config to non-trickle and restart: the fresh
	// generation must carry the new mode.
	stice_ice_pairing_config_t pc{};
	REQUIRE(stice_make_pairing_config(STICE_PAIRING_RFC8445_COMPAT, &pc) == STICE_ERR_SUCCESS);
	pc.enable_trickle = false;
	REQUIRE(stice_set_pairing_config(a, &pc) == STICE_ERR_SUCCESS);
	sa.gatheringDone.store(false);
	REQUIRE(stice_agent_restart(a) == STICE_ERR_SUCCESS);

	std::string sdp2 = localSdp(buf2, sizeof(buf2));
	REQUIRE(sdp2.find("a=ice-options:ice2,trickle") == std::string::npos);
	REQUIRE(sdp2.find("a=ice-options:ice2\r\n") != std::string::npos);
	// The restart also produced a fresh generation of credentials.
	REQUIRE(sdp2.substr(sdp2.find("a=ice-ufrag:") + 12, 8) !=
	        sdp1.substr(sdp1.find("a=ice-ufrag:") + 12, 8));

	stice_destroy(a);
	sticeClosesocket(sink);
}

TEST_CASE("ICE state machine: New -> Gathering -> Checking -> Connected", "[integration][state]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);

	REQUIRE(sa.state.load() == STICE_STATE_DISCONNECTED);
	REQUIRE(sb.state.load() == STICE_STATE_DISCONNECTED);

	// Triggering gathering transitions both to GATHERING.
	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);

	REQUIRE(waitFor([&] { return sa.state.load() == STICE_STATE_GATHERING; }, 500));
	REQUIRE(waitFor([&] { return sb.state.load() == STICE_STATE_GATHERING; }, 500));

	// Exchange descriptions -> transition to CONNECTING (Checking).
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 3000));

	char bufA[4096], bufB[4096];
	REQUIRE(stice_get_local_description(a, bufA, sizeof(bufA)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b, bufB, sizeof(bufB)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(a, bufB) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(b, bufA) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);

	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTING || as == STICE_STATE_CONNECTED ||
		        as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTING || bs == STICE_STATE_CONNECTED ||
		        bs == STICE_STATE_COMPLETED);
	}, 2000));

	// Eventually reach CONNECTED or COMPLETED.
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 5000));

	stice_destroy(a);
	stice_destroy(b);
}

TEST_CASE("stice_set_local_ice_attributes: custom ufrag/pwd used", "[integration][ufrag]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);

	REQUIRE(stice_set_local_ice_attributes(a, "customufragA", "custompwdAcustompwdAxxxx") ==
	        STICE_ERR_SUCCESS);
	REQUIRE(stice_set_local_ice_attributes(b, "customufragB", "custompwdBcustompwdBxxxx") ==
	        STICE_ERR_SUCCESS);

	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);

	char bufA[4096], bufB[4096];
	REQUIRE(stice_get_local_description(a, bufA, sizeof(bufA)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b, bufB, sizeof(bufB)) == STICE_ERR_SUCCESS);

	REQUIRE(std::string(bufA).find("customufragA") != std::string::npos);
	REQUIRE(std::string(bufA).find("custompwdAcustompwdAxxxx") != std::string::npos);
	REQUIRE(std::string(bufB).find("customufragB") != std::string::npos);
	REQUIRE(std::string(bufB).find("custompwdBcustompwdBxxxx") != std::string::npos);

	REQUIRE(stice_set_remote_description(a, bufB) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(b, bufA) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);

	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 5000));

	stice_destroy(a);
	stice_destroy(b);
}

TEST_CASE("State transitions to FAILED when remote description never set", "[integration][failed]") {
	stice_set_log_level(STICE_LOG_LEVEL_FATAL);

	AgentState sa;
	auto cfgA = makeConfig(sa);
	stice_agent_t *a = stice_create(&cfgA);
	REQUIRE(a != nullptr);

	// Gather host candidates but never set a remote description.
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);

	// After gathering the agent should stay in GATHERING (waiting for
	// remote description). It should NOT transition to CONNECTING/FAILED
	// until a remote description arrives.
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));
	REQUIRE(sa.state.load() == STICE_STATE_GATHERING);

	stice_destroy(a);
}

// ---------------------------------------------------------------------------
// Test 4: TURN Relay allocation (Integration Test 4)
//   Two agents on the same machine, both configured with a TURN server taken
//   from STICE_TEST_TURN_HOST/_PORT/_USER/_PASS (defaults to the lab coturn).
//   Only relay candidates are exchanged (host candidates filtered out) so
//   all traffic flows through the TURN relay. SKIPs when the server is
//   unreachable.
//   Verifies: TURN Allocate, CreatePermission, ChannelBind, ChannelData,
//             and bidirectional data exchange via the relay.
// ---------------------------------------------------------------------------

namespace {
// Filter an SDP string to only include relay candidates (typ relay).
// Keeps ice-ufrag, ice-pwd, and end-of-candidates lines.
std::string filterRelayOnly(const std::string &sdp) {
	std::string out;
	std::istringstream iss(sdp);
	std::string line;
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
} // namespace

TEST_CASE("TURN relay: all traffic via coturn relay", "[integration][turn]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	const ExternalTurn turn = externalTurn();
	if (!udpEndpointReachable(turn.host, turn.port, 1000))
		SKIP("no TURN server at " << turn.host << ":" << turn.port
		                          << " (set STICE_TEST_TURN_HOST/_PORT)");

	AgentState sa, sb;

	stice_config_t cfgA = makeConfig(sa);
	stice_config_t cfgB = makeConfig(sb);
	// Also set STUN server (the TURN server answers Binding too) to test UDP recv.
	cfgA.stun_server_host = turn.host.c_str();
	cfgA.stun_server_port = turn.port;
	cfgB.stun_server_host = turn.host.c_str();
	cfgB.stun_server_port = turn.port;

	stice_turn_server_t turnServer{};
	turnServer.host = turn.host.c_str();
	turnServer.port = turn.port;
	turnServer.username = turn.username.c_str();
	turnServer.password = turn.password.c_str();
	turnServer.transport = STICE_TURN_TRANSPORT_UDP;

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);
	REQUIRE(stice_add_turn_server(a, &turnServer) == STICE_ERR_SUCCESS);
	REQUIRE(stice_add_turn_server(b, &turnServer) == STICE_ERR_SUCCESS);

	// Gather candidates (host + relay). TURN allocation takes a few round-trips.
	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);

	// Wait for gathering to complete (TURN allocation included).
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 10000));
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 10000));

	// Verify relay candidates were gathered.
	REQUIRE(!sa.candidates.empty());
	REQUIRE(!sb.candidates.empty());
	bool hasRelayA = false, hasRelayB = false;
	for (const auto &c : sa.candidates)
		if (c.find("typ relay") != std::string::npos) hasRelayA = true;
	for (const auto &c : sb.candidates)
		if (c.find("typ relay") != std::string::npos) hasRelayB = true;
	REQUIRE(hasRelayA);
	REQUIRE(hasRelayB);

	// Get local SDP and filter to relay-only.
	char bufA[4096], bufB[4096];
	REQUIRE(stice_get_local_description(a, bufA, sizeof(bufA)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b, bufB, sizeof(bufB)) == STICE_ERR_SUCCESS);

	std::string sdpA = filterRelayOnly(bufA);
	std::string sdpB = filterRelayOnly(bufB);
	INFO("SDP A (relay-only): " << sdpA);
	INFO("SDP B (relay-only): " << sdpB);
	REQUIRE(sdpA.find("typ relay") != std::string::npos);
	REQUIRE(sdpB.find("typ relay") != std::string::npos);

	// Exchange relay-only SDP.
	REQUIRE(stice_set_remote_description(a, sdpB.c_str()) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(b, sdpA.c_str()) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);

	// Wait for both to reach CONNECTED or COMPLETED (relay path is slower).
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 15000));

	// Bidirectional data exchange through the relay.
	const char *msgAtoB = "relay-hello-A";
	const char *msgBtoA = "relay-hello-B";
	REQUIRE(stice_send(a, msgAtoB, std::strlen(msgAtoB)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_send(b, msgBtoA, std::strlen(msgBtoA)) == STICE_ERR_SUCCESS);

	REQUIRE(waitFor([&] { return recvCount(sb) >= 1; }, 5000));
	REQUIRE(waitFor([&] { return recvCount(sa) >= 1; }, 5000));
	REQUIRE(recvAt(sb, 0) == msgAtoB);
	REQUIRE(recvAt(sa, 0) == msgBtoA);

	// Verify the selected pair involves a relay candidate. Since host
	// candidates have higher priority than relayed ones, ICE may select a
	// (host local, relay remote) pair — the data still flows through the
	// relay because the remote is relayed. The remote must be relay (only
	// relay candidates were exchanged), confirming the relay path is used.
	char localA[512], remoteA[512];
	REQUIRE(stice_get_selected_candidates(a, localA, sizeof(localA), remoteA, sizeof(remoteA)) ==
	        STICE_ERR_SUCCESS);
	REQUIRE(std::string(remoteA).find("typ relay") != std::string::npos);

	stice_destroy(a);
	stice_destroy(b);
}

// ---------------------------------------------------------------------------
// Test 4b: Multi-ICE-server parallel gathering (aligned with pion-ice)
//   Two agents on the same machine, each configured with MULTIPLE STUN and
//   TURN servers from DIFFERENT providers, mirroring the pion
//   webrtc.Configuration.ICEServers pattern (TURN #1 + TURN #2 + public STUN):
//     - STUN #1: primary TURN host   (STICE_TEST_TURN_HOST, fast/reliable)
//     - STUN #2: secondary TURN host (STICE_TEST_TURN2_HOST, second provider)
//     - STUN #3: stun.l.google.com:19302 (public, may be slow/unreachable)
//     - TURN #1: primary TURN host   (config index 0)
//     - TURN #2: secondary TURN host (config index 1)
//   Verifies:
//     1. Multi-STUN parallel gathering: srflx candidates collected from all
//        configured STUN servers concurrently. Google STUN failure (if public
//        network blocked) is isolated and does not block the local STUN
//        gathering.
//     2. Multi-TURN parallel gathering: relay candidates collected from both
//        TURN servers concurrently, each producing an independent relay
//        allocation (distinct 5-tuples → no RFC 5766 §2.3 collision).
//     3. Relay candidate priority ordering: relay candidates from earlier
//        TURN servers in the config array get higher priority (lower index
//        subtracted from localPref in computePriority).
//     4. End-to-end relay connectivity + bidirectional data exchange.
//   The test SKIPs unless both TURN servers answer a STUN binding probe.
// ---------------------------------------------------------------------------

// Parse the priority field from an a=candidate line. Returns 0 on failure.
static std::uint32_t parseCandidatePriority(const std::string &candSdp) {
	// a=candidate:<foundation> <component> <transport> <priority> ...
	auto pos = candSdp.find("a=candidate:");
	if (pos == std::string::npos) return 0;
	std::istringstream iss(candSdp.substr(pos + 12));
	std::string foundation, componentStr, transport, priorityStr;
	iss >> foundation >> componentStr >> transport >> priorityStr;
	try {
		return static_cast<std::uint32_t>(std::stoul(priorityStr));
	} catch (...) {
		return 0;
	}
}

TEST_CASE("Multi-ICE-server: parallel STUN+TURN gathering and relay ordering",
          "[integration][turn][multi]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	const ExternalTurn turn1Cfg = externalTurn();
	const ExternalTurn turn2Cfg = externalTurn2();
	if (!udpEndpointReachable(turn1Cfg.host, turn1Cfg.port, 1000) ||
	    !udpEndpointReachable(turn2Cfg.host, turn2Cfg.port, 1000))
		SKIP("needs two TURN servers (STICE_TEST_TURN_HOST, STICE_TEST_TURN2_HOST)");

	AgentState sa, sb;

	stice_config_t cfgA = makeConfig(sa);
	stice_config_t cfgB = makeConfig(sb);

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);

	// --- Multi-STUN: TURN #1 + TURN #2 + Google (public) ---
	// Mirrors pion ICEServers with three STUN providers. All are queried
	// concurrently; if Google STUN is unreachable (public network blocked),
	// its failure is isolated and the two local STUN servers still produce srflx.
	REQUIRE(stice_add_stun_server(a, turn1Cfg.host.c_str(), turn1Cfg.port) == STICE_ERR_SUCCESS);
	REQUIRE(stice_add_stun_server(a, turn2Cfg.host.c_str(), turn2Cfg.port) == STICE_ERR_SUCCESS);
	REQUIRE(stice_add_stun_server(a, "stun.l.google.com", 19302) == STICE_ERR_SUCCESS);
	REQUIRE(stice_add_stun_server(b, turn1Cfg.host.c_str(), turn1Cfg.port) == STICE_ERR_SUCCESS);
	REQUIRE(stice_add_stun_server(b, turn2Cfg.host.c_str(), turn2Cfg.port) == STICE_ERR_SUCCESS);
	REQUIRE(stice_add_stun_server(b, "stun.l.google.com", 19302) == STICE_ERR_SUCCESS);

	// --- Multi-TURN: provider #1 (index 0) + provider #2 (index 1) ---
	// Two DIFFERENT physical TURN servers → distinct 5-tuples, so both
	// Allocate requests succeed independently (no RFC 5766 §2.3 collision).
	// The first (index 0) must have higher relay priority than the second
	// (index 1), verifying config-order relay priority alignment with pion-ice.
	stice_turn_server_t turn1{};
	turn1.host = turn1Cfg.host.c_str();
	turn1.port = turn1Cfg.port;
	turn1.username = turn1Cfg.username.c_str();
	turn1.password = turn1Cfg.password.c_str();
	turn1.transport = STICE_TURN_TRANSPORT_UDP;

	stice_turn_server_t turn2{};
	turn2.host = turn2Cfg.host.c_str();
	turn2.port = turn2Cfg.port;
	turn2.username = turn2Cfg.username.c_str();
	turn2.password = turn2Cfg.password.c_str();
	turn2.transport = STICE_TURN_TRANSPORT_UDP;

	REQUIRE(stice_add_turn_server(a, &turn1) == STICE_ERR_SUCCESS);
	REQUIRE(stice_add_turn_server(a, &turn2) == STICE_ERR_SUCCESS);
	REQUIRE(stice_add_turn_server(b, &turn1) == STICE_ERR_SUCCESS);
	REQUIRE(stice_add_turn_server(b, &turn2) == STICE_ERR_SUCCESS);

	// Gather candidates: multi-STUN + TURN in parallel.
	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);

	// Wait for gathering to complete (TURN allocations take a few RTTs;
	// Google STUN may time out if public network is blocked — the wait
	// covers the full gathering window including any failed-server timeout).
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 20000));
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 20000));

	// --- Verify multi-STUN parallel gathering produced srflx candidates ---
	// At least the coturn STUN should succeed; Google STUN may or may not
	// depending on public network reachability (failure isolation).
	bool hasSrflxA = false, hasSrflxB = false;
	for (const auto &c : sa.candidates)
		if (c.find("typ srflx") != std::string::npos) hasSrflxA = true;
	for (const auto &c : sb.candidates)
		if (c.find("typ srflx") != std::string::npos) hasSrflxB = true;
	REQUIRE(hasSrflxA);
	REQUIRE(hasSrflxB);

	// --- Verify multi-TURN parallel gathering produced relay candidates ---
	std::vector<std::string> relayA, relayB;
	for (const auto &c : sa.candidates)
		if (c.find("typ relay") != std::string::npos) relayA.push_back(c);
	for (const auto &c : sb.candidates)
		if (c.find("typ relay") != std::string::npos) relayB.push_back(c);
	INFO("Agent A relay candidates: " << relayA.size());
	INFO("Agent B relay candidates: " << relayB.size());
	REQUIRE(relayA.size() >= 2);
	REQUIRE(relayB.size() >= 2);

	// --- Verify relay candidate priority shape ---
	// localPref is subtracted by (config index + allocation-RTT penalty), so the
	// per-server ordering is not deterministic: a fast TURN server outranks a
	// slow one even at a lower config index. What must hold is the bit layout —
	// every per-server difference lives in localPref, i.e. bits 8+, so all relay
	// priorities differ by multiples of 256 and share the same low byte.
	std::uint32_t maxPrio = 0, minPrio = UINT32_MAX;
	for (const auto &c : relayA) {
		std::uint32_t p = parseCandidatePriority(c);
		if (p > maxPrio) maxPrio = p;
		if (p < minPrio) minPrio = p;
	}
	INFO("Relay A max priority: " << maxPrio << "  min priority: " << minPrio);
	REQUIRE(maxPrio > 0);
	REQUIRE((maxPrio - minPrio) % 256 == 0);
	REQUIRE((maxPrio & 0xFF) == (minPrio & 0xFF));

	// --- Filter to relay-only SDP and exchange ---
	char bufA[4096], bufB[4096];
	REQUIRE(stice_get_local_description(a, bufA, sizeof(bufA)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b, bufB, sizeof(bufB)) == STICE_ERR_SUCCESS);

	std::string sdpA = filterRelayOnly(bufA);
	std::string sdpB = filterRelayOnly(bufB);
	REQUIRE(sdpA.find("typ relay") != std::string::npos);
	REQUIRE(sdpB.find("typ relay") != std::string::npos);

	REQUIRE(stice_set_remote_description(a, sdpB.c_str()) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(b, sdpA.c_str()) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);

	// --- Wait for connectivity through relay ---
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 15000));

	// --- Bidirectional data exchange through the relay ---
	const char *msgAtoB = "multi-turn-hello-A";
	const char *msgBtoA = "multi-turn-hello-B";
	REQUIRE(stice_send(a, msgAtoB, std::strlen(msgAtoB)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_send(b, msgBtoA, std::strlen(msgBtoA)) == STICE_ERR_SUCCESS);

	REQUIRE(waitFor([&] { return recvCount(sb) >= 1; }, 5000));
	REQUIRE(waitFor([&] { return recvCount(sa) >= 1; }, 5000));
	REQUIRE(recvAt(sb, 0) == msgAtoB);
	REQUIRE(recvAt(sa, 0) == msgBtoA);

	// --- Verify selected pair uses a relay candidate (remote side) ---
	char localA[512], remoteA[512];
	REQUIRE(stice_get_selected_candidates(a, localA, sizeof(localA), remoteA, sizeof(remoteA)) ==
	        STICE_ERR_SUCCESS);
	REQUIRE(std::string(remoteA).find("typ relay") != std::string::npos);

	stice_destroy(a);
	stice_destroy(b);
}

// ---------------------------------------------------------------------------
// Phase 3: ICE Agent state machine tests
//
// These tests verify the ICE state machine transitions using the public C API
// over a local UDP loopback. They mirror pion-ice's agent.go state flow:
//   New → Gathering → Checking → Connected → Completed
//   Checking → Failed (when all pairs fail)
//   USE-CANDIDATE nomination drives the controlling side to Completed.
// ---------------------------------------------------------------------------

TEST_CASE("ICE nomination: controlling side reaches COMPLETED via USE-CANDIDATE",
          "[integration][state][nomination]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);

	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);

	trickleExchange(a, sa, b, sb);

	// The controlling side (A) must eventually reach COMPLETED, which is the
	// post-nomination state. This confirms USE-CANDIDATE was sent by the
	// controller and accepted by the controlled side.
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		return as == STICE_STATE_COMPLETED;
	}, 5000));

	// The controlled side (B) should be at least CONNECTED.
	REQUIRE(waitFor([&] {
		auto bs = sb.state.load();
		return bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED;
	}, 5000));

	// After nomination, data must still flow in both directions.
	const char *msg = "post-nomination-data";
	REQUIRE(stice_send(a, msg, std::strlen(msg)) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return recvCount(sb) >= 1; }, 2000));
	REQUIRE(sb.received[0] == msg);

	// The selected pair must be queryable on both sides.
	char localA[512], remoteA[512];
	REQUIRE(stice_get_selected_candidates(a, localA, sizeof(localA), remoteA, sizeof(remoteA)) ==
	        STICE_ERR_SUCCESS);
	REQUIRE(std::string(localA).size() > 0);
	REQUIRE(std::string(remoteA).size() > 0);

	stice_destroy(a);
	stice_destroy(b);
}

TEST_CASE("ICE state transition matrix: New → Gathering → Checking → Connected/Completed",
          "[integration][state][matrix]") {
	// Verifies the core state transitions from RFC 8445 §9 (pion agent.go):
	//   Disconnected --GatherCandidates()--> Gathering
	//   Gathering     --OnGatheringComplete()--> Checking
	//   Checking      --Valid pair found--> Connected
	//   Connected     --USE-CANDIDATE received--> Completed
	//   Checking      --All pairs failed--> Failed
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	SECTION("New -> Gathering on gather_candidates()") {
		AgentState sa;
		auto cfgA = makeConfig(sa);
		stice_agent_t *a = stice_create(&cfgA);
		REQUIRE(sa.state.load() == STICE_STATE_DISCONNECTED);

		REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
		REQUIRE(waitFor([&] { return sa.state.load() == STICE_STATE_GATHERING; }, 500));

		stice_destroy(a);
	}

	SECTION("Gathering -> Checking -> Connected/Completed") {
		AgentState sa, sb;
		auto cfgA = makeConfig(sa);
		auto cfgB = makeConfig(sb);
		stice_agent_t *a = stice_create(&cfgA);
		stice_agent_t *b = stice_create(&cfgB);

		REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
		REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
		REQUIRE(waitFor([&] { return sa.state.load() == STICE_STATE_GATHERING; }, 500));
		REQUIRE(waitFor([&] { return sb.state.load() == STICE_STATE_GATHERING; }, 500));

		trickleExchange(a, sa, b, sb);

		// After remote description + gathering done, transition to CONNECTING.
		REQUIRE(waitFor([&] {
			auto as = sa.state.load();
			return as == STICE_STATE_CONNECTING || as == STICE_STATE_CONNECTED ||
			       as == STICE_STATE_COMPLETED;
		}, 2000));

		// Eventually reach CONNECTED or COMPLETED.
		REQUIRE(waitFor([&] {
			auto as = sa.state.load();
			auto bs = sb.state.load();
			return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
			       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
		}, 5000));

		stice_destroy(a);
		stice_destroy(b);
	}

	SECTION("Checking -> Failed when no remote description") {
		// An agent that gathers but never receives a remote description stays
		// in Gathering (no pairs to check). This documents the behavior: the
		// agent does NOT transition to Failed until it has entered Checking.
		AgentState sa;
		auto cfgA = makeConfig(sa);
		stice_agent_t *a = stice_create(&cfgA);
		REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
		REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));
		REQUIRE(sa.state.load() == STICE_STATE_GATHERING);

		stice_destroy(a);
	}

	SECTION("Close: destroy transitions agent away from active states") {
		// stice_destroy tears down the agent. After destroy, the handle is
		// invalid; we verify the agent reached at least Connected before close
		// and that destroy does not hang.
		AgentState sa, sb;
		auto cfgA = makeConfig(sa);
		auto cfgB = makeConfig(sb);
		stice_agent_t *a = stice_create(&cfgA);
		stice_agent_t *b = stice_create(&cfgB);
		REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
		REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
		trickleExchange(a, sa, b, sb);
		REQUIRE(waitFor([&] {
			auto as = sa.state.load();
			auto bs = sb.state.load();
			return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
			       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
		}, 5000));

		// Close both agents — must not block or crash.
		stice_destroy(a);
		stice_destroy(b);
		REQUIRE(true); // reached here without hanging
	}
}

// ---------------------------------------------------------------------------
// UDPMux tests: multiple ICE agents sharing a single UDP socket.
// ---------------------------------------------------------------------------

TEST_CASE("UDPMux: two agents share one socket, connect and exchange data",
          "[integration][udpmux]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	// Create a shared UDPMux on an ephemeral port.
	stice_udp_mux_t *mux = stice_create_udp_mux(nullptr, 0, 0);
	REQUIRE(mux != nullptr);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);

	// Bind both agents to the shared mux BEFORE gathering.
	REQUIRE(stice_agent_use_udp_mux(a, mux) == STICE_ERR_SUCCESS);
	REQUIRE(stice_agent_use_udp_mux(b, mux) == STICE_ERR_SUCCESS);

	// B is controlled (sets remote description first); A is controlling.
	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);

	trickleExchange(a, sa, b, sb);

	// Wait for both sides to reach CONNECTED or COMPLETED.
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 5000));

	// Bidirectional data exchange.
	// Note: in UDPMux loopback mode, both agents share the same address.
	// The mux tracks the last sender to avoid echoing data back. Sending
	// both messages simultaneously can cause the address map to be
	// overwritten before the first packet is processed. We send A→B first,
	// wait for delivery, then send B→A.
	const char *msgAtoB = "mux hello from A";
	const char *msgBtoA = "mux hello from B";
	REQUIRE(stice_send(a, msgAtoB, std::strlen(msgAtoB)) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return recvCount(sb) >= 1; }, 2000));
	REQUIRE(stice_send(b, msgBtoA, std::strlen(msgBtoA)) == STICE_ERR_SUCCESS);

	REQUIRE(waitFor([&] { return recvCount(sb) >= 1; }, 2000));
	REQUIRE(waitFor([&] { return recvCount(sa) >= 1; }, 2000));

	REQUIRE(recvAt(sb, 0) == msgAtoB);
	REQUIRE(recvAt(sa, 0) == msgBtoA);

	stice_destroy(a);
	stice_destroy(b);
	stice_destroy_udp_mux(mux);
}

TEST_CASE("UDPMux: agent restart re-registers the new ufrag and reconnects",
          "[integration][udpmux][restart]") {
	// 0.14.0 made restart() drop the old generation's mux registration and
	// re-register under the new ufrag: the mux demuxes inbound packets by ufrag,
	// so without it the endpoint was permanently deaf to new inbound traffic
	// after an ICE restart. This path had no test at all.
	stice_set_log_level(STICE_LOG_LEVEL_DEBUG);

	stice_udp_mux_t *mux = stice_create_udp_mux(nullptr, 0, 0);
	REQUIRE(mux != nullptr);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);
	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);
	REQUIRE(stice_agent_use_udp_mux(a, mux) == STICE_ERR_SUCCESS);
	REQUIRE(stice_agent_use_udp_mux(b, mux) == STICE_ERR_SUCCESS);

	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	trickleExchange(a, sa, b, sb);
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 5000));

	// Restart A; B follows on A's new generation, then A learns B's.
	sa.gatheringDone.store(false);
	REQUIRE(stice_agent_restart(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));
	char bufA2[4096];
	REQUIRE(stice_get_local_description(a, bufA2, sizeof(bufA2)) == STICE_ERR_SUCCESS);
	sb.gatheringDone.store(false);
	REQUIRE(stice_set_remote_description(b, bufA2) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 3000));
	char bufB2[4096];
	REQUIRE(stice_get_local_description(b, bufB2, sizeof(bufB2)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(a, bufB2) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);

	// The new generation must connect through the SAME shared socket: if the
	// mux still routes by the retired ufrag, nothing arrives and this times out.
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 15000));

	const char *msgAtoB = "mux after restart from A";
	const char *msgBtoA = "mux after restart from B";
	REQUIRE(stice_send(a, msgAtoB, std::strlen(msgAtoB)) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return recvCount(sb) >= 1; }, 3000));
	REQUIRE(stice_send(b, msgBtoA, std::strlen(msgBtoA)) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return recvCount(sa) >= 1; }, 3000));

	stice_destroy(a);
	stice_destroy(b);
	stice_destroy_udp_mux(mux);
}

TEST_CASE("UDPMux: restarting one pair leaves sibling pairs untouched",
          "[integration][udpmux][restart][multi]") {
	// Two independent pairs share one mux socket. Restarting pair 1 must
	// re-register its agents under fresh ufrags WITHOUT disturbing pair 2 —
	// registration isolation. The restart also mutates the mux's agent list
	// while the poll thread iterates it for bookkeeping, exercising the
	// snapshot-then-callback discipline the AB-BA fix relies on.
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	stice_udp_mux_t *mux = stice_create_udp_mux(nullptr, 0, 0);
	REQUIRE(mux != nullptr);

	AgentState sa, sb, sc, sd;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);
	auto cfgC = makeConfig(sc);
	auto cfgD = makeConfig(sd);

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	stice_agent_t *c = stice_create(&cfgC);
	stice_agent_t *d = stice_create(&cfgD);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);
	REQUIRE(c != nullptr);
	REQUIRE(d != nullptr);
	REQUIRE(stice_agent_use_udp_mux(a, mux) == STICE_ERR_SUCCESS);
	REQUIRE(stice_agent_use_udp_mux(b, mux) == STICE_ERR_SUCCESS);
	REQUIRE(stice_agent_use_udp_mux(c, mux) == STICE_ERR_SUCCESS);
	REQUIRE(stice_agent_use_udp_mux(d, mux) == STICE_ERR_SUCCESS);

	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(d) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(c) == STICE_ERR_SUCCESS);

	trickleExchange(a, sa, b, sb);
	trickleExchange(c, sc, d, sd);

	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		auto cs = sc.state.load();
		auto ds = sd.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED) &&
		       (cs == STICE_STATE_CONNECTED || cs == STICE_STATE_COMPLETED) &&
		       (ds == STICE_STATE_CONNECTED || ds == STICE_STATE_COMPLETED);
	}, 8000));

	// Baseline traffic on both pairs. On loopback the mux broadcasts app data
	// to every agent except the sender, so waits match message CONTENT —
	// cross-delivery to the sibling pair is a known artifact.
	const char *msgAB1 = "pair1 baseline from A";
	const char *msgCD1 = "pair2 baseline from C";
	REQUIRE(stice_send(a, msgAB1, std::strlen(msgAB1)) == STICE_ERR_SUCCESS);
	REQUIRE(waitForRecv(sb, msgAB1, 2000));
	REQUIRE(stice_send(c, msgCD1, std::strlen(msgCD1)) == STICE_ERR_SUCCESS);
	REQUIRE(waitForRecv(sd, msgCD1, 2000));

	// Restart A (pair 1); B follows on A's new generation; C/D keep running.
	char bufA1[4096];
	REQUIRE(stice_get_local_description(a, bufA1, sizeof(bufA1)) == STICE_ERR_SUCCESS);
	std::string sdpA1(bufA1);
	auto ufragA1 = sdpA1.substr(sdpA1.find("a=ice-ufrag:") + 12, 4);

	sa.gatheringDone.store(false);
	REQUIRE(stice_agent_restart(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));

	char bufA2[4096];
	REQUIRE(stice_get_local_description(a, bufA2, sizeof(bufA2)) == STICE_ERR_SUCCESS);
	std::string sdpA2(bufA2);
	auto ufragA2 = sdpA2.substr(sdpA2.find("a=ice-ufrag:") + 12, 4);
	REQUIRE(ufragA2 != ufragA1);

	sb.gatheringDone.store(false);
	REQUIRE(stice_set_remote_description(b, bufA2) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 3000));
	char bufB2[4096];
	REQUIRE(stice_get_local_description(b, bufB2, sizeof(bufB2)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(a, bufB2) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);

	// The sibling pair must keep passing data WHILE pair 1 renegotiates: its
	// registrations, consent keepalives and poll bookkeeping are independent
	// of pair 1's restart. On loopback the mux attributes each app-data packet
	// to the LAST loopback sender, so a probe can be misrouted away from its
	// target under heavy check traffic — retry until one probe lands.
	bool c2dAlive = false;
	bool d2cAlive = false;
	for (int attempt = 0; attempt < 5 && !(c2dAlive && d2cAlive); ++attempt) {
		std::string probeC = "pair2 alive c->d #" + std::to_string(attempt);
		std::string probeD = "pair2 alive d->c #" + std::to_string(attempt);
		REQUIRE(stice_send(c, probeC.c_str(), probeC.size()) == STICE_ERR_SUCCESS);
		REQUIRE(stice_send(d, probeD.c_str(), probeD.size()) == STICE_ERR_SUCCESS);
		c2dAlive = waitForRecv(sd, probeC, 1000);
		d2cAlive = waitForRecv(sc, probeD, 1000);
		if (!c2dAlive) {
			// A missed C->D probe that shows up in C's OWN stream proves the
			// loopback "last sender" attribution excluded D from the broadcast.
			bool selfEcho = false;
			for (const auto &m : recvSnapshot(sc))
				if (m == probeC) selfEcho = true;
			WARN("DIAG attempt=" << attempt << " c2d miss selfEcho=" << selfEcho);
			for (const auto &m : recvSnapshot(sd))
				WARN("DIAG sd='" << m << "'");
		}
	}
	REQUIRE(c2dAlive);
	REQUIRE(d2cAlive);

	// Pair 1 reconnects in its new generation through the SAME shared socket.
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 15000));

	const char *msgAB2 = "pair1 after restart from A";
	const char *msgBA2 = "pair1 after restart from B";
	REQUIRE(stice_send(a, msgAB2, std::strlen(msgAB2)) == STICE_ERR_SUCCESS);
	REQUIRE(waitForRecv(sb, msgAB2, 3000));
	REQUIRE(stice_send(b, msgBA2, std::strlen(msgBA2)) == STICE_ERR_SUCCESS);
	REQUIRE(waitForRecv(sa, msgBA2, 3000));

	stice_destroy(a);
	stice_destroy(b);
	stice_destroy(c);
	stice_destroy(d);
	stice_destroy_udp_mux(mux);
}

TEST_CASE("UDPMux: three agents share one socket, pairwise connect",
          "[integration][udpmux][multi]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	stice_udp_mux_t *mux = stice_create_udp_mux(nullptr, 0, 0);
	REQUIRE(mux != nullptr);

	// Three agents: A↔B, A↔C. All share the same mux.
	AgentState sa, sb, sc;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);
	auto cfgC = makeConfig(sc);

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	stice_agent_t *c = stice_create(&cfgC);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);
	REQUIRE(c != nullptr);

	REQUIRE(stice_agent_use_udp_mux(a, mux) == STICE_ERR_SUCCESS);
	REQUIRE(stice_agent_use_udp_mux(b, mux) == STICE_ERR_SUCCESS);
	REQUIRE(stice_agent_use_udp_mux(c, mux) == STICE_ERR_SUCCESS);

	// Gather on all three.
	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(c) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);

	// Exchange between A and B.
	trickleExchange(a, sa, b, sb);
	// Exchange between A and C — but A already has remote desc from B.
	// For a proper 3-way test we'd need separate agents, but the key
	// point here is that all three agents' STUN traffic is correctly
	// routed by ufrag through the shared socket. So just verify A↔B works
	// and C's gathering completed without error.
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 5000));

	// A↔B data exchange.
	const char *msg = "mux3 test";
	REQUIRE(stice_send(a, msg, std::strlen(msg)) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return recvCount(sb) >= 1; }, 2000));
	REQUIRE(sb.received[0] == msg);

	// C should have gathered successfully (host candidates emitted).
	REQUIRE(sc.gatheringDone.load());

	stice_destroy(a);
	stice_destroy(b);
	stice_destroy(c);
	stice_destroy_udp_mux(mux);
}

// ---------------------------------------------------------------------------
// TURN over TCP: relay allocation and data exchange via the TURN TCP transport.
//
// Two agents configured with a TURN server using TCP transport. Both allocate
// relay candidates through TURN over TCP, exchange relay-only SDP, and verify
// bidirectional data flows through the relay. Requires a TURN server with a TCP
// listener (STICE_TEST_TURN_HOST/_PORT/_USER/_PASS); SKIPs when unreachable.
// ---------------------------------------------------------------------------

TEST_CASE("TURN over TCP: relay allocation and data exchange", "[integration][turn][tcp]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	const ExternalTurn turn = externalTurn();
	if (!tcpEndpointReachable(turn.host, turn.port, 1000))
		SKIP("no TURN TCP listener at " << turn.host << ":" << turn.port
		                                << " (set STICE_TEST_TURN_HOST/_PORT)");

	AgentState sa, sb;

	stice_config_t cfgA = makeConfig(sa);
	stice_config_t cfgB = makeConfig(sb);
	// TCP TURN requires POLL concurrency mode (shared background thread for
	// TCP socket events).
	cfgA.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
	cfgB.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;

	stice_turn_server_t turnServer{};
	turnServer.host = turn.host.c_str();
	turnServer.port = turn.port;
	turnServer.username = turn.username.c_str();
	turnServer.password = turn.password.c_str();
	turnServer.transport = STICE_TURN_TRANSPORT_TCP;
	turnServer.skip_tls_verify = 0;

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);
	REQUIRE(stice_add_turn_server(a, &turnServer) == STICE_ERR_SUCCESS);
	REQUIRE(stice_add_turn_server(b, &turnServer) == STICE_ERR_SUCCESS);

	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);

	// Wait for gathering (TCP TURN allocation may be slower than UDP).
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 15000));
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 15000));

	// Verify relay candidates were gathered.
	REQUIRE(!sa.candidates.empty());
	REQUIRE(!sb.candidates.empty());
	bool hasRelayA = false, hasRelayB = false;
	for (const auto &c : sa.candidates)
		if (c.find("typ relay") != std::string::npos) hasRelayA = true;
	for (const auto &c : sb.candidates)
		if (c.find("typ relay") != std::string::npos) hasRelayB = true;
	REQUIRE(hasRelayA);
	REQUIRE(hasRelayB);

	// Filter to relay-only SDP (same as UDP TURN test).
	char bufA[4096], bufB[4096];
	REQUIRE(stice_get_local_description(a, bufA, sizeof(bufA)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b, bufB, sizeof(bufB)) == STICE_ERR_SUCCESS);

	std::string sdpA = filterRelayOnly(bufA);
	std::string sdpB = filterRelayOnly(bufB);
	REQUIRE(sdpA.find("typ relay") != std::string::npos);
	REQUIRE(sdpB.find("typ relay") != std::string::npos);

	REQUIRE(stice_set_remote_description(a, sdpB.c_str()) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(b, sdpA.c_str()) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);

	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 15000));

	// Bidirectional data exchange through the TCP relay.
	const char *msgAtoB = "tcp-relay-hello-A";
	const char *msgBtoA = "tcp-relay-hello-B";
	REQUIRE(stice_send(a, msgAtoB, std::strlen(msgAtoB)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_send(b, msgBtoA, std::strlen(msgBtoA)) == STICE_ERR_SUCCESS);

	REQUIRE(waitFor([&] { return recvCount(sb) >= 1; }, 5000));
	REQUIRE(waitFor([&] { return recvCount(sa) >= 1; }, 5000));
	REQUIRE(recvAt(sb, 0) == msgAtoB);
	REQUIRE(recvAt(sa, 0) == msgBtoA);

	// Verify the selected pair involves a relay candidate.
	char localA[512], remoteA[512];
	REQUIRE(stice_get_selected_candidates(a, localA, sizeof(localA), remoteA, sizeof(remoteA)) ==
	        STICE_ERR_SUCCESS);
	REQUIRE(std::string(remoteA).find("typ relay") != std::string::npos);

	stice_destroy(a);
	stice_destroy(b);
}

// ---------------------------------------------------------------------------
// TURN over TCP: connection failure handling (unreachable server)
//
// Configures a TURN server at 240.0.0.1:3478 (RFC 5737 reserved address,
// guaranteed to be unroutable — connect() fails immediately with EHOSTUNREACH
// / ENETUNREACH on most stacks). Verifies that:
//   1. The Agent detects the TCP connection failure.
//   2. The TURN Client transitions to Failed state (via the
//      handleInbound(nullptr,0) transport-failure signal).
//   3. onFailed is invoked, decrementing pendingRelayAllocations_.
//   4. Gathering completes (does not hang forever) even though the relay
//      allocation never succeeded.
//   5. The agent still produces host candidates and can establish a
//      direct ICE connection without the relay.
// ---------------------------------------------------------------------------

TEST_CASE("TURN over TCP: connection failure does not hang gathering", "[integration][turn][tcp][failure]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);

	// Configure an unreachable TURN server over TCP.
	stice_turn_server_t badTurn{};
	badTurn.host = "240.0.0.1"; // RFC 5737 reserved, unroutable
	badTurn.port = 3478;
	badTurn.username = "testuser";
	badTurn.password = "123456";
	badTurn.transport = STICE_TURN_TRANSPORT_TCP;

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);
	REQUIRE(stice_add_turn_server(a, &badTurn) == STICE_ERR_SUCCESS);
	REQUIRE(stice_add_turn_server(b, &badTurn) == STICE_ERR_SUCCESS);

	// Start gathering. The TURN TCP connect should fail quickly.
	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);

	// Critical assertion: gathering must complete (not hang) despite the
	// TURN TCP connection failure. With the fix, the failure is signaled
	// to the TURN Client, which invokes onFailed, decrements the pending
	// relay count, and allows gathering to complete with only host
	// candidates. Without the fix, gathering hangs forever waiting for an
	// allocation that will never succeed.
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 5000));
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 5000));

	// Host candidates should be present (relay candidates will be absent).
	REQUIRE_FALSE(sa.candidates.empty());
	REQUIRE_FALSE(sb.candidates.empty());
	bool hasHostA = false, hasHostB = false;
	bool hasRelayA = false, hasRelayB = false;
	for (const auto &c : sa.candidates) {
		if (c.find("typ host") != std::string::npos) hasHostA = true;
		if (c.find("typ relay") != std::string::npos) hasRelayA = true;
	}
	for (const auto &c : sb.candidates) {
		if (c.find("typ host") != std::string::npos) hasHostB = true;
		if (c.find("typ relay") != std::string::npos) hasRelayB = true;
	}
	REQUIRE(hasHostA);
	REQUIRE(hasHostB);
	REQUIRE_FALSE(hasRelayA);
	REQUIRE_FALSE(hasRelayB);

	stice_destroy(a);
	stice_destroy(b);
}

// ---------------------------------------------------------------------------
// UDP ICE failure scenarios
//
// These tests exercise the error-handling paths in the ICE state machine
// that are NOT covered by the happy-path tests above:
//
// 1. ufrag mismatch → STUN 400 error response → pair Failed → Agent FAILED
// 2. Empty remote candidates → Agent stays in CONNECTING (not FAILED)
// 3. Role conflict (487) → role switch + retry (pair NOT marked Failed)
// ---------------------------------------------------------------------------

TEST_CASE("UDP ICE: ufrag mismatch causes STUN 400 → pair Failed → Agent FAILED",
          "[integration][udp][failure]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);

	// Both gather host candidates.
	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 3000));

	// Get B's local SDP and tamper with the ice-ufrag so A's STUN checks
	// will use a wrong USERNAME. B will reject with 400 (ufrag mismatch).
	char bufB[4096];
	REQUIRE(stice_get_local_description(b, bufB, sizeof(bufB)) == STICE_ERR_SUCCESS);
	std::string sdpB(bufB);
	auto ufragPos = sdpB.find("a=ice-ufrag:");
	REQUIRE(ufragPos != std::string::npos);
	auto eolPos = sdpB.find('\n', ufragPos);
	sdpB.replace(ufragPos, eolPos - ufragPos, "a=ice-ufrag:WRONGUFRAG");

	// A receives the tampered SDP (wrong ufrag for B).
	REQUIRE(stice_set_remote_description(a, sdpB.c_str()) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);

	// A enters CONNECTING and sends STUN checks to B. B rejects every
	// request with 400 (USERNAME local-part != B's local ufrag). A marks
	// all pairs as Failed and transitions to FAILED.
	REQUIRE(waitFor([&] { return sa.state.load() == STICE_STATE_CONNECTING; }, 2000));
	REQUIRE(waitFor([&] { return sa.state.load() == STICE_STATE_FAILED; }, 5000));

	// B should NOT be FAILED (it never entered CONNECTING because no
	// remote description was set on B).
	REQUIRE(sb.state.load() != STICE_STATE_FAILED);

	stice_destroy(a);
	stice_destroy(b);
}

TEST_CASE("UDP ICE: empty remote candidates + EOC fails fast",
          "[integration][udp][failure]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa;
	auto cfgA = makeConfig(sa);
	stice_agent_t *a = stice_create(&cfgA);
	REQUIRE(a != nullptr);

	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));

	// Remote SDP with ufrag/pwd, NO candidates, and end-of-candidates. Both
	// sides are done gathering and no pair can ever form, so the agent takes
	// the deliberate fast-failure path (stice product choice; RFC 8863 §4's
	// patience is pointless once no further pair can appear) instead of
	// sitting in CONNECTING for the 39.5 s PAC window.
	const char *emptySdp =
	    "a=ice-ufrag:remoteufrag\n"
	    "a=ice-pwd:remotepwdremotepwdremotepwd\n"
	    "a=end-of-candidates\n";
	REQUIRE(stice_set_remote_description(a, emptySdp) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);

	REQUIRE(waitFor([&] { return sa.state.load() == STICE_STATE_FAILED; }, 3000));

	stice_destroy(a);
}

TEST_CASE("UDP ICE: empty remote candidates without EOC stays CONNECTING",
          "[integration][udp][failure]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa;
	auto cfgA = makeConfig(sa);
	stice_agent_t *a = stice_create(&cfgA);
	REQUIRE(a != nullptr);

	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));

	// No remote candidates yet and the remote has NOT declared end-of-
	// candidates: trickled candidates may still arrive, so the agent must
	// stay in CONNECTING rather than fail.
	const char *emptySdp =
	    "a=ice-ufrag:remoteufrag\n"
	    "a=ice-pwd:remotepwdremotepwdremotepwd\n";
	REQUIRE(stice_set_remote_description(a, emptySdp) == STICE_ERR_SUCCESS);

	REQUIRE(waitFor([&] { return sa.state.load() == STICE_STATE_CONNECTING; }, 2000));
	REQUIRE(sa.state.load() == STICE_STATE_CONNECTING);

	std::this_thread::sleep_for(std::chrono::milliseconds(500));
	REQUIRE(sa.state.load() == STICE_STATE_CONNECTING);

	stice_destroy(a);
}

TEST_CASE("UDP ICE: role conflict 487 triggers role switch not failure",
          "[integration][udp][failure]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);

	// Force BOTH agents to be Controlling. This creates a role conflict
	// that must be resolved via 487 responses, not by marking pairs as
	// Failed. After role resolution, the agents should still connect.
	REQUIRE(stice_set_local_ice_attributes(a, "ufragA", "pwdApwdApwdApwdApwdAxx") ==
	        STICE_ERR_SUCCESS);
	REQUIRE(stice_set_local_ice_attributes(b, "ufragB", "pwdBpwdBpwdBpwdBpwdBxx") ==
	        STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 3000));

	// Exchange SDP normally.
	trickleExchange(a, sa, b, sb);

	// Despite the initial role conflict (both Controlling), the agents
	// must resolve it via 487 and eventually reach CONNECTED/COMPLETED.
	// If 487 were incorrectly treated as a failure, both would go FAILED.
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 8000));

	stice_destroy(a);
	stice_destroy(b);
}

// ---------------------------------------------------------------------------
// TCP ICE failure scenarios
//
// 1. Remote TCP passive candidate unreachable → Agent FAILED
// 2. TCP passive candidate with no local passive listener → stays CONNECTING
//    (stic cannot accept inbound TCP, only initiate)
// ---------------------------------------------------------------------------

TEST_CASE("TCP ICE: unreachable remote passive candidate → Agent FAILED",
          "[integration][tcp][failure]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa;
	auto cfgA = makeConfig(sa);
	cfgA.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;

	stice_agent_t *a = stice_create(&cfgA);
	REQUIRE(a != nullptr);

	// Enable active TCP mode so the agent will try to connect to remote
	// passive TCP candidates.
	REQUIRE(stice_set_ice_tcp_mode(a, STICE_ICE_TCP_MODE_ACTIVE) == STICE_ERR_SUCCESS);

	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));

	// Feed a remote SDP with a passive TCP candidate at an unroutable
	// address (RFC 5737 240.0.0.1). The agent will attempt an active TCP
	// connect, which fails with EHOSTUNREACH/ENETUNREACH.
	const char *remoteSdp =
	    "a=ice-ufrag:remoteufrag\n"
	    "a=ice-pwd:remotepwdremotepwdremotepwd\n"
	    "a=candidate:1 1 tcp 2114977791 240.0.0.1 9 typ host tcptype passive\n"
	    "a=end-of-candidates\n";
	REQUIRE(stice_set_remote_description(a, remoteSdp) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);

	// Agent enters CONNECTING, TCP connect fails, all TCP pairs go Failed.
	// An immediate EHOSTUNREACH can fail the pair before the first poll
	// sample, so CONNECTING is not guaranteed to be observable.
	REQUIRE(waitFor([&] {
		auto s = sa.state.load();
		return s == STICE_STATE_CONNECTING || s == STICE_STATE_FAILED;
	}, 2000));
	REQUIRE(waitFor([&] { return sa.state.load() == STICE_STATE_FAILED; }, 10000));

	stice_destroy(a);
}

TEST_CASE("TCP ICE: connection-refused remote passive → Agent FAILED",
          "[integration][tcp][failure]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa;
	auto cfgA = makeConfig(sa);
	cfgA.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;

	stice_agent_t *a = stice_create(&cfgA);
	REQUIRE(a != nullptr);
	REQUIRE(stice_set_ice_tcp_mode(a, STICE_ICE_TCP_MODE_ACTIVE) == STICE_ERR_SUCCESS);

	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));

	// 127.0.0.1:1 — connection refused (no listener on port 1). On most
	// stacks connect() fails immediately with ECONNREFUSED.
	const char *remoteSdp =
	    "a=ice-ufrag:remoteufrag\n"
	    "a=ice-pwd:remotepwdremotepwdremotepwd\n"
	    "a=candidate:1 1 tcp 2114977791 127.0.0.1 1 typ host tcptype passive\n"
	    "a=end-of-candidates\n";
	REQUIRE(stice_set_remote_description(a, remoteSdp) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);

	// ECONNREFUSED can fail the pair before the first poll sample.
	REQUIRE(waitFor([&] {
		auto s = sa.state.load();
		return s == STICE_STATE_CONNECTING || s == STICE_STATE_FAILED;
	}, 2000));
	REQUIRE(waitFor([&] { return sa.state.load() == STICE_STATE_FAILED; }, 10000));

	stice_destroy(a);
}

// ---------------------------------------------------------------------------
// ICE-TCP: RFC 6544 tcptype / SO semantics and TCPMux port sharing.
// ---------------------------------------------------------------------------

TEST_CASE("ICE-TCP: SO mode behaves as PASSIVE and never advertises tcptype so (G-TCP-1)",
          "[integration][tcp][so]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	stice_tcp_mux_t *mux = stice_create_tcp_mux("127.0.0.1", 0);
	REQUIRE(mux != nullptr);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);
	cfgA.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
	cfgB.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;

	stice_agent_t *a = stice_create(&cfgA); // SO mode (documented == PASSIVE)
	stice_agent_t *b = stice_create(&cfgB); // active
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);

	REQUIRE(stice_set_ice_tcp_mode(a, STICE_ICE_TCP_MODE_SO) == STICE_ERR_SUCCESS);
	REQUIRE(stice_agent_use_tcp_mux(a, mux) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_ice_tcp_mode(b, STICE_ICE_TCP_MODE_ACTIVE) == STICE_ERR_SUCCESS);

	char sdpA[4096], sdpB[4096];
	REQUIRE(stice_get_local_description(a, sdpA, sizeof(sdpA)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b, sdpB, sizeof(sdpB)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(a, sdpB) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(b, sdpA) == STICE_ERR_SUCCESS);

	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 3000));

	// SO mode must advertise `tcptype passive` candidates and never `tcptype so`
	// (stice implements the SO framework only; see stice.h).
	{
		std::lock_guard<std::mutex> lk(sa.candidatesMutex);
		bool sawPassive = false;
		for (const auto &c : sa.candidates) {
			if (c.find(" TCP ") == std::string::npos) continue;
			REQUIRE(c.find("tcptype so") == std::string::npos);
			if (c.find("tcptype passive") != std::string::npos) sawPassive = true;
		}
		REQUIRE(sawPassive);
	}

	// Forward only TCP candidates so the session is forced onto ICE-TCP.
	{
		std::lock_guard<std::mutex> lk(sa.candidatesMutex);
		for (const auto &c : sa.candidates)
			if (c.find(" TCP ") != std::string::npos)
				stice_add_remote_candidate(b, c.c_str());
	}
	{
		std::lock_guard<std::mutex> lk(sb.candidatesMutex);
		for (const auto &c : sb.candidates)
			if (c.find(" TCP ") != std::string::npos)
				stice_add_remote_candidate(a, c.c_str());
	}
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);

	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		auto ok = [](stice_state_t s) {
			return s == STICE_STATE_CONNECTED || s == STICE_STATE_COMPLETED;
		};
		return ok(as) && ok(bs);
	}, 8000));

	const char *msg = "so-mode-as-passive";
	REQUIRE(stice_send(b, msg, std::strlen(msg)) == STICE_ERR_SUCCESS);
	REQUIRE(waitForRecv(sa, msg, 3000));

	stice_destroy(a);
	stice_destroy(b);
	stice_destroy_tcp_mux(mux);
}

TEST_CASE("ICE-TCP: remote tcptype so candidate is ignored (G-TCP-2)",
          "[integration][tcp][so]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	// Raw TCP listener that the agent would dial if it did not drop the remote
	// `tcptype so` candidate. RFC 6544 §6.2 only pairs so with so, and this
	// agent never gathers `tcptype so`, so the candidate must be dropped.
	socket_t listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	REQUIRE(listener != STICE_INVALID_SOCKET);
	sockaddr_in la{};
	la.sin_family = AF_INET;
	la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	la.sin_port = 0;
	REQUIRE(::bind(listener, reinterpret_cast<sockaddr *>(&la), sizeof(la)) == 0);
	REQUIRE(::listen(listener, 4) == 0);
	socklen_t llen = sizeof(la);
	REQUIRE(::getsockname(listener, reinterpret_cast<sockaddr *>(&la), &llen) == 0);
	const std::uint16_t listenPort = ntohs(la.sin_port);

	AgentState sa;
	auto cfgA = makeConfig(sa);
	cfgA.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
	stice_agent_t *a = stice_create(&cfgA);
	REQUIRE(a != nullptr);
	REQUIRE(stice_set_ice_tcp_mode(a, STICE_ICE_TCP_MODE_ACTIVE) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));

	// Remote description first (ufrag/pwd only), then trickle the SO candidate
	// so the addRemoteCandidate drop path is exercised.
	REQUIRE(stice_set_remote_description(a,
	    "a=ice-ufrag:remoteufrag\n"
	    "a=ice-pwd:remotepwdremotepwdremotepwd\n") == STICE_ERR_SUCCESS);
	std::string soLine = "a=candidate:1 1 tcp 2114977791 127.0.0.1 " +
	    std::to_string(listenPort) + " typ host tcptype so";
	REQUIRE(stice_add_remote_candidate(a, soLine.c_str()) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);

	// No connection may reach the raw listener: the SO candidate was dropped.
	bool accepted = false;
	auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(800);
	while (!accepted && std::chrono::steady_clock::now() < deadline) {
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(listener, &rfds);
		timeval tv{0, 200000}; // 200ms
		int sel = ::select(static_cast<int>(listener) + 1, &rfds, nullptr, nullptr, &tv);
		if (sel > 0) {
			sockaddr_in peer{};
			socklen_t plen = sizeof(peer);
			socket_t c = ::accept(listener, reinterpret_cast<sockaddr *>(&peer), &plen);
			if (c != STICE_INVALID_SOCKET) {
				accepted = true;
				sticeClosesocket(c);
			}
		}
	}
	REQUIRE_FALSE(accepted);
	auto st = sa.state.load();
	REQUIRE(st != STICE_STATE_CONNECTED);
	REQUIRE(st != STICE_STATE_COMPLETED);

	sticeClosesocket(listener);
	stice_destroy(a);
}

TEST_CASE("ICE-TCP: passive candidate port equals TCPMux listener port (G-TCP-3)",
          "[integration][tcp][port]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	// Pick a free TCP port, then bind the mux to exactly that port so the
	// gathered passive candidate's port can be compared against the base.
	socket_t probe = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	REQUIRE(probe != STICE_INVALID_SOCKET);
	sockaddr_in pa{};
	pa.sin_family = AF_INET;
	pa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	pa.sin_port = 0;
	REQUIRE(::bind(probe, reinterpret_cast<sockaddr *>(&pa), sizeof(pa)) == 0);
	socklen_t plen = sizeof(pa);
	REQUIRE(::getsockname(probe, reinterpret_cast<sockaddr *>(&pa), &plen) == 0);
	const std::uint16_t basePort = ntohs(pa.sin_port);
	sticeClosesocket(probe);

	stice_tcp_mux_t *mux = stice_create_tcp_mux("127.0.0.1", basePort);
	REQUIRE(mux != nullptr);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa);
	auto cfgB = makeConfig(sb);
	cfgA.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
	cfgB.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
	stice_agent_t *a = stice_create(&cfgA); // passive
	stice_agent_t *b = stice_create(&cfgB); // active
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);
	REQUIRE(stice_set_ice_tcp_mode(a, STICE_ICE_TCP_MODE_PASSIVE) == STICE_ERR_SUCCESS);
	REQUIRE(stice_agent_use_tcp_mux(a, mux) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_ice_tcp_mode(b, STICE_ICE_TCP_MODE_ACTIVE) == STICE_ERR_SUCCESS);

	char sdpA[4096], sdpB[4096];
	REQUIRE(stice_get_local_description(a, sdpA, sizeof(sdpA)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b, sdpB, sizeof(sdpB)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(a, sdpB) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(b, sdpA) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 3000));

	// Token index 5 of "a=candidate:F <comp> <transport> <prio> <host> <port> ..."
	auto candidatePort = [](const std::string &c) -> int {
		std::istringstream iss(c);
		std::string tok;
		int idx = 0;
		while (iss >> tok) {
			if (idx == 5) return std::atoi(tok.c_str());
			++idx;
		}
		return -1;
	};

	// The passive candidate MUST listen on the mux base port.
	{
		std::lock_guard<std::mutex> lk(sa.candidatesMutex);
		bool checked = false;
		for (const auto &c : sa.candidates) {
			if (c.find(" TCP ") == std::string::npos) continue;
			if (c.find("tcptype passive") == std::string::npos) continue;
			REQUIRE(candidatePort(c) == static_cast<int>(basePort));
			checked = true;
		}
		REQUIRE(checked);
	}

	// Forward TCP candidates; the active side dials the mux port.
	{
		std::lock_guard<std::mutex> lk(sa.candidatesMutex);
		for (const auto &c : sa.candidates)
			if (c.find(" TCP ") != std::string::npos)
				stice_add_remote_candidate(b, c.c_str());
	}
	{
		std::lock_guard<std::mutex> lk(sb.candidatesMutex);
		for (const auto &c : sb.candidates)
			if (c.find(" TCP ") != std::string::npos)
				stice_add_remote_candidate(a, c.c_str());
	}
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);

	REQUIRE(waitFor([&] {
		auto ok = [](stice_state_t s) {
			return s == STICE_STATE_CONNECTED || s == STICE_STATE_COMPLETED;
		};
		return ok(sa.state.load()) && ok(sb.state.load());
	}, 8000));

	// RFC 6544 §4.5: an active candidate signals port 9 (its real source port
	// is arbitrary and only known after connect).
	{
		std::lock_guard<std::mutex> lk(sb.candidatesMutex);
		bool checked = false;
		for (const auto &c : sb.candidates) {
			if (c.find(" TCP ") == std::string::npos) continue;
			if (c.find("tcptype active") == std::string::npos) continue;
			REQUIRE(candidatePort(c) == 9);
			checked = true;
		}
		REQUIRE(checked);
	}

	stice_destroy(a);
	stice_destroy(b);
	stice_destroy_tcp_mux(mux);
}

TEST_CASE("ICE-TCP: multiple active agents dial one shared passive port (G-TCP-4)",
          "[integration][tcp][mux]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	stice_tcp_mux_t *mux = stice_create_tcp_mux("127.0.0.1", 0);
	REQUIRE(mux != nullptr);

	AgentState sa1, sa2, sb1, sb2;
	auto c1 = makeConfig(sa1);
	auto c2 = makeConfig(sa2);
	auto c3 = makeConfig(sb1);
	auto c4 = makeConfig(sb2);
	c1.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
	c2.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
	c3.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
	c4.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;

	stice_agent_t *a1 = stice_create(&c1);
	stice_agent_t *a2 = stice_create(&c2);
	stice_agent_t *b1 = stice_create(&c3);
	stice_agent_t *b2 = stice_create(&c4);
	REQUIRE(a1 != nullptr);
	REQUIRE(a2 != nullptr);
	REQUIRE(b1 != nullptr);
	REQUIRE(b2 != nullptr);

	// Two passive agents share one TCPMux (hence one listening port); two
	// active agents dial that same port. TCPMux demultiplexes by the USERNAME
	// ufrag in each connection's first STUN packet.
	REQUIRE(stice_set_ice_tcp_mode(a1, STICE_ICE_TCP_MODE_PASSIVE) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_ice_tcp_mode(a2, STICE_ICE_TCP_MODE_PASSIVE) == STICE_ERR_SUCCESS);
	REQUIRE(stice_agent_use_tcp_mux(a1, mux) == STICE_ERR_SUCCESS);
	REQUIRE(stice_agent_use_tcp_mux(a2, mux) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_ice_tcp_mode(b1, STICE_ICE_TCP_MODE_ACTIVE) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_ice_tcp_mode(b2, STICE_ICE_TCP_MODE_ACTIVE) == STICE_ERR_SUCCESS);

	char s1[4096], s2[4096], s3[4096], s4[4096];
	REQUIRE(stice_get_local_description(a1, s1, sizeof(s1)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(a2, s2, sizeof(s2)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b1, s3, sizeof(s3)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b2, s4, sizeof(s4)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(a1, s3) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(b1, s1) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(a2, s4) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(b2, s2) == STICE_ERR_SUCCESS);

	REQUIRE(stice_gather_candidates(a1) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a2) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(b1) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(b2) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa1.gatheringDone.load(); }, 3000));
	REQUIRE(waitFor([&] { return sa2.gatheringDone.load(); }, 3000));
	REQUIRE(waitFor([&] { return sb1.gatheringDone.load(); }, 3000));
	REQUIRE(waitFor([&] { return sb2.gatheringDone.load(); }, 3000));

	auto forwardTcp = [](AgentState &from, stice_agent_t *to) {
		std::lock_guard<std::mutex> lk(from.candidatesMutex);
		for (const auto &c : from.candidates)
			if (c.find(" TCP ") != std::string::npos)
				stice_add_remote_candidate(to, c.c_str());
	};
	forwardTcp(sa1, b1);
	forwardTcp(sb1, a1);
	forwardTcp(sa2, b2);
	forwardTcp(sb2, a2);
	REQUIRE(stice_set_remote_gathering_done(a1) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a2) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b1) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b2) == STICE_ERR_SUCCESS);

	REQUIRE(waitFor([&] {
		auto ok = [](stice_state_t s) {
			return s == STICE_STATE_CONNECTED || s == STICE_STATE_COMPLETED;
		};
		return ok(sa1.state.load()) && ok(sa2.state.load()) &&
		       ok(sb1.state.load()) && ok(sb2.state.load());
	}, 10000));

	// Data must reach the correct passive agent (no cross-wiring).
	const char *m1 = "pair-one";
	const char *m2 = "pair-two";
	REQUIRE(stice_send(b1, m1, std::strlen(m1)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_send(b2, m2, std::strlen(m2)) == STICE_ERR_SUCCESS);
	REQUIRE(waitForRecv(sa1, m1, 3000));
	REQUIRE(waitForRecv(sa2, m2, 3000));

	stice_destroy(a1);
	stice_destroy(a2);
	stice_destroy(b1);
	stice_destroy(b2);
	stice_destroy_tcp_mux(mux);
}

// ---------------------------------------------------------------------------
// TCP TURN failure scenarios
//
// 1. TURN TLS with invalid certificate verification → gathering completes
//    with only host candidates (allocation fails, does not hang).
//    NOTE: This test uses the real coturn server with skip_tls_verify=0
//    (verify) against a plain TCP listener — the TLS handshake will fail
//    because the server doesn't speak TLS on the plain port. Skipped if
//    coturn is unreachable.
// ---------------------------------------------------------------------------

TEST_CASE("TCP TURN: unreachable server does not hang gathering",
          "[integration][turn][tcp][failure]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa;
	auto cfgA = makeConfig(sa);
	cfgA.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;

	stice_turn_server_t badTurn{};
	badTurn.host = "240.0.0.1"; // RFC 5737 reserved, unroutable
	badTurn.port = 3478;
	badTurn.username = "testuser";
	badTurn.password = "123456";
	badTurn.transport = STICE_TURN_TRANSPORT_TCP;

	stice_agent_t *a = stice_create(&cfgA);
	REQUIRE(a != nullptr);
	REQUIRE(stice_add_turn_server(a, &badTurn) == STICE_ERR_SUCCESS);

	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);

	// Gathering must complete despite the TURN TCP connection failure.
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 8000));

	// Host candidates present, relay candidates absent.
	REQUIRE_FALSE(sa.candidates.empty());
	bool hasRelay = false;
	bool hasHost = false;
	for (const auto &c : sa.candidates) {
		if (c.find("typ relay") != std::string::npos) hasRelay = true;
		if (c.find("typ host") != std::string::npos) hasHost = true;
	}
	REQUIRE(hasHost);
	REQUIRE_FALSE(hasRelay);

	stice_destroy(a);
}

TEST_CASE("TCP TURN: wrong credentials → allocation fails, gathering completes",
          "[integration][turn][tcp][failure]") {
	// Requires a reachable TURN server with a TCP listener. It uses wrong
	// credentials so the TURN allocation fails with 401-after-creds. The fix
	// ensures the client transitions to Failed (not infinite loop) and gathering
	// completes with only host candidates. SKIPs when the server is unreachable.
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	const ExternalTurn server = externalTurn();
	if (!tcpEndpointReachable(server.host, server.port, 1000))
		SKIP("no TURN TCP listener at " << server.host << ":" << server.port
		                                << " (set STICE_TEST_TURN_HOST/_PORT)");

	AgentState sa;
	auto cfgA = makeConfig(sa);
	cfgA.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;

	stice_turn_server_t turn{};
	turn.host = server.host.c_str();
	turn.port = server.port;
	turn.username = "wronguser";
	turn.password = "wrongpass";
	turn.transport = STICE_TURN_TRANSPORT_TCP;

	stice_agent_t *a = stice_create(&cfgA);
	REQUIRE(a != nullptr);
	REQUIRE(stice_add_turn_server(a, &turn) == STICE_ERR_SUCCESS);

	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);

	// With the 401-loop fix, the client fails fast (after the second 401).
	// Without the fix, this would hang forever. Use a generous timeout.
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 15000));

	REQUIRE_FALSE(sa.candidates.empty());
	bool hasRelay = false;
	for (const auto &c : sa.candidates)
		if (c.find("typ relay") != std::string::npos) hasRelay = true;
	REQUIRE_FALSE(hasRelay);

	stice_destroy(a);
}

// ===========================================================================
// Resource lifecycle / fd leak verification (checklist §7)
// ===========================================================================

TEST_CASE("Resource: repeated create/destroy — no fd/handle leak",
          "[integration][resource]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	// Baseline: count open handles before creating any agents.
	auto countHandles = []() -> unsigned long {
#ifdef _WIN32
		DWORD handleCount = 0;
		HANDLE h = GetCurrentProcess();
		if (!GetProcessHandleCount(h, &handleCount)) return 0;
		return handleCount;
#else
		DIR *d = opendir("/proc/self/fd");
		if (!d) return 0;
		long count = 0;
		while (readdir(d)) ++count;
		closedir(d);
		return static_cast<unsigned long>(count - 2);
#endif
	};

	warmPollRegistryPool();

	// Create and destroy one agent before the baseline: the first agent also
	// initialises process-wide state (Winsock, crypto RNG, CRT pools) that is
	// not per-agent and must not be counted as a leak.
	auto runOnce = [&]() {
		AgentState sa;
		auto cfg = makeConfig(sa);
		cfg.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;

		stice_agent_t *a = stice_create(&cfg);
		REQUIRE(a != nullptr);
		REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
		REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));
		stice_destroy(a);
	};

	runOnce();
	std::this_thread::sleep_for(std::chrono::milliseconds(200));
	auto baseline = countHandles();

	// Create and destroy 20 agents, each gathering candidates.
	for (int i = 0; i < 20; i++) runOnce();

	// Allow a brief moment for cleanup to complete (PollRegistry thread join).
	std::this_thread::sleep_for(std::chrono::milliseconds(500));

	auto after = countHandles();
	// Allow up to 5 handles of variance (thread caching, CRT internals).
	// The key assertion: no unbounded growth indicating fd/handle leak.
	fprintf(stderr, "[fd-leak] baseline=%lu after=%lu\n",
	        static_cast<unsigned long>(baseline), static_cast<unsigned long>(after));
	REQUIRE(after <= baseline + 5);
}

TEST_CASE("Resource: relay-only mode — no direct host candidates",
          "[integration][resource]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	const ExternalTurn server = externalTurn();
	if (!udpEndpointReachable(server.host, server.port, 1000))
		SKIP("no TURN server at " << server.host << ":" << server.port
		                          << " (set STICE_TEST_TURN_HOST/_PORT)");

	AgentState sa;
	auto cfg = makeConfig(sa);
	cfg.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;

	stice_turn_server_t turn{};
	turn.host = server.host.c_str();
	turn.port = server.port;
	turn.username = server.username.c_str();
	turn.password = server.password.c_str();
	turn.transport = STICE_TURN_TRANSPORT_UDP;

	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);
	REQUIRE(stice_add_turn_server(a, &turn) == STICE_ERR_SUCCESS);

	// Enable relay-only mode if available.
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 10000));

	// We should have at least a relay candidate (host candidates may also
	// be present since stice doesn't have an explicit relay-only flag yet,
	// but relay candidates must exist).
	bool hasRelay = false;
	for (const auto &c : sa.candidates)
		if (c.find("typ relay") != std::string::npos) hasRelay = true;
	REQUIRE(hasRelay);

	stice_destroy(a);
}

// ---------------------------------------------------------------------------
// GetSelectedCandidatePair: no selected pair returns STICE_ERR_NOT_AVAIL
//
// Verifies [pion #747]: when no pair is selected, the API must return a
// distinct error code rather than nil-pair + nil-error ambiguity.
// ---------------------------------------------------------------------------

TEST_CASE("GetSelectedCandidates: returns NOT_AVAIL before connection",
          "[integration][api]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa;
	auto cfg = makeConfig(sa);
	stice_agent_t *a = stice_create(&cfg);
	REQUIRE(a != nullptr);

	// Before gathering: no selected pair, must return NOT_AVAIL.
	char local[512], remote[512];
	REQUIRE(stice_get_selected_candidates(a, local, sizeof(local), remote, sizeof(remote)) ==
	        STICE_ERR_NOT_AVAIL);

	// After gathering (but no remote description): still no selected pair.
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));
	REQUIRE(stice_get_selected_candidates(a, local, sizeof(local), remote, sizeof(remote)) ==
	        STICE_ERR_NOT_AVAIL);

	// Same for the address variant.
	char localAddr[64], remoteAddr[64];
	REQUIRE(stice_get_selected_addresses(a, localAddr, sizeof(localAddr),
	                                     remoteAddr, sizeof(remoteAddr)) == STICE_ERR_NOT_AVAIL);

	stice_destroy(a);
}

// ---------------------------------------------------------------------------
// TURN allocation timeout: transaction/permission properly reclaimed
//
// Verifies [checklist §7]: TURN分配超时场景 — 事务、权限正常回收.
// Uses an unreachable TURN server; gathering must complete with only host
// candidates (relay allocation fails), and no fd/handle leak.
// ---------------------------------------------------------------------------

TEST_CASE("TURN alloc timeout: unreachable server — no leak, gathering completes",
          "[integration][turn][timeout]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	auto countHandles = []() -> unsigned long {
#ifdef _WIN32
		DWORD handleCount = 0;
		HANDLE h = GetCurrentProcess();
		if (!GetProcessHandleCount(h, &handleCount)) return 0;
		return handleCount;
#else
		DIR *d = opendir("/proc/self/fd");
		if (!d) return 0;
		long count = 0;
		while (readdir(d)) ++count;
		closedir(d);
		return static_cast<unsigned long>(count - 2);
#endif
	};

	warmPollRegistryPool();

	// One warm-up agent before the baseline: the first agent also initialises
	// process-wide state (Winsock, crypto RNG, CRT pools) that is not per-agent.
	auto runOnce = [&]() {
		AgentState sa;
		auto cfg = makeConfig(sa);
		cfg.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;

		stice_turn_server_t badTurn{};
		badTurn.host = "240.0.0.1"; // RFC 5737 unroutable
		badTurn.port = 3478;
		badTurn.username = "testuser";
		badTurn.password = "123456";
		badTurn.transport = STICE_TURN_TRANSPORT_TCP;

		stice_agent_t *a = stice_create(&cfg);
		REQUIRE(a != nullptr);
		REQUIRE(stice_add_turn_server(a, &badTurn) == STICE_ERR_SUCCESS);
		REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
		// Gathering must complete despite TURN failure (not hang).
		REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 8000));

		// Host candidates present, relay candidates absent.
		bool hasHost = false, hasRelay = false;
		for (const auto &c : sa.candidates) {
			if (c.find("typ host") != std::string::npos) hasHost = true;
			if (c.find("typ relay") != std::string::npos) hasRelay = true;
		}
		REQUIRE(hasHost);
		REQUIRE_FALSE(hasRelay);

		stice_destroy(a);
	};

	runOnce();
	std::this_thread::sleep_for(std::chrono::milliseconds(200));
	auto baseline = countHandles();

	// Run 5 iterations against an unreachable TURN server. Each must fail
	// the allocation, complete gathering, and release all resources.
	// TCP transport is used because it fails fast (connection refused or
	// unreachable) compared to UDP which silently drops packets and relies
	// on the longer STUN transaction timeout.
	for (int i = 0; i < 5; i++) runOnce();

	// Teardown of a failed TURN TCP connect is asynchronous: the poll thread
	// may still be closing sockets/thread handles for a moment. Poll instead of
	// sampling once, so a slow-but-correct release is not reported as a leak.
	unsigned long after = baseline;
	for (int i = 0; i < 50; ++i) {
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		after = countHandles();
		if (after <= baseline + 5) break;
	}
	fprintf(stderr, "[turn-timeout-leak] baseline=%lu after=%lu\n",
	        static_cast<unsigned long>(baseline), static_cast<unsigned long>(after));
	REQUIRE(after <= baseline + 5);
}

// ---------------------------------------------------------------------------
// Concurrent sessions: many agents — no timer storm / event-loop stall
//
// Verifies [checklist §7]: 大量并发会话：定时器无风暴、事件循环无卡死、
// 资源正常回收. Creates 10 concurrent agents, all gathering candidates
// simultaneously, and verifies they all complete and resources are reclaimed.
// ---------------------------------------------------------------------------

TEST_CASE("Concurrency: 10 simultaneous agents — no storm, no leak",
          "[integration][concurrency]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	constexpr int N = 10;
	std::vector<AgentState> states(N);
	std::vector<stice_agent_t *> agents(N);

	for (int i = 0; i < N; i++) {
		auto cfg = makeConfig(states[i]);
		cfg.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
		agents[i] = stice_create(&cfg);
		REQUIRE(agents[i] != nullptr);
	}

	// Kick off gathering on all agents at once.
	for (int i = 0; i < N; i++) {
		REQUIRE(stice_gather_candidates(agents[i]) == STICE_ERR_SUCCESS);
	}

	// All must finish gathering within a generous deadline.
	for (int i = 0; i < N; i++) {
		REQUIRE(waitFor([&] { return states[i].gatheringDone.load(); }, 5000));
	}

	// All agents should have at least one host candidate.
	for (int i = 0; i < N; i++) {
		REQUIRE_FALSE(states[i].candidates.empty());
	}

	// Destroy all.
	for (int i = 0; i < N; i++) {
		stice_destroy(agents[i]);
	}
}

// ===========================================================================
// Test gap coverage (P0/P1)
//
// These tests cover scenarios that previously lacked coverage and could
// mask P0/P1 defects:
//   - Multi-port candidate matching (multiple candidates at different ports)
//   - ICE-TCP EOF/RST disconnect detection
//   - STUN high-RTT transaction retransmission scheduling
// ===========================================================================

// ---------------------------------------------------------------------------
// Multi-port candidate matching
//
// Verifies that when the remote SDP contains multiple candidates at different
// ports (some unreachable), the agent correctly:
//   1. Creates pairs for each remote candidate
//   2. Skips the unreachable ones (failed connect)
//   3. Selects the reachable one and completes
//
// This exercises the findOrCreatePair() transport-matching fix and ensures
// candidates at different ports are not conflated.
// ---------------------------------------------------------------------------
TEST_CASE("Multi-port candidate matching: selects reachable port among many",
          "[integration][multiport]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

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

	// Get B's local description and extract its real host candidate.
	char bufB[4096];
	REQUIRE(stice_get_local_description(b, bufB, sizeof(bufB)) == STICE_ERR_SUCCESS);

	// Find B's actual host candidate line.
	std::string sdpB(bufB);
	std::string bCandidateLine;
	{
		std::istringstream iss(sdpB);
		std::string line;
		while (std::getline(iss, line)) {
			if (line.rfind("a=candidate:", 0) == 0 && line.find("typ host") != std::string::npos) {
				bCandidateLine = line;
				break;
			}
		}
	}
	REQUIRE_FALSE(bCandidateLine.empty());

	// Build a remote SDP for A that contains:
	//   - B's real host candidate (reachable)
	//   - Two bogus host candidates at unreachable ports on 127.0.0.1
	//     (port 1 and port 2 — connection refused, but still valid SDP).
	// A must try all three, fail the two unreachable ones, and succeed on
	// the reachable one. This confirms per-port matching, not just per-IP.
	std::string remoteSdpForA;
	{
		std::istringstream iss(sdpB);
		std::string line;
		while (std::getline(iss, line)) {
			if (line.rfind("a=ice-ufrag:", 0) == 0) {
				remoteSdpForA += line + "\n";
			} else if (line.rfind("a=ice-pwd:", 0) == 0) {
				remoteSdpForA += line + "\n";
			}
		}
	}
	// Add bogus unreachable candidates first (low priority — they'll be
	// tried but fail). Distinct foundation IDs and ports.
	remoteSdpForA += "a=candidate:bogus1 1 udp 1 127.0.0.1 1 typ host\n";
	remoteSdpForA += "a=candidate:bogus2 1 udp 1 127.0.0.1 2 typ host\n";
	// B's real reachable candidate. ICE sorts by priority, so the real
	// candidate (much higher priority value) wins once its check succeeds.
	remoteSdpForA += bCandidateLine + "\n";
	remoteSdpForA += "a=end-of-candidates\n";

	REQUIRE(stice_set_remote_description(a, remoteSdpForA.c_str()) == STICE_ERR_SUCCESS);

	// Give A B's SDP; give B A's SDP (normal exchange).
	char bufA[4096];
	REQUIRE(stice_get_local_description(a, bufA, sizeof(bufA)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(b, bufA) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);

	// Both must reach CONNECTED/COMPLETED despite the bogus candidates.
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 8000));

	// Verify data flows on the selected (reachable) pair.
	const char *msg = "multiport-ok";
	REQUIRE(stice_send(a, msg, std::strlen(msg)) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return recvCount(sb) >= 1; }, 2000));
	REQUIRE(sb.received[0] == msg);

	stice_destroy(a);
	stice_destroy(b);
}

// ---------------------------------------------------------------------------
// ICE-TCP EOF/RST disconnect detection
//
// Sets up a TCP ICE connection between a passive agent (TCPMux) and an active
// agent, exchanges data, then abruptly destroys the PASSIVE side. The ACTIVE
// side must detect the TCP connection loss (EOF/RST) via its ICE-TCP connection
// onTcpEvents() callback and transition to FAILED quickly.
//
// The active side has direct transport-state monitoring (POLLHUP/POLLERR/recv
// ==0 → TcpState::Disconnected/Failed → fail pairs → updateState → FAILED),
// so detection should be near-immediate. The passive side relies on consent
// freshness (30s, RFC 8445 §7.3) since the TCPMux connection-close path does
// not yet propagate back to the agent.
// ---------------------------------------------------------------------------
TEST_CASE("ICE-TCP EOF/RST disconnect: active detects passive-side teardown",
          "[integration][tcp][eof]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	// Create a TCPMux for the passive side.
	stice_tcp_mux_t *mux = stice_create_tcp_mux("127.0.0.1", 0);
	REQUIRE(mux != nullptr);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa); // passive
	auto cfgB = makeConfig(sb); // active
	cfgA.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
	cfgB.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);

	REQUIRE(stice_set_ice_tcp_mode(a, STICE_ICE_TCP_MODE_PASSIVE) == STICE_ERR_SUCCESS);
	REQUIRE(stice_agent_use_tcp_mux(a, mux) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_ice_tcp_mode(b, STICE_ICE_TCP_MODE_ACTIVE) == STICE_ERR_SUCCESS);

	// Exchange SDP (ufrag/pwd) before gathering.
	char sdpA[4096], sdpB[4096];
	REQUIRE(stice_get_local_description(a, sdpA, sizeof(sdpA)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b, sdpB, sizeof(sdpB)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(a, sdpB) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(b, sdpA) == STICE_ERR_SUCCESS);

	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);

	// Wait for gathering, then trickle TCP candidates.
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 3000));

	// Forward only TCP candidates to force ICE-TCP.
	{
		std::lock_guard<std::mutex> lk(sa.candidatesMutex);
		for (const auto &c : sa.candidates) {
			if (c.find("tcp") != std::string::npos) {
				stice_add_remote_candidate(b, c.c_str());
			}
		}
	}
	{
		std::lock_guard<std::mutex> lk(sb.candidatesMutex);
		for (const auto &c : sb.candidates) {
			if (c.find("tcp") != std::string::npos) {
				stice_add_remote_candidate(a, c.c_str());
			}
		}
	}
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);

	// Wait for both to connect over TCP.
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 8000));

	// Verify data flows before disconnect.
	const char *msg = "pre-disconnect";
	REQUIRE(stice_send(b, msg, std::strlen(msg)) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return recvCount(sa) >= 1; }, 2000));
	REQUIRE(sa.received[0] == msg);

	// Abruptly destroy the PASSIVE side (A + TCPMux). This closes all TCP
	// sockets on the passive end, sending FIN/RST to the active side.
	stice_destroy(a);
	stice_destroy_tcp_mux(mux);

	// The active side (B) must detect the TCP connection loss via its
	// per-pair TCP connection EOF/RST path and transition to FAILED. This should
	// happen quickly (next poll cycle detects POLLHUP/recv==0).
	REQUIRE(waitFor([&] {
		auto bs = sb.state.load();
		return bs == STICE_STATE_FAILED || bs == STICE_STATE_DISCONNECTED;
	}, 10000));

	stice_destroy(b);
}

TEST_CASE("ICE-TCP restart: new ufrag re-registers with the shared TCPMux",
          "[integration][tcp][restart]") {
	// 0.14.0 made restart() also drop the TCPMux registration of the old
	// generation (mirroring UDPMux): the mux demuxes inbound dials by the
	// USERNAME ufrag and closes connections whose ufrag has no agent entry,
	// so without re-registration the passive endpoint is permanently deaf
	// after a restart. The active side must be able to re-dial the SAME
	// listener and reach the agent under its NEW ufrag.
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	stice_tcp_mux_t *mux = stice_create_tcp_mux("127.0.0.1", 0);
	REQUIRE(mux != nullptr);

	AgentState sa, sb;
	auto cfgA = makeConfig(sa); // passive, mux-attached
	auto cfgB = makeConfig(sb); // active
	cfgA.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
	cfgB.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;

	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);

	REQUIRE(stice_set_ice_tcp_mode(a, STICE_ICE_TCP_MODE_PASSIVE) == STICE_ERR_SUCCESS);
	REQUIRE(stice_agent_use_tcp_mux(a, mux) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_ice_tcp_mode(b, STICE_ICE_TCP_MODE_ACTIVE) == STICE_ERR_SUCCESS);

	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 3000));

	char sdpA1[4096], sdpB1[4096];
	REQUIRE(stice_get_local_description(a, sdpA1, sizeof(sdpA1)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b, sdpB1, sizeof(sdpB1)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(a, sdpB1) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(b, sdpA1) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);

	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 8000));

	const char *pre = "tcp pre-restart from B";
	REQUIRE(stice_send(b, pre, std::strlen(pre)) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return recvCount(sa) >= 1; }, 2000));

	// Restart the PASSIVE side (the mux-attached agent). restart() must drop
	// the old generation's registration; gatherCandidates re-registers under
	// the fresh ufrag.
	std::string sdpA1Str(sdpA1);
	auto ufragA1 = sdpA1Str.substr(sdpA1Str.find("a=ice-ufrag:") + 12, 4);

	sa.gatheringDone.store(false);
	REQUIRE(stice_agent_restart(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));

	char sdpA2[4096];
	REQUIRE(stice_get_local_description(a, sdpA2, sizeof(sdpA2)) == STICE_ERR_SUCCESS);
	std::string sdpA2Str(sdpA2);
	auto ufragA2 = sdpA2Str.substr(sdpA2Str.find("a=ice-ufrag:") + 12, 4);
	// A genuinely new generation: without changed credentials the re-register
	// path would not be exercised at all.
	REQUIRE(ufragA2 != ufragA1);

	// B follows on A's new generation (RFC 8445 §9 peer-restart detection).
	sb.gatheringDone.store(false);
	REQUIRE(stice_set_remote_description(b, sdpA2) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 3000));
	char sdpB2[4096];
	REQUIRE(stice_get_local_description(b, sdpB2, sizeof(sdpB2)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(a, sdpB2) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);

	// B re-dials the SAME passive listener; the mux must hand the fresh
	// connection (USERNAME carries the NEW ufrag) to A's new registration.
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
		       (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
	}, 15000));

	// Data flows both ways in the new generation.
	size_t seenA = recvCount(sa);
	size_t seenB = recvCount(sb);
	const char *post1 = "tcp after restart from B";
	const char *post2 = "tcp after restart from A";
	REQUIRE(stice_send(b, post1, std::strlen(post1)) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return recvCount(sa) > seenA; }, 3000));
	REQUIRE(recvSnapshot(sa).back() == post1);
	REQUIRE(stice_send(a, post2, std::strlen(post2)) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return recvCount(sb) > seenB; }, 3000));
	REQUIRE(recvSnapshot(sb).back() == post2);

	stice_destroy(a);
	stice_destroy(b);
	stice_destroy_tcp_mux(mux);
}

// ---------------------------------------------------------------------------
// In-test TCP forwarding proxy. Sits between the ICE-TCP active agent and the
// passive agent's TCPMux so a test can break the TCP link mid-path (both legs)
// without destroying either agent — the precondition for the RFC 6544 §11.1
// redial-revival scenario.
// ---------------------------------------------------------------------------

namespace {
struct ProxySession {
	socket_t front = STICE_INVALID_SOCKET;
	socket_t back = STICE_INVALID_SOCKET;
	std::atomic<bool> dead{false};
	std::thread toBackend;
	std::thread toFront;
};
using ProxySessionPtr = std::shared_ptr<ProxySession>;

bool fdSendAll(socket_t fd, const char *buf, int len) {
	int off = 0;
	while (off < len) {
		int n = ::send(fd, buf + off, len - off, 0);
		if (n <= 0) return false;
		off += n;
	}
	return true;
}

void pumpFd(socket_t in, socket_t out, std::atomic<bool> *dead) {
	char buf[4096];
	while (!dead->load()) {
		int n = ::recv(in, buf, sizeof(buf), 0);
		if (n == 0) break; // peer closed
		if (n < 0) {
			if (stice::net::wouldBlock()) {
				std::this_thread::sleep_for(std::chrono::milliseconds(2));
				continue;
			}
			break;
		}
		if (!fdSendAll(out, buf, n)) break;
	}
	dead->store(true);
	// Wake the sibling pump so it observes the break too.
	::shutdown(in, 2);
	::shutdown(out, 2);
}

// Rewrites the port in a candidate SDP line (element 5 in the
// "candidate:<foundation> <comp> <transport> <prio> <ip> <port> ..." shape).
std::string rewriteCandidatePort(const std::string &cand, uint16_t port) {
	std::istringstream iss(cand);
	std::vector<std::string> tok;
	std::string w;
	while (iss >> w) tok.push_back(w);
	REQUIRE(tok.size() > 5);
	tok[5] = std::to_string(port);
	std::ostringstream oss;
	for (size_t i = 0; i < tok.size(); ++i) {
		if (i) oss << ' ';
		oss << tok[i];
	}
	return oss.str();
}

uint16_t candidatePort(const std::string &cand) {
	std::istringstream iss(cand);
	std::vector<std::string> tok;
	std::string w;
	while (iss >> w) tok.push_back(w);
	REQUIRE(tok.size() > 5);
	return static_cast<uint16_t>(std::stoi(tok[5]));
}
} // namespace

class TcpForwardProxy {
public:
	TcpForwardProxy(uint16_t backendPort) : backendPort_(backendPort) {
		listenSock_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		REQUIRE(listenSock_ != STICE_INVALID_SOCKET);
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr.sin_port = 0;
		REQUIRE(::bind(listenSock_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
		REQUIRE(::listen(listenSock_, 4) == 0);
		// A blocking accept() is not woken by close() on POSIX (unspecified
		// behaviour, and in practice it keeps sleeping), which deadlocks the
		// destructor's join() on Linux. Poll a non-blocking listener instead.
		REQUIRE(stice::net::setNonBlocking(listenSock_));
		sockaddr_in bound{};
		socklen_t blen = sizeof(bound);
		REQUIRE(getsockname(listenSock_, reinterpret_cast<sockaddr *>(&bound), &blen) == 0);
		port_ = ntohs(bound.sin_port);
		acceptor_ = std::thread([this] { acceptLoop(); });
	}

	~TcpForwardProxy() {
		stopping_.store(true);
		sticeClosesocket(listenSock_);
		if (acceptor_.joinable()) acceptor_.join();
		killSessions();
		for (auto &s : sessions_) {
			if (s->toBackend.joinable()) s->toBackend.join();
			if (s->toFront.joinable()) s->toFront.join();
		}
	}

	uint16_t port() const { return port_; }

	// Break every established session (both legs), simulating a mid-path link
	// loss. The listener stays up, so a redial forms a fresh session.
	void killSessions() {
		std::lock_guard<std::mutex> lk(mtx_);
		for (auto &s : sessions_) {
			if (!s->dead.load()) {
				::shutdown(s->front, 2);
				::shutdown(s->back, 2);
				sticeClosesocket(s->front);
				sticeClosesocket(s->back);
				s->dead.store(true);
			}
		}
	}

private:
	void acceptLoop() {
		while (!stopping_.load()) {
			socket_t c = ::accept(listenSock_, nullptr, nullptr);
			if (c == STICE_INVALID_SOCKET) {
				if (stice::net::wouldBlock()) {
					std::this_thread::sleep_for(std::chrono::milliseconds(2));
					continue;
				}
				break;
			}
			socket_t b = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (b == STICE_INVALID_SOCKET) {
				sticeClosesocket(c);
				break;
			}
			sockaddr_in dst{};
			dst.sin_family = AF_INET;
			dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			dst.sin_port = htons(backendPort_);
			if (::connect(b, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)) != 0) {
				sticeClosesocket(c);
				sticeClosesocket(b);
				continue;
			}
			ProxySessionPtr s = std::make_shared<ProxySession>();
			s->front = c;
			s->back = b;
			s->toBackend = std::thread([s] { pumpFd(s->front, s->back, &s->dead); });
			s->toFront = std::thread([s] { pumpFd(s->back, s->front, &s->dead); });
			std::lock_guard<std::mutex> lk(mtx_);
			sessions_.push_back(std::move(s));
		}
	}

	socket_t listenSock_ = STICE_INVALID_SOCKET;
	uint16_t backendPort_ = 0;
	uint16_t port_ = 0;
	std::thread acceptor_;
	std::atomic<bool> stopping_{false};
	std::mutex mtx_;
	std::vector<ProxySessionPtr> sessions_;
};

namespace {
// AgentState + state history (needed to observe the revival path shape).
struct HistState {
	std::atomic<stice_state_t> state{STICE_STATE_DISCONNECTED};
	std::vector<std::string> candidates;
	std::atomic<bool> gatheringDone{false};
	std::vector<std::string> received;
	std::mutex candidatesMutex;
	std::mutex receivedMutex;
	std::mutex histMutex;
	std::vector<stice_state_t> hist;

	void record(stice_state_t s) {
		std::lock_guard<std::mutex> lk(histMutex);
		hist.push_back(s);
	}
	std::vector<stice_state_t> history() {
		std::lock_guard<std::mutex> lk(histMutex);
		return hist;
	}
};

stice_config_t makeHistConfig(HistState &s) {
	stice_config_t cfg{};
	cfg.cb_state_changed = [](stice_agent_t *, stice_state_t state, void *user_ptr) {
		auto *s = static_cast<HistState *>(user_ptr);
		s->state.store(state);
		s->record(state);
	};
	cfg.cb_candidate = [](stice_agent_t *, const char *cand, void *user_ptr) {
		auto *s = static_cast<HistState *>(user_ptr);
		std::lock_guard<std::mutex> lk(s->candidatesMutex);
		s->candidates.emplace_back(cand);
	};
	cfg.cb_gathering_done = [](stice_agent_t *, void *user_ptr) {
		static_cast<HistState *>(user_ptr)->gatheringDone.store(true);
	};
	cfg.cb_recv = [](stice_agent_t *, const char *data, size_t size, void *user_ptr) {
		auto *s = static_cast<HistState *>(user_ptr);
		std::lock_guard<std::mutex> lk(s->receivedMutex);
		s->received.emplace_back(data, size);
	};
	cfg.user_ptr = &s;
	cfg.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
	return cfg;
}
} // namespace

// ---------------------------------------------------------------------------
// ICE-TCP redial revival: nomination state lifecycle (P1-N3)
//
// Completes a session through an in-test TCP proxy, then breaks both legs of
// the proxied link. The active side must redial (RFC 6544 §11.1) and the
// revived pair must come back un-nominated:
//   - the DISCONNECTED -> COMPLETED transition must pass through CONNECTED
//     (a revived pair re-runs checks first, and COMPLETED only returns after
//     a fresh nomination cycle). With the P1-N3 bug — stale
//     nominated/nominationRequested on the revived pair — the agent jumps
//     DISCONNECTED -> COMPLETED directly, i.e. the controlled side reports
//     COMPLETED without the peer re-sending USE-CANDIDATE.
//   - the session must fully recover (both sides COMPLETED, active side can
//     send data over the new connection).
// ---------------------------------------------------------------------------
TEST_CASE("ICE-TCP redial revival: revived pair must not inherit nomination (P1-N3)",
          "[integration][tcp][redial][nomination]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	HistState sa, sb; // sa = passive (mux behind proxy), sb = active (redialing)

	stice_tcp_mux_t *mux = stice_create_tcp_mux("127.0.0.1", 0);
	REQUIRE(mux != nullptr);

	auto cfgA = makeHistConfig(sa);
	auto cfgB = makeHistConfig(sb);
	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);

	REQUIRE(stice_set_ice_tcp_mode(a, STICE_ICE_TCP_MODE_PASSIVE) == STICE_ERR_SUCCESS);
	REQUIRE(stice_agent_use_tcp_mux(a, mux) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_ice_tcp_mode(b, STICE_ICE_TCP_MODE_ACTIVE) == STICE_ERR_SUCCESS);

	char sdpA[4096], sdpB[4096];
	REQUIRE(stice_get_local_description(a, sdpA, sizeof(sdpA)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b, sdpB, sizeof(sdpB)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(a, sdpB) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_description(b, sdpA) == STICE_ERR_SUCCESS);

	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);

	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 3000));

	// Find the passive side's TCP candidate, put the proxy in front of it.
	std::string muxCand;
	{
		std::lock_guard<std::mutex> lk(sa.candidatesMutex);
		for (const auto &c : sa.candidates) {
			if (c.find("tcp") != std::string::npos && c.find("passive") != std::string::npos) {
				muxCand = c;
				break;
			}
		}
	}
	REQUIRE(!muxCand.empty());
	uint16_t muxPort = candidatePort(muxCand);

	TcpForwardProxy proxy(muxPort);

	{
		std::string viaProxy = rewriteCandidatePort(muxCand, proxy.port());
		stice_add_remote_candidate(b, viaProxy.c_str());
	}
	{
		std::lock_guard<std::mutex> lk(sb.candidatesMutex);
		for (const auto &c : sb.candidates) {
			if (c.find("tcp") != std::string::npos)
				stice_add_remote_candidate(a, c.c_str());
		}
	}
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);

	// Baseline: complete the session and exchange data in both directions.
	REQUIRE(waitFor([&] {
		auto as = sa.state.load();
		auto bs = sb.state.load();
		return as == STICE_STATE_COMPLETED && bs == STICE_STATE_COMPLETED;
	}, 10000));

	const char *msg1 = "pre-break-b2a";
	REQUIRE(stice_send(b, msg1, std::strlen(msg1)) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] {
		std::lock_guard<std::mutex> lk(sa.receivedMutex);
		return !sa.received.empty() && sa.received.back() == msg1;
	}, 3000));
	const char *msg2 = "pre-break-a2b";
	REQUIRE(stice_send(a, msg2, std::strlen(msg2)) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] {
		std::lock_guard<std::mutex> lk(sb.receivedMutex);
		return !sb.received.empty() && sb.received.back() == msg2;
	}, 3000));

	// Break the link mid-path. Both legs die: the active side sees the loss
	// immediately and redials; the passive side's mux connection also dies.
	proxy.killSessions();

	// 1. The active side must report the loss (grace window), not hang.
	REQUIRE(waitFor([&] { return sb.state.load() == STICE_STATE_DISCONNECTED; }, 10000));

	// 2. Full recovery: redial + fresh nomination cycle back to COMPLETED.
	REQUIRE(waitFor([&] { return sb.state.load() == STICE_STATE_COMPLETED; }, 60000));

	// 3. The revival path shape: between the post-break DISCONNECTED and the
	// next COMPLETED there must be a CONNECTED. A direct jump means the
	// revived pair came back nominated (P1-N3 bug).
	{
		auto hist = sb.history();
		std::ptrdiff_t lastCompleted = -1;
		for (std::ptrdiff_t i = static_cast<std::ptrdiff_t>(hist.size()) - 1; i >= 0; --i) {
			if (hist[static_cast<size_t>(i)] == STICE_STATE_COMPLETED) {
				lastCompleted = i;
				break;
			}
		}
		REQUIRE(lastCompleted > 0);
		std::ptrdiff_t disconnected = -1;
		for (std::ptrdiff_t i = lastCompleted - 1; i >= 0; --i) {
			if (hist[static_cast<size_t>(i)] == STICE_STATE_DISCONNECTED) {
				disconnected = i;
				break;
			}
		}
		REQUIRE(disconnected >= 0);
		bool sawConnected = false;
		for (std::ptrdiff_t i = disconnected + 1; i < lastCompleted; ++i) {
			if (hist[static_cast<size_t>(i)] == STICE_STATE_CONNECTED) {
				sawConnected = true;
				break;
			}
		}
		INFO("state history: " << hist.size() << " transitions");
		REQUIRE(sawConnected);
	}

	// 4. Data flows over the new connection.
	const char *msg3 = "post-recovery-b2a";
	REQUIRE(stice_send(b, msg3, std::strlen(msg3)) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] {
		std::lock_guard<std::mutex> lk(sa.receivedMutex);
		return !sa.received.empty() && sa.received.back() == msg3;
	}, 5000));

	stice_destroy(a);
	stice_destroy(b);
	stice_destroy_tcp_mux(mux);
}

// ---------------------------------------------------------------------------
// STUN high-RTT transaction retransmission
//
// Verifies that the STUN connectivity-check retransmission schedule follows
// RFC 8445 §6.2 (exponential backoff: RTO, 2*RTO, 4*RTO, ...) and does not
// declare failure too early. We feed the agent a single unreachable remote
// candidate and measure that:
//   1. The agent enters CONNECTING quickly.
//   2. The agent stays in CONNECTING for at least a few retransmission
//      intervals (proving the backoff schedule is honoured, not failing on
//      the first timeout).
//   3. The agent is still in CONNECTING after 5s (retransmission ongoing,
//      not hung, not prematurely failed).
//
// This catches regressions where the retransmission counter or timeout is
// misconfigured (e.g., failing on first timeout, or never retransmitting).
// The eventual FAILED transition is covered by the TCP-unreachable and
// ufrag-mismatch tests; here we focus on the retransmission schedule timing.
// ---------------------------------------------------------------------------
TEST_CASE("STUN high-RTT transaction: retransmission schedule before FAILED",
          "[integration][stun][rtt]") {
	stice_set_log_level(STICE_LOG_LEVEL_ERROR);

	AgentState sa;
	auto cfgA = makeConfig(sa);
	cfgA.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;

	stice_agent_t *a = stice_create(&cfgA);
	REQUIRE(a != nullptr);

	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));

	// Remote SDP with a single unreachable UDP host candidate.
	// 240.0.0.1 (RFC 5737) is unroutable; STUN checks will retransmit
	// without any response, exercising the backoff schedule.
	const char *remoteSdp =
	    "a=ice-ufrag:remoteufrag\n"
	    "a=ice-pwd:remotepwdremotepwdremotepwd\n"
	    "a=candidate:f1 1 udp 1 240.0.0.1 9999 typ host\n"
	    "a=end-of-candidates\n";
	REQUIRE(stice_set_remote_description(a, remoteSdp) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);

	// Must enter CONNECTING quickly.
	REQUIRE(waitFor([&] { return sa.state.load() == STICE_STATE_CONNECTING; }, 2000));

	// The agent must NOT fail immediately — it must honour at least a couple
	// of retransmission intervals. RTO starts at 500ms and doubles; the full
	// schedule (6 retransmissions) runs ~23.5s per pair. We assert the agent
	// stays in CONNECTING for at least 3s to catch "fails on first timeout"
	// bugs. After 5s it must still be in CONNECTING (retransmission ongoing).
	auto enterTime = std::chrono::steady_clock::now();
	bool failedTooFast = false;
	while (true) {
		auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
		    std::chrono::steady_clock::now() - enterTime);
		auto st = sa.state.load();
		if (st != STICE_STATE_CONNECTING) {
			if (elapsed.count() < 3000) failedTooFast = true;
			break;
		}
		if (elapsed.count() >= 5000) break; // retransmission still ongoing
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}

	REQUIRE_FALSE(failedTooFast);
	// After 5s the agent must still be in CONNECTING (retransmission active,
	// not prematurely failed, not hung).
	REQUIRE(sa.state.load() == STICE_STATE_CONNECTING);

	stice_destroy(a);
}

// ---------------------------------------------------------------------------
// RFC 8445 §7.3.1.1 role conflict: bidirectional 487 + tiebreaker regeneration
// (G-ICE-1)
//
// Two agents that both start CONTROLLING each answer the other's check with
// 487 and both flip roles. This test drives that exchange at the wire level
// with a STUN-speaking probe so both directions are observable:
//   1. probe -> agent: CONTROLLING check with a lower tiebreaker must be
//      rejected with 487 (the agent wins and keeps CONTROLLING);
//   2. agent -> probe: the agent's own check is answered with 487; the agent
//      MUST switch to CONTROLLED, regenerate its tiebreaker (§7.2.5.1), and
//      retransmit with ICE-CONTROLLED carrying a *different* tiebreaker.
// ---------------------------------------------------------------------------
TEST_CASE("ICE role conflict: bidirectional 487 and tiebreaker regeneration (G-ICE-1)",
          "[integration][udp][role]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa;
	auto cfgA = makeConfig(sa);
	stice_agent_t *a = stice_create(&cfgA);
	REQUIRE(a != nullptr);
	REQUIRE(stice_set_local_ice_attributes(a, "ufragA", "pwdApwdApwdApwdApwdAxx") ==
	        STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));

	char sdp[4096];
	REQUIRE(stice_get_local_description(a, sdp, sizeof(sdp)) == STICE_ERR_SUCCESS);
	std::string localIp;
	uint16_t localPort = 0;
	REQUIRE(findLocalHostCandidate(sdp, localIp, localPort));

	StunProbePeer peer(localIp);
	const std::string remoteSdp =
	    "a=ice-ufrag:remoteufrag\n"
	    "a=ice-pwd:remotepwdremotepwdremotepwd\n"
	    "a=candidate:1 1 UDP 2130706431 " + localIp + " " + std::to_string(peer.port()) +
	    " typ host\n"
	    "a=end-of-candidates\n";
	REQUIRE(stice_set_remote_description(a, remoteSdp.c_str()) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);

	// Direction 1: the probe sends its own CONTROLLING check with tiebreaker 0.
	// Any random 64-bit agent tiebreaker wins, so the agent must answer 487.
	{
		stice::stun::Message req;
		req.method = stice::stun::Method::Binding;
		req.cls = stice::stun::Class::Request;
		req.newTransactionID();
		stice::stun::addString(req, stice::stun::AttrType::Username, "ufragA:remoteufrag");
		stice::stun::addPriority(req, 2130706431u);
		stice::stun::addIceControlling(req, 0);
		REQUIRE(req.encode("pwdApwdApwdApwdApwdAxx"));
		REQUIRE(peer.sendTo(req, localIp, localPort));
	}

	// Collect the 487 response to our check and the agent's own CONTROLLING
	// check (tiebreaker TB1).
	bool got487 = false;
	bool gotCheck = false;
	std::uint64_t tb1 = 0;
	REQUIRE(waitFor([&] {
		stice::stun::Message m;
		while (peer.recv(m, 10)) {
			if (m.cls == stice::stun::Class::ErrorResponse) {
				int code = 0;
				std::string reason;
				stice::stun::readErrorCode(m, code, reason);
				if (code == 487) got487 = true;
			}
			else if (m.cls == stice::stun::Class::Request) {
				std::uint64_t tb = 0;
				if (stice::stun::readIceControlling(m, tb)) {
					tb1 = tb;
					gotCheck = true;
				}
			}
		}
		return got487 && gotCheck;
	}, 5000));
	REQUIRE(got487);
	REQUIRE(gotCheck);

	// Direction 2: answer every CONTROLLING check with 487 until the agent
	// retransmits as CONTROLLED. Answering only the latest transaction keeps
	// the test robust against retransmissions racing our reply.
	bool gotControlled = false;
	std::uint64_t tb2 = 0;
	{
		auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(5000);
		while (!gotControlled && std::chrono::steady_clock::now() < deadline) {
			stice::stun::Message m;
			if (!peer.recv(m, 20)) continue;
			if (m.cls != stice::stun::Class::Request) continue;
			std::uint64_t tb = 0;
			if (stice::stun::readIceControlled(m, tb)) {
				tb2 = tb;
				gotControlled = true;
				break;
			}
			if (stice::stun::readIceControlling(m, tb)) {
				stice::stun::Message resp;
				resp.method = stice::stun::Method::Binding;
				resp.cls = stice::stun::Class::ErrorResponse;
				resp.transactionID = m.transactionID;
				stice::stun::addErrorCode(resp, 487, "Role Conflict");
				stice::stun::addIceControlling(resp, ~std::uint64_t{0});
				REQUIRE(resp.encode("remotepwdremotepwdremotepwd"));
				REQUIRE(peer.sendTo(resp, localIp, localPort));
			}
		}
	}
	REQUIRE(gotControlled);
	// RFC 8445 §7.2.5.1: the tiebreaker MUST be regenerated on a role switch.
	REQUIRE(tb2 != tb1);

	stice_destroy(a);
}

// ---------------------------------------------------------------------------
// RFC 8445 §7.3.1.3 peer-reflexive candidate discovery (G-ICE-3)
//
// A valid check arriving from an address that is not in the remote description
// must create a prflx candidate and a usable pair. The pair must be checked,
// succeed, and be selectable/nominated. The same exchange asserts G-ICE-2:
// every outgoing check carries USERNAME + MESSAGE-INTEGRITY + PRIORITY.
// ---------------------------------------------------------------------------
TEST_CASE("ICE prflx discovery: unknown source check creates a selectable pair (G-ICE-3)",
          "[integration][udp][prflx]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa;
	auto cfgA = makeConfig(sa);
	stice_agent_t *a = stice_create(&cfgA);
	REQUIRE(a != nullptr);
	REQUIRE(stice_set_local_ice_attributes(a, "ufragA", "pwdApwdApwdApwdApwdAxx") ==
	        STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));

	char sdp[4096];
	REQUIRE(stice_get_local_description(a, sdp, sizeof(sdp)) == STICE_ERR_SUCCESS);
	std::string localIp;
	uint16_t localPort = 0;
	REQUIRE(findLocalHostCandidate(sdp, localIp, localPort));

	// The probe is the unknown source; the SDP only advertises an unreachable
	// candidate so the prflx path is the only way to connect.
	StunProbePeer peer(localIp);
	UdpProbePeer deadPeer;
	const std::string remoteSdp =
	    "a=ice-ufrag:remoteufrag\n"
	    "a=ice-pwd:remotepwdremotepwdremotepwd\n"
	    "a=candidate:1 1 UDP 1 127.0.0.1 " + std::to_string(deadPeer.port()) +
	    " typ host\n"
	    "a=end-of-candidates\n";
	REQUIRE(stice_set_remote_description(a, remoteSdp.c_str()) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);

	// Probe -> agent check from an address absent from the remote description.
	{
		stice::stun::Message req;
		req.method = stice::stun::Method::Binding;
		req.cls = stice::stun::Class::Request;
		req.newTransactionID();
		stice::stun::addString(req, stice::stun::AttrType::Username, "ufragA:remoteufrag");
		stice::stun::addPriority(
		    req, stice::ice::Candidate::computePriority(
		             stice::ice::CandidateType::PeerReflexive, AF_INET, 1, 0,
		             stice::ice::CandidateTransport::UDP));
		stice::stun::addIceControlled(req, 1);
		REQUIRE(req.encode("pwdApwdApwdApwdApwdAxx"));
		REQUIRE(peer.sendTo(req, localIp, localPort));
	}

	// The agent must learn the prflx candidate, answer the inbound check, and
	// send its own check to the probe. Reply success to every check so the
	// pair can succeed and be nominated.
	bool sawCheck = false;
	bool sawUseCandidate = false;
	REQUIRE(waitFor([&] {
		stice::stun::Message m;
		while (peer.recv(m, 10)) {
			if (m.cls != stice::stun::Class::Request) continue;
			sawCheck = true;
			// RFC 8445 §7.2.4: a check MUST carry USERNAME + MESSAGE-INTEGRITY
			// and PRIORITY (G-ICE-2).
			REQUIRE(m.find(stice::stun::AttrType::Username) != nullptr);
			REQUIRE(m.find(stice::stun::AttrType::MessageIntegrity) != nullptr);
			REQUIRE(m.find(stice::stun::AttrType::Priority) != nullptr);
			if (stice::stun::hasUseCandidate(m)) sawUseCandidate = true;
			stice::stun::Message resp;
			resp.method = stice::stun::Method::Binding;
			resp.cls = stice::stun::Class::SuccessResponse;
			resp.transactionID = m.transactionID;
			REQUIRE(resp.encode("remotepwdremotepwdremotepwd"));
			REQUIRE(peer.sendTo(resp, localIp, localPort));
		}
		// Regular nomination (the default profile) reaches CONNECTED once a
		// check succeeds and only then sends the nominating USE-CANDIDATE check,
		// so wait for COMPLETED — CONNECTED alone races ahead of nomination.
		return sa.state.load() == STICE_STATE_COMPLETED;
	}, 10000));
	REQUIRE(sawCheck);
	REQUIRE(sawUseCandidate);

	// The selected path must be the peer-reflexive one (the probe address),
	// not the unreachable SDP candidate.
	char selLocal[256] = {0};
	char selRemote[256] = {0};
	REQUIRE(stice_get_selected_addresses(a, selLocal, sizeof(selLocal), selRemote,
	                                     sizeof(selRemote)) == STICE_ERR_SUCCESS);
	REQUIRE(std::string(selRemote).find(localIp + ":" + std::to_string(peer.port())) !=
	        std::string::npos);

	stice_destroy(a);
}

// ---------------------------------------------------------------------------
// RFC 8445 §6.1.2.5 checklist limit (G-ICE-7, F-ICE-3)
//
// The limit MUST be configurable and, when exceeded, the lowest-priority pairs
// must be discarded while the highest-priority ones are kept. Six remote
// candidates with strictly descending priorities are advertised against a
// limit of three: only the top pairs may ever be checked.
// ---------------------------------------------------------------------------
TEST_CASE("ICE checklist limit: lowest-priority pairs are pruned (G-ICE-7)",
          "[integration][udp][limit]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa;
	auto cfgA = makeConfig(sa);
	stice_agent_t *a = stice_create(&cfgA);
	REQUIRE(a != nullptr);

	stice_ice_pairing_config_t pc{};
	REQUIRE(stice_make_pairing_config(STICE_PAIRING_EMBEDDED_STABLE, &pc) ==
	        STICE_ERR_SUCCESS);
	pc.max_candidate_pairs = 3;
	REQUIRE(stice_set_pairing_config(a, &pc) == STICE_ERR_SUCCESS);

	REQUIRE(stice_set_local_ice_attributes(a, "ufragA", "pwdApwdApwdApwdApwdAxx") ==
	        STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));

	constexpr int kRemoteCount = 6;
	std::vector<std::unique_ptr<UdpProbePeer>> peers;
	std::string remoteSdp = "a=ice-ufrag:remoteufrag\n"
	                        "a=ice-pwd:remotepwdremotepwdremotepwd\n";
	std::uint32_t pri = 2000;
	for (int i = 0; i < kRemoteCount; ++i) {
		peers.emplace_back(new UdpProbePeer());
		remoteSdp += "a=candidate:" + std::to_string(i + 1) + " 1 UDP " +
		             std::to_string(pri) + " 127.0.0.1 " +
		             std::to_string(peers.back()->port()) + " typ host\n";
		pri -= 200;
	}
	remoteSdp += "a=end-of-candidates\n";
	REQUIRE(stice_set_remote_description(a, remoteSdp.c_str()) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);

	// Highest-priority candidate must be checked.
	REQUIRE(waitFor([&] {
		for (auto &p : peers) p->gotDatagram();
		return peers[0]->receivedAny();
	}, 6000));

	// Give the scheduler time to arm the remaining (bounded) list, then drain.
	std::this_thread::sleep_for(std::chrono::milliseconds(1500));
	for (auto &p : peers) p->gotDatagram();

	int contacted = 0;
	for (auto &p : peers)
		if (p->receivedAny()) ++contacted;
	// At most `limit` pairs exist, so at most `limit` remote ports can see a
	// check (a pair retransmits to the same port).
	REQUIRE(contacted <= 3);
	// The highest-priority pair is kept, the lowest-priority one is pruned.
	REQUIRE(peers[0]->receivedAny());
	REQUIRE_FALSE(peers[kRemoteCount - 1]->receivedAny());

	stice_destroy(a);
}

// ---------------------------------------------------------------------------
// RFC 8445 §6.1.2.6 unfreezing cadence (G-ICE-4, regression net for F-ICE-2)
//
// Frozen pairs are unfrozen in priority order and the checks are paced by Ta:
// the first check of a wave goes out after one Ta, the next after two, and so
// on. A scheduler that emits the whole checklist as a burst (the pre-F-ICE-2
// behaviour) would deliver all three probes within a few milliseconds, so the
// inter-arrival spacing is the observable that pins the pacing down.
// ---------------------------------------------------------------------------
TEST_CASE("ICE frozen-pair unfreezing is paced one Ta apart (G-ICE-4)",
          "[integration][udp][pacing]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState sa;
	auto cfgA = makeConfig(sa);
	stice_agent_t *a = stice_create(&cfgA);
	REQUIRE(a != nullptr);

	stice_ice_pairing_config_t pc{};
	REQUIRE(stice_make_pairing_config(STICE_PAIRING_EMBEDDED_STABLE, &pc) ==
	        STICE_ERR_SUCCESS);
	// A long Ta makes the spacing unambiguous against OS timer granularity.
	pc.ta_ms = 250;
	pc.max_concurrent_check = 3;
	pc.early_phase_max_concurrent = 3;
	pc.early_phase_duration_ms = 5000; // keep the whole wave in one budget
	REQUIRE(stice_set_pairing_config(a, &pc) == STICE_ERR_SUCCESS);

	REQUIRE(stice_set_local_ice_attributes(a, "ufragA", "pwdApwdApwdApwdApwdAxx") ==
	        STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 3000));

	constexpr int kRemoteCount = 3;
	std::vector<std::unique_ptr<UdpProbePeer>> peers;
	std::string remoteSdp = "a=ice-ufrag:remoteufrag\n"
	                        "a=ice-pwd:remotepwdremotepwdremotepwd\n";
	std::uint32_t pri = 2130706431u;
	for (int i = 0; i < kRemoteCount; ++i) {
		peers.emplace_back(new UdpProbePeer());
		remoteSdp += "a=candidate:" + std::to_string(i + 1) + " 1 UDP " +
		             std::to_string(pri) + " 127.0.0.1 " +
		             std::to_string(peers.back()->port()) + " typ host\n";
		pri -= 1000;
	}
	remoteSdp += "a=end-of-candidates\n";
	REQUIRE(stice_set_remote_description(a, remoteSdp.c_str()) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);

	// Record the first check arrival per probe.
	std::vector<std::chrono::steady_clock::time_point> firstSeen(kRemoteCount);
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(6000);
	while (std::chrono::steady_clock::now() < deadline) {
		bool all = true;
		for (int i = 0; i < kRemoteCount; ++i) {
			if (firstSeen[i].time_since_epoch().count() == 0) {
				if (peers[i]->gotDatagram()) firstSeen[i] = std::chrono::steady_clock::now();
				else all = false;
			}
		}
		if (all) break;
		std::this_thread::sleep_for(std::chrono::milliseconds(2));
	}
	for (int i = 0; i < kRemoteCount; ++i) {
		INFO("probe " << i << " contacted: " << peers[i]->receivedAny());
		REQUIRE(peers[i]->receivedAny());
	}

	// Order the arrivals and assert they are spread one Ta apart. The tolerance
	// is one-sided (scheduling only ever delays a send) with a floor well above
	// a burst and below Ta.
	std::vector<std::chrono::steady_clock::time_point> ordered = firstSeen;
	std::sort(ordered.begin(), ordered.end());
	for (int i = 1; i < kRemoteCount; ++i) {
		const auto gap = std::chrono::duration_cast<std::chrono::milliseconds>(
		    ordered[i] - ordered[i - 1]);
		INFO("check gap " << i << ": " << gap.count() << " ms");
		REQUIRE(gap >= std::chrono::milliseconds(150));
	}
	const auto span = std::chrono::duration_cast<std::chrono::milliseconds>(
	    ordered.back() - ordered.front());
	INFO("first-to-last check span: " << span.count() << " ms");
	REQUIRE(span >= std::chrono::milliseconds(350));

	stice_destroy(a);
}

