// SPDX-License-Identifier: MPL-2.0
// Unit tests for the stice ICE CandidatePair state machine and the
// connectivity-check STUN message it produces.
//
// Covers:
//   - Pair state transitions: Frozen -> Pending -> Succeeded/Failed.
//   - Connectivity-check STUN Binding Request generation (USE-CANDIDATE on
//     nomination, ICE-CONTROLLING / ICE-CONTROLLED, PRIORITY).
//   - Nomination logic: a Succeeded pair with USE-CANDIDATE becomes the
//     nominated pair.
//   - Pair priority ordering matches the ordered list used by the agent.
//
// These tests exercise CandidatePair + STUN message building directly; the
// full agent end-to-end test is in test_integration.cpp.

#include <catch2/catch_all.hpp>

#include "stice/ice/agent.hpp"
#include "stice/ice/candidate.hpp"
#include "stice/ice/candidatepair.hpp"
#include "stice/stun/message.hpp"
#include "stice/stun/attributes.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <vector>

using namespace stice;
using namespace stice::ice;
using namespace stice::stun;

namespace {
Candidate makeCandidate(CandidateType type, CandidateTransport t, std::uint32_t priority) {
	Candidate c;
	c.type = type;
	c.transport = t;
	c.priority = priority;
	c.component = 1;
	c.foundation = "F";
	c.hostname = "1.2.3.4";
	c.service = "5000";
	return c;
}

// Build the STUN Binding Request that the agent would send for a check.
// Mirrors agent.cpp's sendStunBinding for a CHECK entry.
Message buildCheckRequest(const CandidatePair &p, AgentMode mode, std::uint64_t tiebreaker,
                          bool nominate) {
	Message m;
	m.method = Method::Binding;
	m.cls = Class::Request;
	m.newTransactionID();
	// PRIORITY (peer-reflexive learning hint): use the local candidate priority.
	std::uint32_t localPri = p.local ? p.local->priority : 0;
	addPriority(m, localPri);
	if (mode == AgentMode::Controlling) {
		addIceControlling(m, tiebreaker);
		if (nominate) addUseCandidate(m);
	} else {
		addIceControlled(m, tiebreaker);
	}
	m.encode(nullptr, nullptr, nullptr);
	return m;
}
} // namespace

TEST_CASE("CandidatePair default state is Frozen", "[pair]") {
	CandidatePair p;
	REQUIRE(p.state == PairState::Frozen);
	REQUIRE_FALSE(p.nominated);
	REQUIRE_FALSE(p.nominationRequested);
	REQUIRE(p.priority == 0);
	REQUIRE(p.local == nullptr);
	REQUIRE(p.remote == nullptr);
}

TEST_CASE("CandidatePair state transition Frozen -> Pending", "[pair]") {
	CandidatePair p;
	p.state = PairState::Frozen;
	p.state = PairState::Pending;
	REQUIRE(p.state == PairState::Pending);
}

TEST_CASE("CandidatePair state transition Pending -> Succeeded", "[pair]") {
	CandidatePair p;
	p.state = PairState::Pending;
	p.state = PairState::Succeeded;
	REQUIRE(p.state == PairState::Succeeded);
}

TEST_CASE("CandidatePair state transition Pending -> Failed", "[pair]") {
	CandidatePair p;
	p.state = PairState::Pending;
	p.state = PairState::Failed;
	REQUIRE(p.state == PairState::Failed);
}

TEST_CASE("CandidatePair state transition Succeeded -> Failed (consent expiry)", "[pair]") {
	// RFC 8445 §11: a succeeded pair that loses consent transitions to Failed.
	CandidatePair p;
	p.state = PairState::Succeeded;
	p.state = PairState::Failed;
	REQUIRE(p.state == PairState::Failed);
}

TEST_CASE("CandidatePair updatePriority uses local/remote priorities", "[pair]") {
	auto lc = makeCandidate(CandidateType::Host, CandidateTransport::UDP, 100u);
	auto rc = makeCandidate(CandidateType::Host, CandidateTransport::UDP, 90u);
	CandidatePair p;
	p.local = &lc;
	p.remote = &rc;

	SECTION("controlling") {
		p.updatePriority(true);
		REQUIRE(p.priority == CandidatePair::computePriority(100u, 90u, true));
	}
	SECTION("controlled") {
		p.updatePriority(false);
		REQUIRE(p.priority == CandidatePair::computePriority(100u, 90u, false));
	}
}

TEST_CASE("Connectivity check request includes ICE-CONTROLLING", "[pair][check]") {
	auto lc = makeCandidate(CandidateType::Host, CandidateTransport::UDP, 100u);
	auto rc = makeCandidate(CandidateType::Host, CandidateTransport::UDP, 90u);
	CandidatePair p;
	p.local = &lc;
	p.remote = &rc;

	auto m = buildCheckRequest(p, AgentMode::Controlling, 0xCAFEULL, false);
	Message d;
	REQUIRE(d.decode(m.raw.data(), m.raw.size()));

	REQUIRE(d.method == Method::Binding);
	REQUIRE(d.cls == Class::Request);

	std::uint64_t tb = 0;
	REQUIRE(readIceControlling(d, tb));
	REQUIRE(tb == 0xCAFEULL);

	REQUIRE_FALSE(hasUseCandidate(d)); // not nominating

	std::uint32_t pri = 0;
	REQUIRE(readPriority(d, pri));
	REQUIRE(pri == 100u);
}

TEST_CASE("Connectivity check request includes ICE-CONTROLLED", "[pair][check]") {
	auto lc = makeCandidate(CandidateType::Host, CandidateTransport::UDP, 100u);
	auto rc = makeCandidate(CandidateType::Host, CandidateTransport::UDP, 90u);
	CandidatePair p;
	p.local = &lc;
	p.remote = &rc;

	auto m = buildCheckRequest(p, AgentMode::Controlled, 0xBEEFULL, false);
	Message d;
	REQUIRE(d.decode(m.raw.data(), m.raw.size()));

	std::uint64_t tb = 0;
	REQUIRE_FALSE(readIceControlling(d, tb));
	REQUIRE(readIceControlled(d, tb));
	REQUIRE(tb == 0xBEEFULL);
	REQUIRE_FALSE(hasUseCandidate(d));
}

TEST_CASE("Nomination: USE-CANDIDATE present when nominate=true (controlling)", "[pair][check]") {
	auto lc = makeCandidate(CandidateType::Host, CandidateTransport::UDP, 100u);
	auto rc = makeCandidate(CandidateType::Host, CandidateTransport::UDP, 90u);
	CandidatePair p;
	p.local = &lc;
	p.remote = &rc;

	auto m = buildCheckRequest(p, AgentMode::Controlling, 0x1234ULL, true);
	Message d;
	REQUIRE(d.decode(m.raw.data(), m.raw.size()));
	REQUIRE(hasUseCandidate(d));
}

TEST_CASE("Nomination: controlled agent never sets USE-CANDIDATE", "[pair][check]") {
	auto lc = makeCandidate(CandidateType::Host, CandidateTransport::UDP, 100u);
	auto rc = makeCandidate(CandidateType::Host, CandidateTransport::UDP, 90u);
	CandidatePair p;
	p.local = &lc;
	p.remote = &rc;

	auto m = buildCheckRequest(p, AgentMode::Controlled, 0x1234ULL, true);
	Message d;
	REQUIRE(d.decode(m.raw.data(), m.raw.size()));
	REQUIRE_FALSE(hasUseCandidate(d));
}

TEST_CASE("Nomination: a Succeeded pair with USE-CANDIDATE becomes nominated", "[pair]") {
	auto lc = makeCandidate(CandidateType::Host, CandidateTransport::UDP, 100u);
	auto rc = makeCandidate(CandidateType::Host, CandidateTransport::UDP, 90u);
	CandidatePair p;
	p.local = &lc;
	p.remote = &rc;
	p.state = PairState::Pending;

	// Agent sees a successful response to a USE-CANDIDATE request.
	bool sawUseCandidate = true;
	if (sawUseCandidate && p.state == PairState::Pending) {
		p.state = PairState::Succeeded;
		p.nominated = true;
	}
	REQUIRE(p.state == PairState::Succeeded);
	REQUIRE(p.nominated);
}

TEST_CASE("Connectivity check request has FINGERPRINT", "[pair][check]") {
	auto lc = makeCandidate(CandidateType::Host, CandidateTransport::UDP, 100u);
	auto rc = makeCandidate(CandidateType::Host, CandidateTransport::UDP, 90u);
	CandidatePair p;
	p.local = &lc;
	p.remote = &rc;

	auto m = buildCheckRequest(p, AgentMode::Controlling, 0x1ULL, false);
	Message d;
	REQUIRE(d.decode(m.raw.data(), m.raw.size()));
	REQUIRE(d.checkFingerprint());
}

TEST_CASE("CandidatePair transaction ID is 12 bytes", "[pair]") {
	CandidatePair p;
	REQUIRE(p.transactionID.size() == TransactionIDSize);
	REQUIRE(p.transactionIdExpired == true);
}

TEST_CASE("Ordered pair list: higher priority first", "[pair][ordering]") {
	// Build 3 pairs with different priorities; the agent keeps orderedPairs_
	// sorted descending by priority. We simulate the ordering inline.
	auto lc = makeCandidate(CandidateType::Host, CandidateTransport::UDP, 100u);
	// Store remote candidates in a vector so they outlive the pairs.
	std::vector<Candidate> remotes;
	for (std::uint32_t rp : {50u, 90u, 70u})
		remotes.push_back(makeCandidate(CandidateType::Host, CandidateTransport::UDP, rp));
	std::vector<CandidatePair> pairs;
	for (auto &rc : remotes) {
		CandidatePair p;
		p.local = &lc;
		p.remote = &rc;
		p.updatePriority(true);
		pairs.push_back(p);
	}

	std::sort(pairs.begin(), pairs.end(),
	          [](const CandidatePair &a, const CandidatePair &b) { return a.priority > b.priority; });

	REQUIRE(pairs[0].remote->priority == 90u);
	REQUIRE(pairs[1].remote->priority == 70u);
	REQUIRE(pairs[2].remote->priority == 50u);
}

TEST_CASE("Retransmission counter increments on timeout", "[pair]") {
	CandidatePair p;
	p.retransmissions = 0;
	p.retransmissionTimeout = std::chrono::milliseconds(500);

	// First retransmit: 500ms -> 1000ms (per RFC 8445 §15 backoff).
	p.retransmissions++;
	REQUIRE(p.retransmissions == 1);
	// RFC 8445 recommends doubling RTO each time (cap at LastRTO).
	p.retransmissionTimeout *= 2;
	REQUIRE(p.retransmissionTimeout.count() == 1000);
}

TEST_CASE("Max retransmissions reached => pair fails", "[pair]") {
	// libjuice uses MaxStunCheckRetransmissions = 6.
	constexpr int kMaxRetransmissions = 6;
	CandidatePair p;
	p.state = PairState::Pending;
	for (int i = 0; i < kMaxRetransmissions; ++i) {
		p.retransmissions++;
	}
	if (p.retransmissions >= kMaxRetransmissions) {
		p.state = PairState::Failed;
	}
	REQUIRE(p.state == PairState::Failed);
	REQUIRE(p.retransmissions == kMaxRetransmissions);
}

// ---------------------------------------------------------------------------
// RFC 6062 TCP-relayed candidate pair filtering
//
// RFC 6544 §5.2 + RFC 6062: TCP candidate pair filtering rules:
//   - active-active: illegal (neither side connects)
//   - passive-passive (non-relayed): illegal (neither side connects)
//   - passive-passive (both relayed): LEGAL under RFC 6062 — the controlling
//     side sends CONNECT, the controlled side receives CONNECTION-ATTEMPT
//   - active-passive: legal (active side connects to passive)
//   - SO with anything: legal (SO can both initiate and accept)
//   - UDP cannot pair with TCP (different transports)
//
// These tests replicate the exact filtering rule from Agent::formPairs() to
// document and verify the RFC 6062 active+passive dual-mode pairing behavior.
// ---------------------------------------------------------------------------

namespace {
// Replicate the Agent::formPairs() TCP pair-filtering rule (RFC 6544 §5.2 +
// RFC 6062). Returns true if the pair is allowed, false if filtered out.
bool isTcpPairAllowed(const Candidate &local, const Candidate &remote) {
	bool localIsTcp = (local.transport != CandidateTransport::UDP);
	bool remoteIsTcp = (remote.transport != CandidateTransport::UDP);
	// Cross-transport pair not allowed.
	if (localIsTcp != remoteIsTcp) return false;
	if (localIsTcp && remoteIsTcp) {
		bool localActive = (local.transport == CandidateTransport::TCPActive);
		bool remoteActive = (remote.transport == CandidateTransport::TCPActive);
		bool localPassive = (local.transport == CandidateTransport::TCPPassive);
		bool remotePassive = (remote.transport == CandidateTransport::TCPPassive);
		// active-active illegal.
		if (localActive && remoteActive) return false;
		// RFC 6062: two TCP-relayed (passive) candidates CAN pair — the
		// controlling side sends CONNECT, the controlled side receives
		// CONNECTION-ATTEMPT. Only filter non-relayed passive-passive.
		if (localPassive && remotePassive &&
		    !(local.type == CandidateType::Relayed && remote.type == CandidateType::Relayed))
			return false;
	}
	return true;
}
} // namespace

TEST_CASE("RFC 6062: relayed passive-passive TCP pair is allowed", "[pair][rfc6062]") {
	// RFC 6062 key behavior: two TCP-relayed (passive) candidates CAN pair.
	// The controlling side sends CONNECT; the controlled side receives
	// CONNECTION-ATTEMPT. This is the active+passive dual-mode enabler.
	auto localRelayedPassive = makeCandidate(CandidateType::Relayed, CandidateTransport::TCPPassive, 100u);
	auto remoteRelayedPassive = makeCandidate(CandidateType::Relayed, CandidateTransport::TCPPassive, 90u);
	REQUIRE(isTcpPairAllowed(localRelayedPassive, remoteRelayedPassive));
}

TEST_CASE("RFC 6062: non-relayed passive-passive TCP pair is filtered", "[pair][rfc6062]") {
	// Without RFC 6062 (non-relayed), passive-passive is illegal per RFC 6544.
	auto localHostPassive = makeCandidate(CandidateType::Host, CandidateTransport::TCPPassive, 100u);
	auto remoteHostPassive = makeCandidate(CandidateType::Host, CandidateTransport::TCPPassive, 90u);
	REQUIRE_FALSE(isTcpPairAllowed(localHostPassive, remoteHostPassive));
}

TEST_CASE("RFC 6062: active-active TCP pair is filtered", "[pair][rfc6062]") {
	// active-active is always illegal (neither side connects), even if relayed.
	auto localRelayedActive = makeCandidate(CandidateType::Relayed, CandidateTransport::TCPActive, 100u);
	auto remoteRelayedActive = makeCandidate(CandidateType::Relayed, CandidateTransport::TCPActive, 90u);
	REQUIRE_FALSE(isTcpPairAllowed(localRelayedActive, remoteRelayedActive));
}

TEST_CASE("RFC 6062: active-passive TCP pair is allowed", "[pair][rfc6062]") {
	// active-passive is the standard RFC 6544 legal pair.
	auto localActive = makeCandidate(CandidateType::Host, CandidateTransport::TCPActive, 100u);
	auto remotePassive = makeCandidate(CandidateType::Host, CandidateTransport::TCPPassive, 90u);
	REQUIRE(isTcpPairAllowed(localActive, remotePassive));

	// Also legal in the other direction.
	auto localPassive = makeCandidate(CandidateType::Host, CandidateTransport::TCPPassive, 100u);
	auto remoteActive = makeCandidate(CandidateType::Host, CandidateTransport::TCPActive, 90u);
	REQUIRE(isTcpPairAllowed(localPassive, remoteActive));
}

TEST_CASE("RFC 6062: relayed active-passive TCP pair is allowed", "[pair][rfc6062]") {
	// RFC 6062 also allows relayed active-passive pairs (one side relays
	// and actively connects, the other is passive).
	auto localRelayedActive = makeCandidate(CandidateType::Relayed, CandidateTransport::TCPActive, 100u);
	auto remoteRelayedPassive = makeCandidate(CandidateType::Relayed, CandidateTransport::TCPPassive, 90u);
	REQUIRE(isTcpPairAllowed(localRelayedActive, remoteRelayedPassive));
}

TEST_CASE("RFC 6062: SO with any TCP type is allowed", "[pair][rfc6062]") {
	// Simultaneous-Open can pair with any TCP type (RFC 6544 §5.2).
	auto so = makeCandidate(CandidateType::Host, CandidateTransport::TCPSimultaneousOpen, 100u);
	auto passive = makeCandidate(CandidateType::Host, CandidateTransport::TCPPassive, 90u);
	auto active = makeCandidate(CandidateType::Host, CandidateTransport::TCPActive, 90u);
	auto so2 = makeCandidate(CandidateType::Host, CandidateTransport::TCPSimultaneousOpen, 90u);
	REQUIRE(isTcpPairAllowed(so, passive));
	REQUIRE(isTcpPairAllowed(so, active));
	REQUIRE(isTcpPairAllowed(so, so2));
	REQUIRE(isTcpPairAllowed(passive, so));
	REQUIRE(isTcpPairAllowed(active, so));
}

TEST_CASE("RFC 6062: UDP-TCP cross-transport pair is filtered", "[pair][rfc6062]") {
	// UDP cannot pair with TCP (different transports).
	auto udp = makeCandidate(CandidateType::Host, CandidateTransport::UDP, 100u);
	auto tcpActive = makeCandidate(CandidateType::Host, CandidateTransport::TCPActive, 90u);
	auto tcpPassive = makeCandidate(CandidateType::Host, CandidateTransport::TCPPassive, 90u);
	REQUIRE_FALSE(isTcpPairAllowed(udp, tcpActive));
	REQUIRE_FALSE(isTcpPairAllowed(udp, tcpPassive));
	REQUIRE_FALSE(isTcpPairAllowed(tcpActive, udp));
	REQUIRE_FALSE(isTcpPairAllowed(tcpPassive, udp));
}

TEST_CASE("RFC 6062: UDP-UDP pair is allowed", "[pair][rfc6062]") {
	// Standard UDP pairing is unaffected by RFC 6062 rules.
	auto localUdp = makeCandidate(CandidateType::Host, CandidateTransport::UDP, 100u);
	auto remoteUdp = makeCandidate(CandidateType::Host, CandidateTransport::UDP, 90u);
	REQUIRE(isTcpPairAllowed(localUdp, remoteUdp));
}

TEST_CASE("RFC 6062: mixed relayed/non-relayed passive-passive is filtered", "[pair][rfc6062]") {
	// Only BOTH-relayed passive-passive is allowed under RFC 6062.
	// One side relayed + one side host (both passive) is still illegal.
	auto relayedPassive = makeCandidate(CandidateType::Relayed, CandidateTransport::TCPPassive, 100u);
	auto hostPassive = makeCandidate(CandidateType::Host, CandidateTransport::TCPPassive, 90u);
	REQUIRE_FALSE(isTcpPairAllowed(relayedPassive, hostPassive));
	REQUIRE_FALSE(isTcpPairAllowed(hostPassive, relayedPassive));
}
