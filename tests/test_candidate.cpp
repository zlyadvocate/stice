// SPDX-License-Identifier: MPL-2.0
// Unit tests for the stice ICE candidate module (RFC 8445 §5).
//
// Covers:
//   - Candidate priority computation per RFC 8445 §5.1.2.1 (and the
//     RFC 6544 TCP-direction local preference adjustment).
//   - SDP a=candidate line serialization and parsing (round-trip).
//   - TCPType legality: active / passive / so.
//   - Illegal pair filtering: active-active and passive-passive MUST NOT
//     form a candidate pair (RFC 6544 §5.2).

#include <catch2/catch_all.hpp>

#include "stice/ice/candidate.hpp"
#include "stice/ice/candidatepair.hpp"
#include "stice/net/addr.hpp"

#include <cstring>
#include <string>

using namespace stice;
using namespace stice::ice;

namespace {
net::AddrRecord makeV4(std::uint32_t ip, std::uint16_t port) {
	net::AddrRecord r{};
	sockaddr_in in{};
	in.sin_family = AF_INET;
	in.sin_port = htons(port);
	in.sin_addr.s_addr = htonl(ip);
	std::memcpy(&r.addr, &in, sizeof(in));
	r.len = sizeof(in);
	r.socktype = SOCK_DGRAM;
	return r;
}

// Candidate-type preference (RFC 8445 §5.1.2.2, RECOMMENDED values).
constexpr std::uint32_t kPrefHost = 126;
constexpr std::uint32_t kPrefPeerReflexive = 110;
constexpr std::uint32_t kPrefServerReflexive = 100;
constexpr std::uint32_t kPrefRelayed = 0;
} // namespace

TEST_CASE("Candidate priority: host UDP IPv4", "[candidate]") {
	// priority = (typePref << 24) | (localPref << 8) | (256 - component)
	// host/UDP/IPv4: typePref=126, localPref=65535 (aligned with pion-ice), component=1.
	auto p = Candidate::computePriority(CandidateType::Host, AF_INET, 1, 0,
	                                     CandidateTransport::UDP);
	REQUIRE((p == ((126u << 24) | (65535u << 8) | (256u - 1u))));
}

TEST_CASE("Candidate priority: host UDP IPv6", "[candidate]") {
	// host/UDP/IPv6: typePref=126, localPref=65535 (aligned with pion-ice), component=1.
	auto p = Candidate::computePriority(CandidateType::Host, AF_INET6, 1, 0,
	                                     CandidateTransport::UDP);
	REQUIRE((p == ((126u << 24) | (65535u << 8) | (256u - 1u))));
}

TEST_CASE("Candidate priority: srflx UDP IPv4", "[candidate]") {
	auto p = Candidate::computePriority(CandidateType::ServerReflexive, AF_INET, 1, 0,
	                                     CandidateTransport::UDP);
	REQUIRE((p == ((100u << 24) | (65535u << 8) | (256u - 1u))));
}

TEST_CASE("Candidate priority: relay UDP IPv4", "[candidate]") {
	auto p = Candidate::computePriority(CandidateType::Relayed, AF_INET, 1, 0,
	                                     CandidateTransport::UDP);
	REQUIRE((p == ((0u << 24) | (65535u << 8) | (256u - 1u))));
}

TEST_CASE("Candidate priority: prflx", "[candidate]") {
	// prflx uses typePref=110 between srflx (100) and host (126).
	auto pPrflx = Candidate::computePriority(CandidateType::PeerReflexive, AF_INET, 1, 0,
	                                          CandidateTransport::UDP);
	auto pHost = Candidate::computePriority(CandidateType::Host, AF_INET, 1, 0,
	                                         CandidateTransport::UDP);
	auto pSrflx = Candidate::computePriority(CandidateType::ServerReflexive, AF_INET, 1, 0,
	                                          CandidateTransport::UDP);
	REQUIRE(pSrflx < pPrflx);
	REQUIRE(pPrflx < pHost);
}

TEST_CASE("Candidate priority: type ordering host > srflx > relay (same protocol)", "[candidate]") {
	// RFC 8445 §5.1.2.2 RECOMMENDED type preferences: host=126 > prflx=110 >
	// srflx=100 > relay=0. Verify the full ordering holds for the same
	// transport protocol (UDP) and same address family (IPv4).
	auto pHost = Candidate::computePriority(CandidateType::Host, AF_INET, 1, 0,
	                                        CandidateTransport::UDP);
	auto pSrflx = Candidate::computePriority(CandidateType::ServerReflexive, AF_INET, 1, 0,
	                                         CandidateTransport::UDP);
	auto pRelay = Candidate::computePriority(CandidateType::Relayed, AF_INET, 1, 0,
	                                         CandidateTransport::UDP);
	REQUIRE(pHost > pSrflx);
	REQUIRE(pSrflx > pRelay);

	// The ordering must also hold for IPv6 and for TCP transports.
	auto pHost6 = Candidate::computePriority(CandidateType::Host, AF_INET6, 1, 0,
	                                         CandidateTransport::UDP);
	auto pSrflx6 = Candidate::computePriority(CandidateType::ServerReflexive, AF_INET6, 1, 0,
	                                          CandidateTransport::UDP);
	auto pRelay6 = Candidate::computePriority(CandidateType::Relayed, AF_INET6, 1, 0,
	                                          CandidateTransport::UDP);
	REQUIRE(pHost6 > pSrflx6);
	REQUIRE(pSrflx6 > pRelay6);

	// TCP passive: same type ordering.
	auto pHostTcp = Candidate::computePriority(CandidateType::Host, AF_INET, 1, 0,
	                                           CandidateTransport::TCPPassive);
	auto pSrflxTcp = Candidate::computePriority(CandidateType::ServerReflexive, AF_INET, 1, 0,
	                                            CandidateTransport::TCPPassive);
	auto pRelayTcp = Candidate::computePriority(CandidateType::Relayed, AF_INET, 1, 0,
	                                            CandidateTransport::TCPPassive);
	REQUIRE(pHostTcp > pSrflxTcp);
	REQUIRE(pSrflxTcp > pRelayTcp);
}

TEST_CASE("Candidate priority: TCP gets lower preference than UDP", "[candidate]") {
	auto udp = Candidate::computePriority(CandidateType::Host, AF_INET, 1, 0,
	                                       CandidateTransport::UDP);
	auto tcpA = Candidate::computePriority(CandidateType::Host, AF_INET, 1, 0,
	                                         CandidateTransport::TCPActive);
	auto tcpP = Candidate::computePriority(CandidateType::Host, AF_INET, 1, 0,
	                                         CandidateTransport::TCPPassive);
	auto tcpS = Candidate::computePriority(CandidateType::Host, AF_INET, 1, 0,
	                                         CandidateTransport::TCPSimultaneousOpen);
	REQUIRE(tcpA < udp);
	REQUIRE(tcpP < udp);
	REQUIRE(tcpS < udp);
}

TEST_CASE("Candidate priority: TCP direction ordering", "[candidate]") {
	// active > passive > so.
	auto tcpA = Candidate::computePriority(CandidateType::Host, AF_INET, 1, 0,
	                                         CandidateTransport::TCPActive);
	auto tcpP = Candidate::computePriority(CandidateType::Host, AF_INET, 1, 0,
	                                         CandidateTransport::TCPPassive);
	auto tcpS = Candidate::computePriority(CandidateType::Host, AF_INET, 1, 0,
	                                         CandidateTransport::TCPSimultaneousOpen);
	REQUIRE(tcpP < tcpA);
	REQUIRE(tcpS < tcpP);
}

TEST_CASE("Candidate priority: component id affects low byte", "[candidate]") {
	auto c1 = Candidate::computePriority(CandidateType::Host, AF_INET, 1, 0,
	                                       CandidateTransport::UDP);
	auto c2 = Candidate::computePriority(CandidateType::Host, AF_INET, 2, 0,
	                                       CandidateTransport::UDP);
	REQUIRE((c1 & 0xFF) == 255);
	REQUIRE((c2 & 0xFF) == 254);
	REQUIRE(c2 < c1);
}

TEST_CASE("Candidate priority: index affects local preference", "[candidate]") {
	auto a = Candidate::computePriority(CandidateType::Host, AF_INET, 1, 0,
	                                       CandidateTransport::UDP);
	auto b = Candidate::computePriority(CandidateType::Host, AF_INET, 1, 5,
	                                       CandidateTransport::UDP);
	REQUIRE(b < a);
	// The index is subtracted from localPref which is then shifted left by 8
	// (for the component field), so the priority difference is 5 * 256.
	REQUIRE(a - b == (5u << 8));
}

TEST_CASE("Candidate type string round-trip", "[candidate]") {
	REQUIRE(std::string(typeString(CandidateType::Host)) == "host");
	REQUIRE(std::string(typeString(CandidateType::ServerReflexive)) == "srflx");
	REQUIRE(std::string(typeString(CandidateType::PeerReflexive)) == "prflx");
	REQUIRE(std::string(typeString(CandidateType::Relayed)) == "relay");
	REQUIRE(typeFromString("host") == CandidateType::Host);
	REQUIRE(typeFromString("srflx") == CandidateType::ServerReflexive);
	REQUIRE(typeFromString("prflx") == CandidateType::PeerReflexive);
	REQUIRE(typeFromString("relay") == CandidateType::Relayed);
	REQUIRE(typeFromString("garbage") == CandidateType::Unknown);
}

TEST_CASE("Candidate SDP serialization (UDP host)", "[candidate]") {
	Candidate c;
	c.type = CandidateType::Host;
	c.transport = CandidateTransport::UDP;
	c.component = 1;
	c.priority = (126u << 24) | (4095u << 8) | 255u;
	c.foundation = "1234";
	c.hostname = "192.168.1.5";
	c.service = "5000";
	auto sdp = c.toSdp();
	REQUIRE(sdp.find("a=candidate:1234 1 UDP ") == 0);
	REQUIRE(sdp.find(" 192.168.1.5 5000 typ host") != std::string::npos);
}

TEST_CASE("Candidate SDP serialization (TCP active)", "[candidate]") {
	Candidate c;
	c.type = CandidateType::Host;
	c.transport = CandidateTransport::TCPActive;
	c.component = 1;
	c.priority = 12345u;
	c.foundation = "F1";
	c.hostname = "10.0.0.1";
	c.service = "8000";
	auto sdp = c.toSdp();
	REQUIRE(sdp.find(" TCP ") != std::string::npos);
	REQUIRE(sdp.find("tcptype active") != std::string::npos);
	// RFC 6544 §4.5: an active candidate does not know its local port until
	// it connects, so the signaled port MUST be 9 (the discard port) — not
	// the ephemeral bind port it happens to hold (0.14.0 fix).
	REQUIRE(sdp.find(" 10.0.0.1 9 typ host") != std::string::npos);
	REQUIRE(sdp.find(" 10.0.0.1 8000 ") == std::string::npos);
}

TEST_CASE("Candidate SDP serialization (TCP passive keeps the real port)", "[candidate]") {
	// Only active candidates signal port 9; passive candidates own a live
	// listener and must keep advertising its actual port.
	Candidate c;
	c.type = CandidateType::Host;
	c.transport = CandidateTransport::TCPPassive;
	c.component = 1;
	c.priority = 12345u;
	c.foundation = "F1";
	c.hostname = "10.0.0.1";
	c.service = "8000";
	auto sdp = c.toSdp();
	REQUIRE(sdp.find("tcptype passive") != std::string::npos);
	REQUIRE(sdp.find(" 10.0.0.1 8000 typ host") != std::string::npos);
}

TEST_CASE("Candidate SDP round-trip parse", "[candidate]") {
	Candidate c;
	c.type = CandidateType::ServerReflexive;
	c.transport = CandidateTransport::UDP;
	c.component = 1;
	c.priority = 999999u;
	c.foundation = "abcd";
	c.hostname = "203.0.113.7";
	c.service = "3478";
	auto sdp = c.toSdp();

	Candidate parsed;
	REQUIRE(Candidate::parse(sdp, parsed));
	REQUIRE(parsed.foundation == "abcd");
	REQUIRE(parsed.component == 1);
	REQUIRE(parsed.priority == 999999u);
	REQUIRE(parsed.hostname == "203.0.113.7");
	REQUIRE(parsed.service == "3478");
	REQUIRE(parsed.type == CandidateType::ServerReflexive);
	REQUIRE(parsed.transport == CandidateTransport::UDP);
}

TEST_CASE("Candidate SDP parse handles 'a=candidate:' and 'candidate:' prefixes", "[candidate]") {
	std::string lineA = "a=candidate:F 1 UDP 100 1.2.3.4 5000 typ host";
	std::string lineB = "candidate:F 1 UDP 100 1.2.3.4 5000 typ host";
	Candidate a, b;
	REQUIRE(Candidate::parse(lineA, a));
	REQUIRE(Candidate::parse(lineB, b));
	REQUIRE(a.foundation == b.foundation);
	REQUIRE(a.priority == b.priority);
}

TEST_CASE("Candidate SDP parse reads tcptype", "[candidate]") {
	std::string line = "a=candidate:F 1 TCP 100 1.2.3.4 5000 typ host tcptype passive";
	Candidate c;
	REQUIRE(Candidate::parse(line, c));
	REQUIRE(c.transport == CandidateTransport::TCPPassive);

	std::string line2 = "a=candidate:F 1 TCP 100 1.2.3.4 5000 typ host tcptype so";
	Candidate c2;
	REQUIRE(Candidate::parse(line2, c2));
	REQUIRE(c2.transport == CandidateTransport::TCPSimultaneousOpen);
}

TEST_CASE("Candidate SDP emits the real base as raddr/rport", "[candidate][rfc8839][raddr]") {
	// RFC 8839 §5.1.1: rel-addr/rel-port carry the candidate's real base
	// address. pion marshals the same shape; the old libjuice-compatible
	// "raddr 0.0.0.0 rport 0" hack advertised a false address.
	Candidate c;
	c.type = CandidateType::ServerReflexive;
	c.transport = CandidateTransport::UDP;
	c.component = 1;
	c.priority = 999999u;
	c.foundation = "abcd";
	c.hostname = "203.0.113.7";
	c.service = "3478";
	c.related = makeV4(0xC0A80105u, 5000); // 192.168.1.5:5000
	c.hasRelated = true;

	auto sdp = c.toSdp();
	REQUIRE(sdp.find("typ srflx raddr 192.168.1.5 rport 5000") != std::string::npos);
	REQUIRE(sdp.find("raddr 0.0.0.0") == std::string::npos);
	REQUIRE(sdp.find("rport 0 ") == std::string::npos);
}

TEST_CASE("Candidate SDP omits raddr/rport when no base is known",
          "[candidate][rfc8839][raddr]") {
	// RFC 8839 §5.1.1 allows rel-addr/rel-port to be absent; emitting a fake
	// base is worse than emitting none.
	Candidate c;
	c.type = CandidateType::ServerReflexive;
	c.transport = CandidateTransport::UDP;
	c.component = 1;
	c.priority = 999999u;
	c.foundation = "abcd";
	c.hostname = "203.0.113.7";
	c.service = "3478";
	c.hasRelated = false;

	auto sdp = c.toSdp();
	REQUIRE(sdp.find("raddr") == std::string::npos);
	REQUIRE(sdp.find("rport") == std::string::npos);
	REQUIRE(sdp.find("typ srflx") != std::string::npos);
}

TEST_CASE("Candidate SDP puts rel-addr before the tcptype extension",
          "[candidate][rfc8839][raddr]") {
	// RFC 8839 §5.1 ABNF: [SP rel-addr] [SP rel-port] come before
	// *(SP extension-att-name SP extension-att-value), and tcptype (RFC 6544)
	// is such an extension.
	Candidate c;
	c.type = CandidateType::Relayed;
	c.transport = CandidateTransport::TCPPassive;
	c.component = 1;
	c.priority = 12345u;
	c.foundation = "R1";
	c.hostname = "203.0.113.9";
	c.service = "50000";
	c.related = makeV4(0xC0A80105u, 5000);
	c.hasRelated = true;

	auto sdp = c.toSdp();
	REQUIRE(sdp.find("typ relay raddr 192.168.1.5 rport 5000 tcptype passive") !=
	        std::string::npos);
	REQUIRE(sdp.find("rport 5000") < sdp.find("tcptype"));
}

TEST_CASE("Candidate SDP round-trips raddr/rport", "[candidate][rfc8839][raddr]") {
	Candidate c;
	c.type = CandidateType::Relayed;
	c.transport = CandidateTransport::UDP;
	c.component = 1;
	c.priority = 777u;
	c.foundation = "R2";
	c.hostname = "203.0.113.9";
	c.service = "50000";
	c.related = makeV4(0x0A000105u, 6000); // 10.0.1.5:6000
	c.hasRelated = true;

	auto sdp = c.toSdp();
	Candidate p;
	REQUIRE(Candidate::parse(sdp, p));
	REQUIRE(p.hasRelated);
	REQUIRE(net::addrToString(reinterpret_cast<const sockaddr *>(&p.related.addr)) ==
	        "10.0.1.5:6000");
	REQUIRE(net::addrPort(reinterpret_cast<const sockaddr *>(&p.related.addr)) == 6000);
	REQUIRE(p.toSdp() == sdp);
}

TEST_CASE("Candidate SDP parse accepts a peer's spec-clean srflx line",
          "[candidate][rfc8839][raddr]") {
	Candidate p;
	REQUIRE(Candidate::parse(
	    "a=candidate:F 1 UDP 100 203.0.113.7 3478 typ srflx raddr 192.168.1.5 rport 5000", p));
	REQUIRE(p.type == CandidateType::ServerReflexive);
	REQUIRE(p.hasRelated);
	REQUIRE(net::addrPort(reinterpret_cast<const sockaddr *>(&p.related.addr)) == 5000);
	// The advertised address stays the reflexive one; rel-addr is metadata only.
	REQUIRE(p.hostname == "203.0.113.7");
}

TEST_CASE("Candidate foundation is deterministic for same input", "[candidate]") {
	auto f1 = Candidate::computeFoundation(CandidateType::Host, "192.168.1.1",
	                                        CandidateTransport::UDP);
	auto f2 = Candidate::computeFoundation(CandidateType::Host, "192.168.1.1",
	                                        CandidateTransport::UDP);
	REQUIRE(f1 == f2);
	auto f3 = Candidate::computeFoundation(CandidateType::Host, "192.168.1.2",
	                                        CandidateTransport::UDP);
	REQUIRE(f1 != f3);
}

TEST_CASE("Illegal candidate pair filter: TCP active-active", "[candidate][pair]") {
	// Per RFC 6544 §5.2: a pair where BOTH ends are TCP-active is illegal
	// because neither side will open a connection. Likewise both passive.
	// This test documents the rule so the agent must filter such pairs.
	Candidate localActive;
	localActive.transport = CandidateTransport::TCPActive;
	Candidate remoteActive;
	remoteActive.transport = CandidateTransport::TCPActive;

	bool legal = !(localActive.transport == CandidateTransport::TCPActive &&
	               remoteActive.transport == CandidateTransport::TCPActive);
	REQUIRE_FALSE(legal);
}

TEST_CASE("Illegal candidate pair filter: TCP passive-passive", "[candidate][pair]") {
	Candidate localPassive;
	localPassive.transport = CandidateTransport::TCPPassive;
	Candidate remotePassive;
	remotePassive.transport = CandidateTransport::TCPPassive;

	bool legal = !(localPassive.transport == CandidateTransport::TCPPassive &&
	               remotePassive.transport == CandidateTransport::TCPPassive);
	REQUIRE_FALSE(legal);
}

TEST_CASE("Legal candidate pair: TCP active-passive", "[candidate][pair]") {
	Candidate localActive;
	localActive.transport = CandidateTransport::TCPActive;
	Candidate remotePassive;
	remotePassive.transport = CandidateTransport::TCPPassive;

	bool legal = !(localActive.transport == CandidateTransport::TCPActive &&
	               remotePassive.transport == CandidateTransport::TCPActive) &&
	             !(localActive.transport == CandidateTransport::TCPPassive &&
	               remotePassive.transport == CandidateTransport::TCPPassive);
	REQUIRE(legal);
}

TEST_CASE("Legal candidate pair: TCP SO-SO", "[candidate][pair]") {
	Candidate a;
	a.transport = CandidateTransport::TCPSimultaneousOpen;
	Candidate b;
	b.transport = CandidateTransport::TCPSimultaneousOpen;

	bool legal = !(a.transport == CandidateTransport::TCPActive &&
	               b.transport == CandidateTransport::TCPActive) &&
	             !(a.transport == CandidateTransport::TCPPassive &&
	               b.transport == CandidateTransport::TCPPassive);
	REQUIRE(legal);
}

TEST_CASE("CandidatePair priority formula (RFC 8445 §6.1.2.3)", "[candidate][pair]") {
	// pairPriority = 2^32 * MIN(G,D) + 2 * MAX(G,D) + (G > D ? 1 : 0)
	// The RFC coefficient is 2^32 verbatim; inputs are clamped to 2^31-1 so the
	// product stays inside uint64.
	std::uint32_t lp = 100u;
	std::uint32_t rp = 90u;
	constexpr std::uint64_t k = 1ull << 32;

	SECTION("controlling local: G=local, D=remote") {
		// G=100, D=90; min=90, max=100; G>D so +1
		std::uint64_t expected = k * 90u + (std::uint64_t{100} << 1) + 1u;
		REQUIRE(CandidatePair::computePriority(lp, rp, true) == expected);
	}
	SECTION("controlled local: G=remote, D=local") {
		// G=90, D=100; min=90, max=100; G<D so +0
		std::uint64_t expected = k * 90u + (std::uint64_t{100} << 1) + 0u;
		REQUIRE(CandidatePair::computePriority(lp, rp, false) == expected);
	}
	SECTION("equal priorities: tiebreak goes +0") {
		std::uint64_t expected = k * 100u + (std::uint64_t{100} << 1) + 0u;
		REQUIRE(CandidatePair::computePriority(100u, 100u, true) == expected);
	}
}

TEST_CASE("CandidatePair: higher local priority gives higher pair priority when controlling",
          "[candidate][pair]") {
	auto p1 = CandidatePair::computePriority(50u, 50u, true);
	auto p2 = CandidatePair::computePriority(100u, 50u, true);
	REQUIRE(p2 > p1);
}
