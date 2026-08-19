// SPDX-License-Identifier: MPL-2.0
// stice ICE candidate (RFC 8445 §5). Ported from libjuice's ice.c and
// pion-ice's candidate_base.go.

#ifndef STICE_ICE_CANDIDATE_HPP
#define STICE_ICE_CANDIDATE_HPP

#include "stice/net/addr.hpp"
#include "stice/types.hpp"

#include <atomic>
#include <cstdint>
#include <string>

namespace stice::ice {

enum class CandidateType {
	Unknown,
	Host,
	ServerReflexive,
	PeerReflexive,
	Relayed,
};

enum class CandidateTransport {
	UDP,
	TCPActive,
	TCPPassive,
	TCPSimultaneousOpen,
};

// Type preferences (RFC 8445 §5.1.2.2).
constexpr std::uint32_t PrefHost = 126;
constexpr std::uint32_t PrefPeerReflexive = 110;
constexpr std::uint32_t PrefServerReflexive = 100;
constexpr std::uint32_t PrefRelayed = 0;
// Aligned with pion-ice defaultTCPPriorityOffset and libwebrtc.
constexpr std::uint32_t TcpPenalty = 27;

// Runtime-configurable TCP priority offset (P2-1). Defaults to TcpPenalty (27).
// Override via stice_set_tcp_priority_offset(). computePriority reads this
// instead of the hardcoded constant so deployments can tune UDP-vs-TCP
// preference without recompiling.
extern std::atomic<std::uint32_t> g_tcpPriorityOffset;
inline std::uint32_t currentTcpPriorityOffset() {
	return g_tcpPriorityOffset.load(std::memory_order_acquire);
}

const char *typeString(CandidateType t);
const char *transportString(CandidateTransport t);
CandidateType typeFromString(const std::string &s);

struct Candidate {
	CandidateType type = CandidateType::Unknown;
	CandidateTransport transport = CandidateTransport::UDP;
	std::uint32_t priority = 0;
	int component = 1;
	std::string foundation;
	std::string hostname; // numeric host or hostname (resolved before use)
	std::string service;  // port as string
	net::AddrRecord resolved{};
	// Related address (for srflx/relay candidates).
	bool hasRelated = false;
	net::AddrRecord related{};

	// Compute the SDP "a=candidate:" line for this candidate.
	std::string toSdp() const;
	// Parse a candidate SDP line ("a=candidate:..." or "candidate:...").
	static bool parse(const std::string &line, Candidate &out);
	// Compute the candidate priority per RFC 8445 §5.1.2.1.
	static std::uint32_t computePriority(CandidateType type, int family, int component,
	                                     int index, CandidateTransport transport);
	std::uint32_t computePriority(int index) const {
		int fam = AF_INET;
		if (resolved.addr.ss_family == AF_INET6) fam = AF_INET6;
		return computePriority(type, fam, component, index, transport);
	}
	// Compute a foundation (CRC32 of type+addr+transport, hex string).
	static std::string computeFoundation(CandidateType type, const std::string &addr,
	                                     CandidateTransport transport);
};

} // namespace stice::ice

#endif
