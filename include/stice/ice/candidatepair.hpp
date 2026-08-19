// SPDX-License-Identifier: MPL-2.0
// stice ICE candidate pair (RFC 8445 §6). Ported from libjuice's ice.c
// and pion-ice's candidatepair.go.

#ifndef STICE_ICE_CANDIDATEPAIR_HPP
#define STICE_ICE_CANDIDATEPAIR_HPP

#include "stice/ice/candidate.hpp"

#include <array>
#include <chrono>
#include <cstdint>

namespace stice::ice {

enum class PairState {
	Frozen,
	Pending,
	Succeeded,
	Failed,
};

struct CandidatePair {
	const Candidate *local = nullptr;
	const Candidate *remote = nullptr;
	std::uint64_t priority = 0;
	PairState state = PairState::Frozen;
	bool nominated = false;
	bool nominationRequested = false;
	// Last NOMINATION value received (draft-thatcher-ice-renomination).
	// The controlled side tracks the highest value seen and only switches
	// the selected pair when a strictly larger value arrives.
	std::uint32_t nominationValue = 0;
	std::chrono::steady_clock::time_point consentExpiry{};
	std::chrono::steady_clock::time_point nextTransmission{};
	std::chrono::milliseconds retransmissionTimeout{500};
	int retransmissions = 0;
	std::array<unsigned char, 12> transactionID{};
	bool transactionIdExpired = true;

	// Compute the pair priority per RFC 8445 §6.1.2.3:
	// pairPriority = 2^32 * MIN(G,D) + 2 * MAX(G,D) + (G > D ? 1 : 0)
	// where G is the controlling priority and D is the controlled priority.
	//
	// Note: pion-ice (candidatepair.go priority()) uses (2^32 - 1) instead of
	// 2^32 to avoid uint64 overflow when both G and D are maxUint32. We align
	// with pion-ice for bit-level numeric compatibility. In practice candidate
	// priorities never reach maxUint32, so ordering is unaffected.
	static std::uint64_t computePriority(std::uint32_t localPriority,
	                                     std::uint32_t remotePriority, bool localIsControlling) {
		std::uint64_t g = localIsControlling ? localPriority : remotePriority;
		std::uint64_t d = localIsControlling ? remotePriority : localPriority;
		std::uint64_t min = g < d ? g : d;
		std::uint64_t max = g > d ? g : d;
		return ((1ull << 32) - 1) * min + (max << 1) + (g > d ? 1 : 0);
	}

	void updatePriority(bool localIsControlling) {
		std::uint32_t lp = local ? local->priority : 0;
		std::uint32_t rp = remote ? remote->priority : 0;
		priority = computePriority(lp, rp, localIsControlling);
	}
};

} // namespace stice::ice

#endif
