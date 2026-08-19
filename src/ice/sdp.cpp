/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "stice/ice/sdp.hpp"

#include "stice/crypto.hpp"

#include <algorithm>
#include <sstream>

namespace stice::ice {

std::string generateUfrag() {
	// RFC 8445: ufrag 4-32 chars. Use 8 for compactness.
	return crypto::randomStr64(8);
}

std::string generatePwd() {
	// RFC 8445: pwd 22-256 chars. Use 24.
	return crypto::randomStr64(24);
}

void Description::sortCandidates() {
	std::stable_sort(candidates.begin(), candidates.end(),
	                 [](const Candidate &a, const Candidate &b) { return a.priority > b.priority; });
}

std::string Description::generateSdp() const {
	std::string s;
	s.reserve(256);
	s += "a=ice-ufrag:";
	s += iceUfrag;
	s += "\r\na=ice-pwd:";
	s += icePwd;
	s += "\r\n";
	if (iceLite) s += "a=ice-lite\r\n";
	for (const auto &c : candidates) {
		// prflx candidates are never emitted in SDP (only learned via STUN).
		if (c.type == CandidateType::PeerReflexive) continue;
		s += c.toSdp();
		s += "\r\n";
	}
	if (finished) {
		s += "a=end-of-candidates\r\n";
		s += "a=ice-options:ice2\r\n";
	} else {
		s += "a=ice-options:ice2,trickle\r\n";
	}
	return s;
}

bool Description::addCandidateFromSdp(const std::string &line) {
	if (candidates.size() >= MaxCandidates) return false;
	Candidate c;
	if (!Candidate::parse(line, c)) return false;
	candidates.push_back(std::move(c));
	return true;
}

bool Description::parse(const std::string &sdp) {
	std::istringstream iss(sdp);
	std::string line;
	while (std::getline(iss, line)) {
		// Strip trailing \r.
		if (!line.empty() && line.back() == '\r') line.pop_back();
		if (line.empty()) continue;
		if (line.rfind("a=ice-ufrag:", 0) == 0) {
			iceUfrag = line.substr(12);
		} else if (line.rfind("a=ice-pwd:", 0) == 0) {
			icePwd = line.substr(10);
		} else if (line == "a=ice-lite") {
			iceLite = true;
		} else if (line == "a=end-of-candidates") {
			finished = true;
		} else if (line.rfind("a=candidate:", 0) == 0) {
			addCandidateFromSdp(line);
		}
	}
	sortCandidates();
	return !iceUfrag.empty() && !icePwd.empty();
}

} // namespace stice::ice
