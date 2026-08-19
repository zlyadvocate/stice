// SPDX-License-Identifier: MPL-2.0
// stice ICE SDP / candidate-description handling. Ported from libjuice's
// ice.c parse_sdp_line / ice_generate_sdp and libdatachannel's
// candidate.cpp.
//
// The description is a fragment of SDP containing:
//   a=ice-ufrag:<ufrag>
//   a=ice-pwd:<pwd>
//   a=ice-lite                (optional)
//   a=candidate:...           (zero or more)
//   a=end-of-candidates       (optional, marks trickle done)
//   a=ice-options:ice2[,trickle]

#ifndef STICE_ICE_SDP_HPP
#define STICE_ICE_SDP_HPP

#include "stice/ice/candidate.hpp"

#include <string>
#include <vector>

namespace stice::ice {

constexpr std::size_t MaxCandidates = 30;
constexpr std::size_t MaxUfragLen = 256;
constexpr std::size_t MaxPwdLen = 256;

struct Description {
	std::string iceUfrag;
	std::string icePwd;
	bool iceLite = false;
	std::vector<Candidate> candidates;
	bool finished = false; // end-of-candidates seen

	void sortCandidates();
	std::string generateSdp() const;
	// Parse a SDP fragment. Lines may be \n or \r\n separated. Returns
	// false if ufrag or pwd is missing after parsing all lines.
	bool parse(const std::string &sdp);
	// Add a candidate from a "a=candidate:..." line.
	bool addCandidateFromSdp(const std::string &line);
};

// Generate a random ufrag (4+ chars, base64 alphabet).
std::string generateUfrag();
// Generate a random pwd (22+ chars, base64 alphabet).
std::string generatePwd();

} // namespace stice::ice

#endif
