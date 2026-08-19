// SPDX-License-Identifier: MPL-2.0
// stice NAT 1:1 IP address rewrite mapper.
// Ported from pion-ice's external_ip_mapper.go and gather.go address rewrite
// logic. Supports replace and append modes for host/srflx/relay candidates.
//
// The mapper takes a list of AddressRewriteRule entries and, for each local
// candidate address, determines the set of external IPs to advertise (and
// whether to keep or drop the original).

#ifndef STICE_ICE_ADDR_REWRITE_HPP
#define STICE_ICE_ADDR_REWRITE_HPP

#include "stice/ice/candidate.hpp"
#include "stice/net/addr.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace stice::ice {

// Controls whether a rule replaces the original candidate or appends extras.
enum class AddressRewriteMode {
	Unspecified = 0,
	Replace,
	Append,
};

// A rule for remapping candidate addresses (NAT 1:1 IP mapping).
struct AddressRewriteRule {
	// External IPs to advertise for this rule.
	// - Replace mode with empty list: drop the matched candidate.
	// - Append mode with empty list: keep the original, add nothing.
	std::vector<std::string> external;
	// Optional: pin this rule to a specific local address.
	std::string local;
	// Optional: interface name to limit the rule to (empty = any).
	std::string iface;
	// Optional: CIDR to limit the rule to (empty = any).
	std::string cidr;
	// Candidate type to publish as (defaults to host if unspecified).
	CandidateType asCandidateType = CandidateType::Unknown;
	// Replace or append.
	AddressRewriteMode mode = AddressRewriteMode::Unspecified;
};

// Result of a rewrite lookup.
struct RewriteResult {
	std::vector<std::string> externalIPs; // mapped external IPs
	bool matched = false;                  // did any rule match?
	AddressRewriteMode mode = AddressRewriteMode::Unspecified;
};

// Returns the default rewrite mode for a candidate type (pion convention):
//   Host           -> Replace
//   ServerReflexive -> Append
//   Relay          -> Append
inline AddressRewriteMode defaultRewriteMode(CandidateType t) {
	switch (t) {
	case CandidateType::Host: return AddressRewriteMode::Replace;
	case CandidateType::ServerReflexive:
	case CandidateType::Relayed: return AddressRewriteMode::Append;
	default: return AddressRewriteMode::Replace;
	}
}

// The address rewrite mapper. Holds compiled rules and answers lookups.
class AddressRewriteMapper {
public:
	AddressRewriteMapper() = default;

	// Build the mapper from a list of rules. Returns false (and leaves the
	// mapper empty) if no valid rules were provided.
	bool build(const std::vector<AddressRewriteRule> &rules);

	// True if any rule targets the given candidate type.
	bool hasCandidateType(CandidateType ct) const;

	// True if any rule for the candidate type uses Replace mode.
	bool shouldReplace(CandidateType ct) const;

	// Find external IPs for a local address.
	// localIP: the local IP string (numeric).
	// iface: the interface name (empty if unknown).
	RewriteResult findExternalIPs(CandidateType ct, const std::string &localIP,
	                              const std::string &iface) const;

	bool empty() const { return rulesByType_.empty(); }

private:
	struct CompiledRule {
		AddressRewriteRule rule;
		AddressRewriteMode mode;
		// Parsed external IPs (sorted by family).
		std::vector<std::string> externalIPv4;
		std::vector<std::string> externalIPv6;
		// Catch-all external IPs (when rule.local is empty).
		bool catchAllSet = false;
		// Per-local-IP mapping: local IP string -> external IPs.
		// (Simplified from pion's per-family ipMapping.)
		std::vector<std::pair<std::string, std::vector<std::string>>> localMap;
		// CIDR parsed (empty = no CIDR filter).
		std::string cidr;
		// Whether IPv4/IPv6 are allowed (based on Networks filter — currently all).
		bool allowIPv4 = true;
		bool allowIPv6 = true;
	};

	std::vector<std::pair<CandidateType, std::vector<CompiledRule>>> rulesByType_;

	const std::vector<CompiledRule> *rulesFor(CandidateType ct) const;
};

} // namespace stice::ice

#endif
