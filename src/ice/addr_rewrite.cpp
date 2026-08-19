/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
#include "stice/ice/addr_rewrite.hpp"

#include "stice/log.hpp"

#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace stice::ice {

namespace {

// Parse an IP string. Returns true and sets isIPv4 on success.
bool validateIPString(const std::string &s, bool &isIPv4) {
	if (s.empty()) return false;
	// Try IPv4 first.
	struct in_addr addr4;
	if (inet_pton(AF_INET, s.c_str(), &addr4) == 1) {
		isIPv4 = true;
		return true;
	}
	struct in6_addr addr6;
	if (inet_pton(AF_INET6, s.c_str(), &addr6) == 1) {
		isIPv4 = false;
		return true;
	}
	return false;
}

// Check if a CIDR contains a local IP. Simplified: supports IPv4 CIDR only.
// Returns true if cidr is empty (no filter).
bool cidrContains(const std::string &cidr, const std::string &localIP) {
	if (cidr.empty()) return true;
	// Parse "ip/prefix".
	auto slash = cidr.find('/');
	if (slash == std::string::npos) return false;
	std::string cidrIP = cidr.substr(0, slash);
	int prefix = std::atoi(cidr.substr(slash + 1).c_str());
	if (prefix < 0 || prefix > 128) return false;

	bool cidrIsIPv4 = false;
	if (!validateIPString(cidrIP, cidrIsIPv4)) return false;

	bool localIsIPv4 = false;
	if (!validateIPString(localIP, localIsIPv4)) return false;

	if (cidrIsIPv4 != localIsIPv4) return false;

	if (cidrIsIPv4) {
		struct in_addr net, addr;
		if (inet_pton(AF_INET, cidrIP.c_str(), &net) != 1) return false;
		if (inet_pton(AF_INET, localIP.c_str(), &addr) != 1) return false;
		if (prefix > 32) prefix = 32;
		std::uint32_t mask = prefix == 0 ? 0 : htonl(~((1u << (32 - prefix)) - 1));
		return (net.s_addr & mask) == (addr.s_addr & mask);
	} else {
		struct in6_addr net, addr;
		if (inet_pton(AF_INET6, cidrIP.c_str(), &net) != 1) return false;
		if (inet_pton(AF_INET6, localIP.c_str(), &addr) != 1) return false;
		int fullBytes = prefix / 8;
		int remainder = prefix % 8;
		if (std::memcmp(&net, &addr, fullBytes) != 0) return false;
		if (remainder > 0 && fullBytes < 16) {
			std::uint8_t mask = static_cast<std::uint8_t>(~((1 << (8 - remainder)) - 1));
			if ((net.s6_addr[fullBytes] & mask) != (addr.s6_addr[fullBytes] & mask))
				return false;
		}
		return true;
	}
}

// Trim whitespace.
std::string trim(const std::string &s) {
	auto begin = s.find_first_not_of(" \t\r\n");
	if (begin == std::string::npos) return "";
	auto end = s.find_last_not_of(" \t\r\n");
	return s.substr(begin, end - begin + 1);
}

} // namespace

const std::vector<AddressRewriteMapper::CompiledRule> *
AddressRewriteMapper::rulesFor(CandidateType ct) const {
	for (const auto &entry : rulesByType_) {
		if (entry.first == ct) return &entry.second;
	}
	return nullptr;
}

bool AddressRewriteMapper::build(const std::vector<AddressRewriteRule> &rules) {
	rulesByType_.clear();
	if (rules.empty()) return false;

	for (const auto &rule : rules) {
		CandidateType ct = rule.asCandidateType;
		if (ct == CandidateType::Unknown) ct = CandidateType::Host;
		if (ct == CandidateType::PeerReflexive) {
			STICE_LOG_WARN("AddressRewrite: PeerReflexive candidate type not supported");
			continue;
		}

		AddressRewriteMode mode = rule.mode;
		if (mode == AddressRewriteMode::Unspecified) {
			mode = defaultRewriteMode(ct);
		}

		CompiledRule cr;
		cr.rule = rule;
		cr.mode = mode;
		cr.cidr = rule.cidr;

		std::string trimmedLocal = trim(rule.local);
		bool hasLocalAddr = !trimmedLocal.empty();
		bool localIsIPv4 = false;
		if (hasLocalAddr) {
			if (!validateIPString(trimmedLocal, localIsIPv4)) {
				STICE_LOG_WARN("AddressRewrite: invalid local IP %s", trimmedLocal.c_str());
				continue;
			}
		}

		bool added = false;
		for (const auto &raw : rule.external) {
			std::string extIP = trim(raw);
			if (extIP.empty()) continue;
			bool isExtIPv4 = false;
			if (!validateIPString(extIP, isExtIPv4)) {
				STICE_LOG_WARN("AddressRewrite: invalid external IP %s", extIP.c_str());
				continue;
			}
			// Determine target family.
			bool targetIPv4 = isExtIPv4;
			if (hasLocalAddr) targetIPv4 = localIsIPv4;
			else if (!cr.cidr.empty()) {
				bool cidrIsIPv4 = false;
				if (validateIPString(cr.cidr.substr(0, cr.cidr.find('/')), cidrIsIPv4))
					targetIPv4 = cidrIsIPv4;
			}
			if (targetIPv4 != isExtIPv4) continue;

			if (hasLocalAddr) {
				// Per-local-IP mapping.
				bool found = false;
				for (auto &kv : cr.localMap) {
					if (kv.first == trimmedLocal) {
						kv.second.push_back(extIP);
						found = true;
						break;
					}
				}
				if (!found) {
					cr.localMap.push_back({trimmedLocal, {extIP}});
				}
			} else {
				// Catch-all.
				if (targetIPv4) cr.externalIPv4.push_back(extIP);
				else cr.externalIPv6.push_back(extIP);
				cr.catchAllSet = true;
			}
			added = true;
		}

		if (!added) {
			// Empty external list: mark as valid but with no IPs.
			// For replace mode this means "drop the candidate".
			// For append mode this is a no-op.
			if (hasLocalAddr) {
				cr.localMap.push_back({trimmedLocal, {}});
			} else {
				cr.catchAllSet = true;
			}
		}

		// Find or create the rules vector for this candidate type.
		bool found = false;
		for (auto &entry : rulesByType_) {
			if (entry.first == ct) {
				entry.second.push_back(std::move(cr));
				found = true;
				break;
			}
		}
		if (!found) {
			rulesByType_.push_back({ct, {std::move(cr)}});
		}
	}

	return !rulesByType_.empty();
}

bool AddressRewriteMapper::hasCandidateType(CandidateType ct) const {
	const auto *rules = rulesFor(ct);
	if (!rules) return false;
	return !rules->empty();
}

bool AddressRewriteMapper::shouldReplace(CandidateType ct) const {
	const auto *rules = rulesFor(ct);
	if (!rules) return false;
	for (const auto &r : *rules) {
		if (r.mode == AddressRewriteMode::Replace) return true;
	}
	return false;
}

RewriteResult AddressRewriteMapper::findExternalIPs(CandidateType ct,
                                                     const std::string &localIP,
                                                     const std::string &iface) const {
	RewriteResult result;
	const auto *rules = rulesFor(ct);
	if (!rules) return result;

	bool localIsIPv4 = false;
	if (!validateIPString(localIP, localIsIPv4)) {
		return result;
	}

	// Track best catch-all (by specificity: iface+cidr > iface > cidr > none).
	std::vector<std::string> catchAll;
	AddressRewriteMode catchAllMode = AddressRewriteMode::Unspecified;
	bool hasCatchAll = false;
	int bestSpec = -1;

	for (const auto &rule : *rules) {
		// Interface filter.
		if (!rule.rule.iface.empty() && rule.rule.iface != iface) continue;
		// CIDR filter.
		if (!rule.cidr.empty() && !cidrContains(rule.cidr, localIP)) continue;

		// Check for explicit per-local-IP mapping first.
		bool explicitMatch = false;
		for (const auto &kv : rule.localMap) {
			if (kv.first == localIP) {
				result.externalIPs = kv.second;
				result.matched = true;
				result.mode = rule.mode;
				explicitMatch = true;
				break;
			}
		}
		if (explicitMatch) return result;

		// Check catch-all.
		if (rule.catchAllSet) {
			// Compute specificity.
			int spec = 0;
			if (!rule.rule.iface.empty()) {
				spec += 2;
				if (!rule.cidr.empty()) spec += 1;
			} else if (!rule.cidr.empty()) {
				spec += 1;
			}
			if (!hasCatchAll || spec > bestSpec) {
				catchAll = localIsIPv4 ? rule.externalIPv4 : rule.externalIPv6;
				catchAllMode = rule.mode;
				hasCatchAll = true;
				bestSpec = spec;
			}
		}
	}

	if (hasCatchAll) {
		result.externalIPs = catchAll;
		result.matched = true;
		result.mode = catchAllMode;
	}

	return result;
}

} // namespace stice::ice
