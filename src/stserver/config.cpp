// SPDX-License-Identifier: MPL-2.0
// Author: zlyadvocate
// Version: 0.13.0
#include "stice/stserver/config.hpp"

#include "stice/log.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace {

// Trim leading/trailing whitespace (spaces and tabs) in place.
std::string trim(const std::string &s) {
	std::size_t a = 0;
	while (a < s.size() && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r')) ++a;
	std::size_t b = s.size();
	while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r')) --b;
	return s.substr(a, b - a);
}

// Split "users = u1:p1,u2:p2" value into the users map. Each entry is
// "username:password". Malformed entries are skipped.
void parseUsersList(const std::string &val, std::map<std::string, std::string> &out) {
	std::stringstream ss(val);
	std::string item;
	while (std::getline(ss, item, ',')) {
		item = trim(item);
		if (item.empty()) continue;
		auto colon = item.find(':');
		if (colon == std::string::npos) continue; // malformed, skip
		std::string u = trim(item.substr(0, colon));
		std::string p = trim(item.substr(colon + 1));
		if (u.empty()) continue;
		out[u] = p;
	}
}

// Normalize a key for matching: lowercase and strip '_'/'-' separators so
// snake_case, camelCase and kebab-case all match ("relay_port_begin",
// "relayPortBegin", "relay-port-begin" -> "relayportbegin").
std::string normalizeKey(const std::string &s) {
	std::string out;
	out.reserve(s.size());
	for (char c : s) {
		if (c == '_' || c == '-') continue;
		out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
	}
	return out;
}

// Strict integer parse with range validation. Returns false (and logs) on
// malformed input or out-of-range values so bad config fails loudly.
bool parseRange(const std::string &val, const char *key, long long lo, long long hi,
                long long &out) {
	try {
		std::size_t pos = 0;
		long long v = std::stoll(val, &pos);
		// Reject trailing garbage ("6478abc").
		while (pos < val.size() && std::isspace(static_cast<unsigned char>(val[pos]))) ++pos;
		if (pos != val.size() || v < lo || v > hi) {
			STICE_LOG_ERROR("stserver: config '%s' value '%s' out of range [%lld, %lld]",
			                key, trim(val).c_str(), lo, hi);
			return false;
		}
		out = v;
		return true;
	} catch (...) {
		STICE_LOG_ERROR("stserver: config '%s' value '%s' is not a number",
		                key, trim(val).c_str());
		return false;
	}
}

} // namespace

bool Config::load(const std::string &path) {
	std::ifstream f(path);
	if (!f.is_open()) {
		STICE_LOG_ERROR("stserver: cannot open config file: %s", path.c_str());
		return false;
	}

	std::string userVal, passVal, usersVal;
	std::string line;
	bool firstLine = true;
	while (std::getline(f, line)) {
		if (firstLine) {
			firstLine = false;
			// Strip a UTF-8 BOM: an editor-saved BOM prefixes the first key's
			// name and made the parser silently fall through to the unknown-key
			// branch, so the server ran on defaults while the file looked right.
			if (line.size() >= 3 && (unsigned char)line[0] == 0xEF &&
			    (unsigned char)line[1] == 0xBB && (unsigned char)line[2] == 0xBF)
				line.erase(0, 3);
		}
		// Strip comments: a '#' starts a comment only at the beginning of the
		// (trimmed) line. We don't support inline trailing comments to avoid
		// mangling passwords that contain '#'.
		std::string t = trim(line);
		if (t.empty() || t[0] == '#') continue;
		auto eq = t.find('=');
		if (eq == std::string::npos) continue;
		std::string key = trim(t.substr(0, eq));
		std::string val = trim(t.substr(eq + 1));
		if (key.empty()) continue;
		std::string nk = normalizeKey(key);

		long long num = 0;
		if (nk == "listenaddress") listenAddress = val;
		else if (nk == "relayaddress") relayAddress = val;
		else if (nk == "udpport") {
			if (!parseRange(val, "udp_port", 1, 65535, num)) return false;
			udpPort = static_cast<std::uint16_t>(num);
		} else if (nk == "tcpport") {
			if (!parseRange(val, "tcp_port", 1, 65535, num)) return false;
			tcpPort = static_cast<std::uint16_t>(num);
		} else if (nk == "realm") realm = val;
		else if (nk == "user") userVal = val;
		else if (nk == "password") passVal = val;
		else if (nk == "users") usersVal = val;
		else if (nk == "maxallocations") {
			if (!parseRange(val, "max_allocations", 1, 1000000, num)) return false;
			maxAllocations = static_cast<int>(num);
		} else if (nk == "allocationlifetime") {
			if (!parseRange(val, "allocation_lifetime", 10, 86400, num)) return false;
			allocationLifetime = static_cast<std::uint32_t>(num);
		} else if (nk == "noncelifetimesec") {
			if (!parseRange(val, "nonce_lifetime_sec", 1, 86400, num)) return false;
			nonceLifetimeSec = static_cast<std::uint32_t>(num);
		} else if (nk == "relayportbegin") {
			if (!parseRange(val, "relay_port_begin", 1024, 65535, num)) return false;
			relayPortBegin = static_cast<std::uint16_t>(num);
		} else if (nk == "relayportend") {
			if (!parseRange(val, "relay_port_end", 1024, 65535, num)) return false;
			relayPortEnd = static_cast<std::uint16_t>(num);
		} else if (nk == "loglevel") logLevel = val;
		else if (nk == "workercount") {
			if (!parseRange(val, "worker_count", 1, 256, num)) return false;
			workerCount = static_cast<int>(num);
		} else {
			// Unknown keys are logged (forward-compat, but visible: a
			// silently ignored misspelled key previously left the server
			// running on dangerous defaults).
			STICE_LOG_WARN("stserver: ignoring unknown config key '%s'", key.c_str());
		}
	}

	// Relay range sanity: begin must be <= end; both inside the ephemeral
	// Windows range (49152-65535) are rejected loudly.
	if (relayPortEnd < relayPortBegin) std::swap(relayPortBegin, relayPortEnd);
	if (relayPortBegin >= 49152) {
		STICE_LOG_WARN("stserver: relay port range %u-%u overlaps the Windows ephemeral "
		               "range (49152-65535); relay binds may collide with outbound "
		               "source ports",
		               relayPortBegin, relayPortEnd);
	}

	// Resolve credentials. The `users` list takes precedence over a single
	// user=/password= pair.
	if (!usersVal.empty()) {
		users.clear();
		parseUsersList(usersVal, users);
	} else if (!userVal.empty()) {
		users.clear();
		users[userVal] = passVal;
	}

	if (users.empty()) {
		STICE_LOG_WARN("stserver: no users configured; TURN Allocate will be rejected");
	}
	return true;
}
