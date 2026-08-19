// SPDX-License-Identifier: MPL-2.0
// Author: zlyadvocate
// Version: 0.10.0
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

} // namespace

bool Config::load(const std::string &path) {
	std::ifstream f(path);
	if (!f.is_open()) {
		STICE_LOG_ERROR("stserver: cannot open config file: %s", path.c_str());
		return false;
	}

	std::string userVal, passVal, usersVal;
	std::string line;
	while (std::getline(f, line)) {
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

		if (key == "listen_address") listenAddress = val;
		else if (key == "udp_port") udpPort = static_cast<std::uint16_t>(std::atoi(val.c_str()));
		else if (key == "tcp_port") tcpPort = static_cast<std::uint16_t>(std::atoi(val.c_str()));
		else if (key == "realm") realm = val;
		else if (key == "user") userVal = val;
		else if (key == "password") passVal = val;
		else if (key == "users") usersVal = val;
		else if (key == "max_allocations") maxAllocations = std::atoi(val.c_str());
		else if (key == "allocation_lifetime")
			allocationLifetime = static_cast<std::uint32_t>(std::atoi(val.c_str()));
		else if (key == "relay_port_begin")
			relayPortBegin = static_cast<std::uint16_t>(std::atoi(val.c_str()));
		else if (key == "relay_port_end")
			relayPortEnd = static_cast<std::uint16_t>(std::atoi(val.c_str()));
		else if (key == "log_level") logLevel = val;
		else if (key == "worker_count") workerCount = std::atoi(val.c_str());
		// Unknown keys are ignored (forward-compat).
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
	if (relayPortEnd < relayPortBegin) std::swap(relayPortBegin, relayPortEnd);
	return true;
}
