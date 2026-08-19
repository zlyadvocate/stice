// SPDX-License-Identifier: MPL-2.0
// stserver configuration parser. Reads a simple key=value file into a Config
// struct used by TurnServer.

#ifndef STSERVER_CONFIG_HPP
#define STSERVER_CONFIG_HPP

#include <cstdint>
#include <map>
#include <string>

struct Config {
	std::string listenAddress = "0.0.0.0";
	std::uint16_t udpPort = 3478;
	std::uint16_t tcpPort = 3478;
	std::string realm = "stserver";
	std::map<std::string, std::string> users; // username -> password
	int maxAllocations = 2000;
	std::uint32_t allocationLifetime = 600; // seconds
	std::uint16_t relayPortBegin = 49152;
	std::uint16_t relayPortEnd = 65535;
	std::string logLevel = "info";
	int workerCount = 4; // IO worker threads (TCP data plane)

	// Parse the file at `path`. Returns false on read/open error. Missing or
	// malformed entries keep their defaults. `users = u1:p1,u2:p2` (if
	// present) overrides any `user`/`password` pair.
	bool load(const std::string &path);
};

#endif // STSERVER_CONFIG_HPP
