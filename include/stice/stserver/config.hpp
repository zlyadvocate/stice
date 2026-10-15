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
	// IP advertised in XOR-RELAYED-ADDRESS (coturn "external-ip" equivalent).
	// Empty = derive from listenAddress: a specific listenAddress is advertised
	// verbatim, an any-address bind (0.0.0.0/::/empty) falls back to 127.0.0.1
	// so local loopback interop keeps working. Set this when listening on
	// 0.0.0.0 on a NAT/gateway box so off-host peers can reach relayed ports.
	std::string relayAddress;
	std::uint16_t udpPort = 3478;
	std::uint16_t tcpPort = 3478;
	std::string realm = "stserver";
	std::map<std::string, std::string> users; // username -> password
	int maxAllocations = 2000;
	std::uint32_t allocationLifetime = 600; // seconds
	// TURN/STUN long-term-credential nonce lifetime (seconds, RFC 5389 §15.4).
	// Exposed so tests can force nonce rotation quickly: the rotation window is
	// where the "each stale request mints a new nonce" stampede used to kill
	// every client at once, and reaching it otherwise takes 30 real minutes.
	std::uint32_t nonceLifetimeSec = 1800;
	// Default relay range deliberately avoids the Windows ephemeral port
	// range (49152-65535): binding relay sockets there collides with
	// outbound connections' auto-assigned source ports and made Allocate
	// fail with InsufficientCapacity.
	std::uint16_t relayPortBegin = 40000;
	std::uint16_t relayPortEnd = 48999;
	std::string logLevel = "info";
	int workerCount = 4; // IO worker threads (TCP data plane)

	// Parse the file at `path`. Returns false on read/open error or on an
	// invalid (out-of-range) numeric value — bad config fails loudly instead
	// of silently running with defaults. Keys are case- and
	// separator-insensitive: relay_port_begin, relayPortBegin and
	// relay-port-begin are all accepted. Missing entries keep their
	// defaults. `users = u1:p1,u2:p2` (if present) overrides any
	// `user`/`password` pair.
	bool load(const std::string &path);
};

#endif // STSERVER_CONFIG_HPP
