/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
#include "stice/ice/candidate.hpp"

#include "stice/crypto.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstdio>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

namespace stice::ice {

// Runtime-configurable TCP priority offset (P2-1). Defaults to TcpPenalty.
std::atomic<std::uint32_t> g_tcpPriorityOffset{TcpPenalty};

const char *typeString(CandidateType t) {
	switch (t) {
	case CandidateType::Host: return "host";
	case CandidateType::ServerReflexive: return "srflx";
	case CandidateType::PeerReflexive: return "prflx";
	case CandidateType::Relayed: return "relay";
	default: return "unknown";
	}
}

const char *transportString(CandidateTransport t) {
	switch (t) {
	case CandidateTransport::UDP: return "UDP";
	case CandidateTransport::TCPActive: return "TCP";
	case CandidateTransport::TCPPassive: return "TCP";
	case CandidateTransport::TCPSimultaneousOpen: return "TCP";
	default: return "UDP";
	}
}

CandidateType typeFromString(const std::string &s) {
	if (s == "host") return CandidateType::Host;
	if (s == "srflx") return CandidateType::ServerReflexive;
	if (s == "prflx") return CandidateType::PeerReflexive;
	if (s == "relay") return CandidateType::Relayed;
	return CandidateType::Unknown;
}

std::uint32_t Candidate::computePriority(CandidateType type, int family, int component,
                                        int index, CandidateTransport transport) {
	// RFC 8445 §5.1.2.1 + RFC 6544 §4.2 (TCP direction preference).
	// priority = (1<<24) * typePref + (1<<8) * localPref + (1<<0) * (256 - component)
	// localPref (TCP) = (2^13) * directionPref + otherPref
	std::uint32_t typePref = 0;
	switch (type) {
	case CandidateType::Host: typePref = PrefHost; break;
	case CandidateType::PeerReflexive: typePref = PrefPeerReflexive; break;
	case CandidateType::ServerReflexive: typePref = PrefServerReflexive; break;
	case CandidateType::Relayed: typePref = PrefRelayed; break;
	default: break;
	}
	// Prefer UDP over TCP (pion: typePref -= defaultTCPPriorityOffset for TCP).
	// The offset is runtime-configurable (P2-1).
	if (transport != CandidateTransport::UDP) {
		std::uint32_t offset = currentTcpPriorityOffset();
		if (typePref >= offset) typePref -= offset;
		else typePref = 0;
	}

	// Local preference. For UDP this is just the IP-family preference.
	// For TCP, RFC 6544 §4.2: localPref = (2^13) * directionPref + otherPref
	std::uint32_t localPref = 0;
	if (transport != CandidateTransport::UDP) {
		// Direction preference differs by candidate type per RFC 6544 §4.2:
		//   host/relay:    active=6, passive=4, so=2
		//   srflx/prflx:   so=6, active=4, passive=2
		std::uint32_t directionPref = 0;
		switch (type) {
		case CandidateType::Host:
		case CandidateType::Relayed:
			switch (transport) {
			case CandidateTransport::TCPActive: directionPref = 6; break;
			case CandidateTransport::TCPPassive: directionPref = 4; break;
			case CandidateTransport::TCPSimultaneousOpen: directionPref = 2; break;
			default: break;
			}
			break;
		case CandidateType::ServerReflexive:
		case CandidateType::PeerReflexive:
			switch (transport) {
			case CandidateTransport::TCPSimultaneousOpen: directionPref = 6; break;
			case CandidateTransport::TCPActive: directionPref = 4; break;
			case CandidateTransport::TCPPassive: directionPref = 2; break;
			default: break;
			}
			break;
		default: break;
		}
		localPref = (directionPref << 13);
		// otherPref: 8191 for IPv4 single-homed (max), 8191 for IPv6 too.
		switch (family) {
		case AF_INET6: localPref += 8191; break;
		case AF_INET: localPref += 8191; break;
		default: break;
		}
		// Subtract index to keep pairs unique on multi-homed hosts.
		std::uint32_t clampedIdx = static_cast<std::uint32_t>(index > 4095 ? 4095 : (index < 0 ? 0 : index));
		if (localPref >= clampedIdx) localPref -= clampedIdx;
	} else {
		// UDP: pion-ice uses a fixed defaultLocalPreference=65535 for all
		// families (RFC 8445 §5.1.2.1: "should be 65535 for single-homed").
		// Subtract index to keep pairs unique on multi-homed hosts.
		localPref = 65535;
		std::uint32_t clampedIdx = static_cast<std::uint32_t>(index > 4095 ? 4095 : (index < 0 ? 0 : index));
		if (localPref >= clampedIdx) localPref -= clampedIdx;
	}

	std::uint32_t p = (typePref << 24) | (localPref << 8);
	int comp = component < 1 ? 1 : (component > 256 ? 256 : component);
	p += static_cast<std::uint32_t>(256 - comp);
	return p;
}

std::string Candidate::computeFoundation(CandidateType type, const std::string &addr,
                                         CandidateTransport transport) {
	std::string input = std::string(typeString(type)) + addr + std::string(transportString(transport));
	auto crc = crypto::crc32(reinterpret_cast<const unsigned char *>(input.data()), input.size());
	char buf[16];
	std::snprintf(buf, sizeof(buf), "%u", crc);
	return buf;
}

std::string Candidate::toSdp() const {
	// a=candidate:<foundation> <component> <transport> <priority> <host> <port> typ <type>[ tcptype active|passive|so][ raddr .. rport ..]
	char buf[512];
	std::string suffix;
	// TCP candidates MUST include tcptype (RFC 6544 §4.5).
	if (transport == CandidateTransport::TCPActive) suffix += " tcptype active";
	else if (transport == CandidateTransport::TCPPassive) suffix += " tcptype passive";
	else if (transport == CandidateTransport::TCPSimultaneousOpen) suffix += " tcptype so";
	// libjuice appends "raddr 0.0.0.0 rport 0" for srflx/relay for Firefox compatibility.
	if (type == CandidateType::ServerReflexive || type == CandidateType::Relayed) {
		suffix += " raddr 0.0.0.0 rport 0";
	}
	std::snprintf(buf, sizeof(buf), "a=candidate:%s %d %s %u %s %s typ %s%s",
	              foundation.c_str(), component, transportString(transport), priority,
	              hostname.c_str(), service.c_str(), typeString(type), suffix.c_str());
	return buf;
}

bool Candidate::parse(const std::string &line, Candidate &out) {
	// Strip "a=" prefix and "candidate:" prefix.
	std::string s = line;
	if (s.rfind("a=", 0) == 0) s = s.substr(2);
	if (s.rfind("candidate:", 0) == 0) s = s.substr(10);

	// foundation component transport priority host port typ type [extra...]
	char foundation[64] = {0};
	char transportStr[16] = {0};
	char typeStr[16] = {0};
	char host[256] = {0};
	char port[16] = {0};
	unsigned int priority = 0;
	int component = 0;
	// Try the 7-field UDP form first.
	int n = std::sscanf(s.c_str(), "%63s %d %15s %u %255s %15s typ %15s",
	                    foundation, &component, transportStr, &priority, host, port, typeStr);
	if (n != 7) return false;

	out = Candidate();
	out.foundation = foundation;
	out.component = component;
	out.priority = priority;
	out.hostname = host;
	out.service = port;
	out.type = typeFromString(typeStr);
	if (out.type == CandidateType::Unknown) return false;
	// Transport. RFC 8839: transport tokens are case-insensitive
	// ("udp", "UDP", "tcp", "TCP" are all valid).
	std::string transportLower = transportStr;
	std::transform(transportLower.begin(), transportLower.end(), transportLower.begin(),
	               [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
	if (transportLower == "tcp") {
		// Look for "tcptype active|passive|so" (case-insensitive per RFC 6544).
		std::size_t pos = s.find("tcptype ");
		if (pos != std::string::npos) {
			std::string t = s.substr(pos + 8);
			std::size_t sp = t.find(' ');
			if (sp != std::string::npos) t = t.substr(0, sp);
			std::transform(t.begin(), t.end(), t.begin(),
			               [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
			if (t == "active") out.transport = CandidateTransport::TCPActive;
			else if (t == "passive") out.transport = CandidateTransport::TCPPassive;
			else if (t == "so") out.transport = CandidateTransport::TCPSimultaneousOpen;
		}
	} else {
		out.transport = CandidateTransport::UDP;
	}

	// Resolve hostname:port into a sockaddr so the agent can send connectivity
	// checks directly. Without this, remote candidates parsed from SDP would
	// have empty resolved addresses and STUN checks would go nowhere.
	{
		std::uint16_t portNum = static_cast<std::uint16_t>(std::atoi(port));
		int st = (out.transport == CandidateTransport::UDP) ? SOCK_DGRAM : SOCK_STREAM;
		if (net::parseAddr(host, portNum, out.resolved.addr, out.resolved.len)) {
			out.resolved.socktype = st;
		} else {
			// Non-numeric hostname: resolve via DNS.
			auto records = net::resolve(host, port, st);
			if (!records.empty()) out.resolved = records[0];
			// If resolution fails, leave resolved empty; the pair will fail
			// its connectivity check rather than crash.
		}
	}
	return true;
}

} // namespace stice::ice
