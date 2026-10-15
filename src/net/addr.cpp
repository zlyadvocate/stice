/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
#include "stice/net/addr.hpp"

#include "stice/log.hpp"

#include <cstdio>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using ssize_t = int;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace stice::net {

socklen_t addrLen(const struct sockaddr *sa) {
	switch (sa->sa_family) {
	case AF_INET: return sizeof(sockaddr_in);
	case AF_INET6: return sizeof(sockaddr_in6);
	default: return 0;
	}
}

uint16_t addrPort(const struct sockaddr *sa) {
	if (!sa) return 0;
	if (sa->sa_family == AF_INET)
		return ntohs(reinterpret_cast<const sockaddr_in *>(sa)->sin_port);
	if (sa->sa_family == AF_INET6)
		return ntohs(reinterpret_cast<const sockaddr_in6 *>(sa)->sin6_port);
	return 0;
}

void addrSetPort(struct sockaddr *sa, uint16_t port) {
	if (!sa) return;
	if (sa->sa_family == AF_INET)
		reinterpret_cast<sockaddr_in *>(sa)->sin_port = htons(port);
	else if (sa->sa_family == AF_INET6)
		reinterpret_cast<sockaddr_in6 *>(sa)->sin6_port = htons(port);
}

bool addrIsAny(const struct sockaddr *sa) {
	if (!sa) return true;
	if (sa->sa_family == AF_INET)
		return reinterpret_cast<const sockaddr_in *>(sa)->sin_addr.s_addr == INADDR_ANY;
	if (sa->sa_family == AF_INET6)
		return IN6_IS_ADDR_UNSPECIFIED(&reinterpret_cast<const sockaddr_in6 *>(sa)->sin6_addr);
	return false;
}

bool addrIsLocal(const struct sockaddr *sa) {
	if (!sa) return false;
	if (sa->sa_family == AF_INET) {
		auto *in = reinterpret_cast<const sockaddr_in *>(sa);
		uint32_t a = ntohl(in->sin_addr.s_addr);
		// loopback 127.0.0.0/8
		if ((a & 0xFF000000u) == 0x7F000000u) return true;
		// link-local 169.254.0.0/16
		if ((a & 0xFFFF0000u) == 0xA9FE0000u) return true;
		return false;
	}
	if (sa->sa_family == AF_INET6) {
		auto *in6 = reinterpret_cast<const sockaddr_in6 *>(sa);
		if (IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr)) return true;
		if (IN6_IS_ADDR_LINKLOCAL(&in6->sin6_addr)) return true;
		// Dual-stack sockets enumerate IPv4 addresses as v4-mapped
		// (::ffff:a.b.c.d). IPv6 link-local above does NOT match
		// ::ffff:169.254.x, so those leaked through the enumeration
		// filter and reappeared as plain IPv4 host candidates after
		// unmapping. Unwrap here so all v4-mapped addresses follow the
		// IPv4 rules.
		if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
			in_addr v4;
			std::memcpy(&v4, &in6->sin6_addr.s6_addr[12], sizeof(v4));
			uint32_t a = ntohl(v4.s_addr);
			if ((a & 0xFF000000u) == 0x7F000000u) return true;
			if ((a & 0xFFFF0000u) == 0xA9FE0000u) return true;
		}
		return false;
	}
	return false;
}

bool addrIsLinkLocal(const struct sockaddr *sa) {
	if (!sa) return false;
	if (sa->sa_family == AF_INET) {
		auto *in = reinterpret_cast<const sockaddr_in *>(sa);
		uint32_t a = ntohl(in->sin_addr.s_addr);
		// 169.254.0.0/16 (IPv4 link-local / APIPA)
		return (a & 0xFFFF0000u) == 0xA9FE0000u;
	}
	if (sa->sa_family == AF_INET6) {
		auto *in6 = reinterpret_cast<const sockaddr_in6 *>(sa);
		// fe80::/10 (IPv6 link-local)
		if (IN6_IS_ADDR_LINKLOCAL(&in6->sin6_addr)) return true;
		// v4-mapped ::ffff:169.254.x (dual-stack enumeration) follows the
		// IPv4 rule — see addrIsLocal.
		if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
			in_addr v4;
			std::memcpy(&v4, &in6->sin6_addr.s6_addr[12], sizeof(v4));
			uint32_t a = ntohl(v4.s_addr);
			return (a & 0xFFFF0000u) == 0xA9FE0000u;
		}
		return false;
	}
	return false;
}

bool addrUnmapInet6V4Mapped(struct sockaddr *sa, socklen_t &len) {
	if (!sa || sa->sa_family != AF_INET6) return false;
	auto *in6 = reinterpret_cast<sockaddr_in6 *>(sa);
	if (!IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) return false;
	sockaddr_in in4{};
	in4.sin_family = AF_INET;
	in4.sin_port = in6->sin6_port;
	in4.sin_addr.s_addr = in6->sin6_addr.s6_addr[12] | (uint32_t{in6->sin6_addr.s6_addr[13]} << 8) |
	                      (uint32_t{in6->sin6_addr.s6_addr[14]} << 16) | (uint32_t{in6->sin6_addr.s6_addr[15]} << 24);
	std::memcpy(sa, &in4, sizeof(in4));
	len = sizeof(in4);
	return true;
}

bool addrMapInet6V4Mapped(struct sockaddr_storage &ss, socklen_t &len) {
	// Convert an IPv4 sockaddr_in in place to an IPv4-mapped IPv6 sockaddr_in6
	// (::ffff:a.b.c.d). Needed when sending from a dual-stack AF_INET6 socket
	// to an IPv4 destination: sendto to a sockaddr_in from an AF_INET6 socket
	// fails with WSAEAFNOSUPPORT on Windows (and EAFNOSUPPORT on Linux).
	auto *sa = reinterpret_cast<struct sockaddr *>(&ss);
	if (sa->sa_family != AF_INET) return false;
	auto *in4 = reinterpret_cast<sockaddr_in *>(sa);
	sockaddr_in6 in6{};
	in6.sin6_family = AF_INET6;
	in6.sin6_port = in4->sin_port;
	in6.sin6_addr.s6_addr[10] = 0xFF;
	in6.sin6_addr.s6_addr[11] = 0xFF;
	std::memcpy(&in6.sin6_addr.s6_addr[12], &in4->sin_addr.s_addr, 4);
	std::memcpy(&ss, &in6, sizeof(in6));
	len = sizeof(in6);
	return true;
}

bool addrEqual(const struct sockaddr *a, const struct sockaddr *b, bool comparePorts) {
	if (!a || !b) return a == b;
	// Normalize v4-mapped IPv6 (::ffff:a.b.c.d) to plain IPv4 before comparing:
	// both spell the SAME peer, and a dual-stack socket hands out the mapped
	// form. Every current caller unmaps first (addrUnmapInet6V4Mapped), so this
	// is defence in depth - an unmapped address reaching a comparison must not
	// look like a different peer. AddrRecord::hash() applies the identical
	// normalization so "equal" and "same hash" stay consistent for containers.
	unsigned char na[16] = {0}, nb[16] = {0};
	int fa = 0, fb = 0;
	uint16_t pa = 0, pb = 0;
	auto normalize = [](const struct sockaddr *sa, unsigned char *out, int &fam,
	                    uint16_t &port) -> bool {
		if (sa->sa_family == AF_INET) {
			auto *in = reinterpret_cast<const sockaddr_in *>(sa);
			fam = AF_INET;
			std::memcpy(out, &in->sin_addr, 4);
			port = in->sin_port;
			return true;
		}
		if (sa->sa_family == AF_INET6) {
			auto *in6 = reinterpret_cast<const sockaddr_in6 *>(sa);
			fam = AF_INET6;
			std::memcpy(out, &in6->sin6_addr, 16);
			port = in6->sin6_port;
			if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
				fam = AF_INET;
				std::memcpy(out, &in6->sin6_addr.s6_addr[12], 4);
			}
			return true;
		}
		return false; // unsupported family: not equal to anything
	};
	if (!normalize(a, na, fa, pa) || !normalize(b, nb, fb, pb)) return false;
	if (fa != fb) return false;
	const std::size_t n = (fa == AF_INET) ? 4u : 16u;
	if (std::memcmp(na, nb, n) != 0) return false;
	if (comparePorts && pa != pb) return false;
	return true;
}

std::string addrToString(const struct sockaddr *sa) {
	if (!sa) return {};
	char node[64] = {0};
	char serv[8] = {0};
	if (getnameinfo(sa, addrLen(sa), node, sizeof(node), serv, sizeof(serv),
	                NI_NUMERICHOST | NI_NUMERICSERV | NI_DGRAM) != 0) {
		// getnameinfo rejects some legal inputs it cannot render - a link-local
		// IPv6 address without a scope id is the common case on Windows. Falling
		// back to inet_ntop keeps the address visible instead of collapsing the
		// whole string to empty (which made every log line about that peer blank).
		if (sa->sa_family == AF_INET) {
			auto *in = reinterpret_cast<const sockaddr_in *>(sa);
			if (!inet_ntop(AF_INET, &in->sin_addr, node, sizeof(node))) return {};
			std::snprintf(serv, sizeof(serv), "%u", ntohs(in->sin_port));
		} else if (sa->sa_family == AF_INET6) {
			auto *in6 = reinterpret_cast<const sockaddr_in6 *>(sa);
			if (!inet_ntop(AF_INET6, &in6->sin6_addr, node, sizeof(node))) return {};
			std::snprintf(serv, sizeof(serv), "%u", ntohs(in6->sin6_port));
		} else {
			return {};
		}
	}
	std::string s;
	// An IPv6 literal is bracketed when a port is appended (RFC 5952 §6 /
	// RFC 3986 §3.2.2): "2001:db8::1:3478" is ambiguous because the address
	// itself contains colons; "[2001:db8::1]:3478" is not. A link-local scope id
	// follows the RFC 6874 form ("[fe80::1%3]:5353"). This is a diagnostic /
	// display helper only - SDP carries the bare host and the port separately.
	if (sa->sa_family == AF_INET6) {
		s = "[";
		s += node;
		s += "]";
	} else {
		s = node;
	}
	s += ":";
	s += serv;
	return s;
}

bool AddrRecord::isEqual(const AddrRecord &o, bool comparePorts) const {
	if (socktype != o.socktype) return false;
	return addrEqual(reinterpret_cast<const sockaddr *>(&addr), reinterpret_cast<const sockaddr *>(&o.addr),
	                 comparePorts);
}

std::string AddrRecord::toString() const {
	return addrToString(reinterpret_cast<const sockaddr *>(&addr));
}

uint64_t AddrRecord::hash(bool withPort) const {
	// djb2 variant. v4-mapped IPv6 is hashed as the plain IPv4 address it embeds,
	// matching addrEqual()'s normalization - equal keys must hash equally, or a
	// container lookup could miss the entry it just compared as equal. Hash
	// values for every non-mapped address are unchanged.
	uint64_t h = 5381;
	auto *sa = reinterpret_cast<const sockaddr *>(&addr);
	int family = sa->sa_family;
	unsigned char bytes[16] = {0};
	std::size_t nbytes = 0;
	uint16_t port = 0;
	if (family == AF_INET) {
		auto *in = reinterpret_cast<const sockaddr_in *>(sa);
		std::memcpy(bytes, &in->sin_addr, 4);
		nbytes = 4;
		port = in->sin_port;
	} else if (family == AF_INET6) {
		auto *in6 = reinterpret_cast<const sockaddr_in6 *>(sa);
		port = in6->sin6_port;
		if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
			family = AF_INET;
			std::memcpy(bytes, &in6->sin6_addr.s6_addr[12], 4);
			nbytes = 4;
		} else {
			std::memcpy(bytes, &in6->sin6_addr, 16);
			nbytes = 16;
		}
	}
	h = ((h << 5) + h) + static_cast<uint64_t>(family);
	h = ((h << 5) + h) + static_cast<uint64_t>(socktype);
	for (std::size_t i = 0; i < nbytes; ++i) h = ((h << 5) + h) + bytes[i];
	if (withPort) h = ((h << 5) + h) + ntohs(port);
	return h;
}

std::vector<AddrRecord> resolve(const std::string &hostname, const std::string &service, int socktype) {
	std::vector<AddrRecord> out;
	struct addrinfo hints{};
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = socktype;
	hints.ai_flags = AI_ADDRCONFIG;
	struct addrinfo *res = nullptr;
	if (getaddrinfo(hostname.c_str(), service.c_str(), &hints, &res) != 0 || !res)
		return out;
	for (auto *p = res; p; p = p->ai_next) {
		AddrRecord r;
		std::memcpy(&r.addr, p->ai_addr, p->ai_addrlen);
		r.len = static_cast<socklen_t>(p->ai_addrlen);
		r.socktype = p->ai_socktype;
		// Canonicalize v4-mapped IPv6 to plain IPv4.
		addrUnmapInet6V4Mapped(reinterpret_cast<struct sockaddr *>(&r.addr), r.len);
		out.push_back(std::move(r));
	}
	freeaddrinfo(res);
	return out;
}

bool isNumericHostname(const std::string &hostname) {
	struct addrinfo hints{};
	hints.ai_flags = AI_NUMERICHOST;
	struct addrinfo *res = nullptr;
	if (getaddrinfo(hostname.c_str(), nullptr, &hints, &res) != 0)
		return false;
	freeaddrinfo(res);
	return true;
}

bool parseAddr(const std::string &host, uint16_t port, struct sockaddr_storage &out, socklen_t &outLen) {
	std::memset(&out, 0, sizeof(out));
	// Try IPv4 first.
	sockaddr_in in4{};
	in4.sin_family = AF_INET;
	in4.sin_port = htons(port);
	if (inet_pton(AF_INET, host.c_str(), &in4.sin_addr) == 1) {
		std::memcpy(&out, &in4, sizeof(in4));
		outLen = sizeof(in4);
		return true;
	}
	sockaddr_in6 in6{};
	in6.sin6_family = AF_INET6;
	in6.sin6_port = htons(port);
	if (inet_pton(AF_INET6, host.c_str(), &in6.sin6_addr) == 1) {
		std::memcpy(&out, &in6, sizeof(in6));
		outLen = sizeof(in6);
		return true;
	}
	return false;
}

} // namespace stice::net
