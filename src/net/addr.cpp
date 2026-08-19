/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
#include "stice/net/addr.hpp"

#include "stice/log.hpp"

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
	if (a->sa_family != b->sa_family) return false;
	if (a->sa_family == AF_INET) {
		auto *la = reinterpret_cast<const sockaddr_in *>(a);
		auto *lb = reinterpret_cast<const sockaddr_in *>(b);
		if (la->sin_addr.s_addr != lb->sin_addr.s_addr) return false;
		if (comparePorts && la->sin_port != lb->sin_port) return false;
		return true;
	}
	if (a->sa_family == AF_INET6) {
		auto *la = reinterpret_cast<const sockaddr_in6 *>(a);
		auto *lb = reinterpret_cast<const sockaddr_in6 *>(b);
		if (std::memcmp(&la->sin6_addr, &lb->sin6_addr, 16) != 0) return false;
		if (comparePorts && la->sin6_port != lb->sin6_port) return false;
		return true;
	}
	return false;
}

std::string addrToString(const struct sockaddr *sa) {
	if (!sa) return {};
	char node[64];
	char serv[8];
	if (getnameinfo(sa, addrLen(sa), node, sizeof(node), serv, sizeof(serv),
	                NI_NUMERICHOST | NI_NUMERICSERV | NI_DGRAM) != 0)
		return {};
	std::string s = node;
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
	// djb2 variant
	uint64_t h = 5381;
	auto *sa = reinterpret_cast<const sockaddr *>(&addr);
	h = ((h << 5) + h) + static_cast<uint64_t>(sa->sa_family);
	h = ((h << 5) + h) + static_cast<uint64_t>(socktype);
	if (sa->sa_family == AF_INET) {
		auto *in = reinterpret_cast<const sockaddr_in *>(sa);
		uint32_t a = in->sin_addr.s_addr;
		h = ((h << 5) + h) + (a & 0xFF);
		h = ((h << 5) + h) + ((a >> 8) & 0xFF);
		h = ((h << 5) + h) + ((a >> 16) & 0xFF);
		h = ((h << 5) + h) + ((a >> 24) & 0xFF);
		if (withPort) h = ((h << 5) + h) + ntohs(in->sin_port);
	} else if (sa->sa_family == AF_INET6) {
		auto *in6 = reinterpret_cast<const sockaddr_in6 *>(sa);
		for (int i = 0; i < 16; ++i) h = ((h << 5) + h) + in6->sin6_addr.s6_addr[i];
		if (withPort) h = ((h << 5) + h) + ntohs(in6->sin6_port);
	}
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
