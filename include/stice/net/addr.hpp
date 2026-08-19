// SPDX-License-Identifier: MPL-2.0
// stice network address handling. Ported from libjuice's addr.c.
// AddrRecord wraps a sockaddr_storage with length and socktype.

#ifndef STICE_NET_ADDR_HPP
#define STICE_NET_ADDR_HPP

#include "stice/types.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using socklen_t = int;
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace stice::net {

constexpr int ADDR_MAX_STRING_LEN = 64;

struct AddrRecord {
	struct sockaddr_storage addr{};
	socklen_t len = 0;
	int socktype = 0;

	bool operator==(const AddrRecord &o) const { return isEqual(o, true); }
	bool isEqual(const AddrRecord &o, bool comparePorts) const;
	std::string toString() const;
	uint64_t hash(bool withPort) const;
};

socklen_t addrLen(const struct sockaddr *sa);
uint16_t addrPort(const struct sockaddr *sa);
void addrSetPort(struct sockaddr *sa, uint16_t port);
bool addrIsAny(const struct sockaddr *sa);
bool addrIsLocal(const struct sockaddr *sa);
// Convert a v4-mapped IPv6 sockaddr (::ffff:a.b.c.d) back to IPv4 in place.
bool addrUnmapInet6V4Mapped(struct sockaddr *sa, socklen_t &len);
bool addrMapInet6V4Mapped(struct sockaddr_storage &ss, socklen_t &len);
bool addrEqual(const struct sockaddr *a, const struct sockaddr *b, bool comparePorts);

std::string addrToString(const struct sockaddr *sa);

// Resolve hostname:service into records (getaddrinfo). socktype = SOCK_DGRAM/SOCK_STREAM.
std::vector<AddrRecord> resolve(const std::string &hostname, const std::string &service, int socktype);
bool isNumericHostname(const std::string &hostname);

// Build an IPv4/IPv6 sockaddr from a numeric host + port.
bool parseAddr(const std::string &host, uint16_t port, struct sockaddr_storage &out, socklen_t &outLen);

} // namespace stice::net

#endif
