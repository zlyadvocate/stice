// SPDX-License-Identifier: MPL-2.0
// stice UDP socket. Ported from libjuice's udp.c.

#ifndef STICE_NET_UDP_HPP
#define STICE_NET_UDP_HPP

#include "stice/net/addr.hpp"
#include "stice/net/platform.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace stice::net {

struct UdpSocketConfig {
	std::string bindAddress;
	uint16_t portBegin = 0;
	uint16_t portEnd = 0;
};

class UdpSocket {
public:
	UdpSocket() = default;
	~UdpSocket();
	UdpSocket(const UdpSocket &) = delete;
	UdpSocket &operator=(const UdpSocket &) = delete;
	UdpSocket(UdpSocket &&o) noexcept : sock_(o.sock_), family_(o.family_) {
		o.sock_ = STICE_INVALID_SOCKET;
		o.family_ = AF_UNSPEC;
	}
	UdpSocket &operator=(UdpSocket &&o) noexcept;

	// Returns STICE_INVALID_SOCKET on failure.
	static UdpSocket create(const UdpSocketConfig &cfg);

	socket_t handle() const { return sock_; }
	bool valid() const { return sock_ != STICE_INVALID_SOCKET; }

	int recvfrom(char *buf, std::size_t size, AddrRecord &src);
	int sendto(const char *data, std::size_t size, const AddrRecord &dst);
	// Batch send multiple packets in one syscall (P2-2). On Linux uses
	// sendmmsg to reduce per-packet syscall overhead; on other platforms
	// falls back to a loop of sendto. Each packet may have a different
	// destination. Returns the number of packets successfully sent.
	int sendBatch(const char *const *data, const std::size_t *sizes,
	              const AddrRecord *dsts, std::size_t count);
	int sendtoSelf(const char *data, std::size_t size); // wake a poll loop
	int setDiffserv(int ds);
	uint16_t port() const;
	bool boundAddr(AddrRecord &out) const;
	// Enumerate local candidate addresses (host candidates). family may be AF_UNSPEC.
	std::vector<AddrRecord> localAddrs(int family = AF_UNSPEC) const;

	void close();

private:
	socket_t sock_ = STICE_INVALID_SOCKET;
	int family_ = AF_UNSPEC;
};

} // namespace stice::net

#endif
