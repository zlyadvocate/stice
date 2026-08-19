/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "stice/net/udp.hpp"

#include "stice/crypto.hpp"
#include "stice/log.hpp"

#include <cstring>
#include <mutex>

#ifdef _WIN32
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <net/if.h>
#include <sys/ioctl.h>
#ifdef __linux__
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/ip.h>
#endif
#endif

namespace stice::net {

#ifdef _WIN32
struct WsaInit {
	WsaInit() {
		WSADATA d;
		(void)WSAStartup(MAKEWORD(2, 2), &d);
	}
	~WsaInit() { WSACleanup(); }
};
static WsaInit g_wsaInit;
#endif

namespace {
struct addrinfo *findFamily(struct addrinfo *ai, int family) {
	while (ai && ai->ai_family != family) ai = ai->ai_next;
	return ai;
}

uint16_t nextPortInRange(uint16_t begin, uint16_t end) {
	if (begin == 0) begin = 1024;
	if (end == 0) end = 0xFFFF;
	if (begin == end) return begin;
	static std::mutex mtx;
	static uint32_t count = 0;
	std::lock_guard<std::mutex> lock(mtx);
	if (count == 0) count = crypto::randomU32();
	uint32_t diff = end > begin ? uint32_t(end) - begin : 0;
	return begin + static_cast<uint16_t>(count++ % (diff + 1));
}

bool hasDuplicate(const struct sockaddr *addr, const std::vector<AddrRecord> &records) {
	for (const auto &r : records) {
		const auto *rsa = reinterpret_cast<const sockaddr *>(&r.addr);
		if (rsa->sa_family != addr->sa_family) continue;
		if (addr->sa_family == AF_INET) {
			auto *a = reinterpret_cast<const sockaddr_in *>(addr);
			auto *b = reinterpret_cast<const sockaddr_in *>(rsa);
			if (std::memcmp(&a->sin_addr, &b->sin_addr, 4) == 0) return true;
		} else if (addr->sa_family == AF_INET6) {
			auto *a = reinterpret_cast<const sockaddr_in6 *>(addr);
			auto *b = reinterpret_cast<const sockaddr_in6 *>(rsa);
			if (std::memcmp(&a->sin6_addr, &b->sin6_addr, 8) == 0) return true;
		}
	}
	return false;
}
} // namespace

UdpSocket::~UdpSocket() { close(); }

UdpSocket &UdpSocket::operator=(UdpSocket &&o) noexcept {
	if (this != &o) {
		close();
		sock_ = o.sock_;
		family_ = o.family_;
		o.sock_ = STICE_INVALID_SOCKET;
		o.family_ = AF_UNSPEC;
	}
	return *this;
}

void UdpSocket::close() {
	if (sock_ != STICE_INVALID_SOCKET) {
		sticeClosesocket(sock_);
		sock_ = STICE_INVALID_SOCKET;
	}
}

static socket_t createForAddrinfo(const UdpSocketConfig &cfg, const struct addrinfo *ai) {
	socket_t sock = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (sock == STICE_INVALID_SOCKET) {
		STICE_LOG_WARN("UDP socket creation failed, errno=%d", sticeSockerrno);
		return STICE_INVALID_SOCKET;
	}
	// Listen on both IPv6 and IPv4.
	if (ai->ai_family == AF_INET6) {
		int disabled = 0;
		setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char *>(&disabled), sizeof(disabled));
	}
	// Set DF flag (Linux IP_MTU_DISCOVER; others IP_DONTFRAG).
#ifdef __linux__
	int val = IP_PMTUDISC_DO;
	setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
#ifdef IPV6_MTU_DISCOVER
	if (ai->ai_family == AF_INET6)
		setsockopt(sock, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &val, sizeof(val));
#endif
#endif
	// 1 MiB buffers.
	int bufsize = 1 * 1024 * 1024;
	setsockopt(sock, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char *>(&bufsize), sizeof(bufsize));
	setsockopt(sock, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char *>(&bufsize), sizeof(bufsize));

#ifdef _WIN32
	u_long nbio = 1;
	if (ioctlsocket(sock, FIONBIO, &nbio) != 0) {
#else
	int nbio = 1;
	if (ioctl(sock, FIONBIO, &nbio) != 0) {
#endif
		STICE_LOG_ERROR("Setting non-blocking mode on UDP socket failed");
		sticeClosesocket(sock);
		return STICE_INVALID_SOCKET;
	}

	auto bindAddr = [&](struct sockaddr_storage &ss, socklen_t len) -> bool {
		return ::bind(sock, reinterpret_cast<struct sockaddr *>(&ss), len) == 0;
	};

	if (cfg.portBegin == 0 && cfg.portEnd == 0) {
		if (::bind(sock, ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen)) == 0)
			return sock;
		STICE_LOG_WARN("UDP socket binding failed, errno=%d", sticeSockerrno);
	} else if (cfg.portBegin == cfg.portEnd) {
		struct sockaddr_storage ss;
		std::memcpy(&ss, ai->ai_addr, ai->ai_addrlen);
		socklen_t len = static_cast<socklen_t>(ai->ai_addrlen);
		addrSetPort(reinterpret_cast<struct sockaddr *>(&ss), cfg.portBegin);
		if (bindAddr(ss, len)) return sock;
		STICE_LOG_WARN("UDP socket binding failed on port %hu", cfg.portBegin);
	} else {
		struct sockaddr_storage ss;
		std::memcpy(&ss, ai->ai_addr, ai->ai_addrlen);
		socklen_t len = static_cast<socklen_t>(ai->ai_addrlen);
		int retries = cfg.portEnd - cfg.portBegin;
		do {
			uint16_t port = nextPortInRange(cfg.portBegin, cfg.portEnd);
			addrSetPort(reinterpret_cast<struct sockaddr *>(&ss), port);
			if (bindAddr(ss, len)) return sock;
		} while ((sticeSockerrno == EADDRINUSE || sticeSockerrno == EACCES) && retries-- > 0);
		STICE_LOG_WARN("UDP socket binding failed on port range [%hu,%hu]", cfg.portBegin, cfg.portEnd);
	}
	sticeClosesocket(sock);
	return STICE_INVALID_SOCKET;
}

UdpSocket UdpSocket::create(const UdpSocketConfig &cfg) {
	UdpSocket out;
	struct addrinfo hints{};
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
	struct addrinfo *aiList = nullptr;
	if (getaddrinfo(cfg.bindAddress.empty() ? nullptr : cfg.bindAddress.c_str(), "0", &hints, &aiList) != 0) {
		STICE_LOG_ERROR("getaddrinfo for binding address failed");
		return out;
	}
	const int families[2] = {AF_INET6, AF_INET}; // Prefer IPv6 dual-stack.
	for (int fam : families) {
		auto *ai = findFamily(aiList, fam);
		if (!ai) continue;
		socket_t sock = createForAddrinfo(cfg, ai);
		if (sock != STICE_INVALID_SOCKET) {
			out.sock_ = sock;
			out.family_ = fam;
			break;
		}
	}
	freeaddrinfo(aiList);
	return out;
}

int UdpSocket::recvfrom(char *buf, std::size_t size, AddrRecord &src) {
	while (true) {
		src.len = sizeof(src.addr);
		src.socktype = SOCK_DGRAM;
		int len = static_cast<int>(::recvfrom(sock_, buf, static_cast<socklen_t>(size), 0,
		                                      reinterpret_cast<struct sockaddr *>(&src.addr), &src.len));
		if (len >= 0) {
			addrUnmapInet6V4Mapped(reinterpret_cast<struct sockaddr *>(&src.addr), src.len);
			return len;
		}
		if (sticeSockerrno == STICE_SECONNRESET || sticeSockerrno == WSAENETRESET ||
		    sticeSockerrno == ECONNREFUSED) {
			// Windows: ICMP port-unreachable stored, ignore.
			continue;
		}
		return -1;
	}
}

int UdpSocket::sendto(const char *data, std::size_t size, const AddrRecord &dst) {
	// A dual-stack AF_INET6 socket cannot sendto a sockaddr_in (IPv4) directly
	// (WSAEAFNOSUPPORT / EAFNOSUPPORT). Convert IPv4 destinations to
	// IPv4-mapped IPv6 (::ffff:a.b.c.d) so the kernel routes them correctly.
	if (family_ == AF_INET6 && dst.addr.ss_family == AF_INET) {
		sockaddr_storage mapped;
		socklen_t mappedLen = dst.len;
		std::memcpy(&mapped, &dst.addr, dst.len);
		if (addrMapInet6V4Mapped(mapped, mappedLen)) {
			return static_cast<int>(
			    ::sendto(sock_, data, static_cast<socklen_t>(size), 0,
			             reinterpret_cast<const struct sockaddr *>(&mapped), mappedLen));
		}
	}
	return static_cast<int>(
	    ::sendto(sock_, data, static_cast<socklen_t>(size), 0,
	             reinterpret_cast<const struct sockaddr *>(&dst.addr), dst.len));
}

int UdpSocket::sendtoSelf(const char *data, std::size_t size) {
	AddrRecord local;
	if (boundAddr(local) < 0) return -1;
	return static_cast<int>(
	    ::sendto(sock_, data, static_cast<socklen_t>(size), 0,
	             reinterpret_cast<const struct sockaddr *>(&local.addr), local.len));
}

int UdpSocket::sendBatch(const char *const *data, const std::size_t *sizes,
                         const AddrRecord *dsts, std::size_t count) {
	if (count == 0) return 0;
	int sent = 0;
#ifdef __linux__
	// Use sendmmsg to batch multiple UDP sends into one syscall (P2-2).
	// This significantly reduces context-switch overhead when sending many
	// STUN connectivity checks or TURN ChannelData frames in one tick.
	std::vector<mmsghdr> msgs(count);
	std::vector<iovec> iovs(count);
	std::vector<sockaddr_storage> addrs(count);
	for (std::size_t i = 0; i < count; ++i) {
		iovs[i].iov_base = const_cast<char *>(data[i]);
		iovs[i].iov_len = sizes[i];
		addrs[i] = dsts[i].addr;
		msgs[i].msg_hdr.msg_name = &addrs[i];
		msgs[i].msg_hdr.msg_namelen = dsts[i].len;
		msgs[i].msg_hdr.msg_iov = &iovs[i];
		msgs[i].msg_hdr.msg_iovlen = 1;
		msgs[i].msg_hdr.msg_control = nullptr;
		msgs[i].msg_hdr.msg_controllen = 0;
		msgs[i].msg_hdr.msg_flags = 0;
	}
	int r = ::sendmmsg(sock_, msgs.data(), static_cast<unsigned int>(count), 0);
	if (r < 0) return sent;
	return r;
#else
	// Non-Linux (Windows/macOS): fall back to individual sendto calls.
	for (std::size_t i = 0; i < count; ++i) {
		if (sendto(data[i], sizes[i], dsts[i]) >= 0)
			++sent;
		else
			break;
	}
	return sent;
#endif
}

int UdpSocket::setDiffserv(int ds) {
#ifdef _WIN32
	(void)ds;
	STICE_LOG_INFO("IP Differentiated Services are not supported on Windows");
	return -1;
#else
	AddrRecord name;
	if (boundAddr(name) < 0) return -1;
	auto *sa = reinterpret_cast<struct sockaddr *>(&name.addr);
	if (sa->sa_family == AF_INET) {
#ifdef IP_TOS
		return setsockopt(sock_, IPPROTO_IP, IP_TOS, &ds, sizeof(ds));
#else
		return -1;
#endif
	}
	if (sa->sa_family == AF_INET6) {
#ifdef IPV6_TCLASS
		int r = setsockopt(sock_, IPPROTO_IPV6, IPV6_TCLASS, &ds, sizeof(ds));
#ifdef IP_TOS
		setsockopt(sock_, IPPROTO_IP, IP_TOS, &ds, sizeof(ds));
#endif
		return r;
#else
		return -1;
#endif
	}
	return -1;
#endif
}

uint16_t UdpSocket::port() const {
	AddrRecord r;
	if (boundAddr(r) < 0) return 0;
	return addrPort(reinterpret_cast<struct sockaddr *>(&r.addr));
}

bool UdpSocket::boundAddr(AddrRecord &out) const {
	out.len = sizeof(out.addr);
	out.socktype = SOCK_DGRAM;
	if (getsockname(sock_, reinterpret_cast<struct sockaddr *>(&out.addr), &out.len) != 0)
		return false;
	return true;
}

std::vector<AddrRecord> UdpSocket::localAddrs(int family) const {
	std::vector<AddrRecord> records;
	AddrRecord bound;
	if (!boundAddr(bound)) return records;
	auto *boundSa = reinterpret_cast<struct sockaddr *>(&bound.addr);
	// If bound to a specific address, return just that.
	if (!addrIsAny(boundSa)) {
		records.push_back(bound);
		return records;
	}
	uint16_t port = addrPort(boundSa);

#ifdef _WIN32
	char buf[4096];
	DWORD len = 0;
	if (WSAIoctl(sock_, SIO_ADDRESS_LIST_QUERY, nullptr, 0, buf, sizeof(buf), &len, nullptr, nullptr) != 0)
		return records;
	auto *list = reinterpret_cast<SOCKET_ADDRESS_LIST *>(buf);
	for (int i = 0; i < list->iAddressCount; ++i) {
		struct sockaddr *sa = list->Address[i].lpSockaddr;
		socklen_t slen = static_cast<socklen_t>(list->Address[i].iSockaddrLength);
		if ((sa->sa_family == AF_INET ||
		     (sa->sa_family == AF_INET6 && bound.addr.ss_family == AF_INET6)) &&
		    !addrIsLocal(sa) && !hasDuplicate(sa, records)) {
			AddrRecord r;
			std::memcpy(&r.addr, sa, slen);
			r.len = slen;
			r.socktype = SOCK_DGRAM;
			addrUnmapInet6V4Mapped(reinterpret_cast<struct sockaddr *>(&r.addr), r.len);
			addrSetPort(reinterpret_cast<struct sockaddr *>(&r.addr), port);
			records.push_back(std::move(r));
		}
	}
#else
	struct ifaddrs *ifas;
	if (getifaddrs(&ifas) != 0) return records;
	for (auto *ifa = ifas; ifa; ifa = ifa->ifa_next) {
		unsigned int flags = ifa->ifa_flags;
		if (!(flags & IFF_UP) || (flags & IFF_LOOPBACK)) continue;
		if (strcmp(ifa->ifa_name, "docker0") == 0) continue;
		struct sockaddr *sa = ifa->ifa_addr;
		if (!sa) continue;
		socklen_t slen = addrLen(sa);
		if (slen == 0) continue;
		if ((sa->sa_family == AF_INET ||
		     (sa->sa_family == AF_INET6 && bound.addr.ss_family == AF_INET6)) &&
		    !addrIsLocal(sa) && !hasDuplicate(sa, records)) {
			AddrRecord r;
			std::memcpy(&r.addr, sa, slen);
			r.len = slen;
			r.socktype = SOCK_DGRAM;
			addrSetPort(reinterpret_cast<struct sockaddr *>(&r.addr), port);
			records.push_back(std::move(r));
		}
	}
	freeifaddrs(ifas);
#endif
	return records;
}

} // namespace stice::net
