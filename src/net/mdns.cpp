/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
#include "stice/net/mdns.hpp"

#include "stice/crypto.hpp"
#include "stice/log.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace stice::net {

namespace {
// mDNS multicast address and port.
constexpr const char *kMDnsMulticastAddr4 = "224.0.0.251";
constexpr const char *kMDnsMulticastAddr6 = "ff02::fb";
constexpr std::uint16_t kMDnsPort = 5353;
constexpr std::uint16_t kDnsTypeA = 1;
constexpr std::uint16_t kDnsTypeAAAA = 28;
constexpr std::uint16_t kDnsTypeNSEC = 47;
constexpr std::uint16_t kDnsClassIN = 1;
constexpr std::uint16_t kDnsClassCacheFlush = 0x8000; // RFC 6762 §10.2
constexpr std::uint16_t kDnsClassINUnicast = 0x8001; // IN with unicast-response bit
constexpr int kQueryIntervalMs = 1000;
constexpr int kQueryTimeoutMs = 5000;
// draft-ietf-rtcweb-mdns-ice-candidates §3.1 conflict probe: one query, short
// window. Long enough for a same-link responder to answer, short enough that it
// does not visibly delay gathering.
constexpr int kConflictProbeWindowMs = 200;
constexpr std::uint32_t kResponseTTL = 120;

std::string lowerName(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(),
	               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return s;
}

// Join ff02::fb on every usable interface. RFC 6762 §15.1 requires joining the
// IPv6 mDNS group per interface; the IPv4 group is interface-agnostic only
// because INADDR_ANY means "all of them". Best-effort: a host without IPv6
// simply keeps the IPv4-only resolver.
void joinMDnsV6Groups(socket_t s) {
#ifdef _WIN32
	ULONG size = 0;
	const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
	                    GAA_FLAG_SKIP_DNS_SERVER;
	if (GetAdaptersAddresses(AF_INET6, flags, nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW)
		return;
	std::vector<unsigned char> storage(size);
	auto *aa = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(storage.data());
	if (GetAdaptersAddresses(AF_INET6, flags, nullptr, aa, &size) != NO_ERROR) return;
	for (auto *p = aa; p; p = p->Next) {
		if (p->OperStatus != IfOperStatusUp || p->Ipv6IfIndex == 0) continue;
		ipv6_mreq mreq{};
		inet_pton(AF_INET6, kMDnsMulticastAddr6, &mreq.ipv6mr_multiaddr);
		mreq.ipv6mr_interface = p->Ipv6IfIndex;
		::setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP,
		             reinterpret_cast<const char *>(&mreq), sizeof(mreq));
	}
#else
	struct if_nameindex *ni = if_nameindex();
	if (!ni) return;
	for (struct if_nameindex *p = ni; p->if_index != 0 && p->if_name; ++p) {
		ipv6_mreq mreq{};
		inet_pton(AF_INET6, kMDnsMulticastAddr6, &mreq.ipv6mr_multiaddr);
		mreq.ipv6mr_interface = p->if_index;
		::setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP,
		             reinterpret_cast<const char *>(&mreq), sizeof(mreq));
	}
	if_freenameindex(ni);
#endif
}
} // namespace

MDnsClient::MDnsClient() = default;

MDnsClient::~MDnsClient() {
	stop();
}

bool MDnsClient::init(MulticastDNSMode mode, const std::string &hostname,
                      const std::string &localAddr) {
	mode_ = mode;
	degraded_ = false;
	if (mode == MulticastDNSMode::Disabled) return true;

	hostname_ = hostname.empty() ? generateHostname() : hostname;
	localAddr_ = localAddr;
	{
		std::lock_guard<std::mutex> lk(recordsMutex_);
		records_.clear();
	}

	// Create UDP socket for mDNS.
	sock_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock_ == STICE_INVALID_SOCKET) {
		STICE_LOG_WARN("mDNS: failed to create socket, errno=%d", sticeSockerrno);
		return false;
	}

	// Allow address reuse (multiple mDNS listeners on 5353).
	int reuse = 1;
	::setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&reuse),
	             sizeof(reuse));
#ifdef SO_REUSEPORT
	::setsockopt(sock_, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<const char *>(&reuse),
	             sizeof(reuse));
#endif

	// Bind to 0.0.0.0:5353.
	sockaddr_in bindAddr{};
	bindAddr.sin_family = AF_INET;
	bindAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	bindAddr.sin_port = htons(kMDnsPort);
	if (::bind(sock_, reinterpret_cast<struct sockaddr *>(&bindAddr), sizeof(bindAddr)) < 0) {
		STICE_LOG_WARN("mDNS: failed to bind to port %d, errno=%d (continuing in QueryOnly mode)",
		               kMDnsPort, sticeSockerrno);
		// If we can't bind to 5353, we can still send queries from an ephemeral port.
		// But we won't receive multicast responses or queries. Fall back to query-only.
		degraded_ = true;
		if (mode == MulticastDNSMode::QueryAndGather) {
			mode_ = MulticastDNSMode::QueryOnly;
		}
		// Rebind to ephemeral port.
		bindAddr.sin_port = 0;
		if (::bind(sock_, reinterpret_cast<struct sockaddr *>(&bindAddr), sizeof(bindAddr)) < 0) {
			STICE_LOG_WARN("mDNS: failed to bind to ephemeral port, errno=%d", sticeSockerrno);
			sticeClosesocket(sock_);
			sock_ = STICE_INVALID_SOCKET;
			return false;
		}
	}

	// Set non-blocking.
	setNonBlocking(sock_);

	// Join multicast group 224.0.0.251.
	ip_mreq mreq{};
	mreq.imr_multiaddr.s_addr = inet_addr(kMDnsMulticastAddr4);
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	if (::setsockopt(sock_, IPPROTO_IP, IP_ADD_MEMBERSHIP, reinterpret_cast<const char *>(&mreq),
	                 sizeof(mreq)) < 0) {
		STICE_LOG_WARN("mDNS: failed to join multicast group, errno=%d", sticeSockerrno);
		// Not fatal — we can still send queries (responses may not arrive).
	}

	// Set TTL for multicast packets.
	unsigned char ttl = 255;
	::setsockopt(sock_, IPPROTO_IP, IP_MULTICAST_TTL, reinterpret_cast<const char *>(&ttl),
	             sizeof(ttl));

	// Enable multicast loopback so local queries work.
	unsigned char loop = 1;
	::setsockopt(sock_, IPPROTO_IP, IP_MULTICAST_LOOP, reinterpret_cast<const char *>(&loop),
	             sizeof(loop));

	// Set up multicast destination address.
	mcastAddr4_.sin_family = AF_INET;
	mcastAddr4_.sin_addr.s_addr = inet_addr(kMDnsMulticastAddr4);
	mcastAddr4_.sin_port = htons(kMDnsPort);

	// IPv6 transport (RFC 6762 §15.1): a second socket on ff02::fb so AAAA
	// answers can be both sent and received. Optional — a failure here leaves
	// the IPv4 resolver intact.
	sock6_ = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sock6_ != STICE_INVALID_SOCKET) {
		int on = 1;
		::setsockopt(sock6_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&on),
		             sizeof(on));
#ifdef SO_REUSEPORT
		::setsockopt(sock6_, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<const char *>(&on),
		             sizeof(on));
#endif
		::setsockopt(sock6_, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char *>(&on),
		             sizeof(on));
		sockaddr_in6 bind6{};
		bind6.sin6_family = AF_INET6;
		bind6.sin6_addr = in6addr_any;
		bind6.sin6_port = htons(kMDnsPort);
		if (::bind(sock6_, reinterpret_cast<struct sockaddr *>(&bind6), sizeof(bind6)) < 0) {
			STICE_LOG_DEBUG("mDNS: IPv6 bind failed, continuing IPv4-only (errno=%d)",
			                sticeSockerrno);
			sticeClosesocket(sock6_);
			sock6_ = STICE_INVALID_SOCKET;
		} else {
			setNonBlocking(sock6_);
			joinMDnsV6Groups(sock6_);
			unsigned char ttl6 = 255;
			::setsockopt(sock6_, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
			             reinterpret_cast<const char *>(&ttl6), sizeof(ttl6));
			unsigned char loop6 = 1;
			::setsockopt(sock6_, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
			             reinterpret_cast<const char *>(&loop6), sizeof(loop6));
			mcastAddr6_.sin6_family = AF_INET6;
			inet_pton(AF_INET6, kMDnsMulticastAddr6, &mcastAddr6_.sin6_addr);
			mcastAddr6_.sin6_port = htons(kMDnsPort);
		}
	}

	running_ = true;
	thread_ = std::thread([this] { run(); });

	// draft-ietf-rtcweb-mdns-ice-candidates §3.1: probe an auto-generated label
	// before advertising it. A collision is astronomically unlikely with a
	// UUIDv4, but the draft asks for the probe and it is cheap. A caller-supplied
	// hostname is honoured as-is; QueryOnly never advertises a name, so it needs
	// no probe either.
	if (hostname.empty() && mode_ == MulticastDNSMode::QueryAndGather) {
		for (int attempt = 0; attempt < 3; ++attempt) {
			if (!probeNameConflict(hostname_)) break;
			hostname_ = generateHostname();
			STICE_LOG_WARN("mDNS: name conflict detected, retrying with %s", hostname_.c_str());
		}
	}

	STICE_LOG_INFO("mDNS: initialized mode=%d hostname=%s localAddr=%s",
	               static_cast<int>(mode_), hostname_.c_str(), localAddr_.c_str());
	return true;
}

void MDnsClient::stop() {
	if (!running_.exchange(false)) return;
	// RFC 6762 §10.1: a departing responder sends a goodbye (TTL 0) so peers
	// drop the name immediately instead of keeping it for the full TTL. Send it
	// while the socket is still open.
	sendGoodbyes();
	if (sock_ != STICE_INVALID_SOCKET) {
		// Leave multicast group.
		ip_mreq mreq{};
		mreq.imr_multiaddr.s_addr = inet_addr(kMDnsMulticastAddr4);
		mreq.imr_interface.s_addr = htonl(INADDR_ANY);
		::setsockopt(sock_, IPPROTO_IP, IP_DROP_MEMBERSHIP, reinterpret_cast<const char *>(&mreq),
		             sizeof(mreq));
		sticeClosesocket(sock_);
		sock_ = STICE_INVALID_SOCKET;
	}
	if (sock6_ != STICE_INVALID_SOCKET) {
		sticeClosesocket(sock6_);
		sock6_ = STICE_INVALID_SOCKET;
	}
	if (thread_.joinable()) thread_.join();
}

bool MDnsClient::isMDnsName(const std::string &hostname) {
	// draft-ietf-rtcweb-mdns-ice-candidates §3.1: the advertised name is a
	// SINGLE label plus ".local" ("uuid.local"). A multi-label name
	// ("a.b.local") is not one of ours and must not be handed to the resolver.
	std::string s = lowerName(hostname);
	if (!s.empty() && s.back() == '.') s.pop_back(); // optional trailing dot
	if (s.size() < 6) return false;                  // "x.local" minimum
	auto pos = s.rfind(".local");
	if (pos == std::string::npos || pos + 6 != s.size()) return false;
	if (pos == 0) return false;                      // ".local" has no label
	return s.find('.') == pos;                       // reject multi-label names
}

std::string MDnsClient::generateHostname() {
	// Generate a UUID v4 string.
	unsigned char bytes[16];
	crypto::randomBytes(bytes, 16);
	// Set version (4) and variant bits.
	bytes[6] = (bytes[6] & 0x0F) | 0x40; // version 4
	bytes[8] = (bytes[8] & 0x3F) | 0x80; // variant 10
	// Format as 8-4-4-4-12 hex.
	char buf[40];
	std::snprintf(buf, sizeof(buf),
	              "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	              bytes[0], bytes[1], bytes[2], bytes[3],
	              bytes[4], bytes[5], bytes[6], bytes[7],
	              bytes[8], bytes[9], bytes[10], bytes[11],
	              bytes[12], bytes[13], bytes[14], bytes[15]);
	return std::string(buf) + ".local";
}

bool MDnsClient::query(const std::string &hostname, MDnsQueryCallback cb) {
	if (mode_ == MulticastDNSMode::Disabled || sock_ == STICE_INVALID_SOCKET) return false;

	std::string name = hostname;
	// Strip trailing dot if present.
	if (!name.empty() && name.back() == '.') name.pop_back();

	// RFC 6762 §10: serve a still-fresh cached answer without re-querying.
	{
		std::string key = lowerName(name);
		std::string cached;
		{
			std::lock_guard<std::mutex> lk(queriesMutex_);
			auto it = cache_.find(key);
			if (it != cache_.end()) {
				if (std::chrono::steady_clock::now() < it->second.expiry) cached = it->second.addr;
				else cache_.erase(it);
			}
		}
		if (!cached.empty()) {
			if (cb) cb(cached);
			return true;
		}
	}

	PendingQuery pq;
	pq.hostname = name;
	pq.callback = std::move(cb);
	pq.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kQueryTimeoutMs);
	pq.lastSent = {};

	{
		std::lock_guard<std::mutex> lk(queriesMutex_);
		queries_.push_back(std::move(pq));
	}

	// Send the initial query immediately.
	sendPendingQueries();
	return true;
}

bool MDnsClient::probeNameConflict(const std::string &name) {
	if (mode_ == MulticastDNSMode::Disabled || sock_ == STICE_INVALID_SOCKET) return false;
	{
		std::lock_guard<std::mutex> lk(probeMutex_);
		probeDone_ = false;
		probeConflict_ = false;
	}
	PendingQuery pq;
	pq.hostname = name;
	pq.callback = [this](const std::string &addr) {
		{
			std::lock_guard<std::mutex> lk(probeMutex_);
			// The timeout path reports an empty address; only a real answer
			// proves another host already owns the name.
			if (!addr.empty()) probeConflict_ = true;
			probeDone_ = true;
		}
		probeCv_.notify_all();
	};
	pq.deadline =
		std::chrono::steady_clock::now() + std::chrono::milliseconds(kConflictProbeWindowMs);
	pq.lastSent = {};
	{
		std::lock_guard<std::mutex> lk(queriesMutex_);
		queries_.push_back(std::move(pq));
	}
	sendPendingQueries();
	std::unique_lock<std::mutex> lk(probeMutex_);
	probeCv_.wait_for(lk, std::chrono::milliseconds(kConflictProbeWindowMs + 200),
	                  [this] { return probeDone_; });
	return probeConflict_;
}

bool MDnsClient::addRecord(const std::string &hostname, const std::string &addr) {
	if (mode_ != MulticastDNSMode::QueryAndGather) return false;
	std::string name = hostname;
	if (!name.empty() && name.back() == '.') name.pop_back();
	if (name.empty() || addr.empty()) return false;
	{
		std::lock_guard<std::mutex> lk(recordsMutex_);
		records_[lowerName(name)] = addr;
	}
	// RFC 6762 §8.3: announce a newly registered record instead of waiting for
	// a peer to ask. Without this a QueryAndGather peer only learns the address
	// when its own query fires, adding a full retry interval to the handshake.
	if (sock_ != STICE_INVALID_SOCKET) {
		const bool v6 = addr.find(':') != std::string::npos;
		std::uint16_t type = v6 ? kDnsTypeAAAA : kDnsTypeA;
		const sockaddr *dst = v6
			? reinterpret_cast<const sockaddr *>(&mcastAddr6_)
			: reinterpret_cast<const sockaddr *>(&mcastAddr4_);
		sendRecordResponse(name, type, addr, kResponseTTL, dst, true);
	}
	return true;
}

std::vector<unsigned char> MDnsClient::encodeName(const std::string &name) const {
	std::vector<unsigned char> out;
	// Split by dots and encode each label.
	std::size_t start = 0;
	while (start < name.size()) {
		auto dot = name.find('.', start);
		std::string label = (dot == std::string::npos) ? name.substr(start) : name.substr(start, dot - start);
		if (!label.empty()) {
			out.push_back(static_cast<unsigned char>(label.size()));
			out.insert(out.end(), label.begin(), label.end());
		}
		if (dot == std::string::npos) break;
		start = dot + 1;
	}
	out.push_back(0); // root label
	return out;
}

std::vector<unsigned char> MDnsClient::encodeQuery(const std::string &name,
                                                    std::uint16_t type) const {
	std::vector<unsigned char> out;
	// Header: id=0, flags=0, qdcount=1, others=0.
	auto put16 = [&](std::uint16_t v) {
		out.push_back(static_cast<unsigned char>(v >> 8));
		out.push_back(static_cast<unsigned char>(v & 0xFF));
	};
	put16(0);     // id
	put16(0);     // flags
	put16(1);     // qdcount
	put16(0);     // ancount
	put16(0);     // nscount
	put16(0);     // arcount
	// Question: name, type, class.
	auto nameBytes = encodeName(name);
	out.insert(out.end(), nameBytes.begin(), nameBytes.end());
	put16(type);
	put16(kDnsClassINUnicast); // unicast-response bit set
	return out;
}

std::vector<unsigned char> MDnsClient::encodeResponse(std::uint16_t id, const std::string &name,
                                                       std::uint16_t type,
                                                       const std::string &addr,
                                                       std::uint32_t ttl) const {
	std::vector<unsigned char> out;
	auto put16 = [&](std::uint16_t v) {
		out.push_back(static_cast<unsigned char>(v >> 8));
		out.push_back(static_cast<unsigned char>(v & 0xFF));
	};
	auto put32 = [&](std::uint32_t v) {
		out.push_back(static_cast<unsigned char>(v >> 24));
		out.push_back(static_cast<unsigned char>(v >> 16));
		out.push_back(static_cast<unsigned char>(v >> 8));
		out.push_back(static_cast<unsigned char>(v & 0xFF));
	};
	// Header: response, authoritative.
	put16(id);
	put16(0x8400); // flags: response + authoritative
	put16(0);      // qdcount (no question echoed for simplicity)
	put16(1);      // ancount
	put16(0);      // nscount
	put16(0);      // arcount
	// Answer: name, type, class, ttl, rdlength, rdata.
	auto nameBytes = encodeName(name);
	out.insert(out.end(), nameBytes.begin(), nameBytes.end());
	put16(type);
	// RFC 6762 §10.2: a response we own sets the cache-flush bit so the peer
	// replaces any stale record for this name instead of merging addresses.
	put16(kDnsClassIN | kDnsClassCacheFlush);
	put32(ttl);

	// Encode the address.
	if (type == kDnsTypeA) {
		struct in_addr addr4;
		if (inet_pton(AF_INET, addr.c_str(), &addr4) == 1) {
			put16(4);
			out.insert(out.end(), reinterpret_cast<unsigned char *>(&addr4),
			           reinterpret_cast<unsigned char *>(&addr4) + 4);
		}
	} else if (type == kDnsTypeAAAA) {
		struct in6_addr addr6;
		if (inet_pton(AF_INET6, addr.c_str(), &addr6) == 1) {
			put16(16);
			out.insert(out.end(), reinterpret_cast<unsigned char *>(&addr6),
			           reinterpret_cast<unsigned char *>(&addr6) + 16);
		}
	}
	return out;
}

std::string MDnsClient::parseName(const unsigned char *data, std::size_t size,
                                   std::size_t &offset) const {
	std::string name;
	std::size_t pos = offset;
	bool jumped = false;
	std::size_t jumpPos = 0;
	int jumps = 0;

	while (pos < size) {
		if (data[pos] == 0) {
			if (!jumped) offset = pos + 1;
			else offset = jumpPos;
			return name;
		}
		if ((data[pos] & 0xC0) == 0xC0) {
			// Pointer.
			if (pos + 1 >= size) break;
			if (!jumped) jumpPos = pos + 2;
			pos = ((data[pos] & 0x3F) << 8) | data[pos + 1];
			jumped = true;
			if (++jumps > 10) break; // prevent infinite loops
			continue;
		}
		// Label.
		std::size_t labelLen = data[pos];
		if (pos + 1 + labelLen > size) break;
		if (!name.empty()) name += '.';
		name.append(reinterpret_cast<const char *>(data + pos + 1), labelLen);
		pos += 1 + labelLen;
	}
	if (!jumped) offset = pos;
	return name;
}

bool MDnsClient::parseMessage(const unsigned char *data, std::size_t size, DnsHeader &hdr,
                              std::vector<DnsQuestion> &questions,
                              std::vector<DnsAnswer> &answers,
                              std::vector<DnsAnswer> &authorities) const {
	if (size < 12) return false;
	auto get16 = [&](std::size_t &off) -> std::uint16_t {
		std::uint16_t v = (data[off] << 8) | data[off + 1];
		off += 2;
		return v;
	};
	auto get32 = [&](std::size_t &off) -> std::uint32_t {
		std::uint32_t v = (std::uint32_t(data[off]) << 24) | (std::uint32_t(data[off + 1]) << 16) |
		                  (std::uint32_t(data[off + 2]) << 8) | data[off + 3];
		off += 4;
		return v;
	};

	std::size_t off = 0;
	hdr.id = get16(off);
	hdr.flags = get16(off);
	hdr.qdcount = get16(off);
	hdr.ancount = get16(off);
	hdr.nscount = get16(off);
	hdr.arcount = get16(off);

	// Parse questions.
	for (int i = 0; i < hdr.qdcount && off < size; ++i) {
		DnsQuestion q;
		q.name = parseName(data, size, off);
		if (off + 4 > size) return false;
		q.type = get16(off);
		q.qclass = get16(off);
		questions.push_back(std::move(q));
	}

	// Parse answers.
	for (int i = 0; i < hdr.ancount && off < size; ++i) {
		DnsAnswer a;
		a.name = parseName(data, size, off);
		if (off + 10 > size) return false;
		a.type = get16(off);
		a.rclass = get16(off);
		a.ttl = get32(off);
		std::uint16_t rdlength = get16(off);
		if (off + rdlength > size) return false;
		a.rdata.assign(data + off, data + off + rdlength);
		off += rdlength;
		answers.push_back(std::move(a));
	}

	// Parse authority records. mDNS uses NSEC to say "this name does not exist",
	// which lets a resolver fail fast instead of waiting out its 5 s timeout.
	for (int i = 0; i < hdr.nscount && off < size; ++i) {
		DnsAnswer a;
		a.name = parseName(data, size, off);
		if (off + 10 > size) return false;
		a.type = get16(off);
		a.rclass = get16(off);
		a.ttl = get32(off);
		std::uint16_t rdlength = get16(off);
		if (off + rdlength > size) return false;
		a.rdata.assign(data + off, data + off + rdlength);
		off += rdlength;
		authorities.push_back(std::move(a));
	}
	return true;
}

void MDnsClient::sendPendingQueries() {
	auto now = std::chrono::steady_clock::now();
	std::vector<PendingQuery> active;
	std::vector<std::pair<std::string, MDnsQueryCallback>> timedOut;
	{
		std::lock_guard<std::mutex> lk(queriesMutex_);
		// RFC 6762 §10: drop expired cache entries on every tick.
		for (auto it = cache_.begin(); it != cache_.end();) {
			if (now >= it->second.expiry) it = cache_.erase(it);
			else ++it;
		}
		for (auto it = queries_.begin(); it != queries_.end();) {
			if (now >= it->deadline) {
				timedOut.push_back({it->hostname, it->callback});
				it = queries_.erase(it);
				continue;
			}
			if (now >= it->lastSent) {
				it->lastSent = now + std::chrono::milliseconds(kQueryIntervalMs);
				active.push_back(*it);
			}
			++it;
		}
	}

	// Send queries for active entries.
	for (const auto &q : active) {
		// Send BOTH A and AAAA queries - the comment here always claimed this but
		// only the A query was ever sent, which made IPv6 (.local -> AAAA)
		// resolution impossible while the response handler already accepted both
		// record types. AAAA goes over the IPv6 transport when it exists, and
		// falls back to the IPv4 transport otherwise (the record type, not the
		// transport, selects what a responder answers).
		auto pktA = encodeQuery(q.hostname, kDnsTypeA);
		::sendto(sock_, reinterpret_cast<const char *>(pktA.data()),
		         static_cast<int>(pktA.size()), 0,
		         reinterpret_cast<const struct sockaddr *>(&mcastAddr4_),
		         sizeof(mcastAddr4_));
		auto pktAAAA = encodeQuery(q.hostname, kDnsTypeAAAA);
		if (sock6_ != STICE_INVALID_SOCKET) {
			::sendto(sock6_, reinterpret_cast<const char *>(pktAAAA.data()),
			         static_cast<int>(pktAAAA.size()), 0,
			         reinterpret_cast<const struct sockaddr *>(&mcastAddr6_),
			         sizeof(mcastAddr6_));
		} else {
			::sendto(sock_, reinterpret_cast<const char *>(pktAAAA.data()),
			         static_cast<int>(pktAAAA.size()), 0,
			         reinterpret_cast<const struct sockaddr *>(&mcastAddr4_),
			         sizeof(mcastAddr4_));
		}
	}

	// Fire timeout callbacks.
	for (auto &to : timedOut) {
		if (to.second) to.second("");
	}
}

void MDnsClient::sendRecordResponse(const std::string &name, std::uint16_t type,
                                    const std::string &addr, std::uint32_t ttl,
                                    const sockaddr *dst, bool multicast) {
	if (sock_ == STICE_INVALID_SOCKET) return;
	if (!multicast && !dst) return;
	const bool wantV6 = dst && dst->sa_family == AF_INET6;
	// An IPv6 record can still be announced over the IPv4 transport when no
	// IPv6 socket exists (the record type, not the transport, is what matters),
	// but then the destination must be the IPv4 multicast group: handing an
	// ff02::fb sockaddr to an AF_INET socket can only fail.
	const bool useV6 = wantV6 && sock6_ != STICE_INVALID_SOCKET;
	socket_t s = useV6 ? sock6_ : sock_;
	auto resp = encodeResponse(0, name, type, addr, ttl);
	if (multicast) {
		if (useV6) {
			::sendto(s, reinterpret_cast<const char *>(resp.data()),
			         static_cast<int>(resp.size()), 0,
			         reinterpret_cast<const struct sockaddr *>(&mcastAddr6_),
			         sizeof(mcastAddr6_));
		} else {
			::sendto(s, reinterpret_cast<const char *>(resp.data()),
			         static_cast<int>(resp.size()), 0,
			         reinterpret_cast<const struct sockaddr *>(&mcastAddr4_),
			         sizeof(mcastAddr4_));
		}
		return;
	}
	if (wantV6 && !useV6) return; // no IPv6 transport to answer this querier on
	const int dstLen = useV6 ? static_cast<int>(sizeof(sockaddr_in6))
	                         : static_cast<int>(sizeof(sockaddr_in));
	::sendto(s, reinterpret_cast<const char *>(resp.data()), static_cast<int>(resp.size()), 0,
	         dst, dstLen);
}

void MDnsClient::sendGoodbyes() {
	std::map<std::string, std::string> snapshot;
	{
		std::lock_guard<std::mutex> lk(recordsMutex_);
		snapshot = records_;
	}
	for (const auto &kv : snapshot) {
		const bool v6 = kv.second.find(':') != std::string::npos;
		std::uint16_t type = v6 ? kDnsTypeAAAA : kDnsTypeA;
		const sockaddr *dst = v6
			? reinterpret_cast<const sockaddr *>(&mcastAddr6_)
			: reinterpret_cast<const sockaddr *>(&mcastAddr4_);
		sendRecordResponse(kv.first, type, kv.second, 0, dst, true);
	}
}

// Definition; the contract lives in mdns.hpp (it is exposed so it can be
// unit-tested). This client's transport is IPv4 (224.0.0.251) today, so the
// IPv6 branch is defence in depth: it keeps the check correct if an
// IPv6/dual-stack mDNS socket is added later, and it closes the hole where any
// family other than AF_INET used to be accepted unconditionally.
bool mdnsSourceIsPlausible(const sockaddr_storage &ss) {
	if (ss.ss_family == AF_INET) {
		const auto *a4 = reinterpret_cast<const sockaddr_in *>(&ss);
		const std::uint32_t s = ntohl(a4->sin_addr.s_addr);
		if (s == 0u) return false;                            // 0.0.0.0 unspecified
		// 224.0.0.0/3 covers the multicast block (224/4) AND the reserved class E
		// block (240/4, which contains the limited broadcast 255.255.255.255).
		// Neither can be a unicast host address, so a packet claiming to come
		// from one is never a real mDNS answer.
		if ((s & 0xE0000000u) == 0xE0000000u) return false;
		return true;
	}
	if (ss.ss_family == AF_INET6) {
		const auto *a6 = reinterpret_cast<const sockaddr_in6 *>(&ss);
		const unsigned char *b = a6->sin6_addr.s6_addr;
		if (b[0] == 0xFF) return false; // ff00::/8 multicast (includes ff02::fb)
		bool allZero = true;
		for (int i = 0; i < 16; ++i) {
			if (b[i] != 0) { allZero = false; break; }
		}
		if (allZero) return false;      // :: unspecified
		// IPv4-embedded IPv6 forms carry a v4 address, so the v4 rules apply to
		// it: ::ffff:a.b.c.d (IPv4-mapped) and the deprecated IPv4-compatible
		// ::a.b.c.d. Without this a peer on a dual-stack socket could smuggle in
		// exactly the sources the AF_INET branch rejects.
		const bool v4Compat = (b[10] == 0x00 && b[11] == 0x00);
		const bool v4Mapped = (b[10] == 0xFF && b[11] == 0xFF);
		bool v4Embedded = (v4Compat || v4Mapped);
		for (int i = 0; i < 10 && v4Embedded; ++i) {
			if (b[i] != 0) v4Embedded = false;
		}
		if (v4Embedded) {
			const std::uint32_t s = (static_cast<std::uint32_t>(b[12]) << 24) |
			                        (static_cast<std::uint32_t>(b[13]) << 16) |
			                        (static_cast<std::uint32_t>(b[14]) << 8) |
			                        static_cast<std::uint32_t>(b[15]);
			if (s == 0u) return false;                            // embeds 0.0.0.0
			if ((s & 0xE0000000u) == 0xE0000000u) return false;    // embeds 224.0.0.0/3
		}
		return true;
	}
	return false; // unknown family: never a valid mDNS source
}

void MDnsClient::run() {
	unsigned char buf[9000];
	while (running_) {
		// Poll both transports (IPv4 always, IPv6 when available) with a 100 ms
		// timeout. RFC 6762 answers for AAAA arrive on ff02::fb, so listening only
		// on 224.0.0.251 made IPv6 resolution structurally impossible.
		socket_t ready = STICE_INVALID_SOCKET;
#ifdef _WIN32
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(sock_, &fds);
		socket_t maxFd = sock_;
		if (sock6_ != STICE_INVALID_SOCKET) {
			FD_SET(sock6_, &fds);
			if (sock6_ > maxFd) maxFd = sock6_;
		}
		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 100 * 1000;
		int n = ::select(static_cast<int>(maxFd + 1), &fds, nullptr, nullptr, &tv);
		if (n <= 0) {
			sendPendingQueries();
			continue;
		}
		if (FD_ISSET(sock_, &fds)) ready = sock_;
		else if (sock6_ != STICE_INVALID_SOCKET && FD_ISSET(sock6_, &fds)) ready = sock6_;
#else
		struct pollfd pfds[2];
		pfds[0].fd = sock_;
		pfds[0].events = POLLIN;
		pfds[0].revents = 0;
		nfds_t cnt = 1;
		if (sock6_ != STICE_INVALID_SOCKET) {
			pfds[1].fd = sock6_;
			pfds[1].events = POLLIN;
			pfds[1].revents = 0;
			cnt = 2;
		}
		int n = ::poll(pfds, cnt, 100);
		if (n <= 0) {
			sendPendingQueries();
			continue;
		}
		if (pfds[0].revents & POLLIN) ready = sock_;
		else if (cnt == 2 && (pfds[1].revents & POLLIN)) ready = sock6_;
#endif
		if (ready == STICE_INVALID_SOCKET) {
			sendPendingQueries();
			continue;
		}

		sockaddr_storage src{};
		socklen_t srcLen = sizeof(src);
		int len = ::recvfrom(ready, reinterpret_cast<char *>(buf), sizeof(buf), 0,
		                     reinterpret_cast<struct sockaddr *>(&src), &srcLen);
		if (len <= 0) {
			sendPendingQueries();
			continue;
		}

		// Source sanity check before parsing. See mdnsSourceIsPlausible(): it
		// covers both address families (and rejects an unknown family), so a
		// packet from an impossible sender is dropped up front rather than being
		// matched against a pending query purely by its answer name.
		if (!mdnsSourceIsPlausible(src)) {
			STICE_LOG_DEBUG("mDNS: ignoring packet from invalid source");
			continue;
		}

		DnsHeader hdr;
		std::vector<DnsQuestion> questions;
		std::vector<DnsAnswer> answers;
		std::vector<DnsAnswer> authorities;
		if (!parseMessage(buf, static_cast<std::size_t>(len), hdr, questions, answers,
		                  authorities)) {
			continue;
		}

		// Process answers (response to our queries).
		if (!answers.empty()) {
			// Collect the completed callbacks under the lock, then fire them
			// AFTER releasing queriesMutex_. A callback runs on this mDNS thread
			// and locks the ICE agent's mutex; the agent, in turn, calls
			// query() (which takes queriesMutex_) while holding its own mutex_.
			// Invoking the callback with queriesMutex_ held would create the
			// reverse lock order (agent mutex_ -> queriesMutex_ vs
			// queriesMutex_ -> agent mutex_) and deadlock (AB-BA) as soon as
			// both sides resolve an mDNS candidate at the same time.
			const auto now = std::chrono::steady_clock::now();
			std::vector<std::pair<MDnsQueryCallback, std::string>> resolved;
			{
				std::lock_guard<std::mutex> lk(queriesMutex_);
				for (const auto &ans : answers) {
					if (ans.type != kDnsTypeA && ans.type != kDnsTypeAAAA) continue;
					// Normalize the answer name (strip trailing dot, lowercase).
					std::string name = ans.name;
					if (!name.empty() && name.back() == '.') name.pop_back();
					std::transform(name.begin(), name.end(), name.begin(),
					               [](unsigned char c) { return std::tolower(c); });

					// Extract the IP address.
					std::string addr;
					if (ans.type == kDnsTypeA && ans.rdata.size() == 4) {
						char ipbuf[INET_ADDRSTRLEN];
						struct in_addr addr4;
						std::memcpy(&addr4, ans.rdata.data(), 4);
						inet_ntop(AF_INET, &addr4, ipbuf, sizeof(ipbuf));
						addr = ipbuf;
					} else if (ans.type == kDnsTypeAAAA && ans.rdata.size() == 16) {
						char ipbuf[INET6_ADDRSTRLEN];
						struct in6_addr addr6;
						std::memcpy(&addr6, ans.rdata.data(), 16);
						inet_ntop(AF_INET6, &addr6, ipbuf, sizeof(ipbuf));
						addr = ipbuf;
					}
					if (addr.empty()) continue;

					// RFC 6762 §10.1: a TTL-0 answer is a goodbye (the record is
					// withdrawn), not a resolution. Drop the cached entry and do
					// not complete a pending query with it.
					if (ans.ttl == 0) {
						cache_.erase(name);
						continue;
					}

					// Find matching pending queries.
					for (auto it = queries_.begin(); it != queries_.end();) {
						if (lowerName(it->hostname) == name) {
							if (it->callback) {
								resolved.emplace_back(std::move(it->callback), addr);
							}
							it = queries_.erase(it);
						} else {
							++it;
						}
					}
					// RFC 6762 §10: cache the answer for its advertised TTL.
					auto ttl = std::chrono::seconds(ans.ttl);
					cache_[name] = CachedAnswer{addr, now + ttl};
				}
			}
			for (auto &r : resolved) {
				if (r.first) r.first(r.second);
			}
		}

		// Process NSEC authority records: an explicit "no such name" lets a
		// pending query fail immediately instead of waiting out the 5 s timeout
		// (RFC 6762 §6.1 negative responses).
		if (!authorities.empty()) {
			std::vector<MDnsQueryCallback> negatives;
			{
				std::lock_guard<std::mutex> lk(queriesMutex_);
				for (const auto &auth : authorities) {
					if (auth.type != kDnsTypeNSEC) continue;
					std::string name = lowerName(auth.name);
					if (!name.empty() && name.back() == '.') name.pop_back();
					for (auto it = queries_.begin(); it != queries_.end();) {
						if (lowerName(it->hostname) == name) {
							if (it->callback) negatives.push_back(std::move(it->callback));
							it = queries_.erase(it);
						} else {
							++it;
						}
					}
				}
			}
			for (auto &cb : negatives) {
				if (cb) cb("");
			}
		}

		// Process questions (respond to queries for any registered name).
		if (mode_ == MulticastDNSMode::QueryAndGather && !questions.empty()) {
			for (const auto &q : questions) {
				if (q.type != kDnsTypeA && q.type != kDnsTypeAAAA) continue;
				// Normalize the query name.
				std::string qName = q.name;
				if (!qName.empty() && qName.back() == '.') qName.pop_back();
				qName = lowerName(qName);

				std::string answer;
				{
					std::lock_guard<std::mutex> lk(recordsMutex_);
					auto it = records_.find(qName);
					if (it == records_.end()) continue;
					answer = it->second;
				}

				// Check if the registered address matches the query type.
				struct in_addr addr4;
				struct in6_addr addr6;
				if (q.type == kDnsTypeA) {
					if (inet_pton(AF_INET, answer.c_str(), &addr4) != 1) continue;
				} else {
					if (inet_pton(AF_INET6, answer.c_str(), &addr6) != 1) continue;
				}

				// Send the answer with the cache-flush bit set and a normal TTL.
				auto resp = encodeResponse(hdr.id, qName + ".", q.type, answer, kResponseTTL);
				// Answer on the transport the query arrived on: an IPv6 querier
				// (ff02::fb) cannot be reached through the IPv4 group, and vice
				// versa. A non-IPv4/IPv6 source is impossible here (filtered by
				// mdnsSourceIsPlausible), so anything else is skipped.
				socket_t outSock = sock_;
				sockaddr_storage dst{};
				int dstLen = 0;
				bool multicastAnswer = false;
				if (src.ss_family == AF_INET) {
					dst = src;
					const auto *s4 = reinterpret_cast<const sockaddr_in *>(&src);
					// RFC 6762 §5.4 / §6.7: honour the QU (unicast-response) bit
					// and answer legacy unicast queries (source port != 5353)
					// directly; a normal multicast query gets a multicast answer.
					const bool wantUnicast =
						(q.qclass & 0x8000) != 0 || ntohs(s4->sin_port) != kMDnsPort;
					dstLen = static_cast<int>(sizeof(sockaddr_in));
					if (!wantUnicast) {
						std::memcpy(&dst, &mcastAddr4_, sizeof(mcastAddr4_));
						multicastAnswer = true;
					}
				} else if (src.ss_family == AF_INET6 && sock6_ != STICE_INVALID_SOCKET) {
					dst = src;
					const auto *s6 = reinterpret_cast<const sockaddr_in6 *>(&src);
					const bool wantUnicast =
						(q.qclass & 0x8000) != 0 || ntohs(s6->sin6_port) != kMDnsPort;
					outSock = sock6_;
					dstLen = static_cast<int>(sizeof(sockaddr_in6));
					if (!wantUnicast) {
						std::memcpy(&dst, &mcastAddr6_, sizeof(mcastAddr6_));
						multicastAnswer = true;
					}
				} else {
					continue;
				}
				::sendto(outSock, reinterpret_cast<const char *>(resp.data()),
				         static_cast<int>(resp.size()), 0,
				         reinterpret_cast<const struct sockaddr *>(&dst), dstLen);
				STICE_LOG_DEBUG("mDNS: responded to %s query for %s with %s (%s)",
				               multicastAnswer ? "multicast" : "unicast",
				               qName.c_str(), answer.c_str(),
				               src.ss_family == AF_INET6 ? "IPv6" : "IPv4");
			}
		}

		// Periodically retransmit pending queries.
		sendPendingQueries();
	}
}

} // namespace stice::net
