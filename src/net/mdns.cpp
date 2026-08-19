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
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace stice::net {

namespace {
// mDNS multicast address and port.
constexpr const char *kMDnsMulticastAddr4 = "224.0.0.251";
constexpr std::uint16_t kMDnsPort = 5353;
constexpr std::uint16_t kDnsTypeA = 1;
constexpr std::uint16_t kDnsTypeAAAA = 28;
constexpr std::uint16_t kDnsClassIN = 1;
constexpr std::uint16_t kDnsClassINUnicast = 0x8001; // IN with unicast-response bit
constexpr int kQueryIntervalMs = 1000;
constexpr int kQueryTimeoutMs = 5000;
constexpr std::uint32_t kResponseTTL = 120;
} // namespace

MDnsClient::MDnsClient() = default;

MDnsClient::~MDnsClient() {
	stop();
}

bool MDnsClient::init(MulticastDNSMode mode, const std::string &hostname,
                      const std::string &localAddr) {
	mode_ = mode;
	if (mode == MulticastDNSMode::Disabled) return true;

	if (hostname.empty()) {
		hostname_ = generateHostname();
	} else {
		hostname_ = hostname;
	}
	hostnameDot_ = hostname_ + ".";
	localAddr_ = localAddr;

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
#ifdef _WIN32
	u_long nbio = 1;
	ioctlsocket(sock_, FIONBIO, &nbio);
#else
	int nbio = 1;
	ioctl(sock_, FIONBIO, &nbio);
#endif

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

	running_ = true;
	thread_ = std::thread([this] { run(); });

	STICE_LOG_INFO("mDNS: initialized mode=%d hostname=%s localAddr=%s",
	               static_cast<int>(mode_), hostname_.c_str(), localAddr_.c_str());
	return true;
}

void MDnsClient::stop() {
	if (!running_.exchange(false)) return;
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
	if (thread_.joinable()) thread_.join();
}

bool MDnsClient::isMDnsName(const std::string &hostname) {
	// Case-insensitive check for ".local" suffix.
	if (hostname.size() < 6) return false; // "x.local" minimum
	auto pos = hostname.rfind(".local");
	if (pos == std::string::npos) return false;
	// Must end with ".local" or ".local."
	if (pos + 6 == hostname.size()) return true;
	if (pos + 7 == hostname.size() && hostname[pos + 6] == '.') return true;
	return false;
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
                                                       const std::string &addr) const {
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
	put16(kDnsClassIN);
	put32(kResponseTTL);

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
                              std::vector<DnsAnswer> &answers) const {
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
	return true;
}

void MDnsClient::sendPendingQueries() {
	auto now = std::chrono::steady_clock::now();
	std::vector<PendingQuery> active;
	std::vector<std::pair<std::string, MDnsQueryCallback>> timedOut;
	{
		std::lock_guard<std::mutex> lk(queriesMutex_);
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
		// Send both A and AAAA queries.
		auto pkt = encodeQuery(q.hostname, kDnsTypeA);
		::sendto(sock_, reinterpret_cast<const char *>(pkt.data()), static_cast<int>(pkt.size()), 0,
		         reinterpret_cast<const struct sockaddr *>(&mcastAddr4_), sizeof(mcastAddr4_));
	}

	// Fire timeout callbacks.
	for (auto &to : timedOut) {
		if (to.second) to.second("");
	}
}

void MDnsClient::run() {
	unsigned char buf[9000];
	while (running_) {
		// Poll for readable data with a 100ms timeout.
#ifdef _WIN32
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(sock_, &fds);
		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 100 * 1000;
		int n = ::select(0, &fds, nullptr, nullptr, &tv);
		if (n <= 0) {
			// Timeout or error — do query retransmission.
			sendPendingQueries();
			continue;
		}
#else
		struct pollfd pfd;
		pfd.fd = sock_;
		pfd.events = POLLIN;
		pfd.revents = 0;
		int n = ::poll(&pfd, 1, 100);
		if (n <= 0) {
			sendPendingQueries();
			continue;
		}
#endif

		sockaddr_in src{};
		socklen_t srcLen = sizeof(src);
		int len = ::recvfrom(sock_, reinterpret_cast<char *>(buf), sizeof(buf), 0,
		                     reinterpret_cast<struct sockaddr *>(&src), &srcLen);
		if (len <= 0) {
			sendPendingQueries();
			continue;
		}

		DnsHeader hdr;
		std::vector<DnsQuestion> questions;
		std::vector<DnsAnswer> answers;
		if (!parseMessage(buf, static_cast<std::size_t>(len), hdr, questions, answers)) {
			continue;
		}

		// Process answers (response to our queries).
		if (!answers.empty()) {
			std::lock_guard<std::mutex> lk(queriesMutex_);
			for (const auto &ans : answers) {
				if (ans.type != kDnsTypeA && ans.type != kDnsTypeAAAA) continue;
				// Normalize the answer name (strip trailing dot, lowercase).
				std::string name = ans.name;
				if (!name.empty() && name.back() == '.') name.pop_back();
				std::transform(name.begin(), name.end(), name.begin(),
				               [](unsigned char c) { return std::tolower(c); });

				// Find matching pending queries.
				for (auto it = queries_.begin(); it != queries_.end();) {
					std::string qName = it->hostname;
					std::transform(qName.begin(), qName.end(), qName.begin(),
					               [](unsigned char c) { return std::tolower(c); });
					if (qName == name) {
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
						if (!addr.empty() && it->callback) {
							it->callback(addr);
						}
						it = queries_.erase(it);
					} else {
						++it;
					}
				}
			}
		}

		// Process questions (respond to queries for our hostname).
		if (mode_ == MulticastDNSMode::QueryAndGather && !questions.empty()) {
			for (const auto &q : questions) {
				if (q.type != kDnsTypeA && q.type != kDnsTypeAAAA) continue;
				// Normalize the query name.
				std::string qName = q.name;
				if (!qName.empty() && qName.back() == '.') qName.pop_back();
				std::transform(qName.begin(), qName.end(), qName.begin(),
				               [](unsigned char c) { return std::tolower(c); });
				std::string myName = hostname_;
				std::transform(myName.begin(), myName.end(), myName.begin(),
				               [](unsigned char c) { return std::tolower(c); });
				if (qName != myName) continue;

				// Check if our local address matches the query type.
				bool isIPv4 = (q.type == kDnsTypeA);
				struct in_addr addr4;
				struct in6_addr addr6;
				bool addrMatches = false;
				if (isIPv4) {
					if (inet_pton(AF_INET, localAddr_.c_str(), &addr4) == 1) {
						addrMatches = true;
					}
				} else {
					if (inet_pton(AF_INET6, localAddr_.c_str(), &addr6) == 1) {
						addrMatches = true;
					}
				}
				if (!addrMatches) continue;

				// Send response to the multicast group (or unicast to the querier).
				auto resp = encodeResponse(hdr.id, hostnameDot_, q.type, localAddr_);
				sockaddr_in dst = src;
				// If the querier used the standard mDNS port, respond via multicast;
				// otherwise respond unicast.
				if (ntohs(src.sin_port) == kMDnsPort) {
					dst = mcastAddr4_;
				}
				::sendto(sock_, reinterpret_cast<const char *>(resp.data()),
				         static_cast<int>(resp.size()), 0,
				         reinterpret_cast<const struct sockaddr *>(&dst), sizeof(dst));
				STICE_LOG_DEBUG("mDNS: responded to query for %s with %s",
				               hostname_.c_str(), localAddr_.c_str());
			}
		}

		// Periodically retransmit pending queries.
		sendPendingQueries();
	}
}

} // namespace stice::net
