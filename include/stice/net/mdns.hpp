// SPDX-License-Identifier: MPL-2.0
// stice mDNS (Multicast DNS) client.
// Ported from pion-mdns and pion-ice/mdns.go.
//
// Supports three modes (aligned with pion's MulticastDNSMode):
//   - Disabled: no mDNS (remote .local candidates are discarded)
//   - QueryOnly: resolve remote .local candidates via mDNS, but advertise IPs
//   - QueryAndGather: resolve remote .local AND advertise local host candidates
//     with an mDNS hostname (UUID.local) instead of IP addresses
//
// The mDNS client joins the IPv4 multicast group 224.0.0.251:5353 and listens
// for queries. When a query matches our local hostname, it responds with the
// local IP address. It also sends queries to resolve remote .local hostnames.

#ifndef STICE_NET_MDNS_HPP
#define STICE_NET_MDNS_HPP

#include "stice/net/addr.hpp"
#include "stice/net/platform.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace stice::net {

enum class MulticastDNSMode {
	Disabled = 1,
	QueryOnly = 2,
	QueryAndGather = 3,
};

// mDNS query result callback.
// Called on the mDNS thread when a query completes (success or timeout).
// address is empty on failure/timeout.
using MDnsQueryCallback = std::function<void(const std::string &address)>;

class MDnsClient {
public:
	MDnsClient();
	~MDnsClient();

	// Initialize the mDNS client.
	// mode: the mDNS mode.
	// hostname: the local mDNS hostname (e.g. "uuid.local"). If empty, one is generated.
	// localAddr: the local IP to advertise in responses (for QueryAndGather).
	// Returns false on failure (e.g. could not bind multicast socket).
	bool init(MulticastDNSMode mode, const std::string &hostname,
	          const std::string &localAddr);

	// Query a remote mDNS hostname. Calls cb on completion (from the mDNS thread).
	// Returns false if the client is not initialized or the mode is Disabled.
	bool query(const std::string &hostname, MDnsQueryCallback cb);

	// Check if a hostname is an mDNS name (ends with ".local").
	static bool isMDnsName(const std::string &hostname);

	// Generate a random mDNS hostname (UUID v4 + ".local").
	static std::string generateHostname();

	MulticastDNSMode mode() const { return mode_; }
	const std::string &hostname() const { return hostname_; }

	void stop();

private:
	// DNS message structures (simplified).
	struct DnsHeader {
		std::uint16_t id;
		std::uint16_t flags;
		std::uint16_t qdcount;
		std::uint16_t ancount;
		std::uint16_t nscount;
		std::uint16_t arcount;
	};

	struct DnsQuestion {
		std::string name;
		std::uint16_t type;   // A=1, AAAA=28
		std::uint16_t qclass; // IN=1, with unicast bit = 0x8001
	};

	struct DnsAnswer {
		std::string name;
		std::uint16_t type;
		std::uint16_t rclass;
		std::uint32_t ttl;
		std::vector<unsigned char> rdata;
	};

	// Encode a DNS query message.
	std::vector<unsigned char> encodeQuery(const std::string &name, std::uint16_t type) const;
	// Encode a DNS response message.
	std::vector<unsigned char> encodeResponse(std::uint16_t id, const std::string &name,
	                                          std::uint16_t type,
	                                          const std::string &addr) const;
	// Parse a DNS message. Returns true on success.
	bool parseMessage(const unsigned char *data, std::size_t size, DnsHeader &hdr,
	                  std::vector<DnsQuestion> &questions,
	                  std::vector<DnsAnswer> &answers) const;
	// Parse a DNS name at the given offset. Returns the name and the new offset.
	std::string parseName(const unsigned char *data, std::size_t size, std::size_t &offset) const;
	// Encode a DNS name (labels).
	std::vector<unsigned char> encodeName(const std::string &name) const;

	// Background thread: reads from the multicast socket, processes queries and responses.
	void run();

	// Send a multicast query for all pending queries.
	void sendPendingQueries();

	MulticastDNSMode mode_ = MulticastDNSMode::Disabled;
	std::string hostname_; // e.g. "uuid.local"
	std::string hostnameDot_; // "uuid.local." (with trailing dot)
	std::string localAddr_; // local IP for responses

	socket_t sock_ = STICE_INVALID_SOCKET;
	std::atomic<bool> running_{false};
	std::thread thread_;

	// Pending queries: hostname -> list of callbacks.
	struct PendingQuery {
		std::string hostname;
		MDnsQueryCallback callback;
		std::chrono::steady_clock::time_point deadline;
		std::chrono::steady_clock::time_point lastSent;
	};
	std::mutex queriesMutex_;
	std::vector<PendingQuery> queries_;

	// Multicast destination.
	sockaddr_in mcastAddr4_{};
};

} // namespace stice::net

#endif
