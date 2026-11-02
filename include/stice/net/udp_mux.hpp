// SPDX-License-Identifier: MPL-2.0
// stice UDPMux: multiplexes multiple ICE agents over a single shared UDP
// socket. Ported from pion-ice's udp_mux.go / udp_muxed_conn.go.
//
// The UDPMux owns one UdpSocket and is itself a PollParticipant. Incoming
// packets are routed to the correct agent by a two-level lookup:
//   1. Fast path: source-address → agent (covers established pairs and
//      non-STUN application data).
//   2. Slow path: STUN USERNAME → local ufrag → agent (used only for the
//      first packet from a new source that is a STUN Binding Request).
//
// When an agent sends through the mux, the destination address is registered
// in the address map so that subsequent packets from that address take the
// fast path (no STUN parsing). The address map only ever holds REMOTE
// addresses. Loopback packets (an agent sending to the mux's own address,
// as happens when several agents on the same host share one mux) are
// attributed to their sender per packet via loopbackPending_: each loopback
// non-STUN send enqueues (send-time, sender) and the matching recvfrom pairs
// FIFO, so concurrent senders cannot misattribute each other's in-flight
// packets. Mixing loopback attribution into the address map (a single "last
// sender" slot) let a STUN fast-path registration write the DESTINATION agent
// under the mux's own key and misattribute loopback sends after a restart.

#ifndef STICE_NET_UDP_MUX_HPP
#define STICE_NET_UDP_MUX_HPP

#include "stice/net/addr.hpp"
#include "stice/net/platform.hpp"
#include "stice/net/poll.hpp"
#include "stice/net/udp.hpp"

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace stice::net {

// Per-agent registration entry inside the UDPMux.
struct MuxAgentEntry {
	std::string ufrag;
	// Called from the poll thread when a packet arrives for this agent.
	std::function<void(const char *data, int len, const AddrRecord &src)> onPacket;
	// Called from the poll thread during each bookkeeping pass.
	std::function<void(int64_t nowMs)> onBookkeeping;
	// Called from the poll thread to query the next timer timestamp.
	std::function<int64_t()> nextTimestampMs;
	// Remote addresses this agent has sent to (for fast-path routing and
	// cleanup on removal).
	std::vector<std::string> remoteAddressKeys;
};

class UDPMux : public PollParticipant {
public:
	UDPMux();
	~UDPMux();

	UDPMux(const UDPMux &) = delete;
	UDPMux &operator=(const UDPMux &) = delete;

	// Initialize the shared UDP socket. Returns false on failure.
	bool init(const UdpSocketConfig &cfg);

	// Register an agent by its local ufrag. The callbacks are invoked from
	// the poll thread. Must be called before gatherCandidates.
	void registerAgent(const std::string &ufrag,
	                   std::function<void(const char *, int, const AddrRecord &)> onPacket,
	                   std::function<void(int64_t)> onBookkeeping,
	                   std::function<int64_t()> nextTimestampMs);

	// Remove an agent by ufrag. Also removes all address-map entries that
	// point to this agent.
	void removeAgent(const std::string &ufrag);

	// Send a packet via the shared socket. Also registers the destination
	// address in the address map for fast-path routing of replies.
	int sendto(const char *data, std::size_t size, const AddrRecord &dst,
	           const std::string &ufrag);

	// Enumerate local addresses (for host candidate gathering).
	std::vector<AddrRecord> localAddrs(int family = AF_UNSPEC) const;

	// Get the bound address of the shared socket.
	bool boundAddr(AddrRecord &out) const;

	// Set DSCP on the shared socket.
	int setDiffserv(int ds);
	// Atomic set -> send -> reset of the DSCP/TOS window on the shared socket.
	// Serialized on the socket, so concurrent agents cannot interleave their
	// per-socket TOS state. ds < 0 means "leave TOS alone". ufrag attributes
	// loopback sends (same discipline as sendto) and registers the remote
	// destination for fast-path routing; without it, app data sent by muxed
	// agents would never refresh the loopback sender attribution.
	int sendtoWithDiffserv(const char *data, std::size_t size, const AddrRecord &dst, int ds,
	                       const std::string &ufrag);

	// Get the shared socket handle (for logging only).
	socket_t socketHandle() const { return sock_.valid() ? sock_.handle() : STICE_INVALID_SOCKET; }

	// Wake the mux's poll thread so it re-evaluates timers immediately.
	// Called by registered agents when they arm new timers from within
	// onPacket/onBookkeeping callbacks.
	void interrupt();

	// --- PollParticipant interface ---
	socket_t udpSocket() const override { return sock_.valid() ? sock_.handle() : STICE_INVALID_SOCKET; }
	bool hasTcp() const override { return false; }
	socket_t tcpSocket() const override { return STICE_INVALID_SOCKET; }
	short tcpDesiredEvents() const override { return 0; }
	int64_t nextTimestampMs() const override;
	void onUdpReadable() override;
	void onTcpEvents(short) override {}
	void onBookkeeping(int64_t nowMs) override;

private:
	// Route a received packet to the correct agent.
	void routePacket(const char *buf, int len, const AddrRecord &src);

	// True when dst is the mux's own bound address (loopback). Compared by
	// port only since the mux may bind to 0.0.0.0.
	bool isLoopbackDst(const AddrRecord &dst) const;

	// Build a canonical key for an address (host:port).
	static std::string addrKey(const AddrRecord &addr);

	UdpSocket sock_;
	mutable std::mutex mutex_;

	// ufrag → agent entry.
	std::unordered_map<std::string, std::shared_ptr<MuxAgentEntry>> agentsByUfrag_;

	// source-address-key → agent entry (fast path). Remote addresses only.
	std::unordered_map<std::string, std::shared_ptr<MuxAgentEntry>> agentsByAddr_;

	// Per-packet sender attribution for loopback app data. A global "last
	// sender" is wrong when two muxed agents send concurrently: the first
	// sender's packet is still in flight when the second sender overwrites
	// the attribution, so the first packet gets broadcast as if the second
	// agent sent it — permanently excluding a sibling from delivery. Instead
	// every loopback non-STUN send enqueues (send-time, sender) and the
	// matching recvfrom dequeues the head: a single shared UDP socket
	// delivers loopback datagrams in send order, so the queue head IS the
	// in-flight packet's sender. Entries older than the window are dropped
	// as a safety valve. Entries for removed agents are purged.
	struct LoopbackSend {
		std::chrono::steady_clock::time_point sent;
		std::shared_ptr<MuxAgentEntry> sender;
	};
	std::deque<LoopbackSend> loopbackPending_;

	// Per-mux PollRegistry instance (per-agent independent thread model).
	PollRegistry *pollReg_ = nullptr;
};

} // namespace stice::net

#endif // STICE_NET_UDP_MUX_HPP
