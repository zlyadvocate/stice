// SPDX-License-Identifier: MPL-2.0
// stice TCPMux: multiplexes multiple ICE agents over a single shared TCP
// listener socket (RFC 6544 tcp-passive). Ported conceptually from
// pion-ice's tcp_mux.go / tcp_packet_conn.go.
//
// The TCPMux owns one TCP listener and is itself a PollParticipant. When
// the poll loop reports the listener readable, TCPMux::onAccept() accepts
// the new connection, wraps it in a TcpMuxConn (which is its own
// PollParticipant), and registers it with the PollRegistry.
//
// Each TcpMuxConn reads the first STUN Binding Request, extracts the
// USERNAME attribute's local ufrag, and routes the connection + first
// packet to the matching agent. Subsequent frames are delivered directly
// to the agent's onPacket callback.

#ifndef STICE_NET_TCP_MUX_HPP
#define STICE_NET_TCP_MUX_HPP

#include "stice/net/addr.hpp"
#include "stice/net/platform.hpp"
#include "stice/net/poll.hpp"
#include "stice/net/tcp.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace stice::net {

class TCPMux;

// Maximum number of pending (not-yet-established) TCP connections. Prevents
// a flood of malicious inbound connections from exhausting memory/FDs.
// Aligned with str0m #641.
constexpr std::size_t MaxPendingTcpMuxConns = 64;

// Per-agent registration entry inside the TCPMux.
struct TcpMuxAgentEntry {
	std::string ufrag;
	// Called from the poll thread when a packet arrives for this agent
	// over an established TCP connection.
	std::function<void(const char *data, int len, const AddrRecord &src)> onPacket;
	// Called from the poll thread during each bookkeeping pass.
	std::function<void(int64_t nowMs)> onBookkeeping;
	// Called from the poll thread to query the next timer timestamp.
	std::function<int64_t()> nextTimestampMs;
};

// A single accepted TCP connection within the TCPMux. Each connection is
// its own PollParticipant so the PollRegistry polls it for read events.
//
// Lifecycle:
//   1. Created by TCPMux::onAccept in "pending" state.
//   2. Registered with PollRegistry (hasTcp=true).
//   3. onTcpEvents reads the first STUN Binding Request, extracts the
//      local ufrag from USERNAME, and calls TCPMux::onConnEstablished.
//   4. TCPMux finds the matching agent and sets it on this conn.
//   5. Subsequent onTcpEvents calls read RFC 4571-framed packets and
//      deliver them to the agent's onPacket callback.
//   6. When the connection closes (recv==0 or error), the conn marks
//      itself closed, unregisters from PollRegistry, and notifies TCPMux.
//   7. TCPMux cleans up the shared_ptr during the next onBookkeeping.
class TcpMuxConn : public PollParticipant {
public:
	TcpMuxConn(socket_t fd, const AddrRecord &peerAddr, TCPMux *mux);
	~TcpMuxConn();

	TcpMuxConn(const TcpMuxConn &) = delete;
	TcpMuxConn &operator=(const TcpMuxConn &) = delete;

	// --- PollParticipant interface ---
	socket_t udpSocket() const override { return STICE_INVALID_SOCKET; }
	bool hasTcp() const override { return transport_ != nullptr; }
	socket_t tcpSocket() const override;
	short tcpDesiredEvents() const override;
	void onTcpEvents(short events) override;
	int64_t nextTimestampMs() const override { return 0; }
	void onUdpReadable() override {}
	void onBookkeeping(int64_t /*nowMs*/) override {}

	// Send a packet (RFC 4571 framed) over this connection.
	int send(const char *data, std::size_t size);

	// Close the connection and mark as closed.
	void close() {
		if (transport_) transport_->close();
		closed_ = true;
	}

	const AddrRecord &peerAddr() const { return peerAddr_; }
	bool isEstablished() const { return established_; }
	bool isClosed() const { return closed_; }
	const std::string &ufrag() const { return ufrag_; }

	// Called by TCPMux after matching the ufrag to an agent.
	void setAgent(std::shared_ptr<TcpMuxAgentEntry> agent) {
		agent_ = std::move(agent);
		established_ = true;
	}

private:
	// Try to read the first STUN packet and extract the ufrag.
	void tryReadFirstPacket();
	// Read and dispatch all available framed packets (established mode).
	void driveData();

	TCPMux *mux_;
	std::unique_ptr<TcpTransport> transport_;
	AddrRecord peerAddr_;
	bool established_ = false;
	bool closed_ = false;
	std::string ufrag_;
	std::shared_ptr<TcpMuxAgentEntry> agent_;
	std::chrono::steady_clock::time_point acceptedAt_;

	friend class TCPMux;
};

class TCPMux : public PollParticipant {
public:
	TCPMux();
	~TCPMux();

	TCPMux(const TCPMux &) = delete;
	TCPMux &operator=(const TCPMux &) = delete;

	// Create the TCP listener on the given bind address and port. If
	// bindAddress is empty or port is 0, binds to INADDR_ANY:ephemeral.
	// Returns false on failure.
	bool init(const std::string &bindAddress, std::uint16_t port);

	// Register an agent by its local ufrag. Must be called before
	// gatherCandidates. The callbacks are invoked from the poll thread.
	void registerAgent(const std::string &ufrag,
	                   std::function<void(const char *, int, const AddrRecord &)> onPacket,
	                   std::function<void(int64_t)> onBookkeeping,
	                   std::function<int64_t()> nextTimestampMs);

	// Remove an agent by ufrag. Closes all connections associated with
	// this agent.
	void removeAgent(const std::string &ufrag);

	// Send a packet to `dst` over the established TCP connection for that
	// remote address. Returns bytes sent on success, <0 on failure.
	int sendto(const char *data, std::size_t size, const AddrRecord &dst);

	// Get the bound address of the listener (for candidate generation).
	bool boundAddr(AddrRecord &out) const;
	std::uint16_t boundPort() const;

	// Enumerate local addresses of the listener's family (for candidate
	// gathering, mirrors UDPMux::localAddrs).
	std::vector<AddrRecord> localAddrs(int family = AF_UNSPEC) const;

	// Wake the mux's poll thread so it re-evaluates timers immediately.
	// Called by registered agents when they arm new timers from within
	// onPacket/onBookkeeping callbacks.
	void interrupt() { if (pollReg_) pollReg_->interrupt(); }

	// --- PollParticipant interface ---
	socket_t udpSocket() const override { return STICE_INVALID_SOCKET; }
	bool hasTcp() const override { return false; }
	socket_t tcpSocket() const override { return STICE_INVALID_SOCKET; }
	short tcpDesiredEvents() const override { return 0; }
	bool hasListener() const override { return listenSock_ != STICE_INVALID_SOCKET; }
	socket_t listenerSocket() const override { return listenSock_; }
	void onAccept() override;
	int64_t nextTimestampMs() const override;
	void onUdpReadable() override {}
	void onTcpEvents(short) override {}
	void onBookkeeping(int64_t nowMs) override;

	// Called by TcpMuxConn when the first STUN packet is parsed and the
	// ufrag is extracted. Finds the matching agent and sets it on the conn.
	void onConnEstablished(TcpMuxConn *conn, const std::string &ufrag);

	// Called by TcpMuxConn when the connection closes. Removes it from
	// connsByAddr_ (if established) or marks it for cleanup from
	// pendingConns_. The shared_ptr is dropped during onBookkeeping to
	// avoid destroying the conn while onTcpEvents is still on the stack.
	void onConnClosed(TcpMuxConn *conn);

private:
	// Accept all pending connections on the listener socket.
	void acceptOne();

	// Clean up closed connections (drop shared_ptrs) and expire timed-out
	// pending connections (30s, aligned with pion FirstStunBindTimeout).
	void cleanupConns(int64_t nowMs);

	// Build a canonical key for an address (host:port).
	static std::string addrKey(const AddrRecord &addr);

	socket_t listenSock_ = STICE_INVALID_SOCKET;
	mutable std::mutex mutex_;

	// ufrag → agent entry.
	std::unordered_map<std::string, std::shared_ptr<TcpMuxAgentEntry>> agentsByUfrag_;

	// remote-address-key → established connection.
	std::unordered_map<std::string, std::shared_ptr<TcpMuxConn>> connsByAddr_;

	// Pending connections awaiting first STUN packet.
	std::vector<std::shared_ptr<TcpMuxConn>> pendingConns_;

	// Deferred cleanup: closed connections are moved here instead of being
	// destroyed immediately. This prevents UAF when the PollRegistry's
	// bookkeeping loop holds a raw pointer to a TcpMuxConn that is being
	// erased by cleanupConns() during the same bookkeeping pass. The
	// shared_ptrs are dropped at the start of the NEXT onBookkeeping call,
	// by which point the previous bookkeeping snapshot has been discarded.
	std::vector<std::shared_ptr<TcpMuxConn>> toDestroy_;

	// Per-mux PollRegistry instance (per-agent independent thread model).
	// All TcpMuxConns created by this TCPMux register on this instance,
	// so they share one poll thread with the listener.
	PollRegistry *pollReg_ = nullptr;

	friend class TcpMuxConn;
};

} // namespace stice::net

#endif // STICE_NET_TCP_MUX_HPP
