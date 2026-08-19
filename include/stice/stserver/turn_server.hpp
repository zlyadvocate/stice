// SPDX-License-Identifier: MPL-2.0
// stserver TURN/STUN server core. Implements STUN Binding (RFC 5389),
// TURN Allocate/Refresh/CreatePermission/ChannelBind/Send/Data (RFC 8656),
// TURN over TCP framing, and RFC 6062 Mode-B (CONNECT/CONNECTION-ATTEMPT/
// CONNECTION-BIND). Designed to replace coturn for stice interop testing.
//
// IO is handled by an abstract IoBackend (see io_backend.hpp). The backend
// can be select-based (B plan: control/data plane separation with thread
// pool) or IOCP/epoll-based (D plan: kernel-level async IO), selected at
// compile time via STSERVER_IOCP. All shared state is protected by a
// shared_mutex since callbacks fire from multiple worker threads.

#ifndef STSERVER_TURN_SERVER_HPP
#define STSERVER_TURN_SERVER_HPP

#include "stice/net/addr.hpp"
#include "stice/net/platform.hpp"
#include "stice/net/udp.hpp"
#include "stice/stun/message.hpp"
#include "stice/stserver/io_backend.hpp"
#include "stice/turn/stunconn.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

struct Config;

namespace stserver {

// A permission associates a peer IP address with an allocation (RFC 8656 §2.5).
// Port is ignored when matching incoming relayed data to a permission.
struct Permission {
	stice::net::AddrRecord peer;
	std::int64_t expiryMs = 0;
};

// A channel binds a channel number to a peer (full IP:port) on an allocation.
struct Channel {
	std::uint16_t number = 0;
	stice::net::AddrRecord peer;
	std::int64_t expiryMs = 0;
};

struct Allocation {
	int transport = 0;                          // SOCK_DGRAM or SOCK_STREAM
	stice::net::AddrRecord clientAddr;                 // 5-tuple client endpoint
	socket_t controlSock = STICE_INVALID_SOCKET; // TCP control socket (INVALID for UDP)
	stice::net::UdpSocket relaySock;                   // UDP relay socket (invalid for TCP alloc)
	stice::net::AddrRecord relayedAddr;                // XOR-RELAYED-ADDRESS value
	std::uint16_t relayPort = 0;
	std::string username;
	std::vector<Permission> permissions;
	std::vector<Channel> channels;
	std::int64_t expiryMs = 0;

	// RFC 6062 pending connects (TCP allocations only). A CONNECT request
	// from the local client creates a PendingConnect; the held CONNECT
	// success response is flushed once the peer binds with CONNECTION-BIND.
	struct PendingConnect {
		std::uint32_t connId = 0;
		stice::net::AddrRecord peerRelayAddr;
		socket_t firstDataSock = STICE_INVALID_SOCKET; // first CONNECTION-BIND socket
		std::array<unsigned char, 12> connectTid{};     // CONNECT transaction id (response held)
		bool connectResponded = false;                  // CONNECT success already sent
		std::int64_t expiryMs = 0;
	};
	std::vector<PendingConnect> pendingConnects;
};

// A TCP connection: either a TURN control connection (RFC 8656 §3 over TCP)
// or an RFC 6062 data connection (after CONNECTION-BIND). Uses stice's
// StunConn for self-delimiting STUN/ChannelData framing.
struct TcpConn {
	socket_t sock = STICE_INVALID_SOCKET;
	stice::net::AddrRecord peerAddr;
	stice::turn::StunConn stunConn;
	bool isData = false;          // true after CONNECTION-BIND (raw data pipe)
	std::uint32_t connId = 0;     // for data connections: the bound CONNECTION-ID
	std::vector<unsigned char> writeBuf; // pending bytes for non-blocking send
};

class TurnServer : public IoBackendOwner {
public:
	TurnServer();
	~TurnServer();
	TurnServer(const TurnServer &) = delete;
	TurnServer &operator=(const TurnServer &) = delete;

	// Set up listeners and state from `cfg`. Returns false on fatal error.
	bool init(const Config &cfg);
	// Start the IO backend and block until stop() is called. stop() is
	// signal-handler-safe (just sets an atomic flag); this method joins the
	// worker threads after the flag is set.
	void run();
	// Request shutdown (thread-safe, signal-handler-safe). Sets running_
	// to false; run() will then join the backend threads and return.
	void stop() { running_ = false; }

	// Set the number of IO worker threads (must be called before init()).
	void setWorkerCount(int n) { workerCount_ = std::max(1, n); }

private:
	// ---- IoBackendOwner callbacks (called from IO worker threads) ----
	void ioOnUdpData(const unsigned char *data, std::size_t len,
	                 const stice::net::AddrRecord &from) override;
	void ioOnTcpAccepted(socket_t sock, const stice::net::AddrRecord &peer) override;
	void ioOnRelayData(socket_t relaySock, const unsigned char *data,
	                   std::size_t len, const stice::net::AddrRecord &from) override;
	void ioOnTcpConnData(socket_t connSock, const unsigned char *data,
	                     std::size_t len) override;
	void ioOnTcpConnClosed(socket_t connSock) override;
	void ioOnTcpConnWritable(socket_t connSock) override;
	void ioOnTimerTick() override;

	// ---- Allocation key/lookup ----
	// 5-tuple key string: "U|<ip>:<port>" (UDP) or "T|<ip>:<port>" (TCP).
	std::string allocKey(int transport, const stice::net::AddrRecord &client) const;
	Allocation *findAlloc(const std::string &key) const;
	Allocation *findAllocByRelaySock(socket_t s) const;
	Allocation *findTcpAllocByPeer(const stice::net::AddrRecord &peerRelayAddr,
	                               const Allocation *exclude) const;
	Allocation *findPendingByConnId(std::uint32_t connId,
	                                Allocation::PendingConnect **outPc = nullptr);

	// ---- Relay port allocation ----
	std::uint16_t allocRelayPort();
	void releaseRelayPort(std::uint16_t port);
	// Build the relayed AddrRecord advertised to clients, using the server's
	// externally-reachable IP (falls back to loopback for 0.0.0.0 binds).
	bool buildRelayedAddr(std::uint16_t port, stice::net::AddrRecord &out) const;

	// ---- Authentication ----
	void refreshNonce();
	// Returns 0 on success, 401 (unauthenticated), or 438 (stale nonce).
	int authenticate(const stice::stun::Message &msg, std::string &outUsername);

	// ---- Response builders / senders ----
	void sendUdp(const stice::net::AddrRecord &dst, const stice::stun::Message &msg);
	void sendTcp(TcpConn &conn, const stice::stun::Message &msg);
	void sendTcpRaw(TcpConn &conn, const unsigned char *data, std::size_t size);
	bool flushTcp(TcpConn &conn);
	void sendErrorResponseUdp(const stice::net::AddrRecord &dst,
	                           const stice::stun::Message &req, int code);
	void sendAuthErrorResponse(const stice::net::AddrRecord &dst,
	                           const stice::stun::Message &req, int code);
	void sendErrorResponseTcp(TcpConn &conn, const stice::stun::Message &req, int code);
	void sendAuthErrorResponseTcp(TcpConn &conn, const stice::stun::Message &req, int code);
	void sendSuccessResponse(const stice::stun::Message &req, const std::string &username,
	                         stice::stun::Message &resp);

	// ---- STUN/TURN request dispatch ----
	void handleUdpPacket(const unsigned char *data, std::size_t size,
	                     const stice::net::AddrRecord &src);
	void handleTcpFrame(TcpConn &conn, const unsigned char *data, std::size_t size);
	void dispatchStun(stice::stun::Message &msg, const stice::net::AddrRecord &src,
	                  TcpConn *tcpConn, Allocation *alloc);

	void handleBinding(stice::stun::Message &req, const stice::net::AddrRecord &src,
	                   TcpConn *tcpConn);
	void handleAllocate(stice::stun::Message &req, const stice::net::AddrRecord &src,
	                    TcpConn *tcpConn, Allocation *alloc);
	void handleRefresh(stice::stun::Message &req, const stice::net::AddrRecord &src,
	                   TcpConn *tcpConn, Allocation *alloc);
	void handleCreatePermission(stice::stun::Message &req, const stice::net::AddrRecord &src,
	                            TcpConn *tcpConn, Allocation *alloc);
	void handleChannelBind(stice::stun::Message &req, const stice::net::AddrRecord &src,
	                       TcpConn *tcpConn, Allocation *alloc);
	void handleSendIndication(stice::stun::Message &req, Allocation *alloc);
	void handleChannelDataFrame(const unsigned char *data, std::size_t size,
	                            Allocation *alloc);
	void handleConnect(stice::stun::Message &req, TcpConn *tcpConn, Allocation *alloc);
	void handleConnectionBind(stice::stun::Message &req, TcpConn *tcpConn);

	// ---- Relay data forwarding (peer -> client) ----
	void forwardToClient(Allocation &alloc, const stice::net::AddrRecord &peer,
	                     const unsigned char *data, std::size_t size);
	void sendConnectionAttempt(Allocation &targetAlloc,
	                           std::uint32_t connId, const stice::net::AddrRecord &peerRelayAddr);

	// ---- TCP connection management ----
	void closeTcpConn(TcpConn *conn);

	// ---- Expiry ----
	std::int64_t nowMs() const;
	void expireStale();

	// ---- Config / state ----
	std::string listenAddress_;
	std::uint16_t udpPort_ = 3478;
	std::uint16_t tcpPort_ = 3478;
	std::string realm_;
	std::map<std::string, std::string> users_;
	int maxAllocations_ = 2000;
	std::uint32_t allocationLifetime_ = 600;
	std::uint16_t relayPortBegin_ = 49152;
	std::uint16_t relayPortEnd_ = 65535;
	int workerCount_ = 4;
	// Externally-reachable server IP for XOR-RELAYED-ADDRESS (loopback when
	// the listener is 0.0.0.0).
	std::string relayIp_;
	// sockaddr form of relayIp_ for building relayed AddrRecords.
	struct sockaddr_storage relayIpAddr_;
	socklen_t relayIpLen_ = 0;

	// Long-term credential nonce (RFC 5389 §15.4). Refreshed periodically.
	std::string nonce_;
	std::int64_t nonceExpiryMs_ = 0;

	// Listeners.
	stice::net::UdpSocket udpListener_;
	socket_t tcpListener_ = STICE_INVALID_SOCKET;

	// IO backend (B plan: select + thread pool, D plan: IOCP/epoll).
	std::unique_ptr<IoBackend> ioBackend_;

	// Shared state mutex. All maps below are accessed from IO worker threads
	// (potentially concurrently) and must hold this lock. Using
	// recursive_mutex because handlers may indirectly call back into methods
	// that also lock (e.g. closeTcpConn from ioOnTcpConnClosed during
	// handleTcpFrame processing).
	mutable std::recursive_mutex stateMutex_;

	// Allocations: owned by unique_ptr (stable pointers) in a map keyed by
	// the 5-tuple string. Reverse-lookup maps hold raw pointers.
	std::map<std::string, std::unique_ptr<Allocation>> allocations_;
	std::map<socket_t, Allocation *> allocByRelaySock_;
	std::map<socket_t, Allocation *> allocByControlSock_;
	std::map<std::uint32_t, Allocation *> pendingByConnId_;
	std::set<std::uint16_t> usedRelayPorts_;
	std::uint32_t nextConnId_ = 1;

	// TCP connections (control + data). Owned by unique_ptr for stability.
	std::vector<std::unique_ptr<TcpConn>> tcpConns_;
	std::map<socket_t, TcpConn *> tcpBySock_;                 // sock -> connection
	std::map<socket_t, socket_t> dataPipe_;                    // RFC 6062 data pairing

	std::atomic<bool> running_{false};
};

} // namespace stserver

#endif // STSERVER_TURN_SERVER_HPP
