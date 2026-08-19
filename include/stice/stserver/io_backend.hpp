// SPDX-License-Identifier: MPL-2.0
// Abstract IO backend interface for stserver. Allows swapping between
// select()-based (B plan: control/data plane separation with thread pool)
// and IOCP/epoll-based (D plan: kernel-level async IO) backends via
// compile-time selection (STSERVER_IOCP).
//
// Both backends deliver data to TurnServer via the IoBackendOwner callback
// interface. TurnServer never calls recv()/recvfrom() directly — the backend
// handles all IO and passes decoded data through callbacks.

#ifndef STSERVER_IO_BACKEND_HPP
#define STSERVER_IO_BACKEND_HPP

#include "stice/net/addr.hpp"
#include "stice/net/platform.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>

namespace stserver {

// Callback interface: TurnServer implements this. The IO backend calls
// these methods (potentially from multiple worker threads) to deliver
// network events and data.
class IoBackendOwner {
public:
	virtual ~IoBackendOwner() = default;

	// Data arrived on the UDP listener (STUN Binding / TURN control).
	virtual void ioOnUdpData(const unsigned char *data, std::size_t len,
	                         const stice::net::AddrRecord &from) = 0;

	// New TCP connection accepted. The backend has already set the socket
	// to non-blocking mode and called setsockopt(TCP_NODELAY).
	virtual void ioOnTcpAccepted(socket_t sock, const stice::net::AddrRecord &peer) = 0;

	// Data arrived on a relay UDP socket. `relaySock` identifies which
	// allocation's relay socket received the data.
	virtual void ioOnRelayData(socket_t relaySock, const unsigned char *data,
	                           std::size_t len, const stice::net::AddrRecord &from) = 0;

	// Data arrived on a TCP connection (control or RFC 6062 data pipe).
	// The backend has already done the recv(); this delivers the bytes.
	virtual void ioOnTcpConnData(socket_t connSock, const unsigned char *data,
	                             std::size_t len) = 0;

	// TCP connection closed (recv returned 0 or fatal error).
	virtual void ioOnTcpConnClosed(socket_t connSock) = 0;

	// TCP connection is writable again (previously blocked with EWOULDBLOCK).
	// TurnServer should try flushTcp() on this connection.
	virtual void ioOnTcpConnWritable(socket_t connSock) = 0;

	// Timer tick — call expireStale() and other periodic maintenance.
	virtual void ioOnTimerTick() = 0;
};

// Abstract IO backend. Manages socket event monitoring and data delivery.
// Created by TurnServer::init(), destroyed in ~TurnServer.
class IoBackend {
public:
	virtual ~IoBackend() = default;

	// Initialize the backend with listener sockets and the callback owner.
	// udpListener and tcpListener are already bound and listening.
	virtual bool init(IoBackendOwner *owner, socket_t udpListener,
	                  socket_t tcpListener) = 0;

	// Start the backend (spawns worker threads). Returns immediately.
	virtual void start() = 0;

	// Stop and join all worker threads. Blocking.
	virtual void stop() = 0;

	// --- Socket management (called by TurnServer when state changes) ---

	// A new relay UDP socket was created (TURN Allocate). Start monitoring
	// it for readability.
	virtual void addRelaySocket(socket_t s) = 0;

	// A relay socket was closed or its allocation expired. Stop monitoring.
	virtual void removeRelaySocket(socket_t s) = 0;

	// A new TCP connection was accepted (or re-register after state change).
	// `hasWritePending` indicates if writeBuf is already non-empty.
	virtual void addTcpConn(socket_t s, bool hasWritePending) = 0;

	// A TCP connection was closed. Stop monitoring and clean up.
	virtual void removeTcpConn(socket_t s) = 0;

	// Notify that a TCP connection now has (or no longer has) pending write
	// data in its writeBuf. The backend should start/stop monitoring for
	// writability accordingly.
	virtual void setTcpConnWritePending(socket_t s, bool pending) = 0;

	// Configuration: set number of worker threads.
	virtual void setWorkerCount(int n) = 0;
};

// Factory: creates the appropriate backend based on compile-time flag.
// STSERVER_IOCP defined → IOCP (Windows) / epoll (Linux) backend.
// Otherwise → select-based backend with thread pool (B plan).
std::unique_ptr<IoBackend> createIoBackend();

} // namespace stserver

#endif // STSERVER_IO_BACKEND_HPP
