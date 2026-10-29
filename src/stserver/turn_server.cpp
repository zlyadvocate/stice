// SPDX-License-Identifier: MPL-2.0
// Author: zlyadvocate
// Version: 0.13.0
// stserver TURN/STUN server implementation.
//
// Implements STUN Binding (RFC 5389), TURN Allocate/Refresh/CreatePermission/
// ChannelBind/Send/Data (RFC 8656), TURN over TCP framing (self-delimiting),
// and RFC 6062 Mode-B (CONNECT/CONNECTION-ATTEMPT/CONNECTION-BIND).
//
// IO is handled by an abstract IoBackend (B plan: select + thread pool,
// D plan: IOCP/epoll). All shared state is protected by stateMutex_ since
// callbacks fire from multiple worker threads. STICE_STATIC must be defined
// before including stice headers so the static library linkage is selected.

// Raise FD_SETSIZE before pulling in winsock2.h (via stice headers) so the
// select() fd_set can hold many relay/TCP sockets when using SelectBackend.
// This only affects stserver's own fd_set usage; it does not change stice.lib
// internals, and is harmless when using IOCP/epoll.
#ifdef _WIN32
#ifndef FD_SETSIZE
#define FD_SETSIZE 8192
#endif
#endif

#ifndef STICE_STATIC
#define STICE_STATIC
#endif

#include "stice/stserver/turn_server.hpp"
#include "stice/stserver/config.hpp"

#include "stice/crypto.hpp"
#include "stice/log.hpp"
#include "stice/net/addr.hpp"
#include "stice/stun/attributes.hpp"
#include "stice/stun/message.hpp"
#include "stice/turn/channeldata.hpp"
#include "stice/turn/stunconn.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h> // TCP_NODELAY
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace stserver {

using namespace stice::stun;
using namespace stice::turn;
using namespace stice::net;

namespace {
constexpr int PermissionLifetimeMs = 5 * 60 * 1000;   // RFC 8656 §2.5
constexpr int ChannelBindLifetimeMs = 10 * 60 * 1000;  // RFC 8656 §2.6
constexpr int PendingConnectLifetimeMs = 30 * 1000;   // RFC 6062 conn attempt
constexpr int SelectTimeoutMs = 1000;

std::int64_t steadyNowMs() {
	return std::chrono::duration_cast<std::chrono::milliseconds>(
	           std::chrono::steady_clock::now().time_since_epoch())
	    .count();
}

bool setNonBlocking(socket_t s) {
#ifdef _WIN32
	u_long nb = 1;
	return ioctlsocket(s, FIONBIO, &nb) == 0;
#else
	int fl = fcntl(s, F_GETFL, 0);
	return fcntl(s, F_SETFL, fl | O_NONBLOCK) == 0;
#endif
}

bool setReuseAddr(socket_t s) {
	int yes = 1;
	return setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&yes),
	                  sizeof(yes)) == 0;
}

// Compare two addresses by IP only (port ignored) for TURN permission matching.
bool samePeerIP(const AddrRecord &a, const AddrRecord &b) {
	return addrEqual(reinterpret_cast<const sockaddr *>(&a.addr),
	                 reinterpret_cast<const sockaddr *>(&b.addr), false);
}

// Log a failed UDP sendto (relay forward / client delivery path). These
// failures silently drop TURN data — without logging they are undiagnosable.
void logSendToFailure(const AddrRecord &dst, int n) {
	if (n >= 0) return;
#ifdef _WIN32
	int err = WSAGetLastError();
#else
	int err = errno;
#endif
	// EWOULDBLOCK is transient under high-concurrency sends (SNDBUF full), not
	// a fatal error; downgrade to DEBUG to avoid log storms.
	if (
#ifdef _WIN32
	    err == WSAEWOULDBLOCK ||
#endif
	    err == EWOULDBLOCK) {
		STICE_LOG_DEBUG("stserver: relay sendto to %s would-block", dst.toString().c_str());
		return;
	}
	STICE_LOG_ERROR("stserver: relay sendto to %s failed: %d",
	                dst.toString().c_str(), err);
}

// Enlarge a UDP socket's kernel receive/send buffers to absorb bursts so
// concurrent relay forwarding doesn't overflow RCVBUF (relay read missed) or
// SNDBUF (client send dropped).
void setUdpBuf(socket_t s, int sz) {
	if (s == STICE_INVALID_SOCKET) return;
	setsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char *>(&sz), sizeof(sz));
	setsockopt(s, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char *>(&sz), sizeof(sz));
}

// Local-relay (hairpin) shortcut: when a relaying client's peer address is one
// of THIS server's own relayed addresses, deliver the datagram directly to the
// destination allocation instead of sending it out and reading it back through
// the kernel loopback. Saves two of the four syscalls per relayed frame.
// Set STICE_TURN_NO_LOCAL_SHORTCUT=1 to disable (e.g. to measure the raw
// two-hop forwarding path, or when a deployment must force full hairpin).
bool localRelayShortcut() {
	static const bool enabled = (std::getenv("STICE_TURN_NO_LOCAL_SHORTCUT") == nullptr);
	return enabled;
}

// Raise the business (control-plane) thread priority to match the IO threads.
// The IO threads run at ABOVE_NORMAL and this thread handles every
// Allocate/Refresh/CreatePermission/ChannelBind plus allocation expiry; leaving
// it at NORMAL let the boosted IO threads starve it, so TURN control operations
// timed out under load even while the data plane looked healthy.
void boostBusinessThreadPriority() {
#ifdef _WIN32
	::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
#endif
}
} // namespace

// Member definitions for the helpers declared in turn_server.hpp.
std::int64_t TurnServer::nowMs() const { return steadyNowMs(); }

std::string TurnServer::allocKey(int transport, const stice::net::AddrRecord &client) const {
	const char *t = (transport == SOCK_STREAM) ? "T" : "U";
	std::string s = t;
	s += '|';
	s += client.toString();
	return s;
}

TurnServer::TurnServer() = default;
TurnServer::~TurnServer() {
	// Stop the business thread first (it may still be draining queues), then
	// the IO backend so no more callbacks fire while we tear down.
	running_ = false;
	queueCv_.notify_all();
	if (businessThread_.joinable()) businessThread_.join();
	if (ioBackend_) {
		ioBackend_->stop();
		ioBackend_.reset();
	}
	if (tcpListener_ != STICE_INVALID_SOCKET) sticeClosesocket(tcpListener_);
	for (auto &c : tcpConns_)
		if (c->sock != STICE_INVALID_SOCKET) sticeClosesocket(c->sock);
}

bool TurnServer::init(const Config &cfg) {
	listenAddress_ = cfg.listenAddress;
	udpPort_ = cfg.udpPort;
	tcpPort_ = cfg.tcpPort;
	realm_ = cfg.realm;
	users_ = cfg.users;
	maxAllocations_ = cfg.maxAllocations;
	allocationLifetime_ = cfg.allocationLifetime;
	// nonceLifetimeMs_ is configurable (see Config::nonceLifetimeSec) so tests can
	// exercise the nonce-rotation window without waiting 30 minutes.
	nonceLifetimeMs_ = static_cast<std::int64_t>(cfg.nonceLifetimeSec) * 1000;
	relayPortBegin_ = cfg.relayPortBegin;
	relayPortEnd_ = cfg.relayPortEnd;
	workerCount_ = std::max(1, cfg.workerCount);

	// Determine the externally-reachable server IP advertised in
	// XOR-RELAYED-ADDRESS. Priority: explicit relayAddress (coturn external-ip
	// style, for 0.0.0.0 binds on a NAT/gateway box) > a specific listenAddress
	// > loopback fallback so local interop tests route relay traffic back to
	// the server.
	relayIp_ = cfg.relayAddress;
	if (relayIp_.empty()) {
		relayIp_ = listenAddress_;
		if (relayIp_.empty() || relayIp_ == "0.0.0.0" || relayIp_ == "::")
			relayIp_ = "127.0.0.1";
	}
	if (!parseAddr(relayIp_, 0, relayIpAddr_, relayIpLen_)) {
		STICE_LOG_ERROR("stserver: invalid relay ip %s", relayIp_.c_str());
		return false;
	}

	// UDP listener (STUN Binding + TURN over UDP).
	UdpSocketConfig ucfg;
	ucfg.bindAddress = listenAddress_;
	ucfg.portBegin = udpPort_;
	ucfg.portEnd = udpPort_;
	udpListener_ = UdpSocket::create(ucfg);
	if (!udpListener_.valid()) {
		STICE_LOG_ERROR("stserver: failed to bind UDP listener on %s:%u",
		                listenAddress_.c_str(), udpPort_);
		return false;
	}
	// Large receive buffer on the shared UDP listener: it is the single funnel
	// for every client's ChannelData (all N clients share one 5-tuple socket),
	// so a scheduling hiccup on a reader thread can otherwise overflow it and
	// silently drop datagrams. 64 MiB absorbs the initial burst of ~200 clients
	// that all start (and each send their in-flight window) at the same instant.
	setUdpBuf(udpListener_.handle(), 64 * 1024 * 1024);

	// TCP listener (TURN over TCP / RFC 6062). Prefer IPv4 dual-stack via a
	// single AF_INET listener for simplicity (interop runs on loopback).
	struct sockaddr_storage ss;
	socklen_t ssLen;
	if (!parseAddr(listenAddress_.empty() ? "0.0.0.0" : listenAddress_, tcpPort_, ss, ssLen)) {
		STICE_LOG_ERROR("stserver: invalid listen address %s", listenAddress_.c_str());
		return false;
	}
	tcpListener_ = ::socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (tcpListener_ == STICE_INVALID_SOCKET) {
		STICE_LOG_ERROR("stserver: TCP socket() failed: %d", sticeSockerrno);
		return false;
	}
	setReuseAddr(tcpListener_);
	if (::bind(tcpListener_, reinterpret_cast<sockaddr *>(&ss), ssLen) != 0) {
		STICE_LOG_ERROR("stserver: TCP bind on %s:%u failed: %d",
		                listenAddress_.c_str(), tcpPort_, sticeSockerrno);
		sticeClosesocket(tcpListener_);
		tcpListener_ = STICE_INVALID_SOCKET;
		return false;
	}
	// Backlog must absorb a simultaneous client burst: the big-data test
	// launches 200 stice clients in one aligned wave, each opening a TURN/TCP
	// control connection (plus RFC 6062 data connections), i.e. hundreds of
	// SYNs arriving within milliseconds. The previous value (64) overflowed the
	// accept queue, so the surplus SYNs were dropped and those clients never got
	// an allocation (ICE "connect timeout"). Use the platform maximum.
#ifdef _WIN32
	const int kListenBacklog = SOMAXCONN;
#else
	const int kListenBacklog = 512;
#endif
	if (::listen(tcpListener_, kListenBacklog) != 0) {
		STICE_LOG_ERROR("stserver: TCP listen failed: %d", sticeSockerrno);
		sticeClosesocket(tcpListener_);
		tcpListener_ = STICE_INVALID_SOCKET;
		return false;
	}
	setNonBlocking(tcpListener_);

	refreshNonce();

	// Create and initialize the IO backend (B plan: select + thread pool,
	// D plan: IOCP/epoll, selected at compile time via STSERVER_IOCP).
	ioBackend_ = createIoBackend();
	if (!ioBackend_ || !ioBackend_->init(this, udpListener_.handle(), tcpListener_)) {
		STICE_LOG_ERROR("stserver: IO backend init failed");
		return false;
	}
	ioBackend_->setWorkerCount(workerCount_);

	STICE_LOG_INFO("stserver: listening UDP %s:%u  TCP %s:%u  relay=%s  realm=%s  users=%zu  workers=%d",
	               listenAddress_.c_str(), udpPort_, listenAddress_.c_str(), tcpPort_,
	               relayIp_.c_str(), realm_.c_str(), users_.size(), workerCount_);
	return true;
}

void TurnServer::refreshNonce() {
	nonce_ = stice::crypto::randomStr64(32);
	nonceExpiryMs_ = nowMs() + nonceLifetimeMs_;
}

// ---- Allocation key/lookup --------------------------------------------------

Allocation *TurnServer::findAlloc(const std::string &key) const {
	auto it = allocations_.find(key);
	return it == allocations_.end() ? nullptr : it->second.get();
}

Allocation *TurnServer::findAllocByRelaySock(socket_t s) const {
	std::lock_guard<std::mutex> lk(relayMapMutex_);
	auto it = allocByRelaySock_.find(s);
	return it == allocByRelaySock_.end() ? nullptr : it->second;
}

Allocation *TurnServer::findTcpAllocByPeer(const AddrRecord &peerRelayAddr,
                                          const Allocation *exclude) const {
	Allocation *found = nullptr;
	for (auto &kv : allocations_) {
		Allocation *a = kv.second.get();
		if (a == exclude) continue;
		if (a->transport != SOCK_STREAM) continue;
		if (a->relayedAddr == peerRelayAddr) {
			found = a;
			break;
		}
	}
	return found;
}

Allocation *TurnServer::findPendingByConnId(std::uint32_t connId,
                                            Allocation::PendingConnect **outPc) {
	auto it = pendingByConnId_.find(connId);
	if (it == pendingByConnId_.end()) return nullptr;
	Allocation *a = it->second;
	for (auto &pc : a->pendingConnects) {
		if (pc.connId == connId) {
			if (outPc) *outPc = &pc;
			return a;
		}
	}
	return nullptr;
}

// ---- Relay port allocation -------------------------------------------------

std::uint16_t TurnServer::allocRelayPort(const std::set<std::uint16_t> &avoid) {
	if (relayPortEnd_ < relayPortBegin_) std::swap(relayPortBegin_, relayPortEnd_);
	std::uint32_t span = std::uint32_t(relayPortEnd_) - relayPortBegin_ + 1;
	for (int tries = 0; tries < 200; ++tries) {
		std::uint32_t r = stice::crypto::randomU32();
		std::uint16_t port = relayPortBegin_ + static_cast<std::uint16_t>(r % span);
		if (usedRelayPorts_.count(port) == 0 && avoid.count(port) == 0) {
			usedRelayPorts_[port] = nullptr; // owner recorded on allocation commit
			return port;
		}
	}
	// Fallback: sequential scan (inclusive of relayPortEnd_).
	for (std::uint32_t p = relayPortBegin_; p <= relayPortEnd_; ++p) {
		std::uint16_t port = static_cast<std::uint16_t>(p);
		if (usedRelayPorts_.count(port) == 0 && avoid.count(port) == 0) {
			usedRelayPorts_[port] = nullptr;
			return port;
		}
	}
	return 0;
}

void TurnServer::releaseRelayPort(std::uint16_t port, const Allocation *owner) {
	auto it = usedRelayPorts_.find(port);
	if (it == usedRelayPorts_.end()) return;
	// Ownership check: only the owner (or a release before the owner is
	// committed, owner == nullptr during Allocate) may free the port. This
	// makes release idempotent and prevents a double release from freeing a
	// port that has already been handed to a different allocation.
	if (it->second != nullptr && it->second != owner) {
		STICE_LOG_WARN("stserver: relay port %u release rejected (owner mismatch)", port);
		return;
	}
	usedRelayPorts_.erase(it);
}

Allocation *TurnServer::findAllocByClientRef(const stice::net::AddrRecord &addr) {
	std::lock_guard<std::mutex> lk(clientMapMutex_);
	auto it = allocByClientAddr_.find(addr);
	if (it == allocByClientAddr_.end()) return nullptr;
	Allocation *a = it->second;
	if (a->dying_.load(std::memory_order_acquire)) return nullptr;
	a->ioUsers_.fetch_add(1, std::memory_order_acq_rel);
	return a;
}

Allocation *TurnServer::findAllocByRelayRef(socket_t relaySock) {
	std::lock_guard<std::mutex> lk(relayMapMutex_);
	auto it = allocByRelaySock_.find(relaySock);
	if (it == allocByRelaySock_.end()) return nullptr;
	Allocation *a = it->second;
	if (a->dying_.load(std::memory_order_acquire)) return nullptr;
	a->ioUsers_.fetch_add(1, std::memory_order_acq_rel);
	return a;
}

void TurnServer::allocUnref(Allocation *a) {
	// Signal only when a destroyer is actually waiting for the count to drain.
	// The common case (no waiter) stays a single atomic op - important because
	// this runs once per ChannelData packet on the data plane.
	if (a->ioUsers_.fetch_sub(1, std::memory_order_acq_rel) == 1 &&
	    ioUsersWaiters_.load(std::memory_order_relaxed) > 0) {
		std::lock_guard<std::mutex> lk(ioUsersMutex_);
		ioUsersCv_.notify_all();
	}
}

Allocation *TurnServer::findAllocByRelayAddrRef(const stice::net::AddrRecord &addr) {
	std::lock_guard<std::mutex> lk(relayMapMutex_);
	auto it = allocByRelayAddr_.find(addr);
	if (it == allocByRelayAddr_.end()) return nullptr;
	Allocation *a = it->second;
	if (a->dying_.load(std::memory_order_acquire)) return nullptr;
	a->ioUsers_.fetch_add(1, std::memory_order_acq_rel);
	return a;
}

void TurnServer::destroyAllocation(Allocation *a) {
	if (!a) return;
	// Unbind from IO backend first so no further relay data arrives.
	if (a->transport == SOCK_DGRAM && a->relaySock.valid()) {
		if (ioBackend_) ioBackend_->removeRelaySocket(a->relaySock.handle());
	}
	// Mark dying under the map locks so no new IO fast-path reference is taken,
	// then wait for in-flight IO workers to finish before freeing (UAF guard).
	a->dying_.store(true, std::memory_order_release);
	{
		std::lock_guard<std::mutex> lk(relayMapMutex_);
		allocByRelaySock_.erase(a->relaySock.handle());
		allocByRelayAddr_.erase(a->relayedAddr);
	}
	{
		std::lock_guard<std::mutex> lk(clientMapMutex_);
		allocByClientAddr_.erase(a->clientAddr);
	}
	// TURN-over-TCP with UDP relay keeps both a relay socket and a control
	// socket — clean both lookup entries independently.
	if (a->controlSock != STICE_INVALID_SOCKET) {
		allocByControlSock_.erase(a->controlSock);
	}
	for (const auto &pc : a->pendingConnects) pendingByConnId_.erase(pc.connId);
	releaseRelayPort(a->relayPort, a);
	// Wait for in-flight IO fast-path references to drain before freeing.
	// Event-driven (no bare yield-spin): a normally sub-microsecond wait costs
	// no CPU, and a stuck IO worker is reported loudly once per second instead
	// of silently burning a core. We deliberately do not "give up" and free
	// anyway - that would be a use-after-free for an IO thread still
	// dereferencing this allocation; the loud log is the escalation path.
	if (a->ioUsers_.load(std::memory_order_acquire) != 0) {
		ioUsersWaiters_.fetch_add(1, std::memory_order_relaxed);
		{
			std::unique_lock<std::mutex> lk(ioUsersMutex_);
			while (a->ioUsers_.load(std::memory_order_acquire) != 0) {
				if (ioUsersCv_.wait_for(lk, std::chrono::seconds(1)) ==
				    std::cv_status::timeout) {
					STICE_LOG_ERROR("stserver: destroyAllocation waiting on ioUsers_=%d (>1s); IO worker stuck?",
					                a->ioUsers_.load(std::memory_order_acquire));
				}
			}
		}
		ioUsersWaiters_.fetch_sub(1, std::memory_order_relaxed);
	}
	allocations_.erase(allocKey(a->transport, a->clientAddr));
}

bool TurnServer::buildRelayedAddr(std::uint16_t port, AddrRecord &out) const {
	std::memcpy(&out.addr, &relayIpAddr_, relayIpLen_);
	out.len = relayIpLen_;
	out.socktype = SOCK_DGRAM;
	addrSetPort(reinterpret_cast<sockaddr *>(&out.addr), port);
	return true;
}

// ---- Authentication -------------------------------------------------------

// Authenticate a request using long-term credentials (RFC 5389 §15.4).
// Returns: 0 on success, 401 (no/invalid MESSAGE-INTEGRITY), 438 (stale nonce).
// On success, outUsername holds the verified username.
int TurnServer::authenticate(const Message &msg, std::string &outUsername) {
	const Attribute *mi = msg.find(AttrType::MessageIntegrity);
	if (!mi) return StunErrorUnauthenticated;

	std::string username = getString(msg, AttrType::Username);
	std::string realm = getString(msg, AttrType::Realm);
	std::string nonce = getString(msg, AttrType::Nonce);

	// Nonce validation (RFC 5389 §10.2.2 / §15.4). Rotate the server nonce ONLY
	// when it has actually expired; answer a plain mismatch with 438 carrying the
	// CURRENT nonce.
	//
	// Regenerating the nonce on every mismatch caused a stampede: all clients
	// sharing the server rotate together (the nonce is global), so at each
	// rotation every client's next request carried the old nonce. Each such
	// request used to mint a NEW nonce, which immediately invalidated the nonce
	// the server had just handed to the previous client - so their retries kept
	// collecting 438 until they exhausted the client-side retry budget and tore
	// their TURN allocation down. Observed as every relayed client dying at the
	// same instant, once per nonce lifetime.
	if (nowMs() >= nonceExpiryMs_) {
		refreshNonce();
		return StunErrorStaleNonce;
	}
	if (nonce != nonce_) return StunErrorStaleNonce;

	auto it = users_.find(username);
	if (it == users_.end()) return StunErrorUnauthenticated;

	auto key = stice::crypto::longTermKey(username, realm, it->second);
	if (!msg.checkIntegrity(key.data(), key.size())) return StunErrorUnauthenticated;

	outUsername = username;
	return 0;
}

// ---- Response builders / senders ------------------------------------------

void TurnServer::sendUdp(const AddrRecord &dst, const Message &msg) {
	if (!msg.raw.empty()) {
		int n = udpListener_.sendto(reinterpret_cast<const char *>(msg.raw.data()),
		                            static_cast<int>(msg.raw.size()), dst);
		if (n < 0) {
#ifdef _WIN32
			int err = WSAGetLastError();
#else
			int err = errno;
#endif
			STICE_LOG_ERROR("stserver: sendto to %s failed: %d",
			                dst.toString().c_str(), err);
		}
	}
}

void TurnServer::sendTcpRaw(TcpConn &conn, const unsigned char *data, std::size_t size) {
	std::lock_guard<std::mutex> lk(conn.writeMtx);
	sendTcpRawLocked(conn, data, size);
}

// Caller holds conn.writeMtx. The data-pipe fast path (IO worker thread) calls
// this directly so a relayed chunk does not bounce through the single business
// thread, which was the TCP relay's throughput ceiling (the UDP data plane has
// had an equivalent parallel fast path since the relay readloop pool landed).
void TurnServer::sendTcpRawLocked(TcpConn &conn, const unsigned char *data, std::size_t size) {
	if (size == 0) return;
	// Drop the already-sent prefix before appending (cheap no-op in the common
	// case where the previous flush drained everything).
	if (conn.writeOff > 0) {
		if (conn.writeOff >= conn.writeBuf.size()) {
			conn.writeBuf.clear();
		} else {
			conn.writeBuf.erase(conn.writeBuf.begin(), conn.writeBuf.begin() + conn.writeOff);
		}
		conn.writeOff = 0;
	}
	conn.writeBuf.insert(conn.writeBuf.end(), data, data + size);
	flushTcpLocked(conn);
}

bool TurnServer::flushTcp(TcpConn &conn) {
	std::lock_guard<std::mutex> lk(conn.writeMtx);
	return flushTcpLocked(conn);
}

// Caller holds conn.writeMtx.
bool TurnServer::flushTcpLocked(TcpConn &conn) {
	while (conn.writeOff < conn.writeBuf.size()) {
		int n = ::send(conn.sock,
		               reinterpret_cast<const char *>(conn.writeBuf.data() + conn.writeOff),
		               static_cast<int>(conn.writeBuf.size() - conn.writeOff), 0);
		if (n > 0) {
			conn.writeOff += static_cast<std::size_t>(n);
			continue;
		}
		if (n < 0 && wouldBlock()) break; // partial: keep the remainder, need writability
		// Hard error: drop the buffer; the caller tears the connection down.
		conn.writeBuf.clear();
		conn.writeOff = 0;
		if (ioBackend_) ioBackend_->setTcpConnWritePending(conn.sock, false);
		return false;
	}
	const bool drained = (conn.writeOff >= conn.writeBuf.size());
	if (drained) {
		conn.writeBuf.clear();
		conn.writeOff = 0;
	}
	// A single state report per call: arm when data is left over, disarm when the
	// socket drained. The backend makes the call a no-op (no wake syscall) when
	// the value is unchanged, which is the usual case on this path.
	if (ioBackend_) ioBackend_->setTcpConnWritePending(conn.sock, !drained);
	return true;
}

void TurnServer::sendTcp(TcpConn &conn, const Message &msg) {
	if (!msg.raw.empty()) sendTcpRaw(conn, msg.raw.data(), msg.raw.size());
}

// Error response with REALM + NONCE but NO MESSAGE-INTEGRITY (used for 401/438
// where the client has not yet proven credentials). REALM/NONCE are added as
// raw attributes and encode() is called without a password.
void TurnServer::sendAuthErrorResponse(const AddrRecord &dst, const Message &req, int code) {
	Message resp;
	resp.method = req.method;
	resp.cls = Class::ErrorResponse;
	resp.transactionID = req.transactionID;
	addErrorCode(resp, code);
	addString(resp, AttrType::Realm, realm_);
	addString(resp, AttrType::Nonce, nonce_);
	resp.encode(nullptr, nullptr, "stserver");
	sendUdp(dst, resp);
}

void TurnServer::sendAuthErrorResponseTcp(TcpConn &conn, const Message &req, int code) {
	Message resp;
	resp.method = req.method;
	resp.cls = Class::ErrorResponse;
	resp.transactionID = req.transactionID;
	addErrorCode(resp, code);
	addString(resp, AttrType::Realm, realm_);
	addString(resp, AttrType::Nonce, nonce_);
	resp.encode(nullptr, nullptr, "stserver");
	sendTcp(conn, resp);
}

void TurnServer::sendErrorResponseUdp(const AddrRecord &dst, const Message &req, int code) {
	Message resp;
	resp.method = req.method;
	resp.cls = Class::ErrorResponse;
	resp.transactionID = req.transactionID;
	addErrorCode(resp, code);
	resp.encode(nullptr, nullptr, "stserver");
	sendUdp(dst, resp);
}

void TurnServer::sendErrorResponseTcp(TcpConn &conn, const Message &req, int code) {
	Message resp;
	resp.method = req.method;
	resp.cls = Class::ErrorResponse;
	resp.transactionID = req.transactionID;
	addErrorCode(resp, code);
	resp.encode(nullptr, nullptr, "stserver");
	sendTcp(conn, resp);
}

// Success response carrying MESSAGE-INTEGRITY (long-term credentials). The
// caller must have filled resp's method/attributes; this attaches the auth
// attributes + MI + FINGERPRINT using the long-term key.
void TurnServer::sendSuccessResponse(const Message &req, const std::string &username,
                                     Message &resp) {
	resp.method = req.method;
	resp.cls = Class::SuccessResponse;
	resp.transactionID = req.transactionID;
	auto it = users_.find(username);
	if (it == users_.end()) {
		resp.encode(nullptr, nullptr, "stserver");
		return;
	}
	stice::stun::Credentials creds;
	creds.username = username;
	creds.realm = realm_;
	creds.nonce = nonce_;
	auto key = stice::crypto::longTermKey(username, realm_, it->second);
	creds.key = stice::bytes(key.begin(), key.end());
	// password must be non-null to trigger MESSAGE-INTEGRITY; creds.key is
	// used as the HMAC key.
	resp.encode("", &creds, "stserver");
}

// ---- Dispatch -------------------------------------------------------------

void TurnServer::handleUdpPacket(const unsigned char *data, std::size_t size,
                                  const AddrRecord &src) {
	if (isChannelData(data, size)) {
		Allocation *a = findAlloc(allocKey(SOCK_DGRAM, src));
		if (a) handleChannelDataFrame(data, size, a);
		return;
	}
	if (!Message::isMessage(data, size)) return;
	Message msg;
	if (!msg.decode(data, size)) return;
	Allocation *a = findAlloc(allocKey(SOCK_DGRAM, src));
	dispatchStun(msg, src, nullptr, a);
}

void TurnServer::handleTcpFrame(TcpConn &conn, const unsigned char *data, std::size_t size) {
	if (conn.isData) {
		// RFC 6062 data connection: raw bytes piped to the paired socket.
		auto it = dataPipe_.find(conn.sock);
		if (it != dataPipe_.end()) {
			auto pit = tcpBySock_.find(it->second);
			if (pit != tcpBySock_.end()) sendTcpRaw(*pit->second, data, size);
		}
		return;
	}
	if (isChannelData(data, size)) {
		Allocation *a = nullptr;
		if (conn.sock != STICE_INVALID_SOCKET) {
			auto it = allocByControlSock_.find(conn.sock);
			if (it != allocByControlSock_.end()) a = it->second;
		}
		if (a) handleChannelDataFrame(data, size, a);
		return;
	}
	if (!Message::isMessage(data, size)) return;
	Message msg;
	if (!msg.decode(data, size)) return;
	Allocation *a = nullptr;
	if (conn.sock != STICE_INVALID_SOCKET) {
		auto it = allocByControlSock_.find(conn.sock);
		if (it != allocByControlSock_.end()) a = it->second;
	}
	dispatchStun(msg, conn.peerAddr, &conn, a);
}

void TurnServer::dispatchStun(Message &msg, const AddrRecord &src, TcpConn *tcpConn,
                               Allocation *alloc) {
	if (msg.cls != Class::Request && msg.cls != Class::Indication) return;

	switch (msg.method) {
	case Method::Binding:
		if (msg.cls == Class::Request) handleBinding(msg, src, tcpConn);
		break;
	case Method::Allocate:
		if (msg.cls == Class::Request) {
			if (alloc) {
				if (alloc->expiryMs <= nowMs()) {
					// Expired but not yet reaped: replace it, cleaning the
					// old allocation (relay socket, ports, lookups) fully
					// before creating the new one.
					destroyAllocation(alloc);
					alloc = nullptr;
				} else {
					if (tcpConn)
						sendErrorResponseTcp(*tcpConn, msg, StunErrorAllocationMismatch);
					else
						sendErrorResponseUdp(src, msg, StunErrorAllocationMismatch);
					return;
				}
			}
			std::string user;
			int code = authenticate(msg, user);
			if (code != 0) {
				if (tcpConn) sendAuthErrorResponseTcp(*tcpConn, msg, code);
				else sendAuthErrorResponse(src, msg, code);
				return;
			}
			handleAllocate(msg, src, tcpConn, alloc);
			(void)user;
		}
		break;
	case Method::Refresh:
		if (msg.cls == Class::Request) {
			if (!alloc) {
				if (tcpConn) sendErrorResponseTcp(*tcpConn, msg, StunErrorAllocationMismatch);
				else sendErrorResponseUdp(src, msg, StunErrorAllocationMismatch);
				return;
			}
			std::string user;
			int code = authenticate(msg, user);
			if (code != 0) {
				if (tcpConn) sendAuthErrorResponseTcp(*tcpConn, msg, code);
				else sendAuthErrorResponse(src, msg, code);
				return;
			}
			handleRefresh(msg, src, tcpConn, alloc);
			(void)user;
		}
		break;
	case Method::CreatePermission:
		if (msg.cls == Class::Request) {
			if (!alloc) {
				if (tcpConn) sendErrorResponseTcp(*tcpConn, msg, StunErrorAllocationMismatch);
				else sendErrorResponseUdp(src, msg, StunErrorAllocationMismatch);
				return;
			}
			std::string user;
			int code = authenticate(msg, user);
			if (code != 0) {
				if (tcpConn) sendAuthErrorResponseTcp(*tcpConn, msg, code);
				else sendAuthErrorResponse(src, msg, code);
				return;
			}
			handleCreatePermission(msg, src, tcpConn, alloc);
			(void)user;
		}
		break;
	case Method::ChannelBind:
		if (msg.cls == Class::Request) {
			if (!alloc) {
				if (tcpConn) sendErrorResponseTcp(*tcpConn, msg, StunErrorAllocationMismatch);
				else sendErrorResponseUdp(src, msg, StunErrorAllocationMismatch);
				return;
			}
			std::string user;
			int code = authenticate(msg, user);
			if (code != 0) {
				if (tcpConn) sendAuthErrorResponseTcp(*tcpConn, msg, code);
				else sendAuthErrorResponse(src, msg, code);
				return;
			}
			handleChannelBind(msg, src, tcpConn, alloc);
			(void)user;
		}
		break;
	case Method::Send:
		if (msg.cls == Class::Indication && alloc) handleSendIndication(msg, alloc);
		break;
	case Method::Connect:
		if (msg.cls == Class::Request) {
			if (!alloc || !tcpConn) {
				if (tcpConn) sendErrorResponseTcp(*tcpConn, msg, StunErrorAllocationMismatch);
				return;
			}
			if (alloc->transport != SOCK_STREAM) {
				sendErrorResponseTcp(*tcpConn, msg, StunErrorBadRequest);
				return;
			}
			std::string user;
			int code = authenticate(msg, user);
			if (code != 0) {
				sendAuthErrorResponseTcp(*tcpConn, msg, code);
				return;
			}
			handleConnect(msg, tcpConn, alloc);
			(void)user;
		}
		break;
	case Method::ConnectionBind:
		if (msg.cls == Class::Request) handleConnectionBind(msg, tcpConn);
		break;
	default:
		if (msg.cls == Class::Request) {
			if (tcpConn) sendErrorResponseTcp(*tcpConn, msg, StunErrorBadRequest);
			else sendErrorResponseUdp(src, msg, StunErrorBadRequest);
		}
		break;
	}
}

// ---- STUN Binding ---------------------------------------------------------

void TurnServer::handleBinding(Message &req, const AddrRecord &src, TcpConn *tcpConn) {
	Message resp;
	resp.method = Method::Binding;
	resp.cls = Class::SuccessResponse;
	resp.transactionID = req.transactionID;
	// XOR-MAPPED-ADDRESS reflects the client's reflexive address: the UDP
	// packet source or the TCP control connection's peer.
	writeXorAddress(resp, AttrType::XorMappedAddress, src, req.transactionID);
	resp.encode(nullptr, nullptr, "stserver");
	if (tcpConn) sendTcp(*tcpConn, resp);
	else sendUdp(src, resp);
}

// ---- TURN Allocate --------------------------------------------------------

void TurnServer::handleAllocate(Message &req, const AddrRecord &src, TcpConn *tcpConn,
                                 Allocation *alloc) {
	(void)alloc;
	const Attribute *rt = req.find(AttrType::RequestedTransport);
	if (!rt || rt->value.empty()) {
		if (tcpConn) sendErrorResponseTcp(*tcpConn, req, StunErrorBadRequest);
		else sendErrorResponseUdp(src, req, StunErrorBadRequest);
		return;
	}
	std::uint8_t proto = rt->value[0]; // 17=UDP, 6=TCP

	if (static_cast<int>(allocations_.size()) >= maxAllocations_) {
		if (tcpConn) sendErrorResponseTcp(*tcpConn, req, StunErrorAllocationQuotaReached);
		else sendErrorResponseUdp(src, req, StunErrorAllocationQuotaReached);
		return;
	}

	std::string username = getString(req, AttrType::Username);

	auto a = std::make_unique<Allocation>();
	a->transport = (proto == 6) ? SOCK_STREAM : SOCK_DGRAM;
	a->clientAddr = src;
	a->username = username;

	if (proto == 6) {
		// RFC 6062 TCP allocation: no relay socket, allocate a unique relayed
		// port from the range and advertise the server's TCP relay address.
		std::uint16_t port = allocRelayPort({});
		if (port == 0) {
			if (tcpConn) sendErrorResponseTcp(*tcpConn, req, StunErrorInsufficientCapacity);
			else sendErrorResponseUdp(src, req, StunErrorInsufficientCapacity);
			return;
		}
		a->relayPort = port;
		buildRelayedAddr(port, a->relayedAddr);
		a->controlSock = tcpConn ? tcpConn->sock : STICE_INVALID_SOCKET;
	} else {
		// UDP allocation: bind a relay socket on a port from the range.
		// Ports whose bind fails are remembered in `failed` and excluded from
		// subsequent picks, so the retry loop always advances to a fresh
		// port instead of spinning on the same (unbindable) one.
		std::set<std::uint16_t> failed;
		std::uint16_t port = allocRelayPort(failed);
		if (port == 0) {
			if (tcpConn) sendErrorResponseTcp(*tcpConn, req, StunErrorInsufficientCapacity);
			else sendErrorResponseUdp(src, req, StunErrorInsufficientCapacity);
			return;
		}
		UdpSocketConfig rcfg;
		// Bind the relay socket to the SAME address advertised in RELAYED-ADDRESS
		// (relayIp_), not the control-plane listener address. When listening on
		// 0.0.0.0/:: the relayed address is the loopback 127.0.0.1, and binding the
		// relay socket to INADDR_ANY lets the loopback stack mis-deliver UDP to a
		// sibling 0.0.0.0 socket (cross-talk) under concurrent allocations.
		rcfg.bindAddress = relayIp_;
		rcfg.portBegin = port;
		rcfg.portEnd = port;
		UdpSocket rs = UdpSocket::create(rcfg);
		int tries = 0;
		while (!rs.valid() && tries < 50) {
			failed.insert(port);
			releaseRelayPort(port, nullptr);
			port = allocRelayPort(failed);
			if (port == 0) break;
			rcfg.portBegin = port;
			rcfg.portEnd = port;
			rs = UdpSocket::create(rcfg);
			++tries;
		}
		if (!rs.valid()) {
			if (port != 0) releaseRelayPort(port, nullptr);
			if (tcpConn) sendErrorResponseTcp(*tcpConn, req, StunErrorInsufficientCapacity);
			else sendErrorResponseUdp(src, req, StunErrorInsufficientCapacity);
			return;
		}
		setUdpBuf(rs.handle(), 64 * 1024 * 1024);
		// Use the actual bound port. With portBegin==portEnd the bound port
		// equals the reserved one; defensively move the reservation if it
		// differs so release stays exact.
		std::uint16_t reserved = port;
		AddrRecord bound;
		if (rs.boundAddr(bound)) {
			port = addrPort(reinterpret_cast<sockaddr *>(&bound.addr));
		}
		if (port != reserved) {
			releaseRelayPort(reserved, nullptr);
			usedRelayPorts_[port] = nullptr;
		}
		a->relayPort = port;
		a->relaySock = std::move(rs);
		buildRelayedAddr(port, a->relayedAddr);
		// RFC 8656: the allocation's 5-tuple is the control connection it was
		// created on, regardless of the relayed transport. Keep the TCP/TLS
		// control socket so the control plane (CreatePermission, ChannelBind,
		// Refresh, Send, ChannelData) and peer-data forwarding can find and
		// reach this allocation.
		a->controlSock = tcpConn ? tcpConn->sock : STICE_INVALID_SOCKET;
	}

	std::uint32_t lifetime = allocationLifetime_;
	a->expiryMs = nowMs() + static_cast<std::int64_t>(lifetime) * 1000;

	// Build the success response: XOR-RELAYED-ADDRESS, LIFETIME, XOR-MAPPED-ADDRESS.
	Message resp;
	writeXorAddress(resp, AttrType::XorRelayedAddress, a->relayedAddr, req.transactionID);
	writeXorAddress(resp, AttrType::XorMappedAddress, src, req.transactionID);
	addLifetime(resp, lifetime);
	sendSuccessResponse(req, username, resp);

	// Register in lookup maps before sending.
	std::string key = allocKey(a->transport, src);
	Allocation *raw = a.get();
	// Commit relay-port ownership: the reservation held owner=nullptr during
	// Allocate; from here only this allocation may release the port.
	usedRelayPorts_[a->relayPort] = raw;
	if (a->transport == SOCK_DGRAM) {
		{
			std::lock_guard<std::mutex> lk(relayMapMutex_);
			allocByRelaySock_[a->relaySock.handle()] = raw;
			allocByRelayAddr_[a->relayedAddr] = raw;
		}
		{
			std::lock_guard<std::mutex> lk(clientMapMutex_);
			allocByClientAddr_[src] = raw;
		}
		// Register the relay socket with the IO backend so it starts
		// monitoring for incoming peer data.
		if (ioBackend_) ioBackend_->addRelaySocket(a->relaySock.handle());
	} else {
		allocByControlSock_[a->controlSock] = raw;
	}
	// RFC 8656 over a TCP/TLS control connection: a UDP-relay allocation is
	// reachable from BOTH its relay socket (peer data plane) and its control
	// connection (control plane + ChannelData). Key it by the control socket
	// as well so handleTcpFrame finds it. destroyAllocation cleans both maps.
	if (tcpConn && a->controlSock != STICE_INVALID_SOCKET)
		allocByControlSock_[a->controlSock] = raw;
	allocations_[key] = std::move(a);

	if (tcpConn) sendTcp(*tcpConn, resp);
	else sendUdp(src, resp);

	STICE_LOG_INFO("stserver: ALLOCATE %s transport=%s relayed=%s user=%s",
	               key.c_str(), proto == 6 ? "TCP" : "UDP",
	               raw->relayedAddr.toString().c_str(), username.c_str());
}

// ---- TURN Refresh ---------------------------------------------------------

void TurnServer::handleRefresh(Message &req, const AddrRecord &src, TcpConn *tcpConn,
                               Allocation *alloc) {
	std::uint32_t lifetime = allocationLifetime_;
	if (readLifetime(req, lifetime)) {
		if (lifetime > allocationLifetime_) lifetime = allocationLifetime_;
	}
	Message resp;
	if (lifetime == 0) {
		addLifetime(resp, 0);
	} else {
		alloc->expiryMs = nowMs() + static_cast<std::int64_t>(lifetime) * 1000;
		addLifetime(resp, lifetime);
	}
	sendSuccessResponse(req, alloc->username, resp);
	if (tcpConn) sendTcp(*tcpConn, resp);
	else sendUdp(src, resp);

	if (lifetime == 0) {
		STICE_LOG_INFO("stserver: REFRESH lifetime=0 deleting allocation %s",
		               alloc->clientAddr.toString().c_str());
		destroyAllocation(alloc);
	}
}

// ---- TURN CreatePermission -----------------------------------------------

void TurnServer::handleCreatePermission(Message &req, const AddrRecord &src, TcpConn *tcpConn,
                                        Allocation *alloc) {
	std::int64_t expiry = nowMs() + PermissionLifetimeMs;
	int added = 0;
	// alloc->permissions is traversed by the IO data plane (handleChannelDataFrame
	// / forwardToClient on reader threads) under alloc->mtx. Those readers do NOT
	// hold stateMutex_, so the control-plane stateMutex_ does not serialize
	// against them: this writer MUST take alloc->mtx too.
	{
		std::lock_guard<std::mutex> al(alloc->mtx);
		// A single request may carry multiple XOR-PEER-ADDRESS attributes
		// (RFC 8656 §3.3). Decode each against the request transaction id.
		for (const auto &a : req.attributes) {
			if (a.type != AttrType::XorPeerAddress) continue;
			Message tmp;
			tmp.transactionID = req.transactionID;
			tmp.addAttribute(AttrType::XorPeerAddress, a.value);
			AddrRecord peer;
			if (!readXorAddress(tmp, AttrType::XorPeerAddress, peer, req.transactionID)) continue;
			// Replace existing permission for the same peer IP (port ignored).
			bool found = false;
			for (auto &p : alloc->permissions) {
				if (samePeerIP(p.peer, peer)) {
					p.peer = peer;
					p.expiryMs = expiry;
					found = true;
					break;
				}
			}
			if (!found) {
				alloc->permissions.push_back({peer, expiry});
			}
			++added;
		}
	}
	(void)added;
	Message resp;
	sendSuccessResponse(req, alloc->username, resp);
	if (tcpConn) sendTcp(*tcpConn, resp);
	else sendUdp(src, resp);
}

// ---- TURN ChannelBind -----------------------------------------------------

void TurnServer::handleChannelBind(Message &req, const AddrRecord &src, TcpConn *tcpConn,
                                   Allocation *alloc) {
	std::uint16_t channel = 0;
	if (!readChannelNumber(req, channel) || !channelValid(channel)) {
		if (tcpConn) sendErrorResponseTcp(*tcpConn, req, StunErrorBadRequest);
		else sendErrorResponseUdp(src, req, StunErrorBadRequest);
		return;
	}
	AddrRecord peer;
	if (!readXorAddress(req, AttrType::XorPeerAddress, peer, req.transactionID)) {
		if (tcpConn) sendErrorResponseTcp(*tcpConn, req, StunErrorBadRequest);
		else sendErrorResponseUdp(src, req, StunErrorBadRequest);
		return;
	}
	// Validation and mutation both touch alloc->channels/alloc->permissions,
	// which the IO data plane traverses under alloc->mtx without holding
	// stateMutex_. Take alloc->mtx for the whole inspect-then-mutate section so
	// a concurrent reader can never observe a half-updated container. Error
	// responses are sent after the lock is released (no I/O under the lock).
	bool badBinding = false;
	{
		std::lock_guard<std::mutex> al(alloc->mtx);
		// A channel number may bind to only one peer and vice versa.
		for (const auto &c : alloc->channels) {
			if ((c.number == channel && !samePeerIP(c.peer, peer)) ||
			    (samePeerIP(c.peer, peer) && c.number != channel)) {
				badBinding = true;
				break;
			}
		}
		if (!badBinding) {
			std::int64_t expiry = nowMs() + ChannelBindLifetimeMs;
			bool updated = false;
			for (auto &c : alloc->channels) {
				if (c.number == channel) {
					c.peer = peer;
					c.expiryMs = expiry;
					updated = true;
					break;
				}
			}
			if (!updated) alloc->channels.push_back({channel, peer, expiry});

			// ChannelBind also installs a permission for the peer (RFC 8656 §2.6).
			bool permFound = false;
			for (auto &p : alloc->permissions) {
				if (samePeerIP(p.peer, peer)) {
					p.expiryMs = nowMs() + PermissionLifetimeMs;
					permFound = true;
					break;
				}
			}
			if (!permFound) alloc->permissions.push_back({peer, nowMs() + PermissionLifetimeMs});
		}
	}
	if (badBinding) {
		if (tcpConn) sendErrorResponseTcp(*tcpConn, req, StunErrorBadRequest);
		else sendErrorResponseUdp(src, req, StunErrorBadRequest);
		return;
	}

	Message resp;
	sendSuccessResponse(req, alloc->username, resp);
	if (tcpConn) sendTcp(*tcpConn, resp);
	else sendUdp(src, resp);
}

// ---- TURN Send Indication (client -> peer) -------------------------------

void TurnServer::handleSendIndication(Message &req, Allocation *alloc) {
	AddrRecord peer;
	if (!readXorAddress(req, AttrType::XorPeerAddress, peer, req.transactionID)) return;
	const Attribute *dataAttr = req.find(AttrType::Data);
	if (!dataAttr) return;
	// Require a permission for the peer's IP. Take alloc->mtx for the same
	// reason the other control-plane accessors do: the IO data plane traverses
	// alloc->permissions under it without holding stateMutex_.
	bool permitted = false;
	std::size_t permCount = 0;
	{
		std::lock_guard<std::mutex> al(alloc->mtx);
		permCount = alloc->permissions.size();
		for (const auto &p : alloc->permissions) {
			if (samePeerIP(p.peer, peer) && p.expiryMs > nowMs()) { permitted = true; break; }
		}
	}
	STICE_LOG_DEBUG("SEND-IND alloc_client=%s peer=%s perm=%d relay=%u size=%zu",
	               alloc->clientAddr.toString().c_str(), peer.toString().c_str(),
	               permitted ? 1 : 0, alloc->relayPort, dataAttr->value.size());
	if (!permitted) {
		STICE_LOG_WARN("SEND-IND-DENY alloc_client=%s peer=%s perm_count=%zu relay=%u size=%zu",
		               alloc->clientAddr.toString().c_str(), peer.toString().c_str(),
		               permCount, alloc->relayPort, dataAttr->value.size());
		return;
	}
	// Loopback self-echo probe: a client sending to its OWN relay port (peer
	// port == this allocation's relay port) is the round2 failure signature.
	if (addrPort(reinterpret_cast<const sockaddr *>(&peer.addr)) == alloc->relayPort)
		STICE_LOG_WARN("FWD_LOOP_INDIC: alloc_client=%s peer=%s relay_port=%u size=%zu",
		               alloc->clientAddr.toString().c_str(), peer.toString().c_str(),
		               alloc->relayPort, dataAttr->value.size());
	if (alloc->transport == SOCK_DGRAM && alloc->relaySock.valid())
		logSendToFailure(peer, alloc->relaySock.sendto(
		                     reinterpret_cast<const char *>(dataAttr->value.data()),
		                     static_cast<int>(dataAttr->value.size()), peer));
}

// ---- TURN ChannelData frame (client -> peer) -----------------------------

void TurnServer::handleChannelDataFrame(const unsigned char *data, std::size_t size,
                                         Allocation *alloc) {
	std::uint16_t channel = 0;
	const unsigned char *outData = nullptr;
	std::size_t frameSize = 0;
	std::size_t n = unwrapChannelData(data, size, channel, outData, frameSize);
	if (n == 0) return;
	// Decide under the per-alloc lock; send outside it so different allocations
	// are not serialized and the lock is not held across a relay sendto.
	AddrRecord peer;
	bool chFound = false;
	std::size_t chanCount = 0;
	bool selfLoop = false;
	{
		std::lock_guard<std::mutex> al(alloc->mtx);
		const Channel *ch = nullptr;
		for (const auto &c : alloc->channels) {
			if (c.number == channel) { ch = &c; break; }
		}
		chanCount = alloc->channels.size();
		if (ch) {
			peer = ch->peer;
			chFound = true;
			selfLoop = (addrPort(reinterpret_cast<const sockaddr *>(&ch->peer.addr)) ==
			            alloc->relayPort);
		}
	}
	// Logging (and its getnameinfo-backed toString()) happens OUTSIDE the
	// per-allocation critical section: at debug/warn level the string
	// formatting must not extend the lock hold time on the hot data path.
	STICE_LOG_DEBUG("CHDATA alloc_client=%s ch=%u matched=%d ch_peer=%s relay=%u size=%zu",
	               alloc->clientAddr.toString().c_str(), channel, chFound ? 1 : 0,
	               chFound ? peer.toString().c_str() : "-", alloc->relayPort, n);
	if (!chFound) {
		STICE_LOG_WARN("CHDATA-DENY alloc_client=%s ch=%u chan_count=%zu relay=%u size=%zu",
		               alloc->clientAddr.toString().c_str(), channel,
		               chanCount, alloc->relayPort, n);
		return;
	}
	if (selfLoop)
		STICE_LOG_WARN("FWD_LOOP_CHDATA: alloc_client=%s ch_peer=%s channel=%u relay_port=%u size=%zu",
		               alloc->clientAddr.toString().c_str(), peer.toString().c_str(),
		               channel, alloc->relayPort, n);
	if (!(alloc->transport == SOCK_DGRAM && alloc->relaySock.valid()))
		return;
	// Local-relay shortcut: if the peer address is one of THIS server's own
	// relayed addresses (both ends relay through us), deliver the datagram
	// straight to the destination allocation's client instead of sending it out
	// and reading it back through the kernel loopback. That removes two of the
	// four syscalls the relay performs per frame and roughly halves relay CPU
	// under heavy co-located load. Both authorization checks are still enforced:
	// the sender's channel binding above, and the destination's
	// channel/permission inside forwardToClient (which sees the source as the
	// sender's relayed address, exactly as if the packet had looped back).
	// Restricted to UDP-control destinations: TCP-control allocations must be
	// forwarded on the business thread, which owns the tcpBySock_ map.
	if (localRelayShortcut()) {
		Allocation *dst = findAllocByRelayAddrRef(peer);
		if (dst) {
			bool ok = (dst != alloc) && dst->transport == SOCK_DGRAM &&
			          dst->controlSock == STICE_INVALID_SOCKET && dst->relaySock.valid();
			if (ok) {
				forwardToClient(*dst, alloc->relayedAddr, outData, n);
				allocUnref(dst);
				return;
			}
			allocUnref(dst);
		}
	}
	logSendToFailure(peer, alloc->relaySock.sendto(
	                     reinterpret_cast<const char *>(outData),
	                     static_cast<int>(n), peer));
}

// ---- Relay data forwarding (peer -> client) ------------------------------

void TurnServer::forwardToClient(Allocation &alloc, const AddrRecord &peer,
                                 const unsigned char *data, std::size_t size) {
	// The path back to the client is the control connection the allocation was
	// created on (its 5-tuple, RFC 8656 §2.2), NOT the relayed transport. A
	// control socket means TCP/TLS control (both RFC 6062 TCP allocations and
	// RFC 8656 UDP-relay allocations over TCP/TLS control); no control socket
	// means the client is reached over UDP.
	forwardBytes_.fetch_add(size, std::memory_order_relaxed);
	const bool controlIsTcp = (alloc.controlSock != STICE_INVALID_SOCKET);
	STICE_LOG_DEBUG("FWD alloc_client=%s peer=%s control_is_tcp=%d", alloc.clientAddr.toString().c_str(),
	               peer.toString().c_str(), controlIsTcp ? 1 : 0);
	enum class Act { None, ChanUdp, ChanTcp, PermUdp, PermTcp };
	Act act = Act::None;
	stice::bytes frame;
	Message ind;
	TcpConn *dstTcp = nullptr;
	{
		std::lock_guard<std::mutex> al(alloc.mtx);
		// Prefer a bound channel for this peer (full IP:port).
		for (const auto &c : alloc.channels) {
			if (c.peer == peer && c.expiryMs > nowMs()) {
				if (wrapChannelData(c.number, data, size, frame) > 0) {
					if (controlIsTcp) {
						auto it = tcpBySock_.find(alloc.controlSock);
						if (it != tcpBySock_.end()) { dstTcp = it->second; act = Act::ChanTcp; }
					} else {
						act = Act::ChanUdp;
					}
				}
				break;
			}
		}
		if (act == Act::None) {
			// Otherwise, if a permission exists for the peer IP, send a Data indication.
			for (const auto &p : alloc.permissions) {
				if (samePeerIP(p.peer, peer) && p.expiryMs > nowMs()) {
					ind.method = Method::Data;
					ind.cls = Class::Indication;
					ind.newTransactionID();
					writeXorAddress(ind, AttrType::XorPeerAddress, peer, ind.transactionID);
					addData(ind, data, size);
					ind.encode(nullptr, nullptr, "stserver");
					if (controlIsTcp) {
						auto it = tcpBySock_.find(alloc.controlSock);
						if (it != tcpBySock_.end()) { dstTcp = it->second; act = Act::PermTcp; }
					} else {
						act = Act::PermUdp;
					}
					break;
				}
			}
		}
	}
	// Send after releasing the lock so relay workers forwarding different
	// allocations run fully in parallel. Client delivery uses this
	// allocation's OWN relay socket (independent per allocation), so
	// cross-allocation sends never serialize.
	switch (act) {
	case Act::ChanUdp:
		// Client listens on the control socket (udpListener_, 3478); relay data
		// must be delivered from that same address. Winsock UDP sendto on a
		// shared socket is thread-safe, so different forwarder threads send to
		// their own clients concurrently without serialization.
		logSendToFailure(alloc.clientAddr, udpListener_.sendto(
		                     reinterpret_cast<const char *>(frame.data()),
		                     static_cast<int>(frame.size()), alloc.clientAddr));
		forwardOk_.fetch_add(1, std::memory_order_relaxed);
		break;
	case Act::ChanTcp:
		sendTcpRaw(*dstTcp, frame.data(), frame.size());
		break;
	case Act::PermUdp:
		logSendToFailure(alloc.clientAddr, udpListener_.sendto(
		                     reinterpret_cast<const char *>(ind.raw.data()),
		                     static_cast<int>(ind.raw.size()), alloc.clientAddr));
		forwardOk_.fetch_add(1, std::memory_order_relaxed);
		break;
	case Act::PermTcp:
		sendTcp(*dstTcp, ind);
		break;
	default:
		STICE_LOG_WARN("FWD relay=%u DROP from=%s len=%zu", alloc.relayPort, peer.toString().c_str(), size);
		forwardDrop_.fetch_add(1, std::memory_order_relaxed);
		break;
	}
	// No permission/channel: drop per RFC 8656 §2.5.
}

// ---- RFC 6062: CONNECT / CONNECTION-ATTEMPT / CONNECTION-BIND -------------
//
// SCOPE / INTEROP CAVEATS - this is a deliberately reduced RFC 6062 server.
// Read this before treating the TCP-relay path as standard-conformant:
//
//  * SINGLE-SERVER ONLY (single-server assumption). The CONNECT target is found
//    by scanning THIS server's own allocation table for a TCP allocation whose
//    relayed address equals XOR-PEER-ADDRESS (findTcpAllocByPeer). Both peers
//    must therefore be allocated on the same stserver instance. RFC 6062 §5.3
//    also covers a peer that is allocated on ANOTHER TURN server (resolved
//    server-to-server, with the two servers relaying between them); that path
//    is not implemented here.
//
//  * NON-STANDARD ERROR MAPPING. A peer address that is not currently allocated
//    is answered with 403 (Forbidden). RFC 6062 §5.3.5 specifies 447
//    (Connection Timeout or Failure) for exactly that case - 446 (Connection
//    Already Exists) is only for a connection that already exists. Our client
//    and server agree with each other (the client retries on 447), but a
//    standard RFC 6062 client would not read 403 as a retryable condition.
//
//  * The server never dials the peer itself: it only forwards a
//    CONNECTION-ATTEMPT indication so the peer opens a data connection and
//    sends CONNECTION-BIND (see handleConnectionBind). The relayed-address
//    listener belongs to the peer's own TCP allocation.
//
//  * The CONNECT initiator is chosen by a stice/libjuice ufrag comparison on
//    the client side (Agent::shouldInitiateTcpConnect), not by the candidate
//    roles as RFC 6062/6544 describe - see the caveat on that method.

void TurnServer::sendConnectionAttempt(Allocation &targetAlloc, std::uint32_t connId,
                                        const AddrRecord &peerRelayAddr) {
	Message ind;
	ind.method = Method::ConnectionAttempt;
	ind.cls = Class::Indication;
	ind.newTransactionID();
	writeXorAddress(ind, AttrType::XorPeerAddress, peerRelayAddr, ind.transactionID);
	addConnectionId(ind, connId);
	ind.encode(nullptr, nullptr, "stserver");
	auto it = tcpBySock_.find(targetAlloc.controlSock);
	if (it != tcpBySock_.end()) sendTcp(*it->second, ind);
}

void TurnServer::handleConnect(Message &req, TcpConn *tcpConn, Allocation *alloc) {
	AddrRecord peer;
	if (!readXorAddress(req, AttrType::XorPeerAddress, peer, req.transactionID)) {
		sendErrorResponseTcp(*tcpConn, req, StunErrorBadRequest);
		return;
	}
	// Find the peer's TCP allocation whose relayed address matches.
	Allocation *target = findTcpAllocByPeer(peer, alloc);
	if (!target) {
		sendErrorResponseTcp(*tcpConn, req, StunErrorForbidden);
		return;
	}
	std::uint32_t connId = nextConnId_++;
	Allocation::PendingConnect pc;
	pc.connId = connId;
	pc.peerRelayAddr = peer;
	pc.firstDataSock = STICE_INVALID_SOCKET;
	pc.connectTid = req.transactionID;
	pc.connectResponded = false;
	pc.expiryMs = nowMs() + PendingConnectLifetimeMs;
	alloc->pendingConnects.push_back(std::move(pc));
	pendingByConnId_[connId] = alloc;

	// Notify the peer so it opens a data connection and sends CONNECTION-BIND.
	sendConnectionAttempt(*target, connId, alloc->relayedAddr);
	STICE_LOG_INFO("stserver: CONNECT connId=%u from %s to peer %s",
	               connId, alloc->clientAddr.toString().c_str(),
	               target->clientAddr.toString().c_str());
}

void TurnServer::handleConnectionBind(Message &req, TcpConn *tcpConn) {
	if (!tcpConn) return;
	// Authenticate on the new connection using supplied long-term credentials.
	std::string user;
	int code = authenticate(req, user);
	if (code != 0) {
		sendAuthErrorResponseTcp(*tcpConn, req, code);
		return;
	}
	std::uint32_t connId = 0;
	if (!readConnectionId(req, connId)) {
		sendErrorResponseTcp(*tcpConn, req, StunErrorBadRequest);
		return;
	}
	Allocation::PendingConnect *pc = nullptr;
	Allocation *connector = findPendingByConnId(connId, &pc);
	if (!pc) {
		sendErrorResponseTcp(*tcpConn, req, StunErrorAllocationMismatch);
		return;
	}

	if (pc->firstDataSock == STICE_INVALID_SOCKET) {
		// First CONNECTION-BIND (typically the peer): record the data socket
		// and release the held CONNECT success response to the connector.
		pc->firstDataSock = tcpConn->sock;
		tcpConn->isData = true;
		tcpConn->connId = connId;
		{ std::lock_guard<std::mutex> lk(connClassMutex_); dataConns_.insert(tcpConn->sock); }

		if (!pc->connectResponded) {
			// Respond to the original CONNECT with CONNECTION-ID + MI.
			Message connectResp;
			addConnectionId(connectResp, connId);
			Message connectReq;
			connectReq.method = Method::Connect;
			connectReq.cls = Class::Request;
			connectReq.transactionID = pc->connectTid;
			sendSuccessResponse(connectReq, connector->username, connectResp);
			auto it = tcpBySock_.find(connector->controlSock);
			if (it != tcpBySock_.end()) sendTcp(*it->second, connectResp);
			pc->connectResponded = true;
		}

		// Respond to this CONNECTION-BIND with success + MI.
		Message bindResp;
		Message bindReq;
		bindReq.method = Method::ConnectionBind;
		bindReq.cls = Class::Request;
		bindReq.transactionID = req.transactionID;
		sendSuccessResponse(bindReq, user, bindResp);
		sendTcp(*tcpConn, bindResp);
		STICE_LOG_INFO("stserver: CONNECTION-BIND first connId=%u", connId);
	} else {
		// Second CONNECTION-BIND (the connector): pair the two data sockets.
		tcpConn->isData = true;
		tcpConn->connId = connId;
		// Send THIS connection's CONNECTION-BIND success response BEFORE the pair
		// is published to the data-pipe fast path. The response is an unframed
		// STUN message while the relayed peer stream is RFC 4571 framed: if an IO
		// worker won the race and relayed a chunk into this socket first, the
		// response would be spliced into the MIDDLE of the RFC 4571 stream and the
		// peer's de-framer would drift (it then reads payload bytes as a length --
		// observed as tcpturn rx_total > sent_total with the epoll backend, whose
		// 8 IO workers race the business thread far more often than select).
		Message bindResp;
		Message bindReq;
		bindReq.method = Method::ConnectionBind;
		bindReq.cls = Class::Request;
		bindReq.transactionID = req.transactionID;
		sendSuccessResponse(bindReq, user, bindResp);
		sendTcp(*tcpConn, bindResp);
		{ std::lock_guard<std::mutex> lk(connClassMutex_); dataConns_.insert(tcpConn->sock); }
		dataPipe_[tcpConn->sock] = pc->firstDataSock;
		dataPipe_[pc->firstDataSock] = tcpConn->sock;
		// Publish the fast-path peer pointers LAST, and only now that this
		// connection's bind response is already queued. Once visible here,
		// ioOnTcpConnData() relays directly on IO worker threads, so both ends
		// must be fully paired AND the response already ordered ahead of the data.
		{
			auto fit = tcpBySock_.find(pc->firstDataSock);
			if (fit != tcpBySock_.end()) {
				std::lock_guard<std::mutex> lk(pipeMapMutex_);
				dataPipePeer_[tcpConn->sock] = fit->second;
				dataPipePeer_[pc->firstDataSock] = tcpConn;
			}
		}
		// Pairing is published: release whatever either connection buffered
		// while this CONNECTION-ID was half-bound (RFC 6062 Section 5.4). The
		// buffered bytes MUST precede any later chunk. That holds because the
		// flush runs here on the single business thread: a chunk enqueued before
		// this CONNECTION-BIND was either already processed (so it is in the
		// buffer and is flushed now) or is still queued (control is drained
		// before data, and by the time it is processed the pair exists, so it
		// relays directly -- i.e. after this flush).
		flushPrePair(*tcpConn);
		{
			auto fit = tcpBySock_.find(pc->firstDataSock);
			if (fit != tcpBySock_.end()) flushPrePair(*fit->second);
		}
		STICE_LOG_INFO("stserver: CONNECTION-BIND second connId=%u paired", connId);

		// Pending connect is fulfilled; retire it.
		pendingByConnId_.erase(connId);
		auto &v = connector->pendingConnects;
		v.erase(std::remove_if(v.begin(), v.end(),
		                       [connId](const Allocation::PendingConnect &p) { return p.connId == connId; }),
		        v.end());
	}
}

// ---- TCP connection management -------------------------------------------

void TurnServer::closeTcpConn(TcpConn *conn) {
	if (!conn) return;
	socket_t s = conn->sock;
	if (s == STICE_INVALID_SOCKET) return; // already closed (idempotent)
	// If this was a control connection, tear down its allocation.
	Allocation *a = nullptr;
	{
		auto it = allocByControlSock_.find(s);
		if (it != allocByControlSock_.end()) a = it->second;
	}
	if (a) {
		std::string key = allocKey(a->transport, a->clientAddr);
		// Full cleanup: IO unbind, lookup maps, relay port, map entry.
		destroyAllocation(a);
		STICE_LOG_INFO("stserver: allocation deleted (TCP control closed) %s", key.c_str());
	}
	// Remove from RFC 6062 data pipe (both directions).
	auto dp = dataPipe_.find(s);
	if (dp != dataPipe_.end()) {
		dataPipe_.erase(dp->second);
		dataPipe_.erase(dp);
	}
	// Unpublish the fast-path peer pointers and mark the connection dying in one
	// critical section, so no NEW IO-thread reference can be taken from here on
	// (dataPipePeerRef checks dying under the same lock). Entries pointing at
	// this connection are dropped too: a half-closed pipe must stop relaying.
	{
		std::lock_guard<std::mutex> lk(pipeMapMutex_);
		conn->dying.store(true, std::memory_order_release);
		for (auto it = dataPipePeer_.begin(); it != dataPipePeer_.end();) {
			if (it->first == s || it->second == conn) it = dataPipePeer_.erase(it);
			else ++it;
		}
	}
	// Wait for in-flight fast-path references to drain before closing the socket
	// and freeing the connection (same event-driven protocol as
	// destroyAllocation: no bare yield-spin, and a stuck IO worker is reported
	// loudly instead of freeing underneath it - that would be a use-after-free).
	if (conn->ioUsers.load(std::memory_order_acquire) != 0) {
		ioUsersWaiters_.fetch_add(1, std::memory_order_relaxed);
		{
			std::unique_lock<std::mutex> lk(ioUsersMutex_);
			while (conn->ioUsers.load(std::memory_order_acquire) != 0) {
				if (ioUsersCv_.wait_for(lk, std::chrono::seconds(1)) ==
				    std::cv_status::timeout) {
					STICE_LOG_ERROR("stserver: closeTcpConn waiting on ioUsers_=%d (>1s); IO worker stuck?",
					                conn->ioUsers.load(std::memory_order_acquire));
				}
			}
		}
		ioUsersWaiters_.fetch_sub(1, std::memory_order_relaxed);
	}
	// Notify the IO backend to stop monitoring this socket.
	if (ioBackend_) ioBackend_->removeTcpConn(s);
	{
		std::lock_guard<std::mutex> lk(connClassMutex_);
		dataConns_.erase(s);
	}
	tcpBySock_.erase(s);
	if (s != STICE_INVALID_SOCKET) sticeClosesocket(s);
	conn->sock = STICE_INVALID_SOCKET;
	// Erase from tcpConns_.
	for (auto it = tcpConns_.begin(); it != tcpConns_.end(); ++it) {
		if (it->get() == conn) { tcpConns_.erase(it); break; }
	}
}

// ---- Expiry ---------------------------------------------------------------

void TurnServer::expireStale() {
	std::int64_t now = nowMs();
	if (now >= nonceExpiryMs_) refreshNonce();
	for (auto it = allocations_.begin(); it != allocations_.end();) {
		Allocation *a = it->second.get();
		// These containers are traversed by the IO data plane
		// (handleChannelDataFrame / forwardToClient) under alloc->mtx, and that
		// fast path does NOT hold stateMutex_ - so the erase below must take
		// alloc->mtx, otherwise it races a concurrent traversal (UB, iterator
		// invalidation).
		bool expired = false;
		{
			std::lock_guard<std::mutex> al(a->mtx);
			// Expire permissions.
			auto &p = a->permissions;
			p.erase(std::remove_if(p.begin(), p.end(),
			                       [now](const Permission &perm) { return perm.expiryMs <= now; }),
			        p.end());
			// Expire channels.
			auto &c = a->channels;
			c.erase(std::remove_if(c.begin(), c.end(),
			                       [now](const Channel &ch) { return ch.expiryMs <= now; }),
			        c.end());
			// Expire pending connects.
			auto &pc = a->pendingConnects;
			for (const auto &x : pc)
				if (x.expiryMs <= now) pendingByConnId_.erase(x.connId);
			pc.erase(std::remove_if(pc.begin(), pc.end(),
			                        [now](const Allocation::PendingConnect &p) { return p.expiryMs <= now; }),
			         pc.end());
			expired = (a->expiryMs <= now);
		}
		// Expire the allocation itself. Advance the iterator first:
		// destroyAllocation() erases the current map node. It must run with
		// a->mtx RELEASED - it waits for in-flight IO references to drain, and
		// an IO thread holding one may itself be blocked on a->mtx (deadlock).
		++it;
		if (expired) destroyAllocation(a);
	}
	// P1 safety net: force-release any relay port whose owner allocation no
	// longer exists. This runs ONCE per tick, after the allocation sweep - it
	// must not be nested inside the loop above (that made it O(allocations x
	// ports) per 50ms tick). Normally destroyAllocation() releases the port;
	// this only fires if a bug ever leaves an orphaned entry.
	for (auto pit = usedRelayPorts_.begin(); pit != usedRelayPorts_.end();) {
		const Allocation *owner = pit->second;
		if (owner != nullptr &&
			allocations_.count(allocKey(owner->transport, owner->clientAddr)) == 0) {
			STICE_LOG_WARN("stserver: orphaned relay port %u force-released", pit->first);
			pit = usedRelayPorts_.erase(pit);
		} else {
			++pit;
		}
	}
}

// ---- IoBackendOwner callbacks --------------------------------------------
// These are called from IO worker threads. They never touch shared state
// directly: each event is copied into a WorkItem and pushed onto the
// control or data queue. A single business thread (businessLoop) drains
// the control queue first — control (STUN/TURN) is prioritized over data
// but keeps its own arrival order (FIFO) — then the data queue (relay
// forwarding, RFC 6062 data pipes, write flushes).

void TurnServer::ioOnUdpData(const unsigned char *data, std::size_t len,
                              const stice::net::AddrRecord &from) {
	controlBytes_.fetch_add(len, std::memory_order_relaxed);
	// Client->Peer fast path: ChannelData frames are forwarded directly on this
	// IO worker thread (per-allocation lock, no stateMutex_), so concurrent
	// allocations' peer direction runs in parallel instead of serializing on the
	// single business thread. TCP-control or unknown allocations fall back to the
	// control queue; STUN control frames always take the queue.
	if (isChannelData(data, len)) {
		Allocation *a = findAllocByClientRef(from);
		if (a) {
			handleChannelDataFrame(data, len, a);
			allocUnref(a);
			return;
		}
	}
	WorkItem it;
	it.kind = WorkItem::Kind::UdpData;
	it.from = from;
	it.data.assign(data, data + len);
	enqueueControl(std::move(it));
}

void TurnServer::ioOnTcpAccepted(socket_t sock, const stice::net::AddrRecord &peer) {
	WorkItem it;
	it.kind = WorkItem::Kind::TcpAccepted;
	it.sock = sock;
	it.from = peer;
	enqueueControl(std::move(it));
}

void TurnServer::ioOnRelayData(socket_t relaySock, const unsigned char *data,
                                std::size_t len, const stice::net::AddrRecord &from) {
	Allocation *a = findAllocByRelayRef(relaySock);
	if (!a) return;
	relayReadBytes_.fetch_add(len, std::memory_order_relaxed);
	// Relay data-plane fast path: UDP-control allocations are forwarded directly
	// on this IO worker thread (parallel across allocations). TCP-control
	// allocations still go through the single business thread to keep
	// tcpBySock_/write-buffer access serialized (avoids a alloc->mtx vs
	// stateMutex_ lock-order deadlock and non-thread-safe TCP writes).
	if (a->controlSock == STICE_INVALID_SOCKET) {
		forwardToClient(*a, from, data, len);
	} else {
		WorkItem it;
		it.kind = WorkItem::Kind::RelayData;
		it.sock = relaySock;
		it.from = from;
		it.data.assign(data, data + len);
		enqueueData(std::move(it));
	}
	allocUnref(a);
}

void TurnServer::ioOnTcpConnData(socket_t connSock, const unsigned char *data,
                                  std::size_t len) {
	// RFC 6062 data-pipe chunks go through the single business queue (one ordered
	// path per connection). The IO-worker fast path used to relay them inline and
	// could OVERTAKE a chunk that had been queued a moment earlier (pair publish
	// window): the peer then received the two chunks out of order. Reordering a
	// transparent byte pipe corrupts the RFC 6062 tunnel -- measured with a
	// per-block index stamped into the payload (send order 0,1,2,..,6,7,8,9,10..
	// arrived as 0..6,10,11,12,7,8,13.., i.e. whole frames inserted late) while the
	// byte totals stayed exact, which a byte-counting soak cannot see.
	WorkItem it;
	it.kind = WorkItem::Kind::TcpConnData;
	it.sock = connSock;
	it.data.assign(data, data + len);
	// Data pipes (RFC 6062, post CONNECTION-BIND) carry bulk peer data and
	// go to the data queue; control connections carry STUN/TURN frames and
	// go to the (prioritized, order-preserving) control queue.
	if (connIsDataSock(connSock))
		enqueueData(std::move(it));
	else
		enqueueControl(std::move(it));
}

void TurnServer::ioOnTcpConnClosed(socket_t connSock) {
	WorkItem it;
	it.kind = WorkItem::Kind::TcpConnClosed;
	it.sock = connSock;
	enqueueControl(std::move(it));
}

void TurnServer::ioOnTcpConnWritable(socket_t connSock) {
	WorkItem it;
	it.kind = WorkItem::Kind::TcpConnWritable;
	it.sock = connSock;
	enqueueData(std::move(it));
}

void TurnServer::ioOnTimerTick() {
	// No-op: the business thread drives expireStale() unconditionally on
	// its own 50ms schedule. (Previously only the select backend fired this
	// callback, so epoll/IOCP builds never expired allocations.)
}

// ---- Business dispatch ----------------------------------------------------

void TurnServer::enqueueControl(WorkItem &&item) {
	{
		std::lock_guard<std::mutex> lk(queueMutex_);
		controlQueue_.push_back(std::move(item));
	}
	queueCv_.notify_one();
}

void TurnServer::enqueueData(WorkItem &&item) {
	{
		std::lock_guard<std::mutex> lk(queueMutex_);
		dataQueue_.push_back(std::move(item));
	}
	queueCv_.notify_one();
}

void TurnServer::businessLoop() {
	boostBusinessThreadPriority();
	std::deque<WorkItem> controlBatch, dataBatch;
	std::int64_t lastTickMs = nowMs();
	std::int64_t lastStatMs = nowMs();
	while (running_) {
		{
			std::unique_lock<std::mutex> lk(queueMutex_);
			queueCv_.wait_for(lk, std::chrono::milliseconds(50), [&] {
				return !controlQueue_.empty() || !dataQueue_.empty() || !running_;
			});
			// Swap queues out so the lock is only held for the swap, not
			// while items are processed.
			controlBatch.swap(controlQueue_);
			dataBatch.swap(dataQueue_);
		}
		// Control first (FIFO within control), then data (FIFO within data).
		while (!controlBatch.empty()) {
			processItem(controlBatch.front());
			controlBatch.pop_front();
		}
		while (!dataBatch.empty()) {
			processItem(dataBatch.front());
			dataBatch.pop_front();
		}
		// Unconditional timer drive (all IO backends): expiry, nonce refresh.
		std::int64_t now = nowMs();
		if (now - lastTickMs >= 50) {
			lastTickMs = now;
			std::lock_guard<std::recursive_mutex> lk(stateMutex_);
			expireStale();
		}
		if (now - lastStatMs >= 5000) {
			lastStatMs = now;
			// The queue sizes MUST be read under queueMutex_: IO worker threads
			// push to both queues concurrently (enqueueControl/enqueueData), so
			// an unlocked size() here races on the deque internals (the deque
			// keeps its map/size in mutable state that push_back rewrites).
			// TSan reported exactly this read vs. enqueueControl's push_back.
			// Snapshot under the lock, then log after releasing it.
			std::size_t qc = 0, qd = 0;
			{
				std::lock_guard<std::mutex> lk(queueMutex_);
				qc = controlQueue_.size();
				qd = dataQueue_.size();
			}
			STICE_LOG_INFO("stserver: RELAY-STAT ctl=%llu read=%llu fwd=%llu ok=%llu drop=%llu qC=%zu qD=%zu",
			    static_cast<unsigned long long>(controlBytes_.load()),
			    static_cast<unsigned long long>(relayReadBytes_.load()),
			    static_cast<unsigned long long>(forwardBytes_.load()),
			    static_cast<unsigned long long>(forwardOk_.load()),
			    static_cast<unsigned long long>(forwardDrop_.load()),
			    qc, qd);
		}
	}
}

void TurnServer::processItem(const WorkItem &item) {
	std::lock_guard<std::recursive_mutex> lk(stateMutex_);
	switch (item.kind) {
	case WorkItem::Kind::UdpData:
		handleUdpPacket(item.data.data(), item.data.size(), item.from);
		break;
	case WorkItem::Kind::TcpAccepted:
		registerTcpConn(item.sock, item.from);
		break;
	case WorkItem::Kind::RelayData: {
		Allocation *a = findAllocByRelaySock(item.sock);
		if (a) forwardToClient(*a, item.from, item.data.data(), item.data.size());
		break;
	}
	case WorkItem::Kind::TcpConnData:
		handleTcpConnData(item.sock, item.data.data(), item.data.size());
		break;
	case WorkItem::Kind::TcpConnClosed: {
		auto it = tcpBySock_.find(item.sock);
		if (it != tcpBySock_.end()) closeTcpConn(it->second);
		break;
	}
	case WorkItem::Kind::TcpConnWritable: {
		auto it = tcpBySock_.find(item.sock);
		if (it != tcpBySock_.end()) {
			if (!flushTcp(*it->second)) closeTcpConn(it->second);
		}
		break;
	}
	}
}

void TurnServer::registerTcpConn(socket_t sock, const stice::net::AddrRecord &peer) {
	auto conn = std::make_unique<TcpConn>();
	conn->sock = sock;
	conn->peerAddr = peer;
	TcpConn *raw = conn.get();
	tcpBySock_[sock] = raw;
	tcpConns_.push_back(std::move(conn));
	// Register with the IO backend so it starts monitoring for readability.
	if (ioBackend_) ioBackend_->addTcpConn(sock, false);
	// DEBUG, not INFO: this fires once per accepted connection on the single
	// control thread, so at INFO it flooded the log during client-burst tests.
	STICE_LOG_DEBUG("stserver: TCP accept from %s", raw->peerAddr.toString().c_str());
}

// RFC 6062 Section 5.2/5.3: data that arrives on a data connection before its
// pair is published MUST be buffered. Section 7 allows a local-policy limit:
// a peer that streams into a half-bound connection past the cap is not
// following the protocol, so close it instead of buffering without bound.
// The window is only as long as the other side's CONNECTION-BIND round trip, so
// it normally holds a single ICE connectivity check.
namespace { constexpr std::size_t kPrePairBufCap = 256 * 1024; }

void TurnServer::appendPrePair(TcpConn &conn, const unsigned char *data,
                               std::size_t len) {
	if (conn.prePairBuf.size() + len > kPrePairBufCap) {
		STICE_LOG_WARN("stserver: data conn %llu exceeded pre-pair buffer cap "
		               "(%zu + %zu > %zu), closing (RFC 6062 Section 7)",
		               (unsigned long long)conn.sock, conn.prePairBuf.size(), len,
		               kPrePairBufCap);
		conn.prePairBuf.clear();
		closeTcpConn(&conn);
		return;
	}
	conn.prePairBuf.insert(conn.prePairBuf.end(), data, data + len);
	STICE_LOG_DEBUG("stserver: data conn %llu buffered %zu pre-pair bytes (total %zu)",
	                (unsigned long long)conn.sock, len, conn.prePairBuf.size());
}

void TurnServer::flushPrePair(TcpConn &conn) {
	if (conn.prePairBuf.empty()) return;
	auto pit = dataPipe_.find(conn.sock);
	if (pit == dataPipe_.end()) return; // still half-bound: keep buffering
	auto tit = tcpBySock_.find(pit->second);
	if (tit == tcpBySock_.end()) {
		conn.prePairBuf.clear();
		return;
	}
	STICE_LOG_DEBUG("stserver: data conn %llu flushing %zu pre-pair bytes",
	                (unsigned long long)conn.sock, conn.prePairBuf.size());
	sendTcpRaw(*tit->second, conn.prePairBuf.data(), conn.prePairBuf.size());
	conn.prePairBuf.clear();
}

void TurnServer::handleTcpConnData(socket_t connSock, const unsigned char *data,
                                    std::size_t len) {
	auto it = tcpBySock_.find(connSock);
	if (it == tcpBySock_.end()) {
		STICE_LOG_DEBUG("stserver: conn data for unknown sock=%llu len=%zu",
		                (unsigned long long)connSock, len);
		return;
	}
	TcpConn *conn = it->second;
	if (conn->isData) {
		// Raw RFC 6062 data pipe: forward bytes to the paired socket.
		auto pit = dataPipe_.find(connSock);
		if (pit == dataPipe_.end()) {
			// This CONNECTION-ID is only half-bound: the peer's data connection
			// has not sent CONNECTION-BIND yet, so there is no socket to relay
			// to. RFC 6062 Sections 5.2/5.3/5.4 require buffering until the pair
			// is published -- normally just the peer's first ICE connectivity
			// check, sent immediately after its own CONNECTION-BIND.
			appendPrePair(*conn, data, len);
			return;
		}
		auto tit = tcpBySock_.find(pit->second);
		if (tit == tcpBySock_.end()) {
			// The peer connection is gone (closed between pairing and now):
			// nothing to forward to, so drop the stale buffered prefix too.
			conn->prePairBuf.clear();
			STICE_LOG_DEBUG("stserver: data conn %llu peer %llu gone, dropping len=%zu",
			                (unsigned long long)connSock,
			                (unsigned long long)pit->second, len);
			return;
		}
		sendTcpRaw(*tit->second, data, len);
		return;
	}
	// STUN/ChannelData framing.
	conn->stunConn.feed(data, len);
	const unsigned char *frame = nullptr;
	std::size_t fs = 0;
	while ((fs = conn->stunConn.readFrame(frame)) != 0) {
		if (fs == static_cast<std::size_t>(-1)) {
			closeTcpConn(conn);
			return;
		}
		handleTcpFrame(*conn, frame, fs);
	}
}

// ---- RFC 6062 data-pipe fast path ----------------------------------------
// Resolve the peer connection of a paired data socket and take a lifetime
// reference on it. Mirrors findAllocByRelayRef: the map is guarded by its own
// mutex (never stateMutex_) so the data plane runs in parallel with the
// business thread, and dying_/ioUsers_ close the take-pointer -> deref race
// against closeTcpConn().
TcpConn *TurnServer::dataPipePeerRef(socket_t connSock) {
	std::lock_guard<std::mutex> lk(pipeMapMutex_);
	auto it = dataPipePeer_.find(connSock);
	if (it == dataPipePeer_.end()) return nullptr;
	TcpConn *peer = it->second;
	if (!peer || peer->dying.load(std::memory_order_acquire)) return nullptr;
	peer->ioUsers.fetch_add(1, std::memory_order_acq_rel);
	return peer;
}

void TurnServer::connUnref(TcpConn *conn) {
	if (!conn) return;
	// Same shape as allocUnref: the common case (nobody waiting) stays a single
	// atomic, which matters because this runs once per relayed data chunk.
	if (conn->ioUsers.fetch_sub(1, std::memory_order_acq_rel) == 1 &&
	    ioUsersWaiters_.load(std::memory_order_relaxed) > 0) {
		std::lock_guard<std::mutex> lk(ioUsersMutex_);
		ioUsersCv_.notify_all();
	}
}

bool TurnServer::connIsDataSock(socket_t s) const {
	// Consulted on every inbound TCP data packet by the IO thread. Use the
	// dedicated connClassMutex_/dataConns_ pair rather than stateMutex_: the
	// business thread holds stateMutex_ for the whole duration of each
	// control/data item, so sharing it made the TCP data plane serialize
	// against the control plane (the UDP data plane does not take it at all).
	std::lock_guard<std::mutex> lk(connClassMutex_);
	return dataConns_.find(s) != dataConns_.end();
}

// ---- Event loop -----------------------------------------------------------

void TurnServer::run() {
	running_ = true;
	if (!ioBackend_) {
		STICE_LOG_ERROR("stserver: no IO backend, cannot run");
		return;
	}
	// Start the business thread before the IO backend so no callback can
	// enqueue before the consumer is running.
	businessThread_ = std::thread([this] { businessLoop(); });
	ioBackend_->start();
	STICE_LOG_INFO("stserver: running (IO backend + business thread started)");
	// Block until stop() is called (sets running_ = false). Poll every 200ms
	// since stop() just flips an atomic — no condition variable to keep the
	// signal handler trivially safe.
	while (running_) {
		std::this_thread::sleep_for(std::chrono::milliseconds(200));
	}
	// Stop accepting new events, then join the business thread.
	ioBackend_->stop();
	queueCv_.notify_all();
	if (businessThread_.joinable()) businessThread_.join();
	STICE_LOG_INFO("stserver: stopped");
}

} // namespace stserver
