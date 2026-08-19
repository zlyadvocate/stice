/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "stice/net/tcp_mux.hpp"
#include "stice/log.hpp"
#include "stice/stun/attributes.hpp"
#include "stice/stun/message.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <unistd.h>
#endif

namespace stice::net {

// ---------------------------------------------------------------------------
// TcpMuxConn
// ---------------------------------------------------------------------------

TcpMuxConn::TcpMuxConn(socket_t fd, const AddrRecord &peerAddr, TCPMux *mux)
    : mux_(mux), peerAddr_(peerAddr), acceptedAt_(std::chrono::steady_clock::now()) {
	transport_ = std::make_unique<TcpTransport>();
	transport_->attach(fd, peerAddr);
	// Register with the parent TCPMux's PollRegistry so this conn shares
	// the same poll thread as the listener (needed for routing).
	if (mux_ && mux_->pollReg_) mux_->pollReg_->add(this);
	STICE_LOG_INFO("TCPMux: accepted connection from %s (fd=%d, pending)",
	               peerAddr.toString().c_str(), static_cast<int>(fd));
}

TcpMuxConn::~TcpMuxConn() {
	// Unregister from the parent TCPMux's PollRegistry (safe even if
	// already removed — remove() is a no-op for non-registered participants).
	if (mux_ && mux_->pollReg_) mux_->pollReg_->remove(this);
}

socket_t TcpMuxConn::tcpSocket() const {
	return transport_ ? transport_->handle() : STICE_INVALID_SOCKET;
}

short TcpMuxConn::tcpDesiredEvents() const {
	if (!transport_) return 0;
	auto state = transport_->state();
	if (state == TcpState::Disconnected || state == TcpState::Failed)
		return 0;
	short events = POLLIN;
	if (transport_->wantsWrite()) events |= POLLOUT;
	return events;
}

void TcpMuxConn::onTcpEvents(short events) {
	if (closed_ || !transport_) return;

	// Handle error/hangup first.
	if (events & (POLLERR | POLLHUP)) {
		if (!(events & POLLIN)) transport_->onReadable();
		if (!(events & POLLOUT)) transport_->onWritable();
	}
	if (events & POLLOUT) transport_->onWritable();
	if (events & POLLIN) {
		transport_->onReadable();
		if (!established_) {
			tryReadFirstPacket();
		} else {
			driveData();
		}
	}

	// Check if the transport failed or disconnected.
	auto state = transport_->state();
	if (state == TcpState::Failed || state == TcpState::Disconnected) {
		STICE_LOG_INFO("TCPMux: connection from %s closed (state=%d, established=%d)",
		               peerAddr_.toString().c_str(), static_cast<int>(state),
		               static_cast<int>(established_));
		closed_ = true;
		// Close the transport to invalidate the socket fd so the
		// PollRegistry stops polling it.
		transport_->close();
		// Notify TCPMux. The shared_ptr is dropped during onBookkeeping
		// to avoid destroying this object while onTcpEvents is on the
		// call stack.
		if (mux_) mux_->onConnClosed(this);
	}
}

void TcpMuxConn::tryReadFirstPacket() {
	// Read the first complete RFC 4571-framed message from the transport.
	char buf[65536];
	net::AddrRecord peer;
	int n = transport_->recv(buf, sizeof(buf), peer);
	if (n <= 0) return; // incomplete frame or no data yet

	STICE_LOG_DEBUG("TCPMux: first packet from %s (%d bytes)",
	                peerAddr_.toString().c_str(), n);

	// Parse as STUN to extract USERNAME → local ufrag.
	const auto *data = reinterpret_cast<const unsigned char *>(buf);
	if (!stun::Message::isMessage(data, static_cast<std::size_t>(n))) {
		STICE_LOG_WARN("TCPMux: first packet from %s is not STUN, closing",
		               peerAddr_.toString().c_str());
		transport_->close();
		closed_ = true;
		if (mux_) mux_->onConnClosed(this);
		return;
	}

	stun::Message msg;
	if (!msg.decode(data, static_cast<std::size_t>(n))) {
		STICE_LOG_WARN("TCPMux: STUN decode failed from %s, closing",
		               peerAddr_.toString().c_str());
		transport_->close();
		closed_ = true;
		if (mux_) mux_->onConnClosed(this);
		return;
	}

	std::string username = stun::getString(msg, stun::AttrType::Username);
	if (username.empty()) {
		STICE_LOG_WARN("TCPMux: STUN packet from %s has no USERNAME, closing",
		               peerAddr_.toString().c_str());
		transport_->close();
		closed_ = true;
		if (mux_) mux_->onConnClosed(this);
		return;
	}

	// USERNAME format: "localUfrag:remoteUfrag"
	auto colonPos = username.find(':');
	ufrag_ = (colonPos != std::string::npos)
	             ? username.substr(0, colonPos)
	             : username;

	STICE_LOG_INFO("TCPMux: first STUN packet from %s → local ufrag=%s",
	               peerAddr_.toString().c_str(), ufrag_.c_str());

	// Ask TCPMux to match the ufrag to an agent.
	if (mux_) mux_->onConnEstablished(this, ufrag_);

	// If matched, deliver the first packet to the agent.
	if (established_ && agent_ && agent_->onPacket) {
		agent_->onPacket(buf, n, peerAddr_);
	}

	// Also drain any additional frames that may have arrived.
	if (established_) {
		driveData();
	}
}

void TcpMuxConn::driveData() {
	if (!established_ || !agent_ || !agent_->onPacket) return;

	char buf[65536];
	net::AddrRecord peer;
	while (true) {
		int n = transport_->recv(buf, sizeof(buf), peer);
		if (n <= 0) break;
		agent_->onPacket(buf, n, peerAddr_);
	}
}

int TcpMuxConn::send(const char *data, std::size_t size) {
	if (!transport_ || transport_->state() != TcpState::Connected) {
		STICE_LOG_DEBUG("TCPMuxConn::send: not connected (state=%d)",
		                transport_ ? static_cast<int>(transport_->state()) : -1);
		return -1;
	}
	if (!transport_->send(data, size)) return -1;
	return static_cast<int>(size);
}

// ---------------------------------------------------------------------------
// TCPMux
// ---------------------------------------------------------------------------

TCPMux::TCPMux() = default;

TCPMux::~TCPMux() {
	// Full shutdown (P1-1): close the listener AND tear down all accepted
	// connections. Each TcpMuxConn is a PollParticipant; we must unregister
	// every one from the PollRegistry BEFORE dropping its shared_ptr, to
	// avoid a use-after-free race where the poll thread's dispatch loop or
	// bookkeeping snapshot still holds a raw pointer to a destroyed conn.
	{
		std::lock_guard<std::mutex> lock(mutex_);
		for (auto &p : pendingConns_) {
			p->close();
		}
		for (auto &kv : connsByAddr_) {
			kv.second->close();
		}
		agentsByUfrag_.clear();
	}
	// Tear down this TCPMux's own PollRegistry: unregister the listener
	// and all TcpMuxConns, sync to ensure the poll thread is no longer
	// referencing them, then release (delete) the instance.
	if (pollReg_) {
		pollReg_->remove(this);
		{
			std::lock_guard<std::mutex> lock(mutex_);
			for (auto &p : pendingConns_) {
				pollReg_->remove(p.get());
			}
			for (auto &kv : connsByAddr_) {
				pollReg_->remove(kv.second.get());
			}
		}
		pollReg_->sync();
		pollReg_->release();
		pollReg_ = nullptr;
	}
	if (listenSock_ != STICE_INVALID_SOCKET) {
		sticeClosesocket(listenSock_);
		listenSock_ = STICE_INVALID_SOCKET;
	}
	{
		std::lock_guard<std::mutex> lock(mutex_);
		pendingConns_.clear();
		connsByAddr_.clear();
	}
}

bool TCPMux::init(const std::string &bindAddress, std::uint16_t port) {
	// Parse the bind address. Empty → INADDR_ANY (IPv4).
	sockaddr_storage ss{};
	socklen_t ssLen = 0;
	int family = AF_INET;

	if (!bindAddress.empty()) {
		if (!net::parseAddr(bindAddress, port, ss, ssLen)) {
			STICE_LOG_ERROR("TCPMux: failed to parse bind address %s", bindAddress.c_str());
			return false;
		}
		family = ss.ss_family;
	} else {
		auto *sa4 = reinterpret_cast<sockaddr_in *>(&ss);
		sa4->sin_family = AF_INET;
		sa4->sin_addr.s_addr = htonl(INADDR_ANY);
		sa4->sin_port = htons(port);
		ssLen = sizeof(sockaddr_in);
	}

	listenSock_ = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
	if (listenSock_ == STICE_INVALID_SOCKET) {
		STICE_LOG_ERROR("TCPMux: socket creation failed errno=%d", sticeSockerrno);
		return false;
	}

	// Non-blocking.
#ifdef _WIN32
	u_long nbio = 1;
	ioctlsocket(listenSock_, FIONBIO, &nbio);
#else
	int nbio = 1;
	ioctl(listenSock_, FIONBIO, &nbio);
#endif

	// SO_REUSEADDR.
	int reuse = 1;
	setsockopt(listenSock_, SOL_SOCKET, SO_REUSEADDR,
	           reinterpret_cast<const char *>(&reuse), sizeof(reuse));

	if (::bind(listenSock_, reinterpret_cast<sockaddr *>(&ss), ssLen) != 0) {
		STICE_LOG_ERROR("TCPMux: bind failed errno=%d", sticeSockerrno);
		sticeClosesocket(listenSock_);
		listenSock_ = STICE_INVALID_SOCKET;
		return false;
	}

	if (::listen(listenSock_, 64) != 0) {
		STICE_LOG_ERROR("TCPMux: listen failed errno=%d", sticeSockerrno);
		sticeClosesocket(listenSock_);
		listenSock_ = STICE_INVALID_SOCKET;
		return false;
	}

	// Acquire this TCPMux's own PollRegistry instance and register the
	// listener. All TcpMuxConns created later will share this instance.
	pollReg_ = PollRegistry::acquire();
	pollReg_->add(this);

	// Log the bound address.
	AddrRecord bound;
	if (boundAddr(bound)) {
		STICE_LOG_INFO("TCPMux: listening on %s", bound.toString().c_str());
	}
	return true;
}

std::string TCPMux::addrKey(const AddrRecord &addr) {
	return addr.toString();
}

void TCPMux::registerAgent(const std::string &ufrag,
                           std::function<void(const char *, int, const AddrRecord &)> onPacket,
                           std::function<void(int64_t)> onBookkeeping,
                           std::function<int64_t()> nextTimestampMs) {
	std::lock_guard<std::mutex> lock(mutex_);
	auto entry = std::make_shared<TcpMuxAgentEntry>();
	entry->ufrag = ufrag;
	entry->onPacket = std::move(onPacket);
	entry->onBookkeeping = std::move(onBookkeeping);
	entry->nextTimestampMs = std::move(nextTimestampMs);
	agentsByUfrag_[ufrag] = entry;
	STICE_LOG_INFO("TCPMux: registered agent ufrag=%s", ufrag.c_str());
}

void TCPMux::removeAgent(const std::string &ufrag) {
	std::lock_guard<std::mutex> lock(mutex_);
	agentsByUfrag_.erase(ufrag);
	// Close all established connections for this agent but DON'T erase
	// them from connsByAddr_ here. The shared_ptr will be dropped during
	// cleanupConns() on the poll thread. Erasing here (from the caller's
	// thread) would destroy the TcpMuxConn while the PollRegistry's
	// dispatch loop may still hold a raw pointer to it in its slots array,
	// causing a use-after-free race.
	for (auto &kv : connsByAddr_) {
		if (kv.second->ufrag() == ufrag) {
			kv.second->close();
		}
	}
	STICE_LOG_INFO("TCPMux: removed agent ufrag=%s", ufrag.c_str());
}

int TCPMux::sendto(const char *data, std::size_t size, const AddrRecord &dst) {
	auto key = addrKey(dst);
	std::shared_ptr<TcpMuxConn> conn;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		auto it = connsByAddr_.find(key);
		if (it == connsByAddr_.end()) {
			STICE_LOG_DEBUG("TCPMux::sendto: no connection to %s", key.c_str());
			return -1;
		}
		conn = it->second;
	}
	return conn->send(data, size);
}

bool TCPMux::boundAddr(AddrRecord &out) const {
	if (listenSock_ == STICE_INVALID_SOCKET) return false;
	out.len = sizeof(out.addr);
	out.socktype = SOCK_STREAM;
	if (getsockname(listenSock_, reinterpret_cast<sockaddr *>(&out.addr), &out.len) != 0)
		return false;
	return true;
}

std::uint16_t TCPMux::boundPort() const {
	AddrRecord bound;
	if (!boundAddr(bound)) return 0;
	auto *sa = reinterpret_cast<const sockaddr *>(&bound.addr);
	return addrPort(sa);
}

std::vector<AddrRecord> TCPMux::localAddrs(int family) const {
	std::vector<AddrRecord> records;
	AddrRecord bound;
	if (!boundAddr(bound)) return records;
	auto *boundSa = reinterpret_cast<sockaddr *>(&bound.addr);
	// If bound to a specific address, return just that.
	if (!addrIsAny(boundSa)) {
		records.push_back(bound);
		return records;
	}
	uint16_t port = addrPort(boundSa);

#ifdef _WIN32
	char buf[4096];
	DWORD len = 0;
	if (WSAIoctl(listenSock_, SIO_ADDRESS_LIST_QUERY, nullptr, 0, buf, sizeof(buf),
	             &len, nullptr, nullptr) != 0)
		return records;
	auto *list = reinterpret_cast<SOCKET_ADDRESS_LIST *>(buf);
	for (int i = 0; i < list->iAddressCount; ++i) {
		sockaddr *sa = list->Address[i].lpSockaddr;
		socklen_t slen = static_cast<socklen_t>(list->Address[i].iSockaddrLength);
		if ((sa->sa_family == AF_INET ||
		     (sa->sa_family == AF_INET6 && bound.addr.ss_family == AF_INET6)) &&
		    !addrIsLocal(sa)) {
			// Deduplicate.
			bool dup = false;
			for (const auto &r : records) {
				if (addrEqual(sa, reinterpret_cast<const sockaddr *>(&r.addr), false)) {
					dup = true;
					break;
				}
			}
			if (dup) continue;
			AddrRecord r;
			std::memcpy(&r.addr, sa, slen);
			r.len = slen;
			r.socktype = SOCK_STREAM;
			addrUnmapInet6V4Mapped(reinterpret_cast<sockaddr *>(&r.addr), r.len);
			addrSetPort(reinterpret_cast<sockaddr *>(&r.addr), port);
			records.push_back(std::move(r));
		}
	}
#else
	struct ifaddrs *ifas;
	if (getifaddrs(&ifas) != 0) return records;
	for (auto *ifa = ifas; ifa; ifa = ifa->ifa_next) {
		unsigned int flags = ifa->ifa_flags;
		if (!(flags & IFF_UP) || (flags & IFF_LOOPBACK)) continue;
		sockaddr *sa = ifa->ifa_addr;
		if (!sa) continue;
		socklen_t slen = addrLen(sa);
		if (slen == 0) continue;
		if ((sa->sa_family == AF_INET ||
		     (sa->sa_family == AF_INET6 && bound.addr.ss_family == AF_INET6)) &&
		    !addrIsLocal(sa)) {
			bool dup = false;
			for (const auto &r : records) {
				if (addrEqual(sa, reinterpret_cast<const sockaddr *>(&r.addr), false)) {
					dup = true;
					break;
				}
			}
			if (dup) continue;
			AddrRecord r;
			std::memcpy(&r.addr, sa, slen);
			r.len = slen;
			r.socktype = SOCK_STREAM;
			addrSetPort(reinterpret_cast<sockaddr *>(&r.addr), port);
			records.push_back(std::move(r));
		}
	}
	freeifaddrs(ifas);
#endif
	return records;
}

void TCPMux::onAccept() {
	acceptOne();
}

void TCPMux::acceptOne() {
	while (true) {
		// Check pending connection limit before accepting to prevent
		// resource exhaustion from connection floods (str0m #641).
		{
			std::lock_guard<std::mutex> lock(mutex_);
			if (pendingConns_.size() >= MaxPendingTcpMuxConns) {
				STICE_LOG_WARN("TCPMux: pending connection limit reached (%zu), "
				               "rejecting new connections",
				               MaxPendingTcpMuxConns);
				return;
			}
		}
		sockaddr_storage peerSS{};
		socklen_t peerLen = sizeof(peerSS);
		socket_t fd = ::accept(listenSock_, reinterpret_cast<sockaddr *>(&peerSS), &peerLen);
		if (fd == STICE_INVALID_SOCKET) {
			if (wouldBlock()) break; // no more pending connections
			STICE_LOG_WARN("TCPMux: accept failed errno=%d", sticeSockerrno);
			break;
		}
		AddrRecord peerAddr;
		peerAddr.addr = peerSS;
		peerAddr.len = peerLen;
		peerAddr.socktype = SOCK_STREAM;
		// Create a TcpMuxConn. It registers itself with the PollRegistry.
		auto conn = std::make_shared<TcpMuxConn>(fd, peerAddr, this);
		std::lock_guard<std::mutex> lock(mutex_);
		pendingConns_.push_back(conn);
	}
}

void TCPMux::onConnEstablished(TcpMuxConn *conn, const std::string &ufrag) {
	std::shared_ptr<TcpMuxAgentEntry> agent;
	std::shared_ptr<TcpMuxConn> connShared;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		auto it = agentsByUfrag_.find(ufrag);
		if (it != agentsByUfrag_.end()) {
			agent = it->second;
		}
		// Find and remove the shared_ptr from pendingConns_.
		for (auto it2 = pendingConns_.begin(); it2 != pendingConns_.end(); ++it2) {
			if (it2->get() == conn) {
				connShared = *it2;
				pendingConns_.erase(it2);
				break;
			}
		}
	}

	if (!agent) {
		STICE_LOG_WARN("TCPMux: no agent for ufrag=%s, closing connection from %s",
		               ufrag.c_str(), conn->peerAddr().toString().c_str());
		return;
	}

	conn->setAgent(agent);

	if (connShared) {
		std::lock_guard<std::mutex> lock(mutex_);
		connsByAddr_[addrKey(conn->peerAddr())] = connShared;
	}

	STICE_LOG_INFO("TCPMux: connection from %s established → ufrag=%s",
	               conn->peerAddr().toString().c_str(), ufrag.c_str());
}

void TCPMux::onConnClosed(TcpMuxConn *conn) {
	// Don't erase from connsByAddr_ here. This is called from
	// TcpMuxConn::onTcpEvents, and erasing the shared_ptr would destroy
	// `conn` (this) while onTcpEvents is still on the call stack. The
	// closed_ flag is checked by cleanupConns() which runs on the poll
	// thread during the next onBookkeeping pass — that is the safe place
	// to drop the shared_ptr.
	(void)conn;
}

int64_t TCPMux::nextTimestampMs() const {
	std::lock_guard<std::mutex> lock(mutex_);
	int64_t earliest = 0;
	for (const auto &kv : agentsByUfrag_) {
		if (!kv.second->nextTimestampMs) continue;
		int64_t t = kv.second->nextTimestampMs();
		if (t > 0 && (earliest == 0 || t < earliest)) earliest = t;
	}
	return earliest;
}

void TCPMux::onBookkeeping(int64_t nowMs) {
	// Drop deferred cleanup shared_ptrs from the PREVIOUS bookkeeping pass.
	// By now, the PollRegistry's previous bookkeeping snapshot (which may
	// have held raw pointers to these conns) has been fully iterated and
	// discarded, so freeing the TcpMuxConn objects is safe.
	{
		std::lock_guard<std::mutex> lock(mutex_);
		toDestroy_.clear();
	}

	// Clean up closed and expired pending connections.
	cleanupConns(nowMs);

	// Snapshot the agent list and call bookkeeping.
	std::vector<std::shared_ptr<TcpMuxAgentEntry>> snapshot;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		snapshot.reserve(agentsByUfrag_.size());
		for (const auto &kv : agentsByUfrag_) {
			snapshot.push_back(kv.second);
		}
	}
	for (const auto &entry : snapshot) {
		if (entry->onBookkeeping) entry->onBookkeeping(nowMs);
	}
}

void TCPMux::cleanupConns(int64_t nowMs) {
	std::lock_guard<std::mutex> lock(mutex_);
	// Remove closed pending connections and expired ones (30s timeout).
	// Instead of dropping the shared_ptr immediately (which would free the
	// TcpMuxConn while the PollRegistry's bookkeeping loop may still hold
	// a raw pointer to it), move it to toDestroy_ for deferred cleanup.
	constexpr int64_t FirstStunBindTimeoutMs = 30000;
	auto now = std::chrono::steady_clock::now();

	// Use this TCPMux's own PollRegistry instance.
	auto *reg = pollReg_;

	pendingConns_.erase(
	    std::remove_if(pendingConns_.begin(), pendingConns_.end(),
	                   [&](const std::shared_ptr<TcpMuxConn> &c) {
		                   if (c->isClosed()) {
			                   STICE_LOG_DEBUG("TCPMux: cleanup closed pending conn from %s",
			                                  c->peerAddr().toString().c_str());
			                   if (reg) reg->remove(c.get());
			                   toDestroy_.push_back(c);
			                   return true;
		                   }
		                   auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
		                       now - c->acceptedAt_).count(); // unused but kept for future
		                   if (elapsed > FirstStunBindTimeoutMs) {
			                   STICE_LOG_WARN("TCPMux: expiring pending conn from %s (no STUN in %lldms)",
			                                  c->peerAddr().toString().c_str(),
			                                  static_cast<long long>(elapsed));
			                   c->close();
			                   if (reg) reg->remove(c.get());
			                   toDestroy_.push_back(c);
			                   return true;
		                   }
		                   return false;
	                   }),
	    pendingConns_.end());

	// Remove closed established connections (deferred cleanup).
	for (auto it = connsByAddr_.begin(); it != connsByAddr_.end();) {
		if (it->second->isClosed()) {
			STICE_LOG_DEBUG("TCPMux: cleanup closed established conn from %s",
			               it->second->peerAddr().toString().c_str());
			if (reg) reg->remove(it->second.get());
			toDestroy_.push_back(it->second);
			it = connsByAddr_.erase(it);
		} else {
			++it;
		}
	}
}

} // namespace stice::net
