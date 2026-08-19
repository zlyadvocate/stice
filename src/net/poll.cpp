/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// Per-agent independent thread model (aligned with libjuice conn_thread.c).
// Each PollRegistry instance owns ONE background thread that polls ONE
// participant's sockets. No shared global state.

#include "stice/net/poll.hpp"

#include "stice/log.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace stice::net {

#ifdef _WIN32
// Ensure Winsock is initialized before any PollRegistry is created. The
// g_wsaInit static in udp.cpp also does this, but static initialization
// order across translation units is unspecified, so we cannot rely on it.
// WSAStartup is reference-counted, so multiple calls are safe.
struct WsaInit {
	WsaInit() {
		WSADATA d;
		(void)WSAStartup(MAKEWORD(2, 2), &d);
	}
	~WsaInit() { WSACleanup(); }
};
static WsaInit g_wsaInit;
#endif

// acquire() creates a new instance with its own background thread.
// No global state — each caller owns the returned pointer.
PollRegistry *PollRegistry::acquire() { return new PollRegistry(); }

// release() stops the thread and deletes this instance. Called by the
// owner (Agent/UDPMux/TCPMux/TcpMuxConn) when it is destroyed.
void PollRegistry::release() {
	// Cannot call `delete this` from within a member function that the
	// thread is executing, but release() is only called from the owner's
	// thread (never from the poll thread), so this is safe.
	delete this;
}

PollRegistry::PollRegistry() {
	// Interrupt socket: a loopback UDP socket we can send to / recv from.
	interruptSock_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (interruptSock_ == STICE_INVALID_SOCKET) {
		STICE_LOG_WARN("PollRegistry: interrupt socket creation failed errno=%d", sticeSockerrno);
	}
	if (interruptSock_ != STICE_INVALID_SOCKET) {
#ifdef _WIN32
		u_long nbio = 1;
		ioctlsocket(interruptSock_, FIONBIO, &nbio);
#else
		int nbio = 1;
		ioctl(interruptSock_, FIONBIO, &nbio);
#endif
		sockaddr_in bind4{};
		bind4.sin_family = AF_INET;
		bind4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		bind4.sin_port = 0; // ephemeral
		::bind(interruptSock_, reinterpret_cast<struct sockaddr *>(&bind4), sizeof(bind4));
		socklen_t len = sizeof(interruptAddr_.addr);
		getsockname(interruptSock_, reinterpret_cast<struct sockaddr *>(&interruptAddr_.addr), &len);
		interruptAddr_.len = len;
		interruptAddr_.socktype = SOCK_DGRAM;
	}
	thread_ = std::thread([this] { run(); });
}

PollRegistry::~PollRegistry() {
	{
		std::lock_guard<std::mutex> lock(mutex_);
		stopping_ = true;
	}
	interrupt();
	if (thread_.joinable()) {
		// Bounded wait: if the poll thread is stuck in a callback that
		// blocks on a lock held by the caller, detach it instead of
		// hanging the destructor. The detached thread will exit when it
		// next checks stopping_ or when the process terminates.
		std::unique_lock<std::mutex> lock(syncMutex_);
		if (!syncCv_.wait_for(lock, std::chrono::seconds(3),
		                      [this] { return threadExited_; })) {
			STICE_LOG_WARN("PollRegistry::~PollRegistry: thread didn't exit in 3s, detaching");
			thread_.detach();
		} else {
			lock.unlock();
			thread_.join();
		}
	}
	if (interruptSock_ != STICE_INVALID_SOCKET) sticeClosesocket(interruptSock_);
}

void PollRegistry::add(PollParticipant *p) {
	{
		std::lock_guard<std::mutex> lock(mutex_);
		// Idempotent: skip if already registered. Prevents duplicate
		// onBookkeeping/onTcpEvents callbacks when addRemotePassiveTcpCandidate
		// or beginTurnTcpConnect is called multiple times.
		if (std::find(participants_.begin(), participants_.end(), p) != participants_.end()) {
			return;
		}
		participants_.push_back(p);
	}
	interrupt();
}

void PollRegistry::remove(PollParticipant *p) {
	{
		std::lock_guard<std::mutex> lock(mutex_);
		participants_.erase(std::remove(participants_.begin(), participants_.end(), p),
		                    participants_.end());
	}
	interrupt();
}

void PollRegistry::interrupt() {
	if (interruptSock_ == STICE_INVALID_SOCKET) return;
	const char byte = 1;
	::sendto(interruptSock_, &byte, 1, 0, reinterpret_cast<const struct sockaddr *>(&interruptAddr_.addr),
	         interruptAddr_.len);
}

void PollRegistry::sync() {
	// Wait for the poll thread to start a new iteration AFTER any remove()
	// calls that preceded this sync(). The generation_ counter is incremented
	// at the start of each iteration under syncMutex_. Once generation_ has
	// increased, the poll thread has built fresh slots/snapshots from the
	// updated participants_ list (without the removed participants), so no
	// raw pointers to removed participants are in use.
	//
	// Bounded retry: if the poll thread is stuck (e.g., in a dispatch
	// callback that blocks on a lock held by the caller), give up after
	// 2 seconds. This is safe because the participant has already been
	// removed from participants_, and the validation step in run() nulls
	// out stale slots.
	std::unique_lock<std::mutex> lock(syncMutex_);
	uint64_t target = generation_ + 1;
	int retries = 0;
	const int maxRetries = 20; // 20 * 100ms = 2s
	while (generation_ < target && retries < maxRetries) {
		interrupt(); // wake the poll thread if it's sleeping in sticePoll
		syncCv_.wait_for(lock, std::chrono::milliseconds(100),
		                 [this, target] { return generation_ >= target || threadExited_; });
		++retries;
	}
	if (generation_ < target) {
		STICE_LOG_WARN("PollRegistry::sync() timed out after %d retries, proceeding", retries);
	}
}

int64_t PollRegistry::computeTimeoutMs(int64_t nowMs) {
	int64_t next = nowMs + 60000; // default 60s
	std::lock_guard<std::mutex> lock(mutex_);
	for (auto *p : participants_) {
		int64_t t = p->nextTimestampMs();
		if (t > 0 && t < next) next = t;
	}
	int64_t timeout = next - nowMs;
	if (timeout < 0) timeout = 0;
	if (timeout > 60000) timeout = 60000;
	return timeout;
}

void PollRegistry::run() {
	std::vector<pollfd> pfds;
	// Parallel array: for each entry in pfds, which participant and which
	// socket type (0=interrupt, 1=udp, 2=tcp, 3=turn-tcp, 4=listener, 5=turn-data) it corresponds to.
	struct PfdSlot {
		PollParticipant *participant;
		int kind; // 0=interrupt, 1=udp, 2=tcp, 3=turn-tcp, 4=listener, 5=turn-data
	};
	std::vector<PfdSlot> slots;

	while (true) {
		{
			std::lock_guard<std::mutex> lock(mutex_);
			if (stopping_) {
				// Notify any sync() waiters so they don't block forever.
				std::lock_guard<std::mutex> slock(syncMutex_);
				++generation_; // advance so sync() unblocks
				threadExited_ = true;
				syncCv_.notify_all();
				return;
			}
		}
		// Start of a new iteration: increment generation under syncMutex_
		// so sync() can detect that a new iteration has begun.
		{
			std::lock_guard<std::mutex> slock(syncMutex_);
			++generation_;
		}
		syncCv_.notify_all();
		int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
		                    std::chrono::steady_clock::now().time_since_epoch())
		                    .count();
		int64_t timeout = computeTimeoutMs(nowMs);

		// Build a COMPACT pollfd set: only valid FDs are included. Windows
		// WSAPoll misbehaves when INVALID_SOCKET entries are present (it sets
		// POLLERR on them and may return immediately without waiting for
		// events on valid FDs).
		pfds.clear();
		slots.clear();
		{
			std::lock_guard<std::mutex> lock(mutex_);
			pfds.reserve(1 + participants_.size() * 4);
			slots.reserve(1 + participants_.size() * 4);
			// Interrupt socket (always first).
			pollfd ip{};
			ip.fd = interruptSock_;
			ip.events = POLLIN;
			pfds.push_back(ip);
			slots.push_back({nullptr, 0});
			for (auto *p : participants_) {
				socket_t ufd = p->udpSocket();
				if (ufd != STICE_INVALID_SOCKET) {
					pollfd u{};
					u.fd = ufd;
					u.events = POLLIN;
					pfds.push_back(u);
					slots.push_back({p, 1});
				}
				if (p->hasTcp()) {
					socket_t tfd = p->tcpSocket();
					if (tfd != STICE_INVALID_SOCKET) {
						pollfd t{};
						t.fd = tfd;
						t.events = p->tcpDesiredEvents();
						pfds.push_back(t);
						slots.push_back({p, 2});
					}
				}
				if (p->hasTurnTcp()) {
					socket_t tfd = p->turnTcpSocket();
					if (tfd != STICE_INVALID_SOCKET) {
						pollfd t{};
						t.fd = tfd;
						t.events = p->turnTcpDesiredEvents();
						pfds.push_back(t);
						slots.push_back({p, 3});
					}
				}
				if (p->hasListener()) {
					socket_t lfd = p->listenerSocket();
					if (lfd != STICE_INVALID_SOCKET) {
						pollfd l{};
						l.fd = lfd;
						l.events = POLLIN;
						pfds.push_back(l);
						slots.push_back({p, 4});
					}
				}
				if (p->hasTurnDataTcp()) {
					socket_t dfd = p->turnDataTcpSocket();
					if (dfd != STICE_INVALID_SOCKET) {
						pollfd d{};
						d.fd = dfd;
						d.events = p->turnDataDesiredEvents();
						pfds.push_back(d);
						slots.push_back({p, 5});
					}
				}
			}
		}

		int n = sticePoll(pfds.data(), static_cast<nfds_t>(pfds.size()),
		                  static_cast<int>(timeout));
		if (n < 0) {
			if (sticeSockerrno == STICE_SEINTR) continue;
			STICE_LOG_WARN("PollRegistry: poll failed errno=%d", sticeSockerrno);
			continue;
		}

		// Drain interrupt socket (always pfds[0]).
		if (!pfds.empty() && (pfds[0].revents & POLLIN)) {
			char buf[256];
			while (true) {
				int r = static_cast<int>(::recv(interruptSock_, buf, sizeof(buf), 0));
				if (r <= 0) break;
			}
		}

		// Validate slots: a participant may have been removed (and possibly
		// destroyed) from another thread during sticePoll(). Re-lock and
		// null out slots whose participant is no longer registered, to avoid
		// dispatching on a dangling pointer.
		{
			std::lock_guard<std::mutex> lock(mutex_);
			for (auto &slot : slots) {
				if (!slot.participant) continue;
				if (std::find(participants_.begin(), participants_.end(),
				              slot.participant) == participants_.end()) {
					slot.participant = nullptr; // removed during poll
				}
			}
		}

		// Dispatch. Iterate over the compact pfds/slots arrays.
		for (std::size_t i = 1; i < pfds.size(); ++i) {
			auto &slot = slots[i];
			if (!slot.participant) continue; // removed during poll
			if (pfds[i].revents == 0) continue;
			if (slot.kind == 1) {
				// UDP readable.
				slot.participant->onUdpReadable();
			} else if (slot.kind == 2) {
				// TCP events.
				slot.participant->onTcpEvents(pfds[i].revents);
			} else if (slot.kind == 3) {
				// TURN TCP events.
				slot.participant->onTurnTcpEvents(pfds[i].revents);
			} else if (slot.kind == 4) {
				// TCP listener: new connection arrived.
				slot.participant->onAccept();
			} else if (slot.kind == 5) {
				// RFC 6062 TURN data connection events.
				slot.participant->onTurnDataTcpEvents(pfds[i].revents);
			}
		}

		// Bookkeeping pass. Snapshot the participant list to avoid holding
		// the lock while calling back into participants.
		std::vector<PollParticipant *> snapshot;
		{
			std::lock_guard<std::mutex> lock(mutex_);
			snapshot = participants_;
		}
		int64_t afterMs = std::chrono::duration_cast<std::chrono::milliseconds>(
		                      std::chrono::steady_clock::now().time_since_epoch())
		                      .count();
		for (auto *p : snapshot)
			p->onBookkeeping(afterMs);

		// End of iteration: notify any sync() waiters that a new generation
		// has completed. sync() only needs generation_ to increase, which
		// happens at the start of each iteration.
		syncCv_.notify_all();
	}
}

} // namespace stice::net
