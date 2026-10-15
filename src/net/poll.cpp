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
#include <memory>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
// wepoll: an IOCP-backed implementation of the epoll API for Windows. It is
// the only epoll provider on Windows; on Linux the native <sys/epoll.h> below
// provides the identical epoll_* surface, and the two share one event loop.
#include "wepoll/wepoll.h"
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef __linux__
// Native epoll(7). Linux uses the shared epoll event loop below instead of
// poll(2), matching the Windows wepoll backend's event model.
#include <sys/epoll.h>
#endif
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

// ---- Shared poll-registry pool ----
//
// Per-agent independent thread model (aligned with libjuice conn_thread.c) is
// great for a few agents but collapses under high concurrency on Windows:
// each agent owns one background thread, so 2000 pairs -> ~4000+ threads, and
// Windows thread scheduling degrades badly. Instead we share a fixed-size pool
// of PollRegistry instances. Each registry still polls ONE participant's set
// (participants_ is a vector), but all agents round-robin onto a small number
// of registry threads. This keeps the event model identical while collapsing
// thread count from O(agents) down to O(hardware concurrency, capped at 8).
//
// release() is now a no-op: pooled instances live for the process lifetime.
// Owners must still call remove() + sync() before destroying themselves so the
// poll thread no longer touches them (they already do). The pool is torn down
// (joining all threads) in the static destructor at process exit.
namespace {
std::size_t poolSize() {
	unsigned hc = std::thread::hardware_concurrency();
	// Scale with logical cores so ICE state machines run in parallel across
	// the CPU, but cap to avoid re-introducing a thread-scheduling storm.
	std::size_t n = hc >= 16 ? 16 : (hc >= 2 ? hc : 1);
	return n;
}
} // namespace

// acquire() lazily builds the pool (once) and returns the next instance in
// round-robin order. All callers (Agent/UDPMux/TCPMux) share the pool, so the
// total number of poll threads is bounded regardless of agent count. Because
// the PollRegistry ctor/dtor are private, the pool is built here inside the
// member function; pooled instances are process-lifetime (the OS reclaims them
// and the poll threads at exit 鈥?owners have already remove()+sync()'d).
PollRegistry *PollRegistry::acquire() {
	static std::vector<PollRegistry *> pool;
	static std::mutex mtx;
	static std::size_t next = 0;
	std::lock_guard<std::mutex> lock(mtx);
	const std::size_t cap = poolSize();
	// Grow the pool lazily, one registry per wrap-around, up to the per-process
	// cap. A process with only a couple of agents then runs a couple of poll
	// threads instead of eagerly spawning `hardware_concurrency()` of them.
	// This matters when many *processes* each host few agents (e.g. the
	// 100-client big-data test): eager sizing created ~12 idle poll threads per
	// process (~1200 threads total for 100 clients on a 12-core box), whose
	// scheduling pressure starved the stserver relay thread and caused packet
	// loss. High-agent-count processes still grow to the full cap.
	if (pool.empty())
		pool.push_back(new PollRegistry());
	else if (next >= pool.size() && pool.size() < cap)
		pool.push_back(new PollRegistry());
	PollRegistry *r = pool[next % pool.size()];
	++next;
	return r;
}

// release() is a no-op for pooled registries. The owner (Agent/UDPMux/TCPMux)
// must have already called remove() + sync() on the way out; the registry and
// its thread stay alive to serve other participants until process exit.
void PollRegistry::release() {
	// Intentionally empty: shared pool, instances are process-lifetime.
}

PollRegistry::PollRegistry() {
	#ifdef _WIN32
		// Ensure Winsock is initialized before we create sockets or call
		// WSAPoll in the poll thread. The file-scope g_wsaInit static may be
		// elided by the linker when unreferenced; calling WSAStartup here is
		// idempotent (reference-counted) and guarantees the socket layer is up.
		WSADATA d;
		(void)WSAStartup(MAKEWORD(2, 2), &d);
	#endif
	// Interrupt socket: a loopback UDP socket we can send to / recv from.
	interruptSock_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (interruptSock_ == STICE_INVALID_SOCKET) {
		STICE_LOG_WARN("PollRegistry: interrupt socket creation failed errno=%d", sticeSockerrno);
	}
	if (interruptSock_ != STICE_INVALID_SOCKET) {
		setNonBlocking(interruptSock_);
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
		                      [this] { return threadExited_.load(); })) {
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
#if STICE_EPOLL_BACKEND
		// The socket set changed: re-assert every epoll registration so a slot
		// whose fd was silently released by a close() cannot shadow this new
		// socket (see epollSync()).
		epollResyncAll_ = true;
#endif
	}
	interrupt();
}

void PollRegistry::remove(PollParticipant *p) {
	{
		std::lock_guard<std::mutex> lock(mutex_);
		participants_.erase(std::remove(participants_.begin(), participants_.end(), p),
		                    participants_.end());
#if STICE_EPOLL_BACKEND
		// A participant leaving usually means its sockets were (or are about to
		// be) closed; force a registration re-assert so the freed fd numbers
		// cannot shadow a later socket. See epollSync().
		epollResyncAll_ = true;
#endif
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
	uint64_t target = generation_.load() + 1;  // atomic has no operator+
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
	// Default clamp: if a participant's nextTimestampMs() races and reads
	// a not-yet-set gatherStartedAt_ (no soft-gathering deadline exposed),
	// the poll still wakes within 1s so onBookkeeping can force gathering
	// complete promptly. 1s (not 15s) is chosen because under 100 concurrent
	// streams one agent's srflx response occasionally is not consumed in
	// time by its own socket poll; a shorter wake lets the soft timeout
	// complete gathering instead of wedging the whole scenario.
	int64_t next = nowMs + 1000;
	// Ask the participants OUTSIDE the registry mutex: nextTimestampMs() takes
	// the participant's own lock, so holding the registry mutex across it would
	// re-introduce the registry->participant lock order that deadlocks against
	// participant->registry (see epollSync()).
	std::vector<PollParticipant *> parts;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		parts = participants_;
	}
	for (auto *p : parts) {
		int64_t t = p->nextTimestampMs();
		if (t > 0 && t < next) next = t;
	}
	int64_t timeout = next - nowMs;
	if (timeout < 0) timeout = 0;
	if (timeout > 1000) timeout = 1000;
	return timeout;
}

#if STICE_EPOLL_BACKEND
namespace {
// Create/close an epoll handle. Windows uses wepoll's HANDLE; Linux uses a
// native epoll fd. epoll_ctl()/epoll_wait() take the platform handle type
// directly, so only create/close/validity need adapting.
#ifdef _WIN32
inline void *epollHandleCreate(int sizeHint) { return epoll_create(sizeHint); }
inline bool epollHandleValid(void *h) { return h != nullptr; }
inline void epollHandleClose(void *h) { if (h) epoll_close(static_cast<HANDLE>(h)); }
#else
inline int epollHandleCreate(int sizeHint) {
	(void)sizeHint; // epoll_create1() ignores the legacy size hint
	return ::epoll_create1(EPOLL_CLOEXEC);
}
inline bool epollHandleValid(int h) { return h >= 0; }
inline void epollHandleClose(int h) { if (h >= 0) ::close(h); }
#endif
} // namespace

bool PollRegistry::epollSetup() {
	if (epollReady_) return true;
	eph_ = epollHandleCreate(64);
	if (!epollHandleValid(eph_)) {
		STICE_LOG_WARN("PollRegistry: epoll_create failed err=%d", sticeSockerrno);
		return false;
	}
	// Register the interrupt socket permanently (slot 0, kind 0). Never DEL'd.
	if (interruptSock_ != STICE_INVALID_SOCKET) {
		int idx = static_cast<int>(slots_.size());
		Slot s;
		s.fd = interruptSock_;
		s.kind = 0;
		s.lastEvents = POLLIN;
		s.active = true;
		s.seen = true;
		struct epoll_event ee{};
		ee.events = EPOLLIN;
		ee.data.u32 = static_cast<std::uint32_t>(idx);
		if (epoll_ctl(eph_, EPOLL_CTL_ADD, interruptSock_, &ee) != 0) {
			STICE_LOG_WARN("PollRegistry: epoll add interrupt failed err=%d", sticeSockerrno);
		}
		slots_.push_back(s);
		fdToSlot_[interruptSock_] = idx;
	}
	epollReady_ = true;
	return true;
}

void PollRegistry::epollSync(const std::vector<PollParticipant *> &participants,
                             bool forceResync) {
	// Runs on the poll thread WITHOUT the registry mutex held (the caller took a
	// consistent snapshot of participants_ instead). The participant getters
	// below take each participant's own lock, so holding the registry mutex here
	// would invert the lock order against a participant that calls
	// add()/remove() while holding its own lock (Agent::set_remote_description
	// -> pollReg_->add(this)): that deadlocked tcp-ice setup.
	// Reconcile the persistent epoll
	// registration against the current desired socket set of participants_.
	// ADD when a socket first appears, MOD when its desired events change,
	// DEL when it leaves the set (fd became invalid / participant removed).
	// Both backends require persistent registration: wepoll (Windows) does NOT
	// support rapid ADD/DEL churn of the same socket (re-ADD returns EEXIST),
	// and native epoll (Linux) uses the same additive-registration model.
	struct Desired {
		socket_t fd;
		PollParticipant *p;
		int kind;
		int idx;
		short events;
	};
	std::vector<Desired> desired;
	desired.reserve(1 + participants.size() * 6);
	for (auto *p : participants) {
		socket_t ufd = p->udpSocket();
		if (ufd != STICE_INVALID_SOCKET) desired.push_back({ufd, p, 1, -1, POLLIN});
		if (p->hasTcp()) {
			socket_t tfd = p->tcpSocket();
			if (tfd != STICE_INVALID_SOCKET)
				desired.push_back({tfd, p, 2, -1, static_cast<short>(p->tcpDesiredEvents())});
		}
		if (p->hasTurnTcp()) {
			socket_t tfd = p->turnTcpSocket();
			if (tfd != STICE_INVALID_SOCKET)
				desired.push_back({tfd, p, 3, -1, static_cast<short>(p->turnTcpDesiredEvents())});
		}
		{
			int n = p->turnTcpSlotCount();
			for (int si = 0; si < n; ++si) {
				socket_t tfd = p->turnTcpSocketAt(si);
				if (tfd == STICE_INVALID_SOCKET) continue;
				if (p->hasTurnTcp() && tfd == p->turnTcpSocket()) continue; // legacy dup
				desired.push_back({tfd, p, 6, si, static_cast<short>(p->turnTcpDesiredEventsAt(si))});
			}
		}
		if (p->hasListener()) {
			socket_t lfd = p->listenerSocket();
			if (lfd != STICE_INVALID_SOCKET) desired.push_back({lfd, p, 4, -1, POLLIN});
		}
		if (p->hasTurnDataTcp()) {
			socket_t dfd = p->turnDataTcpSocket();
			if (dfd != STICE_INVALID_SOCKET)
				desired.push_back({dfd, p, 5, -1, static_cast<short>(p->turnDataDesiredEvents())});
		}
	}

	// Mark all non-interrupt slots as not-seen this iteration.
	for (auto &s : slots_)
		if (s.kind != 0) s.seen = false;

	// Re-assert every registration when a participant/socket was added or
	// removed, and at least once per kFullResyncMs as a bounded safety net for a
	// participant that swaps its socket without add()/remove() (see the
	// ownerChanged comment below).
	constexpr int64_t kFullResyncMs = 1000;
	const int64_t nowSyncMs =
	    std::chrono::duration_cast<std::chrono::milliseconds>(
	        std::chrono::steady_clock::now().time_since_epoch())
	        .count();
	const bool forceAll =
	    forceResync || (nowSyncMs - epollLastFullSyncMs_) >= kFullResyncMs;

	for (auto &d : desired) {
		auto it = fdToSlot_.find(d.fd);
		if (it == fdToSlot_.end()) {
			// New socket: ADD.
			int idx = static_cast<int>(slots_.size());
			Slot s;
			s.fd = d.fd;
			s.participant = d.p;
			s.kind = d.kind;
			s.idx = d.idx;
			s.lastEvents = d.events;
			s.active = true;
			s.seen = true;
			struct epoll_event ee{};
			if (d.events & POLLIN) ee.events |= EPOLLIN;
			if (d.events & POLLOUT) ee.events |= EPOLLOUT;
			if (d.events & POLLERR) ee.events |= EPOLLERR;
			if (d.events & POLLHUP) ee.events |= EPOLLHUP;
			ee.data.u32 = static_cast<std::uint32_t>(idx);
			if (epoll_ctl(eph_, EPOLL_CTL_ADD, d.fd, &ee) != 0) {
				// Socket already gone / unregisterable; skip.
				continue;
			}
			slots_.push_back(s);
			fdToSlot_[d.fd] = idx;
		} else {
			int idx = it->second;
			Slot &s = slots_[idx];
			s.seen = true;
			// Detect that this fd now belongs to a DIFFERENT participant (or a
			// different transport of the same one). fd numbers are reused
			// aggressively and the kernel silently drops an fd's registration
			// when the previous socket is closed, so an unchanged interest mask
			// does NOT prove the kernel still monitors the CURRENT socket.
			// Skipping epoll_ctl in that case left the new socket unmonitored
			// (observed as clients wedged in the TCPMux accept path: "no STUN in
			// 30 s", fixed by the forced re-assert below).
			const bool ownerChanged = (s.participant != d.p) ||
			                          (s.kind != d.kind) ||
			                          (s.idx != d.idx);
			s.participant = d.p;
			s.kind = d.kind;
			s.idx = d.idx;
			if (s.lastEvents != d.events || ownerChanged || forceAll) {
				struct epoll_event ee{};
				if (d.events & POLLIN) ee.events |= EPOLLIN;
				if (d.events & POLLOUT) ee.events |= EPOLLOUT;
				if (d.events & POLLERR) ee.events |= EPOLLERR;
				if (d.events & POLLHUP) ee.events |= EPOLLHUP;
				ee.data.u32 = static_cast<std::uint32_t>(idx);
				if (epoll_ctl(eph_, EPOLL_CTL_MOD, d.fd, &ee) != 0) {
					// MOD reports that the kernel holds no registration for this
					// fd: its previous owner was closed, or the mapping drifted.
					// Rebuild the association with DEL+ADD so dispatch lands on
					// the current participant.
					STICE_LOG_DEBUG("epollSync: MOD missed fd=%u (stale registration), rebuilding",
					                static_cast<unsigned>(d.fd));
					epoll_ctl(eph_, EPOLL_CTL_DEL, d.fd, nullptr);
					if (epoll_ctl(eph_, EPOLL_CTL_ADD, d.fd, &ee) != 0)
						STICE_LOG_WARN("epollSync: re-ADD failed fd=%u",
						               static_cast<unsigned>(d.fd));
				}
				s.lastEvents = d.events;
			}
		}
	}

	// epollResyncAll_ was already cleared by the caller under the registry mutex.
	if (forceAll) epollLastFullSyncMs_ = nowSyncMs;

	// DEL sockets that left the desired set (excluding the permanent interrupt slot).
	for (std::size_t i = 0; i < slots_.size(); ++i) {
		Slot &s = slots_[i];
		if (s.kind == 0) continue;
		if (s.active && !s.seen) {
			epoll_ctl(eph_, EPOLL_CTL_DEL, s.fd, nullptr);
			fdToSlot_.erase(s.fd);
			s.active = false;
			s.fd = STICE_INVALID_SOCKET;
			s.participant = nullptr;
		}
	}
}
#endif // STICE_EPOLL_BACKEND

void PollRegistry::run() {
#if STICE_EPOLL_BACKEND
	// Persistent epoll loop, shared by both platforms: on Windows this is
	// wepoll over IOCP (deterministic event delivery, unlike WSAPoll which
	// intermittently fails to report readability under socket churn); on Linux
	// it is the native epoll(7) API. Only epollSetup()'s create/close and the
	// handle type differ between them.
	if (!epollSetup()) return;
	std::vector<struct epoll_event> out;
#else
	// poll(2)/pfds loop (macOS/BSD and any other POSIX without an epoll-style
	// backend).
	std::vector<pollfd> pfds;
	struct PfdSlot {
		PollParticipant *participant;
		int kind; // 0=interrupt, 1=udp, 2=tcp, 3=turn-tcp, 4=listener, 5=turn-data
		int idx = -1;
	};
	std::vector<PfdSlot> slots;
#endif

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
		int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
		                    std::chrono::steady_clock::now().time_since_epoch())
		                    .count();
		int64_t timeout = computeTimeoutMs(nowMs);

#if STICE_EPOLL_BACKEND
		// ---- epoll persistent path (wepoll on Windows, native epoll on Linux) ----
		// Snapshot participants_ under the registry mutex, then run epollSync()
		// WITHOUT it: the participant getters take their own lock, so holding the
		// registry mutex across them would invert the lock order against a
		// participant that calls add()/remove() while holding its own lock
		// (deadlock). See epollSync().
		std::vector<PollParticipant *> parts;
		bool forceResync = false;
		{
			std::lock_guard<std::mutex> lock(mutex_);
			parts = participants_;
			forceResync = epollResyncAll_;
			epollResyncAll_ = false;
		}
		epollSync(parts, forceResync);
		int maxevents = slots_.empty() ? 1 : static_cast<int>(slots_.size());
		out.resize(maxevents);
		int n = epoll_wait(eph_, out.data(), maxevents, static_cast<int>(timeout));
		if (n < 0) continue;

		// Validate slots: a participant may have been removed (and possibly
		// destroyed) from another thread during epoll_wait. Null out stale
		// participant pointers to avoid dispatching on a dangling pointer.
		{
			std::lock_guard<std::mutex> lock(mutex_);
			for (int k = 0; k < n; ++k) {
				std::uint32_t idx = out[k].data.u32;
				if (idx >= slots_.size()) continue;
				Slot &s = slots_[idx];
				if (!s.active || !s.participant) continue;
				if (std::find(participants_.begin(), participants_.end(), s.participant) ==
				    participants_.end())
					s.participant = nullptr;
			}
		}

		for (int k = 0; k < n; ++k) {
			std::uint32_t idx = out[k].data.u32;
			if (idx >= slots_.size()) continue;
			Slot &s = slots_[idx];
			if (!s.active) continue;
			std::uint32_t ev = out[k].events;
			if (s.kind == 0) { // interrupt: drain
				char buf[256];
				while (static_cast<int>(::recv(interruptSock_, buf, sizeof(buf), 0)) > 0) {}
				continue;
			}
			if (!s.participant) continue;
			short rev = 0;
			if (ev & EPOLLIN) rev |= POLLIN;
			if (ev & EPOLLOUT) rev |= POLLOUT;
			if (ev & EPOLLERR) rev |= POLLERR;
			if (ev & EPOLLHUP) rev |= POLLHUP;
			STICE_LOG_DEBUG("POLL-DISP idx=%u kind=%d fd=%u part=%p ev=%u",
			                 idx, (int)s.kind, (unsigned)s.fd, (void *)s.participant,
			                 (unsigned)ev);
			switch (s.kind) {
				case 1: s.participant->onUdpReadable(); break;
				case 2: s.participant->onTcpEvents(rev); break;
				case 3: s.participant->onTurnTcpEvents(rev); break;
				case 4: s.participant->onAccept(); break;
				case 5: s.participant->onTurnDataTcpEvents(rev); break;
				case 6: s.participant->onTurnTcpEventsSock(s.fd, rev); break;
			}
		}
#else
		// ---- poll()/pfds path (POSIX) ----
		pfds.clear();
		slots.clear();
		{
			// Snapshot participants_ under the registry mutex, then build the fd
			// set OUTSIDE it: the getters take the participant's own lock, so
			// holding the registry mutex across them would invert the lock order
			// (see epollSync()).
			std::vector<PollParticipant *> parts;
			{
				std::lock_guard<std::mutex> lock(mutex_);
				parts = participants_;
			}
			pfds.reserve(1 + parts.size() * 4);
			slots.reserve(1 + parts.size() * 4);
			pollfd ip{};
			ip.fd = interruptSock_;
			ip.events = POLLIN;
			pfds.push_back(ip);
			slots.push_back({nullptr, 0});
			for (auto *p : parts) {
				socket_t ufd = p->udpSocket();
				if (ufd != STICE_INVALID_SOCKET) {
					pollfd u{}; u.fd = ufd; u.events = POLLIN;
					pfds.push_back(u); slots.push_back({p, 1});
				}
				if (p->hasTcp()) {
					socket_t tfd = p->tcpSocket();
					if (tfd != STICE_INVALID_SOCKET) {
						pollfd t{}; t.fd = tfd; t.events = p->tcpDesiredEvents();
						pfds.push_back(t); slots.push_back({p, 2});
					}
				}
				if (p->hasTurnTcp()) {
					socket_t tfd = p->turnTcpSocket();
					if (tfd != STICE_INVALID_SOCKET) {
						pollfd t{}; t.fd = tfd; t.events = p->turnTcpDesiredEvents();
						pfds.push_back(t); slots.push_back({p, 3, -1});
					}
				}
				{
					int nslot = p->turnTcpSlotCount();
					for (int si = 0; si < nslot; ++si) {
						socket_t tfd = p->turnTcpSocketAt(si);
						if (tfd == STICE_INVALID_SOCKET) continue;
						if (p->hasTurnTcp() && tfd == p->turnTcpSocket()) continue;
						pollfd t{}; t.fd = tfd; t.events = p->turnTcpDesiredEventsAt(si);
						pfds.push_back(t); slots.push_back({p, 6, si});
					}
				}
				if (p->hasListener()) {
					socket_t lfd = p->listenerSocket();
					if (lfd != STICE_INVALID_SOCKET) {
						pollfd l{}; l.fd = lfd; l.events = POLLIN;
						pfds.push_back(l); slots.push_back({p, 4});
					}
				}
				if (p->hasTurnDataTcp()) {
					socket_t dfd = p->turnDataTcpSocket();
					if (dfd != STICE_INVALID_SOCKET) {
						pollfd d{}; d.fd = dfd; d.events = p->turnDataDesiredEvents();
						pfds.push_back(d); slots.push_back({p, 5});
					}
				}
			}
		}

		int np = sticePoll(pfds.data(), static_cast<nfds_t>(pfds.size()),
		                   static_cast<int>(timeout));
		if (np < 0) {
			if (sticeSockerrno == STICE_SEINTR) continue;
			STICE_LOG_WARN("PollRegistry: poll failed errno=%d", sticeSockerrno);
			continue;
		}

		if (!pfds.empty() && (pfds[0].revents & POLLIN)) {
			char buf[256];
			while (static_cast<int>(::recv(interruptSock_, buf, sizeof(buf), 0)) > 0) {}
		}

		{
			std::lock_guard<std::mutex> lock(mutex_);
			for (auto &slot : slots) {
				if (!slot.participant) continue;
				if (std::find(participants_.begin(), participants_.end(), slot.participant) ==
				    participants_.end())
					slot.participant = nullptr;
			}
		}

		for (std::size_t i = 1; i < pfds.size(); ++i) {
			auto &slot = slots[i];
			if (!slot.participant) continue;
			if (pfds[i].revents == 0) continue;
			if (slot.kind == 1)
				slot.participant->onUdpReadable();
			else if (slot.kind == 2)
				slot.participant->onTcpEvents(pfds[i].revents);
			else if (slot.kind == 3)
				slot.participant->onTurnTcpEvents(pfds[i].revents);
			else if (slot.kind == 4)
				slot.participant->onAccept();
			else if (slot.kind == 5)
				slot.participant->onTurnDataTcpEvents(pfds[i].revents);
			else if (slot.kind == 6)
				slot.participant->onTurnTcpEventsSock(pfds[i].fd, pfds[i].revents);
		}
#endif // STICE_EPOLL_BACKEND (epoll event source vs poll(2) fallback)

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
		for (auto *p : snapshot) {
			// No alive check needed: generation_ is only incremented after all
			// callbacks return, so a removed participant is never touched here
			// (remove() + sync() must complete before its destruction).
			p->onBookkeeping(afterMs);
		}

		// End of iteration: increment generation AFTER every participant
		// callback (dispatch + bookkeeping) has fully returned. sync() blocks
		// until this increment, so once sync() returns the poll thread is
		// guaranteed no longer touching any participant — closes the UAF
		// window that existed when the increment happened at iteration start.
		{
			std::lock_guard<std::mutex> slock(syncMutex_);
			++generation_;
		}
		syncCv_.notify_all();
	}
}

} // namespace stice::net
