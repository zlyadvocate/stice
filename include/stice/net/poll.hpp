// SPDX-License-Identifier: MPL-2.0
// stice poll-based event loop. Per-agent independent thread model (aligned
// with libjuice's conn_thread.c): each PollRegistry instance owns ONE
// background thread that polls ONE participant's sockets. This eliminates
// the shared-thread contention that caused DTLS handshake hangs when
// multiple agents were created/destroyed concurrently in libdatachannel.
//
// Migration from shared-singleton to per-instance model:
//   - acquire() now returns a NEW PollRegistry instance each call (no
//     global refcount).
//   - release() is an instance method that stops the thread and deletes
//     the instance. Callers must keep the pointer returned by acquire().
//   - add()/remove()/interrupt()/sync() operate on this instance only.
//
// Callers (Agent, UDPMux, TCPMux, TcpMuxConn) each own their own
// PollRegistry instance. There is no shared global state.

#ifndef STICE_NET_POLL_HPP
#define STICE_NET_POLL_HPP

#include "stice/net/addr.hpp"
#include "stice/net/platform.hpp"
#include <condition_variable>
#include <cstdint>
#include <atomic>
#include <mutex>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------------
// Event-loop backend selection.
//
// Where an epoll-style backend exists, PollRegistry uses it instead of poll(2):
//   * Windows -> wepoll (IOCP-based epoll implementation, src/wepoll/)
//   * Linux   -> the native epoll(7) API
// Both expose the same epoll_* surface (epoll_create/epoll_ctl/epoll_wait),
// so src/net/poll.cpp has a SINGLE epoll event loop shared by both; only the
// handle create/close calls differ. Every other POSIX platform (macOS/BSD)
// keeps the poll(2) fallback.
//
// The macro is derived from the platform HERE rather than relying on a build
// define alone, because PollRegistry's member layout depends on it: a consumer
// that includes this public header must compute the same answer, or the class
// would have two different definitions (ODR violation). CMake additionally
// sets STICE_EPOLL_BACKEND=1 as a PUBLIC compile option on Windows/Linux (see
// stice_apply_common), so the two stay in agreement.
// ---------------------------------------------------------------------------
#ifndef STICE_EPOLL_BACKEND
#if defined(_WIN32) || defined(__linux__)
#define STICE_EPOLL_BACKEND 1
#else
#define STICE_EPOLL_BACKEND 0
#endif
#endif

#if STICE_EPOLL_BACKEND
#include <unordered_map>
#endif

namespace stice::net {

// A participant is an ICE agent (or UDPMux/TCPMux/TcpMuxConn) running in
// POLL mode. Each participant owns its own PollRegistry instance.
class PollParticipant {
public:
	virtual ~PollParticipant() = default;
	virtual socket_t udpSocket() const = 0;
	virtual bool hasTcp() const = 0;
	virtual socket_t tcpSocket() const = 0;
	virtual short tcpDesiredEvents() const = 0; // POLLIN / POLLOUT bits
	// Optional second TCP socket (e.g. TURN over TCP, separate from ICE-TCP).
	// Default: no second TCP socket.
	virtual bool hasTurnTcp() const { return false; }
	virtual socket_t turnTcpSocket() const { return STICE_INVALID_SOCKET; }
	virtual short turnTcpDesiredEvents() const { return 0; }
	virtual void onTurnTcpEvents(short /*events*/) {}
	// Indexed TURN-over-TCP slots: one control connection per relay entry, so
	// multiple TCP/TLS TURN servers can run concurrently (the legacy single
	// slot above only supports one). Enumeration (count/socket/events) is
	// rebuilt every poll iteration; dispatch identifies the transport by its
	// socket fd via onTurnTcpEventsSock(), which stays correct even if the
	// entry list is mutated (erase/push_back) during an earlier callback.
	// Default implementations fall back to the single-slot API.
	virtual int turnTcpSlotCount() const { return hasTurnTcp() ? 1 : 0; }
	virtual socket_t turnTcpSocketAt(int i) const {
		return i == 0 ? turnTcpSocket() : STICE_INVALID_SOCKET;
	}
	virtual short turnTcpDesiredEventsAt(int i) const {
		return i == 0 ? turnTcpDesiredEvents() : 0;
	}
	// Route events for the TURN-TCP control connection whose socket is `sock`.
	// Default: forward to the legacy single-slot handler when it matches.
	virtual void onTurnTcpEventsSock(socket_t sock, short events) {
		if (hasTurnTcp() && sock == turnTcpSocket()) onTurnTcpEvents(events);
	}
	// Optional third TCP socket (RFC 6062 TURN TCP allocation data connection,
	// separate from the TURN control connection). One at a time is sufficient
	// for ICE (one selected pair).
	virtual bool hasTurnDataTcp() const { return false; }
	virtual socket_t turnDataTcpSocket() const { return STICE_INVALID_SOCKET; }
	virtual short turnDataDesiredEvents() const { return 0; }
	virtual void onTurnDataTcpEvents(short /*events*/) {}
	// Optional TCP listener socket (e.g. TCPMux passive listener). When
	// hasListener() returns true, the PollRegistry polls the listener for
	// POLLIN and calls onAccept() when a new connection arrives.
	virtual bool hasListener() const { return false; }
	virtual socket_t listenerSocket() const { return STICE_INVALID_SOCKET; }
	virtual void onAccept() {}
	virtual int64_t nextTimestampMs() const = 0; // 0 => no pending timer
	virtual void onUdpReadable() = 0;
	virtual void onTcpEvents(short events) = 0;
	virtual void onBookkeeping(int64_t nowMs) = 0;
};

// PollRegistry owns ONE background thread that polls the sockets of the
// registered participants. In the per-instance model, a PollRegistry
// typically has exactly ONE participant (the Agent/Mux that owns it), but
// the API supports multiple participants for backward compatibility
// (e.g. TCPMux registers itself + its TcpMuxConns on the same instance).
//
// Lifecycle: acquire() creates an instance and starts the thread;
// release() stops the thread and deletes the instance. Callers MUST keep
// the pointer returned by acquire() and pass it to release().
class PollRegistry {
public:
	// Create a new PollRegistry instance with its own background thread.
	// Returned pointer is owned by the caller; release() deletes it.
	static PollRegistry *acquire();
	// Stop the thread and delete this instance. Must be called exactly once
	// per acquire(). Safe to call on a participant-removed instance.
	void release();

	void add(PollParticipant *p);
	void remove(PollParticipant *p);
	void interrupt(); // wake the poll loop immediately

	// Block until the poll thread has completed at least one full iteration
	// (poll + dispatch + bookkeeping) that started AFTER this call returns.
	// This guarantees the poll thread is not holding any raw pointers from
	// a previous iteration, so it is safe to destroy participants that were
	// removed via remove() before calling sync().
	void sync();

private:
	PollRegistry();
	~PollRegistry();
	PollRegistry(const PollRegistry &) = delete;
	PollRegistry &operator=(const PollRegistry &) = delete;

	void run();
	int64_t computeTimeoutMs(int64_t nowMs);
#if STICE_EPOLL_BACKEND
	// Persistent epoll registration (wepoll on Windows, native epoll on Linux).
	// Both require persistent registration: ADD once, MOD to change interest,
	// DEL when a socket leaves; wepoll in particular does NOT support rapid
	// ADD/DEL churn of the same socket (re-ADD returns EEXIST). So the poll
	// loop keeps a stable slot table and only diffs desired-vs-registered
	// sockets each iteration.
	bool epollSetup();
	// Reconcile the kernel registration against `participants`, a snapshot the
	// caller took under the registry mutex. The participant getters are invoked
	// here with NO registry lock held: they take the participant's own lock, and
	// a participant that holds its lock while calling add()/remove() (e.g.
	// Agent::set_remote_description -> pollReg_->add(this)) would otherwise
	// deadlock us (registry->agent vs agent->registry). slots_/fdToSlot_ are
	// touched only by the poll thread, so they need no lock.
	void epollSync(const std::vector<PollParticipant *> &participants, bool forceResync);
	struct Slot {
		socket_t fd = STICE_INVALID_SOCKET;
		PollParticipant *participant = nullptr;
		int kind = 0; // 0=interrupt 1=udp 2=tcp 3=turn-tcp 4=listener 5=turn-data 6=indexed turn-tcp
		int idx = -1; // kind==6: per-participant turn-TCP slot index
		short lastEvents = 0;
		bool active = false;
		bool seen = false;
	};
	std::vector<Slot> slots_;            // never erased; index stored in epoll data
	std::unordered_map<socket_t, int> fdToSlot_;
#ifdef _WIN32
	void *eph_ = nullptr;                // wepoll epoll handle (HANDLE)
#else
	int eph_ = -1;                       // native epoll(7) fd
#endif
	bool epollReady_ = false;
	// Re-assert every registration on the next epollSync(): set by add()/remove().
	// The kernel drops an fd's epoll registration when the socket is closed, yet
	// the fd number is reused aggressively (lowest free fd first on Linux), so a
	// lingering slot can silently shadow a brand-new socket. See epollSync().
	bool epollResyncAll_ = false;
	// Bounded safety net: force a full registration re-assert at most this often
	// (covers a participant that swaps its socket without add()/remove()).
	int64_t epollLastFullSyncMs_ = 0;
#endif

	std::mutex mutex_;
	std::vector<PollParticipant *> participants_;
	std::thread thread_;
	socket_t interruptSock_ = STICE_INVALID_SOCKET;
	AddrRecord interruptAddr_;
	bool stopping_ = false;

	// Sync barrier: the poll thread increments generation_ at the start of
	// each iteration under syncMutex_. sync() waits for generation_ to
	// increase past the value observed at call time, ensuring the poll
	// thread has started a new iteration with fresh slots/snapshots that
	// don't include removed participants.
	std::mutex syncMutex_;
	std::condition_variable syncCv_;
	// atomic: sync()'s condition_variable predicate may be evaluated outside
	// syncMutex_, and the poll thread writes these from run() — atomics close the
	// memory race TSan reports between run() (write) and sync() (read).
	std::atomic<uint64_t> generation_{0};
	std::atomic<bool> threadExited_{false};
};

} // namespace stice::net

#endif
