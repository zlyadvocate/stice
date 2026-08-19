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
#include <mutex>
#include <thread>
#include <vector>

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
	uint64_t generation_{0};
	bool threadExited_ = false;
};

} // namespace stice::net

#endif
