// SPDX-License-Identifier: MPL-2.0
// Author: zlyadvocate
// Version: 0.13.1
// SelectBackend: B plan implementation — control plane / data plane
// separation with a thread pool.
//
// Architecture:
//   - 1 UDP control thread: handles UDP listener, TCP listener (accept),
//     all relay sockets, and timer ticks (expireStale). This is the
//     "control plane" — all allocation lifecycle operations happen here.
//   - N TCP worker threads: each handles a subset of TCP connections for
//     read/write. This is the "data plane" — STUN framing, ChannelData,
//     and RFC 6062 data piping.
//
// TCP connections are distributed to workers by round-robin (socket fd %
// workerCount). Each worker has its own select() fd_set, so there's no
// contention between workers.
//
// Shared state is protected by TurnServer's shared_mutex (see turn_server.cpp).
// The backend itself only needs a mutex around its socket sets.

// Raise FD_SETSIZE before ANY header pulls in winsock2.h.
//
// A #define in another translation unit has no effect here: turn_server.cpp and
// main.cpp each raise FD_SETSIZE in their own TU, so this file previously saw
// the Winsock default of 64 and every fd_set it built was only 64 slots wide.
// Note the Winsock FD_SET macro DOES bounds-check (`fd_count < FD_SETSIZE`), so
// the failure mode is not a buffer overflow - it is that FD_SET *silently
// ignores* sockets past the limit, so a worker told to watch more than
// FD_SETSIZE-1 sockets just stops monitoring the surplus and those allocations
// become one-way black holes. Must precede every include below.
#ifdef _WIN32
#ifndef FD_SETSIZE
#define FD_SETSIZE 8192
#endif
#endif

#ifndef STICE_STATIC
#define STICE_STATIC
#endif

#include "stice/stserver/io_backend.hpp"

#include "stice/log.hpp"
#include "stice/net/addr.hpp"
#include "stice/net/platform.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

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
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace stserver {

using stice::net::wouldBlock;

namespace {
constexpr int ControlSelectTimeoutMs = 50;  // UDP control thread poll interval
constexpr int WorkerSelectTimeoutMs = 50;    // TCP worker poll interval
// Max datagrams drained from one socket per select cycle before yielding back
// to the control loop. Mirrors pion's per-socket readloop (drain until
// wouldBlock) while bounding each socket's share so a busy UDP listener never
// starves relay sockets in a single cycle.
constexpr int MaxDrainPerCycle = 2048;
// Per-socket recv buffer size. Shared with the IOCP/epoll backends via the
// same STSERVER_IO_BUFFER_SIZE macro so all three backends behave identically
// when the option is set. Default 65536 preserves backward compatibility.
#ifndef STSERVER_IO_BUFFER_SIZE
#define STSERVER_IO_BUFFER_SIZE 65536
#endif
constexpr int BufferSize = STSERVER_IO_BUFFER_SIZE;
// Each worker builds one fd_set per pass. FD_SET bounds-checks against
// FD_SETSIZE and silently IGNORES entries past it, so this is the real
// per-worker limit on monitored sockets (one slot is reserved for the worker's
// interrupt socket). Exceeding it degrades silently - hence the loud check in
// addRelaySocket/addTcpConn.
#ifndef FD_SETSIZE
#define FD_SETSIZE 1024 // non-Windows fallback (sys/select.h normally defines it)
#endif
constexpr std::size_t MaxFdsPerWorkerSet = FD_SETSIZE - 1;
} // namespace

namespace {
// Interrupt-driven snapshot invalidation: each TCP/relay worker owns a
// loopback UDP socket that it always select()s. add/remove of a socket writes a
// byte to wake the worker so it rebuilds its snapshot before the next event
// pass. This closes the stale-snapshot window that silently drops packets when
// a fd is removed and reused between snapshot build and select(). Mirrors
// PollRegistry's generation+interrupt mechanism for the select backend.
// Raise the calling IO thread's priority so the relay data plane is not starved
// when the host runs many client processes. Under 100-way loopback load the
// box is CPU-saturated by client threads; without a boost the single UDP
// control thread is descheduled inside its drain loop, the listener's receive
// buffer overflows and TURN datagrams are silently dropped (~18% loss observed).
// ABOVE_NORMAL keeps the server responsive without starving the OS or the
// server's own business thread (which stays at NORMAL).
static void boostIoThreadPriority() {
#ifdef _WIN32
	::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
#else
	(void)0;
#endif
}
static void closeSock(socket_t s) {
	if (s == STICE_INVALID_SOCKET) return;
#ifdef _WIN32
	::closesocket(s);
#else
	::close(s);
#endif
}
// Probe whether a socket handle is still valid.
//
// Necessary because of a Windows select() property: if ANY handle in the set
// refers to a closed socket, the WHOLE select() call fails with WSAENOTSOCK
// (10038) instead of reporting readable/writable. On the data plane a worker
// snapshots its socket set *under its mutex*, then calls select() with that
// snapshot; meanwhile the business thread may remove a connection
// (removeTcpConn/removeRelaySocket) and then closesocket() it. The snapshot the
// worker is still selecting on then holds a dead handle -> select() fails. The
// old code `break`ed out of the worker loop on that error, permanently killing
// the worker thread and black-holing every connection assigned to it (observed
// as ICE "connect timeout", rx=0, for ~18% of 200 clients). Instead we identify
// and drop the dead handles and keep the worker alive.
static bool socketIsValid(socket_t s) {
	if (s == STICE_INVALID_SOCKET) return false;
	int type = 0;
	socklen_t len = sizeof(type);
	return ::getsockopt(s, SOL_SOCKET, SO_TYPE,
	                    reinterpret_cast<char *>(&type), &len) == 0;
}
static bool makeInterruptSock(socket_t &sock, sockaddr_storage &addr,
                              socklen_t &addrLen) {
	sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == STICE_INVALID_SOCKET) return false;
#ifdef _WIN32
	u_long nb = 1;
	ioctlsocket(sock, FIONBIO, &nb);
#else
	int fl = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, fl | O_NONBLOCK);
#endif
	sockaddr_in bind4{};
	bind4.sin_family = AF_INET;
	bind4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	bind4.sin_port = 0;
	if (::bind(sock, reinterpret_cast<sockaddr *>(&bind4), sizeof(bind4)) != 0) {
		closeSock(sock);
		sock = STICE_INVALID_SOCKET;
		return false;
	}
	socklen_t alen = sizeof(addr);
	if (::getsockname(sock, reinterpret_cast<sockaddr *>(&addr), &alen) != 0) {
		closeSock(sock);
		sock = STICE_INVALID_SOCKET;
		return false;
	}
	addrLen = alen;
	return true;
}
static void wakeWorkerSock(socket_t sock, const sockaddr_storage &addr,
                           socklen_t alen) {
	if (sock == STICE_INVALID_SOCKET) return;
	char byte = 1;
	::sendto(sock, &byte, 1, 0, reinterpret_cast<const sockaddr *>(&addr), alen);
}
} // namespace

class SelectBackend : public IoBackend {
public:
	SelectBackend() = default;
	~SelectBackend() override { stop(); }

	bool init(IoBackendOwner *owner, socket_t udpListener, socket_t tcpListener) override {
		owner_ = owner;
		udpListener_ = udpListener;
		tcpListener_ = tcpListener;
		return true;
	}

	void start() override {
		running_ = true;
		int n = std::max(1, workerCount_);
		// Start UDP control thread (UDP listener + TCP accept + timer only;
		// relay sockets are drained by the relay readloop pool below).
		controlThread_ = std::thread([this] { controlLoop(); });
		// Start TCP worker threads. TcpWorker holds a std::mutex (non-movable),
		// so we store unique_ptr<TcpWorker> in the vector.
		// DATA-RACE FIX (TSan-verified): tcpWorkerLoop()/relayWorkerLoop()
		// dereference tcpWorkers_[workerId]/relayWorkers_[workerId] on thread
		// entry, so the vectors must be FULLY populated before ANY worker thread
		// starts — otherwise a worker reads an element the main thread is still
		// push_back'ing (data race + potential OOB). Construct all, then start.
		tcpWorkerRunning_.reset(new std::atomic<bool>[n]);
		for (int i = 0; i < n; ++i) tcpWorkerRunning_[i] = true;
		tcpWorkers_.reserve(n);
		for (int i = 0; i < n; ++i) tcpWorkers_.push_back(std::make_unique<TcpWorker>());
		for (int i = 0; i < n; ++i)
			if (!makeInterruptSock(tcpWorkers_[i]->interruptSock,
			                       tcpWorkers_[i]->interruptAddr,
			                       tcpWorkers_[i]->interruptAddrLen))
				STICE_LOG_WARN("stserver: tcp worker%d interrupt setup failed", i);
		for (int i = 0; i < n; ++i)
			tcpWorkers_[i]->thread = std::thread([this, i] { tcpWorkerLoop(i); });
		// Start relay readloop pool (pion multi-readloop): one worker thread
		// per workerCount, each select()ing its own relay socket subset.
		relayWorkerRunning_.reset(new std::atomic<bool>[n]);
		for (int i = 0; i < n; ++i) relayWorkerRunning_[i] = true;
		relayWorkers_.reserve(n);
		for (int i = 0; i < n; ++i) relayWorkers_.push_back(std::make_unique<RelayWorker>());
		for (int i = 0; i < n; ++i)
			if (!makeInterruptSock(relayWorkers_[i]->interruptSock,
			                       relayWorkers_[i]->interruptAddr,
			                       relayWorkers_[i]->interruptAddrLen))
				STICE_LOG_WARN("stserver: relay worker%d interrupt setup failed", i);
		for (int i = 0; i < n; ++i)
			relayWorkers_[i]->thread = std::thread([this, i] { relayWorkerLoop(i); });
		// UDP-listener reader pool: fan the shared listener across several
		// threads so the client->peer data plane scales past one core. Sized to
		// the worker count (capped at 8) so ~200 concurrent clients can be
		// drained without the listener buffer overflowing. Note that every
		// reader select()s the same socket, so a datagram wakes all of them and
		// only one wins the recvfrom (thundering herd): too many readers wastes
		// kernel time on losing recvfrom calls. Overridable for tuning.
		int u = std::max(2, std::min(8, n));
		if (const char *e = std::getenv("STSERVER_UDP_READERS")) {
			int v = std::atoi(e);
			if (v >= 1) u = std::min(v, 32);
		}
		udpWorkerRunning_.reset(new std::atomic<bool>[u]);
		for (int i = 0; i < u; ++i) udpWorkerRunning_[i] = true;
		udpWorkers_.reserve(u);
		for (int i = 0; i < u; ++i) udpWorkers_.push_back(std::make_unique<UdpWorker>());
		for (int i = 0; i < u; ++i)
			udpWorkers_[i]->thread = std::thread([this, i] { udpRecvLoop(i); });
		STICE_LOG_INFO("stserver: SelectBackend started, %d TCP workers, %d relay readloops, %d udp readers (per-worker fd_set cap %zu)",
		               n, n, u, MaxFdsPerWorkerSet);
	}

	void stop() override {
		if (!running_.exchange(false)) return;
		for (std::size_t i = 0; i < tcpWorkers_.size(); ++i) tcpWorkerRunning_[i] = false;
		for (std::size_t i = 0; i < relayWorkers_.size(); ++i) relayWorkerRunning_[i] = false;
		if (udpWorkerRunning_)
			for (std::size_t i = 0; i < udpWorkers_.size(); ++i) udpWorkerRunning_[i] = false;
		if (controlThread_.joinable()) controlThread_.join();
		for (auto &t : tcpWorkers_) if (t->thread.joinable()) t->thread.join();
		for (auto &r : relayWorkers_) if (r->thread.joinable()) r->thread.join();
		for (auto &w : udpWorkers_) if (w->thread.joinable()) w->thread.join();
		for (auto &t : tcpWorkers_) closeSock(t->interruptSock);
		for (auto &r : relayWorkers_) closeSock(r->interruptSock);
		tcpWorkers_.clear();
		tcpWorkerRunning_.reset();
		relayWorkers_.clear();
		relayWorkerRunning_.reset();
		udpWorkers_.clear();
		udpWorkerRunning_.reset();
	}

	void addRelaySocket(socket_t s) override {
		if (s == STICE_INVALID_SOCKET) return;
		// Guard: called before start() the worker vectors are empty, so the
		// round-robin modulo below would index an empty vector. Not reachable via
		// TurnServer (it registers relay sockets only from handleAllocate, after
		// run()), but the backend must not assume its caller's ordering.
		if (relayWorkers_.empty()) {
			STICE_LOG_ERROR("stserver: addRelaySocket fd=%llu before start(); ignored",
			                (unsigned long long)s);
			return;
		}
		// Plan A: responsibility separation guard. A relay socket must never
		// share a fd with a control-plane listener; if the OS reused a listener
		// fd for a relay socket, reject it so the control thread keeps sole
		// ownership (avoids dual select() racing the same fd).
		if (s == udpListener_ || s == tcpListener_) {
			STICE_LOG_WARN("stserver: addRelaySocket rejected fd=%llu (control listener)",
			               (unsigned long long)s);
			return;
		}
		// Distribute relay socket to a readloop worker (round-robin).
		int w = nextRelayWorker_++ % (int)relayWorkers_.size();
		{
			std::lock_guard<std::mutex> lk(relayAssignMutex_);
			relayAssignment_[s] = w;
		}
		{
			auto &rw = relayWorkers_[w];
			std::lock_guard<std::mutex> lk(rw->mutex);
			// FD_SET silently drops entries past FD_SETSIZE, so exceeding the
			// per-set capacity would make this relay socket invisible to select()
			// (one-way black hole) with no other symptom. Make it loud.
			if (rw->sockets.size() >= MaxFdsPerWorkerSet) {
				STICE_LOG_ERROR("stserver: relay worker%d fd_set full (%zu >= %zu): fd=%llu will NOT be monitored - raise workerCount",
				                w, rw->sockets.size(), MaxFdsPerWorkerSet,
				                (unsigned long long)s);
			}
			rw->sockets.insert(s);
		}
		// Interrupt-driven snapshot invalidation: wake the owning worker so it
		// rebuilds its snapshot with the new fd before the next event pass.
		{
			auto &rw = relayWorkers_[w];
			wakeWorkerSock(rw->interruptSock, rw->interruptAddr, rw->interruptAddrLen);
		}
	}

	void removeRelaySocket(socket_t s) override {
		int w = -1;
		{
			std::lock_guard<std::mutex> lk(relayAssignMutex_);
			auto it = relayAssignment_.find(s);
			if (it != relayAssignment_.end()) { w = it->second; relayAssignment_.erase(it); }
		}
		if (w >= 0 && w < (int)relayWorkers_.size()) {
			auto &rw = relayWorkers_[w];
			std::lock_guard<std::mutex> lk(rw->mutex);
			rw->sockets.erase(s);
			wakeWorkerSock(rw->interruptSock, rw->interruptAddr, rw->interruptAddrLen);
		}
	}

	void addTcpConn(socket_t s, bool hasWritePending) override {
		if (s == STICE_INVALID_SOCKET) return;
		if (tcpWorkers_.empty()) {
			STICE_LOG_ERROR("stserver: addTcpConn sock=%llu before start(); ignored",
			                (unsigned long long)s);
			return;
		}
		int worker = nextWorker_++ % (int)tcpWorkers_.size();
		{
			std::lock_guard<std::mutex> lk(tcpAssignMutex_);
			tcpAssignment_[s] = worker;
		}
		{
			auto &w = tcpWorkers_[worker];
			std::lock_guard<std::mutex> lk(w->mutex);
			if (w->conns.size() >= MaxFdsPerWorkerSet) {
				STICE_LOG_ERROR("stserver: tcp worker%d fd_set full (%zu >= %zu): sock=%llu will NOT be monitored - raise workerCount",
				                worker, w->conns.size(), MaxFdsPerWorkerSet,
				                (unsigned long long)s);
			}
			w->conns[s] = hasWritePending;
		}
		// DEBUG: this fires once per accepted TCP connection. At 200 clients
		// (hundreds of connections in one wave) an INFO line here made the log
		// tens of thousands of lines and cost a global-lock file write per
		// connection during the burst we are trying to make fast.
		STICE_LOG_DEBUG("stserver: addTcpConn sock=%llu worker=%d writePending=%d", (unsigned long long)s, worker, (int)hasWritePending);
		{
			auto &w = tcpWorkers_[worker];
			wakeWorkerSock(w->interruptSock, w->interruptAddr, w->interruptAddrLen);
		}
	}

	void removeTcpConn(socket_t s) override {
		// Remove from whichever worker owns it.
		int worker = -1;
		{
			std::lock_guard<std::mutex> lk(tcpAssignMutex_);
			auto it = tcpAssignment_.find(s);
			if (it != tcpAssignment_.end()) {
				worker = it->second;
				tcpAssignment_.erase(it);
			}
		}
		if (worker >= 0 && worker < (int)tcpWorkers_.size()) {
			auto &w = tcpWorkers_[worker];
			std::lock_guard<std::mutex> lk(w->mutex);
			w->conns.erase(s);
			wakeWorkerSock(w->interruptSock, w->interruptAddr, w->interruptAddrLen);
		}
	}

	void setTcpConnWritePending(socket_t s, bool pending) override {
		int worker = -1;
		{
			std::lock_guard<std::mutex> lk(tcpAssignMutex_);
			auto it = tcpAssignment_.find(s);
			if (it != tcpAssignment_.end()) worker = it->second;
		}
		if (worker >= 0 && worker < (int)tcpWorkers_.size()) {
			auto &w = tcpWorkers_[worker];
			std::lock_guard<std::mutex> lk(w->mutex);
			auto it = w->conns.find(s);
			if (it == w->conns.end()) return;
			// No-op when the flag already matches: the TCP data path reports its
			// write-pending state after every flush, and waking the worker with a
			// sendto() syscall for an unchanged value dominated the per-packet
			// cost of the TCP data path.
			if (it->second == pending) return;
			it->second = pending;
			wakeWorkerSock(w->interruptSock, w->interruptAddr, w->interruptAddrLen);
		}
	}

	void setWorkerCount(int n) override { workerCount_ = std::max(1, n); }

private:
	// ---- Control plane thread (UDP + TCP accept + relay + timer) ----
	void controlLoop() {
		boostIoThreadPriority();
		auto lastTick = std::chrono::steady_clock::now();
		while (running_) {
			fd_set rfds;
			FD_ZERO(&rfds);
			socket_t maxfd = STICE_INVALID_SOCKET;
			auto setRead = [&](socket_t s) {
				if (s == STICE_INVALID_SOCKET) return;
				FD_SET(s, &rfds);
				if (maxfd == STICE_INVALID_SOCKET || s > maxfd) maxfd = s;
			};

			// The UDP listener is drained by the udp-reader pool below, not by
			// this thread, so a saturated data plane cannot starve TCP accept
			// and the 50ms timer. Keep this thread purely control-plane.
			setRead(tcpListener_);

			timeval tv;
			tv.tv_sec = ControlSelectTimeoutMs / 1000;
			tv.tv_usec = (ControlSelectTimeoutMs % 1000) * 1000;
			int n = ::select(static_cast<int>(maxfd) + 1, &rfds, nullptr, nullptr, &tv);
			if (n < 0) {
				if (wouldBlock() || sticeSockerrno == STICE_SEINTR) continue;
				STICE_LOG_ERROR("stserver: control select() failed: %d", sticeSockerrno);
				break;
			}

			// TCP listener: accept new connections.
			if (tcpListener_ != STICE_INVALID_SOCKET && FD_ISSET(tcpListener_, &rfds)) {
				acceptTcp();
			}

			// Timer tick (every ~50ms).
			auto now = std::chrono::steady_clock::now();
			auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
			                   now - lastTick);
			if (elapsed.count() >= ControlSelectTimeoutMs) {
				lastTick = now;
				owner_->ioOnTimerTick();
			}
		}
	}

	void acceptTcp() {
		while (running_) {
			struct sockaddr_storage ss;
			socklen_t len = sizeof(ss);
			socket_t s = ::accept(tcpListener_, reinterpret_cast<sockaddr *>(&ss), &len);
			if (s == STICE_INVALID_SOCKET) {
				// Distinguish "no more pending connections" from fd/table
				// exhaustion. On exhaustion the listener stays readable while the
				// backlog is non-empty, so breaking out and re-entering select()
				// would spin this thread at 100% and starve the relay readers.
				// Back off briefly instead.
				const int err = sticeSockerrno;
#ifdef _WIN32
				const bool exhausted = (err == WSAEMFILE || err == WSAENOBUFS);
#else
				const bool exhausted = (err == EMFILE || err == ENFILE || err == ENOBUFS);
#endif
				if (exhausted) {
					STICE_LOG_ERROR("stserver: accept() resource exhaustion (err=%d); throttling accept loop", err);
					std::this_thread::sleep_for(std::chrono::milliseconds(50));
				}
				break;
			}
			stice::net::addrUnmapInet6V4Mapped(reinterpret_cast<sockaddr *>(&ss), len);
			// Set non-blocking + TCP_NODELAY.
#ifdef _WIN32
			u_long nb = 1;
			ioctlsocket(s, FIONBIO, &nb);
#else
			int fl = fcntl(s, F_GETFL, 0);
			fcntl(s, F_SETFL, fl | O_NONBLOCK);
#endif
			int one = 1;
			setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
			           reinterpret_cast<const char *>(&one), sizeof(one));
			stice::net::AddrRecord peer;
			std::memcpy(&peer.addr, &ss, len);
			peer.len = len;
			peer.socktype = SOCK_STREAM;
			// Notify TurnServer first (it registers the conn in its maps),
			// then register with the backend for monitoring.
			owner_->ioOnTcpAccepted(s, peer);
		}
	}

	// ---- TCP worker threads (data plane) ----
	void tcpWorkerLoop(int workerId) {
		boostIoThreadPriority();
		auto &myData = tcpWorkers_[workerId];
		auto lastTick = std::chrono::steady_clock::now();
		while (tcpWorkerRunning_[workerId] && running_) {
			fd_set rfds, wfds;
			FD_ZERO(&rfds);
			FD_ZERO(&wfds);
			socket_t maxfd = STICE_INVALID_SOCKET;
			// Only FD_SET a valid interrupt socket: FD_SET(-1) would store an
			// invalid SOCKET and make select() fail with WSAENOTSOCK, killing the
			// worker for the whole process lifetime.
			const bool haveInterrupt = (myData->interruptSock != STICE_INVALID_SOCKET);
			if (haveInterrupt) {
				FD_SET(myData->interruptSock, &rfds);
				maxfd = myData->interruptSock;
			}

			// Snapshot our conn set under the lock, then build the fd_set outside
			// it (FD_SET only writes this thread's local fd_set).
			std::vector<std::pair<socket_t, bool>> conns;
			{
				std::lock_guard<std::mutex> lk(myData->mutex);
				conns.reserve(myData->conns.size());
				for (auto &kv : myData->conns) conns.push_back({kv.first, kv.second});
			}
			for (auto &kv : conns) {
				socket_t s = kv.first;
				if (s == STICE_INVALID_SOCKET) continue;
				FD_SET(s, &rfds);
				if (kv.second) FD_SET(s, &wfds); // write pending
				if (maxfd == STICE_INVALID_SOCKET || s > maxfd) maxfd = s;
			}

			timeval tv;
			tv.tv_sec = WorkerSelectTimeoutMs / 1000;
			tv.tv_usec = (WorkerSelectTimeoutMs % 1000) * 1000;
			int n = ::select(static_cast<int>(maxfd) + 1, &rfds, &wfds, nullptr, &tv);
			if (n < 0) {
				if (wouldBlock() || sticeSockerrno == STICE_SEINTR) continue;
				// A handle in the snapshot was closed between the snapshot above
				// and this select() (business thread removes then closes). On
				// Windows that fails the whole select() with WSAENOTSOCK. Do NOT
				// kill the worker: drop the dead handles and continue. Only exit
				// via the loop condition (shutdown).
				const int err = sticeSockerrno;
				std::vector<socket_t> dead;
				{
					std::lock_guard<std::mutex> lk(myData->mutex);
					for (auto it = myData->conns.begin(); it != myData->conns.end();) {
						if (!socketIsValid(it->first)) { dead.push_back(it->first); it = myData->conns.erase(it); }
						else ++it;
					}
				}
				if (!dead.empty()) {
					std::lock_guard<std::mutex> lk(tcpAssignMutex_);
					for (socket_t ds : dead) tcpAssignment_.erase(ds);
				}
				STICE_LOG_WARN("stserver: worker%d select() failed: errno=%d; pruned %zu closed fd(s), continuing",
				               workerId, err, dead.size());
				// If nothing was prunable the failure came from the stale local
				// snapshot alone (already dropped); the next pass rebuilds it.
				// Sleep briefly so a pathological set cannot spin this thread.
				if (dead.empty()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
				continue;
			}
			// Interrupt-driven snapshot invalidation (same as relay worker).
			if (haveInterrupt && FD_ISSET(myData->interruptSock, &rfds)) {
				char ibuf[64];
				while (static_cast<int>(::recv(myData->interruptSock, ibuf, sizeof(ibuf), 0)) > 0) {}
				continue;
			}

			// Process readable connections. Re-check ownership under the mutex
			// before the recv (this mirrors the relay worker's fd-reuse guard):
			// between the snapshot above and here the business thread may have
			// closed this socket, and the OS may have reused the handle for a
			// different connection - recv'ing on a reused fd would read another
			// connection's data.
			for (auto &kv : conns) {
				if (!running_ || !tcpWorkerRunning_[workerId]) break;
				socket_t s = kv.first;
				if (s == STICE_INVALID_SOCKET || !FD_ISSET(s, &rfds)) continue;
				{
					std::lock_guard<std::mutex> lk(myData->mutex);
					if (myData->conns.find(s) == myData->conns.end()) continue;
				}
				readTcpConn(s);
			}
			// Process writable connections (same ownership recheck).
			for (auto &kv : conns) {
				if (!running_ || !tcpWorkerRunning_[workerId]) break;
				socket_t s = kv.first;
				if (s == STICE_INVALID_SOCKET || !FD_ISSET(s, &wfds)) continue;
				{
					std::lock_guard<std::mutex> lk(myData->mutex);
					if (myData->conns.find(s) == myData->conns.end()) continue;
				}
				owner_->ioOnTcpConnWritable(s);
			}
		}
	}

	// ---- Relay readloop pool (pion multi-readloop) ----
	void relayWorkerLoop(int workerId) {
		boostIoThreadPriority();
		auto &my = relayWorkers_[workerId];
		while (running_ && relayWorkerRunning_[workerId]) {
			fd_set rfds;
			FD_ZERO(&rfds);
			socket_t maxfd = STICE_INVALID_SOCKET;
			// Only FD_SET a valid interrupt socket (see tcpWorkerLoop).
			const bool haveInterrupt = (my->interruptSock != STICE_INVALID_SOCKET);
			if (haveInterrupt) {
				FD_SET(my->interruptSock, &rfds);
				maxfd = my->interruptSock;
			}

			// Snapshot our relay socket subset under the lock; build the fd_set
			// outside it (FD_SET only writes this thread's local fd_set).
			std::vector<socket_t> snapshot;
			{
				std::lock_guard<std::mutex> lk(my->mutex);
				snapshot.reserve(my->sockets.size());
				for (socket_t s : my->sockets) snapshot.push_back(s);
			}
			for (socket_t s : snapshot) {
				FD_SET(s, &rfds);
				if (maxfd == STICE_INVALID_SOCKET || s > maxfd) maxfd = s;
			}

			timeval tv;
			tv.tv_sec = WorkerSelectTimeoutMs / 1000;
			tv.tv_usec = (WorkerSelectTimeoutMs % 1000) * 1000;
			int n = ::select(static_cast<int>(maxfd) + 1, &rfds, nullptr, nullptr, &tv);
			if (n < 0) {
				if (wouldBlock() || sticeSockerrno == STICE_SEINTR) continue;
				// See tcpWorkerLoop: a concurrently-closed handle fails the whole
				// select() with WSAENOTSOCK. Prune the dead relay sockets and keep
				// the worker alive instead of exiting and stalling every relay
				// socket assigned to it.
				const int err = sticeSockerrno;
				std::vector<socket_t> dead;
				{
					std::lock_guard<std::mutex> lk(my->mutex);
					for (auto it = my->sockets.begin(); it != my->sockets.end();) {
						if (!socketIsValid(*it)) { dead.push_back(*it); it = my->sockets.erase(it); }
						else ++it;
					}
				}
				if (!dead.empty()) {
					std::lock_guard<std::mutex> lk(relayAssignMutex_);
					for (socket_t ds : dead) relayAssignment_.erase(ds);
				}
				STICE_LOG_WARN("stserver: relay worker%d select() failed: %d; pruned %zu closed fd(s), continuing",
				               workerId, err, dead.size());
				if (dead.empty()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
				continue;
			}
			if (n == 0) continue;

			// Interrupt-driven snapshot invalidation: drain the interrupt socket
			// first so the snapshot is rebuilt with the latest socket set before
			// processing any data event. Prevents a stale fd (removed + reused)
			// from being select()ed and silently eating the event.
			if (haveInterrupt && FD_ISSET(my->interruptSock, &rfds)) {
				char ibuf[64];
				while (static_cast<int>(::recv(my->interruptSock, ibuf, sizeof(ibuf), 0)) > 0) {}
				continue;
			}

			for (socket_t s : snapshot) {
				if (!running_ || !relayWorkerRunning_[workerId]) break;
				if (!FD_ISSET(s, &rfds)) continue;
				// fd-reuse guard: only process if this socket is still assigned
				// to this worker. If the OS reused the handle for a socket now
				// owned by another worker, skip (that worker drains it).
				{
					std::lock_guard<std::mutex> lk(relayAssignMutex_);
					auto it = relayAssignment_.find(s);
					if (it == relayAssignment_.end() || it->second != workerId) continue;
				}
				// Drain to wouldBlock (pion readloop semantics).
				unsigned char buf[BufferSize];
				int drained = 0;
				while (running_ && drained < MaxDrainPerCycle) {
					stice::net::AddrRecord peer;
					int len = sticeRecvfrom(s, reinterpret_cast<char *>(buf),
					                        sizeof(buf), peer);
					if (len <= 0) {
						// Plan C: fd-reuse / stale-socket fallback. A negative
						// result that is not would-block means the fd has been
						// invalidated (EBADF/ENOTSOCK/ECONNRESET) after select
						// fired; remove it so a later reused fd cannot keep this
						// worker select()ing a dead handle and competing with the
						// current owner for events.
						if (len < 0 && !wouldBlock()) {
							STICE_LOG_WARN("stserver: relay fd=%llu invalid after select, removing",
							               (unsigned long long)s);
							removeRelaySocket(s);
						}
						break;
					}
					owner_->ioOnRelayData(s, buf, static_cast<std::size_t>(len), peer);
					++drained;
				}
			}

		}
	}

	void readTcpConn(socket_t s) {
		unsigned char buf[BufferSize];
		while (true) {
			int n = ::recv(s, reinterpret_cast<char *>(buf), sizeof(buf), 0);
			if (n > 0) {
				owner_->ioOnTcpConnData(s, buf, static_cast<std::size_t>(n));
				continue;
			}
			if (n == 0) {
				owner_->ioOnTcpConnClosed(s);
				return;
			}
			if (wouldBlock()) return;
			owner_->ioOnTcpConnClosed(s);
			return;
		}
	}

	// ---- UDP listener readloop pool ----
	// Unlike the TCP/relay workers these carry NO interrupt socket: nothing needs
	// to wake them out of band (the TCP/relay snapshots must be invalidated when
	// the socket set changes, whereas the UDP listener fd is fixed), so they just
	// re-poll every ControlSelectTimeoutMs and observe running_/udpWorkerRunning_.
	// That also keeps one more fd_set slot free for the listener poll.
	void udpRecvLoop(int workerId) {
		boostIoThreadPriority();
		while (running_ && udpWorkerRunning_[workerId]) {
			socket_t lfd = udpListener_;
			if (lfd == STICE_INVALID_SOCKET) {
				std::this_thread::sleep_for(std::chrono::milliseconds(ControlSelectTimeoutMs));
				continue;
			}
			fd_set rfds;
			FD_ZERO(&rfds);
			FD_SET(lfd, &rfds);
			timeval tv;
			tv.tv_sec = 0;
			tv.tv_usec = ControlSelectTimeoutMs * 1000;
			int n = ::select(static_cast<int>(lfd) + 1, &rfds, nullptr, nullptr, &tv);
			if (n < 0) {
				if (wouldBlock() || sticeSockerrno == STICE_SEINTR) continue;
				STICE_LOG_ERROR("stserver: udp reader%d select() failed: %d", workerId, sticeSockerrno);
				break;
			}
			if (n == 0 || !FD_ISSET(lfd, &rfds)) continue;
			unsigned char buf[BufferSize];
			int drained = 0;
			while (running_ && udpWorkerRunning_[workerId] && drained < MaxDrainPerCycle) {
				stice::net::AddrRecord src;
				int len = sticeRecvfrom(lfd, reinterpret_cast<char *>(buf), sizeof(buf), src);
				if (len <= 0) break;
				owner_->ioOnUdpData(buf, static_cast<std::size_t>(len), src);
				++drained;
			}
		}
	}

	// Helper: wrap platform recvfrom for UdpSocket-style sockets.
	static int sticeRecvfrom(socket_t s, char *buf, int len,
	                         stice::net::AddrRecord &from) {
		sockaddr_storage addr;
		socklen_t addrLen = sizeof(addr);
		int n = ::recvfrom(s, buf, len, 0,
		                   reinterpret_cast<sockaddr *>(&addr), &addrLen);
		if (n > 0) {
			std::memcpy(&from.addr, &addr, addrLen);
			from.len = addrLen;
			from.socktype = SOCK_DGRAM;
		}
		return n;
	}

private:
	IoBackendOwner *owner_ = nullptr;
	socket_t udpListener_ = STICE_INVALID_SOCKET;
	socket_t tcpListener_ = STICE_INVALID_SOCKET;
	int workerCount_ = 2;
	std::atomic<bool> running_{false};

	// Control plane (single thread: UDP listener + TCP accept + timer).
	std::thread controlThread_;

	// TCP worker pool. TcpWorker holds a std::mutex (non-movable), so we
	// store unique_ptr<TcpWorker> to allow vector reallocation.
	struct TcpWorker {
		std::thread thread;
		std::mutex mutex;
		std::map<socket_t, bool> conns;
		socket_t interruptSock = STICE_INVALID_SOCKET;
		sockaddr_storage interruptAddr{};
		socklen_t interruptAddrLen = 0;
	};
	std::vector<std::unique_ptr<TcpWorker>> tcpWorkers_;
	std::unique_ptr<std::atomic<bool>[]> tcpWorkerRunning_;
	std::mutex tcpAssignMutex_;
	std::map<socket_t, int> tcpAssignment_;
	std::atomic<int> nextWorker_{0};

	// Relay readloop pool (pion multi-readloop): relay sockets are distributed
	// round-robin across relayWorkers_; each worker select()s its own subset
	// and drains to wouldBlock, parallelizing the read side.
	struct RelayWorker {
		std::thread thread;
		std::mutex mutex;
		std::set<socket_t> sockets;
		socket_t interruptSock = STICE_INVALID_SOCKET;
		sockaddr_storage interruptAddr{};
		socklen_t interruptAddrLen = 0;
	};
	std::vector<std::unique_ptr<RelayWorker>> relayWorkers_;
	std::unique_ptr<std::atomic<bool>[]> relayWorkerRunning_;
	std::mutex relayAssignMutex_;
	std::map<socket_t, int> relayAssignment_;
	std::atomic<int> nextRelayWorker_{0};

	// UDP-listener readloop pool. The shared UDP listener is the single funnel
	// for every client's ChannelData; with one reader thread its receive buffer
	// overflows under multi-client load and datagrams are silently dropped
	// (measured ~14% loss at 100 concurrent clients). Concurrent recvfrom() on
	// one UDP socket is supported (the kernel hands each caller a distinct
	// datagram) and ioOnUdpData() is thread-safe (ChannelData forwards under the
	// per-allocation lock; control frames enqueue to the single business thread),
	// so the listener is fanned out across a small pool of readers. No interrupt
	// socket is needed - see udpRecvLoop().
	struct UdpWorker {
		std::thread thread;
	};
	std::vector<std::unique_ptr<UdpWorker>> udpWorkers_;
	std::unique_ptr<std::atomic<bool>[]> udpWorkerRunning_;
};

// Factory: creates the appropriate backend based on compile-time flag and
// platform.
//   STSERVER_IOCP + Windows  → IocpBackend   (D plan, IOCP)
//   STSERVER_IOCP + Linux    → EpollBackend  (D plan, epoll)
//   STSERVER_IOCP + other    → SelectBackend (fallback; no kqueue backend)
//   otherwise                → SelectBackend (B plan, select + thread pool)
#if defined(STSERVER_IOCP) && defined(_WIN32)
std::unique_ptr<IoBackend> createIocpBackend();
#elif defined(STSERVER_IOCP) && defined(__linux__)
std::unique_ptr<IoBackend> createEpollBackend();
#endif
std::unique_ptr<IoBackend> createIoBackend() {
#if defined(STSERVER_IOCP) && defined(_WIN32)
	return createIocpBackend();
#elif defined(STSERVER_IOCP) && defined(__linux__)
	return createEpollBackend();
#else
	return std::make_unique<SelectBackend>();
#endif
}

} // namespace stserver
