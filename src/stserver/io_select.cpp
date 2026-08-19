// SPDX-License-Identifier: MPL-2.0
// Author: zlyadvocate
// Version: 0.10.0
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
// Per-socket recv buffer size. Shared with the IOCP/epoll backends via the
// same STSERVER_IO_BUFFER_SIZE macro so all three backends behave identically
// when the option is set. Default 65536 preserves backward compatibility.
#ifndef STSERVER_IO_BUFFER_SIZE
#define STSERVER_IO_BUFFER_SIZE 65536
#endif
constexpr int BufferSize = STSERVER_IO_BUFFER_SIZE;
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
		// Start UDP control thread (handles UDP + TCP accept + relay + timer).
		controlThread_ = std::thread([this] { controlLoop(); });
		// Start TCP worker threads. TcpWorker holds a std::mutex (non-movable),
		// so we store unique_ptr<TcpWorker> in the vector.
		int n = std::max(1, workerCount_);
		tcpWorkerRunning_.resize(n, true);
		tcpWorkers_.reserve(n);
		for (int i = 0; i < n; ++i) {
			auto w = std::make_unique<TcpWorker>();
			w->thread = std::thread([this, i] { tcpWorkerLoop(i); });
			tcpWorkers_.push_back(std::move(w));
		}
		STICE_LOG_INFO("stserver: SelectBackend started, %d TCP workers", n);
	}

	void stop() override {
		if (!running_.exchange(false)) return;
		// Signal workers to stop.
		for (auto &r : tcpWorkerRunning_) r = false;
		// Join all threads.
		if (controlThread_.joinable()) controlThread_.join();
		for (auto &t : tcpWorkers_) {
			if (t->thread.joinable()) t->thread.join();
		}
		tcpWorkers_.clear();
		tcpWorkerRunning_.clear();
	}

	void addRelaySocket(socket_t s) override {
		if (s == STICE_INVALID_SOCKET) return;
		std::lock_guard<std::mutex> lk(controlMutex_);
		relaySockets_.insert(s);
	}

	void removeRelaySocket(socket_t s) override {
		std::lock_guard<std::mutex> lk(controlMutex_);
		relaySockets_.erase(s);
	}

	void addTcpConn(socket_t s, bool hasWritePending) override {
		if (s == STICE_INVALID_SOCKET) return;
		int worker = nextWorker_++ % std::max(1, (int)tcpWorkers_.size());
		{
			std::lock_guard<std::mutex> lk(tcpAssignMutex_);
			tcpAssignment_[s] = worker;
		}
		{
			auto &w = tcpWorkers_[worker];
			std::lock_guard<std::mutex> lk(w->mutex);
			w->conns[s] = hasWritePending;
		}
		STICE_LOG_INFO("stserver: addTcpConn sock=%llu worker=%d writePending=%d", (unsigned long long)s, worker, (int)hasWritePending);
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
			if (it != w->conns.end()) it->second = pending;
		}
	}

	void setWorkerCount(int n) override { workerCount_ = std::max(1, n); }

private:
	// ---- Control plane thread (UDP + TCP accept + relay + timer) ----
	void controlLoop() {
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

			setRead(udpListener_);
			setRead(tcpListener_);

			// Snapshot relay sockets.
			{
				std::lock_guard<std::mutex> lk(controlMutex_);
				for (socket_t s : relaySockets_) setRead(s);
			}

			timeval tv;
			tv.tv_sec = ControlSelectTimeoutMs / 1000;
			tv.tv_usec = (ControlSelectTimeoutMs % 1000) * 1000;
			int n = ::select(static_cast<int>(maxfd) + 1, &rfds, nullptr, nullptr, &tv);
			if (n < 0) {
				if (wouldBlock() || sticeSockerrno == STICE_SEINTR) continue;
				STICE_LOG_ERROR("stserver: control select() failed: %d", sticeSockerrno);
				break;
			}

			// UDP listener readable.
			if (udpListener_ != STICE_INVALID_SOCKET && FD_ISSET(udpListener_, &rfds)) {
				unsigned char buf[BufferSize];
				stice::net::AddrRecord src;
				int len = sticeRecvfrom(udpListener_, reinterpret_cast<char *>(buf),
				                        sizeof(buf), src);
				if (len > 0) {
					owner_->ioOnUdpData(buf, static_cast<std::size_t>(len), src);
				}
			}

			// TCP listener: accept new connections.
			if (tcpListener_ != STICE_INVALID_SOCKET && FD_ISSET(tcpListener_, &rfds)) {
				acceptTcp();
			}

			// Relay sockets readable.
			std::vector<socket_t> readyRelay;
			{
				std::lock_guard<std::mutex> lk(controlMutex_);
				for (socket_t s : relaySockets_) {
					if (FD_ISSET(s, &rfds)) readyRelay.push_back(s);
				}
			}
			for (socket_t s : readyRelay) {
				if (!running_) break;
				unsigned char buf[BufferSize];
				stice::net::AddrRecord peer;
				int len = sticeRecvfrom(s, reinterpret_cast<char *>(buf),
				                        sizeof(buf), peer);
				if (len > 0) {
					owner_->ioOnRelayData(s, buf, static_cast<std::size_t>(len), peer);
				}
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
			if (s == STICE_INVALID_SOCKET) break;
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
		auto &myData = tcpWorkers_[workerId];
		auto lastTick = std::chrono::steady_clock::now();
		while (tcpWorkerRunning_[workerId] && running_) {
			fd_set rfds, wfds;
			FD_ZERO(&rfds);
			FD_ZERO(&wfds);
			socket_t maxfd = STICE_INVALID_SOCKET;

			// Snapshot our conn set.
			std::vector<std::pair<socket_t, bool>> conns;
			{
				std::lock_guard<std::mutex> lk(myData->mutex);
				conns.reserve(myData->conns.size());
				for (auto &kv : myData->conns) conns.push_back({kv.first, kv.second});
			}
			if (!conns.empty()) {
				STICE_LOG_INFO("stserver: worker%d monitoring %zu conns", workerId, conns.size());
			}
			for (auto &kv : conns) {
				socket_t s = kv.first;
				if (s == STICE_INVALID_SOCKET) continue;
				FD_SET(s, &rfds);
				if (kv.second) FD_SET(s, &wfds); // write pending
				if (maxfd == STICE_INVALID_SOCKET || s > maxfd) maxfd = s;
			}

			if (maxfd == STICE_INVALID_SOCKET) {
				std::this_thread::sleep_for(
				    std::chrono::milliseconds(WorkerSelectTimeoutMs));
				continue;
			}

			timeval tv;
			tv.tv_sec = WorkerSelectTimeoutMs / 1000;
			tv.tv_usec = (WorkerSelectTimeoutMs % 1000) * 1000;
			int n = ::select(static_cast<int>(maxfd) + 1, &rfds, &wfds, nullptr, &tv);
			if (n < 0) {
				STICE_LOG_ERROR("stserver: worker%d select() failed: errno=%d", workerId, sticeSockerrno);
				if (wouldBlock() || sticeSockerrno == STICE_SEINTR) continue;
				break;
			}
			if (n > 0) {
				STICE_LOG_INFO("stserver: worker%d select returned %d (rfds=%d wfds=%d)", workerId, n, (int)rfds.fd_count, (int)wfds.fd_count);
			}

			// Process readable connections.
			for (auto &kv : conns) {
				if (!running_ || !tcpWorkerRunning_[workerId]) break;
				socket_t s = kv.first;
				if (s == STICE_INVALID_SOCKET) continue;
				if (FD_ISSET(s, &rfds)) {
					readTcpConn(s);
				}
			}
			// Process writable connections.
			for (auto &kv : conns) {
				if (!running_ || !tcpWorkerRunning_[workerId]) break;
				socket_t s = kv.first;
				if (s == STICE_INVALID_SOCKET) continue;
				if (FD_ISSET(s, &wfds)) {
					owner_->ioOnTcpConnWritable(s);
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

	// Control plane.
	std::thread controlThread_;
	std::mutex controlMutex_;
	std::set<socket_t> relaySockets_;

	// TCP worker pool. TcpWorker holds a std::mutex (non-movable), so we
	// store unique_ptr<TcpWorker> to allow vector reallocation.
	struct TcpWorker {
		std::thread thread;
		std::mutex mutex;
		std::map<socket_t, bool> conns;
	};
	std::vector<std::unique_ptr<TcpWorker>> tcpWorkers_;
	std::vector<bool> tcpWorkerRunning_;
	std::mutex tcpAssignMutex_;
	std::map<socket_t, int> tcpAssignment_;
	std::atomic<int> nextWorker_{0};
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
