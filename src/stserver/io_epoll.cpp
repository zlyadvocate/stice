// SPDX-License-Identifier: MPL-2.0
// Author: zlyadvocate
// Version: 0.10.0
// EpollBackend: D plan implementation on Linux — epoll-based async IO with
// a dynamic worker thread pool.
//
// Architecture (mirrors IocpBackend on Windows):
//   - Single epoll fd, all sockets registered with EPOLLIN | EPOLLET
//     (edge-triggered).
//   - N worker threads call epoll_wait() in a loop.
//   - UDP listener and relay sockets use recvfrom() (edge-triggered → must
//     drain until EWOULDBLOCK).
//   - TCP listener uses accept4() (non-blocking, drain all pending).
//   - TCP connections use recv() (edge-triggered → drain).
//   - Sockets with pending write data are additionally registered with
//     EPOLLOUT; a periodic retry thread also flushes every 50ms.
//
// Performance vs SelectBackend:
//   - O(1) event notification (no fd_set scanning)
//   - Kernel-level readiness (no user-space polling)
//   - Scales to thousands of sockets (epoll has no FD_SETSIZE limit)
//   - Trade-off: edge-triggered requires draining all data per event
//
// This file is compiled only when STSERVER_IOCP is defined AND on Linux.
// epoll is a Linux-specific API; on macOS/BSD a kqueue backend would be
// needed (not implemented — those platforms fall back to SelectBackend).

#if defined(__linux__)

#ifndef STICE_STATIC
#define STICE_STATIC
#endif

#include "stice/stserver/io_backend.hpp"

#include "stice/log.hpp"
#include "stice/net/addr.hpp"
#include "stice/net/platform.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h> // TCP_NODELAY
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace stserver {

using stice::net::wouldBlock;

namespace {
constexpr int EpollTimeoutMs = 50;         // epoll_wait timeout
constexpr int WriteRetryIntervalMs = 50;    // Pending write flush interval
// Per-socket recv buffer size. Overridable via STSERVER_IO_BUFFER_SIZE for
// memory-constrained targets (e.g. embedded Linux). Must be large enough for
// the largest expected STUN/TURN packet — 8192 covers ChannelData (4 + MTU)
// and STUN messages; default 65536 preserves backward compatibility.
#ifndef STSERVER_IO_BUFFER_SIZE
#define STSERVER_IO_BUFFER_SIZE 65536
#endif
constexpr int BufferSize = STSERVER_IO_BUFFER_SIZE;
constexpr int MaxEvents = 256;              // epoll_wait batch size

// epoll user-data encoding. We store the socket fd directly as uint64_t;
// the high bit distinguishes listener types so the worker knows how to
// dispatch without consulting a map under lock for the common path.
constexpr uint64_t kUdpListenerTag = 0x100000000ULL;
constexpr uint64_t kTcpListenerTag = 0x200000000ULL;

bool setNonBlocking(int s) {
	int fl = fcntl(s, F_GETFL, 0);
	return fcntl(s, F_SETFL, fl | O_NONBLOCK) == 0;
}

bool setCloseOnExec(int s) {
	int fl = fcntl(s, F_GETFD, 0);
	return fcntl(s, F_SETFD, fl | FD_CLOEXEC) == 0;
}
} // namespace

class EpollBackend : public IoBackend {
public:
	EpollBackend() = default;
	~EpollBackend() override { stop(); }

	bool init(IoBackendOwner *owner, socket_t udpListener, socket_t tcpListener) override {
		owner_ = owner;
		udpListener_ = udpListener;
		tcpListener_ = tcpListener;

		epollFd_ = ::epoll_create1(EPOLL_CLOEXEC);
		if (epollFd_ < 0) {
			STICE_LOG_ERROR("stserver: epoll_create1 failed: %d", errno);
			return false;
		}

		// Register UDP listener (edge-triggered).
		if (udpListener_ != STICE_INVALID_SOCKET) {
			epoll_event ev{};
			ev.events = EPOLLIN | EPOLLET;
			ev.data.u64 = kUdpListenerTag | static_cast<uint64_t>(udpListener_);
			if (::epoll_ctl(epollFd_, EPOLL_CTL_ADD, udpListener_, &ev) < 0) {
				STICE_LOG_ERROR("stserver: epoll_ctl ADD udpListener failed: %d", errno);
				return false;
			}
		}
		// Register TCP listener (edge-triggered → must accept-loop).
		if (tcpListener_ != STICE_INVALID_SOCKET) {
			epoll_event ev{};
			ev.events = EPOLLIN | EPOLLET;
			ev.data.u64 = kTcpListenerTag | static_cast<uint64_t>(tcpListener_);
			if (::epoll_ctl(epollFd_, EPOLL_CTL_ADD, tcpListener_, &ev) < 0) {
				STICE_LOG_ERROR("stserver: epoll_ctl ADD tcpListener failed: %d", errno);
				return false;
			}
		}
		return true;
	}

	void start() override {
		running_ = true;
		int n = std::max(1, workerCount_);

		workers_.reserve(n);
		for (int i = 0; i < n; ++i) {
			workers_.emplace_back([this] { workerLoop(); });
		}
		writeThread_ = std::thread([this] { writeRetryLoop(); });

		STICE_LOG_INFO("stserver: EpollBackend started, %d workers", n);
	}

	void stop() override {
		if (!running_.exchange(false)) return;
		for (auto &t : workers_) {
			if (t.joinable()) t.join();
		}
		workers_.clear();
		if (writeThread_.joinable()) writeThread_.join();
		if (epollFd_ >= 0) {
			::close(epollFd_);
			epollFd_ = -1;
		}
	}

	void addRelaySocket(socket_t s) override {
		if (s == STICE_INVALID_SOCKET) return;
		{
			std::lock_guard<std::mutex> lk(relayMutex_);
			relaySockets_.insert(s);
		}
		epoll_event ev{};
		ev.events = EPOLLIN | EPOLLET;
		ev.data.u64 = static_cast<uint64_t>(s); // no tag → relay/conn
		::epoll_ctl(epollFd_, EPOLL_CTL_ADD, s, &ev);
	}

	void removeRelaySocket(socket_t s) override {
		::epoll_ctl(epollFd_, EPOLL_CTL_DEL, s, nullptr);
		std::lock_guard<std::mutex> lk(relayMutex_);
		relaySockets_.erase(s);
	}

	void addTcpConn(socket_t s, bool hasWritePending) override {
		if (s == STICE_INVALID_SOCKET) return;
		uint32_t events = EPOLLIN | EPOLLET;
		if (hasWritePending) {
			events |= EPOLLOUT;
			std::lock_guard<std::mutex> lk(writePendingMutex_);
			writePending_.insert(s);
		}
		epoll_event ev{};
		ev.events = events;
		ev.data.u64 = static_cast<uint64_t>(s);
		::epoll_ctl(epollFd_, EPOLL_CTL_ADD, s, &ev);
	}

	void removeTcpConn(socket_t s) override {
		::epoll_ctl(epollFd_, EPOLL_CTL_DEL, s, nullptr);
		std::lock_guard<std::mutex> lk(writePendingMutex_);
		writePending_.erase(s);
	}

	void setTcpConnWritePending(socket_t s, bool pending) override {
		{
			std::lock_guard<std::mutex> lk(writePendingMutex_);
			if (pending) writePending_.insert(s);
			else writePending_.erase(s);
		}
		// Re-arm with EPOLLOUT if pending, otherwise just EPOLLIN.
		// With edge-triggered epoll, MOD re-arms the fd.
		uint32_t events = EPOLLIN | EPOLLET;
		if (pending) events |= EPOLLOUT;
		epoll_event ev{};
		ev.events = events;
		ev.data.u64 = static_cast<uint64_t>(s);
		::epoll_ctl(epollFd_, EPOLL_CTL_MOD, s, &ev);
	}

	void setWorkerCount(int n) override { workerCount_ = std::max(1, n); }

private:
	// Worker thread: process epoll events.
	void workerLoop() {
		std::vector<epoll_event> events(MaxEvents);
		while (running_) {
			int n = ::epoll_wait(epollFd_, events.data(), MaxEvents, EpollTimeoutMs);
			if (!running_) break;
			if (n < 0) {
				if (errno == EINTR) continue;
				STICE_LOG_ERROR("stserver: epoll_wait failed: %d", errno);
				break;
			}
			for (int i = 0; i < n; ++i) {
				if (!running_) break;
				const epoll_event &ev = events[i];
				uint64_t data = ev.data.u64;
				uint64_t tag = data & 0xF00000000ULL;
				socket_t sock = static_cast<socket_t>(data & 0xFFFFFFFF);

				if (tag == kUdpListenerTag) {
					// UDP listener readable.
					if (ev.events & EPOLLIN) drainUdpListener();
				} else if (tag == kTcpListenerTag) {
					// TCP listener: accept all pending.
					if (ev.events & EPOLLIN) drainAccept();
				} else {
					// Relay socket or TCP connection.
					if (ev.events & EPOLLIN) {
						if (!handleReadable(sock)) continue;
					}
					if (ev.events & EPOLLOUT) {
						owner_->ioOnTcpConnWritable(sock);
					}
					if (ev.events & (EPOLLHUP | EPOLLERR)) {
						owner_->ioOnTcpConnClosed(sock);
					}
				}
			}
		}
	}

	// Drain UDP listener: read all pending datagrams (edge-triggered).
	void drainUdpListener() {
		unsigned char buf[BufferSize];
		while (true) {
			sockaddr_storage addr;
			socklen_t addrLen = sizeof(addr);
			int n = ::recvfrom(udpListener_, reinterpret_cast<char *>(buf),
			                   sizeof(buf), 0,
			                   reinterpret_cast<sockaddr *>(&addr), &addrLen);
			if (n > 0) {
				stice::net::AddrRecord from;
				std::memcpy(&from.addr, &addr, addrLen);
				from.len = addrLen;
				from.socktype = SOCK_DGRAM;
				owner_->ioOnUdpData(buf, static_cast<std::size_t>(n), from);
				continue;
			}
			break; // EWOULDBLOCK or error
		}
	}

	// Drain TCP accept queue (edge-triggered).
	void drainAccept() {
		while (running_) {
			sockaddr_storage ss;
			socklen_t len = sizeof(ss);
#ifdef HAVE_ACCEPT4
			int s = ::accept4(tcpListener_, reinterpret_cast<sockaddr *>(&ss),
			                  &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
			int s = ::accept(tcpListener_, reinterpret_cast<sockaddr *>(&ss), &len);
#endif
			if (s == STICE_INVALID_SOCKET) break;
#ifndef HAVE_ACCEPT4
			setNonBlocking(s);
			setCloseOnExec(s);
#endif
			stice::net::addrUnmapInet6V4Mapped(reinterpret_cast<sockaddr *>(&ss), len);
			int one = 1;
			setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
			           reinterpret_cast<const char *>(&one), sizeof(one));

			stice::net::AddrRecord peer;
			std::memcpy(&peer.addr, &ss, len);
			peer.len = len;
			peer.socktype = SOCK_STREAM;

			owner_->ioOnTcpAccepted(s, peer);
		}
	}

	// Handle a readable event on a relay socket or TCP connection.
	// Returns true if the socket should continue to be processed (e.g. for
	// EPOLLOUT), false if it was closed.
	bool handleReadable(socket_t s) {
		// Check if it's a relay socket.
		bool isRelay = false;
		{
			std::lock_guard<std::mutex> lk(relayMutex_);
			isRelay = relaySockets_.count(s) > 0;
		}
		if (isRelay) {
			drainRelay(s);
			return true;
		}
		// TCP connection: drain recv.
		drainTcpConn(s);
		return true;
	}

	void drainRelay(socket_t s) {
		unsigned char buf[BufferSize];
		while (true) {
			sockaddr_storage addr;
			socklen_t addrLen = sizeof(addr);
			int n = ::recvfrom(s, reinterpret_cast<char *>(buf), sizeof(buf), 0,
			                   reinterpret_cast<sockaddr *>(&addr), &addrLen);
			if (n > 0) {
				stice::net::AddrRecord peer;
				std::memcpy(&peer.addr, &addr, addrLen);
				peer.len = addrLen;
				peer.socktype = SOCK_DGRAM;
				owner_->ioOnRelayData(s, buf, static_cast<std::size_t>(n), peer);
				continue;
			}
			if (n == 0) return;
			if (wouldBlock()) return;
			// Error on UDP relay socket — log but don't close (may be
			// transient, e.g. ICMP port unreachable from a previous peer).
			if (errno == ECONNREFUSED) return;
			return;
		}
	}

	void drainTcpConn(socket_t s) {
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

	// Write retry thread: periodically flush pending writes.
	void writeRetryLoop() {
		while (running_) {
			std::this_thread::sleep_for(
			    std::chrono::milliseconds(WriteRetryIntervalMs));
			if (!running_) break;
			std::vector<socket_t> pending;
			{
				std::lock_guard<std::mutex> lk(writePendingMutex_);
				pending.assign(writePending_.begin(), writePending_.end());
			}
			for (socket_t s : pending) {
				if (!running_) break;
				owner_->ioOnTcpConnWritable(s);
			}
		}
	}

private:
	IoBackendOwner *owner_ = nullptr;
	socket_t udpListener_ = STICE_INVALID_SOCKET;
	socket_t tcpListener_ = STICE_INVALID_SOCKET;
	int workerCount_ = 4;
	int epollFd_ = -1;
	std::atomic<bool> running_{false};

	std::vector<std::thread> workers_;
	std::thread writeThread_;

	// Relay socket tracking (to distinguish relay vs TCP conn on event).
	std::mutex relayMutex_;
	std::set<socket_t> relaySockets_;

	// Sockets with pending write data.
	std::mutex writePendingMutex_;
	std::set<socket_t> writePending_;
};

// Factory function for epoll backend (called by createIoBackend in io_select.cpp).
std::unique_ptr<IoBackend> createEpollBackend() {
	return std::make_unique<EpollBackend>();
}

} // namespace stserver

#endif // __linux__
