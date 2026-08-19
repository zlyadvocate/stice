// SPDX-License-Identifier: MPL-2.0
// Author: zlyadvocate
// Version: 0.10.0
// IocpBackend: D plan implementation — Windows IOCP (Input/Output Completion
// Port) based async IO with a dynamic worker thread pool.
//
// Architecture:
//   - Single IOCP handle, all sockets associated with it.
//   - N worker threads call GetQueuedCompletionStatus() in a loop.
//   - UDP listener and relay sockets use WSARecvFrom (overlapped) to get
//     both data and source address in one operation.
//   - TCP listener uses AcceptEx for overlapped accept.
//   - TCP connections use WSARecv (overlapped) for data.
//   - Sends use non-blocking send() with writeBuf; a periodic retry
//     thread flushes pending writes every 50ms (avoids overlapped WSASend
//     complexity while still getting O(1) recv notification from IOCP).
//
// Performance vs SelectBackend:
//   - O(1) event notification (no fd_set scanning)
//   - Kernel-level completion (no user-space polling)
//   - Scales to thousands of sockets without FD_SETSIZE limit
//   - Trade-off: slightly higher memory per socket (OVERLAPPED context)
//
// This file is compiled only when STSERVER_IOCP is defined AND on Windows.

#ifdef _WIN32

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
#include <mswsock.h>
#include <set>
#include <thread>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")

namespace stserver {

namespace {
constexpr int IocpTimeoutMs = 50;        // GetQueuedCompletionStatus timeout
constexpr int WriteRetryIntervalMs = 50;  // Pending write flush interval
// Per-socket recv buffer size. Overridable via STSERVER_IO_BUFFER_SIZE for
// memory-constrained targets (e.g. embedded Linux). Must be large enough for
// the largest expected STUN/TURN packet — 8192 covers ChannelData (4 + MTU)
// and STUN messages; default 65536 preserves backward compatibility.
#ifndef STSERVER_IO_BUFFER_SIZE
#define STSERVER_IO_BUFFER_SIZE 65536
#endif
constexpr int BufferSize = STSERVER_IO_BUFFER_SIZE;

// Operation type identifiers for OVERLAPPED contexts.
enum class OpType : int {
	RecvFrom,    // Overlapped WSARecvFrom on UDP listener / relay socket
	Recv,        // Overlapped WSARecv on TCP connection
	Accept,      // AcceptEx on TCP listener
};

// Extended OVERLAPPED structure carrying operation context.
struct OverlappedCtx {
	OVERLAPPED ol;
	OpType type;
	socket_t sock;
	WSABUF wbuf;
	char buf[BufferSize];
	// For RecvFrom: source address filled by WSARecvFrom.
	sockaddr_storage fromAddr;
	int fromLen;
	// For AcceptEx: the client socket and accept buffer.
	socket_t acceptSock;
	char acceptBuf[(sizeof(sockaddr_in) + 16) * 2];
};

// Load AcceptEx function pointer via WSAIoctl.
LPFN_ACCEPTEX g_acceptEx = nullptr;
LPFN_GETACCEPTEXSOCKADDRS g_getAcceptExSockaddrs = nullptr;

bool loadExtensions() {
	if (g_acceptEx) return true;
	socket_t tmp = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (tmp == INVALID_SOCKET) return false;
	DWORD dw;
	GUID guidAccept = WSAID_ACCEPTEX;
	GUID guidAddrs = WSAID_GETACCEPTEXSOCKADDRS;
	::WSAIoctl(tmp, SIO_GET_EXTENSION_FUNCTION_POINTER, &guidAccept,
	           sizeof(guidAccept), &g_acceptEx, sizeof(g_acceptEx), &dw, nullptr, nullptr);
	::WSAIoctl(tmp, SIO_GET_EXTENSION_FUNCTION_POINTER, &guidAddrs,
	           sizeof(guidAddrs), &g_getAcceptExSockaddrs, sizeof(g_getAcceptExSockaddrs),
	           &dw, nullptr, nullptr);
	::closesocket(tmp);
	return g_acceptEx != nullptr;
}

bool setNonBlocking(socket_t s) {
	u_long nb = 1;
	return ioctlsocket(s, FIONBIO, &nb) == 0;
}
} // namespace

class IocpBackend : public IoBackend {
public:
	IocpBackend() = default;
	~IocpBackend() override { stop(); }

	bool init(IoBackendOwner *owner, socket_t udpListener, socket_t tcpListener) override {
		owner_ = owner;
		udpListener_ = udpListener;
		tcpListener_ = tcpListener;

		if (!loadExtensions()) {
			STICE_LOG_ERROR("stserver: Failed to load AcceptEx");
			return false;
		}

		iocp_ = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
		if (!iocp_) {
			STICE_LOG_ERROR("stserver: CreateIoCompletionPort failed: %lu", GetLastError());
			return false;
		}

		// Associate listeners with IOCP.
		if (udpListener_ != INVALID_SOCKET) {
			::CreateIoCompletionPort(reinterpret_cast<HANDLE>(udpListener_), iocp_,
			                         static_cast<ULONG_PTR>(udpListener_), 0);
		}
		if (tcpListener_ != INVALID_SOCKET) {
			::CreateIoCompletionPort(reinterpret_cast<HANDLE>(tcpListener_), iocp_,
			                         static_cast<ULONG_PTR>(tcpListener_), 0);
		}
		return true;
	}

	void start() override {
		running_ = true;
		int n = std::max(1, workerCount_);

		// Post initial overlapped WSARecvFrom on UDP listener.
		if (udpListener_ != INVALID_SOCKET) {
			postRecvFrom(udpListener_);
		}
		// Post initial AcceptEx.
		if (tcpListener_ != INVALID_SOCKET) {
			postAccept();
		}

		// Start worker threads.
		workers_.reserve(n);
		for (int i = 0; i < n; ++i) {
			workers_.emplace_back([this] { workerLoop(); });
		}
		// Start write retry thread.
		writeThread_ = std::thread([this] { writeRetryLoop(); });

		STICE_LOG_INFO("stserver: IocpBackend started, %d workers", n);
	}

	void stop() override {
		if (!running_.exchange(false)) return;
		// Post a special completion packet to wake up all workers.
		for (int i = 0; i < (int)workers_.size(); ++i) {
			::PostQueuedCompletionStatus(iocp_, 0, 0, nullptr);
		}
		for (auto &t : workers_) {
			if (t.joinable()) t.join();
		}
		workers_.clear();
		if (writeThread_.joinable()) writeThread_.join();
		if (iocp_) {
			::CloseHandle(iocp_);
			iocp_ = nullptr;
		}
		// Clean up pending overlapped contexts.
		std::lock_guard<std::mutex> lk(ctxMutex_);
		for (auto &kv : ctxs_) {
			if (kv.second->acceptSock != INVALID_SOCKET) {
				::closesocket(kv.second->acceptSock);
			}
		}
		ctxs_.clear();
	}

	void addRelaySocket(socket_t s) override {
		if (s == INVALID_SOCKET) return;
		::CreateIoCompletionPort(reinterpret_cast<HANDLE>(s), iocp_,
		                         static_cast<ULONG_PTR>(s), 0);
		{
			std::lock_guard<std::mutex> lk(relayMutex_);
			relaySockets_.insert(s);
		}
		postRecvFrom(s);
	}

	void removeRelaySocket(socket_t s) override {
		// Mark the socket as removed first so completion handlers know not
		// to deliver data or re-post. We do NOT erase the context from ctxs_
		// here — the worker thread that picks up the final completion (or
		// the CancelIo completion) will safely extract and destroy it.
		// Erasing here would free the OverlappedCtx while an IOCP completion
		// packet for it may still be queued, causing a use-after-free in
		// the worker thread's CONTAINING_RECORD call.
		::CancelIo(reinterpret_cast<HANDLE>(s));
		std::lock_guard<std::mutex> lk(relayMutex_);
		relaySockets_.erase(s);
	}

	void addTcpConn(socket_t s, bool hasWritePending) override {
		if (s == INVALID_SOCKET) return;
		::CreateIoCompletionPort(reinterpret_cast<HANDLE>(s), iocp_,
		                         static_cast<ULONG_PTR>(s), 0);
		if (hasWritePending) {
			std::lock_guard<std::mutex> lk(writePendingMutex_);
			writePending_.insert(s);
		}
		postRecv(s);
	}

	void removeTcpConn(socket_t s) override {
		// Same pattern as removeRelaySocket: don't erase the context here.
		// The worker thread will safely handle the final completion and
		// clean up the context. Erasing here risks use-after-free if an
		// IOCP completion packet is already queued.
		::CancelIo(reinterpret_cast<HANDLE>(s));
		std::lock_guard<std::mutex> lk(writePendingMutex_);
		writePending_.erase(s);
	}

	void setTcpConnWritePending(socket_t s, bool pending) override {
		std::lock_guard<std::mutex> lk(writePendingMutex_);
		if (pending) {
			writePending_.insert(s);
		} else {
			writePending_.erase(s);
		}
	}

	void setWorkerCount(int n) override { workerCount_ = std::max(1, n); }

private:
	// Post an overlapped WSARecvFrom on a UDP socket (listener or relay).
	// This gives us both the data and the source address in one operation.
	// IMPORTANT: the context must be stored in ctxs_ BEFORE the WSARecvFrom
	// call, because the completion can fire (on another worker thread) before
	// WSARecvFrom returns. If the context isn't in the map yet, the completion
	// handler's linear search fails and the socket stops receiving.
	void postRecvFrom(socket_t s) {
		auto ctx = std::make_unique<OverlappedCtx>();
		std::memset(&ctx->ol, 0, sizeof(OVERLAPPED));
		ctx->type = OpType::RecvFrom;
		ctx->sock = s;
		ctx->wbuf.buf = ctx->buf;
		ctx->wbuf.len = BufferSize;
		ctx->fromLen = sizeof(ctx->fromAddr);
		ctx->acceptSock = INVALID_SOCKET;

		auto *raw = ctx.get();
		{
			std::lock_guard<std::mutex> lk(ctxMutex_);
			ctxs_[s] = std::move(ctx);
		}

		DWORD flags = 0;
		DWORD bytesRecv = 0;
		int rc = ::WSARecvFrom(s, &raw->wbuf, 1, &bytesRecv, &flags,
		                       reinterpret_cast<sockaddr *>(&raw->fromAddr),
		                       &raw->fromLen, &raw->ol, nullptr);
		if (rc == SOCKET_ERROR) {
			int err = WSAGetLastError();
			if (err != WSA_IO_PENDING) {
				STICE_LOG_ERROR("stserver: WSARecvFrom failed: %d", err);
				std::lock_guard<std::mutex> lk(ctxMutex_);
				ctxs_.erase(s);
				return;
			}
		}
	}

	// Post an overlapped WSARecv on a TCP connection socket.
	void postRecv(socket_t s) {
		auto ctx = std::make_unique<OverlappedCtx>();
		std::memset(&ctx->ol, 0, sizeof(OVERLAPPED));
		ctx->type = OpType::Recv;
		ctx->sock = s;
		ctx->wbuf.buf = ctx->buf;
		ctx->wbuf.len = BufferSize;
		ctx->acceptSock = INVALID_SOCKET;

		auto *raw = ctx.get();
		{
			std::lock_guard<std::mutex> lk(ctxMutex_);
			ctxs_[s] = std::move(ctx);
		}

		DWORD flags = 0;
		DWORD bytesRecv = 0;
		int rc = ::WSARecv(s, &raw->wbuf, 1, &bytesRecv, &flags, &raw->ol, nullptr);
		if (rc == SOCKET_ERROR) {
			int err = WSAGetLastError();
			if (err != WSA_IO_PENDING) {
				if (err == WSAECONNRESET || err == WSAECONNABORTED ||
				    err == WSAESHUTDOWN) {
					owner_->ioOnTcpConnClosed(s);
				}
				std::lock_guard<std::mutex> lk(ctxMutex_);
				ctxs_.erase(s);
				return;
			}
		}
	}

	// Post an overlapped AcceptEx on the TCP listener.
	void postAccept() {
		auto ctx = std::make_unique<OverlappedCtx>();
		std::memset(&ctx->ol, 0, sizeof(OVERLAPPED));
		ctx->type = OpType::Accept;
		ctx->sock = tcpListener_;
		ctx->acceptSock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (ctx->acceptSock == INVALID_SOCKET) return;

		socket_t key = static_cast<socket_t>(0x40000000 | acceptCounter_++);
		auto *raw = ctx.get();
		{
			std::lock_guard<std::mutex> lk(ctxMutex_);
			ctxs_[key] = std::move(ctx);
		}

		DWORD bytesRecv = 0;
		BOOL ok = g_acceptEx(tcpListener_, raw->acceptSock, raw->acceptBuf, 0,
		                     sizeof(sockaddr_in) + 16, sizeof(sockaddr_in) + 16,
		                     &bytesRecv, &raw->ol);
		if (!ok) {
			int err = WSAGetLastError();
			if (err != WSA_IO_PENDING) {
				::closesocket(raw->acceptSock);
				std::lock_guard<std::mutex> lk(ctxMutex_);
				ctxs_.erase(key);
				return;
			}
		}
	}

	// Worker thread: process IOCP completions.
	void workerLoop() {
		DWORD bytesTransfered = 0;
		ULONG_PTR completionKey = 0;
		OVERLAPPED *ol = nullptr;

		while (running_) {
			BOOL ok = ::GetQueuedCompletionStatus(iocp_, &bytesTransfered,
			                                      &completionKey, &ol, IocpTimeoutMs);
			if (!running_) break;

			if (!ok) {
				int err = GetLastError();
				if (ol == nullptr) {
					// Timeout or shutdown notification.
					continue;
				}
				// IO failed (connection reset, etc.).
				auto *ctx = CONTAINING_RECORD(ol, OverlappedCtx, ol);
				socket_t s = ctx->sock;
				OpType opType = ctx->type;

				if (opType == OpType::Accept) {
					// AcceptEx failed — clean up and re-post.
					if (ctx->acceptSock != INVALID_SOCKET) {
						::closesocket(ctx->acceptSock);
					}
					std::lock_guard<std::mutex> lk(ctxMutex_);
					for (auto it = ctxs_.begin(); it != ctxs_.end(); ++it) {
						if (it->second.get() == ctx) { ctxs_.erase(it); break; }
					}
					if (running_) postAccept();
					continue;
				}

				if (opType == OpType::Recv && s != udpListener_) {
					// TCP connection failed.
					owner_->ioOnTcpConnClosed(s);
					std::lock_guard<std::mutex> lk(ctxMutex_);
					for (auto it = ctxs_.begin(); it != ctxs_.end(); ++it) {
						if (it->second.get() == ctx) { ctxs_.erase(it); break; }
					}
				} else if (opType == OpType::RecvFrom) {
					// UDP recv failed — just clean up the context.
					// The socket may have been removed via removeRelaySocket.
					std::lock_guard<std::mutex> lk(ctxMutex_);
					for (auto it = ctxs_.begin(); it != ctxs_.end(); ++it) {
						if (it->second.get() == ctx) { ctxs_.erase(it); break; }
					}
				}
				continue;
			}

			auto *ctx = CONTAINING_RECORD(ol, OverlappedCtx, ol);
			OpType opType = ctx->type;
			socket_t sock = ctx->sock;

			if (opType == OpType::Accept) {
				handleAcceptCompletion(ctx);
			} else if (opType == OpType::RecvFrom) {
				handleRecvFromCompletion(ctx, bytesTransfered);
			} else {
				// OpType::Recv (TCP)
				handleRecvCompletion(ctx, bytesTransfered);
			}
		}
	}

	void handleAcceptCompletion(OverlappedCtx *ctx) {
		socket_t newSock = ctx->acceptSock;
		ctx->acceptSock = INVALID_SOCKET; // Ownership transferred.

		sockaddr *localAddr = nullptr;
		sockaddr *remoteAddr = nullptr;
		int localLen = 0, remoteLen = 0;
		g_getAcceptExSockaddrs(ctx->acceptBuf, 0,
		                       sizeof(sockaddr_in) + 16,
		                       sizeof(sockaddr_in) + 16,
		                       &localAddr, &localLen,
		                       &remoteAddr, &remoteLen);

		// Update accept context: SO_UPDATE_ACCEPT_CONTEXT.
		socket_t listenSock = tcpListener_;
		::setsockopt(newSock, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
		             reinterpret_cast<char *>(&listenSock), sizeof(listenSock));

		setNonBlocking(newSock);
		int one = 1;
		setsockopt(newSock, IPPROTO_TCP, TCP_NODELAY,
		           reinterpret_cast<char *>(&one), sizeof(one));

		stice::net::AddrRecord peer;
		std::memcpy(&peer.addr, remoteAddr, remoteLen);
		peer.len = remoteLen;
		peer.socktype = SOCK_STREAM;

		// Remove the accept context before notifying owner (which may
		// trigger addTcpConn, which creates a new context for the same sock).
		{
			std::lock_guard<std::mutex> lk(ctxMutex_);
			for (auto it = ctxs_.begin(); it != ctxs_.end(); ++it) {
				if (it->second.get() == ctx) { ctxs_.erase(it); break; }
			}
		}

		// Notify TurnServer.
		owner_->ioOnTcpAccepted(newSock, peer);

		// Post next AcceptEx.
		if (running_) postAccept();
	}

	void handleRecvFromCompletion(OverlappedCtx *ctx, DWORD bytesTransfered) {
		socket_t sock = ctx->sock;

		// Extract the context from ctxs_ BEFORE calling the owner callback.
		// The callback (ioOnRelayData) may trigger removeRelaySocket(), which
		// would erase the context from ctxs_ and free it while we still hold
		// a raw pointer. By extracting first, we own the unique_ptr and the
		// callback cannot free it from under us.
		std::unique_ptr<OverlappedCtx> ctxOwner;
		{
			std::lock_guard<std::mutex> lk(ctxMutex_);
			for (auto it = ctxs_.begin(); it != ctxs_.end(); ++it) {
				if (it->second.get() == ctx) {
					ctxOwner = std::move(it->second);
					ctxs_.erase(it);
					break;
				}
			}
		}

		// Build AddrRecord from the source address.
		stice::net::AddrRecord from;
		std::memcpy(&from.addr, &ctx->fromAddr, ctx->fromLen);
		from.len = ctx->fromLen;
		from.socktype = SOCK_DGRAM;

		// Determine if this is the UDP listener or a relay socket.
		bool isListener = (sock == udpListener_);
		bool isRelay = false;
		if (!isListener) {
			std::lock_guard<std::mutex> lk(relayMutex_);
			isRelay = relaySockets_.count(sock) > 0;
		}

		if (isListener) {
			owner_->ioOnUdpData(reinterpret_cast<unsigned char *>(ctx->buf),
			                    static_cast<std::size_t>(bytesTransfered), from);
		} else if (isRelay) {
			owner_->ioOnRelayData(sock,
			                      reinterpret_cast<unsigned char *>(ctx->buf),
			                      static_cast<std::size_t>(bytesTransfered), from);
		}

		// Re-post recv if the socket is still valid (not removed during callback).
		bool shouldRepost = running_ && ctxOwner != nullptr;
		bool stillRelay = false;
		if (shouldRepost && !isListener) {
			std::lock_guard<std::mutex> lk(relayMutex_);
			stillRelay = relaySockets_.count(sock) > 0;
		}
		// Release the old context (it will be freed when ctxOwner goes out
		// of scope). postRecvFrom creates a fresh context for the next recv.
		ctxOwner.reset();
		if (shouldRepost && (isListener || stillRelay)) {
			postRecvFrom(sock);
		}
	}

	void handleRecvCompletion(OverlappedCtx *ctx, DWORD bytesTransfered) {
		socket_t sock = ctx->sock;

		// Extract the context before calling callbacks (same pattern as
		// handleRecvFromCompletion: the callback may close the socket and
		// trigger removeTcpConn, which would free the context under us).
		std::unique_ptr<OverlappedCtx> ctxOwner;
		{
			std::lock_guard<std::mutex> lk(ctxMutex_);
			for (auto it = ctxs_.begin(); it != ctxs_.end(); ++it) {
				if (it->second.get() == ctx) {
					ctxOwner = std::move(it->second);
					ctxs_.erase(it);
					break;
				}
			}
		}

		if (bytesTransfered == 0) {
			// Connection closed (graceful).
			owner_->ioOnTcpConnClosed(sock);
			ctxOwner.reset();
			return;
		}

		// Deliver data.
		owner_->ioOnTcpConnData(sock,
		                        reinterpret_cast<unsigned char *>(ctx->buf),
		                        static_cast<std::size_t>(bytesTransfered));

		// Re-post recv if the connection is still valid.
		bool shouldRepost = running_ && ctxOwner != nullptr;
		ctxOwner.reset();
		if (shouldRepost) postRecv(sock);
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
	socket_t udpListener_ = INVALID_SOCKET;
	socket_t tcpListener_ = INVALID_SOCKET;
	int workerCount_ = 4;
	HANDLE iocp_ = nullptr;
	std::atomic<bool> running_{false};

	std::vector<std::thread> workers_;
	std::thread writeThread_;

	// Overlapped contexts: key = socket (for recv) or synthetic key (for accept).
	std::mutex ctxMutex_;
	std::map<socket_t, std::unique_ptr<OverlappedCtx>> ctxs_;
	std::atomic<int> acceptCounter_{0};

	// Relay socket tracking (to distinguish relay vs TCP conn on completion).
	std::mutex relayMutex_;
	std::set<socket_t> relaySockets_;

	// Sockets with pending write data.
	std::mutex writePendingMutex_;
	std::set<socket_t> writePending_;
};

// Factory function for IOCP backend (called by createIoBackend in io_select.cpp).
std::unique_ptr<IoBackend> createIocpBackend() {
	return std::make_unique<IocpBackend>();
}

} // namespace stserver

#endif // _WIN32
