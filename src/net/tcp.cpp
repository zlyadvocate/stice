/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "stice/net/tcp.hpp"

#include "stice/log.hpp"

#include <algorithm>
#include <cstring>
#include <cstddef>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#ifdef STICE_HAVE_OPENSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

namespace stice::net {

namespace {
#ifdef STICE_HAVE_OPENSSL
void clearSslError() { ERR_clear_error(); }
#endif

// Socket options shared by every TCP transport: outgoing connects
// (beginConnect) and accepted sockets (attach). Kept in one place so the two
// paths cannot drift apart.
void applyTcpSocketOptions(socket_t s) {
	int on = 1;
	setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&on), sizeof(on));
	// 512 KiB socket buffers. The OS default (64 KiB on Windows) is too small
	// for relayed bulk transfers: a burst larger than the send buffer forces
	// the kernel queue to overflow, dropping segments and triggering
	// exponential RTO backoff across the multi-hop relay path (measured:
	// 11 Mbps with 10 s stalls vs 344 Mbps with the buffer raised).
	int tcpBuf = 512 * 1024;
	setsockopt(s, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char *>(&tcpBuf), sizeof(tcpBuf));
	setsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char *>(&tcpBuf), sizeof(tcpBuf));
	// Keepalive: a relayed TCP connection can sit idle for a long time (TURN
	// control between refreshes, RFC 6062 data pipes between bursts) and be
	// silently reaped by a NAT/middlebox, which then surfaces as a one-way
	// stall with no local error. SO_KEEPALIVE probes the peer so the failure is
	// reported here instead. Linux gets a tightened probe schedule; Windows has
	// no per-socket tuning before Win10 1709 and ICE/TURN keepalives already run
	// above this layer there.
	setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char *>(&on), sizeof(on));
#ifdef __linux__
	int keepIdle = 30;  // first probe after 30 s idle
	int keepIntvl = 10; // then every 10 s
	int keepCnt = 3;    // give up after 3 unanswered probes
	setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, reinterpret_cast<const char *>(&keepIdle), sizeof(keepIdle));
	setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, reinterpret_cast<const char *>(&keepIntvl), sizeof(keepIntvl));
	setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, reinterpret_cast<const char *>(&keepCnt), sizeof(keepCnt));
#endif
	// SO_LINGER{1,0} (RST on close, skipping TIME_WAIT) was tried here and
	// REVERTED: it aborts the connection while the peer may still have unread
	// data, which manifested as "TURN transport failure (state=2)" on every peer
	// at teardown and corrupted the byte accounting of a TURN-over-TCP soak
	// (rx_total > sent_total). A graceful FIN (the default) is required for
	// byte-exact zero-loss runs, and per-allocation connection churn is far too
	// low for TIME_WAIT to matter here.
}
} // namespace

TcpTransport::~TcpTransport() { close(); }

void TcpTransport::close() {
#ifdef STICE_HAVE_OPENSSL
	if (ssl_) {
		SSL_shutdown(static_cast<SSL *>(ssl_));
		SSL_free(static_cast<SSL *>(ssl_));
		ssl_ = nullptr;
	}
	if (sslCtx_) {
		SSL_CTX_free(static_cast<SSL_CTX *>(sslCtx_));
		sslCtx_ = nullptr;
	}
#endif
	if (sock_ != STICE_INVALID_SOCKET) {
		sticeClosesocket(sock_);
		sock_ = STICE_INVALID_SOCKET;
	}
	state_ = TcpState::Disconnected;
	{
		std::lock_guard<std::mutex> lk(sendMtx_);
		sendQueue_.clear();
		sendOff_ = 0;
		ctrlQueue_.clear();
		ctrlOff_ = 0;
	}
	{
		std::lock_guard<std::mutex> lk(recvMtx_);
		recvBuf_.clear();
		recvOff_ = 0;
	}
	connectDeadlineMs_.store(-1, std::memory_order_release);
}

bool TcpTransport::connectTimedOut() const {
	int64_t dl = connectDeadlineMs_.load(std::memory_order_acquire);
	if (dl <= 0) return false;
	if (state_ != TcpState::Connecting && state_ != TcpState::TlsHandshaking)
		return false;
	int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
	                    std::chrono::steady_clock::now().time_since_epoch())
	                    .count();
	return nowMs >= dl;
}

void TcpTransport::setConnectTimeoutMs(int timeoutMs) {
	if (timeoutMs <= 0) {
		connectDeadlineMs_.store(-1, std::memory_order_release);
		return;
	}
	int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
	                    std::chrono::steady_clock::now().time_since_epoch())
	                    .count();
	connectDeadlineMs_.store(nowMs + timeoutMs, std::memory_order_release);
}

bool TcpTransport::beginConnect(const AddrRecord &dst, const std::string &sni, bool useTls,
                                bool skipVerify) {
	close();
	useTls_ = useTls;
	skipVerify_ = skipVerify;
	sni_ = sni;
	peerAddr_ = dst;
	sock_ = ::socket(dst.addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (sock_ == STICE_INVALID_SOCKET) {
		STICE_LOG_WARN("TCP socket creation failed, errno=%d", sticeSockerrno);
		state_ = TcpState::Failed;
		return false;
	}
	setNonBlocking(sock_);
	applyTcpSocketOptions(sock_);

	int r = ::connect(sock_, reinterpret_cast<const struct sockaddr *>(&dst.addr), dst.len);
	if (r == 0) {
		// Immediate connect (rare). If TLS, start handshake; else connected.
		if (useTls_) {
			state_ = TcpState::Connecting; // will transition to handshake in onWritable
		} else {
			state_ = TcpState::Connected;
		}
		return true;
	}
	if (sticeSockerrno == STICE_SEINPROGRESS || sticeSockerrno == STICE_SEWOULDBLOCK) {
		state_ = TcpState::Connecting;
		return true;
	}
	STICE_LOG_WARN("TCP connect failed, errno=%d", sticeSockerrno);
	state_ = TcpState::Failed;
	sticeClosesocket(sock_);
	sock_ = STICE_INVALID_SOCKET;
	return false;
}

bool TcpTransport::attach(socket_t fd, const AddrRecord &peerAddr) {
	close();
	sock_ = fd;
	peerAddr_ = peerAddr;
	// Ensure non-blocking + TCP_NODELAY (caller should have done this, but
	// be defensive — accept()ed sockets inherit the listener's flags on
	// some platforms).
	setNonBlocking(sock_);
	// Accepted sockets inherit the listener's options on some platforms, so
	// apply the full set here too (beginConnect does the same for outbound).
	applyTcpSocketOptions(sock_);
	state_ = TcpState::Connected;
	useTls_ = false;
	STICE_LOG_DEBUG("TCP transport attached to accepted fd (peer=%s)",
	                peerAddr.toString().c_str());
	return true;
}

short TcpTransport::onWritable() {
	if (state_ == TcpState::Connecting) {
		// Check connect completion.
		int err = 0;
		socklen_t len = sizeof(err);
		if (getsockopt(sock_, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&err), &len) != 0 || err != 0) {
			if (err == 0) err = sticeSockerrno;
			if (err == STICE_SEINPROGRESS || err == STICE_SEWOULDBLOCK)
				return POLLOUT;
			STICE_LOG_WARN("TCP connect failed (SO_ERROR=%d)", err);
			state_ = TcpState::Failed;
			return 0;
		}
		// Connected.
		if (useTls_) {
#ifdef STICE_HAVE_OPENSSL
			sslCtx_ = SSL_CTX_new(TLS_client_method());
			if (!sslCtx_) { state_ = TcpState::Failed; return 0; }
			SSL_CTX_set_default_verify_paths(static_cast<SSL_CTX *>(sslCtx_));
			if (!skipVerify_) {
				// Verify the server certificate against the system trust
				// store (pion's default behavior). skipVerify_ is set only
				// for testing with self-signed certificates.
				SSL_CTX_set_verify(static_cast<SSL_CTX *>(sslCtx_),
				                   SSL_VERIFY_PEER, nullptr);
			}
			ssl_ = SSL_new(static_cast<SSL_CTX *>(sslCtx_));
			if (!ssl_) { state_ = TcpState::Failed; return 0; }
			SSL_set_tlsext_host_name(static_cast<SSL *>(ssl_), sni_.c_str());
			// Enable hostname verification (RFC 6125) unless skipped.
			if (!skipVerify_ && !sni_.empty()) {
				X509_VERIFY_PARAM *param = SSL_get0_param(static_cast<SSL *>(ssl_));
				X509_VERIFY_PARAM_set1_host(param, sni_.c_str(), sni_.size());
			}
			SSL_set_fd(static_cast<SSL *>(ssl_), static_cast<int>(sock_));
			state_ = TcpState::TlsHandshaking;
			return driveTlsHandshake();
#else
			STICE_LOG_WARN("TLS requested but stice built without OpenSSL; using plain TCP");
			state_ = TcpState::Connected;
#endif
		}
		state_ = TcpState::Connected;
	}
	if (state_ == TcpState::TlsHandshaking)
		return driveTlsHandshake();
	return flushSends();
}

short TcpTransport::onReadable() {
	if (state_ == TcpState::TlsHandshaking)
		return driveTlsHandshake();
	if (state_ != TcpState::Connected)
		return POLLIN;

	while (true) {
		// 64 KiB chunks: bulk transfers move ~16x fewer bytes per wakeup
		// than the old 4 KiB buffer, and each extra poll-loop iteration
		// costs a full bookkeeping pass over all participants.
		unsigned char tmp[65536];
		int n;
		if (ssl_) {
#ifdef STICE_HAVE_OPENSSL
			clearSslError();
			n = SSL_read(static_cast<SSL *>(ssl_), tmp, sizeof(tmp));
			if (n <= 0) {
				int e = SSL_get_error(static_cast<SSL *>(ssl_), n);
				if (e == SSL_ERROR_WANT_READ) { tlsWantRead_ = true; return POLLIN; }
				if (e == SSL_ERROR_WANT_WRITE) { tlsWantWrite_ = true; return POLLIN | POLLOUT; }
				state_ = TcpState::Failed;
				return 0;
			}
#else
			n = 0;
#endif
		} else {
			n = static_cast<int>(::recv(sock_, reinterpret_cast<char *>(tmp), sizeof(tmp), 0));
			if (n > 0) {
				// ok
			} else if (n == 0) {
				state_ = TcpState::Disconnected;
				return 0;
			} else if (wouldBlock()) {
				return POLLIN;
			} else {
				state_ = TcpState::Failed;
				return 0;
			}
		}
		{
			std::lock_guard<std::mutex> lk(recvMtx_);
			// Compact the consumed prefix if it has grown large, so recvBuf_
			// memory stays bounded without a per-frame front erase.
			if (recvOff_ > 0 && (recvOff_ >= 1048576 || recvOff_ >= recvBuf_.size())) {
				recvBuf_.erase(recvBuf_.begin(), recvBuf_.begin() + recvOff_);
				recvOff_ = 0;
			}
			recvBuf_.insert(recvBuf_.end(), tmp, tmp + n);
		}
		// Plain TCP: keep draining until EWOULDBLOCK. Returning early on a
		// short read used to leave data in the kernel buffer, forcing one
		// poll iteration (with full bookkeeping) per ~4 KiB. TLS keeps the
		// short-read exit (SSL_read returning less than requested may
		// still have buffered records pending).
		if (ssl_ && n < static_cast<int>(sizeof(tmp))) return POLLIN;
	}
}

short TcpTransport::driveTlsHandshake() {
#ifdef STICE_HAVE_OPENSSL
	clearSslError();
	int r = SSL_connect(static_cast<SSL *>(ssl_));
	if (r == 1) {
		// Handshake complete. Verify the peer certificate unless we were
		// explicitly told to skip verification.
		if (!skipVerify_) {
			long verifyResult = SSL_get_verify_result(static_cast<SSL *>(ssl_));
			if (verifyResult != X509_V_OK) {
				STICE_LOG_WARN("TLS certificate verification failed: %s",
				               X509_verify_cert_error_string(verifyResult));
				state_ = TcpState::Failed;
				return 0;
			}
		}
		state_ = TcpState::Connected;
		tlsWantRead_ = tlsWantWrite_ = false;
		return flushSends();
	}
	int e = SSL_get_error(static_cast<SSL *>(ssl_), r);
	if (e == SSL_ERROR_WANT_READ) { tlsWantRead_ = true; tlsWantWrite_ = false; return POLLIN; }
	if (e == SSL_ERROR_WANT_WRITE) { tlsWantWrite_ = true; tlsWantRead_ = false; return POLLIN | POLLOUT; }
	state_ = TcpState::Failed;
	return 0;
#else
	state_ = TcpState::Failed;
	return 0;
#endif
}

short TcpTransport::flushSends() {
	std::lock_guard<std::mutex> lk(sendMtx_);
	// Two queues: ctrlQueue_ (STUN/TURN signalling) is always drained before
	// sendQueue_ (bulk application data). A saturated data stream can then
	// never starve keepalives — head-of-line blocking of Refresh/
	// ConnectionBind made coturn drop allocations and data connections under
	// 100 MiB/round floods (observed: 9s Binding RTT, "connection lost
	// state=4").
	//
	// drain() return contract:
	//   -1          queue fully drained — caller may proceed to the next one
	//   POLLIN|...  blocked with backlog left / TLS wants an event
	//   0           transport failed (state_ = Failed)
	auto drain = [this](std::vector<unsigned char> &q, std::size_t &off) -> short {
		while (off < q.size()) {
			const unsigned char *p = q.data() + off;
			std::size_t avail = q.size() - off;
			int n;
			if (ssl_) {
#ifdef STICE_HAVE_OPENSSL
				clearSslError();
				n = SSL_write(static_cast<SSL *>(ssl_), p,
				              static_cast<int>(std::min<std::size_t>(avail, 16384)));
				if (n <= 0) {
					int e = SSL_get_error(static_cast<SSL *>(ssl_), n);
					if (e == SSL_ERROR_WANT_READ) { tlsWantRead_ = true; return POLLIN; }
					if (e == SSL_ERROR_WANT_WRITE) { tlsWantWrite_ = true; return POLLIN | POLLOUT; }
					state_ = TcpState::Failed;
					return 0;
				}
#else
				n = 0;
#endif
			} else {
				// 64 KiB chunks (fewer syscalls for bulk backlogs; RFC 4571
				// frames are reassembled by the receiver anyway).
				n = static_cast<int>(::send(sock_, reinterpret_cast<const char *>(p),
				                            static_cast<socklen_t>(std::min<std::size_t>(avail, 65536)), 0));
				if (n > 0) {
					// ok
				} else if (wouldBlock()) {
					break;
				} else {
					state_ = TcpState::Failed;
					return 0;
				}
			}
			off += static_cast<std::size_t>(n);
		}
		if (off >= q.size()) {
			q.clear();
			off = 0;
			return -1; // fully drained
		}
		// Amortized consumption: only compact the consumed prefix when it is
		// large. Erasing the front on every 16 KiB chunk made flushSends O(queue)
		// per chunk — with a multi-MB backlog under a stalled peer that memmoved
		// the entire queue per chunk (measured: 100 MiB bulk send over ICE-TCP
		// degraded to 5 MB/s on a 2-core box solely from these erases).
		if (off >= 1048576) {
			q.erase(q.begin(), q.begin() + off);
			off = 0;
		}
		return POLLIN | POLLOUT; // blocked with backlog: keep POLLOUT armed
	};
	short r = drain(ctrlQueue_, ctrlOff_);
	if (r >= 0)
		return r; // ctrl blocked/failed — do not touch data queue yet
	r = drain(sendQueue_, sendOff_);
	if (r >= 0)
		return r; // data blocked (POLLOUT stays armed) or transport failed
	return POLLIN; // both queues drained
}

bool TcpTransport::send(const char *data, std::size_t size) {
	if (state_ == TcpState::Failed || state_ == TcpState::Disconnected)
		return false;
	{
		std::lock_guard<std::mutex> lk(sendMtx_);
		// D2: bound the write queue. If the peer is stalled (TCP flow control
		// never drains), the queue would otherwise grow without bound and the
		// caller would never observe backpressure. Rejecting the write (false)
		// propagates EAGAIN-like backpressure up to sendRaw/stice_send, aligning
		// TCP with the UDP path's negative-errno semantics.
		const std::size_t kSendQueueHighWater = 16 * 1024 * 1024; // 16 MiB
		if (sendQueue_.size() > kSendQueueHighWater) {
			STICE_LOG_WARN("TcpTransport: send queue at high watermark (%zu), rejecting write",
			               sendQueue_.size());
			return false;
		}
		if (framing_ == FramingMode::RFC4571) {
			// RFC 4571: 2-byte big-endian length prefix.
			unsigned char hdr[2];
			hdr[0] = static_cast<unsigned char>(size >> 8);
			hdr[1] = static_cast<unsigned char>(size & 0xFF);
			sendQueue_.insert(sendQueue_.end(), hdr, hdr + 2);
		}
		sendQueue_.insert(sendQueue_.end(), reinterpret_cast<const unsigned char *>(data),
		                  reinterpret_cast<const unsigned char *>(data) + size);
	}
	// Try an immediate flush (takes sendMtx_ itself).
	if (state_ == TcpState::Connected)
		flushSends();
	return true;
}

bool TcpTransport::sendControl(const char *data, std::size_t size) {
	if (state_ == TcpState::Failed || state_ == TcpState::Disconnected)
		return false;
	{
		std::lock_guard<std::mutex> lk(sendMtx_);
		// Control frames ignore the high watermark: they are small
		// (tens/hundreds of bytes) and protocol-critical. Starving Refresh or
		// ConnectionBind is exactly what previously let coturn drop the
		// allocation under bulk-data load.
		if (framing_ == FramingMode::RFC4571) {
			unsigned char hdr[2];
			hdr[0] = static_cast<unsigned char>(size >> 8);
			hdr[1] = static_cast<unsigned char>(size & 0xFF);
			ctrlQueue_.insert(ctrlQueue_.end(), hdr, hdr + 2);
		}
		ctrlQueue_.insert(ctrlQueue_.end(), reinterpret_cast<const unsigned char *>(data),
		                  reinterpret_cast<const unsigned char *>(data) + size);
	}
	if (state_ == TcpState::Connected)
		flushSends();
	return true;
}

int TcpTransport::recv(char *out, std::size_t outSize, AddrRecord & /*peer*/) {
	std::lock_guard<std::mutex> lk(recvMtx_);
	// Helper: consume `bytes` from the front (tracked by recvOff_) and
	// compact lazily. Avoids a front erase per frame: with ~87k small frames
	// per 100 MiB each erase memmoved the (up to 64 KiB) remainder.
	auto consume = [this](std::size_t bytes) {
		recvOff_ += bytes;
		if (recvOff_ >= recvBuf_.size()) {
			recvBuf_.clear();
			recvOff_ = 0;
		} else if (recvOff_ >= 1048576) {
			recvBuf_.erase(recvBuf_.begin(), recvBuf_.begin() + recvOff_);
			recvOff_ = 0;
		}
	};
	if (framing_ == FramingMode::Raw) {
		// Raw mode: return whatever bytes are available (no framing).
		std::size_t avail = recvBuf_.size() - recvOff_;
		if (avail == 0) return 0;
		std::size_t copyLen = std::min(avail, outSize);
		std::memcpy(out, recvBuf_.data() + recvOff_, copyLen);
		consume(copyLen);
		return static_cast<int>(copyLen);
	}
	// RFC 4571 mode: 2-byte length prefix + payload.
	std::size_t avail = recvBuf_.size() - recvOff_;
	if (avail < 2)
		return 0; // need framing header
	const unsigned char *h = recvBuf_.data() + recvOff_;
	uint16_t len = (uint16_t{h[0]} << 8) | h[1];
	if (len == 0) {
		// Skip zero-length frame.
		consume(2);
		return 0;
	}
	if (avail < std::size_t(2) + len)
		return 0; // incomplete
	std::size_t copyLen = std::min<std::size_t>(len, outSize);
	std::memcpy(out, h + 2, copyLen);
	consume(2 + len);
	return static_cast<int>(copyLen);
}

} // namespace stice::net
