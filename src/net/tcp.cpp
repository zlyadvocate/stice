/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "stice/net/tcp.hpp"

#include "stice/log.hpp"
#include "stice/net/tls.hpp"

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

namespace stice::net {

namespace {

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

TcpTransport::TcpTransport() = default;

TcpTransport::~TcpTransport() { close(); }

void TcpTransport::close() {
	if (txBytes_.load(std::memory_order_relaxed) || rxBytes_.load(std::memory_order_relaxed)) {
		STICE_LOG_INFO("TcpTransport: closed tls=%d tx=%llu rx=%llu",
		               useTls_ ? 1 : 0,
		               static_cast<unsigned long long>(txBytes_.load(std::memory_order_relaxed)),
		               static_cast<unsigned long long>(rxBytes_.load(std::memory_order_relaxed)));
	}
	if (tls_) {
		tls_->shutdown();
		tls_->close();
		tls_.reset();
	}
	tlsWantRead_ = tlsWantWrite_ = false;
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
		sendTlsPendingLen_ = 0;
		ctrlTlsPendingLen_ = 0;
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
                                bool skipVerify, const std::string &caFile) {
	close();
	useTls_ = useTls;
	skipVerify_ = skipVerify;
	sni_ = sni;
	caFile_ = caFile;
	peerAddr_ = dst;
	sock_ = ::socket(dst.addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (sock_ == STICE_INVALID_SOCKET) {
		STICE_LOG_WARN("TCP socket creation failed, errno=%d", sticeSockerrno);
		state_ = TcpState::Failed;
		return false;
	}
	setNonBlocking(sock_);
	applyTcpSocketOptions(sock_);
	disableSigPipe(sock_); // macOS/BSD: no per-send MSG_NOSIGNAL there

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
	disableSigPipe(sock_);
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
			if (!TlsSession::available()) {
				// Built without a TLS backend: degrade to plain TCP, exactly as
				// before TLS support existed, but say so.
				STICE_LOG_WARN("TLS requested but stice was built without a TLS backend; "
				               "using plain TCP");
				state_ = TcpState::Connected;
			} else {
				tls_.reset(new TlsSession());
				TlsParams params;
				params.sni = sni_;
				params.skipVerify = skipVerify_;
				// Per-server trust anchor; when empty the backend falls back to
				// STICE_TLS_CA_FILE and then to the platform store.
				params.caFile = caFile_;
				if (!tls_->initClient(sock_, params)) {
					STICE_LOG_WARN("TLS client setup failed (%s): %s",
					               TlsSession::backendName(), tls_->errorString().c_str());
					tls_.reset();
					state_ = TcpState::Failed;
					return 0;
				}
				state_ = TcpState::TlsHandshaking;
				return driveTlsHandshake();
			}
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
		std::size_t n = 0;
		const bool tlsActive = tls_ && tls_->active();
		if (tlsActive) {
			TlsStatus st = tls_->read(tmp, sizeof(tmp), n);
			if (st == TlsStatus::WantRead) {
				tlsWantRead_ = true;
				return POLLIN;
			}
			if (st == TlsStatus::WantWrite) {
				tlsWantWrite_ = true;
				return POLLIN | POLLOUT;
			}
			if (st == TlsStatus::Closed) {
				state_ = TcpState::Disconnected;
				return 0;
			}
			if (st == TlsStatus::Failed) {
				STICE_LOG_WARN("TLS read failed (%s): %s", TlsSession::backendName(),
				               tls_->errorString().c_str());
				state_ = TcpState::Failed;
				return 0;
			}
			if (n == 0) return POLLIN; // nothing transferred yet
			clearTlsWantHints();      // progress: stale hints would spin the poll loop
		} else {
			int r = static_cast<int>(::recv(sock_, reinterpret_cast<char *>(tmp), sizeof(tmp), 0));
			if (r > 0) {
				n = static_cast<std::size_t>(r);
			} else if (r == 0) {
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
		rxBytes_.fetch_add(n, std::memory_order_relaxed);
		// Keep draining until the transport reports would-block — for TLS as
		// well as for plain TCP.
		//
		// The TLS branch used to return here as soon as one record came back
		// (a record read always returns less than the 64 KiB buffer, so the
		// "short read" exit fired on *every* event). That capped the receive
		// path at one record (~16 KiB) per poll iteration, which kept the TCP
		// receive window small and left records queued in the kernel socket
		// buffer. Under a sustained 512 KiB/s ChannelData stream this made the
		// TURN server's per-connection send buffer back up, and coturn then
		// dropped relayed frames silently (measured: isolated 1-13 message tail
		// loss in TURN-over-TLS soaks that never occurred in the plaintext TCP
		// mode sharing the same relay hop and the same code path). Draining
		// fully per readable event keeps the window open.
		//
		// Termination: the loop exits when read() reports WantRead/WantWrite
		// (nothing left in the record layer or the socket), Closed/Failed, or
		// Ok with n == 0.
	}
}

short TcpTransport::driveTlsHandshake() {
	if (!tls_ || !tls_->active()) {
		state_ = TcpState::Failed;
		return 0;
	}
	switch (tls_->handshake()) {
	case TlsStatus::Ok:
		state_ = TcpState::Connected;
		tlsWantRead_ = tlsWantWrite_ = false;
		return flushSends();
	case TlsStatus::WantRead:
		tlsWantRead_ = true;
		tlsWantWrite_ = false;
		return POLLIN;
	case TlsStatus::WantWrite:
		tlsWantWrite_ = true;
		tlsWantRead_ = false;
		return POLLIN | POLLOUT;
	default:
		STICE_LOG_WARN("TLS handshake failed (%s): %s", TlsSession::backendName(),
		               tls_->errorString().c_str());
		state_ = TcpState::Failed;
		return 0;
	}
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
	auto drain = [this](std::vector<unsigned char> &q, std::size_t &off,
	                    std::size_t &tlsPendingLen) -> short {
		while (off < q.size()) {
			const unsigned char *p = q.data() + off;
			std::size_t avail = q.size() - off;
			std::size_t n = 0;
			if (tls_ && tls_->active()) {
				// A WantWrite/WantRead from SSL_write means the record layer has
				// already taken (part of) this buffer and MUST be resumed with the
				// same pointer AND the same length, otherwise OpenSSL reports
				// "bad write retry" and the connection dies. `avail` can grow in
				// between because senders keep appending to the queue, so the
				// length of the interrupted call is remembered per queue.
				std::size_t len = std::min<std::size_t>(avail, 16384);
				if (tlsPendingLen != 0) len = std::min(tlsPendingLen, avail);
				TlsStatus st = tls_->write(p, len, n);
				if (st == TlsStatus::WantRead) {
					tlsWantRead_ = true;
					tlsPendingLen = len;
					return POLLIN;
				}
				if (st == TlsStatus::WantWrite) {
					tlsWantWrite_ = true;
					tlsPendingLen = len;
					return POLLIN | POLLOUT;
				}
				// Contract (tls.hpp): "Ok with n == 0 is a legal result meaning
				// 'nothing transferred, try again'". Only a non-Ok status is a
				// failure — treating Ok+n==0 as fatal would tear down a healthy
				// connection if a backend (or a future library version, e.g. a
				// TLS 1.3 post-handshake situation) legitimately makes no
				// progress in one call. Mirrors the read path.
				if (st != TlsStatus::Ok) {
					STICE_LOG_WARN("TLS write failed (%s): %s", TlsSession::backendName(),
					               tls_->errorString().c_str());
					state_ = TcpState::Failed;
					return 0;
				}
				if (n == 0) break;        // nothing transferred; keep the rest queued
				clearTlsWantHints();      // progress: drop the stale hints
			} else {
				// 64 KiB chunks (fewer syscalls for bulk backlogs; RFC 4571
				// frames are reassembled by the receiver anyway).
				int r = static_cast<int>(::send(sock_, reinterpret_cast<const char *>(p),
				                                static_cast<socklen_t>(
				                                    std::min<std::size_t>(avail, 65536)),
				                                STICE_MSG_NOSIGNAL));
				if (r > 0) {
					n = static_cast<std::size_t>(r);
				} else if (wouldBlock()) {
					break;
				} else {
					state_ = TcpState::Failed;
					return 0;
				}
			}
			off += n;
			tlsPendingLen = 0; // progress: any interrupted write completed
			txBytes_.fetch_add(n, std::memory_order_relaxed);
		}
		if (off >= q.size()) {
			q.clear();
			off = 0;
			tlsPendingLen = 0;
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
	short r = drain(ctrlQueue_, ctrlOff_, ctrlTlsPendingLen_);
	if (r >= 0)
		return r; // ctrl blocked/failed — do not touch data queue yet
	r = drain(sendQueue_, sendOff_, sendTlsPendingLen_);
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
