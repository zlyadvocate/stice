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
	sendQueue_.clear();
	recvBuf_.clear();
	hasConnectDeadline_ = false;
}

bool TcpTransport::connectTimedOut() const {
	if (!hasConnectDeadline_) return false;
	if (state_ != TcpState::Connecting && state_ != TcpState::TlsHandshaking)
		return false;
	return std::chrono::steady_clock::now() >= connectDeadline_;
}

void TcpTransport::setConnectTimeoutMs(int timeoutMs) {
	if (timeoutMs <= 0) {
		hasConnectDeadline_ = false;
		return;
	}
	connectDeadline_ = std::chrono::steady_clock::now() +
	                   std::chrono::milliseconds(timeoutMs);
	hasConnectDeadline_ = true;
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
#ifdef _WIN32
	u_long nbio = 1;
	ioctlsocket(sock_, FIONBIO, &nbio);
#else
	int nbio = 1;
	ioctl(sock_, FIONBIO, &nbio);
#endif
	int on = 1;
	setsockopt(sock_, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&on), sizeof(on));

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
#ifdef _WIN32
	u_long nbio = 1;
	ioctlsocket(sock_, FIONBIO, &nbio);
#else
	int nbio = 1;
	ioctl(sock_, FIONBIO, &nbio);
#endif
	int on = 1;
	setsockopt(sock_, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&on), sizeof(on));
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
		unsigned char tmp[4096];
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
		recvBuf_.insert(recvBuf_.end(), tmp, tmp + n);
		// Keep looping until EWOULDBLOCK to drain the socket.
		if (n < static_cast<int>(sizeof(tmp))) return POLLIN;
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
	if (sendQueue_.empty()) return POLLIN;
	while (!sendQueue_.empty()) {
		int n;
		if (ssl_) {
#ifdef STICE_HAVE_OPENSSL
			clearSslError();
			n = SSL_write(static_cast<SSL *>(ssl_), sendQueue_.data(),
			              static_cast<int>(std::min<std::size_t>(sendQueue_.size(), 16384)));
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
			n = static_cast<int>(::send(sock_, reinterpret_cast<const char *>(sendQueue_.data()),
			                            static_cast<socklen_t>(std::min<std::size_t>(sendQueue_.size(), 16384)), 0));
			if (n > 0) {
				// ok
			} else if (wouldBlock()) {
				return POLLIN | POLLOUT;
			} else {
				state_ = TcpState::Failed;
				return 0;
			}
		}
		sendQueue_.erase(sendQueue_.begin(), sendQueue_.begin() + n);
	}
	return POLLIN;
}

bool TcpTransport::send(const char *data, std::size_t size) {
	if (state_ == TcpState::Failed || state_ == TcpState::Disconnected)
		return false;
	if (framing_ == FramingMode::RFC4571) {
		// RFC 4571: 2-byte big-endian length prefix.
		unsigned char hdr[2];
		hdr[0] = static_cast<unsigned char>(size >> 8);
		hdr[1] = static_cast<unsigned char>(size & 0xFF);
		sendQueue_.insert(sendQueue_.end(), hdr, hdr + 2);
	}
	sendQueue_.insert(sendQueue_.end(), reinterpret_cast<const unsigned char *>(data),
	                  reinterpret_cast<const unsigned char *>(data) + size);
	// Try an immediate flush.
	if (state_ == TcpState::Connected)
		flushSends();
	return true;
}

int TcpTransport::recv(char *out, std::size_t outSize, AddrRecord & /*peer*/) {
	if (framing_ == FramingMode::Raw) {
		// Raw mode: return whatever bytes are available (no framing).
		if (recvBuf_.empty()) return 0;
		std::size_t copyLen = std::min(recvBuf_.size(), outSize);
		std::memcpy(out, recvBuf_.data(), copyLen);
		recvBuf_.erase(recvBuf_.begin(), recvBuf_.begin() + copyLen);
		return static_cast<int>(copyLen);
	}
	// RFC 4571 mode: 2-byte length prefix + payload.
	if (recvBuf_.size() < 2)
		return 0; // need framing header
	uint16_t len = (uint16_t{recvBuf_[0]} << 8) | recvBuf_[1];
	if (len == 0) {
		// Skip zero-length frame.
		recvBuf_.erase(recvBuf_.begin(), recvBuf_.begin() + 2);
		return 0;
	}
	if (recvBuf_.size() < std::size_t(2) + len)
		return 0; // incomplete
	std::size_t copyLen = std::min<std::size_t>(len, outSize);
	std::memcpy(out, recvBuf_.data() + 2, copyLen);
	recvBuf_.erase(recvBuf_.begin(), recvBuf_.begin() + 2 + len);
	return static_cast<int>(copyLen);
}

} // namespace stice::net
