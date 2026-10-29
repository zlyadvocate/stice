// SPDX-License-Identifier: MPL-2.0
// stice TLS transport abstraction for TURN over TLS (RFC 8656 §4).
//
// The TLS stack is pluggable: exactly one of OpenSSL, GnuTLS or Mbed TLS is
// compiled in, selected at configure time with the same CMake variables
// libdatachannel uses (USE_GNUTLS / USE_MBEDTLS, see CMakeLists.txt). Every
// backend implements this one interface, so the ICE/TURN code above it does
// not know which library is underneath:
//
//   TlsSession s;
//   s.initClient(fd, params);      // or initServer(fd, params)
//   while (s.handshake() == TlsStatus::WantRead) poll(...);  // non-blocking
//   s.write(buf, len, n); s.read(buf, len, n);
//
// IMPORTANT non-blocking contract: the fd is expected to be non-blocking and
// EVERY call may return WantRead / WantWrite instead of transferring anything.
// Ok with n == 0 is a legal result meaning "nothing transferred, try again".
// Closed means the peer sent close_notify (or the stream ended), Failed is a
// hard error with a message available from errorString().

#ifndef STICE_NET_TLS_HPP
#define STICE_NET_TLS_HPP

#include "stice/net/platform.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace stice::net {

// Socket handles travel through GnuTLS (gnutls_transport_ptr_t) and Mbed TLS
// (the BIO context pointer) as an opaque user pointer. On Windows SOCKET is a
// pointer-sized UINT_PTR and on POSIX socket_t is a narrower int, so a
// pointer-sized slot always fits — assert that instead of casting blind, so a
// future platform where the handle is wider than a pointer fails to compile
// rather than silently addressing the wrong descriptor. (OpenSSL is the odd one
// out: its API takes an int, so tls_openssl.cpp range-checks at runtime.)
inline void *socketToUserPtr(socket_t fd) {
	static_assert(sizeof(void *) >= sizeof(socket_t), "socket handle does not fit in void *");
	return reinterpret_cast<void *>(static_cast<std::uintptr_t>(fd));
}

inline socket_t userPtrToSocket(void *p) {
	return static_cast<socket_t>(reinterpret_cast<std::uintptr_t>(p));
}

// "192.0.2.1" / "2001:db8::1": an IP literal has to be verified against the
// certificate's iPAddress SANs and must not be sent in SNI (RFC 6066 §3), while
// a DNS name needs hostname verification plus SNI. TURN servers are routinely
// configured by IP, so every backend has to make this distinction.
inline bool isIpLiteral(const std::string &s) {
	unsigned char buf[16];
	return ::inet_pton(AF_INET, s.c_str(), buf) == 1 ||
	       ::inet_pton(AF_INET6, s.c_str(), buf) == 1;
}

enum class TlsStatus {
	Ok,
	WantRead,
	WantWrite,
	Closed,
	Failed,
};

struct TlsParams {
	// Client: server name for SNI and (unless skipVerify) certificate
	// hostname verification.
	std::string sni;
	// Client: disable certificate verification entirely. Test/self-signed
	// only — a verifying handshake is the default.
	bool skipVerify = false;
	// Client: PEM bundle used instead of the platform trust store. When empty
	// the STICE_TLS_CA_FILE environment variable is consulted, then the
	// platform store (OpenSSL default paths / GnuTLS system trust). Mbed TLS
	// ships no trust store: without a bundle it cannot verify, and says so.
	//
	// Non-empty wins over STICE_TLS_CA_FILE, which is how a single agent can
	// keep allocations on several TURN servers that each use a different
	// private CA: stice_turn_server_t::ca_file lands here, per control
	// connection (and on the RFC 6062 data connection it inherits from).
	std::string caFile;
	// Server: PEM certificate chain and private key.
	std::string certFile;
	std::string keyFile;
};

class TlsSession {
public:
	TlsSession();
	~TlsSession();
	TlsSession(const TlsSession &) = delete;
	TlsSession &operator=(const TlsSession &) = delete;

	// Prepare a session on an already-connected, non-blocking socket. Returns
	// false on setup failure (missing certificate, unusable key, no backend).
	bool initClient(socket_t fd, const TlsParams &params);
	bool initServer(socket_t fd, const TlsParams &params);

	// Drive the handshake. Ok = established; WantRead/WantWrite = call again
	// when the socket is ready; anything else is a failure (Closed included).
	TlsStatus handshake();

	// Transfer application data. `n` is the number of bytes transferred.
	//
	// WantRead/WantWrite only mean "retry when the socket is ready"; they never
	// ask the caller to resume handshake() — no backend returns WantRead for a
	// post-handshake event. A TLS 1.2 peer-initiated renegotiation is refused by
	// the GnuTLS backend (Failed + errorString) rather than reported as
	// WantRead, which would make the caller re-arm POLLIN forever without
	// making progress.
	TlsStatus read(unsigned char *buf, std::size_t len, std::size_t &n);
	TlsStatus write(const unsigned char *buf, std::size_t len, std::size_t &n);

	// Send close_notify (best effort, non-blocking) and release the session.
	void shutdown();
	void close();

	bool active() const;

	// Human-readable detail for the last Failed status.
	const std::string &errorString() const;

	// Name of the backend compiled into this build: "openssl", "gnutls",
	// "mbedtls" or "none".
	static const char *backendName();
	// False when stice was built without any TLS backend (TURN/TLS then
	// degrades to plain TCP, as before).
	static bool available();

private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};

} // namespace stice::net

#endif
