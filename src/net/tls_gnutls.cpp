// SPDX-License-Identifier: MPL-2.0
// TLS backend: GnuTLS. Selected with STICE_TLS_GNUTLS (CMake USE_GNUTLS).
//
// Behavior mirrors the OpenSSL backend so TURN-over-TLS behaves identically
// whichever crypto library the host project (libdatachannel) already uses:
//   * TLS 1.2 is the floor,
//   * the server certificate is verified against the system trust store by
//     default, with SNI/hostname verification when an SNI name is known,
//   * skip_tls_verify disables verification (test rigs with self-signed certs),
//   * STICE_TLS_CA_FILE overrides the trust store with an explicit PEM bundle.
//
// Non-blocking: the socket is driven through custom pull/push callbacks that
// report "would block" as EAGAIN, which is what GnuTLS turns into
// GNUTLS_E_AGAIN + gnutls_record_get_direction().

#include "stice/net/tls.hpp"

#include "stice/log.hpp"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h> // gnutls_x509_crt_check_ip (IP-addressed peers)

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>

namespace stice::net {

namespace {

void ensureGnutlsInit() {
	static std::once_flag once;
	std::call_once(once, [] {
		int r = gnutls_global_init();
		if (r < 0) STICE_LOG_WARN("gnutls_global_init failed: %s", gnutls_strerror(r));
	});
}

// Windows sockets report WSAEWOULDBLOCK, but GnuTLS decides "retry later" from
// errno. MSVC's errno is thread-local and independent of Winsock, so the
// would-block condition has to be published explicitly.
void publishErrno(bool blocked) {
#ifdef _WIN32
	errno = blocked ? EAGAIN : ECONNRESET;
#else
	(void)blocked; // POSIX recv/send already set errno
#endif
}

ssize_t tlsPull(gnutls_transport_ptr_t ptr, void *buf, size_t len) {
	socket_t fd = userPtrToSocket(ptr);
	int cap = len > 0x40000000u ? 0x40000000 : static_cast<int>(len);
	int r = static_cast<int>(::recv(fd, static_cast<char *>(buf), cap, 0));
	if (r >= 0) return r;
	publishErrno(wouldBlock());
	return -1;
}

ssize_t tlsPush(gnutls_transport_ptr_t ptr, const void *buf, size_t len) {
	socket_t fd = userPtrToSocket(ptr);
	int cap = len > 0x40000000u ? 0x40000000 : static_cast<int>(len);
	int r = static_cast<int>(::send(fd, static_cast<const char *>(buf), cap, STICE_MSG_NOSIGNAL));
	if (r >= 0) return r;
	publishErrno(wouldBlock());
	return -1;
}

std::string caFileFromEnv() {
	const char *v = std::getenv("STICE_TLS_CA_FILE");
	return (v && *v) ? std::string(v) : std::string();
}

} // namespace

struct TlsSession::Impl {
	gnutls_session_t session = nullptr;
	gnutls_certificate_credentials_t cred = nullptr;
	bool isServer = false;
	// Client-side verification is performed explicitly once the handshake
	// completes (see handshake()); no application data flows before that.
	bool verifyPeer = false;
	std::string sni;
	std::string err;

	~Impl() { reset(); }

	void reset() {
		if (session) {
			gnutls_deinit(session);
			session = nullptr;
		}
		if (cred) {
			gnutls_certificate_free_credentials(cred);
			cred = nullptr;
		}
	}

	bool fail(const char *what, int code) {
		err = std::string(what) + ": " + gnutls_strerror(code);
		return false;
	}

	bool start(socket_t fd, bool server, const TlsParams &p) {
		ensureGnutlsInit();
		isServer = server;
		sni = p.sni;
		int r = gnutls_init(&session, (server ? GNUTLS_SERVER : GNUTLS_CLIENT) | GNUTLS_NONBLOCK);
		if (r < 0) return fail("gnutls_init", r);
		// TLS 1.2 floor plus a modern-only profile (RFC 8656 §4): "-RSA" drops
		// static RSA key exchange, keeping (EC)DHE forward secrecy; NORMAL also
		// excludes NULL/anon and legacy MACs. GnuTLS 3.6+ understands the
		// +VERS-TLS1.3 token; older ones reject the whole string, hence the
		// fallbacks. Every fallback still pins the protocol range — dropping to
		// a bare "NORMAL" would silently re-admit TLS 1.0/1.1 and break the
		// documented "TLS 1.2 is the floor" guarantee — and says so, because a
		// downgraded profile is something the operator must know about.
		r = gnutls_priority_set_direct(session, "NORMAL:-RSA:-VERS-TLS-ALL:+VERS-TLS1.3:+VERS-TLS1.2",
		                               nullptr);
		if (r < 0) {
			STICE_LOG_WARN("GnuTLS: TLS 1.3 priority profile rejected (%s); falling back to a "
			               "TLS 1.2-only modern profile",
			               gnutls_strerror(r));
			r = gnutls_priority_set_direct(session, "NORMAL:-RSA:-VERS-TLS-ALL:+VERS-TLS1.2", nullptr);
		}
		if (r < 0) {
			STICE_LOG_WARN("GnuTLS: -RSA priority modifier rejected (%s); falling back to the "
			               "TLS 1.2-only default profile (static RSA key exchange may be offered)",
			               gnutls_strerror(r));
			r = gnutls_priority_set_direct(session, "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2", nullptr);
		}
		if (r < 0) return fail("gnutls_priority_set_direct", r);
		r = gnutls_certificate_allocate_credentials(&cred);
		if (r < 0) return fail("gnutls_certificate_allocate_credentials", r);

		if (server) {
			if (p.certFile.empty() || p.keyFile.empty()) {
				err = "server TLS needs certFile + keyFile";
				return false;
			}
			r = gnutls_certificate_set_x509_key_file(cred, p.certFile.c_str(), p.keyFile.c_str(),
			                                         GNUTLS_X509_FMT_PEM);
			if (r < 0) return fail(("gnutls_certificate_set_x509_key_file(" + p.certFile + ")").c_str(), r);
		} else {
			std::string ca = p.caFile.empty() ? caFileFromEnv() : p.caFile;
			if (!p.skipVerify) {
				verifyPeer = true;
				if (!ca.empty()) {
					r = gnutls_certificate_set_x509_trust_file(cred, ca.c_str(), GNUTLS_X509_FMT_PEM);
					if (r < 0) return fail(("gnutls_certificate_set_x509_trust_file(" + ca + ")").c_str(), r);
					if (r == 0)
						STICE_LOG_WARN("GnuTLS: %s contained no usable CA certificate", ca.c_str());
					else
						STICE_LOG_DEBUG("GnuTLS: pinned %d trust anchor(s) from %s", r, ca.c_str());
				} else {
					int added = gnutls_certificate_set_x509_system_trust(cred);
					if (added < 0) {
						STICE_LOG_WARN("GnuTLS: no system trust store (%s); TLS peer "
						               "certificates cannot be verified",
						               gnutls_strerror(added));
					} else if (added == 0) {
						// Same trap as the OpenSSL backend: verification is on but
						// there is nothing to verify against, so the handshake will
						// die with "certificate verify failed" and point at the
						// peer certificate instead of at the missing anchors.
						STICE_LOG_WARN("GnuTLS: the system trust store loaded 0 CA certificates, so "
						               "the peer certificate CANNOT be verified. Install a CA "
						               "bundle, set STICE_TLS_CA_FILE, or skip_tls_verify=1 for a "
						               "test rig.");
					} else {
						STICE_LOG_DEBUG("GnuTLS: loaded %d system trust anchors", added);
					}
				}
			}
		}

		r = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
		if (r < 0) return fail("gnutls_credentials_set", r);

		if (!server && !p.sni.empty() && !isIpLiteral(p.sni)) {
			// SNI carries a DNS name only (RFC 6066 §3); an IP literal is
			// verified against the iPAddress SAN in handshake() instead.
			r = gnutls_server_name_set(session, GNUTLS_NAME_DNS, p.sni.data(), p.sni.size());
			if (r < 0) return fail("gnutls_server_name_set", r);
		}

		gnutls_transport_set_ptr(session, static_cast<gnutls_transport_ptr_t>(socketToUserPtr(fd)));
		gnutls_transport_set_pull_function(session, tlsPull);
		gnutls_transport_set_push_function(session, tlsPush);
		return true;
	}
};

TlsSession::TlsSession() : impl_(new Impl()) {}
TlsSession::~TlsSession() = default;

bool TlsSession::initClient(socket_t fd, const TlsParams &p) {
	impl_.reset(new Impl());
	return impl_->start(fd, false, p);
}

bool TlsSession::initServer(socket_t fd, const TlsParams &p) {
	impl_.reset(new Impl());
	return impl_->start(fd, true, p);
}

TlsStatus TlsSession::handshake() {
	if (!impl_->session) return TlsStatus::Failed;
	int r = gnutls_handshake(impl_->session);
	if (r == 0) {
		// Client-side certificate verification is done explicitly here rather
		// than through gnutls_session_set_verify_cert(): the session-level hook
		// rejects chains that gnutls_certificate_verify_peers3 accepts on some
		// builds (observed with the mingw-w64 GnuTLS on Windows). Nothing has
		// been exchanged yet at this point, so refusing here is equivalent for
		// the caller: the session never reaches Connected.
		if (!impl_->isServer && impl_->verifyPeer) {
			// An IP-addressed peer (routine for TURN) has to be matched against
			// the certificate's iPAddress SANs: verify_peers3() compares the
			// string with dNSName entries, so hand it no hostname and check the
			// address with gnutls_x509_crt_check_ip() below.
			const bool ipLiteral = !impl_->sni.empty() && isIpLiteral(impl_->sni);
			unsigned status = 0;
			int vrc = gnutls_certificate_verify_peers3(
			    impl_->session, (impl_->sni.empty() || ipLiteral) ? nullptr : impl_->sni.c_str(),
			    &status);
			if (vrc < 0 || status != 0) {
				std::string detail = "certificate verification failed";
				gnutls_datum_t txt{nullptr, 0};
				if (vrc >= 0 &&
				    gnutls_certificate_verification_status_print(status, GNUTLS_CRT_X509, &txt, 0) >= 0 &&
				    txt.data != nullptr) {
					detail += std::string(": ") + reinterpret_cast<const char *>(txt.data);
					gnutls_free(txt.data);
				}
				impl_->err = detail;
				return TlsStatus::Failed;
			}
			if (ipLiteral) {
				unsigned char ip[16];
				unsigned ipLen = 0;
				if (::inet_pton(AF_INET, impl_->sni.c_str(), ip) == 1)
					ipLen = 4;
				else if (::inet_pton(AF_INET6, impl_->sni.c_str(), ip) == 1)
					ipLen = 16;
				unsigned int listSize = 1;
				const gnutls_datum_t *chain =
				    gnutls_certificate_get_peers(impl_->session, &listSize);
				gnutls_x509_crt_t peer = nullptr;
				int match = 0;
				if (chain && ipLen &&
				    gnutls_x509_crt_init(&peer) == 0 &&
				    gnutls_x509_crt_import(peer, chain, GNUTLS_X509_FMT_DER) == 0)
					match = gnutls_x509_crt_check_ip(peer, ip, ipLen, 0);
				if (peer) gnutls_x509_crt_deinit(peer);
				if (match != 1) {
					impl_->err = "certificate has no iPAddress SAN matching " + impl_->sni;
					return TlsStatus::Failed;
				}
			}
		}
		return TlsStatus::Ok;
	}
	if (r == GNUTLS_E_AGAIN || r == GNUTLS_E_INTERRUPTED) {
		if (r == GNUTLS_E_INTERRUPTED) return TlsStatus::WantRead;
		return gnutls_record_get_direction(impl_->session) ? TlsStatus::WantWrite : TlsStatus::WantRead;
	}
	if (r == GNUTLS_E_PREMATURE_TERMINATION) return TlsStatus::Closed;
	if (gnutls_error_is_fatal(r) == 0) return TlsStatus::WantRead;
	impl_->fail("gnutls_handshake failed", r);
	return TlsStatus::Failed;
}

TlsStatus TlsSession::read(unsigned char *buf, std::size_t len, std::size_t &n) {
	n = 0;
	if (!impl_->session) return TlsStatus::Failed;
	ssize_t r = gnutls_record_recv(impl_->session, buf, len);
	if (r > 0) {
		n = static_cast<std::size_t>(r);
		return TlsStatus::Ok;
	}
	if (r == 0) return TlsStatus::Closed; // close_notify
	if (r == GNUTLS_E_AGAIN || r == GNUTLS_E_INTERRUPTED) {
		if (r == GNUTLS_E_INTERRUPTED) return TlsStatus::WantRead;
		return gnutls_record_get_direction(impl_->session) ? TlsStatus::WantWrite : TlsStatus::WantRead;
	}
	if (r == GNUTLS_E_REHANDSHAKE) {
		// A TLS 1.2 peer asked for a renegotiation. TcpTransport cannot resume a
		// handshake from the read path (it would re-arm POLLIN and spin
		// forever), and renegotiation is an attack surface modern clients
		// refuse anyway — a TURN server has no reason to request one. Fail the
		// connection instead of pretending to wait for data.
		impl_->err = "peer requested TLS renegotiation (refused)";
		STICE_LOG_WARN("GnuTLS: peer requested TLS renegotiation; closing the connection");
		return TlsStatus::Failed;
	}
	impl_->fail("gnutls_record_recv failed", static_cast<int>(r));
	return TlsStatus::Failed;
}

TlsStatus TlsSession::write(const unsigned char *buf, std::size_t len, std::size_t &n) {
	n = 0;
	if (!impl_->session) return TlsStatus::Failed;
	ssize_t r = gnutls_record_send(impl_->session, buf, len);
	if (r > 0) {
		n = static_cast<std::size_t>(r);
		return TlsStatus::Ok;
	}
	if (r == GNUTLS_E_AGAIN || r == GNUTLS_E_INTERRUPTED) {
		if (r == GNUTLS_E_INTERRUPTED) return TlsStatus::WantRead;
		return gnutls_record_get_direction(impl_->session) ? TlsStatus::WantWrite : TlsStatus::WantRead;
	}
	impl_->fail("gnutls_record_send failed", static_cast<int>(r));
	return TlsStatus::Failed;
}

void TlsSession::shutdown() {
	if (!impl_->session) return;
	// Best effort on a non-blocking socket: the close_notify may not fit in
	// the socket buffer, in which case it is simply dropped (the TCP FIN that
	// follows is what the peer reacts to).
	gnutls_bye(impl_->session, GNUTLS_SHUT_WR);
}

void TlsSession::close() {
	impl_->reset(); // free in place: no allocation, errorString() stays valid
}

bool TlsSession::active() const { return impl_ && impl_->session != nullptr; }

const std::string &TlsSession::errorString() const { return impl_->err; }

const char *TlsSession::backendName() { return "gnutls"; }

bool TlsSession::available() { return true; }

} // namespace stice::net
