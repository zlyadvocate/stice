// SPDX-License-Identifier: MPL-2.0
// TLS backend: OpenSSL (default). Selected with STICE_TLS_OPENSSL.
//
// Ported from the inline OpenSSL handling that used to live in tcp.cpp: same
// TLS 1.2+ client policy, same "verify against the platform trust store unless
// skip_tls_verify" default, same hostname verification (RFC 6125).

#include "stice/net/tls.hpp"

#include "stice/log.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <limits>

namespace stice::net {

namespace {

void drainSslErrors(std::string &out) {
	char buf[256];
	unsigned long e;
	bool first = true;
	while ((e = ERR_get_error()) != 0) {
		ERR_error_string_n(e, buf, sizeof(buf));
		// Keep the message readable: ": " before the first OpenSSL error (so it
		// does not run into the backend's own text), "; " between them.
		if (first) {
			if (!out.empty()) out += ": ";
		} else {
			out += "; ";
		}
		out += buf;
		first = false;
	}
}

// STICE_TLS_CA_FILE: PEM bundle used instead of the platform trust store.
// Lets a deployment (or a test) pin an explicit CA without touching the
// system store.
std::string caFileFromEnv() {
	const char *v = std::getenv("STICE_TLS_CA_FILE");
	return (v && *v) ? std::string(v) : std::string();
}

// Modern-only profile, as RFC 8656 §4 recommends for TURN over TLS: forward
// secret (EC)DHE key exchange with AEAD ciphers, no static RSA key exchange, no
// NULL/MD5/RC4/3DES/DES/EXPORT/PSK/SRP/DSS. Without this the backend inherits
// whatever OpenSSL's default security level happens to allow on the host.
// (Name-based, so it also works with OpenSSL builds that disabled suites.)
// NOTE: "!kRSA" (key exchange), not "!RSA" — the latter is shorthand for
// kRSA|aRSA and would also drop ECDHE-RSA-* suites, i.e. every RSA-certificate
// server out there.
const char kCipherList[] = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:"
                           "!aNULL:!eNULL:!MD5:!RC4:!3DES:!DES:!EXPORT:!PSK:!SRP:!DSS:!kRSA";
const char kCipherSuites13[] = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
                               "TLS_AES_128_GCM_SHA256";

bool applyCipherPolicy(SSL_CTX *ctx) {
	if (SSL_CTX_set_cipher_list(ctx, kCipherList) != 1) { // TLS 1.2 and below
		ERR_clear_error();
		return false;
	}
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	SSL_CTX_set_ciphersuites(ctx, kCipherSuites13); // TLS 1.3
#endif
	ERR_clear_error();
	return true;
}

// A successful SSL_CTX_set_default_verify_paths() is not proof that any trust
// anchor was loaded: on Windows it usually finds nothing (OpenSSL does not read
// the platform certificate store), leaving an empty store behind. Checking the
// store lets the caller say "no CA bundle" *before* the handshake, instead of
// leaving the user with a bare "certificate verify failed".
bool storeHasCertificates(SSL_CTX *ctx) {
	X509_STORE *store = SSL_CTX_get_cert_store(ctx);
	if (!store) return false;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	STACK_OF(X509_OBJECT) *objs = X509_STORE_get0_objects(store);
	if (!objs) return false;
	for (int i = 0; i < sk_X509_OBJECT_num(objs); ++i) {
		X509_OBJECT *o = sk_X509_OBJECT_value(objs, i);
		if (o && X509_OBJECT_get_type(o) == X509_LU_X509) return true;
	}
	return false;
#else
	(void)store;
	return true; // 1.0.2 has no cheap way to inspect the store: assume loaded
#endif
}

// IP literals are handled with IP-SAN verification (see isIpLiteral() in
// tls.hpp), and the corresponding check lives in Impl::attach().

// Socket BIO used instead of SSL_set_fd(). Two reasons:
//  * SSL_set_fd() writes through OpenSSL's own socket BIO, which uses write(2)
//    and therefore raises SIGPIPE once the peer is gone; a reset TURN control
//    connection must not be able to kill the host process. Our writes pass
//    STICE_MSG_NOSIGNAL (same approach as libjuice/libdatachannel).
//  * the handle travels in a pointer-sized slot, so a 64-bit Windows SOCKET is
//    no longer squeezed into an int.
int bioWrite(BIO *b, const char *out, int outl) {
	BIO_clear_retry_flags(b);
	if (!out || outl <= 0) return 0;
	socket_t fd = userPtrToSocket(BIO_get_data(b));
	int r = static_cast<int>(::send(fd, out, outl, STICE_MSG_NOSIGNAL));
	if (r < 0) {
		if (wouldBlock() || sticeSockerrno == STICE_SEINTR) BIO_set_retry_write(b);
		return -1;
	}
	return r;
}

int bioRead(BIO *b, char *in, int inl) {
	BIO_clear_retry_flags(b);
	if (!in || inl <= 0) return 0;
	socket_t fd = userPtrToSocket(BIO_get_data(b));
	int r = static_cast<int>(::recv(fd, in, inl, 0));
	if (r < 0) {
		if (wouldBlock() || sticeSockerrno == STICE_SEINTR) BIO_set_retry_read(b);
		return -1;
	}
	return r; // 0 = orderly EOF, which OpenSSL turns into a clean close
}

long bioCtrl(BIO *b, int cmd, long num, void *ptr) {
	(void)b;
	(void)num;
	(void)ptr;
	switch (cmd) {
	case BIO_CTRL_FLUSH: return 1;
	case BIO_CTRL_DUP: return 1;
	default: return 0;
	}
}

int bioCreate(BIO *b) {
	BIO_set_init(b, 1);
	BIO_set_data(b, nullptr);
	return 1;
}

int bioDestroy(BIO *b) {
	(void)b;
	return 1; // the descriptor is owned by TcpTransport, never by the BIO
}

BIO_METHOD *socketBioMethod() {
	static BIO_METHOD *m = [] {
		BIO_METHOD *mm =
		    BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "stice-socket");
		if (!mm) return static_cast<BIO_METHOD *>(nullptr);
		BIO_meth_set_write(mm, bioWrite);
		BIO_meth_set_read(mm, bioRead);
		BIO_meth_set_ctrl(mm, bioCtrl);
		BIO_meth_set_create(mm, bioCreate);
		BIO_meth_set_destroy(mm, bioDestroy);
		return mm;
	}();
	return m;
}

} // namespace

struct TlsSession::Impl {
	SSL *ssl = nullptr;
	SSL_CTX *ctx = nullptr;
	bool isServer = false;
	// True when the peer certificate is verified during the handshake. With
	// skip_tls_verify the verify result is meaningless (SSL_VERIFY_NONE leaves
	// x509 errors behind), so the post-handshake check must be gated on this.
	bool verifyPeer = false;
	std::string err;

	~Impl() { reset(); }

	void reset() {
		if (ssl) {
			SSL_free(ssl);
			ssl = nullptr;
		}
		if (ctx) {
			SSL_CTX_free(ctx);
			ctx = nullptr;
		}
	}

	bool fail(const std::string &what) {
		err = what;
		drainSslErrors(err);
		return false;
	}

	// Shared tail of initClient/initServer: attach the fd to a fresh SSL.
	bool attach(socket_t fd, const TlsParams &p) {
		ssl = SSL_new(ctx);
		if (!ssl) return fail("SSL_new");
		if (!p.sni.empty()) {
			// SNI is a DNS-name extension (RFC 6066 §3 forbids IP literals in
			// it), and OpenSSL matches an IP against the certificate's IP SANs
			// only via set1_ip_asc — set1_host would treat "192.0.2.1" as a DNS
			// name and reject a perfectly valid certificate. TURN servers are
			// routinely configured by IP, so both cases matter here.
			const bool ipLiteral = isIpLiteral(p.sni);
			if (!ipLiteral) SSL_set_tlsext_host_name(ssl, p.sni.c_str());
			if (!p.skipVerify) {
				X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
				if (ipLiteral)
					X509_VERIFY_PARAM_set1_ip_asc(param, p.sni.c_str());
				else
					X509_VERIFY_PARAM_set1_host(param, p.sni.c_str(), p.sni.size());
			}
		}
		BIO *bio = BIO_new(socketBioMethod());
		if (!bio) return fail("BIO_new");
		BIO_set_data(bio, socketToUserPtr(fd));
		// One BIO for both directions; SSL takes ownership and frees it in
		// SSL_free() (bioDestroy above never closes the descriptor).
		SSL_set_bio(ssl, bio, bio);
		if (isServer)
			SSL_set_accept_state(ssl);
		else
			SSL_set_connect_state(ssl);
		ERR_clear_error();
		return true;
	}
};

TlsSession::TlsSession() : impl_(new Impl()) {}
TlsSession::~TlsSession() = default;

bool TlsSession::initClient(socket_t fd, const TlsParams &p) {
	impl_.reset(new Impl());
	impl_->isServer = false;
	impl_->ctx = SSL_CTX_new(TLS_client_method());
	if (!impl_->ctx) return impl_->fail("SSL_CTX_new");
	if (!applyCipherPolicy(impl_->ctx)) return impl_->fail("no usable cipher suite for the TLS profile");

	// TLS 1.2 is the floor: RFC 8656 TURN servers still commonly offer it.
	SSL_CTX_set_min_proto_version(impl_->ctx, TLS1_2_VERSION);

	std::string ca = p.caFile.empty() ? caFileFromEnv() : p.caFile;
	bool noTrustAnchors = false;
	if (!ca.empty()) {
		if (SSL_CTX_load_verify_locations(impl_->ctx, ca.c_str(), nullptr) != 1)
			return impl_->fail("SSL_CTX_load_verify_locations(" + ca + ")");
	} else if (SSL_CTX_set_default_verify_paths(impl_->ctx) != 1) {
		ERR_clear_error();
		noTrustAnchors = true;
	} else if (!storeHasCertificates(impl_->ctx)) {
		noTrustAnchors = true;
	}
	if (!p.skipVerify) {
		// Verify the peer certificate during the handshake (pion/libjuice
		// default). skip_tls_verify is only meant for self-signed test rigs.
		SSL_CTX_set_verify(impl_->ctx, SSL_VERIFY_PEER, nullptr);
		impl_->verifyPeer = true;
		if (noTrustAnchors)
			// Verification is mandatory but there is nothing to verify against,
			// so every handshake will fail with "certificate verify failed".
			// Say the real cause up front (Windows has no OpenSSL default path;
			// minimal containers ship no ca-certificates).
			STICE_LOG_WARN("TLS: no CA bundle loaded — OpenSSL found no default trust store on "
			               "this host (on Windows it does not read the certificate store at all), "
			               "so the peer certificate CANNOT be verified. Set STICE_TLS_CA_FILE to a "
			               "PEM bundle, or skip_tls_verify=1 for a test rig.");
	}
	return impl_->attach(fd, p);
}

bool TlsSession::initServer(socket_t fd, const TlsParams &p) {
	impl_.reset(new Impl());
	impl_->isServer = true;
	if (p.certFile.empty() || p.keyFile.empty()) return impl_->fail("server TLS needs certFile + keyFile");
	impl_->ctx = SSL_CTX_new(TLS_server_method());
	if (!impl_->ctx) return impl_->fail("SSL_CTX_new");
	if (!applyCipherPolicy(impl_->ctx)) return impl_->fail("no usable cipher suite for the TLS profile");
	SSL_CTX_set_min_proto_version(impl_->ctx, TLS1_2_VERSION);
	if (SSL_CTX_use_certificate_chain_file(impl_->ctx, p.certFile.c_str()) != 1)
		return impl_->fail("SSL_CTX_use_certificate_chain_file(" + p.certFile + ")");
	if (SSL_CTX_use_PrivateKey_file(impl_->ctx, p.keyFile.c_str(), SSL_FILETYPE_PEM) != 1)
		return impl_->fail("SSL_CTX_use_PrivateKey_file(" + p.keyFile + ")");
	if (SSL_CTX_check_private_key(impl_->ctx) != 1) return impl_->fail("SSL_CTX_check_private_key");
	return impl_->attach(fd, p);
}

TlsStatus TlsSession::handshake() {
	if (!impl_->ssl) return TlsStatus::Failed;
	ERR_clear_error();
	int r = impl_->isServer ? SSL_accept(impl_->ssl) : SSL_connect(impl_->ssl);
	if (r == 1) {
		if (!impl_->isServer && impl_->verifyPeer) {
			// SSL_VERIFY_PEER already aborts a bad chain inside the handshake;
			// surface the detail here for a diagnosable log line.
			long vr = SSL_get_verify_result(impl_->ssl);
			if (vr != X509_V_OK) {
				impl_->err = std::string("certificate verify failed: ") + X509_verify_cert_error_string(vr);
				return TlsStatus::Failed;
			}
		}
		return TlsStatus::Ok;
	}
	int e = SSL_get_error(impl_->ssl, r);
	if (e == SSL_ERROR_WANT_READ) return TlsStatus::WantRead;
	if (e == SSL_ERROR_WANT_WRITE) return TlsStatus::WantWrite;
	if (e == SSL_ERROR_ZERO_RETURN) return TlsStatus::Closed;
	impl_->fail("SSL handshake failed");
	return TlsStatus::Failed;
}

TlsStatus TlsSession::read(unsigned char *buf, std::size_t len, std::size_t &n) {
	n = 0;
	if (!impl_->ssl) return TlsStatus::Failed;
	ERR_clear_error();
	int chunk = len > 16384 ? 16384 : static_cast<int>(len);
	int r = SSL_read(impl_->ssl, buf, chunk);
	if (r > 0) {
		n = static_cast<std::size_t>(r);
		return TlsStatus::Ok;
	}
	int e = SSL_get_error(impl_->ssl, r);
	if (e == SSL_ERROR_WANT_READ) return TlsStatus::WantRead;
	if (e == SSL_ERROR_WANT_WRITE) return TlsStatus::WantWrite;
	if (e == SSL_ERROR_ZERO_RETURN) return TlsStatus::Closed;
	impl_->fail("SSL_read failed");
	return TlsStatus::Failed;
}

TlsStatus TlsSession::write(const unsigned char *buf, std::size_t len, std::size_t &n) {
	n = 0;
	if (!impl_->ssl) return TlsStatus::Failed;
	ERR_clear_error();
	int chunk = len > 16384 ? 16384 : static_cast<int>(len);
	int r = SSL_write(impl_->ssl, buf, chunk);
	if (r > 0) {
		n = static_cast<std::size_t>(r);
		return TlsStatus::Ok;
	}
	int e = SSL_get_error(impl_->ssl, r);
	if (e == SSL_ERROR_WANT_READ) return TlsStatus::WantRead;
	if (e == SSL_ERROR_WANT_WRITE) return TlsStatus::WantWrite;
	if (e == SSL_ERROR_ZERO_RETURN) return TlsStatus::Closed;
	impl_->fail("SSL_write failed");
	return TlsStatus::Failed;
}

void TlsSession::shutdown() {
	if (!impl_->ssl) return;
	ERR_clear_error();
	SSL_shutdown(impl_->ssl); // best effort on a non-blocking socket
	ERR_clear_error();
}

void TlsSession::close() {
	impl_->reset(); // free in place: no allocation, errorString() stays valid
}

bool TlsSession::active() const { return impl_ && impl_->ssl != nullptr; }

const std::string &TlsSession::errorString() const { return impl_->err; }

const char *TlsSession::backendName() { return "openssl"; }

bool TlsSession::available() { return true; }

} // namespace stice::net
