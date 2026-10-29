// SPDX-License-Identifier: MPL-2.0
// TLS backend: Mbed TLS. Selected with STICE_TLS_MBEDTLS (CMake USE_MBEDTLS).
//
// Works with both the 2.x and 3.x series (the host project may pin either; see
// the version guards below). Behavior matches the OpenSSL/GnuTLS backends:
//   * TLS 1.2 floor,
//   * certificate verification is REQUIRED when a trust anchor is available,
//   * skip_tls_verify / STICE_TLS_CA_FILE as in the other backends.
//
// Unlike OpenSSL and GnuTLS, Mbed TLS does not ship or locate an OS trust
// store. A verifying handshake therefore needs an explicit CA bundle
// (STICE_TLS_CA_FILE); without one the session falls back to VERIFY_NONE and
// says so loudly, because silently pretending to verify would be worse.

#include "stice/net/tls.hpp"

#include "stice/log.hpp"

// Configuration header: Mbed TLS 3.x renamed config.h to build_info.h, and the
// 2.x series (e.g. 2.28 on Ubuntu 22.04) does not ship build_info.h at all, so
// pick whichever the installed version provides.
#if defined(__has_include)
#  if __has_include(<mbedtls/build_info.h>)
#    include <mbedtls/build_info.h>
#  else
#    include <mbedtls/config.h>
#  endif
#else
#  include <mbedtls/config.h>
#endif
#include <mbedtls/asn1.h> // mbedtls_asn1_get_tag / get_len (2.x IP-SAN lookup)
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h> // MBEDTLS_ERR_NET_SEND_FAILED / RECV_FAILED
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace stice::net {

namespace {

int tlsSend(void *ctx, const unsigned char *buf, size_t len) {
	socket_t fd = userPtrToSocket(ctx);
	int cap = len > 0x40000000u ? 0x40000000 : static_cast<int>(len);
	int r = static_cast<int>(::send(fd, reinterpret_cast<const char *>(buf), cap, STICE_MSG_NOSIGNAL));
	if (r >= 0) return r;
	if (wouldBlock()) return MBEDTLS_ERR_SSL_WANT_WRITE;
	return MBEDTLS_ERR_NET_SEND_FAILED;
}

int tlsRecv(void *ctx, unsigned char *buf, size_t len) {
	socket_t fd = userPtrToSocket(ctx);
	int cap = len > 0x40000000u ? 0x40000000 : static_cast<int>(len);
	int r = static_cast<int>(::recv(fd, reinterpret_cast<char *>(buf), cap, 0));
	if (r >= 0) return r;
	if (wouldBlock()) return MBEDTLS_ERR_SSL_WANT_READ;
	return MBEDTLS_ERR_NET_RECV_FAILED;
}

#if MBEDTLS_VERSION_NUMBER < 0x03000000
// ---- iPAddress SAN lookup for mbedTLS 2.x --------------------------------
// 2.x fills mbedtls_x509_crt::subject_alt_names with dNSName/otherName entries
// only (see its documentation) and exposes no API for the iPAddress ones, so
// mbedtls_ssl_set_hostname() cannot check an IP-addressed peer — a routine
// configuration for TURN servers. Read the subjectAltName extension
// (2.5.29.17) out of the peer certificate's DER instead. 3.x keeps the IP SANs
// in subject_alt_names and does this itself, so none of this is compiled there.

// Skip one arbitrary TLV (tag byte + length + value).
bool skipTlv(unsigned char *&p, const unsigned char *end) {
	if (p >= end) return false;
	++p; // tag
	size_t len = 0;
	if (mbedtls_asn1_get_len(&p, end, &len) != 0) return false;
	if (len > static_cast<size_t>(end - p)) return false;
	p += len;
	return true;
}

// GeneralNames ::= SEQUENCE OF GeneralName; iPAddress is [7] with 4/16 octets.
bool generalNamesMatchIp(unsigned char *p, const unsigned char *end, const unsigned char *want,
                         size_t wantLen) {
	while (p < end) {
		const int tag = *p;
		++p;
		size_t len = 0;
		if (mbedtls_asn1_get_len(&p, end, &len) != 0) return false;
		if (len > static_cast<size_t>(end - p)) return false;
		if (tag == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 7) && len == wantLen &&
		    std::memcmp(p, want, wantLen) == 0)
			return true;
		p += len;
	}
	return false;
}

bool ipSanMatchesDer(const unsigned char *der, size_t derLen, const std::string &ip) {
	unsigned char want[16];
	size_t wantLen;
	if (::inet_pton(AF_INET, ip.c_str(), want) == 1)
		wantLen = 4;
	else if (::inet_pton(AF_INET6, ip.c_str(), want) == 1)
		wantLen = 16;
	else
		return false;

	unsigned char *p = const_cast<unsigned char *>(der);
	const unsigned char *end = der + derLen;
	size_t len = 0;

	// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
	if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
		return false;
	end = p + len;
	// tbsCertificate ::= SEQUENCE { [0] version, serial, sigAlg, issuer,
	//                               validity, subject, spki, [1], [2], [3] exts }
	if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
		return false;
	const unsigned char *tbsEnd = p + len;

	if (p < tbsEnd && *p == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0)) {
		if (!skipTlv(p, tbsEnd)) return false; // explicit version
	}
	for (int i = 0; i < 6; ++i) // serial, sigAlg, issuer, validity, subject, spki
		if (!skipTlv(p, tbsEnd)) return false;

	while (p < tbsEnd) {
		const int tag = *p;
		unsigned char *q = p + 1;
		size_t tlvLen = 0;
		if (mbedtls_asn1_get_len(&q, tbsEnd, &tlvLen) != 0) return false;
		if (tlvLen > static_cast<size_t>(tbsEnd - q)) return false;
		const unsigned char *valEnd = q + tlvLen;

		if (tag != (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 3)) {
			p = const_cast<unsigned char *>(valEnd); // [1] / [2] unique IDs
			continue;
		}
		// extensions [3] EXPLICIT Extensions ::= SEQUENCE OF Extension
		// Extension  ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL,
		//                           extnValue OCTET STRING }
		unsigned char *ep = q;
		size_t listLen = 0;
		if (mbedtls_asn1_get_tag(&ep, valEnd, &listLen,
		                         MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
			return false;
		const unsigned char *listEnd = ep + listLen;
		while (ep < listEnd) {
			size_t seqLen = 0;
			if (mbedtls_asn1_get_tag(&ep, listEnd, &seqLen,
			                         MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
				return false;
			const unsigned char *extEnd = ep + seqLen;

			unsigned char *oid = ep;
			size_t oidLen = 0;
			if (mbedtls_asn1_get_tag(&oid, extEnd, &oidLen, MBEDTLS_ASN1_OID) != 0) return false;
			static const unsigned char kSanOid[] = {0x55, 0x1D, 0x11}; // 2.5.29.17
			const bool isSan =
			    oidLen == sizeof(kSanOid) && std::memcmp(oid, kSanOid, sizeof(kSanOid)) == 0;
			oid += oidLen;
			if (oid < extEnd && *oid == MBEDTLS_ASN1_BOOLEAN) {
				if (!skipTlv(oid, extEnd)) return false; // critical flag
			}
			size_t octLen = 0;
			if (mbedtls_asn1_get_tag(&oid, extEnd, &octLen, MBEDTLS_ASN1_OCTET_STRING) != 0)
				return false;
			if (isSan) {
				unsigned char *gp = oid;
				const unsigned char *gEnd = oid + octLen;
				size_t namesLen = 0;
				if (mbedtls_asn1_get_tag(&gp, gEnd, &namesLen,
				                         MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) == 0 &&
				    generalNamesMatchIp(gp, gp + namesLen, want, wantLen))
					return true;
			}
			ep = const_cast<unsigned char *>(extEnd);
		}
		return false; // extensions parsed, no matching IP SAN
	}
	return false;
}
#endif

std::string caFileFromEnv() {
	const char *v = std::getenv("STICE_TLS_CA_FILE");
	return (v && *v) ? std::string(v) : std::string();
}
std::string mbedErrText(int code) {
	char buf[256];
	mbedtls_strerror(code, buf, sizeof(buf));
	if (buf[0] == '\0') {
		char alt[32];
		std::snprintf(alt, sizeof(alt), "err -0x%04X", static_cast<unsigned>(-code));
		return std::string(alt);
	}
	return std::string(buf);
}

} // namespace

struct TlsSession::Impl {
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_ctr_drbg_context ctrDrbg;
	mbedtls_entropy_context entropy;
	mbedtls_x509_crt cert;   // client: trust anchors / server: own chain
	mbedtls_pk_context pkey; // server only
	bool isServer = false;
	bool ready = false;
	// Client-side verification is on (a trust anchor was configured and
	// skip_tls_verify is false).
	bool verifyPeer = false;
	// Non-empty when the peer is addressed by IP and mbedTLS 2.x is in use: the
	// iPAddress SAN is checked by hand after the handshake (3.x does it itself).
	std::string ipLiteral;
	std::string err;

	Impl() {
		mbedtls_ssl_init(&ssl);
		mbedtls_ssl_config_init(&conf);
		mbedtls_ctr_drbg_init(&ctrDrbg);
		mbedtls_entropy_init(&entropy);
		mbedtls_x509_crt_init(&cert);
		mbedtls_pk_init(&pkey);
	}

	~Impl() { release(); }

	// Release the TLS contexts in place. TlsSession::close() uses reset()
	// instead of reallocating the Impl, so closing a connection costs no
	// allocation and errorString() stays valid.
	void release() {
		mbedtls_ssl_free(&ssl);
		mbedtls_ssl_config_free(&conf);
		mbedtls_x509_crt_free(&cert);
		mbedtls_pk_free(&pkey);
		mbedtls_ctr_drbg_free(&ctrDrbg);
		mbedtls_entropy_free(&entropy);
		ready = false;
	}

	void reset() {
		release();
		mbedtls_ssl_init(&ssl);
		mbedtls_ssl_config_init(&conf);
		mbedtls_x509_crt_init(&cert);
		mbedtls_pk_init(&pkey);
		mbedtls_ctr_drbg_init(&ctrDrbg);
		mbedtls_entropy_init(&entropy);
	}

	bool fail(const std::string &what, int code) {
		err = what + (code ? ": " + mbedErrText(code) : std::string());
		return false;
	}

	bool start(socket_t fd, bool server, const TlsParams &p) {
		isServer = server;
		static const char pers[] = "stice-tls";
		int r = mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy,
		                              reinterpret_cast<const unsigned char *>(pers), sizeof(pers) - 1);
		if (r != 0) return fail("mbedtls_ctr_drbg_seed", r);

		r = mbedtls_ssl_config_defaults(&conf, server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
		                                MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
		if (r != 0) return fail("mbedtls_ssl_config_defaults", r);
		mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctrDrbg);
		// Modern-only profile (RFC 8656 §4): forward-secret (EC)DHE key exchange
		// with AEAD ciphers only -- no static RSA key exchange, no CBC, no
		// SHA-1 MACs. The IDs are numeric because the MBEDTLS_TLS_* constant
		// names were reshuffled between the 2.x and 3.x series; the values
		// themselves are stable IANA IDs.
		//
		// One list covers every protocol version: Mbed TLS 3.x has no
		// per-version setter (mbedtls_ssl_conf_ciphersuites() feeds both TLS
		// 1.2 and TLS 1.3), so the TLS 1.3 IDs must be in the same array.
		// Handing it 1.2-only IDs made every 3.x handshake fail with
		// "handshake negotiation failed".
		static const int kSuites[] = {
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
		    0x1301, // TLS_AES_128_GCM_SHA256           (TLS 1.3, AEAD-only by design)
		    0x1302, // TLS_AES_256_GCM_SHA384           (TLS 1.3)
		    0x1303, // TLS_CHACHA20_POLY1305_SHA256     (TLS 1.3)
#endif
		    0xC02C, // TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384
		    0xC030, // TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
		    0xC02B, // TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
		    0xC02F, // TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
		    0xCCA9, // TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256
		    0xCCA8, // TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256
		    0};
		mbedtls_ssl_conf_ciphersuites(&conf, kSuites);
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
		// In TLS 1.3 the key exchange is configured separately from the
		// ciphersuite; allow pure-ephemeral only (no PSK, no PSK-ephemeral).
		mbedtls_ssl_conf_tls13_key_exchange_modes(
		    &conf, MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL);
#endif
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
		mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
#else
		mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
#endif

		if (server) {
			if (p.certFile.empty() || p.keyFile.empty()) {
				err = "server TLS needs certFile + keyFile";
				return false;
			}
			r = mbedtls_x509_crt_parse_file(&cert, p.certFile.c_str());
			if (r != 0) return fail("mbedtls_x509_crt_parse_file(" + p.certFile + ")", r);
#if MBEDTLS_VERSION_NUMBER >= 0x03060000
			r = mbedtls_pk_parse_keyfile(&pkey, p.keyFile.c_str(), "", nullptr, nullptr);
#else
			r = mbedtls_pk_parse_keyfile(&pkey, p.keyFile.c_str(), "");
#endif
			if (r != 0) return fail("mbedtls_pk_parse_keyfile(" + p.keyFile + ")", r);
			r = mbedtls_ssl_conf_own_cert(&conf, &cert, &pkey);
			if (r != 0) return fail("mbedtls_ssl_conf_own_cert", r);
		} else {
			std::string ca = p.caFile.empty() ? caFileFromEnv() : p.caFile;
			bool canVerify = false;
			if (!p.skipVerify) {
				if (!ca.empty()) {
					r = mbedtls_x509_crt_parse_file(&cert, ca.c_str());
					if (r != 0) return fail("mbedtls_x509_crt_parse_file(" + ca + ")", r);
					mbedtls_ssl_conf_ca_chain(&conf, &cert, nullptr);
					canVerify = true;
					verifyPeer = true;
				} else {
					STICE_LOG_WARN("Mbed TLS: no CA bundle configured; Mbed TLS has no system "
					               "trust store, so the TURN/TLS peer certificate will NOT be "
					               "verified. Set STICE_TLS_CA_FILE to verify.");
				}
			}
			mbedtls_ssl_conf_authmode(&conf, canVerify ? MBEDTLS_SSL_VERIFY_REQUIRED
			                                           : MBEDTLS_SSL_VERIFY_NONE);
		}

		r = mbedtls_ssl_setup(&ssl, &conf);
		if (r != 0) return fail("mbedtls_ssl_setup", r);
		if (!server && !p.sni.empty()) {
#if MBEDTLS_VERSION_NUMBER < 0x03000000
			if (isIpLiteral(p.sni)) {
				// 2.x: set_hostname would compare the literal against dNSName
				// SANs only (and send an illegal SNI), so check the iPAddress
				// SAN after the handshake instead.
				ipLiteral = p.sni;
			} else
#endif
			{
				// Also sets the SNI extension.
				r = mbedtls_ssl_set_hostname(&ssl, p.sni.c_str());
				if (r != 0) return fail("mbedtls_ssl_set_hostname", r);
			}
		}
		mbedtls_ssl_set_bio(&ssl, socketToUserPtr(fd), tlsSend, tlsRecv, nullptr);
		ready = true;
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
	if (!impl_->ready) return TlsStatus::Failed;
	int r = mbedtls_ssl_handshake(&impl_->ssl);
	if (r == 0) {
#if MBEDTLS_VERSION_NUMBER < 0x03000000
		// IP-addressed peer on 2.x: the chain was verified during the handshake;
		// the address is matched against the iPAddress SAN here because 2.x does
		// not expose those entries.
		if (!impl_->isServer && impl_->verifyPeer && !impl_->ipLiteral.empty()) {
			const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&impl_->ssl);
			if (!peer || !ipSanMatchesDer(peer->raw.p, peer->raw.len, impl_->ipLiteral)) {
				impl_->err = "certificate has no iPAddress SAN matching " + impl_->ipLiteral;
				return TlsStatus::Failed;
			}
		}
#endif
		return TlsStatus::Ok;
	}
	if (r == MBEDTLS_ERR_SSL_WANT_READ) return TlsStatus::WantRead;
	if (r == MBEDTLS_ERR_SSL_WANT_WRITE) return TlsStatus::WantWrite;
	if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || r == MBEDTLS_ERR_SSL_CONN_EOF) return TlsStatus::Closed;
	impl_->fail("mbedtls_ssl_handshake failed", r);
	return TlsStatus::Failed;
}

TlsStatus TlsSession::read(unsigned char *buf, std::size_t len, std::size_t &n) {
	n = 0;
	if (!impl_->ready) return TlsStatus::Failed;
	int r = mbedtls_ssl_read(&impl_->ssl, buf, len);
	if (r > 0) {
		n = static_cast<std::size_t>(r);
		return TlsStatus::Ok;
	}
	if (r == 0) return TlsStatus::Closed;
	if (r == MBEDTLS_ERR_SSL_WANT_READ) return TlsStatus::WantRead;
	if (r == MBEDTLS_ERR_SSL_WANT_WRITE) return TlsStatus::WantWrite;
	if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || r == MBEDTLS_ERR_SSL_CONN_EOF) return TlsStatus::Closed;
	impl_->fail("mbedtls_ssl_read failed", r);
	return TlsStatus::Failed;
}

TlsStatus TlsSession::write(const unsigned char *buf, std::size_t len, std::size_t &n) {
	n = 0;
	if (!impl_->ready) return TlsStatus::Failed;
	int r = mbedtls_ssl_write(&impl_->ssl, buf, len);
	if (r > 0) {
		n = static_cast<std::size_t>(r);
		return TlsStatus::Ok;
	}
	if (r == MBEDTLS_ERR_SSL_WANT_READ) return TlsStatus::WantRead;
	if (r == MBEDTLS_ERR_SSL_WANT_WRITE) return TlsStatus::WantWrite;
	impl_->fail("mbedtls_ssl_write failed", r);
	return TlsStatus::Failed;
}

void TlsSession::shutdown() {
	if (!impl_->ready) return;
	mbedtls_ssl_close_notify(&impl_->ssl); // best effort, non-blocking
}

void TlsSession::close() {
	impl_->reset(); // free in place: no allocation, errorString() stays valid
}

bool TlsSession::active() const { return impl_ && impl_->ready; }

const std::string &TlsSession::errorString() const { return impl_->err; }

const char *TlsSession::backendName() { return "mbedtls"; }

bool TlsSession::available() { return true; }

} // namespace stice::net
