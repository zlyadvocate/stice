// SPDX-License-Identifier: MPL-2.0
// TLS backend: none. Compiled when stice is configured without any TLS
// library (STICE_USE_OPENSSL=OFF and no USE_GNUTLS/USE_MBEDTLS).
//
// TURN over TLS is then unavailable: the TCP transport keeps working as plain
// TCP (as it did before any TLS support existed) and reports why.

#include "stice/net/tls.hpp"

#include <string>

namespace stice::net {

struct TlsSession::Impl {
	std::string err;
};

TlsSession::TlsSession() : impl_(new Impl()) {}
TlsSession::~TlsSession() = default;

bool TlsSession::initClient(socket_t, const TlsParams &) {
	impl_->err = "stice was built without a TLS backend (OpenSSL/GnuTLS/Mbed TLS)";
	return false;
}

bool TlsSession::initServer(socket_t, const TlsParams &) {
	impl_->err = "stice was built without a TLS backend (OpenSSL/GnuTLS/Mbed TLS)";
	return false;
}

TlsStatus TlsSession::handshake() { return TlsStatus::Failed; }

TlsStatus TlsSession::read(unsigned char *, std::size_t, std::size_t &n) {
	n = 0;
	return TlsStatus::Failed;
}

TlsStatus TlsSession::write(const unsigned char *, std::size_t, std::size_t &n) {
	n = 0;
	return TlsStatus::Failed;
}

void TlsSession::shutdown() {}

void TlsSession::close() { impl_->err.clear(); }

bool TlsSession::active() const { return false; }

const std::string &TlsSession::errorString() const { return impl_->err; }

const char *TlsSession::backendName() { return "none"; }

bool TlsSession::available() { return false; }

} // namespace stice::net
