/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
#include "stice/stun/client.hpp"
#include "stice/stun/attributes.hpp"

#include "stice/log.hpp"
#include "stice/net/platform.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#endif

namespace stice::stun {

namespace {

// RFC 8489 §9.2.3: a 438 (Stale Nonce) may be answered with a refreshed NONCE
// a bounded number of times; a server that keeps returning 438 is treated as
// failing rather than retried forever.
constexpr int MaxAuthRetries = 2;

// Apply the REALM / NONCE / PASSWORD-ALGORITHMS challenge carried by a 401 or
// 438 response to `creds`, re-deriving the long-term keys. SHA-256 is preferred
// when the server advertises it (RFC 8489 §14.1); the MD5 form is the RFC 5389
// default when PASSWORD-ALGORITHMS is absent.
void applyChallenge(const Message &resp, const char *password, Credentials &creds) {
	std::string realm = getString(resp, AttrType::Realm);
	std::string nonce = getString(resp, AttrType::Nonce);
	if (!realm.empty()) creds.realm = realm;
	if (!nonce.empty()) creds.nonce = nonce;

	std::vector<std::uint16_t> algorithms;
	if (readPasswordAlgorithms(resp, algorithms) && !algorithms.empty()) {
		creds.algo = std::find(algorithms.begin(), algorithms.end(), PasswordAlgorithmSha256) !=
		                     algorithms.end()
		                 ? IntegrityAlgo::HmacSha256
		                 : IntegrityAlgo::HmacSha1;
	} else if (creds.algo == IntegrityAlgo::HmacSha1) {
		creds.algo = IntegrityAlgo::HmacSha1;
	}

	// RFC 8489 §9.2.4: the client must echo the server's PASSWORD-ALGORITHMS
	// verbatim in the retried request; omitting it is what a bid-down attacker
	// would do to force MD5.
	creds.passwordAlgorithms.clear();
	if (const auto *pas = resp.find(AttrType::PasswordAlgorithms))
		creds.passwordAlgorithms = pas->value;

	if (password && *password && !creds.username.empty()) {
		auto sha1Key = crypto::longTermKey(creds.username, creds.realm, password);
		creds.key.assign(sha1Key.begin(), sha1Key.end());
		auto sha256Key = crypto::longTermKeySha256(creds.username, creds.realm, password);
		creds.keySha256.assign(sha256Key.begin(), sha256Key.end());
	}
}

} // namespace

Message buildBindingRequest() {
	Message m;
	m.method = Method::Binding;
	m.cls = Class::Request;
	m.newTransactionID();
	return m;
}

std::optional<BindingResult> sendBindingRequest(net::UdpSocket &sock,
                                                const net::AddrRecord &server,
                                                std::chrono::milliseconds timeout,
                                                int maxRetransmissions,
                                                const Credentials *creds,
                                                const char *password,
                                                bool strictIntegrity) {
	const bool havePassword = password && *password;
	Credentials local;
	if (creds) local = *creds;
	// Long-term authentication needs a username and either a password to derive
	// the keys from or pre-derived keys supplied by the caller.
	const bool longTerm = creds && !local.username.empty() &&
	                      (havePassword || !local.key.empty());

	int authRetries = 0;
	bool shortTermRetried = false;
	auto start = std::chrono::steady_clock::now();

	while (true) {
		Message req = buildBindingRequest();
		// RFC 8489 §9.2.4: a negotiated non-default algorithm must be declared
		// via PASSWORD-ALGORITHM, before encode() appends MESSAGE-INTEGRITY.
		if (longTerm && local.algo == IntegrityAlgo::HmacSha256)
			addPasswordAlgorithm(req, PasswordAlgorithmSha256);
		if (!req.encode(havePassword ? password : nullptr, longTerm ? &local : nullptr, "stice")) {
			STICE_LOG_WARN("STUN binding: encode failed");
			return std::nullopt;
		}

		int retransmit = 0;
		std::chrono::milliseconds rto(500);
		bool retryAuth = false;

		while (!retryAuth) {
			int sent = sock.sendto(reinterpret_cast<const char *>(req.raw.data()), req.raw.size(),
			                       server);
			if (sent < 0) {
				STICE_LOG_WARN("STUN binding: sendto failed, errno=%d", sticeSockerrno);
				return std::nullopt;
			}

			auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
			    std::chrono::steady_clock::now() - start);
			auto remaining = timeout - elapsed;
			if (remaining <= std::chrono::milliseconds(0)) return std::nullopt;
			auto wait = std::min(rto, remaining);

			pollfd pfd{};
			pfd.fd = sock.handle();
			pfd.events = POLLIN;
			int n = sticePoll(&pfd, 1, static_cast<int>(wait.count()));
			if (n < 0) {
				if (sticeSockerrno == STICE_SEINTR) continue;
				return std::nullopt;
			}
			if (n > 0 && (pfd.revents & POLLIN)) {
				// RFC 8489 §14: a STUN message may be up to 64 KiB (the length
				// field is 16 bits). A fixed 1500-byte buffer silently truncated
				// larger responses, so decode() rejected them as malformed.
				std::vector<unsigned char> buf(65536);
				net::AddrRecord from;
				int len = sock.recvfrom(reinterpret_cast<char *>(buf.data()),
				                       static_cast<int>(buf.size()), from);
				if (len > 0 && Message::isMessage(buf.data(), static_cast<std::size_t>(len))) {
					Message resp;
					if (!resp.decode(buf.data(), static_cast<std::size_t>(len))) continue;
					if (resp.method != Method::Binding) continue;
					// RFC 8489 §8.2/§11.2.3: a received message carrying
					// FINGERPRINT with a bad CRC MUST be discarded.
					if (!resp.checkFingerprint(true)) continue;
					if (std::memcmp(resp.transactionID.data(), req.transactionID.data(),
					                TransactionIDSize) != 0)
						continue;

					BindingResult r;
					r.transactionID = resp.transactionID;

					if (resp.cls == Class::SuccessResponse) {
						// RFC 8489 §9.2: with credentials in play a success
						// response MUST carry MESSAGE-INTEGRITY (or the SHA-256
						// form) and it MUST verify. A response that fails is
						// rejected instead of being trusted.
						bool integrityOk = true;
						if (longTerm) {
							integrityOk = resp.checkIntegrityDual(
							    local.key.data(), local.key.size(), local.keySha256.data(),
							    local.keySha256.size(), !strictIntegrity);
						} else if (havePassword) {
							integrityOk = resp.checkIntegrity(
							    reinterpret_cast<const unsigned char *>(password),
							    std::strlen(password), !strictIntegrity);
						}
						if (!integrityOk) {
							STICE_LOG_WARN("STUN binding: response integrity check failed");
							r.errorCode = StunErrorUnauthenticated;
							r.errorReason = "response integrity check failed";
							return r;
						}

						if (!readXorAddress(resp, AttrType::XorMappedAddress, r.reflexiveAddr,
						                    resp.transactionID)) {
							// Fall back to plain MAPPED-ADDRESS.
							if (!readMappedAddress(resp, r.reflexiveAddr)) {
								STICE_LOG_WARN(
								    "STUN binding: response missing XOR-MAPPED-ADDRESS");
								return std::nullopt;
							}
						}
						return r;
					}

					if (resp.cls != Class::ErrorResponse) continue;

					int code = 0;
					std::string reason;
					if (!readErrorCode(resp, code, reason)) code = StunErrorServerError;
					r.errorCode = code;
					r.errorReason = reason.empty() ? errorReason(code) : reason;

					if (code == StunErrorUnauthenticated) {
						// 401: authenticate and retry with a fresh transaction.
						if (longTerm) {
							if (authRetries >= MaxAuthRetries) {
								STICE_LOG_WARN("STUN binding: still unauthenticated after %d retries",
								               authRetries);
								return r;
							}
							applyChallenge(resp, password, local);
							++authRetries;
							retryAuth = true;
							break;
						}
						if (havePassword && !shortTermRetried) {
							shortTermRetried = true;
							retryAuth = true;
							break;
						}
						return r;
					}

					if (code == StunErrorStaleNonce && longTerm) {
						if (authRetries >= MaxAuthRetries) {
							STICE_LOG_WARN("STUN binding: stale nonce persisted after %d retries",
							               authRetries);
							return r;
						}
						applyChallenge(resp, password, local);
						++authRetries;
						retryAuth = true;
						break;
					}

					if (code == StunErrorUnknownAttribute) {
						// RFC 8489 §6.3.4: the server rejected attributes we sent
						// that it does not understand. Surface them for diagnosis.
						std::vector<std::uint16_t> unknown;
						readUnknownAttributes(resp, unknown);
						STICE_LOG_WARN("STUN binding: server returned 420 with %zu unknown attribute(s)",
						               unknown.size());
					}
					if (code == StunErrorTryAlternate) {
						// RFC 8489 §14.11: 300 carries the preferred server address.
						net::AddrRecord alt;
						if (readAlternateServer(resp, alt)) {
							r.hasAlternateServer = true;
							r.alternateServer = alt;
							STICE_LOG_INFO("STUN binding: 300 Try Alternate -> %s",
							               alt.toString().c_str());
						}
					}
					return r;
				}
			}

			// No response in this RTO window: retransmit or give up.
			// RFC 8489 §6.2.1: double the RTO but cap it at 8 s.
			if (retransmit >= maxRetransmissions) return std::nullopt;
			++retransmit;
			rto = std::min(rto * 2, std::chrono::milliseconds(8000));
		}
	}
}

} // namespace stice::stun
