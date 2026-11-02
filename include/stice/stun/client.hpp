// SPDX-License-Identifier: MPL-2.0
// stice STUN client. Sends a Binding request to a STUN server and returns
// the server-reflexive address. Internal diagnostic / srflx helper: the ICE
// agent's async gather path uses StunEntry transactions instead, so this
// blocking helper is not on the production gather path.
// Ported from libjuice's STUN-gather path in agent.c and pion-stun's client.go.

#ifndef STICE_STUN_CLIENT_HPP
#define STICE_STUN_CLIENT_HPP

#include "stice/net/addr.hpp"
#include "stice/net/udp.hpp"
#include "stice/stun/message.hpp"

#include <chrono>
#include <optional>
#include <string>

namespace stice::stun {

struct BindingResult {
	net::AddrRecord reflexiveAddr;
	std::array<unsigned char, TransactionIDSize> transactionID{};
	// 0 on success; otherwise the STUN error code from the response (401,
	// 420, 438, 300, ...). Error responses are surfaced instead of being
	// silently discarded, so callers can distinguish "no server" from
	// "authentication required".
	int errorCode = 0;
	std::string errorReason;
	// RFC 8489 §14.11: a 300 Try Alternate response carries ALTERNATE-SERVER.
	// Surfaced so the caller can re-issue the Binding request to the address the
	// server prefers instead of treating the redirect as a terminal failure.
	bool hasAlternateServer = false;
	net::AddrRecord alternateServer;
};

// Send a STUN Binding request to `server` via `sock` and wait up to
// `timeout` for a response. Returns the XOR-MAPPED-ADDRESS (or
// MAPPED-ADDRESS) on success, or a BindingResult carrying the STUN error
// code when the server rejected the request. Implements RFC 8489 §6.2.1
// retransmission: initial RTO 500 ms, doubling with an 8 s cap, Rc=7
// retransmissions, and the 31.5 s total transaction budget (0.5+1+2+4+8+8+8).
//
// Authentication (RFC 8489 §9.2): pass `password` for short-term
// credentials or `creds` (username + password) for long-term credentials.
// A 401 challenge is answered automatically with the REALM/NONCE from the
// response and the algorithm advertised in PASSWORD-ALGORITHMS (SHA-256
// preferred). A 438 Stale Nonce is retried with the refreshed NONCE, bounded
// by MaxNonceRetries. When credentials are supplied, a success response
// without a valid MESSAGE-INTEGRITY / MESSAGE-INTEGRITY-SHA256 is rejected
// unless `strictIntegrity` is false.
//
// `sock` is the same UDP socket the ICE agent will use for checks, so the
// reflexive address is valid for that 5-tuple.
std::optional<BindingResult> sendBindingRequest(
	net::UdpSocket &sock, const net::AddrRecord &server,
	std::chrono::milliseconds timeout = std::chrono::milliseconds(39500),
	int maxRetransmissions = 7, const Credentials *creds = nullptr,
	const char *password = nullptr, bool strictIntegrity = true);

// Build a Binding request with a fresh transaction ID. Exposed so the ICE
// agent can build connectivity-check requests with extra attributes
// (USERNAME, PRIORITY, ICE-CONTROLLING, USE-CANDIDATE) before encoding.
Message buildBindingRequest();

} // namespace stice::stun

#endif
