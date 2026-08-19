// SPDX-License-Identifier: MPL-2.0
// stice STUN client. Sends a Binding request to a STUN server and returns
// the server-reflexive address. Used by the ICE agent to gather srflx
// candidates. Ported from libjuice's STUN-gather path in agent.c and
// pion-stun's client.go.

#ifndef STICE_STUN_CLIENT_HPP
#define STICE_STUN_CLIENT_HPP

#include "stice/net/addr.hpp"
#include "stice/net/udp.hpp"
#include "stice/stun/message.hpp"

#include <chrono>
#include <optional>

namespace stice::stun {

struct BindingResult {
	net::AddrRecord reflexiveAddr;
	std::array<unsigned char, TransactionIDSize> transactionID{};
};

// Send a STUN Binding request to `server` via `sock` and wait up to
// `timeout` for a success response. Returns the XOR-MAPPED-ADDRESS
// (or MAPPED-ADDRESS) on success. Implements RFC 5780 retransmission
// (RTO 500ms, doubling backoff, up to `maxRetransmissions` resends).
// `sock` is the same UDP socket the ICE agent will use for checks, so
// the reflexive address is valid for that 5-tuple.
std::optional<BindingResult> sendBindingRequest(net::UdpSocket &sock,
                                                const net::AddrRecord &server,
                                                std::chrono::milliseconds timeout =
                                                    std::chrono::milliseconds(5000),
                                                int maxRetransmissions = 5);

// Build a Binding request with a fresh transaction ID. Exposed so the ICE
// agent can build connectivity-check requests with extra attributes
// (USERNAME, PRIORITY, ICE-CONTROLLING, USE-CANDIDATE) before encoding.
Message buildBindingRequest();

} // namespace stice::stun

#endif
