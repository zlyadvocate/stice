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

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#endif

namespace stice::stun {

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
                                                int maxRetransmissions) {
	Message req = buildBindingRequest();
	if (!req.encode(nullptr, nullptr, "stice")) {
		STICE_LOG_WARN("STUN binding: encode failed");
		return std::nullopt;
	}

	auto start = std::chrono::steady_clock::now();
	int retransmit = 0;
	std::chrono::milliseconds rto(500);

	while (true) {
		int sent = sock.sendto(reinterpret_cast<const char *>(req.raw.data()), req.raw.size(), server);
		if (sent < 0) {
			STICE_LOG_WARN("STUN binding: sendto failed, errno=%d", sticeSockerrno);
			return std::nullopt;
		}

		// Poll for response with current RTO.
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
			unsigned char buf[1500];
			net::AddrRecord from;
			int len = sock.recvfrom(reinterpret_cast<char *>(buf), sizeof(buf), from);
			if (len > 0 && Message::isMessage(buf, static_cast<std::size_t>(len))) {
				Message resp;
				if (!resp.decode(buf, static_cast<std::size_t>(len))) continue;
				if (resp.method != Method::Binding) continue;
				if (resp.cls != Class::SuccessResponse) continue;
				if (std::memcmp(resp.transactionID.data(), req.transactionID.data(),
				                TransactionIDSize) != 0)
					continue;
				BindingResult r;
				r.transactionID = resp.transactionID;
				if (!readXorAddress(resp, AttrType::XorMappedAddress, r.reflexiveAddr,
				                    resp.transactionID)) {
					// Fall back to plain MAPPED-ADDRESS.
					if (!readMappedAddress(resp, r.reflexiveAddr)) {
						STICE_LOG_WARN("STUN binding: response missing XOR-MAPPED-ADDRESS");
						return std::nullopt;
					}
				}
				return r;
			}
		}

		// No response in this RTO window: retransmit or give up.
		if (retransmit >= maxRetransmissions) return std::nullopt;
		++retransmit;
		rto *= 2;
	}
}

} // namespace stice::stun
