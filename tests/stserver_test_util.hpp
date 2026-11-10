// SPDX-License-Identifier: MPL-2.0
// Shared in-process stserver test harness.
//
// These helpers start a real TurnServer inside the test process (no external
// stserver needed) and drive it over UDP with raw STUN messages. They are used
// by the server protocol tests (test_stserver_auth_order / _protocol / _6062).
//
// The header is intentionally header-only and is NOT compiled as a test: the
// CMake glob only picks up tests/*.cpp.

#ifndef STICE_TESTS_STSERVER_TEST_UTIL_HPP
#define STICE_TESTS_STSERVER_TEST_UTIL_HPP

#include <catch2/catch_test_macros.hpp>

#include "stice/crypto.hpp"
#include "stice/log.hpp"
#include "stice/net/addr.hpp"
#include "stice/net/udp.hpp"
#include "stice/stserver/config.hpp"
#include "stice/stserver/turn_server.hpp"
#include "stice/stun/attributes.hpp"
#include "stice/stun/message.hpp"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace stice_test {

using namespace std::chrono_literals;
using stice::net::AddrRecord;
using stice::net::UdpSocket;
using stice::net::UdpSocketConfig;
using stice::stun::AttrType;
using stice::stun::Class;
using stice::stun::Message;
using stice::stun::Method;

inline constexpr const char *kUser = "testuser";
inline constexpr const char *kPassword = "123456";
inline constexpr const char *kRealm = "stice-test";

// Server knobs the protocol tests need to drive (ports, quotas, short
// permission/channel lifetimes).
struct ServerOptions {
	std::uint16_t firstPort = 13520;
	std::uint16_t lastPort = 13560;
	int maxAllocations = 2000;
	std::uint32_t allocationLifetime = 600;
	std::uint32_t maxAllocationLifetime = 3600;
	std::uint32_t permissionLifetimeSec = 300;
	std::uint32_t channelLifetimeSec = 600;
	std::uint16_t relayPortBegin = 41000;
	std::uint16_t relayPortEnd = 41999;
	int workerCount = 1;
	// Opt-in RFC 8489 §9.2.4 anti-bid-down enforcement (PASSWORD-ALGORITHMS
	// echo). Off by default like the production server, because browsers do not
	// echo the attribute; the protocol tests that exercise the chain enable it.
	bool passwordAlgorithms = false;
};

inline AddrRecord loopback(std::uint16_t port) {
	AddrRecord r{};
	REQUIRE(stice::net::parseAddr("127.0.0.1", port, r.addr, r.len));
	r.socktype = SOCK_DGRAM;
	return r;
}

// Owns a TurnServer plus its run() thread.
struct TestServer {
	std::unique_ptr<stserver::TurnServer> server;
	std::thread thread;
	std::uint16_t port = 0;

	~TestServer() {
		if (server) server->stop();
		if (thread.joinable()) thread.join();
	}

	bool start(const ServerOptions &opt = {}) {
		for (std::uint16_t p = opt.firstPort; p <= opt.lastPort; ++p) {
			auto srv = std::make_unique<stserver::TurnServer>();
			Config cfg;
			cfg.listenAddress = "127.0.0.1";
			cfg.udpPort = p;
			cfg.tcpPort = p;
			cfg.realm = kRealm;
			cfg.users = {{kUser, kPassword}};
			cfg.workerCount = opt.workerCount;
			cfg.maxAllocations = opt.maxAllocations;
			cfg.allocationLifetime = opt.allocationLifetime;
			cfg.maxAllocationLifetime = opt.maxAllocationLifetime;
			cfg.permissionLifetimeSec = opt.permissionLifetimeSec;
			cfg.channelLifetimeSec = opt.channelLifetimeSec;
			cfg.relayPortBegin = opt.relayPortBegin;
			cfg.relayPortEnd = opt.relayPortEnd;
			cfg.passwordAlgorithms = opt.passwordAlgorithms;
			if (!srv->init(cfg)) continue;
			server = std::move(srv);
			port = p;
			thread = std::thread([this] { server->run(); });
			return true;
		}
		return false;
	}
};

// Send `req` and wait for a response carrying the same transaction ID.
// Retransmits while waiting so a datagram lost to a still-warming-up server
// does not fail the test.
inline bool transact(UdpSocket &sock, const AddrRecord &dst, const Message &req, Message &resp,
                     int timeoutMs = 5000) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
	auto nextSend = std::chrono::steady_clock::now();
	char buf[4096];
	while (std::chrono::steady_clock::now() < deadline) {
		if (std::chrono::steady_clock::now() >= nextSend) {
			sock.sendto(reinterpret_cast<const char *>(req.raw.data()),
			            static_cast<std::size_t>(req.raw.size()), dst);
			nextSend = std::chrono::steady_clock::now() + 150ms;
		}
		AddrRecord from{};
		int n = sock.recvfrom(buf, sizeof(buf), from);
		if (n <= 0) {
			std::this_thread::sleep_for(5ms);
			continue;
		}
		Message m;
		if (!m.decode(reinterpret_cast<const unsigned char *>(buf), static_cast<std::size_t>(n)))
			continue;
		if (m.transactionID != req.transactionID) continue;
		resp = m;
		return true;
	}
	return false;
}

inline int errorCodeOf(const Message &m) {
	int code = 0;
	std::string reason;
	if (!stice::stun::readErrorCode(m, code, reason)) return 0;
	return code;
}

inline Message makeBindingRequest() {
	Message req;
	req.method = Method::Binding;
	req.cls = Class::Request;
	req.newTransactionID();
	REQUIRE(req.encode(nullptr, nullptr, nullptr));
	return req;
}

// Build an Allocate request. When `creds` is null the message is unauthenticated
// (used to obtain the 401 challenge).
inline Message makeAllocateRequest(bool withUnknownAttribute,
                                   const stice::stun::Credentials *creds,
                                   std::uint8_t proto = 17) {
	Message req;
	req.method = Method::Allocate;
	req.cls = Class::Request;
	req.newTransactionID();
	stice::stun::addRequestedTransport(req, proto);
	if (withUnknownAttribute)
		req.addAttribute(static_cast<AttrType>(0x7777), nullptr, 0);
	if (creds)
		REQUIRE(req.encode(kPassword, creds, nullptr));
	else
		REQUIRE(req.encode(nullptr, nullptr, nullptr));
	return req;
}

inline stice::stun::Credentials credentialsFor(const Message &challenge, bool sha256 = false) {
	stice::stun::Credentials creds;
	creds.username = kUser;
	creds.realm = stice::stun::getString(challenge, AttrType::Realm);
	creds.nonce = stice::stun::getString(challenge, AttrType::Nonce);
	// RFC 8489 §9.2.4: the challenge advertises PASSWORD-ALGORITHMS and the
	// nonce cookie declares the feature, so a compliant client must echo the
	// list byte-for-byte in the authenticated request.
	if (const auto *pas = challenge.find(AttrType::PasswordAlgorithms))
		creds.passwordAlgorithms = pas->value;
	auto key = stice::crypto::longTermKey(creds.username, creds.realm, kPassword);
	creds.key.assign(key.begin(), key.end());
	if (sha256) {
		auto key256 = stice::crypto::longTermKeySha256(creds.username, creds.realm, kPassword);
		creds.keySha256.assign(key256.begin(), key256.end());
		creds.algo = stice::stun::IntegrityAlgo::HmacSha256;
	}
	return creds;
}

// A socket plus a running server known to be accepting requests.
struct Fixture {
	TestServer srv;
	UdpSocket sock;
	AddrRecord serverAddr;

	explicit Fixture(const ServerOptions &opt = {}) {
		stice_set_log_level(STICE_LOG_LEVEL_ERROR);
		REQUIRE(srv.start(opt));
		serverAddr = loopback(srv.port);
		UdpSocketConfig cfg;
		cfg.bindAddress = "127.0.0.1";
		sock = UdpSocket::create(cfg);
		REQUIRE(sock.valid());
		stice::net::setNonBlocking(sock.handle());
	}

	// Readiness probe: an anonymous Binding is answered without credentials.
	void waitReady() {
		Message binding = makeBindingRequest();
		Message resp;
		REQUIRE(transact(sock, serverAddr, binding, resp));
		REQUIRE(resp.cls == Class::SuccessResponse);
	}

	// Authenticated Allocate. Returns the response (success or error).
	Message allocate(const stice::stun::Credentials &creds, std::uint8_t proto = 17,
	                 std::uint32_t requestedLifetime = 0) {
		Message req;
		req.method = Method::Allocate;
		req.cls = Class::Request;
		req.newTransactionID();
		stice::stun::addRequestedTransport(req, proto);
		if (requestedLifetime > 0) stice::stun::addLifetime(req, requestedLifetime);
		REQUIRE(req.encode(kPassword, &creds, nullptr));
		Message resp;
		REQUIRE(transact(sock, serverAddr, req, resp));
		return resp;
	}
};

// Obtain the long-term credential challenge for an Allocate.
inline stice::stun::Credentials obtainCredentials(Fixture &f, bool sha256 = false) {
	Message challengeReq = makeAllocateRequest(false, nullptr);
	Message challenge;
	REQUIRE(transact(f.sock, f.serverAddr, challengeReq, challenge));
	REQUIRE(challenge.cls == Class::ErrorResponse);
	REQUIRE(errorCodeOf(challenge) == stice::stun::StunErrorUnauthenticated);
	auto creds = credentialsFor(challenge, sha256);
	REQUIRE_FALSE(creds.realm.empty());
	REQUIRE_FALSE(creds.nonce.empty());
	return creds;
}

// Read XOR-RELAYED-ADDRESS from an Allocate success response.
inline AddrRecord relayedAddrOf(const Message &resp) {
	AddrRecord out{};
	REQUIRE(stice::stun::readXorAddress(resp, AttrType::XorRelayedAddress, out,
	                                    resp.transactionID));
	return out;
}

// Authenticated control request (Refresh / CreatePermission / ChannelBind /
// Connect). `build` fills the method and attributes before encoding.
template <typename BuildFn>
Message controlRequest(const stice::stun::Credentials &creds, BuildFn &&build) {
	Message req;
	req.cls = Class::Request;
	req.newTransactionID();
	build(req);
	REQUIRE(req.encode(kPassword, &creds, nullptr));
	return req;
}

inline Message makeCreatePermission(const stice::stun::Credentials &creds,
                                    const AddrRecord &peer) {
	return controlRequest(creds, [&](Message &m) {
		m.method = Method::CreatePermission;
		stice::stun::writeXorAddress(m, AttrType::XorPeerAddress, peer, m.transactionID);
	});
}

inline Message makeChannelBind(const stice::stun::Credentials &creds, std::uint16_t channel,
                               const AddrRecord &peer) {
	return controlRequest(creds, [&](Message &m) {
		m.method = Method::ChannelBind;
		stice::stun::addChannelNumber(m, channel);
		stice::stun::writeXorAddress(m, AttrType::XorPeerAddress, peer, m.transactionID);
	});
}

inline Message makeRefresh(const stice::stun::Credentials &creds, std::uint32_t lifetime) {
	return controlRequest(creds, [&](Message &m) {
		m.method = Method::Refresh;
		stice::stun::addLifetime(m, lifetime);
	});
}

// Receive one datagram on `sock` within `timeoutMs`. Returns false on timeout.
inline bool recvWithin(UdpSocket &sock, unsigned char *buf, std::size_t cap, std::size_t &outLen,
                       AddrRecord *from = nullptr, int timeoutMs = 1500) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
	while (std::chrono::steady_clock::now() < deadline) {
		AddrRecord f{};
		int n = sock.recvfrom(reinterpret_cast<char *>(buf), cap, f);
		if (n > 0) {
			outLen = static_cast<std::size_t>(n);
			if (from) *from = f;
			return true;
		}
		std::this_thread::sleep_for(5ms);
	}
	return false;
}

} // namespace stice_test

#endif // STICE_TESTS_STSERVER_TEST_UTIL_HPP
