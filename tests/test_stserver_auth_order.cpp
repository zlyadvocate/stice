// SPDX-License-Identifier: MPL-2.0
// Regression tests for RFC 8489 §9.2.1 processing order in stserver.
//
// The RFC requires authentication to run before request processing. stserver
// used to evaluate comprehension-required attributes first, so an
// unauthenticated ALLOCATE carrying an unknown attribute got 420
// (Unknown Attribute) instead of the 401 challenge. That leaked the attribute
// table to a peer that had proved no credential, and made a misconfigured
// client report "unknown attribute" when the real cause was "not
// authenticated".
//
// These tests start a real TurnServer in-process (no external server needed)
// and drive it over UDP with raw STUN messages.

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
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using stice::net::AddrRecord;
using stice::net::UdpSocket;
using stice::net::UdpSocketConfig;
using stice::stun::AttrType;
using stice::stun::Class;
using stice::stun::Message;
using stice::stun::Method;

namespace {

// Unassigned comprehension-required attribute (< 0x8000, not in the server's
// known set). Any value would do; a fixed one makes the assertion exact.
constexpr std::uint16_t kUnknownComprehensionRequired = 0x7777;

constexpr const char *kUser = "testuser";
constexpr const char *kPassword = "123456";

AddrRecord loopback(std::uint16_t port) {
	AddrRecord r{};
	REQUIRE(stice::net::parseAddr("127.0.0.1", port, r.addr, r.len));
	r.socktype = SOCK_DGRAM;
	return r;
}

// Owns a TurnServer plus its run() thread. stop() only flips an atomic, so the
// destructor ordering matters: run() sets running_ = true as its first
// statement, and start() does not return until the server has answered a
// Binding request, which proves run() is past that point.
struct TestServer {
	std::unique_ptr<stserver::TurnServer> server;
	std::thread thread;
	std::uint16_t port = 0;

	~TestServer() {
		if (server) server->stop();
		if (thread.joinable()) thread.join();
	}

	bool start() {
		for (std::uint16_t p = 13520; p <= 13540; ++p) {
			auto srv = std::make_unique<stserver::TurnServer>();
			Config cfg;
			cfg.listenAddress = "127.0.0.1";
			cfg.udpPort = p;
			cfg.tcpPort = p;
			cfg.realm = "stice-auth-order";
			cfg.users = {{kUser, kPassword}};
			cfg.workerCount = 1;
			cfg.relayPortBegin = 41000;
			cfg.relayPortEnd = 41999;
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
bool transact(UdpSocket &sock, const AddrRecord &dst, const Message &req, Message &resp,
              int timeoutMs = 5000) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
	auto nextSend = std::chrono::steady_clock::now();
	char buf[2048];
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

int errorCodeOf(const Message &m) {
	int code = 0;
	std::string reason;
	if (!stice::stun::readErrorCode(m, code, reason)) return 0;
	return code;
}

Message makeBindingRequest() {
	Message req;
	req.method = Method::Binding;
	req.cls = Class::Request;
	req.newTransactionID();
	REQUIRE(req.encode(nullptr, nullptr, nullptr));
	return req;
}

Message makeAllocateRequest(bool withUnknownAttribute, const stice::stun::Credentials *creds) {
	Message req;
	req.method = Method::Allocate;
	req.cls = Class::Request;
	req.newTransactionID();
	stice::stun::addRequestedTransport(req, 17); // UDP
	if (withUnknownAttribute)
		req.addAttribute(static_cast<AttrType>(kUnknownComprehensionRequired), nullptr, 0);
	if (creds)
		REQUIRE(req.encode(kPassword, creds, nullptr));
	else
		REQUIRE(req.encode(nullptr, nullptr, nullptr));
	return req;
}

stice::stun::Credentials credentialsFor(const Message &challenge) {
	stice::stun::Credentials creds;
	creds.username = kUser;
	creds.realm = stice::stun::getString(challenge, AttrType::Realm);
	creds.nonce = stice::stun::getString(challenge, AttrType::Nonce);
	// RFC 8489 §9.2.4 anti-bid-down echo (the server rejects the request when
	// the advertised list is missing or altered).
	if (const auto *pas = challenge.find(AttrType::PasswordAlgorithms))
		creds.passwordAlgorithms = pas->value;
	auto key = stice::crypto::longTermKey(creds.username, creds.realm, kPassword);
	creds.key.assign(key.begin(), key.end());
	return creds;
}

struct Client {
	UdpSocket sock;
	AddrRecord serverAddr;
};

// A socket plus a server known to be accepting requests.
struct Fixture {
	TestServer srv;
	Client client;

	Fixture() {
		stice_set_log_level(STICE_LOG_LEVEL_ERROR);
		REQUIRE(srv.start());
		client.serverAddr = loopback(srv.port);
		UdpSocketConfig cfg;
		cfg.bindAddress = "127.0.0.1";
		client.sock = UdpSocket::create(cfg);
		REQUIRE(client.sock.valid());
		stice::net::setNonBlocking(client.sock.handle());
	}
};

} // namespace

TEST_CASE("stserver challenges unauthenticated ALLOCATE before checking attributes",
          "[stserver][auth]") {
	Fixture f;

	// Readiness probe: an anonymous Binding is answered without credentials.
	Message binding = makeBindingRequest();
	Message bindingResp;
	REQUIRE(transact(f.client.sock, f.client.serverAddr, binding, bindingResp));
	REQUIRE(bindingResp.cls == Class::SuccessResponse);

	// The regression: ALLOCATE with an unknown comprehension-required attribute
	// and no MESSAGE-INTEGRITY must be rejected with 401 (RFC 8489 §9.2.1),
	// not 420. The 401 also has to carry REALM/NONCE so the client can retry.
	Message allocate = makeAllocateRequest(true, nullptr);
	Message resp;
	REQUIRE(transact(f.client.sock, f.client.serverAddr, allocate, resp));
	REQUIRE(resp.cls == Class::ErrorResponse);
	REQUIRE(errorCodeOf(resp) == stice::stun::StunErrorUnauthenticated);
	REQUIRE_FALSE(stice::stun::getString(resp, AttrType::Realm).empty());
	REQUIRE_FALSE(stice::stun::getString(resp, AttrType::Nonce).empty());
	// A 420 would list the offending type; the 401 challenge must not.
	REQUIRE(resp.find(AttrType::UnknownAttributes) == nullptr);

	// Same request without the unknown attribute: also 401, so the earlier
	// result is not an artifact of the attribute being present.
	Message plain = makeAllocateRequest(false, nullptr);
	Message plainResp;
	REQUIRE(transact(f.client.sock, f.client.serverAddr, plain, plainResp));
	REQUIRE(plainResp.cls == Class::ErrorResponse);
	REQUIRE(errorCodeOf(plainResp) == stice::stun::StunErrorUnauthenticated);
}

TEST_CASE("stserver returns 420 for unknown attributes only after authentication",
          "[stserver][auth]") {
	Fixture f;

	// Obtain the long-term credential challenge.
	Message challengeReq = makeAllocateRequest(false, nullptr);
	Message challenge;
	REQUIRE(transact(f.client.sock, f.client.serverAddr, challengeReq, challenge));
	REQUIRE(challenge.cls == Class::ErrorResponse);
	REQUIRE(errorCodeOf(challenge) == stice::stun::StunErrorUnauthenticated);

	auto creds = credentialsFor(challenge);
	REQUIRE_FALSE(creds.realm.empty());
	REQUIRE_FALSE(creds.nonce.empty());

	// Authenticated request carrying the unknown attribute: authentication
	// succeeds, so processing reaches the attribute check and answers 420
	// listing exactly the offending type.
	Message withUnknown = makeAllocateRequest(true, &creds);
	Message resp;
	REQUIRE(transact(f.client.sock, f.client.serverAddr, withUnknown, resp));
	REQUIRE(resp.cls == Class::ErrorResponse);
	REQUIRE(errorCodeOf(resp) == stice::stun::StunErrorUnknownAttribute);
	std::vector<std::uint16_t> unknown;
	REQUIRE(stice::stun::readUnknownAttributes(resp, unknown));
	REQUIRE(unknown.size() == 1);
	REQUIRE(unknown[0] == kUnknownComprehensionRequired);

	// Control: the same credentials with no unknown attribute allocate
	// successfully, proving the 420 above came from the attribute and not from
	// a credential/verification failure.
	Message clean = makeAllocateRequest(false, &creds);
	Message cleanResp;
	REQUIRE(transact(f.client.sock, f.client.serverAddr, clean, cleanResp));
	REQUIRE(cleanResp.cls == Class::SuccessResponse);
	REQUIRE(cleanResp.find(AttrType::XorRelayedAddress) != nullptr);
}
