// SPDX-License-Identifier: MPL-2.0
// In-process stserver protocol regression (RFC 8489 §9.2.4, RFC 8656 §7/§9/§10).
//
// Every case starts a real TurnServer inside the test process and drives it
// with raw STUN/TURN messages over UDP, so the server's error-code and
// lifetime branches are covered without an external stserver or coturn.
//
// Covered report IDs:
//   G-STUN-3  MI present but REALM/NONCE/USERNAME missing -> 400
//   G-STUN-4  PASSWORD-ALGORITHM not in PASSWORD-ALGORITHMS -> 400
//   G-STUN-4b PASSWORD-ALGORITHMS echo missing/rewritten -> 400 (anti-bid-down)
//   G-STUN-5  response carries exactly one integrity attribute
//   G-STUN-7  401/438 carry REALM + NONCE + PASSWORD-ALGORITHMS
//   G-TURN-1  442 / 440 / 420 on Allocate
//   G-TURN-2  437 on a second Allocate over the same 5-tuple
//   G-TURN-3  486 quota / 508 relay capacity
//   G-TURN-4  lifetime negotiation (default / request / clamp / Refresh 0)
//   G-TURN-5  permission expiry drops inbound peer data
//   G-TURN-6  channel expiry drops ChannelData
//   G-TURN-7  permission is per peer IP, not per peer port
//   G-TURN-8  large payload passthrough (Send indication + ChannelData)
//   G-TURN-10 same client IP, different source port -> isolated allocations

#include "stserver_test_util.hpp"

#include "stice/crypto.hpp"
#include "stice/turn/channeldata.hpp"
#include "stice/turn/turn.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <string>
#include <thread>
#include <vector>

using namespace stice_test;

namespace {

Message decodeDatagram(const unsigned char *data, std::size_t size) {
	Message m;
	REQUIRE(m.decode(data, size));
	return m;
}

// Wait for one datagram on the client socket. Returns the decoded message.
bool recvMessage(UdpSocket &sock, Message &out, int timeoutMs = 1500) {
	std::array<unsigned char, 8192> buf{};
	std::size_t len = 0;
	if (!recvWithin(sock, buf.data(), buf.size(), len, nullptr, timeoutMs)) return false;
	if (!out.decode(buf.data(), len)) return false;
	return true;
}

// True when no datagram arrives within the window.
bool quiet(UdpSocket &sock, int timeoutMs) {
	std::array<unsigned char, 8192> buf{};
	std::size_t len = 0;
	return !recvWithin(sock, buf.data(), buf.size(), len, nullptr, timeoutMs);
}

// A peer socket bound to 127.0.0.1 with a known address record.
struct Peer {
	UdpSocket sock;
	AddrRecord addr{};

	Peer() {
		UdpSocketConfig cfg;
		cfg.bindAddress = "127.0.0.1";
		sock = UdpSocket::create(cfg);
		REQUIRE(sock.valid());
		REQUIRE(sock.boundAddr(addr));
		addr.socktype = SOCK_DGRAM;
		stice::net::setNonBlocking(sock.handle());
	}
};

// Allocate with a full custom attribute set.
Message allocateWith(const stice::stun::Credentials &creds, std::uint8_t proto,
                     const std::function<void(Message &)> &extra) {
	Message req;
	req.method = Method::Allocate;
	req.cls = Class::Request;
	req.newTransactionID();
	stice::stun::addRequestedTransport(req, proto);
	if (extra) extra(req);
	REQUIRE(req.encode(kPassword, &creds, nullptr));
	return req;
}

std::uint32_t lifetimeOf(const Message &m) {
	std::uint32_t v = 0;
	REQUIRE(stice::stun::readLifetime(m, v));
	return v;
}

} // namespace

// ---- G-STUN-3: missing long-term credential attributes ---------------------

TEST_CASE("stserver answers 400 when MESSAGE-INTEGRITY lacks REALM or NONCE",
          "[stserver][stun][protocol]") {
	Fixture f;
	f.waitReady();
	auto creds = obtainCredentials(f);

	SECTION("missing REALM") {
		auto broken = creds;
		broken.realm.clear();
		Message req = allocateWith(broken, 17, nullptr);
		Message resp;
		REQUIRE(transact(f.sock, f.serverAddr, req, resp));
		REQUIRE(resp.cls == Class::ErrorResponse);
		REQUIRE(errorCodeOf(resp) == stice::stun::StunErrorBadRequest);
		// 400 is a plain error, not a credential challenge.
		REQUIRE(stice::stun::getString(resp, AttrType::Realm).empty());
		REQUIRE(stice::stun::getString(resp, AttrType::Nonce).empty());
	}

	SECTION("missing NONCE") {
		auto broken = creds;
		broken.nonce.clear();
		Message req = allocateWith(broken, 17, nullptr);
		Message resp;
		REQUIRE(transact(f.sock, f.serverAddr, req, resp));
		REQUIRE(resp.cls == Class::ErrorResponse);
		REQUIRE(errorCodeOf(resp) == stice::stun::StunErrorBadRequest);
	}

	SECTION("missing USERNAME") {
		auto broken = creds;
		broken.username.clear();
		Message req = allocateWith(broken, 17, nullptr);
		Message resp;
		REQUIRE(transact(f.sock, f.serverAddr, req, resp));
		REQUIRE(resp.cls == Class::ErrorResponse);
		REQUIRE(errorCodeOf(resp) == stice::stun::StunErrorBadRequest);
	}
}

// ---- G-STUN-4: PASSWORD-ALGORITHM must be advertised -----------------------

TEST_CASE("stserver answers 400 for an unadvertised PASSWORD-ALGORITHM",
          "[stserver][stun][protocol]") {
	ServerOptions opt;
	opt.passwordAlgorithms = true;
	Fixture f(opt);
	f.waitReady();
	auto creds = obtainCredentials(f);

	Message req = allocateWith(creds, 17, [](Message &m) {
		stice::stun::addPasswordAlgorithm(m, 0x0003); // not MD5(1) / SHA-256(2)
	});
	Message resp;
	REQUIRE(transact(f.sock, f.serverAddr, req, resp));
	REQUIRE(resp.cls == Class::ErrorResponse);
	REQUIRE(errorCodeOf(resp) == stice::stun::StunErrorBadRequest);

	// Control: the advertised algorithms are accepted. Each attempt uses a
	// fresh source port so it is a new 5-tuple (a second Allocate on the same
	// 5-tuple would be 437).
	for (std::uint16_t algo : {stice::stun::PasswordAlgorithmMd5,
	                           stice::stun::PasswordAlgorithmSha256}) {
		auto okCreds = creds;
		if (algo == stice::stun::PasswordAlgorithmSha256) {
			okCreds.algo = stice::stun::IntegrityAlgo::HmacSha256;
			auto k = stice::crypto::longTermKeySha256(kUser, kRealm, kPassword);
			okCreds.keySha256.assign(k.begin(), k.end());
		}
		UdpSocketConfig cfg;
		cfg.bindAddress = "127.0.0.1";
		UdpSocket sock = UdpSocket::create(cfg);
		REQUIRE(sock.valid());
		stice::net::setNonBlocking(sock.handle());
		Message ok = allocateWith(okCreds, 17, [&](Message &m) {
			stice::stun::addPasswordAlgorithm(m, algo);
		});
		Message okResp;
		REQUIRE(transact(sock, f.serverAddr, ok, okResp));
		REQUIRE(okResp.cls == Class::SuccessResponse);
	}
}

// ---- G-STUN-4b: §9.2.4 anti-bid-down chain --------------------------------

// RFC 8489 §9.2.4 checks 2/3: once the 401 challenge advertised
// PASSWORD-ALGORITHMS (and the nonce cookie declares the feature), an
// authenticated request MUST repeat the list unchanged. Dropping it is exactly
// what an on-path attacker does to force MD5, so the server must reject it.
TEST_CASE("stserver enforces the PASSWORD-ALGORITHMS echo (anti-bid-down)",
          "[stserver][stun][protocol]") {
	ServerOptions opt;
	opt.passwordAlgorithms = true;
	Fixture f(opt);
	f.waitReady();
	auto creds = obtainCredentials(f);
	REQUIRE_FALSE(creds.passwordAlgorithms.empty());

	SECTION("missing echo is rejected with 400") {
		auto stripped = creds;
		stripped.passwordAlgorithms.clear();
		Message req = allocateWith(stripped, 17, nullptr);
		Message wire;
		REQUIRE(wire.decode(req.raw.data(), req.raw.size()));
		REQUIRE(wire.find(AttrType::PasswordAlgorithms) == nullptr);
		Message resp;
		REQUIRE(transact(f.sock, f.serverAddr, req, resp));
		REQUIRE(resp.cls == Class::ErrorResponse);
		REQUIRE(errorCodeOf(resp) == stice::stun::StunErrorBadRequest);
	}

	SECTION("rewritten list is rejected with 400") {
		auto tampered = creds;
		// MD5 only: the classic bid-down rewrite.
		tampered.passwordAlgorithms =
		    stice::stun::encodePasswordAlgorithms({stice::stun::PasswordAlgorithmMd5});
		Message req = allocateWith(tampered, 17, nullptr);
		Message resp;
		REQUIRE(transact(f.sock, f.serverAddr, req, resp));
		REQUIRE(resp.cls == Class::ErrorResponse);
		REQUIRE(errorCodeOf(resp) == stice::stun::StunErrorBadRequest);
	}

	SECTION("exact echo is accepted") {
		Message req = allocateWith(creds, 17, nullptr);
		Message wire;
		REQUIRE(wire.decode(req.raw.data(), req.raw.size()));
		const auto *pas = wire.find(AttrType::PasswordAlgorithms);
		REQUIRE(pas != nullptr);
		REQUIRE(pas->value == creds.passwordAlgorithms);
		Message resp;
		REQUIRE(transact(f.sock, f.serverAddr, req, resp));
		REQUIRE(resp.cls == Class::SuccessResponse);
	}
}

// ---- G-STUN-5: a response carries at most one integrity attribute ----------

TEST_CASE("stserver mirrors MESSAGE-INTEGRITY-SHA256 and emits only one integrity attribute",
          "[stserver][stun][protocol]") {
	Fixture f;
	f.waitReady();
	auto creds = obtainCredentials(f, /*sha256=*/true);

	Message req = f.allocate(creds);
	REQUIRE(req.cls == Class::SuccessResponse);

	// RFC 8489 §9.2.4: only one of MI / MI-SHA256 may appear.
	REQUIRE(req.find(AttrType::MessageIntegritySha256) != nullptr);
	REQUIRE(req.find(AttrType::MessageIntegrity) == nullptr);

	// The SHA-256 HMAC must verify against the long-term SHA-256 key.
	auto key = stice::crypto::longTermKey(kUser, kRealm, kPassword);
	auto key256 = stice::crypto::longTermKeySha256(kUser, kRealm, kPassword);
	REQUIRE(req.checkIntegrityDual(key.data(), key.size(), key256.data(), key256.size()));

	// And the legacy MD5 key must NOT validate a SHA-256-only message.
	REQUIRE_FALSE(req.checkIntegrityDual(key.data(), key.size(), nullptr, 0));
}

// ---- G-STUN-7: challenge/stale-nonce contents ------------------------------

TEST_CASE("stserver 401 and 438 carry REALM, NONCE and PASSWORD-ALGORITHMS",
          "[stserver][stun][protocol]") {
	ServerOptions opt;
	opt.passwordAlgorithms = true;
	Fixture f(opt);
	f.waitReady();

	Message challenge;
	Message probe = makeAllocateRequest(false, nullptr);
	REQUIRE(transact(f.sock, f.serverAddr, probe, challenge));
	REQUIRE(challenge.cls == Class::ErrorResponse);
	REQUIRE(errorCodeOf(challenge) == stice::stun::StunErrorUnauthenticated);

	const std::string realm = stice::stun::getString(challenge, AttrType::Realm);
	const std::string nonce = stice::stun::getString(challenge, AttrType::Nonce);
	REQUIRE_FALSE(realm.empty());
	REQUIRE_FALSE(nonce.empty());
	// RFC 8489 §9.1.1 / §14.10: the nonce starts with the 13-character cookie
	// "obMatJos2" + base64 of the 24-bit Security Features, where bit 0
	// (0x800000) declares PASSWORD-ALGORITHMS support.
	REQUIRE(nonce.rfind(stice::stun::makeNonceCookie(
	                        stice::stun::SecurityFeaturePasswordAlgorithms) + ":",
	                    0) == 0);
	REQUIRE(stice::stun::nonceHasPasswordAlgorithmsFeature(nonce));

	std::vector<std::uint16_t> algos;
	REQUIRE(stice::stun::readPasswordAlgorithms(challenge, algos));
	REQUIRE(std::find(algos.begin(), algos.end(), stice::stun::PasswordAlgorithmMd5) !=
	        algos.end());
	REQUIRE(std::find(algos.begin(), algos.end(), stice::stun::PasswordAlgorithmSha256) !=
	        algos.end());

	// 438 (stale nonce) must repeat the full challenge material, including the
	// PASSWORD-ALGORITHMS list, so the client can retry in place.
	auto creds = credentialsFor(challenge);
	creds.nonce = "stale-nonce";
	Message stale = allocateWith(creds, 17, nullptr);
	Message staleResp;
	REQUIRE(transact(f.sock, f.serverAddr, stale, staleResp));
	REQUIRE(staleResp.cls == Class::ErrorResponse);
	REQUIRE(errorCodeOf(staleResp) == stice::stun::StunErrorStaleNonce);
	REQUIRE_FALSE(stice::stun::getString(staleResp, AttrType::Realm).empty());
	REQUIRE_FALSE(stice::stun::getString(staleResp, AttrType::Nonce).empty());
	algos.clear();
	REQUIRE(stice::stun::readPasswordAlgorithms(staleResp, algos));
	REQUIRE(algos.size() == 2);
}

// ---- G-STUN-8: default-off PASSWORD-ALGORITHMS (browser interop) -----------

// The §9.2.4 echo chain is opt-in. With the default config the server must not
// advertise PASSWORD-ALGORITHMS at all: browsers do not echo the attribute, so
// an unconditional advertisement (and the matching omission rejection) made
// every browser TURN allocation fail with 400.
TEST_CASE("stserver does not advertise PASSWORD-ALGORITHMS by default",
          "[stserver][stun][protocol]") {
	Fixture f;
	f.waitReady();

	Message challenge;
	Message probe = makeAllocateRequest(false, nullptr);
	REQUIRE(transact(f.sock, f.serverAddr, probe, challenge));
	REQUIRE(challenge.cls == Class::ErrorResponse);
	REQUIRE(errorCodeOf(challenge) == stice::stun::StunErrorUnauthenticated);

	REQUIRE(challenge.find(AttrType::PasswordAlgorithms) == nullptr);
	const std::string nonce = stice::stun::getString(challenge, AttrType::Nonce);
	REQUIRE_FALSE(nonce.empty());
	REQUIRE_FALSE(stice::stun::nonceHasPasswordAlgorithmsFeature(nonce));

	// A client that behaves like a browser (no echo) must still allocate.
	auto creds = obtainCredentials(f);
	REQUIRE(creds.passwordAlgorithms.empty());
	Message resp = f.allocate(creds);
	REQUIRE(resp.cls == Class::SuccessResponse);
}

// ---- G-TURN-1: 442 / 440 / 420 on Allocate --------------------------------

TEST_CASE("stserver Allocate rejects unsupported transport with 442",
          "[stserver][turn][protocol]") {
	Fixture f;
	f.waitReady();
	auto creds = obtainCredentials(f);

	for (std::uint8_t proto : {static_cast<std::uint8_t>(1), static_cast<std::uint8_t>(2),
	                           static_cast<std::uint8_t>(33)}) {
		Message req = allocateWith(creds, proto, nullptr);
		Message resp;
		REQUIRE(transact(f.sock, f.serverAddr, req, resp));
		REQUIRE(resp.cls == Class::ErrorResponse);
		REQUIRE(errorCodeOf(resp) == stice::stun::StunErrorUnsupportedTransport);
	}
}

TEST_CASE("stserver Allocate rejects an unsupported address family with 440",
          "[stserver][turn][protocol]") {
	Fixture f; // listens on 127.0.0.1, so the relay is IPv4
	f.waitReady();
	auto creds = obtainCredentials(f);

	Message req = allocateWith(creds, 17, [](Message &m) {
		stice::stun::addRequestedAddressFamily(m, 0x02); // IPv6 on an IPv4 relay
	});
	Message resp;
	REQUIRE(transact(f.sock, f.serverAddr, req, resp));
	REQUIRE(resp.cls == Class::ErrorResponse);
	REQUIRE(errorCodeOf(resp) == stice::stun::StunErrorAddressFamilyNotSupported);

	// The matching family is accepted.
	Message ok = allocateWith(creds, 17, [](Message &m) {
		stice::stun::addRequestedAddressFamily(m, 0x01);
	});
	Message okResp;
	REQUIRE(transact(f.sock, f.serverAddr, ok, okResp));
	REQUIRE(okResp.cls == Class::SuccessResponse);
}

TEST_CASE("stserver Allocate rejects unimplemented TURN attributes with 420",
          "[stserver][turn][protocol]") {
	Fixture f;
	f.waitReady();
	auto creds = obtainCredentials(f);

	struct Case {
		std::uint16_t type;
		std::function<void(Message &)> add;
	};
	const std::vector<Case> cases = {
	    {0x0018, [](Message &m) { m.addAttribute(AttrType::EvenPort, nullptr, 0); }},
	    {0x001A, [](Message &m) { stice::stun::addDontFragment(m); }},
	    {0x0022,
	     [](Message &m) {
		     unsigned char token[8] = {0};
		     stice::stun::addReservationToken(m, token);
	     }},
	};

	for (const auto &c : cases) {
		Message req = allocateWith(creds, 17, c.add);
		Message resp;
		REQUIRE(transact(f.sock, f.serverAddr, req, resp));
		REQUIRE(resp.cls == Class::ErrorResponse);
		REQUIRE(errorCodeOf(resp) == stice::stun::StunErrorUnknownAttribute);
		std::vector<std::uint16_t> unknown;
		REQUIRE(stice::stun::readUnknownAttributes(resp, unknown));
		REQUIRE(std::find(unknown.begin(), unknown.end(), c.type) != unknown.end());
	}
}

// ---- G-TURN-2: 437 on a second Allocate over the same 5-tuple --------------

TEST_CASE("stserver answers 437 for a second Allocate on the same 5-tuple",
          "[stserver][turn][protocol]") {
	Fixture f;
	f.waitReady();
	auto creds = obtainCredentials(f);

	Message first = f.allocate(creds);
	REQUIRE(first.cls == Class::SuccessResponse);

	Message second = f.allocate(creds);
	REQUIRE(second.cls == Class::ErrorResponse);
	REQUIRE(errorCodeOf(second) == stice::stun::StunErrorAllocationMismatch);

	// A different source port is a different 5-tuple and must succeed.
	Fixture other;
	other.waitReady();
	Message otherResp = other.allocate(obtainCredentials(other));
	REQUIRE(otherResp.cls == Class::SuccessResponse);
}

// ---- G-TURN-3: 486 quota / 508 capacity -----------------------------------

TEST_CASE("stserver answers 486 when the allocation quota is reached",
          "[stserver][turn][protocol]") {
	ServerOptions opt;
	opt.maxAllocations = 1;
	Fixture f(opt);
	f.waitReady();
	auto creds = obtainCredentials(f);
	REQUIRE(f.allocate(creds).cls == Class::SuccessResponse);

	// Second client (different source port) over the quota.
	UdpSocketConfig cfg;
	cfg.bindAddress = "127.0.0.1";
	UdpSocket second = UdpSocket::create(cfg);
	REQUIRE(second.valid());
	stice::net::setNonBlocking(second.handle());

	Message req = allocateWith(creds, 17, nullptr);
	Message resp;
	REQUIRE(transact(second, f.serverAddr, req, resp));
	REQUIRE(resp.cls == Class::ErrorResponse);
	REQUIRE(errorCodeOf(resp) == stice::stun::StunErrorAllocationQuotaReached);
}

TEST_CASE("stserver answers 508 when the relay port range is exhausted",
          "[stserver][turn][protocol]") {
	ServerOptions opt;
	opt.relayPortBegin = 43600;
	opt.relayPortEnd = 43602;
	Fixture f(opt);
	f.waitReady();
	auto creds = obtainCredentials(f);

	std::vector<UdpSocket> clients;
	for (int i = 0; i < 3; ++i) {
		UdpSocketConfig cfg;
		cfg.bindAddress = "127.0.0.1";
		clients.push_back(UdpSocket::create(cfg));
		REQUIRE(clients.back().valid());
		stice::net::setNonBlocking(clients.back().handle());
		Message req = allocateWith(creds, 17, nullptr);
		Message resp;
		REQUIRE(transact(clients.back(), f.serverAddr, req, resp));
		REQUIRE(resp.cls == Class::SuccessResponse);
	}

	UdpSocketConfig cfg;
	cfg.bindAddress = "127.0.0.1";
	UdpSocket extra = UdpSocket::create(cfg);
	REQUIRE(extra.valid());
	stice::net::setNonBlocking(extra.handle());
	Message req = allocateWith(creds, 17, nullptr);
	Message resp;
	REQUIRE(transact(extra, f.serverAddr, req, resp));
	REQUIRE(resp.cls == Class::ErrorResponse);
	REQUIRE(errorCodeOf(resp) == stice::stun::StunErrorInsufficientCapacity);
}

// ---- G-TURN-4: lifetime negotiation ---------------------------------------

TEST_CASE("stserver negotiates the allocation lifetime (default / request / clamp)",
          "[stserver][turn][protocol]") {
	ServerOptions opt;
	opt.allocationLifetime = 600;
	opt.maxAllocationLifetime = 1200;
	Fixture f(opt);
	f.waitReady();
	auto creds = obtainCredentials(f);

	Message def = f.allocate(creds, 17, 0);
	REQUIRE(def.cls == Class::SuccessResponse);
	REQUIRE(lifetimeOf(def) == 600);

	// Requesting more than the server maximum is clamped, not rejected.
	Fixture f2(opt);
	f2.waitReady();
	Message big = f2.allocate(obtainCredentials(f2), 17, 100000);
	REQUIRE(big.cls == Class::SuccessResponse);
	REQUIRE(lifetimeOf(big) == 1200);

	// A request between the default and the maximum is honoured verbatim.
	Fixture f3(opt);
	f3.waitReady();
	Message mid = f3.allocate(obtainCredentials(f3), 17, 900);
	REQUIRE(mid.cls == Class::SuccessResponse);
	REQUIRE(lifetimeOf(mid) == 900);
}

TEST_CASE("stserver Refresh negotiates lifetime and 0 releases the allocation",
          "[stserver][turn][protocol]") {
	ServerOptions opt;
	opt.allocationLifetime = 600;
	opt.maxAllocationLifetime = 1200;
	Fixture f(opt);
	f.waitReady();
	auto creds = obtainCredentials(f);
	REQUIRE(f.allocate(creds).cls == Class::SuccessResponse);

	// Refresh with no LIFETIME -> default.
	Message plain = controlRequest(creds, [](Message &m) { m.method = Method::Refresh; });
	Message plainResp;
	REQUIRE(transact(f.sock, f.serverAddr, plain, plainResp));
	REQUIRE(plainResp.cls == Class::SuccessResponse);
	REQUIRE(lifetimeOf(plainResp) == 600);

	// Refresh above the maximum -> clamped.
	Message big = makeRefresh(creds, 100000);
	Message bigResp;
	REQUIRE(transact(f.sock, f.serverAddr, big, bigResp));
	REQUIRE(bigResp.cls == Class::SuccessResponse);
	REQUIRE(lifetimeOf(bigResp) == 1200);

	// Refresh 0 -> allocation deleted, LIFETIME echoed as 0.
	Message zero = makeRefresh(creds, 0);
	Message zeroResp;
	REQUIRE(transact(f.sock, f.serverAddr, zero, zeroResp));
	REQUIRE(zeroResp.cls == Class::SuccessResponse);
	REQUIRE(lifetimeOf(zeroResp) == 0);

	// The 5-tuple no longer owns an allocation.
	Message again = makeRefresh(creds, 600);
	Message againResp;
	REQUIRE(transact(f.sock, f.serverAddr, again, againResp));
	REQUIRE(againResp.cls == Class::ErrorResponse);
	REQUIRE(errorCodeOf(againResp) == stice::stun::StunErrorAllocationMismatch);
}

// ---- G-TURN-5: permission expiry drops inbound peer data ------------------

TEST_CASE("stserver drops inbound peer data once the permission expires",
          "[stserver][turn][protocol]") {
	ServerOptions opt;
	opt.permissionLifetimeSec = 1;
	Fixture f(opt);
	f.waitReady();
	auto creds = obtainCredentials(f);

	Message alloc = f.allocate(creds);
	REQUIRE(alloc.cls == Class::SuccessResponse);
	AddrRecord relayed = relayedAddrOf(alloc);

	Peer peer;
	Message perm = makeCreatePermission(creds, peer.addr);
	Message permResp;
	REQUIRE(transact(f.sock, f.serverAddr, perm, permResp));
	REQUIRE(permResp.cls == Class::SuccessResponse);

	// Permission alive: peer -> relay is forwarded as a Data indication.
	const char payload[] = "permission-live";
	REQUIRE(peer.sock.sendto(payload, sizeof(payload) - 1, relayed) > 0);
	Message ind;
	REQUIRE(recvMessage(f.sock, ind));
	REQUIRE(ind.method == Method::Data);
	REQUIRE(ind.cls == Class::Indication);
	const stice::stun::Attribute *data = ind.find(AttrType::Data);
	REQUIRE(data != nullptr);
	REQUIRE(std::string(reinterpret_cast<const char *>(data->value.data()),
	                    data->value.size()) == "permission-live");

	// Wait past the 1 s permission lifetime, then the same datagram is dropped.
	std::this_thread::sleep_for(std::chrono::milliseconds(1200));
	REQUIRE(peer.sock.sendto(payload, sizeof(payload) - 1, relayed) > 0);
	REQUIRE(quiet(f.sock, 800));
}

// ---- G-TURN-6: channel expiry drops ChannelData ---------------------------

TEST_CASE("stserver drops ChannelData once the channel binding expires",
          "[stserver][turn][protocol]") {
	ServerOptions opt;
	opt.channelLifetimeSec = 1;
	Fixture f(opt);
	f.waitReady();
	auto creds = obtainCredentials(f);

	Message alloc = f.allocate(creds);
	REQUIRE(alloc.cls == Class::SuccessResponse);
	AddrRecord relayed = relayedAddrOf(alloc);

	Peer peer;
	constexpr std::uint16_t channel = 0x4001;
	Message bind = makeChannelBind(creds, channel, peer.addr);
	Message bindResp;
	REQUIRE(transact(f.sock, f.serverAddr, bind, bindResp));
	REQUIRE(bindResp.cls == Class::SuccessResponse);

	const std::string payload = "channel-live";
	stice::bytes frame;
	std::size_t frameSize = stice::turn::wrapChannelData(
	    channel, reinterpret_cast<const unsigned char *>(payload.data()), payload.size(), frame,
	    /*pad=*/false);
	REQUIRE(frameSize == frame.size());
	REQUIRE(frameSize > 0);
	REQUIRE(f.sock.sendto(reinterpret_cast<const char *>(frame.data()), frame.size(),
	                      f.serverAddr) > 0);

	std::array<unsigned char, 512> buf{};
	std::size_t len = 0;
	REQUIRE(recvWithin(peer.sock, buf.data(), buf.size(), len, nullptr, 1500));
	REQUIRE(len == payload.size());
	REQUIRE(std::memcmp(buf.data(), payload.data(), len) == 0);

	// After expiry the channel no longer matches and the frame is dropped.
	std::this_thread::sleep_for(std::chrono::milliseconds(1200));
	REQUIRE(f.sock.sendto(reinterpret_cast<const char *>(frame.data()), frame.size(),
	                      f.serverAddr) > 0);
	REQUIRE(quiet(peer.sock, 800));
}

// ---- G-TURN-7: permission granularity is the peer IP ----------------------

TEST_CASE("stserver CreatePermission authorises the whole peer IP, not one port",
          "[stserver][turn][protocol]") {
	Fixture f;
	f.waitReady();
	auto creds = obtainCredentials(f);

	Message alloc = f.allocate(creds);
	REQUIRE(alloc.cls == Class::SuccessResponse);
	AddrRecord relayed = relayedAddrOf(alloc);

	Peer allowed; // 127.0.0.1:<port A>
	Message perm = makeCreatePermission(creds, allowed.addr);
	Message permResp;
	REQUIRE(transact(f.sock, f.serverAddr, perm, permResp));
	REQUIRE(permResp.cls == Class::SuccessResponse);

	// A different source port on the same IP must also be permitted.
	Peer sibling; // 127.0.0.1:<port B>
	const char payload[] = "same-ip";
	REQUIRE(sibling.sock.sendto(payload, sizeof(payload) - 1, relayed) > 0);
	Message ind;
	REQUIRE(recvMessage(f.sock, ind));
	REQUIRE(ind.method == Method::Data);

	// A different IP is still denied. 127.0.0.2 is loopback on Windows too.
	UdpSocketConfig cfg;
	cfg.bindAddress = "127.0.0.2";
	UdpSocket otherIp = UdpSocket::create(cfg);
	if (otherIp.valid()) {
		REQUIRE(otherIp.sendto(payload, sizeof(payload) - 1, relayed) > 0);
		REQUIRE(quiet(f.sock, 800));
	}
}

// ---- G-TURN-8: large payload passthrough ----------------------------------

TEST_CASE("stserver passes large Send indication and ChannelData payloads intact",
          "[stserver][turn][protocol]") {
	Fixture f;
	f.waitReady();
	auto creds = obtainCredentials(f);

	Message alloc = f.allocate(creds);
	REQUIRE(alloc.cls == Class::SuccessResponse);
	AddrRecord relayed = relayedAddrOf(alloc);

	Peer peer;
	Message perm = makeCreatePermission(creds, peer.addr);
	Message permResp;
	REQUIRE(transact(f.sock, f.serverAddr, perm, permResp));
	REQUIRE(permResp.cls == Class::SuccessResponse);

	// 3000 bytes: above any common MTU, below the UDP datagram limit.
	std::vector<unsigned char> big(3000);
	for (std::size_t i = 0; i < big.size(); ++i)
		big[i] = static_cast<unsigned char>(i & 0xFF);

	Message sendInd;
	sendInd.method = Method::Send;
	sendInd.cls = Class::Indication;
	sendInd.newTransactionID();
	stice::stun::writeXorAddress(sendInd, AttrType::XorPeerAddress, peer.addr,
	                             sendInd.transactionID);
	stice::stun::addData(sendInd, big.data(), big.size());
	REQUIRE(sendInd.encode(nullptr, nullptr, nullptr));
	REQUIRE(f.sock.sendto(reinterpret_cast<const char *>(sendInd.raw.data()),
	                      sendInd.raw.size(), f.serverAddr) > 0);

	std::vector<unsigned char> buf(8192);
	std::size_t len = 0;
	REQUIRE(recvWithin(peer.sock, buf.data(), buf.size(), len, nullptr, 1500));
	REQUIRE(len == big.size());
	REQUIRE(std::memcmp(buf.data(), big.data(), big.size()) == 0);

	// Same payload through a bound channel.
	constexpr std::uint16_t channel = 0x4002;
	Message bind = makeChannelBind(creds, channel, peer.addr);
	Message bindResp;
	REQUIRE(transact(f.sock, f.serverAddr, bind, bindResp));
	REQUIRE(bindResp.cls == Class::SuccessResponse);

	stice::bytes frame;
	stice::turn::wrapChannelData(channel, big.data(), big.size(), frame, /*pad=*/false);
	REQUIRE(f.sock.sendto(reinterpret_cast<const char *>(frame.data()), frame.size(),
	                      f.serverAddr) > 0);
	REQUIRE(recvWithin(peer.sock, buf.data(), buf.size(), len, nullptr, 1500));
	REQUIRE(len == big.size());
	REQUIRE(std::memcmp(buf.data(), big.data(), big.size()) == 0);
}

// ---- G-TURN-10: same IP, different source port = isolated allocations -----

TEST_CASE("stserver isolates allocations from the same IP on different source ports",
          "[stserver][turn][protocol]") {
	Fixture f;
	f.waitReady();
	auto creds = obtainCredentials(f);
	Message first = f.allocate(creds);
	REQUIRE(first.cls == Class::SuccessResponse);
	AddrRecord relayA = relayedAddrOf(first);

	// Second client, same loopback IP, different ephemeral source port.
	UdpSocketConfig cfg;
	cfg.bindAddress = "127.0.0.1";
	UdpSocket second = UdpSocket::create(cfg);
	REQUIRE(second.valid());
	stice::net::setNonBlocking(second.handle());
	Message req = allocateWith(creds, 17, nullptr);
	Message secondResp;
	REQUIRE(transact(second, f.serverAddr, req, secondResp));
	REQUIRE(secondResp.cls == Class::SuccessResponse);
	AddrRecord relayB = relayedAddrOf(secondResp);

	REQUIRE(stice::net::addrPort(reinterpret_cast<const sockaddr *>(&relayA.addr)) !=
	        stice::net::addrPort(reinterpret_cast<const sockaddr *>(&relayB.addr)));

	// Releasing one allocation must not disturb the other.
	Message zero = makeRefresh(creds, 0);
	Message zeroResp;
	REQUIRE(transact(second, f.serverAddr, zero, zeroResp));
	REQUIRE(zeroResp.cls == Class::SuccessResponse);

	Message still = controlRequest(creds, [](Message &m) { m.method = Method::Refresh; });
	Message stillResp;
	REQUIRE(transact(f.sock, f.serverAddr, still, stillResp));
	REQUIRE(stillResp.cls == Class::SuccessResponse);
	REQUIRE(lifetimeOf(stillResp) == 600);
}

// ---- G-TURN-9: 300 Try Alternate closes the redirect loop ------------------

namespace {
// Encode ALTERNATE-SERVER (0x8023) exactly as RFC 8489 §14.11 specifies:
// MAPPED-ADDRESS layout (family + port + address), not XOR-obfuscated.
void addAlternateServerAttr(Message &m, const AddrRecord &addr) {
	const auto *in = reinterpret_cast<const sockaddr_in *>(&addr.addr);
	const std::uint16_t port = ntohs(in->sin_port);
	const unsigned char *ip = reinterpret_cast<const unsigned char *>(&in->sin_addr);
	const unsigned char v[8] = {0,
	                            stice::stun::FamilyIPv4,
	                            static_cast<unsigned char>(port >> 8),
	                            static_cast<unsigned char>(port & 0xFF),
	                            ip[0],
	                            ip[1],
	                            ip[2],
	                            ip[3]};
	m.addAttribute(AttrType::AlternateServer, v, sizeof(v));
}

std::uint16_t portOf(const AddrRecord &a) {
	return stice::net::addrPort(reinterpret_cast<const sockaddr *>(&a.addr));
}
} // namespace

// A redirector answers every Allocate with 300 + ALTERNATE-SERVER pointing at
// a real TurnServer. The client must not merely report the redirect (the old
// coverage): it must retarget its send path, re-run the 401 handshake against
// the alternate, and end up holding an allocation that only the alternate
// could have granted.
TEST_CASE("TURN 300 Try Alternate migrates the allocation to the alternate server (G-TURN-9)",
          "[stserver][turn][protocol][redirect]") {
	Fixture f; // the real server the redirect points at
	f.waitReady();

	UdpSocketConfig cfg;
	cfg.bindAddress = "127.0.0.1";
	UdpSocket redirect = UdpSocket::create(cfg);
	REQUIRE(redirect.valid());
	AddrRecord redirectAddr{};
	REQUIRE(redirect.boundAddr(redirectAddr));
	redirectAddr.socktype = SOCK_DGRAM;
	stice::net::setNonBlocking(redirect.handle());

	UdpSocket clientSock = UdpSocket::create(cfg);
	REQUIRE(clientSock.valid());
	stice::net::setNonBlocking(clientSock.handle());

	std::atomic<bool> stop{false};
	std::atomic<int> redirected{0};
	std::thread responder([&] {
		std::array<unsigned char, 4096> buf{};
		while (!stop.load()) {
			AddrRecord from{};
			int n = redirect.recvfrom(reinterpret_cast<char *>(buf.data()),
			                          static_cast<int>(buf.size()), from);
			if (n <= 0) {
				std::this_thread::sleep_for(std::chrono::milliseconds(2));
				continue;
			}
			Message req;
			if (!req.decode(buf.data(), static_cast<std::size_t>(n))) continue;
			if (req.method != Method::Allocate || req.cls != Class::Request) continue;
			redirected.fetch_add(1);
			Message r;
			r.method = Method::Allocate;
			r.cls = Class::ErrorResponse;
			r.transactionID = req.transactionID;
			stice::stun::addErrorCode(r, stice::stun::StunErrorTryAlternate, "Try Alternate");
			addAlternateServerAttr(r, f.serverAddr);
			r.encode(nullptr, nullptr, nullptr);
			redirect.sendto(reinterpret_cast<const char *>(r.raw.data()),
			                static_cast<int>(r.raw.size()), from);
		}
	});

	stice::turn::Client client;
	stice::turn::TurnConfig tcfg;
	tcfg.serverHost = "127.0.0.1";
	tcfg.serverPort = portOf(redirectAddr);
	tcfg.username = kUser;
	tcfg.password = kPassword;
	tcfg.transport = stice::turn::TurnTransport::UDP;
	tcfg.requestedLifetime = 600;

	AddrRecord target = redirectAddr;
	bool sawAlternate = false;
	bool allocated = false;
	AddrRecord relayed{};
	int failedCode = 0;

	stice::turn::TurnSink sink;
	sink.sendRaw = [&](const unsigned char *d, std::size_t n) -> int {
		return clientSock.sendto(reinterpret_cast<const char *>(d), static_cast<int>(n), target);
	};
	sink.onAllocated = [&](const AddrRecord &a, std::uint32_t) {
		relayed = a;
		allocated = true;
	};
	sink.onFailed = [&](int code, const std::string &) { failedCode = code; };
	sink.onAlternateServer = [&](const AddrRecord &alt) {
		target = alt;
		sawAlternate = true;
	};
	client.init(tcfg, std::move(sink));
	client.allocate();

	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	while (!allocated && failedCode == 0 && std::chrono::steady_clock::now() < deadline) {
		std::array<unsigned char, 4096> buf{};
		AddrRecord from{};
		int n = clientSock.recvfrom(reinterpret_cast<char *>(buf.data()),
		                            static_cast<int>(buf.size()), from);
		if (n > 0) client.handleInbound(buf.data(), static_cast<std::size_t>(n));
		client.tick();
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
	stop.store(true);
	responder.join();

	REQUIRE(sawAlternate);
	REQUIRE(failedCode == 0);
	REQUIRE(allocated);
	REQUIRE(redirected.load() >= 1);

	// The retry left the redirector: the send path now points at the alternate,
	// and the relayed address sits in the real server's relay port range (the
	// redirector never allocates anything).
	REQUIRE(portOf(target) == portOf(f.serverAddr));
	const std::uint16_t relayPort = portOf(relayed);
	INFO("relayed port: " << relayPort);
	REQUIRE(relayPort >= 41000);
	REQUIRE(relayPort <= 41999);
}
