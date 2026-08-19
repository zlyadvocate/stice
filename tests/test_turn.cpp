// SPDX-License-Identifier: MPL-2.0
// Unit tests for the stice TURN client (RFC 8656).
//
// These tests do NOT talk to a real TURN server. Instead they:
//   - Build Allocate / CreatePermission / ChannelBind / Send / Refresh
//     requests via the Client and assert the on-the-wire STUN fields.
//   - Hand-craft success/error responses and feed them to handleInbound,
//     then assert the Client transitions state correctly.
//   - Exercise ChannelData wrap/unwrap including padding edge cases.
//   - Simulate retransmission by advancing the clock and calling tick().
//
// The Client talks to the network only through TurnSink::sendRaw, which the
// test replaces with a lambda that records outgoing bytes for inspection.

#include <catch2/catch_all.hpp>

#include "stice/turn/channeldata.hpp"
#include "stice/turn/stunconn.hpp"
#include "stice/turn/turn.hpp"
#include "stice/stun/attributes.hpp"
#include "stice/stun/message.hpp"
#include "stice/crypto.hpp"

#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace stice;
using namespace stice::turn;
using namespace stice::stun;

namespace {
net::AddrRecord makeV4(std::uint32_t ip, std::uint16_t port) {
	net::AddrRecord r{};
	sockaddr_in in{};
	in.sin_family = AF_INET;
	in.sin_port = htons(port);
	in.sin_addr.s_addr = htonl(ip);
	std::memcpy(&r.addr, &in, sizeof(in));
	r.len = sizeof(in);
	r.socktype = SOCK_DGRAM;
	return r;
}

// Build an Allocate Success Response that the server would send back.
// `relayedIp`/`relayedPort` is the XOR-RELAYED-ADDRESS; `lifetime` is the
// granted allocation lifetime.
bytes buildAllocateSuccess(const std::array<unsigned char, 12> &reqTid,
                            std::uint32_t relayedIp, std::uint16_t relayedPort,
                            std::uint32_t lifetime) {
	Message m;
	m.method = Method::Allocate;
	m.cls = Class::SuccessResponse;
	m.transactionID = reqTid;
	auto addr = makeV4(relayedIp, relayedPort);
	writeXorAddress(m, AttrType::XorRelayedAddress, addr, m.transactionID);
	addLifetime(m, lifetime);
	// Also include XOR-MAPPED-ADDRESS for completeness (RFC 8489).
	writeXorAddress(m, AttrType::XorMappedAddress, makeV4(0xC0A80101u, 12345), m.transactionID);
	m.encode(nullptr, nullptr, nullptr);
	return m.raw;
}

// Build an Allocate 401 Unauthenticated error with REALM + NONCE.
bytes buildAllocate401(const std::array<unsigned char, 12> &reqTid,
                        const std::string &realm, const std::string &nonce) {
	Message m;
	m.method = Method::Allocate;
	m.cls = Class::ErrorResponse;
	m.transactionID = reqTid;
	addErrorCode(m, 401, "Unauthenticated");
	addString(m, AttrType::Realm, realm);
	addString(m, AttrType::Nonce, nonce);
	m.encode(nullptr, nullptr, nullptr);
	return m.raw;
}

// Build a generic success response for a request TID (Refresh / CreatePermission / ChannelBind).
bytes buildSuccessResponse(Method method, const std::array<unsigned char, 12> &reqTid,
                            std::uint32_t lifetime = 0) {
	Message m;
	m.method = method;
	m.cls = Class::SuccessResponse;
	m.transactionID = reqTid;
	if (lifetime > 0) addLifetime(m, lifetime);
	m.encode(nullptr, nullptr, nullptr);
	return m.raw;
}

// A test harness that records every byte the Client sends to the TURN server.
struct TurnHarness {
	TurnConfig cfg;
	std::vector<bytes> sent;
	net::AddrRecord allocated;
	std::uint32_t allocatedLifetime = 0;
	int failedCode = 0;
	std::string failedReason;
	std::vector<std::pair<net::AddrRecord, bytes>> received;
	// RFC 6062 callback captures.
	struct ConnectEvent {
		std::uint32_t connectionId = 0;
		net::AddrRecord peer;
	};
	std::vector<ConnectEvent> connectSuccess;     // onConnectSuccess
	std::vector<ConnectEvent> connectionAttempts; // onConnectionAttempt
	struct ConnectFailEvent {
		int code = 0;
		std::string reason;
		net::AddrRecord peer;
	};
	std::vector<ConnectFailEvent> connectFailures; // onConnectFailed

	Client client;

	void init(std::uint32_t lifetime = 600) {
		cfg.serverHost = "127.0.0.1";
		cfg.serverPort = 3478;
		cfg.username = "alice";
		cfg.password = "secret";
		cfg.transport = TurnTransport::UDP;
		cfg.requestedLifetime = lifetime;

		TurnSink sink;
		sink.sendRaw = [this](const unsigned char *d, std::size_t n) {
			bytes b(d, d + n);
			sent.push_back(b);
		};
		sink.onAllocated = [this](const net::AddrRecord &a, std::uint32_t lt) {
			allocated = a;
			allocatedLifetime = lt;
		};
		sink.onFailed = [this](int code, const std::string &reason) {
			failedCode = code;
			failedReason = reason;
		};
		sink.onData = [this](const net::AddrRecord &peer, const unsigned char *d, std::size_t n) {
			received.emplace_back(peer, bytes(d, d + n));
		};
		sink.onLog = [](int, const char *) {};
		sink.onConnectSuccess = [this](std::uint32_t connId, const net::AddrRecord &peer) {
			connectSuccess.push_back({connId, peer});
		};
		sink.onConnectionAttempt = [this](std::uint32_t connId, const net::AddrRecord &peer) {
			connectionAttempts.push_back({connId, peer});
		};
		sink.onConnectFailed = [this](int code, const std::string &reason, const net::AddrRecord &peer) {
			connectFailures.push_back({code, reason, peer});
		};
		client.init(cfg, std::move(sink));
	}

	// Drive the client through Allocate + 401 + retry + success so it reaches
	// the Allocated state. Captures the Allocate request TID for the caller.
	// `tcp` selects REQUESTED-TRANSPORT=TCP(6) for RFC 6062 allocations.
	void reachAllocated(bool tcp = false) {
		cfg.transport = tcp ? TurnTransport::TCP : TurnTransport::UDP;
		// Re-init to apply the transport change.
		TurnSink sink;
		sink.sendRaw = [this](const unsigned char *d, std::size_t n) {
			sent.emplace_back(d, d + n);
		};
		sink.onAllocated = [this](const net::AddrRecord &a, std::uint32_t lt) {
			allocated = a;
			allocatedLifetime = lt;
		};
		sink.onFailed = [this](int code, const std::string &reason) {
			failedCode = code;
			failedReason = reason;
		};
		sink.onData = [this](const net::AddrRecord &peer, const unsigned char *d, std::size_t n) {
			received.emplace_back(peer, bytes(d, d + n));
		};
		sink.onLog = [](int, const char *) {};
		sink.onConnectSuccess = [this](std::uint32_t connId, const net::AddrRecord &peer) {
			connectSuccess.push_back({connId, peer});
		};
		sink.onConnectionAttempt = [this](std::uint32_t connId, const net::AddrRecord &peer) {
			connectionAttempts.push_back({connId, peer});
		};
		sink.onConnectFailed = [this](int code, const std::string &reason, const net::AddrRecord &peer) {
			connectFailures.push_back({code, reason, peer});
		};
		client.init(cfg, std::move(sink));

		client.allocate();
		auto firstReq = popLastMessage();
		REQUIRE(firstReq.method == Method::Allocate);
		// Challenge with 401 to establish credentials.
		auto err = buildAllocate401(firstReq.transactionID, "example.org", "nonce1");
		sent.clear();
		client.handleInbound(err.data(), err.size());
		auto retry = popLastMessage();
		REQUIRE(retry.find(AttrType::Username) != nullptr);
		// Grant the allocation.
		auto ok = buildAllocateSuccess(retry.transactionID, 0xC0A80164u, 5000, 600);
		client.handleInbound(ok.data(), ok.size());
		REQUIRE(client.state() == AllocState::Allocated);
		sent.clear();
	}

	// Pop the most recent sent message and decode it as a STUN Message.
	Message popLastMessage() {
		REQUIRE_FALSE(sent.empty());
		Message m;
		REQUIRE(m.decode(sent.back().data(), sent.back().size()));
		return m;
	}
};
} // namespace

// ---------------------------------------------------------------------------
// ChannelData framing (RFC 8656 §12.4)
// ---------------------------------------------------------------------------

TEST_CASE("ChannelData wrap/unwrap round-trip (no padding needed)", "[turn][channeldata]") {
	unsigned char data[] = {1, 2, 3, 4}; // 4 bytes, already aligned
	bytes out;
	auto n = wrapChannelData(0x4001, data, sizeof(data), out);
	REQUIRE(n == 8);
	REQUIRE(out[0] == 0x40);
	REQUIRE(out[1] == 0x01);
	REQUIRE(out[2] == 0x00);
	REQUIRE(out[3] == 0x04);
	REQUIRE(out[4] == 1);
	REQUIRE(out[5] == 2);
	REQUIRE(out[6] == 3);
	REQUIRE(out[7] == 4);
}

TEST_CASE("ChannelData wrap pads to 4 bytes", "[turn][channeldata]") {
	unsigned char data[] = {1, 2, 3}; // 3 bytes -> pad 1
	bytes out;
	auto n = wrapChannelData(0x7FFF, data, sizeof(data), out);
	REQUIRE(n == 8);
	REQUIRE(out[3] == 0x03); // length field is unpadded size
	REQUIRE(out[4] == 1);
	REQUIRE(out[5] == 2);
	REQUIRE(out[6] == 3);
	REQUIRE(out[7] == 0); // padding
}

TEST_CASE("ChannelData wrap rejects out-of-range channel", "[turn][channeldata]") {
	unsigned char data[] = {1};
	bytes out;
	REQUIRE(wrapChannelData(0x3FFF, data, 1, out) == 0);
	REQUIRE(wrapChannelData(0x8000, data, 1, out) == 0);
}

TEST_CASE("ChannelData unwrap recovers data and channel", "[turn][channeldata]") {
	unsigned char data[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE}; // 5 bytes
	bytes out;
	wrapChannelData(0x4042, data, sizeof(data), out);

	std::uint16_t ch = 0;
	const unsigned char *payload = nullptr;
	std::size_t frameSize = 0;
	std::size_t len = unwrapChannelData(out.data(), out.size(), ch, payload, frameSize);
	REQUIRE(len == 5);
	REQUIRE(ch == 0x4042);
	REQUIRE(frameSize == 12); // 4 header + 5 data + 3 padding = 12
	REQUIRE(std::memcmp(payload, data, 5) == 0);
}

TEST_CASE("ChannelData unwrap rejects bad channel number", "[turn][channeldata]") {
	unsigned char bad[] = {0x3F, 0xFF, 0x00, 0x00};
	std::uint16_t ch = 0;
	const unsigned char *payload = nullptr;
	std::size_t fs = 0;
	REQUIRE(unwrapChannelData(bad, sizeof(bad), ch, payload, fs) == 0);
}

TEST_CASE("ChannelData isChannelData demux", "[turn][channeldata]") {
	unsigned char cd[] = {0x40, 0x00, 0x00, 0x00};
	unsigned char stun[] = {0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42};
	REQUIRE(isChannelData(cd, sizeof(cd)));
	REQUIRE_FALSE(isChannelData(stun, sizeof(stun)));
	// Application data whose first byte falls in 0x40-0x7F (e.g. 'h'=0x68)
	// must NOT be misidentified as ChannelData (RFC 7982 length check).
	const char *appData = "hello from A";
	REQUIRE_FALSE(isChannelData(reinterpret_cast<const unsigned char *>(appData), strlen(appData)));
}

TEST_CASE("ChannelData randomChannelNumber is in range", "[turn][channeldata]") {
	for (int i = 0; i < 100; ++i) {
		auto ch = randomChannelNumber();
		REQUIRE(ch >= ChannelMin);
		REQUIRE(ch <= ChannelMax);
	}
}

// ---------------------------------------------------------------------------
// TURN Client: Allocate flow
// ---------------------------------------------------------------------------

TEST_CASE("TURN allocate sends initial request (no auth)", "[turn]") {
	TurnHarness h;
	h.init();
	h.client.allocate();

	REQUIRE(h.client.state() == AllocState::Allocating);
	REQUIRE_FALSE(h.sent.empty());

	auto m = h.popLastMessage();
	REQUIRE(m.method == Method::Allocate);
	REQUIRE(m.cls == Class::Request);

	const auto *rt = m.find(AttrType::RequestedTransport);
	REQUIRE(rt != nullptr);
	REQUIRE(rt->value.size() == 4);
	REQUIRE(rt->value[0] == 17); // UDP
}

TEST_CASE("TURN allocate retries on 401 with REALM/NONCE", "[turn]") {
	TurnHarness h;
	h.init();
	h.client.allocate();

	REQUIRE_FALSE(h.sent.empty());
	auto firstReq = h.popLastMessage();
	REQUIRE(firstReq.find(AttrType::Username) == nullptr);

	// Server responds 401 with realm+nonce.
	auto err = buildAllocate401(firstReq.transactionID, "example.org", "nonce123");
	h.sent.clear();
	h.client.handleInbound(err.data(), err.size());

	// Client should retry with credentials.
	REQUIRE_FALSE(h.sent.empty());
	auto retry = h.popLastMessage();
	REQUIRE(retry.method == Method::Allocate);
	REQUIRE(retry.cls == Class::Request);
	REQUIRE(retry.find(AttrType::Username) != nullptr);
	REQUIRE(getString(retry, AttrType::Realm) == "example.org");
	REQUIRE(getString(retry, AttrType::Nonce) == "nonce123");
}

TEST_CASE("TURN allocate success stores relayed address + lifetime", "[turn]") {
	TurnHarness h;
	h.init();
	h.client.allocate();
	auto req = h.popLastMessage();

	// Server responds 200 OK with XOR-RELAYED-ADDRESS and LIFETIME.
	auto ok = buildAllocateSuccess(req.transactionID, 0xC0A80164u /* 192.168.1.100 */,
	                                5000, 600);
	h.client.handleInbound(ok.data(), ok.size());

	REQUIRE(h.client.state() == AllocState::Allocated);
	REQUIRE(h.client.lifetime() == 600);
	REQUIRE(ntohl(reinterpret_cast<const sockaddr_in *>(&h.client.relayedAddr().addr)->sin_addr.s_addr)
	        == 0xC0A80164u);
	REQUIRE(ntohs(reinterpret_cast<const sockaddr_in *>(&h.client.relayedAddr().addr)->sin_port)
	        == 5000);
	REQUIRE(h.allocatedLifetime == 600);
}

TEST_CASE("TURN allocate failure triggers onFailed", "[turn]") {
	TurnHarness h;
	h.init();
	h.client.allocate();
	auto req = h.popLastMessage();

	// Server responds 403 Forbidden.
	Message err;
	err.method = Method::Allocate;
	err.cls = Class::ErrorResponse;
	err.transactionID = req.transactionID;
	addErrorCode(err, 403, "Forbidden");
	err.encode(nullptr, nullptr, nullptr);
	h.client.handleInbound(err.raw.data(), err.raw.size());

	REQUIRE(h.client.state() == AllocState::Failed);
	REQUIRE(h.failedCode == 403);
}

// ---------------------------------------------------------------------------
// TURN Client: CreatePermission / ChannelBind / sendData
// ---------------------------------------------------------------------------

TEST_CASE("TURN sendData before channel-ready sends Send indication", "[turn]") {
	TurnHarness h;
	h.init();
	// Force the allocated state so sendData will actually emit.
	h.client.allocate();
	auto req = h.popLastMessage();
	auto ok = buildAllocateSuccess(req.transactionID, 0xC0A80164u, 5000, 600);
	h.client.handleInbound(ok.data(), ok.size());
	h.sent.clear();

	auto peer = makeV4(0x0A000005u, 4000);
	unsigned char data[] = {1, 2, 3, 4};
	h.client.sendData(peer, data, sizeof(data));

	// With the buffering mechanism, sendData sends CreatePermission and
	// buffers the data. The Send indication is sent only after
	// CreatePermission succeeds (data is flushed then).
	REQUIRE_FALSE(h.sent.empty());
	Message cp;
	bool sawCreatePermission = false;
	for (const auto &b : h.sent) {
		Message m;
		if (!m.decode(b.data(), b.size())) continue;
		if (m.method == Method::CreatePermission && m.cls == Class::Request) {
			cp = m;
			sawCreatePermission = true;
			break;
		}
	}
	REQUIRE(sawCreatePermission);

	// Feed CreatePermission success → buffered data is flushed as Send indication.
	h.sent.clear();
	auto cpOk = buildSuccessResponse(Method::CreatePermission, cp.transactionID);
	h.client.handleInbound(cpOk.data(), cpOk.size());

	REQUIRE(h.client.hasPermission(peer));

	// The flushed data should be a Send indication.
	Message sendInd;
	bool sawSend = false;
	for (const auto &b : h.sent) {
		Message m;
		if (!m.decode(b.data(), b.size())) continue;
		if (m.method == Method::Send && m.cls == Class::Indication) {
			sendInd = m;
			sawSend = true;
		}
	}
	REQUIRE(sawSend);
	REQUIRE(sendInd.find(AttrType::XorPeerAddress) != nullptr);
	REQUIRE(sendInd.find(AttrType::Data) != nullptr);
}

TEST_CASE("TURN CreatePermission response marks peer permitted", "[turn]") {
	TurnHarness h;
	h.init();
	h.client.allocate();
	auto allocReq = h.popLastMessage();
	auto allocOk = buildAllocateSuccess(allocReq.transactionID, 0xC0A80164u, 5000, 600);
	h.client.handleInbound(allocOk.data(), allocOk.size());
	h.sent.clear();

	auto peer = makeV4(0x0A000005u, 4000);
	unsigned char data[] = {1};
	h.client.sendData(peer, data, sizeof(data));

	// Find the CreatePermission request we just sent.
	std::array<unsigned char, 12> cpTid{};
	for (const auto &b : h.sent) {
		Message m;
		if (!m.decode(b.data(), b.size())) continue;
		if (m.method == Method::CreatePermission && m.cls == Class::Request) {
			cpTid = m.transactionID;
			break;
		}
	}
	REQUIRE_FALSE(cpTid == std::array<unsigned char, 12>{});

	REQUIRE_FALSE(h.client.hasPermission(peer));
	auto ok = buildSuccessResponse(Method::CreatePermission, cpTid);
	h.client.handleInbound(ok.data(), ok.size());
	REQUIRE(h.client.hasPermission(peer));
}

TEST_CASE("TURN ChannelBind response marks channel ready", "[turn]") {
	TurnHarness h;
	h.init();
	h.client.allocate();
	auto allocReq = h.popLastMessage();
	auto allocOk = buildAllocateSuccess(allocReq.transactionID, 0xC0A80164u, 5000, 600);
	h.client.handleInbound(allocOk.data(), allocOk.size());
	h.sent.clear();

	auto peer = makeV4(0x0A000005u, 4000);

	// Establish permission first (sendData buffers data until permission is granted).
	h.client.ensurePermission(peer);
	std::array<unsigned char, 12> cpTid{};
	for (const auto &b : h.sent) {
		Message m;
		if (!m.decode(b.data(), b.size())) continue;
		if (m.method == Method::CreatePermission && m.cls == Class::Request) {
			cpTid = m.transactionID;
			break;
		}
	}
	REQUIRE_FALSE(cpTid == std::array<unsigned char, 12>{});
	auto cpOk = buildSuccessResponse(Method::CreatePermission, cpTid);
	h.client.handleInbound(cpOk.data(), cpOk.size());
	REQUIRE(h.client.hasPermission(peer));

	// Now sendData will send a Send indication and kick off ChannelBind.
	h.sent.clear();
	unsigned char data[] = {1};
	h.client.sendData(peer, data, sizeof(data));

	// Find the ChannelBind request (sendData kicks one off after permission is ready).
	std::array<unsigned char, 12> cbTid{};
	std::uint16_t channel = 0;
	for (const auto &b : h.sent) {
		Message m;
		if (!m.decode(b.data(), b.size())) continue;
		if (m.method == Method::ChannelBind && m.cls == Class::Request) {
			cbTid = m.transactionID;
			REQUIRE(readChannelNumber(m, channel));
			break;
		}
	}
	REQUIRE(channel != 0);

	auto ok = buildSuccessResponse(Method::ChannelBind, cbTid);
	h.client.handleInbound(ok.data(), ok.size());

	// Now a subsequent sendData should send ChannelData (not Send indication).
	h.sent.clear();
	unsigned char data2[] = {9, 9, 9};
	h.client.sendData(peer, data2, sizeof(data2));
	REQUIRE_FALSE(h.sent.empty());
	REQUIRE(isChannelData(h.sent.back().data(), h.sent.back().size()));
	// Verify the channel number in the ChannelData frame.
	REQUIRE(h.sent.back()[0] == static_cast<unsigned char>(channel >> 8));
	REQUIRE(h.sent.back()[1] == static_cast<unsigned char>(channel & 0xFF));
}

// ---------------------------------------------------------------------------
// TURN Client: deallocate / Refresh
// ---------------------------------------------------------------------------

TEST_CASE("TURN deallocate sends Refresh with LIFETIME=0", "[turn]") {
	TurnHarness h;
	h.init();
	h.client.allocate();
	auto allocReq = h.popLastMessage();
	auto allocOk = buildAllocateSuccess(allocReq.transactionID, 0xC0A80164u, 5000, 600);
	h.client.handleInbound(allocOk.data(), allocOk.size());
	h.sent.clear();

	h.client.deallocate();

	REQUIRE_FALSE(h.sent.empty());
	auto m = h.popLastMessage();
	REQUIRE(m.method == Method::Refresh);
	REQUIRE(m.cls == Class::Request);
	std::uint32_t lt = 1;
	REQUIRE(readLifetime(m, lt));
	REQUIRE(lt == 0);
	REQUIRE(h.client.state() == AllocState::Idle);
}

// ---------------------------------------------------------------------------
// TURN Client: retransmission / tick
// ---------------------------------------------------------------------------

TEST_CASE("TURN tick returns next wake-up time", "[turn]") {
	TurnHarness h;
	h.init();
	h.client.allocate();
	// nextTick_ should be set to now + 500ms (per allocate()).
	auto now = std::chrono::steady_clock::now();
	auto nt = h.client.nextTick();
	REQUIRE(nt > now);
	REQUIRE(nt <= now + std::chrono::seconds(2));
}

TEST_CASE("TURN inbound ChannelData is delivered to onData", "[turn]") {
	TurnHarness h;
	h.init();
	h.client.allocate();
	auto allocReq = h.popLastMessage();
	auto allocOk = buildAllocateSuccess(allocReq.transactionID, 0xC0A80164u, 5000, 600);
	h.client.handleInbound(allocOk.data(), allocOk.size());

	// Establish permission first, then sendData to kick off ChannelBind.
	auto peer = makeV4(0x0A000005u, 4000);
	h.client.ensurePermission(peer);
	std::array<unsigned char, 12> cpTid{};
	for (const auto &b : h.sent) {
		Message m;
		if (!m.decode(b.data(), b.size())) continue;
		if (m.method == Method::CreatePermission && m.cls == Class::Request) {
			cpTid = m.transactionID;
			break;
		}
	}
	REQUIRE_FALSE(cpTid == std::array<unsigned char, 12>{});
	auto cpOk = buildSuccessResponse(Method::CreatePermission, cpTid);
	h.client.handleInbound(cpOk.data(), cpOk.size());

	unsigned char data[] = {1};
	h.client.sendData(peer, data, sizeof(data));
	std::array<unsigned char, 12> cbTid{};
	std::uint16_t channel = 0;
	for (const auto &b : h.sent) {
		Message m;
		if (!m.decode(b.data(), b.size())) continue;
		if (m.method == Method::ChannelBind && m.cls == Class::Request) {
			cbTid = m.transactionID;
			REQUIRE(readChannelNumber(m, channel));
			break;
		}
	}
	auto ok = buildSuccessResponse(Method::ChannelBind, cbTid);
	h.client.handleInbound(ok.data(), ok.size());

	// Server sends ChannelData back.
	unsigned char incoming[] = {0xAA, 0xBB, 0xCC};
	bytes frame;
	wrapChannelData(channel, incoming, sizeof(incoming), frame);
	h.client.handleInbound(frame.data(), frame.size());

	REQUIRE(h.received.size() == 1);
	REQUIRE(h.received[0].second.size() == 3);
	REQUIRE(h.received[0].second[0] == 0xAA);
	REQUIRE(h.received[0].second[1] == 0xBB);
	REQUIRE(h.received[0].second[2] == 0xCC);
}

TEST_CASE("TURN inbound Data indication is delivered to onData", "[turn]") {
	TurnHarness h;
	h.init();
	h.client.allocate();
	auto allocReq = h.popLastMessage();
	auto allocOk = buildAllocateSuccess(allocReq.transactionID, 0xC0A80164u, 5000, 600);
	h.client.handleInbound(allocOk.data(), allocOk.size());

	auto peer = makeV4(0x0A000005u, 4000);
	// Build a Data indication from the server.
	Message di;
	di.method = Method::Data;
	di.cls = Class::Indication;
	di.newTransactionID();
	writeXorAddress(di, AttrType::XorPeerAddress, peer, di.transactionID);
	unsigned char payload[] = {0x01, 0x02, 0x03};
	addData(di, payload, sizeof(payload));
	di.encode(nullptr, nullptr, nullptr);
	h.client.handleInbound(di.raw.data(), di.raw.size());

	REQUIRE(h.received.size() == 1);
	REQUIRE(h.received[0].second.size() == 3);
	REQUIRE(h.received[0].second[0] == 0x01);
}

// ---------------------------------------------------------------------------
// StunConn: self-delimiting TURN over TCP/TLS frame parser
// ---------------------------------------------------------------------------

TEST_CASE("StunConn parses complete STUN message", "[turn][stunconn]") {
	// Build a minimal STUN Binding Request (20-byte header, no attributes).
	Message m;
	m.method = Method::Binding;
	m.cls = Class::Request;
	m.newTransactionID();
	m.encode(nullptr, nullptr, nullptr);

	StunConn sc;
	sc.feed(m.raw.data(), m.raw.size());

	const unsigned char *frame = nullptr;
	auto sz = sc.readFrame(frame);
	REQUIRE(sz == m.raw.size());
	REQUIRE(frame != nullptr);
	REQUIRE(std::memcmp(frame, m.raw.data(), sz) == 0);
	REQUIRE(sc.buffered() == 0);
}

TEST_CASE("StunConn returns 0 for incomplete STUN message", "[turn][stunconn]") {
	Message m;
	m.method = Method::Binding;
	m.cls = Class::Request;
	m.newTransactionID();
	m.encode(nullptr, nullptr, nullptr);

	StunConn sc;
	// Feed only the first 10 bytes (header is 20).
	sc.feed(m.raw.data(), 10);

	const unsigned char *frame = nullptr;
	REQUIRE(sc.readFrame(frame) == 0);
	REQUIRE(frame == nullptr);
	REQUIRE(sc.buffered() == 10);

	// Feed the rest; now the frame should be complete.
	sc.feed(m.raw.data() + 10, m.raw.size() - 10);
	auto sz = sc.readFrame(frame);
	REQUIRE(sz == m.raw.size());
	REQUIRE(std::memcmp(frame, m.raw.data(), sz) == 0);
	REQUIRE(sc.buffered() == 0);
}

TEST_CASE("StunConn parses STUN message fed byte-by-byte", "[turn][stunconn]") {
	Message m;
	m.method = Method::Allocate;
	m.cls = Class::SuccessResponse;
	m.newTransactionID();
	addLifetime(m, 600);
	m.encode(nullptr, nullptr, nullptr);

	StunConn sc;
	const unsigned char *frame = nullptr;
	for (std::size_t i = 0; i < m.raw.size(); ++i) {
		sc.feed(m.raw.data() + i, 1);
		// Should only return a frame after the last byte.
		if (i < m.raw.size() - 1) {
			REQUIRE(sc.readFrame(frame) == 0);
		}
	}
	auto sz = sc.readFrame(frame);
	REQUIRE(sz == m.raw.size());
	REQUIRE(std::memcmp(frame, m.raw.data(), sz) == 0);
}

TEST_CASE("StunConn parses complete ChannelData frame with padding", "[turn][stunconn]") {
	// 3 bytes of data -> padded to 4 -> total frame = 4 (header) + 4 = 8.
	unsigned char data[] = {0xAA, 0xBB, 0xCC};
	bytes cd;
	wrapChannelData(0x4001, data, sizeof(data), cd);
	// wrapChannelData already adds padding.
	REQUIRE(cd.size() == 8);

	StunConn sc;
	sc.feed(cd.data(), cd.size());

	const unsigned char *frame = nullptr;
	auto sz = sc.readFrame(frame);
	REQUIRE(sz == 8);
	REQUIRE(frame != nullptr);
	REQUIRE(std::memcmp(frame, cd.data(), sz) == 0);
	REQUIRE(sc.buffered() == 0);
}

TEST_CASE("StunConn parses ChannelData with no padding needed", "[turn][stunconn]") {
	// 4 bytes of data -> no padding -> total frame = 4 + 4 = 8.
	unsigned char data[] = {1, 2, 3, 4};
	bytes cd;
	wrapChannelData(0x7FFE, data, sizeof(data), cd);
	REQUIRE(cd.size() == 8);

	StunConn sc;
	sc.feed(cd.data(), cd.size());

	const unsigned char *frame = nullptr;
	auto sz = sc.readFrame(frame);
	REQUIRE(sz == 8);
	REQUIRE(std::memcmp(frame, cd.data(), sz) == 0);
}

TEST_CASE("StunConn parses multiple frames in one feed", "[turn][stunconn]") {
	// Build two STUN messages and one ChannelData frame.
	Message m1;
	m1.method = Method::Binding;
	m1.cls = Class::Request;
	m1.newTransactionID();
	m1.encode(nullptr, nullptr, nullptr);

	Message m2;
	m2.method = Method::Allocate;
	m2.cls = Class::SuccessResponse;
	m2.newTransactionID();
	addLifetime(m2, 300);
	m2.encode(nullptr, nullptr, nullptr);

	unsigned char cdData[] = {0x01, 0x02};
	bytes cd;
	wrapChannelData(0x4042, cdData, sizeof(cdData), cd);

	// Concatenate all three into one buffer.
	bytes combined;
	combined.insert(combined.end(), m1.raw.begin(), m1.raw.end());
	combined.insert(combined.end(), m2.raw.begin(), m2.raw.end());
	combined.insert(combined.end(), cd.begin(), cd.end());

	StunConn sc;
	sc.feed(combined.data(), combined.size());

	const unsigned char *frame = nullptr;

	// First frame: m1 (STUN).
	auto sz1 = sc.readFrame(frame);
	REQUIRE(sz1 == m1.raw.size());
	REQUIRE(std::memcmp(frame, m1.raw.data(), sz1) == 0);

	// Second frame: m2 (STUN).
	auto sz2 = sc.readFrame(frame);
	REQUIRE(sz2 == m2.raw.size());
	REQUIRE(std::memcmp(frame, m2.raw.data(), sz2) == 0);

	// Third frame: ChannelData.
	auto sz3 = sc.readFrame(frame);
	REQUIRE(sz3 == cd.size());
	REQUIRE(std::memcmp(frame, cd.data(), sz3) == 0);

	// No more frames.
	REQUIRE(sc.readFrame(frame) == 0);
	REQUIRE(sc.buffered() == 0);
}

TEST_CASE("StunConn parses mixed STUN and ChannelData fed in chunks", "[turn][stunconn]") {
	// Build a STUN message followed by a ChannelData frame.
	Message m;
	m.method = Method::Binding;
	m.cls = Class::SuccessResponse;
	m.newTransactionID();
	m.encode(nullptr, nullptr, nullptr);

	unsigned char cdData[] = {0xDE, 0xAD, 0xBE, 0xEF};
	bytes cd;
	wrapChannelData(0x4050, cdData, sizeof(cdData), cd);

	StunConn sc;
	const unsigned char *frame = nullptr;

	// Feed first half of STUN message.
	std::size_t half = m.raw.size() / 2;
	sc.feed(m.raw.data(), half);
	REQUIRE(sc.readFrame(frame) == 0);

	// Feed second half of STUN + first byte of ChannelData.
	sc.feed(m.raw.data() + half, m.raw.size() - half);
	sc.feed(cd.data(), 1);
	auto sz1 = sc.readFrame(frame);
	REQUIRE(sz1 == m.raw.size());
	REQUIRE(std::memcmp(frame, m.raw.data(), sz1) == 0);
	// Only 1 byte of ChannelData buffered, not enough.
	REQUIRE(sc.readFrame(frame) == 0);

	// Feed rest of ChannelData.
	sc.feed(cd.data() + 1, cd.size() - 1);
	auto sz2 = sc.readFrame(frame);
	REQUIRE(sz2 == cd.size());
	REQUIRE(std::memcmp(frame, cd.data(), sz2) == 0);
	REQUIRE(sc.buffered() == 0);
}

TEST_CASE("StunConn handles empty feed", "[turn][stunconn]") {
	StunConn sc;
	sc.feed(nullptr, 0);
	const unsigned char *frame = nullptr;
	REQUIRE(sc.readFrame(frame) == 0);
	REQUIRE(sc.buffered() == 0);
}

// ---------------------------------------------------------------------------
// TURN Client: TCP transport mode
// ---------------------------------------------------------------------------

TEST_CASE("TURN over TCP sends Allocate request", "[turn][tcp]") {
	TurnHarness h;
	h.init();
	h.cfg.transport = TurnTransport::TCP;
	// Re-init with TCP transport.
	TurnSink sink;
	sink.sendRaw = [&h](const unsigned char *d, std::size_t n) {
		h.sent.emplace_back(d, d + n);
	};
	sink.onAllocated = [&h](const net::AddrRecord &a, std::uint32_t lt) {
		h.allocated = a;
		h.allocatedLifetime = lt;
	};
	sink.onFailed = [&h](int code, const std::string &reason) {
		h.failedCode = code;
		h.failedReason = reason;
	};
	sink.onData = [&h](const net::AddrRecord &peer, const unsigned char *d, std::size_t n) {
		h.received.emplace_back(peer, bytes(d, d + n));
	};
	sink.onLog = [](int, const char *) {};
	h.client.init(h.cfg, std::move(sink));

	h.client.allocate();

	REQUIRE(h.client.state() == AllocState::Allocating);
	REQUIRE(h.client.isTcpAllocation());
	REQUIRE_FALSE(h.sent.empty());

	auto m = h.popLastMessage();
	REQUIRE(m.method == Method::Allocate);
	REQUIRE(m.cls == Class::Request);

	// RFC 6062: TCP transport (control connection) implies a TCP allocation
	// (REQUESTED-TRANSPORT=6). This enables active+passive dual-mode: the
	// client can CONNECT to peers and receive CONNECTION-ATTEMPT indications.
	const auto *rt = m.find(AttrType::RequestedTransport);
	REQUIRE(rt != nullptr);
	REQUIRE(rt->value.size() == 4);
	REQUIRE(rt->value[0] == 6); // TCP relayed transport (RFC 6062)
}

TEST_CASE("TURN over TCP handles 401 challenge with long-term creds", "[turn][tcp]") {
	TurnHarness h;
	h.init();
	h.cfg.transport = TurnTransport::TCP;
	TurnSink sink;
	sink.sendRaw = [&h](const unsigned char *d, std::size_t n) {
		h.sent.emplace_back(d, d + n);
	};
	sink.onAllocated = [&h](const net::AddrRecord &a, std::uint32_t lt) {
		h.allocated = a;
		h.allocatedLifetime = lt;
	};
	sink.onFailed = [&h](int code, const std::string &reason) {
		h.failedCode = code;
		h.failedReason = reason;
	};
	sink.onData = [&h](const net::AddrRecord &peer, const unsigned char *d, std::size_t n) {
		h.received.emplace_back(peer, bytes(d, d + n));
	};
	sink.onLog = [](int, const char *) {};
	h.client.init(h.cfg, std::move(sink));

	h.client.allocate();
	auto firstReq = h.popLastMessage();
	REQUIRE(firstReq.find(AttrType::Username) == nullptr);

	// Server responds 401 with realm+nonce.
	auto err = buildAllocate401(firstReq.transactionID, "example.org", "nonce456");
	h.sent.clear();
	h.client.handleInbound(err.data(), err.size());

	REQUIRE_FALSE(h.sent.empty());
	auto retry = h.popLastMessage();
	REQUIRE(retry.method == Method::Allocate);
	REQUIRE(retry.cls == Class::Request);
	REQUIRE(retry.find(AttrType::Username) != nullptr);
	REQUIRE(getString(retry, AttrType::Realm) == "example.org");
	REQUIRE(getString(retry, AttrType::Nonce) == "nonce456");
}

TEST_CASE("TURN over TCP allocates successfully", "[turn][tcp]") {
	TurnHarness h;
	h.init();
	h.cfg.transport = TurnTransport::TCP;
	TurnSink sink;
	sink.sendRaw = [&h](const unsigned char *d, std::size_t n) {
		h.sent.emplace_back(d, d + n);
	};
	sink.onAllocated = [&h](const net::AddrRecord &a, std::uint32_t lt) {
		h.allocated = a;
		h.allocatedLifetime = lt;
	};
	sink.onFailed = [&h](int code, const std::string &reason) {
		h.failedCode = code;
		h.failedReason = reason;
	};
	sink.onData = [&h](const net::AddrRecord &peer, const unsigned char *d, std::size_t n) {
		h.received.emplace_back(peer, bytes(d, d + n));
	};
	sink.onLog = [](int, const char *) {};
	h.client.init(h.cfg, std::move(sink));

	h.client.allocate();
	auto req = h.popLastMessage();

	auto ok = buildAllocateSuccess(req.transactionID, 0xC0A80164u, 5000, 600);
	h.client.handleInbound(ok.data(), ok.size());

	REQUIRE(h.client.state() == AllocState::Allocated);
	REQUIRE(h.client.lifetime() == 600);
	REQUIRE(h.allocatedLifetime == 600);
}

TEST_CASE("TURN over TCP + StunConn round-trip: allocate flow", "[turn][tcp][stunconn]") {
	// End-to-end simulation of TURN over TCP: the Client sends raw bytes
	// (captured by the harness), we feed them through StunConn to verify
	// they're self-delimiting, then feed the parsed frame back to the
	// Client as if it came from the TCP stream.
	TurnHarness h;
	h.init();
	h.cfg.transport = TurnTransport::TCP;
	TurnSink sink;
	sink.sendRaw = [&h](const unsigned char *d, std::size_t n) {
		h.sent.emplace_back(d, d + n);
	};
	sink.onAllocated = [&h](const net::AddrRecord &a, std::uint32_t lt) {
		h.allocated = a;
		h.allocatedLifetime = lt;
	};
	sink.onFailed = [&h](int code, const std::string &reason) {
		h.failedCode = code;
		h.failedReason = reason;
	};
	sink.onData = [&h](const net::AddrRecord &peer, const unsigned char *d, std::size_t n) {
		h.received.emplace_back(peer, bytes(d, d + n));
	};
	sink.onLog = [](int, const char *) {};
	h.client.init(h.cfg, std::move(sink));

	h.client.allocate();

	// The Client's outgoing Allocate request should be parseable by StunConn.
	REQUIRE_FALSE(h.sent.empty());
	StunConn outConn;
	outConn.feed(h.sent.back().data(), h.sent.back().size());
	const unsigned char *frame = nullptr;
	auto sz = outConn.readFrame(frame);
	REQUIRE(sz == h.sent.back().size());

	// Decode the frame as a STUN message to get the TID.
	Message req;
	REQUIRE(req.decode(frame, sz));
	REQUIRE(req.method == Method::Allocate);

	// Server responds with 401.
	auto err = buildAllocate401(req.transactionID, "example.org", "nonce789");
	h.sent.clear();

	// Feed the 401 response through StunConn (simulating TCP stream).
	StunConn inConn;
	inConn.feed(err.data(), err.size());
	const unsigned char *respFrame = nullptr;
	auto respSz = inConn.readFrame(respFrame);
	REQUIRE(respSz == err.size());
	h.client.handleInbound(respFrame, respSz);

	// Client should have retried with credentials.
	REQUIRE_FALSE(h.sent.empty());
	auto retry = h.popLastMessage();
	REQUIRE(retry.find(AttrType::Username) != nullptr);

	// Feed Allocate success through StunConn.
        auto ok = buildAllocateSuccess(retry.transactionID, 0xC0A80164u, 5000, 600);
        inConn.feed(ok.data(), ok.size());
        respSz = inConn.readFrame(respFrame);
        REQUIRE(respSz == ok.size());
        h.client.handleInbound(respFrame, respSz);

        REQUIRE(h.client.state() == AllocState::Allocated);
}

// ---------------------------------------------------------------------------
// TURN Client: TCP connection failure signaling
//
// When TURN over TCP is used and the TCP connection fails (connection refused,
// network unreachable, TLS handshake failure, etc.), the Agent signals the
// failure to the TURN Client by calling handleInbound(nullptr, 0). The Client
// must transition to Failed state and invoke the onFailed sink callback so
// that the Agent can decrement pendingRelayAllocations_ and complete gathering
// (otherwise gathering hangs forever waiting for an allocation that will
// never succeed).
// ---------------------------------------------------------------------------

TEST_CASE("TURN handleInbound(nullptr,0) signals failure and triggers onFailed", "[turn][tcp][failure]") {
	TurnHarness h;
	h.init();
	h.client.allocate();
	REQUIRE(h.client.state() == AllocState::Allocating);

	// Simulate TCP connection failure: Agent calls handleInbound(nullptr, 0).
	h.client.handleInbound(nullptr, 0);

	// The Client must transition to Failed and invoke onFailed so the Agent
	// can complete gathering instead of hanging forever.
	REQUIRE(h.client.state() == AllocState::Failed);
	REQUIRE((h.failedCode != 0 || !h.failedReason.empty()));
}

TEST_CASE("TURN handleInbound(nullptr,0) signals failure on idle client (TCP path)", "[turn][tcp][failure]") {
	// TCP TURN path: allocate() is NOT called until the TCP connection
	// completes (see Agent::onTurnTcpConnected). If the TCP connection
	// fails before completion, the Client is still in Idle state. The
	// transport-failure signal must still transition it to Failed and
	// invoke onFailed, so the Agent can decrement pendingRelayAllocations_
	// and complete gathering.
	TurnHarness h;
	h.init();
	REQUIRE(h.client.state() == AllocState::Idle);

	h.client.handleInbound(nullptr, 0);

	REQUIRE(h.client.state() == AllocState::Failed);
	REQUIRE(h.failedCode == 0);
	REQUIRE(h.failedReason == "transport failure");
}

TEST_CASE("TURN handleInbound(nullptr,0) signals failure after 401 retry", "[turn][tcp][failure]") {
	// Realistic TCP TURN failure scenario: the Allocate request is sent,
	// the server challenges with 401, the client retries with credentials,
	// and THEN the TCP connection drops before the retry response arrives.
	TurnHarness h;
	h.init();
	h.cfg.transport = TurnTransport::TCP;
	TurnSink sink;
	sink.sendRaw = [&h](const unsigned char *d, std::size_t n) {
		h.sent.emplace_back(d, d + n);
	};
	sink.onAllocated = [&h](const net::AddrRecord &a, std::uint32_t lt) {
		h.allocated = a;
		h.allocatedLifetime = lt;
	};
	sink.onFailed = [&h](int code, const std::string &reason) {
		h.failedCode = code;
		h.failedReason = reason;
	};
	sink.onData = [&h](const net::AddrRecord &peer, const unsigned char *d, std::size_t n) {
		h.received.emplace_back(peer, bytes(d, d + n));
	};
	sink.onLog = [](int, const char *) {};
	h.client.init(h.cfg, std::move(sink));

	// Initial Allocate (no auth).
	h.client.allocate();
	auto firstReq = h.popLastMessage();
	REQUIRE(h.client.state() == AllocState::Allocating);

	// 401 challenge.
	auto err = buildAllocate401(firstReq.transactionID, "example.org", "nonce999");
	h.sent.clear();
	h.client.handleInbound(err.data(), err.size());
	REQUIRE_FALSE(h.sent.empty());
	auto retry = h.popLastMessage();
	REQUIRE(retry.find(AttrType::Username) != nullptr);

	// TCP connection drops before the retry response arrives.
	h.client.handleInbound(nullptr, 0);

	REQUIRE(h.client.state() == AllocState::Failed);
	REQUIRE((h.failedCode != 0 || !h.failedReason.empty()));
}

// ---------------------------------------------------------------------------
// TURN failure scenarios: auth failure, stale-nonce loop, invalid stream data
//
// These tests cover error-handling paths that previously had bugs:
//   1. 401 after credentials → must NOT loop forever (was: infinite 401 retry)
//   2. 438 StaleNonce loop → must terminate after MaxNonceRetries
//   3. StunConn invalid stream data → must surface error (was: silent stall)
//   4. TURN Allocate timeout → must invoke onFailed (retransmission exhausted)
// ---------------------------------------------------------------------------

TEST_CASE("TURN 401 after credentials does not loop (auth failure)", "[turn][failure]") {
	// Bug scenario: when the server returns 401 a SECOND time (after the
	// client already sent credentials), the client used to retry forever.
	// Fix: treat a second 401 as a fatal auth failure, invoke onFailed.
	TurnHarness h;
	h.init();
	h.client.allocate();
	REQUIRE(h.client.state() == AllocState::Allocating);

	auto firstReq = h.popLastMessage();
	REQUIRE(firstReq.find(AttrType::Username) == nullptr);

	// First 401: server challenges with realm + nonce.
	auto err1 = buildAllocate401(firstReq.transactionID, "example.org", "nonce1");
	h.sent.clear();
	h.client.handleInbound(err1.data(), err1.size());
	REQUIRE_FALSE(h.sent.empty());
	auto retry = h.popLastMessage();
	REQUIRE(retry.find(AttrType::Username) != nullptr);
	REQUIRE(h.client.state() == AllocState::Allocating);

	// Second 401: credentials rejected. Must NOT retry — must fail.
	h.sent.clear();
	auto err2 = buildAllocate401(retry.transactionID, "example.org", "nonce1");
	h.client.handleInbound(err2.data(), err2.size());

	REQUIRE(h.sent.empty());           // no third request sent
	REQUIRE(h.client.state() == AllocState::Failed);
	REQUIRE(h.failedCode == 401);
	REQUIRE_FALSE(h.failedReason.empty());
}

TEST_CASE("TURN 438 StaleNonce loop terminates after MaxNonceRetries", "[turn][failure]") {
	// Bug scenario: a misbehaving server that always returns 438 StaleNonce
	// would cause the client to retry forever. Fix: limit to MaxNonceRetries.
	TurnHarness h;
	h.init();
	h.client.allocate();
	auto req = h.popLastMessage();

	// First 401 to establish credentials.
	auto err401 = buildAllocate401(req.transactionID, "example.org", "nonce0");
	h.sent.clear();
	h.client.handleInbound(err401.data(), err401.size());
	std::array<unsigned char, 12> lastTid = h.popLastMessage().transactionID;

	// Repeatedly return 438 StaleNonce. The client retries with the new
	// nonce until nonceRetries_ exceeds MaxNonceRetries, after which it
	// transitions to Failed without sending another request.
	for (int i = 0; i < MaxNonceRetries + 2; ++i) {
		REQUIRE(h.client.state() == AllocState::Allocating);
		std::string nextNonce = "nonce" + std::to_string(i + 1);
		Message err438;
		err438.method = Method::Allocate;
		err438.cls = Class::ErrorResponse;
		err438.transactionID = lastTid;
		addErrorCode(err438, 438, "Stale Nonce");
		addString(err438, AttrType::Realm, "example.org");
		addString(err438, AttrType::Nonce, nextNonce);
		err438.encode(nullptr, nullptr, nullptr);
		h.sent.clear();
		h.client.handleInbound(err438.raw.data(), err438.raw.size());
		if (h.client.state() == AllocState::Failed) break;
		// Client retried: capture the new TID for the next response.
		lastTid = h.popLastMessage().transactionID;
	}

	REQUIRE(h.client.state() == AllocState::Failed);
	REQUIRE_FALSE(h.failedReason.empty());
}

TEST_CASE("StunConn surfaces invalid stream data instead of silent stall", "[turn][stunconn][failure]") {
	// Bug scenario: a byte on the TCP stream that is neither STUN nor
	// ChannelData (e.g. first byte < 0x40 but magic cookie mismatch) used
	// to leave StunConn permanently stuck returning 0. Fix: return SIZE_MAX
	// so the caller can close the connection.
	StunConn sc;

	// Feed a garbage byte: first byte < 0x40 (looks like STUN) but bytes
	// 4-7 do not match the magic cookie.
	unsigned char garbage[] = {0x01, 0x02, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0xAA, 0xBB};
	sc.feed(garbage, sizeof(garbage));

	const unsigned char *frame = nullptr;
	std::size_t r = sc.readFrame(frame);
	REQUIRE(r == static_cast<std::size_t>(-1)); // SIZE_MAX — invalid stream
}

TEST_CASE("TURN Allocate retransmission timeout invokes onFailed", "[turn][failure]") {
	// When the TURN server never responds, the client's retransmission
	// logic must eventually exhaust retries and invoke onFailed. This
	// covers the "server silent" failure mode (e.g. packet loss to a UDP
	// TURN server, or a black-hole route).
	TurnHarness h;
	h.init();
	h.client.allocate();
	REQUIRE(h.client.state() == AllocState::Allocating);

	// Drive the retransmission timer past TurnMaxRtxCount retries.
	// Each tick() advances the clock; we simulate time passing by calling
	// tick() enough times with the harness clock advancing.
	auto start = std::chrono::steady_clock::now();
	bool failed = false;
	for (int i = 0; i < 200; ++i) {
		// Simulate time advancing: tick() uses steady_clock, so we sleep.
		std::this_thread::sleep_for(std::chrono::milliseconds(TurnMaxRtxIntervalMs + 50));
		h.client.tick();
		if (h.client.state() == AllocState::Failed) { failed = true; break; }
		if (std::chrono::steady_clock::now() - start > std::chrono::seconds(30)) break;
	}
	REQUIRE(failed);
	REQUIRE(h.client.state() == AllocState::Failed);
	REQUIRE_FALSE(h.failedReason.empty());
}

// ---------------------------------------------------------------------------
// RFC 6062 TCP allocation support
//
// These tests verify the TURN client's RFC 6062 implementation:
//   - TCP allocation sends REQUESTED-TRANSPORT=TCP(6) (vs UDP=17)
//   - isTcpAllocation() reflects the configured transport
//   - CONNECT request (active mode) is built correctly with XOR-PEER-ADDRESS
//   - CONNECT success response extracts CONNECTION-ID and fires onConnectSuccess
//   - CONNECT error response does NOT fire onConnectSuccess
//   - CONNECTION-BIND request is built with CONNECTION-ID + MESSAGE-INTEGRITY
//   - CONNECTION-ATTEMPT indication (passive mode) fires onConnectionAttempt
//   - sendConnect before Allocated is a safe no-op
//
// RFC 6062 §3.2: a TCP allocation uses REQUESTED-TRANSPORT=6. The control
// connection MUST be TCP or TLS. After allocation, the client may:
//   - Actively CONNECT to a peer's relayed TCP address (active mode)
//   - Receive CONNECTION-ATTEMPT indications when peers connect to its
//     relayed TCP address (passive mode)
// In both cases, a separate TCP data connection is opened to the TURN server
// and bound via CONNECTION-BIND; raw application data then flows end-to-end.
// ---------------------------------------------------------------------------

TEST_CASE("RFC 6062: TCP allocation sends REQUESTED-TRANSPORT=6", "[turn][rfc6062]") {
	TurnHarness h;
	h.init();
	h.cfg.transport = TurnTransport::TCP;
	TurnSink sink;
	sink.sendRaw = [&h](const unsigned char *d, std::size_t n) {
		h.sent.emplace_back(d, d + n);
	};
	sink.onLog = [](int, const char *) {};
	h.client.init(h.cfg, std::move(sink));

	REQUIRE_FALSE(h.client.isTcpAllocation()); // not yet allocated
	h.client.allocate();

	REQUIRE(h.client.isTcpAllocation());
	REQUIRE_FALSE(h.sent.empty());
	auto m = h.popLastMessage();
	REQUIRE(m.method == Method::Allocate);
	REQUIRE(m.cls == Class::Request);

	const auto *rt = m.find(AttrType::RequestedTransport);
	REQUIRE(rt != nullptr);
	REQUIRE(rt->value.size() == 4);
	REQUIRE(rt->value[0] == 6); // TCP (RFC 6062 §3.2)
}

TEST_CASE("RFC 6062: UDP allocation sends REQUESTED-TRANSPORT=17", "[turn][rfc6062]") {
	TurnHarness h;
	h.init();
	h.client.allocate();

	REQUIRE_FALSE(h.client.isTcpAllocation());
	auto m = h.popLastMessage();
	const auto *rt = m.find(AttrType::RequestedTransport);
	REQUIRE(rt != nullptr);
	REQUIRE(rt->value[0] == 17); // UDP
}

// Build a CONNECT success response: the server created a TCP connection to
// the peer and assigned CONNECTION-ID. Per RFC 6062 §6.3, the success
// response carries CONNECTION-ID (and the credentials are NOT required).
bytes buildConnectSuccess(const std::array<unsigned char, 12> &reqTid,
                          std::uint32_t connectionId) {
	Message m;
	m.method = Method::Connect;
	m.cls = Class::SuccessResponse;
	m.transactionID = reqTid;
	addConnectionId(m, connectionId);
	m.encode(nullptr, nullptr, nullptr);
	return m.raw;
}

// Build a CONNECT error response (e.g. 403 Forbidden peer).
bytes buildConnectError(const std::array<unsigned char, 12> &reqTid,
                        int code, const std::string &reason) {
	Message m;
	m.method = Method::Connect;
	m.cls = Class::ErrorResponse;
	m.transactionID = reqTid;
	addErrorCode(m, code, reason);
	m.encode(nullptr, nullptr, nullptr);
	return m.raw;
}

// Build a CONNECTION-ATTEMPT indication (RFC 6062 §6.4): the server tells us
// a peer initiated a TCP connection to our relayed address. Carries
// XOR-PEER-ADDRESS and CONNECTION-ID.
bytes buildConnectionAttempt(const net::AddrRecord &peer, std::uint32_t connectionId) {
	Message m;
	m.method = Method::ConnectionAttempt;
	m.cls = Class::Indication;
	m.newTransactionID();
	writeXorAddress(m, AttrType::XorPeerAddress, peer, m.transactionID);
	addConnectionId(m, connectionId);
	m.encode(nullptr, nullptr, nullptr);
	return m.raw;
}

TEST_CASE("RFC 6062: sendConnect builds CONNECT request with XOR-PEER-ADDRESS", "[turn][rfc6062]") {
	TurnHarness h;
	h.init();
	h.reachAllocated(/*tcp=*/true);

	auto peer = makeV4(0x0A000005u, 4000); // 10.0.0.5:4000
	h.client.sendConnect(peer);

	REQUIRE_FALSE(h.sent.empty());
	auto m = h.popLastMessage();
	REQUIRE(m.method == Method::Connect);
	REQUIRE(m.cls == Class::Request);

	// XOR-PEER-ADDRESS must be present and decode back to the peer.
	net::AddrRecord decoded;
	REQUIRE(readXorAddress(m, AttrType::XorPeerAddress, decoded, m.transactionID));
	REQUIRE(decoded.isEqual(peer, true));
}

TEST_CASE("RFC 6062: sendConnect before Allocated is a no-op", "[turn][rfc6062]") {
	TurnHarness h;
	h.init();
	REQUIRE(h.client.state() == AllocState::Idle);

	auto peer = makeV4(0x0A000005u, 4000);
	h.client.sendConnect(peer); // must not crash or send anything
	REQUIRE(h.sent.empty());
	REQUIRE(h.client.state() == AllocState::Idle);
}

TEST_CASE("RFC 6062: CONNECT success fires onConnectSuccess with CONNECTION-ID", "[turn][rfc6062]") {
	TurnHarness h;
	h.init();
	h.reachAllocated(/*tcp=*/true);

	auto peer = makeV4(0x0A000005u, 4000);
	h.client.sendConnect(peer);

	// Find the CONNECT request TID.
	std::array<unsigned char, 12> connectTid{};
	bool found = false;
	for (const auto &b : h.sent) {
		Message m;
		if (!m.decode(b.data(), b.size())) continue;
		if (m.method == Method::Connect && m.cls == Class::Request) {
			connectTid = m.transactionID;
			found = true;
			break;
		}
	}
	REQUIRE(found);

	// Server responds with success + CONNECTION-ID=0x12345678.
	constexpr std::uint32_t connId = 0x12345678u;
	auto ok = buildConnectSuccess(connectTid, connId);
	h.client.handleInbound(ok.data(), ok.size());

	REQUIRE(h.connectSuccess.size() == 1);
	REQUIRE(h.connectSuccess[0].connectionId == connId);
	REQUIRE(h.connectSuccess[0].peer.isEqual(peer, true));
}

TEST_CASE("RFC 6062: CONNECT error does NOT fire onConnectSuccess", "[turn][rfc6062]") {
	TurnHarness h;
	h.init();
	h.reachAllocated(/*tcp=*/true);

	auto peer = makeV4(0x0A000005u, 4000);
	h.client.sendConnect(peer);

	std::array<unsigned char, 12> connectTid{};
	for (const auto &b : h.sent) {
		Message m;
		if (!m.decode(b.data(), b.size())) continue;
		if (m.method == Method::Connect && m.cls == Class::Request) {
			connectTid = m.transactionID;
			break;
		}
	}

	// Server rejects the CONNECT (e.g. peer unreachable).
	auto err = buildConnectError(connectTid, 403, "Forbidden peer");
	h.client.handleInbound(err.data(), err.size());

	REQUIRE(h.connectSuccess.empty());
	// onConnectFailed must be invoked with the error code and reason.
	REQUIRE(h.connectFailures.size() == 1);
	REQUIRE(h.connectFailures[0].code == 403);
	REQUIRE(h.connectFailures[0].reason == "Forbidden peer");
	REQUIRE(h.connectFailures[0].peer.isEqual(peer, true));
	// Allocation must remain intact — a failed CONNECT does not tear down
	// the allocation; the agent may retry with another pair.
	REQUIRE(h.client.state() == AllocState::Allocated);
}

TEST_CASE("RFC 6062: buildConnectionBindRequest produces valid CONNECTION-BIND", "[turn][rfc6062]") {
	TurnHarness h;
	h.init();
	h.reachAllocated(/*tcp=*/true);

	constexpr std::uint32_t connId = 0xDEADBEEFu;
	auto raw = h.client.buildConnectionBindRequest(connId);
	REQUIRE_FALSE(raw.empty());

	// The raw bytes must be a decodable STUN message.
	Message m;
	REQUIRE(m.decode(raw.data(), raw.size()));
	REQUIRE(m.method == Method::ConnectionBind);
	REQUIRE(m.cls == Class::Request);

	// CONNECTION-ID must round-trip.
	std::uint32_t readConnId = 0;
	REQUIRE(readConnectionId(m, readConnId));
	REQUIRE(readConnId == connId);

	// MESSAGE-INTEGRITY must be present (CONNECTION-BIND is authenticated
	// with the same long-term credentials as the allocation, per RFC 6062 §6.5).
	REQUIRE(m.find(AttrType::MessageIntegrity) != nullptr);
}

TEST_CASE("RFC 6062: CONNECTION-ATTEMPT fires onConnectionAttempt", "[turn][rfc6062]") {
	TurnHarness h;
	h.init();
	h.reachAllocated(/*tcp=*/true);

	auto peer = makeV4(0xC0A80101u, 8888); // 192.168.1.1:8888
	constexpr std::uint32_t connId = 0xCAFEBABEu;
	auto ind = buildConnectionAttempt(peer, connId);
	h.client.handleInbound(ind.data(), ind.size());

	REQUIRE(h.connectionAttempts.size() == 1);
	REQUIRE(h.connectionAttempts[0].connectionId == connId);
	REQUIRE(h.connectionAttempts[0].peer.isEqual(peer, true));
}

TEST_CASE("RFC 6062: CONNECTION-ATTEMPT missing XOR-PEER-ADDRESS is ignored", "[turn][rfc6062]") {
	TurnHarness h;
	h.init();
	h.reachAllocated(/*tcp=*/true);

	// Build a malformed CONNECTION-ATTEMPT with only CONNECTION-ID (no peer).
	Message m;
	m.method = Method::ConnectionAttempt;
	m.cls = Class::Indication;
	m.newTransactionID();
	addConnectionId(m, 0x11111111u);
	m.encode(nullptr, nullptr, nullptr);
	h.client.handleInbound(m.raw.data(), m.raw.size());

	REQUIRE(h.connectionAttempts.empty());
	// Allocation remains intact.
	REQUIRE(h.client.state() == AllocState::Allocated);
}

TEST_CASE("RFC 6062: CONNECTION-ATTEMPT missing CONNECTION-ID is ignored", "[turn][rfc6062]") {
	TurnHarness h;
	h.init();
	h.reachAllocated(/*tcp=*/true);

	auto peer = makeV4(0xC0A80101u, 8888);
	// Build a malformed CONNECTION-ATTEMPT with only XOR-PEER-ADDRESS (no conn id).
	Message m;
	m.method = Method::ConnectionAttempt;
	m.cls = Class::Indication;
	m.newTransactionID();
	writeXorAddress(m, AttrType::XorPeerAddress, peer, m.transactionID);
	m.encode(nullptr, nullptr, nullptr);
	h.client.handleInbound(m.raw.data(), m.raw.size());

	REQUIRE(h.connectionAttempts.empty());
	REQUIRE(h.client.state() == AllocState::Allocated);
}

TEST_CASE("RFC 6062: CONNECT request is retransmitted until response", "[turn][rfc6062][retransmit]") {
	// The CONNECT request, like other TURN requests, must be retransmitted
	// per the RTO schedule until a response arrives or retries exhaust.
	// This mirrors the unified retransmission in tick() for all PendingTx.
	TurnHarness h;
	h.init();
	h.reachAllocated(/*tcp=*/true);

	auto peer = makeV4(0x0A000005u, 4000);
	h.client.sendConnect(peer);
	std::size_t sentBefore = h.sent.size();

	// Advance the clock past the RTO; tick() should retransmit CONNECT.
	std::this_thread::sleep_for(std::chrono::milliseconds(TurnRtoMs + 50));
	h.client.tick();

	// At least one retransmission should have been sent.
	REQUIRE(h.sent.size() > sentBefore);

	// The retransmitted frame must still be a CONNECT request (same TID).
	bool sawConnectRetransmit = false;
	std::array<unsigned char, 12> firstTid{};
	bool haveFirst = false;
	for (const auto &b : h.sent) {
		Message m;
		if (!m.decode(b.data(), b.size())) continue;
		if (m.method == Method::Connect && m.cls == Class::Request) {
			if (!haveFirst) { firstTid = m.transactionID; haveFirst = true; }
			else if (m.transactionID == firstTid) { sawConnectRetransmit = true; }
		}
	}
	REQUIRE(sawConnectRetransmit);
}

TEST_CASE("RFC 6062: CONNECTION-ID attribute round-trip", "[turn][rfc6062][attr]") {
	// Verify the CONNECTION-ID attribute encodes as a 4-byte big-endian
	// uint32 and decodes back, covering boundary values.
	for (std::uint32_t v : {0x00000000u, 0x00000001u, 0x12345678u, 0xCAFEBABEu,
	                        0xDEADBEEFu, 0xFFFFFFFFu}) {
		Message m;
		m.method = Method::Connect;
		m.cls = Class::SuccessResponse;
		m.newTransactionID();
		addConnectionId(m, v);
		m.encode(nullptr, nullptr, nullptr);

		Message dec;
		REQUIRE(dec.decode(m.raw.data(), m.raw.size()));
		std::uint32_t out = 0;
		REQUIRE(readConnectionId(dec, out));
		REQUIRE(out == v);
	}
}

TEST_CASE("RFC 6062: readConnectionId returns false when attribute absent", "[turn][rfc6062][attr]") {
	Message m;
	m.method = Method::Binding;
	m.cls = Class::Request;
	m.newTransactionID();
	m.encode(nullptr, nullptr, nullptr);

	Message dec;
	REQUIRE(dec.decode(m.raw.data(), m.raw.size()));
	std::uint32_t out = 12345u; // sentinel
	REQUIRE_FALSE(readConnectionId(dec, out));
	REQUIRE(out == 12345u); // unchanged
}

TEST_CASE("RFC 6062: active+passive dual mode on same allocation", "[turn][rfc6062][dual]") {
	// A single TCP allocation supports BOTH modes: the client may actively
	// CONNECT to one peer while passively receiving CONNECTION-ATTEMPT from
	// another. This is the active+passive dual-mode capability.
	TurnHarness h;
	h.init();
	h.reachAllocated(/*tcp=*/true);

	// Active mode: send CONNECT to peer A.
	auto peerA = makeV4(0x0A000001u, 4000);
	h.client.sendConnect(peerA);
	std::array<unsigned char, 12> connectTidA{};
	for (const auto &b : h.sent) {
		Message m;
		if (!m.decode(b.data(), b.size())) continue;
		if (m.method == Method::Connect && m.cls == Class::Request) {
			connectTidA = m.transactionID;
			break;
		}
	}
	auto okA = buildConnectSuccess(connectTidA, 100);
	h.client.handleInbound(okA.data(), okA.size());
	REQUIRE(h.connectSuccess.size() == 1);
	REQUIRE(h.connectSuccess[0].connectionId == 100);

	// Passive mode: receive CONNECTION-ATTEMPT from peer B (different peer).
	auto peerB = makeV4(0x0A000002u, 5000);
	auto ind = buildConnectionAttempt(peerB, 200);
	h.client.handleInbound(ind.data(), ind.size());
	REQUIRE(h.connectionAttempts.size() == 1);
	REQUIRE(h.connectionAttempts[0].connectionId == 200);
	REQUIRE(h.connectionAttempts[0].peer.isEqual(peerB, true));

	// Both modes coexist on the same allocation.
	REQUIRE(h.client.state() == AllocState::Allocated);
	REQUIRE(h.connectSuccess.size() == 1);
	REQUIRE(h.connectionAttempts.size() == 1);
}

