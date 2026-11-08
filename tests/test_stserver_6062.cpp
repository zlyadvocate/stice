// SPDX-License-Identifier: MPL-2.0
// In-process RFC 6062 (TURN TCP Allocations) server regression.
//
// Drives a real TurnServer over raw TCP with self-delimiting TURN framing
// (RFC 8656 §4.1 - no RFC 4571 prefix on the control connection) and covers the
// server branches that previously had no in-process coverage:
//
//   G-6062-1  447 (peer not allocated) and 446 (connection already exists)
//   G-6062-2  CreatePermission / ChannelBind on a TCP allocation are accepted
//             as no-ops (RFC 6062 §4 forbids clients sending them)
//   G-6062-3  the data connection is a raw byte pipe: a STUN message sent on it
//             is relayed verbatim and never answered by the server

#include "stserver_test_util.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace stice_test;

namespace {

constexpr int kIoTimeoutMs = 3000;

void closeSock(socket_t s) {
#ifdef _WIN32
	::closesocket(s);
#else
	::close(s);
#endif
}

bool waitReadable(socket_t s, int timeoutMs) {
	fd_set r;
	FD_ZERO(&r);
	FD_SET(s, &r);
	timeval tv{};
	tv.tv_sec = timeoutMs / 1000;
	tv.tv_usec = (timeoutMs % 1000) * 1000;
	int n = ::select(static_cast<int>(s) + 1, &r, nullptr, nullptr, &tv);
	return n > 0 && FD_ISSET(s, &r);
}

bool readExact(socket_t s, unsigned char *buf, std::size_t n, int timeoutMs) {
	std::size_t got = 0;
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
	while (got < n) {
		auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
		                deadline - std::chrono::steady_clock::now())
		                .count();
		if (left <= 0) return false;
		if (!waitReadable(s, static_cast<int>(left))) return false;
		int r = ::recv(s, reinterpret_cast<char *>(buf + got), static_cast<int>(n - got), 0);
		if (r <= 0) return false;
		got += static_cast<std::size_t>(r);
	}
	return true;
}

bool writeAll(socket_t s, const unsigned char *buf, std::size_t n) {
	std::size_t sent = 0;
	while (sent < n) {
		int r = ::send(s, reinterpret_cast<const char *>(buf + sent),
		               static_cast<int>(n - sent), 0);
		if (r <= 0) return false;
		sent += static_cast<std::size_t>(r);
	}
	return true;
}

// Minimal blocking TURN-over-TCP client: self-delimiting frames on the control
// connection, raw bytes on a paired data connection.
struct TcpClient {
	socket_t sock = STICE_INVALID_SOCKET;

	TcpClient() = default;
	explicit TcpClient(std::uint16_t port) { connectTo(port); }
	~TcpClient() { close(); }
	TcpClient(const TcpClient &) = delete;
	TcpClient &operator=(const TcpClient &) = delete;
	TcpClient(TcpClient &&o) noexcept : sock(o.sock) { o.sock = STICE_INVALID_SOCKET; }
	TcpClient &operator=(TcpClient &&o) noexcept {
		if (this != &o) {
			close();
			sock = o.sock;
			o.sock = STICE_INVALID_SOCKET;
		}
		return *this;
	}

	bool connectTo(std::uint16_t port) {
		close();
		socket_t s = ::socket(AF_INET, SOCK_STREAM, 0);
		if (s == STICE_INVALID_SOCKET) return false;
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_port = htons(port);
		a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (::connect(s, reinterpret_cast<sockaddr *>(&a), sizeof(a)) != 0) {
			closeSock(s);
			return false;
		}
		sock = s;
		return true;
	}

	void close() {
		if (sock != STICE_INVALID_SOCKET) {
			closeSock(sock);
			sock = STICE_INVALID_SOCKET;
		}
	}

	bool valid() const { return sock != STICE_INVALID_SOCKET; }

	bool sendMsg(const Message &m) {
		return valid() && writeAll(sock, m.raw.data(), m.raw.size());
	}

	bool recvMsg(Message &out, int timeoutMs = kIoTimeoutMs) {
		unsigned char hdr[stice::stun::MessageHeaderSize];
		if (!readExact(sock, hdr, sizeof(hdr), timeoutMs)) return false;
		std::size_t bodyLen = (static_cast<std::size_t>(hdr[2]) << 8) | hdr[3];
		std::vector<unsigned char> buf(sizeof(hdr) + bodyLen);
		std::memcpy(buf.data(), hdr, sizeof(hdr));
		if (bodyLen && !readExact(sock, buf.data() + sizeof(hdr), bodyLen, timeoutMs)) return false;
		return out.decode(buf.data(), buf.size());
	}

	bool recvRaw(unsigned char *out, std::size_t n, int timeoutMs = kIoTimeoutMs) {
		return readExact(sock, out, n, timeoutMs);
	}

	bool sendRaw(const void *data, std::size_t n) {
		return valid() && writeAll(sock, static_cast<const unsigned char *>(data), n);
	}

	bool quiet(int timeoutMs) { return !waitReadable(sock, timeoutMs); }
};

Message tcpAllocateRequest(const stice::stun::Credentials *creds, std::uint8_t proto) {
	Message req;
	req.method = Method::Allocate;
	req.cls = Class::Request;
	req.newTransactionID();
	stice::stun::addRequestedTransport(req, proto);
	if (creds)
		REQUIRE(req.encode(kPassword, creds, nullptr));
	else
		REQUIRE(req.encode(nullptr, nullptr, nullptr));
	return req;
}

stice::stun::Credentials tcpObtainCredentials(TcpClient &client) {
	Message probe = tcpAllocateRequest(nullptr, 17);
	REQUIRE(client.sendMsg(probe));
	Message challenge;
	REQUIRE(client.recvMsg(challenge));
	REQUIRE(challenge.cls == Class::ErrorResponse);
	REQUIRE(errorCodeOf(challenge) == stice::stun::StunErrorUnauthenticated);
	auto creds = credentialsFor(challenge);
	REQUIRE_FALSE(creds.realm.empty());
	REQUIRE_FALSE(creds.nonce.empty());
	return creds;
}

// TCP allocation helper: returns the relayed address.
AddrRecord tcpAllocate(TcpClient &client, const stice::stun::Credentials &creds) {
	Message req = tcpAllocateRequest(&creds, 6);
	REQUIRE(client.sendMsg(req));
	Message resp;
	REQUIRE(client.recvMsg(resp));
	REQUIRE(resp.cls == Class::SuccessResponse);
	return relayedAddrOf(resp);
}

struct TcpFixture {
	TestServer srv;
	std::uint16_t port = 0;

	TcpFixture() {
		stice_set_log_level(STICE_LOG_LEVEL_ERROR);
		REQUIRE(srv.start());
		port = srv.port;
	}
};

Message makeConnect(const stice::stun::Credentials &creds, const AddrRecord &peer) {
	return controlRequest(creds, [&](Message &m) {
		m.method = Method::Connect;
		stice::stun::writeXorAddress(m, AttrType::XorPeerAddress, peer, m.transactionID);
	});
}

Message makeConnectionBind(const stice::stun::Credentials &creds, std::uint32_t connId) {
	return controlRequest(creds, [&](Message &m) {
		m.method = Method::ConnectionBind;
		stice::stun::addConnectionId(m, connId);
	});
}

// Wait for the CONNECTION-ATTEMPT indication carrying a CONNECTION-ID.
bool recvConnectionAttempt(TcpClient &client, std::uint32_t &connId, AddrRecord &peer) {
	Message ind;
	if (!client.recvMsg(ind)) return false;
	if (ind.method != Method::ConnectionAttempt) return false;
	if (!stice::stun::readConnectionId(ind, connId)) return false;
	return stice::stun::readXorAddress(ind, AttrType::XorPeerAddress, peer, ind.transactionID);
}

} // namespace

// ---- G-6062-1: 447 for a peer that has no TCP allocation -------------------

TEST_CASE("stserver answers 447 when CONNECT targets an unallocated peer",
          "[stserver][6062][protocol]") {
	TcpFixture f;
	TcpClient a(f.port);
	REQUIRE(a.valid());
	auto creds = tcpObtainCredentials(a);
	AddrRecord relayA = tcpAllocate(a, creds);

	// A port inside the same range but with no allocation behind it.
	AddrRecord missing{};
	std::uint16_t missingPort = static_cast<std::uint16_t>(
	    stice::net::addrPort(reinterpret_cast<const sockaddr *>(&relayA.addr)) + 7);
	REQUIRE(stice::net::parseAddr("127.0.0.1", missingPort, missing.addr, missing.len));
	missing.socktype = SOCK_STREAM;

	Message connect = makeConnect(creds, missing);
	REQUIRE(a.sendMsg(connect));
	Message resp;
	REQUIRE(a.recvMsg(resp));
	REQUIRE(resp.cls == Class::ErrorResponse);
	REQUIRE(errorCodeOf(resp) == stice::stun::StunErrorConnectionTimeoutOrFailure);
}

// ---- G-6062-1 / G-6062-3: pairing, 446, raw data pipe ---------------------

TEST_CASE("stserver RFC 6062 pairing answers 446 on duplicate CONNECT and relays raw bytes",
          "[stserver][6062][protocol]") {
	TcpFixture f;

	// Two TCP allocations: A (connector) and B (peer).
	TcpClient a(f.port);
	TcpClient b(f.port);
	REQUIRE(a.valid());
	REQUIRE(b.valid());
	auto credsA = tcpObtainCredentials(a);
	auto credsB = tcpObtainCredentials(b);
	AddrRecord relayA = tcpAllocate(a, credsA);
	AddrRecord relayB = tcpAllocate(b, credsB);
	REQUIRE(stice::net::addrPort(reinterpret_cast<const sockaddr *>(&relayA.addr)) !=
	        stice::net::addrPort(reinterpret_cast<const sockaddr *>(&relayB.addr)));

	// A -> CONNECT(B). The response is held until the first CONNECTION-BIND.
	Message connect = makeConnect(credsA, relayB);
	REQUIRE(a.sendMsg(connect));

	// B is told to open a data connection.
	std::uint32_t connId = 0;
	AddrRecord peerSeen{};
	REQUIRE(recvConnectionAttempt(b, connId, peerSeen));
	REQUIRE(peerSeen.toString() == relayA.toString());

	// B's data connection binds first: B gets success, A gets the CONNECT
	// success with the CONNECTION-ID.
	TcpClient bData(f.port);
	REQUIRE(bData.valid());
	Message bindB = makeConnectionBind(credsB, connId);
	REQUIRE(bData.sendMsg(bindB));
	Message bindBResp;
	REQUIRE(bData.recvMsg(bindBResp));
	REQUIRE(bindBResp.cls == Class::SuccessResponse);

	Message connectResp;
	REQUIRE(a.recvMsg(connectResp));
	REQUIRE(connectResp.cls == Class::SuccessResponse);
	std::uint32_t echoedId = 0;
	REQUIRE(stice::stun::readConnectionId(connectResp, echoedId));
	REQUIRE(echoedId == connId);

	// Duplicate CONNECT to the same peer is 446 (a connection already exists).
	Message duplicate = makeConnect(credsA, relayB);
	REQUIRE(a.sendMsg(duplicate));
	Message dupResp;
	REQUIRE(a.recvMsg(dupResp));
	REQUIRE(dupResp.cls == Class::ErrorResponse);
	REQUIRE(errorCodeOf(dupResp) == stice::stun::StunErrorConnectionAlreadyExists);

	// A's data connection binds second, completing the pair.
	TcpClient aData(f.port);
	REQUIRE(aData.valid());
	Message bindA = makeConnectionBind(credsA, connId);
	REQUIRE(aData.sendMsg(bindA));
	Message bindAResp;
	REQUIRE(aData.recvMsg(bindAResp));
	REQUIRE(bindAResp.cls == Class::SuccessResponse);

	// Data pipe: bytes written on one side arrive verbatim on the other.
	const std::string payload = "rfc6062-raw-pipe";
	REQUIRE(aData.sendRaw(payload.data(), payload.size()));
	std::array<unsigned char, 256> buf{};
	REQUIRE(bData.recvRaw(buf.data(), payload.size()));
	REQUIRE(std::memcmp(buf.data(), payload.data(), payload.size()) == 0);

	// A STUN message on the data connection is just payload: it must be relayed
	// verbatim and never answered by the server (the pipe is not a control
	// connection). This locks the RFC 6062 §5.5 raw-stream contract.
	Message binding = makeBindingRequest();
	REQUIRE(aData.sendRaw(binding.raw.data(), binding.raw.size()));
	std::vector<unsigned char> got(binding.raw.size());
	REQUIRE(bData.recvRaw(got.data(), got.size()));
	REQUIRE(std::memcmp(got.data(), binding.raw.data(), got.size()) == 0);
	REQUIRE(aData.quiet(500));
}

// ---- G-6062-2: CreatePermission / ChannelBind on a TCP allocation ----------

TEST_CASE("stserver accepts CreatePermission and ChannelBind on a TCP allocation",
          "[stserver][6062][protocol]") {
	TcpFixture f;
	TcpClient a(f.port);
	REQUIRE(a.valid());
	auto creds = tcpObtainCredentials(a);
	tcpAllocate(a, creds);

	AddrRecord peer{};
	REQUIRE(stice::net::parseAddr("127.0.0.1", 9999, peer.addr, peer.len));
	peer.socktype = SOCK_STREAM;

	// RFC 6062 §4: clients MUST NOT send these on a TCP allocation. The server
	// accepts them as no-ops (the TCP relay does not filter peers), which is
	// the behaviour this case locks.
	Message perm = makeCreatePermission(creds, peer);
	REQUIRE(a.sendMsg(perm));
	Message permResp;
	REQUIRE(a.recvMsg(permResp));
	REQUIRE(permResp.cls == Class::SuccessResponse);

	Message bind = makeChannelBind(creds, 0x4003, peer);
	REQUIRE(a.sendMsg(bind));
	Message bindResp;
	REQUIRE(a.recvMsg(bindResp));
	REQUIRE(bindResp.cls == Class::SuccessResponse);
}
