// tests/test_tls_turn.cpp
//
// TURN over TLS (RFC 8656 §4) allocation, end to end, with an in-process TLS
// TURN server. Unlike test_longrun_4mode (which needs an external coturn and is
// pinned to a 60 s smoke run in ctest) this test actually exercises the
// STICE_TURN_TRANSPORT_TLS code path:
//
//   G-TURNTSL-1  Allocate over a TLS control connection succeeds and the agent
//                emits a relay candidate. Covers the 401 challenge/credential
//                retry and the response MESSAGE-INTEGRITY check.
//   G-TURNTSL-2  A STUN transaction on the reliable TLS transport is not
//                retransmitted: with the first Allocate held for 1.2 s (longer
//                than the 500 ms initial RTO), the server must still see exactly
//                one unauthenticated Allocate.
//
// The server is deliberately minimal: it answers Allocate/Refresh/
// CreatePermission/ChannelBind and signs responses with the long-term key,
// which is all gathering needs. It is not a relay.

#include <catch2/catch_all.hpp>

#include "stice/net/addr.hpp"
#include "stice/net/platform.hpp"
#include "stice/net/tls.hpp"
#include "stice/stice.h"
#include "stice/stun/attributes.hpp"
#include "stice/stun/message.hpp"
#include "stice/crypto.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace stice;
using namespace stice::net;

namespace {

std::string dataPath(const char *name) {
#ifdef STICE_TEST_DATA_DIR
	return std::string(STICE_TEST_DATA_DIR) + "/" + name;
#else
	return std::string("tests/data/") + name;
#endif
}

std::string certPath() { return dataPath("tls_test_cert.pem"); }
std::string keyPath() { return dataPath("tls_test_key.pem"); }
std::string caPath() { return dataPath("tls_test_ca.pem"); }

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

void setBlocking(socket_t s) {
#ifdef _WIN32
	u_long mode = 0;
	ioctlsocket(s, FIONBIO, &mode);
#else
	int flags = ::fcntl(s, F_GETFL, 0);
	if (flags >= 0) ::fcntl(s, F_SETFL, flags & ~O_NONBLOCK);
#endif
}

// Minimal in-process TURN-over-TLS server. One control connection at a time
// (the agent opens exactly one for a single TURN server).
class TlsTurnServer {
public:
	TlsTurnServer() = default;
	~TlsTurnServer() { stop(); }

	// Delay applied before answering the FIRST Allocate. A UDP client would
	// retransmit at the 500 ms initial RTO; a TLS client must not.
	void setFirstAllocateDelayMs(int ms) { firstAllocateDelayMs_ = ms; }

	bool start() {
#ifdef _WIN32
		WSADATA wsa{};
		WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
		listenFd_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (listenFd_ == STICE_INVALID_SOCKET) return false;
		int on = 1;
		setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR,
		           reinterpret_cast<const char *>(&on), sizeof(on));
		sockaddr_in sin{};
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		sin.sin_port = 0;
		if (::bind(listenFd_, reinterpret_cast<sockaddr *>(&sin), sizeof(sin)) != 0) return false;
		if (::listen(listenFd_, 4) != 0) return false;
		sockaddr_in bound{};
		socklen_t blen = sizeof(bound);
		if (::getsockname(listenFd_, reinterpret_cast<sockaddr *>(&bound), &blen) != 0) return false;
		port_ = ntohs(bound.sin_port);
		setNonBlocking(listenFd_);
		thread_ = std::thread([this] { run(); });
		return true;
	}

	void stop() {
		stop_.store(true);
		if (thread_.joinable()) thread_.join();
		if (listenFd_ != STICE_INVALID_SOCKET) {
			sticeClosesocket(listenFd_);
			listenFd_ = STICE_INVALID_SOCKET;
		}
	}

	uint16_t port() const { return port_; }
	int handshakes() const { return handshakes_.load(); }
	// Total Allocate requests received (authenticated + unauthenticated).
	int allocateRequests() const { return allocateRequests_.load(); }
	int authenticatedAllocates() const { return authenticatedAllocates_.load(); }
	std::string lastError() const { return err_; }

private:
	void run() {
		while (!stop_.load()) {
			sockaddr_storage ss{};
			socklen_t sl = sizeof(ss);
			socket_t c = ::accept(listenFd_, reinterpret_cast<sockaddr *>(&ss), &sl);
			if (c == STICE_INVALID_SOCKET) {
				if (stop_.load()) return;
				std::this_thread::sleep_for(std::chrono::milliseconds(5));
				continue;
			}
			serveOne(c);
			sticeClosesocket(c);
		}
	}

	void serveOne(socket_t c) {
		setBlocking(c);
		TlsSession tls;
		TlsParams p;
		p.certFile = certPath();
		p.keyFile = keyPath();
		if (!tls.initServer(c, p)) {
			err_ = "initServer: " + tls.errorString();
			return;
		}
		bool established = false;
		for (int i = 0; i < 100000 && !established && !stop_.load(); ++i) {
			TlsStatus st = tls.handshake();
			if (st == TlsStatus::Ok) established = true;
			else if (st != TlsStatus::WantRead && st != TlsStatus::WantWrite) {
				err_ = "handshake: " + tls.errorString();
				tls.close();
				return;
			}
		}
		if (!established) {
			err_ = "handshake did not converge";
			tls.close();
			return;
		}
		handshakes_.fetch_add(1);

		std::vector<unsigned char> pending;
		std::vector<unsigned char> buf(16384);
		while (!stop_.load()) {
			std::size_t n = 0;
			TlsStatus st = tls.read(buf.data(), buf.size(), n);
			if (st == TlsStatus::Ok) {
				if (n > 0) {
					pending.insert(pending.end(), buf.begin(), buf.begin() + n);
					// TURN over TCP/TLS uses self-delimiting STUN framing: the
					// header's 16-bit length (minus the 0x8000 marker bit) is the
					// number of bytes after the 20-byte header.
					while (pending.size() >= stun::MessageHeaderSize) {
						std::size_t bodyLen =
						    (static_cast<std::size_t>(pending[2] & 0x7f) << 8) | pending[3];
						std::size_t total = stun::MessageHeaderSize + bodyLen;
						if (pending.size() < total) break;
						handleFrame(tls, pending.data(), total);
						pending.erase(pending.begin(), pending.begin() + total);
					}
				}
			} else if (st == TlsStatus::Closed) {
				break;
			} else if (st == TlsStatus::Failed) {
				err_ = "read: " + tls.errorString();
				break;
			}
		}
		tls.shutdown();
		tls.close();
	}

	void sendBytes(TlsSession &tls, const bytes &raw) {
		std::size_t off = 0;
		while (off < raw.size() && !stop_.load()) {
			std::size_t w = 0;
			TlsStatus st = tls.write(raw.data() + off, raw.size() - off, w);
			if (st == TlsStatus::Ok) off += w;
			else if (st != TlsStatus::WantRead && st != TlsStatus::WantWrite) return;
		}
	}

	// Sign a response the way a compliant TURN server does: long-term
	// MESSAGE-INTEGRITY, no USERNAME/REALM/NONCE echo (RFC 8489 §9.2.2).
	static void signResponse(stun::Message &m) {
		stun::Credentials creds;
		creds.username = "alice";
		creds.realm = "example.org";
		auto key = crypto::longTermKey(creds.username, creds.realm, "secret");
		creds.key.assign(key.begin(), key.end());
		m.encode("secret", &creds, nullptr, /*emitAuthAttributes=*/false);
	}

	void handleFrame(TlsSession &tls, const unsigned char *data, std::size_t size) {
		stun::Message m;
		if (!m.decode(data, size)) return;
		if (m.cls != stun::Class::Request) return;

		if (m.method == stun::Method::Allocate) {
			const bool authenticated = m.find(stun::AttrType::Username) != nullptr;
			int seq = allocateRequests_.fetch_add(1) + 1;
			if (authenticated) authenticatedAllocates_.fetch_add(1);
			if (seq == 1 && firstAllocateDelayMs_ > 0) {
				std::this_thread::sleep_for(std::chrono::milliseconds(firstAllocateDelayMs_));
			}
			if (!authenticated) {
				stun::Message r;
				r.method = stun::Method::Allocate;
				r.cls = stun::Class::ErrorResponse;
				r.transactionID = m.transactionID;
				stun::addErrorCode(r, stun::StunErrorUnauthenticated, "Unauthenticated");
				stun::addString(r, stun::AttrType::Realm, "example.org");
				stun::addString(r, stun::AttrType::Nonce, "nonce1");
				r.encode(nullptr, nullptr, nullptr);
				sendBytes(tls, r.raw);
			} else {
				stun::Message r;
				r.method = stun::Method::Allocate;
				r.cls = stun::Class::SuccessResponse;
				r.transactionID = m.transactionID;
				stun::writeXorAddress(r, stun::AttrType::XorRelayedAddress,
				                       makeV4(0x7F000001u, 5000), r.transactionID);
				stun::writeXorAddress(r, stun::AttrType::XorMappedAddress,
				                       makeV4(0x7F000001u, 12345), r.transactionID);
				stun::addLifetime(r, 600);
				signResponse(r);
				sendBytes(tls, r.raw);
			}
			return;
		}

		// Refresh / CreatePermission / ChannelBind: a plain signed success is
		// enough for gathering and for the allocation's keepalive.
		if (m.method == stun::Method::Refresh || m.method == stun::Method::CreatePermission ||
		    m.method == stun::Method::ChannelBind) {
			stun::Message r;
			r.method = m.method;
			r.cls = stun::Class::SuccessResponse;
			r.transactionID = m.transactionID;
			if (m.method == stun::Method::Refresh) stun::addLifetime(r, 600);
			signResponse(r);
			sendBytes(tls, r.raw);
			return;
		}
	}

	socket_t listenFd_ = STICE_INVALID_SOCKET;
	uint16_t port_ = 0;
	int firstAllocateDelayMs_ = 0;
	std::atomic<bool> stop_{false};
	std::atomic<int> handshakes_{0};
	std::atomic<int> allocateRequests_{0};
	std::atomic<int> authenticatedAllocates_{0};
	std::string err_;
	std::thread thread_;
};

struct GatherState {
	std::atomic<bool> done{false};
	std::atomic<stice_state_t> state{STICE_STATE_DISCONNECTED};
};

bool waitFor(const std::function<bool()> &cond, int timeoutMs) {
	auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
	while (std::chrono::steady_clock::now() < deadline) {
		if (cond()) return true;
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	return cond();
}

// Count `typ relay` candidate lines in an SDP description.
int countRelayCandidates(const std::string &sdp) {
	int n = 0;
	std::size_t pos = 0;
	while ((pos = sdp.find("typ relay", pos)) != std::string::npos) {
		++n;
		pos += 9;
	}
	return n;
}

} // namespace

TEST_CASE("TURN over TLS: Allocate succeeds and yields a relay candidate", "[turn][tls][integration]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	TlsTurnServer server;
	REQUIRE(server.start());

	GatherState st;
	stice_config_t cfg{};
	cfg.local_port_range_begin = 0;
	cfg.local_port_range_end = 0;
	cfg.multicast_dns_mode = STICE_MDNS_MODE_DISABLED;
	cfg.cb_gathering_done = [](stice_agent_t *, void *user) {
		static_cast<GatherState *>(user)->done.store(true);
	};
	cfg.cb_state_changed = [](stice_agent_t *, stice_state_t s, void *user) {
		static_cast<GatherState *>(user)->state.store(s);
	};
	cfg.user_ptr = &st;

	stice_turn_server_t turn{};
	turn.host = "127.0.0.1";
	turn.username = "alice";
	turn.password = "secret";
	turn.port = server.port();
	turn.transport = STICE_TURN_TRANSPORT_TLS;
	turn.skip_tls_verify = 0;
	// caPath() returns by value: keep the string alive across stice_create(),
	// which copies the pointer's contents but only during the call.
	const std::string ca = caPath();
	turn.ca_file = ca.c_str();
	cfg.turn_servers = &turn;
	cfg.turn_servers_count = 1;

	stice_agent_t *agent = stice_create(&cfg);
	REQUIRE(agent != nullptr);
	REQUIRE(stice_gather_candidates(agent) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return st.done.load(); }, 15000));

	char sdp[8192];
	REQUIRE(stice_get_local_description(agent, sdp, sizeof(sdp)) == STICE_ERR_SUCCESS);
	const std::string desc(sdp);
	INFO("TLS TURN handshakes=" << server.handshakes() << " allocates=" << server.allocateRequests()
	                            << " server_err='" << server.lastError() << "'");
	REQUIRE(server.handshakes() >= 1);
	REQUIRE(server.authenticatedAllocates() >= 1);
	REQUIRE(countRelayCandidates(desc) >= 1);

	stice_destroy(agent);
	server.stop();
}

TEST_CASE("TURN over TLS: a STUN transaction is never retransmitted", "[turn][tls][rfc8656]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	TlsTurnServer server;
	// Longer than the 500 ms initial RTO: a UDP-style retransmission would show
	// up as a second unauthenticated Allocate with the same transaction ID.
	server.setFirstAllocateDelayMs(1200);
	REQUIRE(server.start());

	GatherState st;
	stice_config_t cfg{};
	cfg.local_port_range_begin = 0;
	cfg.local_port_range_end = 0;
	cfg.multicast_dns_mode = STICE_MDNS_MODE_DISABLED;
	cfg.cb_gathering_done = [](stice_agent_t *, void *user) {
		static_cast<GatherState *>(user)->done.store(true);
	};
	cfg.user_ptr = &st;

	stice_turn_server_t turn{};
	turn.host = "127.0.0.1";
	turn.username = "alice";
	turn.password = "secret";
	turn.port = server.port();
	turn.transport = STICE_TURN_TRANSPORT_TLS;
	turn.skip_tls_verify = 0;
	const std::string ca = caPath();
	turn.ca_file = ca.c_str();
	cfg.turn_servers = &turn;
	cfg.turn_servers_count = 1;

	stice_agent_t *agent = stice_create(&cfg);
	REQUIRE(agent != nullptr);
	REQUIRE(stice_gather_candidates(agent) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return st.done.load(); }, 20000));

	// Give any delayed duplicate time to arrive before sampling.
	std::this_thread::sleep_for(std::chrono::milliseconds(300));
	INFO("allocates=" << server.allocateRequests()
	                  << " authenticated=" << server.authenticatedAllocates()
	                  << " server_err='" << server.lastError() << "'");
	// Exactly the initial challenge request plus the authenticated retry.
	REQUIRE(server.allocateRequests() == 2);
	REQUIRE(server.authenticatedAllocates() == 1);

	stice_destroy(agent);
	server.stop();
}
