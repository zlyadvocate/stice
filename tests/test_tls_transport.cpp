// tests/test_tls_transport.cpp
//
// TLS record-layer regression for TURN over TLS (RFC 8656 §4), run against
// whatever backend the build selected (OpenSSL, GnuTLS or Mbed TLS — see the
// USE_GNUTLS / USE_MBEDTLS handling in CMakeLists.txt).
//
// The test is hermetic: it starts an in-process TLS echo server with the same
// TlsSession abstraction in server mode, then drives the real client path
// (TcpTransport::beginConnect(useTls=true) → handshake → RFC 4571 framing →
// send/recv) against it. That covers, for every backend:
//
//   * the handshake completes and application data round-trips byte-exactly,
//   * a self-signed peer is REJECTED when verification is on and no trust
//     anchor covers it (the secure default),
//   * the same peer is ACCEPTED when STICE_TLS_CA_FILE pins its certificate,
//   * skip_tls_verify accepts it without a trust anchor,
//   * stice_get_tls_backend() reports the backend that was compiled in.
//
// Mbed TLS has no system trust store, so the "rejected" case is only asserted
// for OpenSSL/GnuTLS; for Mbed TLS the first case proves the documented
// VERIFY_NONE fallback instead.

#include "stice/net/addr.hpp"
#include "stice/net/platform.hpp"
#include "stice/net/tcp.hpp"
#include "stice/net/tls.hpp"
#include "stice/stice.h"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
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
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace stice::net;

namespace {

std::string certPath() {
#ifdef STICE_TEST_DATA_DIR
	return std::string(STICE_TEST_DATA_DIR) + "/tls_test_cert.pem";
#else
	return std::string("tests/data/tls_test_cert.pem");
#endif
}

std::string keyPath() {
#ifdef STICE_TEST_DATA_DIR
	return std::string(STICE_TEST_DATA_DIR) + "/tls_test_key.pem";
#else
	return std::string("tests/data/tls_test_key.pem");
#endif
}

// CA that signed the test server certificate (tests/data holds a small
// two-level PKI: tls_test_ca.pem + tls_test_cert.pem/key).
std::string caPath() {
#ifdef STICE_TEST_DATA_DIR
	return std::string(STICE_TEST_DATA_DIR) + "/tls_test_ca.pem";
#else
	return std::string("tests/data/tls_test_ca.pem");
#endif
}

std::string backendName() {
	const char *b = stice_get_tls_backend();
	return b ? b : "none";
}

// Install a stice log handler for the whole test binary: TLS failures are
// reported through STICE_LOG_WARN, and Catch2's output alone would show only
// "did not connect" without the crypto library's reason.
struct LogInstaller {
	LogInstaller() {
		stice_set_log_level(STICE_LOG_LEVEL_WARN);
		stice_set_log_handler([](stice_log_level_t level, const char *msg) {
			std::fprintf(stderr, "[stice %d] %s\n", static_cast<int>(level), msg ? msg : "");
		});
	}
};
LogInstaller g_logInstaller;

void setCaFileEnv(const char *path) {
#ifdef _WIN32
	if (path && *path)
		_putenv_s("STICE_TLS_CA_FILE", path);
	else
		_putenv_s("STICE_TLS_CA_FILE", "");
#else
	if (path && *path)
		setenv("STICE_TLS_CA_FILE", path, 1);
	else
		unsetenv("STICE_TLS_CA_FILE");
#endif
}

// accept()ed sockets can inherit the listener's non-blocking flag (Windows
// does), while the echo server wants a blocking session per connection.
void setBlocking(socket_t s) {
#ifdef _WIN32
	u_long mode = 0;
	ioctlsocket(s, FIONBIO, &mode);
#else
	int flags = ::fcntl(s, F_GETFL, 0);
	if (flags >= 0) ::fcntl(s, F_SETFL, flags & ~O_NONBLOCK);
#endif
}

// In-process TLS echo server: one connection at a time, echoes every byte the
// client sends back through the same TLS session.
class EchoServer {
public:
	EchoServer() = default;
	~EchoServer() { stop(); }

	bool start() {
#ifdef _WIN32
		WSADATA wsa{};
		WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
		listenFd_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (listenFd_ == STICE_INVALID_SOCKET) return false;
		int on = 1;
		setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&on), sizeof(on));
		sockaddr_in sin{};
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		sin.sin_port = 0; // ephemeral
		if (::bind(listenFd_, reinterpret_cast<sockaddr *>(&sin), sizeof(sin)) != 0) return false;
		if (::listen(listenFd_, 8) != 0) return false;
		sockaddr_in bound{};
		socklen_t blen = sizeof(bound);
		if (::getsockname(listenFd_, reinterpret_cast<sockaddr *>(&bound), &blen) != 0) return false;
		port_ = ntohs(bound.sin_port);
		// Non-blocking listener: the accept loop can then always observe
		// stop_, so teardown never depends on close() waking a blocked accept.
		setNonBlocking(listenFd_);
		thread_ = std::thread([this] { run(); });
		return true;
	}

	void stop() {
		stop_.store(true);
		if (listenFd_ != STICE_INVALID_SOCKET) {
			sticeClosesocket(listenFd_);
			listenFd_ = STICE_INVALID_SOCKET;
		}
		if (thread_.joinable()) thread_.join();
	}

	uint16_t port() const { return port_; }
	int handshakes() const { return handshakes_.load(); }
	std::string lastError() const { return err_; }
	std::size_t bytesIn() const { return bytesIn_.load(); }
	std::size_t bytesOut() const { return bytesOut_.load(); }

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
			std::fprintf(stderr, "[echo-server] %s\n", err_.c_str());
			return;
		}
		// Blocking socket: a WantRead/WantWrite here just means "call again",
		// which the blocking transport turns into a wait inside recv/send.
		bool established = false;
		for (int i = 0; i < 100000 && !established; ++i) {
			TlsStatus st = tls.handshake();
			if (st == TlsStatus::Ok) {
				established = true;
			} else if (st == TlsStatus::WantRead || st == TlsStatus::WantWrite) {
				continue;
			} else {
				err_ = "handshake: " + tls.errorString();
				std::fprintf(stderr, "[echo-server] %s\n", err_.c_str());
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

		std::vector<unsigned char> buf(16384);
		while (!stop_.load()) {
			std::size_t n = 0;
			TlsStatus st = tls.read(buf.data(), buf.size(), n);
			if (st == TlsStatus::Ok) {
				bytesIn_.fetch_add(n);
				std::size_t off = 0;
				while (off < n && !stop_.load()) {
					std::size_t w = 0;
					TlsStatus wst = tls.write(buf.data() + off, n - off, w);
					if (wst == TlsStatus::Ok) {
						off += w;
						bytesOut_.fetch_add(w);
					} else if (wst == TlsStatus::WantRead || wst == TlsStatus::WantWrite) {
						continue;
					} else {
						err_ = "echo write: " + tls.errorString();
						tls.close();
						return;
					}
				}
			} else if (st == TlsStatus::Closed) {
				break;
			} else if (st == TlsStatus::Failed) {
				err_ = "echo read: " + tls.errorString();
				break;
			}
		}
		tls.shutdown();
		tls.close();
	}

	socket_t listenFd_ = STICE_INVALID_SOCKET;
	uint16_t port_ = 0;
	std::atomic<bool> stop_{false};
	std::atomic<int> handshakes_{0};
	std::atomic<std::size_t> bytesIn_{0};
	std::atomic<std::size_t> bytesOut_{0};
	std::string err_;
	std::thread thread_;
};

// Pump the TcpTransport until it reaches a terminal/desired state.
bool driveTo(TcpTransport &t, TcpState want, int timeoutMs) {
	auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
	while (std::chrono::steady_clock::now() < deadline) {
		TcpState st = t.state();
		if (st == want) return true;
		if (st == TcpState::Failed || (st == TcpState::Disconnected && want != TcpState::Disconnected))
			return false;
		struct pollfd pfd{};
		pfd.fd = t.handle();
		pfd.events = POLLIN | POLLOUT;
		sticePoll(&pfd, 1, 20);
		if (pfd.revents & (POLLOUT | POLLIN | POLLERR | POLLHUP)) {
			t.onWritable();
			t.onReadable();
		}
	}
	return false;
}

AddrRecord loopback(uint16_t port) {
	AddrRecord rec;
	parseAddr("127.0.0.1", port, rec.addr, rec.len);
	rec.socktype = SOCK_STREAM;
	return rec;
}

} // namespace

TEST_CASE("TLS: backend is reported by the C API", "[tls]") {
	// A build with TLS must name its backend; when stice was configured with no
	// TLS library the whole suite below degrades to a single skip.
	const std::string b = backendName();
	INFO("TLS backend: " << b);
	REQUIRE_FALSE(b.empty());
	REQUIRE((b == "openssl" || b == "gnutls" || b == "mbedtls" || b == "none"));
}

TEST_CASE("TLS: handshake + byte-exact echo over TcpTransport", "[tls][transport]") {
	REQUIRE(backendName() != "none");

	EchoServer server;
	REQUIRE(server.start());

	TcpTransport client;
	// skipVerify=true: this case is about the record layer, not about trust.
	REQUIRE(client.beginConnect(loopback(server.port()), "localhost", true, true));
	REQUIRE(driveTo(client, TcpState::Connected, 8000));

	// 60000 bytes: one RFC 4571 frame (the 2-byte length prefix caps a frame at
	// 65535 bytes), large enough to span several TLS records.
	std::string payload;
	payload.reserve(60000);
	for (int i = 0; i < 60000; ++i) payload.push_back(static_cast<char>('a' + (i % 26)));
	REQUIRE(client.send(payload.data(), payload.size()));

	std::string echoed;
	std::vector<char> buf(65536);
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
	while (echoed.size() < payload.size() && std::chrono::steady_clock::now() < deadline) {
		struct pollfd pfd{};
		pfd.fd = client.handle();
		pfd.events = POLLIN | POLLOUT;
		sticePoll(&pfd, 1, 20);
		// onWritable()/onReadable() are the transport's pump: onReadable()
		// moves ciphertext into the receive buffer, recv() only de-frames it.
		if (pfd.revents & (POLLOUT | POLLERR | POLLHUP)) client.onWritable();
		if (pfd.revents & (POLLIN | POLLERR | POLLHUP)) {
			client.onReadable();
			AddrRecord peer;
			int n = client.recv(buf.data(), buf.size(), peer);
			if (n > 0) echoed.append(buf.data(), static_cast<std::size_t>(n));
			else if (n < 0) break;
		}
	}
	INFO("backend=" << backendName() << " server_err='" << server.lastError() << "' handshakes="
	                << server.handshakes() << " client_state=" << static_cast<int>(client.state())
	                << " echoed=" << echoed.size() << "/" << payload.size() << " server_in="
	                << server.bytesIn() << " server_out=" << server.bytesOut());
	REQUIRE(echoed.size() == payload.size());
	REQUIRE(echoed == payload);
	REQUIRE(server.handshakes() == 1);
	client.close();
	server.stop();
}

TEST_CASE("TLS: self-signed peer is rejected without a trust anchor", "[tls][verify]") {
	if (backendName() == "none") return;
	// Mbed TLS has no system trust store: without STICE_TLS_CA_FILE it runs
	// with VERIFY_NONE by design (documented), so the rejection cannot be
	// asserted there.
	if (backendName() == "mbedtls") return;

	EchoServer server;
	REQUIRE(server.start());
	setCaFileEnv(nullptr);

	TcpTransport client;
	REQUIRE(client.beginConnect(loopback(server.port()), "localhost", true, false));
	// Verification must fail the handshake: the peer certificate is self-signed
	// and not in the platform trust store.
	REQUIRE_FALSE(driveTo(client, TcpState::Connected, 8000));
	REQUIRE((client.state() == TcpState::Failed || client.state() == TcpState::Disconnected));
	client.close();
	server.stop();
}

TEST_CASE("TLS: IP-addressed peer is matched against its iPAddress SAN", "[tls][verify]") {
	if (backendName() == "none") return;

	EchoServer server;
	REQUIRE(server.start());
	// tests/data/tls_test_cert.pem carries SAN DNS:localhost, IP:127.0.0.1, so
	// addressing the peer by IP must verify against the IP SAN (and the literal
	// must not be sent as SNI), while 127.0.0.2 is not in the certificate.
	// This is the TURN-by-IP case: mbedTLS 2.x needs its own DER SAN lookup.
	setCaFileEnv(nullptr);
	{
		TcpTransport client;
		REQUIRE(client.beginConnect(loopback(server.port()), "127.0.0.1", true, false, caPath()));
		REQUIRE(driveTo(client, TcpState::Connected, 8000));
		client.close();
	}
	{
		TcpTransport client;
		REQUIRE(client.beginConnect(loopback(server.port()), "127.0.0.2", true, false, caPath()));
		REQUIRE(driveTo(client, TcpState::Failed, 8000));
		client.close();
	}
	server.stop();
}

TEST_CASE("TLS: per-connection caFile overrides STICE_TLS_CA_FILE", "[tls][verify]") {
	if (backendName() == "none") return;

	EchoServer server;
	REQUIRE(server.start());

	// This is the rule stice_turn_server_t::ca_file relies on: a non-empty
	// per-connection bundle wins, an empty one falls back to the environment.
	// That is what lets one agent hold allocations on several TURN servers with
	// different private CAs.

	// 1) The field alone pins the trust anchor (no environment variable).
	setCaFileEnv(nullptr);
	{
		TcpTransport client;
		REQUIRE(client.beginConnect(loopback(server.port()), "localhost", true, false, caPath()));
		REQUIRE(driveTo(client, TcpState::Connected, 8000));
		client.close();
	}

	// 2) The field wins over a broken env value: the env path does not exist,
	//    yet the handshake succeeds because the per-connection bundle is used.
	setCaFileEnv("/nonexistent/stice-env-ca.pem");
	{
		TcpTransport client;
		REQUIRE(client.beginConnect(loopback(server.port()), "localhost", true, false, caPath()));
		REQUIRE(driveTo(client, TcpState::Connected, 8000));
		client.close();
	}

	// 3) ... and the reverse: a non-empty field is authoritative, so a broken
	//    per-connection bundle must fail even though the env would have worked.
	//    Silently falling back would hide a misconfigured server.
	setCaFileEnv(caPath().c_str());
	{
		TcpTransport client;
		REQUIRE(client.beginConnect(loopback(server.port()), "localhost", true, false,
		                            "/nonexistent/stice-per-server-ca.pem"));
		REQUIRE(driveTo(client, TcpState::Failed, 8000));
		client.close();
	}

	setCaFileEnv(nullptr);
	server.stop();
}

TEST_CASE("TLS: STICE_TLS_CA_FILE pins the peer certificate", "[tls][verify]") {
	if (backendName() == "none") return;

	EchoServer server;
	REQUIRE(server.start());
	// Trust exactly the CA that signed the test server certificate: pinning has
	// to make the same peer that was rejected above acceptable with verification
	// left ON.
	setCaFileEnv(caPath().c_str());

	TcpTransport client;
	REQUIRE(client.beginConnect(loopback(server.port()), "localhost", true, false));
	REQUIRE(driveTo(client, TcpState::Connected, 8000));

	const std::string msg = "pinned-ca-roundtrip";
	REQUIRE(client.send(msg.data(), msg.size()));
	std::string echoed;
	std::vector<char> buf(4096);
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	while (echoed.size() < msg.size() && std::chrono::steady_clock::now() < deadline) {
		struct pollfd pfd{};
		pfd.fd = client.handle();
		pfd.events = POLLIN | POLLOUT;
		sticePoll(&pfd, 1, 20);
		if (pfd.revents & (POLLOUT | POLLERR | POLLHUP)) client.onWritable();
		if (pfd.revents & (POLLIN | POLLERR | POLLHUP)) {
			client.onReadable();
			AddrRecord peer;
			int n = client.recv(buf.data(), buf.size(), peer);
			if (n > 0) echoed.append(buf.data(), static_cast<std::size_t>(n));
			else if (n < 0) break;
		}
	}
	REQUIRE(echoed == msg);
	client.close();
	setCaFileEnv(nullptr);
	server.stop();
}
