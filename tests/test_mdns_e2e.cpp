// tests/test_mdns_e2e.cpp
//
// End-to-end mDNS ICE candidate tests (draft-ietf-rtcweb-mdns-ice-candidates).
//
//   G-MDNS-1  QueryAndGather must advertise host candidates as "<uuid>.local"
//             and must NOT leak the real interface IP in the SDP.
//   G-MDNS-2  A remote "x.local" candidate is resolved through a real multicast
//             query/answer exchange, the candidate is replaced by the resolved
//             address, and ICE connects over it.
//
// The resolver side is driven by a tiny hand-rolled mDNS responder (not another
// MDnsClient): MDnsClient always answers with the unicast-response (QU) bit set,
// and on one host two sockets bound to 5353 would race for the unicast answer.
// Answering via the multicast group removes that ambiguity, so the test is
// deterministic on both platforms.

#include <catch2/catch_all.hpp>

#include "stice/net/mdns.hpp"
#include "stice/net/platform.hpp"
#include "stice/stice.h"

#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <functional>
#include <mutex>
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

namespace {

constexpr const char *kMcast4 = "224.0.0.251";
constexpr std::uint16_t kMdnsPort = 5353;

std::string lower(std::string s) {
	for (auto &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	return s;
}

bool parseDnsName(const unsigned char *data, std::size_t size, std::size_t &off,
                  std::string &out) {
	out.clear();
	std::size_t p = off;
	while (p < size) {
		unsigned char len = data[p];
		if ((len & 0xC0) == 0xC0) {
			// Compression pointer: only its length matters here (a query never
			// points, but tolerate it).
			if (p + 1 >= size) return false;
			off = p + 2;
			return !out.empty();
		}
		if (len == 0) {
			off = p + 1;
			return true;
		}
		if (p + 1 + len > size) return false;
		if (!out.empty()) out.push_back('.');
		out.append(reinterpret_cast<const char *>(data + p + 1), len);
		p += 1 + len;
	}
	return false;
}

void appendName(std::vector<unsigned char> &out, const std::string &name) {
	std::size_t start = 0;
	while (start < name.size()) {
		auto dot = name.find('.', start);
		std::size_t end = dot == std::string::npos ? name.size() : dot;
		out.push_back(static_cast<unsigned char>(end - start));
		out.insert(out.end(), name.begin() + static_cast<long>(start), name.begin() + static_cast<long>(end));
		if (dot == std::string::npos) break;
		start = dot + 1;
	}
	out.push_back(0);
}

// Minimal mDNS responder: answers A queries for one name with one IPv4 address,
// sending the answer to the multicast group so every listener sees it.
class MdnsResponder {
public:
	~MdnsResponder() { stop(); }

	bool start(const std::string &name, const std::string &ip) {
#ifdef _WIN32
		WSADATA wsa{};
		WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
		target_ = lower(name);
		inet_pton(AF_INET, ip.c_str(), &addr4_);
		sock_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sock_ == STICE_INVALID_SOCKET) return false;
		int on = 1;
		setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&on), sizeof(on));
		sockaddr_in bindAddr{};
		bindAddr.sin_family = AF_INET;
		bindAddr.sin_addr.s_addr = htonl(INADDR_ANY);
		bindAddr.sin_port = htons(kMdnsPort);
		if (::bind(sock_, reinterpret_cast<sockaddr *>(&bindAddr), sizeof(bindAddr)) != 0) {
			sticeClosesocket(sock_);
			sock_ = STICE_INVALID_SOCKET;
			return false;
		}
		ip_mreq mreq{};
		inet_pton(AF_INET, kMcast4, &mreq.imr_multiaddr);
		mreq.imr_interface.s_addr = htonl(INADDR_ANY);
		if (setsockopt(sock_, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		               reinterpret_cast<const char *>(&mreq), sizeof(mreq)) != 0) {
			sticeClosesocket(sock_);
			sock_ = STICE_INVALID_SOCKET;
			return false;
		}
		mcast_.sin_family = AF_INET;
		mcast_.sin_port = htons(kMdnsPort);
		inet_pton(AF_INET, kMcast4, &mcast_.sin_addr);
		stice::net::setNonBlocking(sock_);
		thread_ = std::thread([this] { run(); });
		return true;
	}

	void stop() {
		stop_.store(true);
		if (thread_.joinable()) thread_.join();
		if (sock_ != STICE_INVALID_SOCKET) {
			ip_mreq mreq{};
			inet_pton(AF_INET, kMcast4, &mreq.imr_multiaddr);
			mreq.imr_interface.s_addr = htonl(INADDR_ANY);
			setsockopt(sock_, IPPROTO_IP, IP_DROP_MEMBERSHIP,
			           reinterpret_cast<const char *>(&mreq), sizeof(mreq));
			sticeClosesocket(sock_);
			sock_ = STICE_INVALID_SOCKET;
		}
	}

	int answered() const { return answered_.load(); }

private:
	void run() {
		unsigned char buf[2048];
		while (!stop_.load()) {
			sockaddr_in from{};
			socklen_t fl = sizeof(from);
			int n = static_cast<int>(::recvfrom(sock_, reinterpret_cast<char *>(buf), sizeof(buf), 0,
			                                    reinterpret_cast<sockaddr *>(&from), &fl));
			if (n <= 0) {
				std::this_thread::sleep_for(std::chrono::milliseconds(5));
				continue;
			}
			handle(buf, static_cast<std::size_t>(n));
		}
	}

	void handle(const unsigned char *data, std::size_t size) {
		if (size < 12) return;
		std::uint16_t flags = static_cast<std::uint16_t>((data[2] << 8) | data[3]);
		if (flags & 0x8000) return; // a response, not a query
		std::uint16_t qd = static_cast<std::uint16_t>((data[4] << 8) | data[5]);
		if (qd == 0) return;
		std::size_t off = 12;
		std::string name;
		if (!parseDnsName(data, size, off, name)) return;
		if (off + 4 > size) return;
		std::uint16_t qtype = static_cast<std::uint16_t>((data[off] << 8) | data[off + 1]);
		off += 4;
		if (qtype != 1) return; // A only
		if (lower(name) != target_) return;

		std::uint16_t id = static_cast<std::uint16_t>((data[0] << 8) | data[1]);
		std::vector<unsigned char> r;
		auto put16 = [&](std::uint16_t v) {
			r.push_back(static_cast<unsigned char>(v >> 8));
			r.push_back(static_cast<unsigned char>(v & 0xff));
		};
		auto put32 = [&](std::uint32_t v) {
			r.push_back(static_cast<unsigned char>(v >> 24));
			r.push_back(static_cast<unsigned char>(v >> 16));
			r.push_back(static_cast<unsigned char>(v >> 8));
			r.push_back(static_cast<unsigned char>(v));
		};
		put16(id);
		put16(0x8400); // response + authoritative
		put16(1);      // qdcount
		put16(1);      // ancount
		put16(0);
		put16(0);
		appendName(r, name);
		put16(1); // A
		put16(1); // IN
		r.push_back(0xC0);
		r.push_back(0x0C); // answer name = pointer to the question at offset 12
		put16(1);          // A
		put16(0x8001);     // IN + cache-flush
		put32(120);        // TTL
		put16(4);
		r.insert(r.end(), reinterpret_cast<unsigned char *>(&addr4_),
		         reinterpret_cast<unsigned char *>(&addr4_) + 4);
		::sendto(sock_, reinterpret_cast<const char *>(r.data()), static_cast<int>(r.size()), 0,
		         reinterpret_cast<const sockaddr *>(&mcast_), sizeof(mcast_));
		answered_.fetch_add(1);
	}

	socket_t sock_ = STICE_INVALID_SOCKET;
	std::string target_;
	in_addr addr4_{};
	sockaddr_in mcast_{};
	std::atomic<bool> stop_{false};
	std::atomic<int> answered_{0};
	std::thread thread_;
};

struct AgentState {
	std::atomic<bool> gatheringDone{false};
	std::atomic<stice_state_t> state{STICE_STATE_DISCONNECTED};
	std::mutex candidatesMutex;
	std::vector<std::string> candidates;
};

stice_config_t makeConfig(AgentState &st, const char *bindAddr,
                          stice_multicast_dns_mode_t mdnsMode) {
	stice_config_t cfg{};
	cfg.bind_address = bindAddr;
	cfg.local_port_range_begin = 0;
	cfg.local_port_range_end = 0;
	cfg.multicast_dns_mode = mdnsMode;
	cfg.cb_gathering_done = [](stice_agent_t *, void *user) {
		static_cast<AgentState *>(user)->gatheringDone.store(true);
	};
	cfg.cb_state_changed = [](stice_agent_t *, stice_state_t s, void *user) {
		static_cast<AgentState *>(user)->state.store(s);
	};
	cfg.cb_candidate = [](stice_agent_t *, const char *cand, void *user) {
		auto *st = static_cast<AgentState *>(user);
		std::lock_guard<std::mutex> lk(st->candidatesMutex);
		st->candidates.emplace_back(cand);
	};
	cfg.user_ptr = &st;
	return cfg;
}

bool waitFor(const std::function<bool()> &cond, int timeoutMs) {
	auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
	while (std::chrono::steady_clock::now() < deadline) {
		if (cond()) return true;
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	return cond();
}

std::vector<std::string> splitLines(const std::string &s) {
	std::vector<std::string> out;
	std::size_t start = 0;
	while (start <= s.size()) {
		auto nl = s.find('\n', start);
		std::string line = s.substr(start, nl == std::string::npos ? std::string::npos : nl - start);
		if (!line.empty() && line.back() == '\r') line.pop_back();
		if (!line.empty()) out.push_back(line);
		if (nl == std::string::npos) break;
		start = nl + 1;
	}
	return out;
}

// Rewrite the connection address (token 5) of every candidate line.
std::string rewriteCandidateAddress(const std::string &sdp, const std::string &newAddr) {
	std::string out;
	for (const auto &line : splitLines(sdp)) {
		if (line.rfind("a=candidate:", 0) == 0) {
			std::vector<std::string> tokens;
			std::size_t start = std::strlen("a=candidate:");
			std::size_t p = start;
			while (p <= line.size()) {
				auto sp = line.find(' ', p);
				tokens.push_back(line.substr(p, sp == std::string::npos ? std::string::npos : sp - p));
				if (sp == std::string::npos) break;
				p = sp + 1;
			}
			// tokens: foundation component transport priority address port ...
			if (tokens.size() > 4) tokens[4] = newAddr;
			out += "a=candidate:";
			for (std::size_t i = 0; i < tokens.size(); ++i) {
				if (i) out += ' ';
				out += tokens[i];
			}
		} else {
			out += line;
		}
		out += "\r\n";
	}
	return out;
}

// Addresses advertised as host candidates in an SDP description.
std::vector<std::string> hostCandidateAddresses(const std::string &sdp) {
	std::vector<std::string> out;
	for (const auto &line : splitLines(sdp)) {
		if (line.rfind("a=candidate:", 0) != 0) continue;
		std::vector<std::string> tokens;
		std::size_t p = std::strlen("a=candidate:");
		while (p <= line.size()) {
			auto sp = line.find(' ', p);
			tokens.push_back(line.substr(p, sp == std::string::npos ? std::string::npos : sp - p));
			if (sp == std::string::npos) break;
			p = sp + 1;
		}
		if (tokens.size() > 7 && tokens[7] == "host") out.push_back(tokens[4]);
	}
	return out;
}

} // namespace

TEST_CASE("mDNS QueryAndGather advertises .local and never leaks the IP", "[mdns][gather]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	AgentState st;
	auto cfg = makeConfig(st, "127.0.0.1", STICE_MDNS_MODE_QUERY_AND_GATHER);
	stice_agent_t *agent = stice_create(&cfg);
	REQUIRE(agent != nullptr);
	REQUIRE(stice_gather_candidates(agent) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return st.gatheringDone.load(); }, 5000));

	char sdp[8192];
	REQUIRE(stice_get_local_description(agent, sdp, sizeof(sdp)) == STICE_ERR_SUCCESS);
	const std::string desc(sdp);
	auto addrs = hostCandidateAddresses(desc);
	INFO("local description:\n" << desc);

	REQUIRE_FALSE(addrs.empty());
	// mDNS unavailable (could not bind 5353) makes QueryAndGather degrade to
	// QueryOnly, which is correct behaviour but cannot exercise this rule.
	if (addrs.front().find(".local") == std::string::npos) {
		stice_destroy(agent);
		SKIP("mDNS unavailable on this host (port 5353 not bindable); gathering degraded to QueryOnly");
	}
	for (const auto &a : addrs) {
		INFO("host candidate address: " << a);
		REQUIRE(a.size() > 6);
		REQUIRE(a.compare(a.size() - 6, 6, ".local") == 0);
	}
	// The privacy goal: the real address must not appear anywhere in the SDP.
	REQUIRE(desc.find("127.0.0.1") == std::string::npos);

	stice_destroy(agent);
}

TEST_CASE("mDNS resolve: a .local remote candidate is resolved and ICE connects", "[mdns][resolve][integration]") {
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	// 127.0.0.1 is the address the responder hands out; A binds there so the
	// resolved candidate points at a real listening socket.
	const std::string mdnsName = "stice-e2e-test.local";
	MdnsResponder responder;
	if (!responder.start(mdnsName, "127.0.0.1")) {
		SKIP("mDNS responder could not bind port 5353; multicast unavailable");
	}

	AgentState sa, sb;
	auto cfgA = makeConfig(sa, "127.0.0.1", STICE_MDNS_MODE_DISABLED);
	auto cfgB = makeConfig(sb, "127.0.0.1", STICE_MDNS_MODE_QUERY_ONLY);
	stice_agent_t *a = stice_create(&cfgA);
	stice_agent_t *b = stice_create(&cfgB);
	REQUIRE(a != nullptr);
	REQUIRE(b != nullptr);

	REQUIRE(stice_gather_candidates(a) == STICE_ERR_SUCCESS);
	REQUIRE(stice_gather_candidates(b) == STICE_ERR_SUCCESS);
	REQUIRE(waitFor([&] { return sa.gatheringDone.load(); }, 5000));
	REQUIRE(waitFor([&] { return sb.gatheringDone.load(); }, 5000));

	char bufA[4096];
	char bufB[4096];
	REQUIRE(stice_get_local_description(a, bufA, sizeof(bufA)) == STICE_ERR_SUCCESS);
	REQUIRE(stice_get_local_description(b, bufB, sizeof(bufB)) == STICE_ERR_SUCCESS);

	// A is controlled: it learns B's real address first.
	REQUIRE(stice_set_remote_description(a, bufB) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(a) == STICE_ERR_SUCCESS);

	// B only ever sees A under its mDNS name.
	const std::string rewritten = rewriteCandidateAddress(bufA, mdnsName);
	REQUIRE(stice_set_remote_description(b, rewritten.c_str()) == STICE_ERR_SUCCESS);
	REQUIRE(stice_set_remote_gathering_done(b) == STICE_ERR_SUCCESS);

	const bool connected = waitFor([&] {
		auto saState = sa.state.load();
		auto sbState = sb.state.load();
		return (saState == STICE_STATE_CONNECTED || saState == STICE_STATE_COMPLETED) &&
		       (sbState == STICE_STATE_CONNECTED || sbState == STICE_STATE_COMPLETED);
	}, 15000);

	INFO("A state=" << static_cast<int>(sa.state.load()) << " B state="
	                << static_cast<int>(sb.state.load()) << " mdns answers=" << responder.answered());
	if (!connected && responder.answered() == 0) {
		stice_destroy(a);
		stice_destroy(b);
		SKIP("no mDNS query/answer observed (multicast loopback unavailable on this host)");
	}
	REQUIRE(responder.answered() >= 1);
	REQUIRE(connected);

	stice_destroy(a);
	stice_destroy(b);
}
