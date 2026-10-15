// test_addr_util.cpp
//
// Unit tests for the address helpers shared by the whole library:
//   addrToString() - the display/encoding form, which must bracket IPv6
//   addrEqual()    - peer identity, which must treat v4 and v4-mapped v6 alike
//   AddrRecord::hash() - must stay consistent with addrEqual for container keys
//
// These are small but load-bearing: addrEqual backs every peer/permission/
// channel match, and its hash sibling backs the unordered_maps keyed by address.
#include "stice/net/addr.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstring>

namespace {

// Winsock must be initialised before any name/address helper runs; without this
// getnameinfo() fails with WSANOTINITIALISED and the tests would see empty
// strings for reasons that have nothing to do with the code under test.
#ifdef _WIN32
struct WinsockInit {
	WinsockInit() {
		WSADATA wsa;
		WSAStartup(MAKEWORD(2, 2), &wsa);
	}
};
const WinsockInit g_winsockInit;
#endif

sockaddr_storage v4(const char *ip, std::uint16_t port) {
	sockaddr_storage ss{};
	auto *a = reinterpret_cast<sockaddr_in *>(&ss);
	a->sin_family = AF_INET;
	a->sin_port = htons(port);
	REQUIRE(inet_pton(AF_INET, ip, &a->sin_addr) == 1);
	return ss;
}

sockaddr_storage v6(const char *ip, std::uint16_t port) {
	sockaddr_storage ss{};
	auto *a = reinterpret_cast<sockaddr_in6 *>(&ss);
	a->sin6_family = AF_INET6;
	a->sin6_port = htons(port);
	REQUIRE(inet_pton(AF_INET6, ip, &a->sin6_addr) == 1);
	return ss;
}

const struct sockaddr *sa(const sockaddr_storage &ss) {
	return reinterpret_cast<const struct sockaddr *>(&ss);
}

} // namespace

TEST_CASE("addrToString brackets IPv6 literals", "[addr]") {
	CHECK(stice::net::addrToString(sa(v4("10.1.2.3", 5353))) == "10.1.2.3:5353");
	// IPv6 without brackets is ambiguous because the address itself has colons.
	CHECK(stice::net::addrToString(sa(v6("2001:db8::1", 5353))) == "[2001:db8::1]:5353");
	CHECK(stice::net::addrToString(sa(v6("::1", 3478))) == "[::1]:3478");
	CHECK(stice::net::addrToString(sa(v6("fe80::1", 5353))) == "[fe80::1]:5353");
	CHECK(stice::net::addrToString(nullptr).empty());
}

TEST_CASE("addrEqual compares IPv4 addresses and honours comparePorts", "[addr]") {
	const auto a = v4("192.168.1.10", 5000);
	const auto b = v4("192.168.1.10", 5000);
	const auto c = v4("192.168.1.10", 6000);
	const auto d = v4("192.168.1.11", 5000);

	CHECK(stice::net::addrEqual(sa(a), sa(b), true));
	CHECK_FALSE(stice::net::addrEqual(sa(a), sa(c), true));   // port differs
	CHECK(stice::net::addrEqual(sa(a), sa(c), false));        // port ignored
	CHECK_FALSE(stice::net::addrEqual(sa(a), sa(d), false));  // address differs

	CHECK(stice::net::addrEqual(nullptr, nullptr, true));
	CHECK_FALSE(stice::net::addrEqual(sa(a), nullptr, true));
	CHECK_FALSE(stice::net::addrEqual(nullptr, sa(a), true));
}

TEST_CASE("addrEqual compares IPv6 addresses", "[addr]") {
	const auto a = v6("2001:db8::1", 5000);
	const auto b = v6("2001:db8::1", 5000);
	const auto c = v6("2001:db8::2", 5000);

	CHECK(stice::net::addrEqual(sa(a), sa(b), true));
	CHECK_FALSE(stice::net::addrEqual(sa(a), sa(c), true));
	// ::1 and a v4-mapped v4 address are different families after normalization,
	// so they must not compare equal.
	CHECK_FALSE(stice::net::addrEqual(sa(v6("::1", 1)), sa(v4("0.0.0.1", 1)), true));
}

TEST_CASE("addrEqual treats v4-mapped IPv6 as the IPv4 address it embeds", "[addr]") {
	// A dual-stack socket reports the peer as ::ffff:a.b.c.d. It is the same peer
	// as the plain IPv4 address, so identity comparisons must agree.
	const auto plain = v4("192.168.3.244", 3478);
	const auto mapped = v6("::ffff:192.168.3.244", 3478);
	CHECK(stice::net::addrEqual(sa(plain), sa(mapped), true));
	CHECK(stice::net::addrEqual(sa(mapped), sa(plain), true));
	CHECK(stice::net::addrEqual(sa(plain), sa(mapped), false));

	// Port is still significant when asked for.
	const auto mappedOtherPort = v6("::ffff:192.168.3.244", 4000);
	CHECK_FALSE(stice::net::addrEqual(sa(plain), sa(mappedOtherPort), true));
	CHECK(stice::net::addrEqual(sa(plain), sa(mappedOtherPort), false));

	// A different embedded address is a different peer.
	CHECK_FALSE(stice::net::addrEqual(sa(plain), sa(v6("::ffff:192.168.3.245", 3478)), true));
}

TEST_CASE("AddrRecord::hash stays consistent with addrEqual normalization", "[addr]") {
	stice::net::AddrRecord plain;
	plain.addr = v4("192.168.3.244", 3478);
	plain.len = sizeof(sockaddr_in);
	plain.socktype = SOCK_DGRAM;

	stice::net::AddrRecord mapped;
	mapped.addr = v6("::ffff:192.168.3.244", 3478);
	mapped.len = sizeof(sockaddr_in6);
	mapped.socktype = SOCK_DGRAM;

	// Equal objects must hash equally, otherwise an unordered_map lookup can miss
	// the entry it would otherwise compare as equal.
	CHECK(plain.isEqual(mapped, true));
	CHECK(plain.hash(true) == mapped.hash(true));
	CHECK(plain.hash(false) == mapped.hash(false));

	// A genuinely different address must not collide.
	stice::net::AddrRecord other;
	other.addr = v4("192.168.3.245", 3478);
	other.len = sizeof(sockaddr_in);
	other.socktype = SOCK_DGRAM;
	CHECK_FALSE(plain.isEqual(other, true));
	CHECK(plain.hash(true) != other.hash(true));

	// Same address, different port: hash(false) must agree, hash(true) differ.
	stice::net::AddrRecord otherPort;
	otherPort.addr = v4("192.168.3.244", 4000);
	otherPort.len = sizeof(sockaddr_in);
	otherPort.socktype = SOCK_DGRAM;
	CHECK(plain.hash(false) == otherPort.hash(false));
	CHECK(plain.hash(true) != otherPort.hash(true));
}
