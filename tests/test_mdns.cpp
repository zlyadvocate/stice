// test_mdns.cpp
//
// Unit tests for net::mdnsSourceIsPlausible() - the mDNS answer source filter.
//
// Why this exists: mDNS answers are accepted purely by matching the answer NAME
// to a pending query, so the source check is the only thing standing between a
// forged A/AAAA answer and a bogus ICE candidate being fed to the agent. The
// function is pure, so every boundary rule can be pinned down here rather than
// inferred from the receive loop.
#include "stice/net/mdns.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstring>

namespace {

sockaddr_storage makeV4(const char *ip, std::uint16_t port = 5353) {
	sockaddr_storage ss{};
	auto *a = reinterpret_cast<sockaddr_in *>(&ss);
	a->sin_family = AF_INET;
	a->sin_port = htons(port);
	REQUIRE(inet_pton(AF_INET, ip, &a->sin_addr) == 1);
	return ss;
}

sockaddr_storage makeV6(const char *ip, std::uint16_t port = 5353) {
	sockaddr_storage ss{};
	auto *a = reinterpret_cast<sockaddr_in6 *>(&ss);
	a->sin6_family = AF_INET6;
	a->sin6_port = htons(port);
	REQUIRE(inet_pton(AF_INET6, ip, &a->sin6_addr) == 1);
	return ss;
}

} // namespace

TEST_CASE("mdnsSourceIsPlausible: IPv4 impossible sources are rejected", "[mdns][security]") {
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV4("0.0.0.0")));            // unspecified
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV4("224.0.0.0")));          // 224/4 low
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV4("224.0.0.251")));        // the mDNS group itself
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV4("239.255.255.255")));    // 224/4 high
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV4("255.255.255.255")));    // limited broadcast
}

TEST_CASE("mdnsSourceIsPlausible: IPv4 unicast sources are accepted", "[mdns][security]") {
	CHECK(stice::net::mdnsSourceIsPlausible(makeV4("192.168.3.244")));
	CHECK(stice::net::mdnsSourceIsPlausible(makeV4("10.0.0.1")));
	CHECK(stice::net::mdnsSourceIsPlausible(makeV4("172.16.0.1")));
	CHECK(stice::net::mdnsSourceIsPlausible(makeV4("169.254.1.1"))); // link-local
	CHECK(stice::net::mdnsSourceIsPlausible(makeV4("127.0.0.1")));   // loopback
	CHECK(stice::net::mdnsSourceIsPlausible(makeV4("8.8.8.8")));     // global unicast
}

TEST_CASE("mdnsSourceIsPlausible: IPv4 range boundaries", "[mdns][security]") {
	// 224.0.0.0/3 = the multicast block (224/4) + the reserved class E block
	// (240/4). Neither can be a unicast host address, so the whole range is
	// rejected.
	CHECK(stice::net::mdnsSourceIsPlausible(makeV4("223.255.255.255"))); // just below
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV4("224.0.0.0")));
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV4("239.255.255.255")));
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV4("240.0.0.0")));
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV4("240.0.0.1")));
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV4("255.255.255.254")));
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV4("255.255.255.255")));
	// 0.0.0.1 is not the unspecified address.
	CHECK(stice::net::mdnsSourceIsPlausible(makeV4("0.0.0.1")));
}

TEST_CASE("mdnsSourceIsPlausible: IPv6 impossible sources are rejected", "[mdns][security]") {
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV6("::")));        // unspecified
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV6("ff00::")));    // ff00::/8 low
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV6("ff01::1")));   // all-nodes link-local
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV6("ff02::fb")));  // the IPv6 mDNS group
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV6("ffff::1")));   // ff00::/8 high
}

TEST_CASE("mdnsSourceIsPlausible: IPv6 unicast sources are accepted", "[mdns][security]") {
	CHECK(stice::net::mdnsSourceIsPlausible(makeV6("::1")));          // loopback
	CHECK(stice::net::mdnsSourceIsPlausible(makeV6("fe80::1")));      // link-local
	CHECK(stice::net::mdnsSourceIsPlausible(makeV6("2001:db8::1")));  // documentation range
	// Boundary: fe00:: is below ff00::/8 (10xxxxxx first byte), so not multicast.
	CHECK(stice::net::mdnsSourceIsPlausible(makeV6("fe00::1")));
	// Boundary: fd00:: (unique-local) has first byte 0xFD, not 0xFF.
	CHECK(stice::net::mdnsSourceIsPlausible(makeV6("fd00::1")));
}

TEST_CASE("mdnsSourceIsPlausible: IPv4-mapped IPv6 follows the IPv4 rules", "[mdns][security]") {
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV6("::ffff:0.0.0.0")));
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV6("::ffff:224.0.0.251")));
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV6("::ffff:239.255.255.255")));
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV6("::ffff:240.0.0.1")));
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV6("::ffff:255.255.255.255")));
	CHECK(stice::net::mdnsSourceIsPlausible(makeV6("::ffff:192.168.3.244")));
	CHECK(stice::net::mdnsSourceIsPlausible(makeV6("::ffff:8.8.8.8")));
	CHECK(stice::net::mdnsSourceIsPlausible(makeV6("::ffff:223.255.255.255")));
}

TEST_CASE("mdnsSourceIsPlausible: IPv4-compatible IPv6 also follows the IPv4 rules",
          "[mdns][security]") {
	// Deprecated ::a.b.c.d form. An embedded v4 address must not be a way around
	// the IPv4 branch.
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV6("::224.0.0.251")));
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV6("::240.0.0.1")));
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV6("::255.255.255.255")));
	CHECK(stice::net::mdnsSourceIsPlausible(makeV6("::192.168.3.244")));
	// ::1 embeds 0.0.0.1, which the v4 rules accept.
	CHECK(stice::net::mdnsSourceIsPlausible(makeV6("::1")));
}

TEST_CASE("mdnsSourceIsPlausible: unknown address families are rejected", "[mdns][security]") {
	// A family the filter does not know can never be a valid mDNS source; before
	// this was explicit, anything that was not AF_INET fell through and was
	// accepted unconditionally.
	sockaddr_storage ss{};
	std::memset(&ss, 0, sizeof(ss));

	ss.ss_family = AF_UNSPEC;
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(ss));

	ss.ss_family = 0x1234; // arbitrary non-IP family value
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(ss));
}

TEST_CASE("mdnsSourceIsPlausible: the port does not affect the decision", "[mdns][security]") {
	// Only the source ADDRESS matters: a query from an ephemeral port is still a
	// legitimate unicast sender (the responder then answers unicast), and a
	// multicast source stays invalid from any port.
	CHECK(stice::net::mdnsSourceIsPlausible(makeV4("192.168.3.244", 5353)));
	CHECK(stice::net::mdnsSourceIsPlausible(makeV4("192.168.3.244", 49152)));
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV4("224.0.0.251", 49152)));
	CHECK(stice::net::mdnsSourceIsPlausible(makeV6("fe80::1", 5353)));
	CHECK(stice::net::mdnsSourceIsPlausible(makeV6("fe80::1", 49152)));
	CHECK_FALSE(stice::net::mdnsSourceIsPlausible(makeV6("ff02::fb", 49152)));
}
