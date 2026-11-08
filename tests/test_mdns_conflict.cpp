// SPDX-License-Identifier: MPL-2.0
// Regression tests for mDNS conflict probing
// (draft-ietf-rtcweb-mdns-ice-candidates §3.1).
//
// The advertised name is a random UUIDv4 label, so a collision is
// astronomically unlikely - but the draft still asks for a probe before the
// name is used. init() now multicasts one query for the auto-generated label
// and regenerates it if any host answers. These tests pin the label format and
// drive the probe directly: a real collision cannot be provoked through the
// random path, so the probe is exercised with a name the same client has
// already registered (the multicast loopback makes it answer itself, which is
// exactly the "someone owns this name" signal the probe looks for).

#include <catch2/catch_test_macros.hpp>

#include "stice/net/mdns.hpp"

#include <string>

using namespace stice;

TEST_CASE("mDNS hostname is a random single-label UUIDv4", "[mdns][conflict]") {
	const std::string a = net::MDnsClient::generateHostname();
	const std::string b = net::MDnsClient::generateHostname();

	REQUIRE(net::MDnsClient::isMDnsName(a));
	REQUIRE(net::MDnsClient::isMDnsName(b));
	REQUIRE(a != b);
	// 8-4-4-4-12 hex + ".local".
	REQUIRE(a.size() == 36 + 6);
	REQUIRE(a.substr(36) == ".local");
	REQUIRE(a[8] == '-');
	REQUIRE(a[13] == '-');
	REQUIRE(a[18] == '-');
	REQUIRE(a[23] == '-');
	// RFC 4122 version 4 + variant 10xx.
	REQUIRE(a[14] == '4');
	REQUIRE((a[19] == '8' || a[19] == '9' || a[19] == 'a' || a[19] == 'b'));
}

TEST_CASE("mDNS conflict probing detects an already-advertised name", "[mdns][conflict]") {
	net::MDnsClient client;
	if (!client.init(net::MulticastDNSMode::QueryAndGather, "", "127.0.0.1") ||
	    client.mode() != net::MulticastDNSMode::QueryAndGather) {
		SKIP("mDNS multicast unavailable on this host (degraded to QueryOnly)");
	}

	const std::string taken = "stice-probe-self.local";
	REQUIRE(client.addRecord(taken, "127.0.0.1"));

	// The client answers its own query through multicast loopback, which is the
	// same "name is in use" signal a colliding peer would produce.
	REQUIRE(client.probeNameConflict(taken));
	// A fresh random label has no owner and must not report a conflict.
	REQUIRE_FALSE(client.probeNameConflict(net::MDnsClient::generateHostname()));
}

TEST_CASE("mDNS conflict probing is a no-op when mDNS is disabled", "[mdns][conflict]") {
	net::MDnsClient client;
	REQUIRE(client.init(net::MulticastDNSMode::Disabled, "", "127.0.0.1"));
	// Nothing is advertised and no socket exists, so there can be no conflict.
	REQUIRE_FALSE(client.probeNameConflict("stice-probe-self.local"));
}
