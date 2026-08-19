/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
#include "stice/stun/attributes.hpp"

#include "stice/log.hpp"

#include <cstring>

namespace stice::stun {

namespace {
// Encode a sockaddr as XOR-MAPPED-ADDRESS-style value (no TLV header).
// Returns the value bytes (4 or 20 bytes for IPv4/IPv6 respectively).
bytes encodeXorAddr(const net::AddrRecord &rec,
                    const std::array<unsigned char, TransactionIDSize> &tid) {
	auto mask = xorMask(tid);
	auto *sa = reinterpret_cast<const sockaddr *>(&rec.addr);
	bytes out;
	if (sa->sa_family == AF_INET) {
		out.resize(8); // 1 reserved + 1 family + 2 port + 4 addr
		out[0] = 0;
		out[1] = FamilyIPv4;
		auto *in = reinterpret_cast<const sockaddr_in *>(sa);
		// Port XOR top 16 bits of magic cookie. Both must be in host
		// byte order before XOR'ing. sin_port is network order, so
		// convert it first. The result is written big-endian (wire order).
		std::uint16_t port = ntohs(in->sin_port);
		std::uint16_t xport = port ^ (static_cast<std::uint16_t>(mask[0] << 8) | mask[1]);
		out[2] = static_cast<unsigned char>(xport >> 8);
		out[3] = static_cast<unsigned char>(xport & 0xFF);
		// Address XOR magic cookie (IP is already in network order, mask
		// bytes are in wire order, so byte-wise XOR is correct).
		const unsigned char *ip = reinterpret_cast<const unsigned char *>(&in->sin_addr);
		for (int i = 0; i < 4; ++i) out[4 + i] = ip[i] ^ mask[i];
	} else if (sa->sa_family == AF_INET6) {
		out.resize(20); // 1 + 1 + 2 + 16
		out[0] = 0;
		out[1] = FamilyIPv6;
		auto *in6 = reinterpret_cast<const sockaddr_in6 *>(sa);
		std::uint16_t port = ntohs(in6->sin6_port);
		std::uint16_t xport = port ^ (static_cast<std::uint16_t>(mask[0] << 8) | mask[1]);
		out[2] = static_cast<unsigned char>(xport >> 8);
		out[3] = static_cast<unsigned char>(xport & 0xFF);
		const unsigned char *ip = reinterpret_cast<const unsigned char *>(&in6->sin6_addr);
		for (int i = 0; i < 16; ++i) out[4 + i] = ip[i] ^ mask[i];
	}
	return out;
}

bool decodeXorAddr(const bytes &value, net::AddrRecord &out,
                   const std::array<unsigned char, TransactionIDSize> &tid) {
	if (value.size() < 4) return false;
	std::uint8_t family = value[1];
	auto mask = xorMask(tid);
	// value[2:4] is the big-endian (network-order) XOR'd port. mask[0:2]
	// are the big-endian bytes of 0x2112. Read both into host-order uint16,
	// XOR, then store the result in sin_port using htons() (network order).
	std::uint16_t xport = (static_cast<std::uint16_t>(value[2]) << 8) | value[3];
	std::uint16_t port = xport ^ (static_cast<std::uint16_t>(mask[0] << 8) | mask[1]);

	if (family == FamilyIPv4) {
		if (value.size() < 8) return false;
		sockaddr_in in{};
		in.sin_family = AF_INET;
		in.sin_port = htons(port); // host → network order
		unsigned char *ip = reinterpret_cast<unsigned char *>(&in.sin_addr);
		for (int i = 0; i < 4; ++i) ip[i] = value[4 + i] ^ mask[i];
		std::memcpy(&out.addr, &in, sizeof(in));
		out.len = sizeof(in);
		out.socktype = SOCK_DGRAM;
		return true;
	}
	if (family == FamilyIPv6) {
		if (value.size() < 20) return false;
		sockaddr_in6 in6{};
		in6.sin6_family = AF_INET6;
		in6.sin6_port = htons(port); // host → network order
		unsigned char *ip = reinterpret_cast<unsigned char *>(&in6.sin6_addr);
		for (int i = 0; i < 16; ++i) ip[i] = value[4 + i] ^ mask[i];
		std::memcpy(&out.addr, &in6, sizeof(in6));
		out.len = sizeof(in6);
		out.socktype = SOCK_DGRAM;
		return true;
	}
	return false;
}
} // namespace

bool writeXorAddress(Message &msg, AttrType type, const net::AddrRecord &addr,
                     const std::array<unsigned char, TransactionIDSize> &tid) {
	bytes v = encodeXorAddr(addr, tid);
	if (v.empty()) return false;
	msg.addAttribute(type, v);
	return true;
}

bool readXorAddress(const Message &msg, AttrType type, net::AddrRecord &out,
                    const std::array<unsigned char, TransactionIDSize> &tid) {
	const auto *a = msg.find(type);
	if (!a) return false;
	return decodeXorAddr(a->value, out, tid);
}

bool writeMappedAddress(Message &msg, const net::AddrRecord &addr) {
	auto *sa = reinterpret_cast<const sockaddr *>(&addr.addr);
	bytes out;
	if (sa->sa_family == AF_INET) {
		out.resize(8);
		out[0] = 0; out[1] = FamilyIPv4;
		auto *in = reinterpret_cast<const sockaddr_in *>(sa);
		// sin_port is network order; convert to host order then write
		// big-endian (wire order).
		std::uint16_t port = ntohs(in->sin_port);
		out[2] = static_cast<unsigned char>(port >> 8);
		out[3] = static_cast<unsigned char>(port & 0xFF);
		std::memcpy(out.data() + 4, &in->sin_addr, 4);
	} else if (sa->sa_family == AF_INET6) {
		out.resize(20);
		out[0] = 0; out[1] = FamilyIPv6;
		auto *in6 = reinterpret_cast<const sockaddr_in6 *>(sa);
		std::uint16_t port = ntohs(in6->sin6_port);
		out[2] = static_cast<unsigned char>(port >> 8);
		out[3] = static_cast<unsigned char>(port & 0xFF);
		std::memcpy(out.data() + 4, &in6->sin6_addr, 16);
	} else return false;
	msg.addAttribute(AttrType::MappedAddress, out);
	return true;
}

bool readMappedAddress(const Message &msg, net::AddrRecord &out) {
	const auto *a = msg.find(AttrType::MappedAddress);
	if (!a || a->value.size() < 4) return false;
	std::uint8_t family = a->value[1];
	// Wire bytes are big-endian (network order). Read into host-order
	// uint16, then store in sin_port using htons() (network order).
	std::uint16_t port = (static_cast<std::uint16_t>(a->value[2]) << 8) | a->value[3];
	if (family == FamilyIPv4) {
		if (a->value.size() < 8) return false;
		sockaddr_in in{};
		in.sin_family = AF_INET;
		in.sin_port = htons(port); // host → network order
		std::memcpy(&in.sin_addr, a->value.data() + 4, 4);
		std::memcpy(&out.addr, &in, sizeof(in));
		out.len = sizeof(in);
		out.socktype = SOCK_DGRAM;
		return true;
	}
	if (family == FamilyIPv6) {
		if (a->value.size() < 20) return false;
		sockaddr_in6 in6{};
		in6.sin6_family = AF_INET6;
		in6.sin6_port = htons(port); // host → network order
		std::memcpy(&in6.sin6_addr, a->value.data() + 4, 16);
		std::memcpy(&out.addr, &in6, sizeof(in6));
		out.len = sizeof(in6);
		out.socktype = SOCK_DGRAM;
		return true;
	}
	return false;
}

void addPriority(Message &msg, std::uint32_t priority) {
	unsigned char buf[4];
	writeU32Be(buf, priority);
	msg.addAttribute(AttrType::Priority, buf, 4);
}

bool readPriority(const Message &msg, std::uint32_t &out) {
	const auto *a = msg.find(AttrType::Priority);
	if (!a || a->value.size() != 4) return false;
	out = readU32Be(a->value.data());
	return true;
}

void addIceControlling(Message &msg, std::uint64_t tiebreaker) {
	unsigned char buf[8];
	for (int i = 0; i < 8; ++i) buf[i] = static_cast<unsigned char>(tiebreaker >> (56 - 8 * i));
	msg.addAttribute(AttrType::IceControlling, buf, 8);
}

void addIceControlled(Message &msg, std::uint64_t tiebreaker) {
	unsigned char buf[8];
	for (int i = 0; i < 8; ++i) buf[i] = static_cast<unsigned char>(tiebreaker >> (56 - 8 * i));
	msg.addAttribute(AttrType::IceControlled, buf, 8);
}

bool readIceControlling(const Message &msg, std::uint64_t &out) {
	const auto *a = msg.find(AttrType::IceControlling);
	if (!a || a->value.size() != 8) return false;
	out = 0;
	for (int i = 0; i < 8; ++i)
		out = (out << 8) | a->value[i];
	return true;
}

bool readIceControlled(const Message &msg, std::uint64_t &out) {
	const auto *a = msg.find(AttrType::IceControlled);
	if (!a || a->value.size() != 8) return false;
	out = 0;
	for (int i = 0; i < 8; ++i)
		out = (out << 8) | a->value[i];
	return true;
}

void addErrorCode(Message &msg, int code, const std::string &reason) {
	int cls = code / 100;
	int num = code % 100;
	std::string r = reason.empty() ? errorReason(code) : reason;
	bytes v;
	v.resize(4 + r.size());
	v[0] = 0; v[1] = 0;
	v[2] = static_cast<unsigned char>(cls & 0x07);
	v[3] = static_cast<unsigned char>(num);
	std::memcpy(v.data() + 4, r.data(), r.size());
	msg.addAttribute(AttrType::ErrorCode, v);
}

bool readErrorCode(const Message &msg, int &code, std::string &reason) {
	const auto *a = msg.find(AttrType::ErrorCode);
	if (!a || a->value.size() < 4) return false;
	int cls = a->value[2] & 0x07;
	int num = a->value[3];
	code = cls * 100 + num;
	reason.assign(reinterpret_cast<const char *>(a->value.data() + 4), a->value.size() - 4);
	return true;
}

void addChannelNumber(Message &msg, std::uint16_t channel) {
	unsigned char buf[4] = {0, 0, 0, 0};
	buf[0] = static_cast<unsigned char>(channel >> 8);
	buf[1] = static_cast<unsigned char>(channel & 0xFF);
	msg.addAttribute(AttrType::ChannelNumber, buf, 4);
}

bool readChannelNumber(const Message &msg, std::uint16_t &out) {
	const auto *a = msg.find(AttrType::ChannelNumber);
	if (!a || a->value.size() != 4) return false;
	out = (static_cast<std::uint16_t>(a->value[0]) << 8) | a->value[1];
	return true;
}

void addLifetime(Message &msg, std::uint32_t seconds) {
	unsigned char buf[4];
	writeU32Be(buf, seconds);
	msg.addAttribute(AttrType::Lifetime, buf, 4);
}

bool readLifetime(const Message &msg, std::uint32_t &out) {
	const auto *a = msg.find(AttrType::Lifetime);
	if (!a || a->value.size() != 4) return false;
	out = readU32Be(a->value.data());
	return true;
}

void addRequestedTransport(Message &msg, std::uint8_t protocol) {
	unsigned char buf[4] = {0, 0, 0, 0};
	buf[0] = protocol;
	msg.addAttribute(AttrType::RequestedTransport, buf, 4);
}

void addRequestedAddressFamily(Message &msg, std::uint8_t family) {
	unsigned char buf[1] = {family};
	msg.addAttribute(AttrType::RequestedAddressFamily, buf, 1);
}

void addReservationToken(Message &msg, const unsigned char token[8]) {
	msg.addAttribute(AttrType::ReservationToken, token, 8);
}

void addTcpType(Message &msg, std::uint32_t tcpType) {
	unsigned char buf[4];
	writeU32Be(buf, tcpType);
	msg.addAttribute(AttrType::TcpType, buf, 4);
}

bool readTcpType(const Message &msg, std::uint32_t &out) {
	const auto *a = msg.find(AttrType::TcpType);
	if (!a || a->value.size() != 4) return false;
	out = readU32Be(a->value.data());
	return true;
}

} // namespace stice::stun
