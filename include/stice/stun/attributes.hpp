// SPDX-License-Identifier: MPL-2.0
// stice STUN attribute helpers. Ported from libjuice's stun.c attribute
// encoders/decoders and pion-stun's xoraddr/integrity/fingerprint helpers.

#ifndef STICE_STUN_ATTRIBUTES_HPP
#define STICE_STUN_ATTRIBUTES_HPP

#include "stice/net/addr.hpp"
#include "stice/stun/message.hpp"

#include <cstdint>
#include <cstring>
#include <string>

namespace stice::stun {

// XOR-MAPPED-ADDRESS / XOR-PEER-ADDRESS / XOR-RELAYED-ADDRESS.
// Port is XOR'd with the top 16 bits of the magic cookie (0x2112).
// Address is XOR'd with the full 16-byte mask (magic cookie || tid) for IPv6,
// or with the 4-byte magic cookie for IPv4.
bool writeXorAddress(Message &msg, AttrType type, const net::AddrRecord &addr,
                     const std::array<unsigned char, TransactionIDSize> &tid);
bool readXorAddress(const Message &msg, AttrType type, net::AddrRecord &out,
                    const std::array<unsigned char, TransactionIDSize> &tid);

// Plain MAPPED-ADDRESS (no XOR). Used by older STUN servers.
bool writeMappedAddress(Message &msg, const net::AddrRecord &addr);
bool readMappedAddress(const Message &msg, net::AddrRecord &out);

// USERNAME / REALM / NONCE / SOFTWARE — UTF-8 text attributes.
inline void addString(Message &msg, AttrType type, const std::string &s) {
	msg.addAttribute(type, reinterpret_cast<const unsigned char *>(s.data()), s.size());
}
inline std::string getString(const Message &msg, AttrType type) {
	if (const auto *a = msg.find(type))
		return std::string(reinterpret_cast<const char *>(a->value.data()), a->value.size());
	return {};
}

// PRIORITY (uint32 BE, ICE candidate priority for peer-reflexive learning).
void addPriority(Message &msg, std::uint32_t priority);
bool readPriority(const Message &msg, std::uint32_t &out);

// USE-CANDIDATE (empty attribute; presence = nominated).
inline void addUseCandidate(Message &msg) {
	msg.addAttribute(AttrType::UseCandidate, nullptr, 0);
}
inline bool hasUseCandidate(const Message &msg) {
	return msg.find(AttrType::UseCandidate) != nullptr;
}

// NOMINATION (draft-thatcher-ice-renomation): uint32 BE nomination value.
inline void addNomination(Message &msg, std::uint32_t value) {
	unsigned char v[4];
	v[0] = static_cast<unsigned char>(value >> 24);
	v[1] = static_cast<unsigned char>(value >> 16);
	v[2] = static_cast<unsigned char>(value >> 8);
	v[3] = static_cast<unsigned char>(value & 0xFF);
	msg.addAttribute(AttrType::Nomination, v, 4);
}
inline bool readNomination(const Message &msg, std::uint32_t &out) {
	const auto *a = msg.find(AttrType::Nomination);
	if (!a || a->value.size() < 4) return false;
	out = (std::uint32_t(a->value[0]) << 24) | (std::uint32_t(a->value[1]) << 16) |
	      (std::uint32_t(a->value[2]) << 8) | std::uint32_t(a->value[3]);
	return true;
}

// ICE-CONTROLLING / ICE-CONTROLLED (uint64 BE tiebreaker).
void addIceControlling(Message &msg, std::uint64_t tiebreaker);
void addIceControlled(Message &msg, std::uint64_t tiebreaker);
bool readIceControlling(const Message &msg, std::uint64_t &out);
bool readIceControlled(const Message &msg, std::uint64_t &out);

// ERROR-CODE: class*100 + number, optional reason phrase.
void addErrorCode(Message &msg, int code, const std::string &reason = "");
bool readErrorCode(const Message &msg, int &code, std::string &reason);

// CHANNEL-NUMBER (uint16 channel + uint16 reserved).
void addChannelNumber(Message &msg, std::uint16_t channel);
bool readChannelNumber(const Message &msg, std::uint16_t &out);

// LIFETIME (uint32 BE seconds).
void addLifetime(Message &msg, std::uint32_t seconds);
bool readLifetime(const Message &msg, std::uint32_t &out);

// REQUESTED-TRANSPORT (u8 protocol=17 + 3 bytes reserved).
void addRequestedTransport(Message &msg, std::uint8_t protocol = 17);

// CONNECTION-ID (RFC 6062 §6.2): uint32 BE, identifies a TCP connection
// created by a CONNECT request or announced by a CONNECTION-ATTEMPT indication.
inline void addConnectionId(Message &msg, std::uint32_t connId) {
	unsigned char v[4];
	v[0] = static_cast<unsigned char>(connId >> 24);
	v[1] = static_cast<unsigned char>(connId >> 16);
	v[2] = static_cast<unsigned char>(connId >> 8);
	v[3] = static_cast<unsigned char>(connId & 0xFF);
	msg.addAttribute(AttrType::ConnectionId, v, 4);
}
inline bool readConnectionId(const Message &msg, std::uint32_t &out) {
	const auto *a = msg.find(AttrType::ConnectionId);
	if (!a || a->value.size() < 4) return false;
	out = (std::uint32_t(a->value[0]) << 24) | (std::uint32_t(a->value[1]) << 16) |
	      (std::uint32_t(a->value[2]) << 8) | std::uint32_t(a->value[3]);
	return true;
}

// DONT-FRAGMENT (empty attribute).
inline void addDontFragment(Message &msg) {
	msg.addAttribute(AttrType::DontFragment, nullptr, 0);
}

// DATA (raw application bytes).
inline void addData(Message &msg, const unsigned char *data, std::size_t len) {
	msg.addAttribute(AttrType::Data, data, len);
}
inline void addData(Message &msg, const bytes &data) {
	msg.addAttribute(AttrType::Data, data);
}

// REQUESTED-ADDRESS-FAMILY (u8: 0x01 IPv4, 0x02 IPv6).
void addRequestedAddressFamily(Message &msg, std::uint8_t family);

// RESERVATION-TOKEN (8 bytes).
void addReservationToken(Message &msg, const unsigned char token[8]);

// TCP-TYPE (RFC 6544 §8.1): 32-bit enum encoding the TCP candidate direction.
//   active  = 0x00000006
//   passive = 0x00000005
//   so      = 0x00000002
// Used in STUN connectivity checks over TCP so the peer can verify the
// candidate pair's TCP direction matches.
constexpr std::uint32_t TcpTypeActive = 0x00000006;
constexpr std::uint32_t TcpTypePassive = 0x00000005;
constexpr std::uint32_t TcpTypeSo = 0x00000002;
void addTcpType(Message &msg, std::uint32_t tcpType);
bool readTcpType(const Message &msg, std::uint32_t &out);

} // namespace stice::stun

#endif
