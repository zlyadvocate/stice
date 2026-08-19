/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "stice/stun/message.hpp"
#include "stice/stun/attributes.hpp"

#include "stice/log.hpp"

#include <algorithm>
#include <cstring>

namespace stice::stun {

const char *errorReason(int code) {
	switch (code) {
	case 300: return "Try Alternate";
	case 400: return "Bad Request";
	case 401: return "Unauthenticated";
	case 403: return "Forbidden";
	case 420: return "Unknown Attribute";
	case 437: return "Allocation Mismatch";
	case 438: return "Stale Nonce";
	case 440: return "Address Family not Supported";
	case 441: return "Wrong credentials";
	case 442: return "Unsupported Transport Protocol";
	case 443: return "Peer Address Family Mismatch";
	case 486: return "Allocation Quota Reached";
	case 500: return "Server Error";
	case 508: return "Insufficient Capacity";
	default:  return "Unknown Error";
	}
}

void Message::newTransactionID() {
	if (!crypto::randomBytes(transactionID.data(), TransactionIDSize)) {
		// Fallback: shouldn't happen in practice.
		for (auto &b : transactionID) b = 0;
	}
}

void Message::addAttribute(AttrType type, const unsigned char *value, std::size_t len) {
	Attribute a;
	a.type = type;
	if (len) {
		a.value.resize(len);
		std::memcpy(a.value.data(), value, len);
	}
	attributes.push_back(std::move(a));
}

const Attribute *Message::find(AttrType type) const {
	for (const auto &a : attributes)
		if (a.type == type) return &a;
	return nullptr;
}

Attribute *Message::find(AttrType type) {
	for (auto &a : attributes)
		if (a.type == type) return &a;
	return nullptr;
}

bool Message::encode(const char *password, const Credentials *creds, const char *software) {
	raw.clear();
	raw.reserve(MessageHeaderSize + attributes.size() * 8);

	// Header (length will be patched at the end).
	raw.resize(MessageHeaderSize);
	writeU16Be(raw.data(), encodeType(method, cls));
	writeU16Be(raw.data() + 2, 0); // placeholder length
	writeU32Be(raw.data() + 4, MagicCookie);
	std::memcpy(raw.data() + 8, transactionID.data(), TransactionIDSize);

	auto appendAttr = [&](AttrType type, const unsigned char *value, std::size_t len) {
		std::size_t offset = raw.size();
		raw.resize(offset + AttributeHeaderSize + paddedSize(len));
		writeU16Be(raw.data() + offset, static_cast<std::uint16_t>(type));
		writeU16Be(raw.data() + offset + 2, static_cast<std::uint16_t>(len));
		if (len) std::memcpy(raw.data() + offset + 4, value, len);
		// Padding bytes are already zero from resize.
		for (std::size_t i = len; i < paddedSize(len); ++i)
			raw[offset + 4 + i] = 0;
	};

	// 1. Optional USERNAME / REALM / NONCE for long-term credentialed requests.
	//    Per RFC 5389 §15.3, requests MUST carry USERNAME when MESSAGE-INTEGRITY
	//    is present and the mechanism is long-term.
	if (creds && password && cls != Class::Indication) {
		if (!creds->username.empty())
			appendAttr(AttrType::Username,
			           reinterpret_cast<const unsigned char *>(creds->username.data()),
			           creds->username.size());
		if (!creds->realm.empty())
			appendAttr(AttrType::Realm,
			           reinterpret_cast<const unsigned char *>(creds->realm.data()),
			           creds->realm.size());
		if (!creds->nonce.empty())
			appendAttr(AttrType::Nonce,
			           reinterpret_cast<const unsigned char *>(creds->nonce.data()),
			           creds->nonce.size());
	}

	// 2. User-supplied attributes (caller already added PRIORITY, USE-CANDIDATE,
	//    ICE-CONTROLLING/CONTROLLED, XOR-MAPPED-ADDRESS, ERROR-CODE,
	//    CHANNEL-NUMBER, LIFETIME, XOR-PEER-ADDRESS, DATA, etc.).
	for (const auto &a : attributes)
		appendAttr(a.type, a.value.data(), a.value.size());

	// 3. SOFTWARE (per libjuice, added before MESSAGE-INTEGRITY).
	if (software && *software)
		appendAttr(AttrType::Software, reinterpret_cast<const unsigned char *>(software),
		           std::strlen(software));

	// 4. MESSAGE-INTEGRITY (HMAC-SHA1) for non-indication messages when authed.
	//    Per RFC 5389 §15.4 and pion-stun, the HMAC is computed over the header
	//    + body (NOT including the MI TLV itself), with the header length field
	//    patched to include the full MI TLV (header + value = 24 bytes).
	if (password && cls != Class::Indication) {
		const unsigned char *key = nullptr;
		std::size_t keyLen = 0;
		bytes keyBuf;
		if (creds && !creds->key.empty()) {
			key = creds->key.data();
			keyLen = creds->key.size();
		} else {
			keyBuf.assign(reinterpret_cast<const unsigned char *>(password),
			              reinterpret_cast<const unsigned char *>(password) + std::strlen(password));
			key = keyBuf.data();
			keyLen = keyBuf.size();
		}
		// Patch header length to cover body + full MI TLV (header + value = 24).
		std::size_t bodyLen = raw.size() - MessageHeaderSize;
		writeU16Be(raw.data() + 2,
		           static_cast<std::uint16_t>(bodyLen + AttributeHeaderSize + HmacSha1Size));
		// Compute HMAC over header (with patched length) + body, excluding MI TLV.
		auto hmac = crypto::hmacSha1(key, keyLen, raw.data(), raw.size());
		// Append the MI TLV header + 20-byte HMAC value.
		std::size_t miTlvOff = raw.size();
		raw.resize(raw.size() + AttributeHeaderSize + HmacSha1Size);
		writeU16Be(raw.data() + miTlvOff, static_cast<std::uint16_t>(AttrType::MessageIntegrity));
		writeU16Be(raw.data() + miTlvOff + 2, HmacSha1Size);
		std::memcpy(raw.data() + miTlvOff + AttributeHeaderSize, hmac.data(), HmacSha1Size);
	}

	// 5. FINGERPRINT (always last). Per RFC 5389 §15.5 and pion-stun, the CRC
	//    is computed over the header + body (NOT including the FP TLV itself),
	//    with the header length field patched to include the full FP TLV
	//    (header + value = 8 bytes).
	{
		// Patch header length to cover body + full FP TLV (header + value = 8).
		std::size_t bodyLen = raw.size() - MessageHeaderSize;
		writeU16Be(raw.data() + 2,
		           static_cast<std::uint16_t>(bodyLen + AttributeHeaderSize + 4));
		// Compute CRC over header (with patched length) + body, excluding FP TLV.
		std::uint32_t crc = crypto::crc32(raw.data(), raw.size());
		std::uint32_t fp = crc ^ FingerprintXor;
		// Append the FP TLV header + 4-byte CRC value.
		std::size_t fpTlvOff = raw.size();
		raw.resize(raw.size() + AttributeHeaderSize + 4);
		writeU16Be(raw.data() + fpTlvOff, static_cast<std::uint16_t>(AttrType::Fingerprint));
		writeU16Be(raw.data() + fpTlvOff + 2, 4);
		unsigned char fpBuf[4];
		writeU32Be(fpBuf, fp);
		std::memcpy(raw.data() + fpTlvOff + AttributeHeaderSize, fpBuf, 4);
	}

	// Final header length = body size (everything after the 20-byte header).
	writeU16Be(raw.data() + 2, static_cast<std::uint16_t>(raw.size() - MessageHeaderSize));
	return true;
}

bool Message::decode(const unsigned char *data, std::size_t size) {
	if (size < MessageHeaderSize) return false;
	if (!isMessage(data, size)) return false;

	std::uint16_t type = readU16Be(data);
	std::uint16_t length = readU16Be(data + 2);
	std::uint32_t cookie = readU32Be(data + 4);
	(void)cookie;
	decodeType(type, method, cls);
	std::memcpy(transactionID.data(), data + 8, TransactionIDSize);

	raw.assign(data, data + size);
	attributes.clear();

	std::size_t offset = MessageHeaderSize;
	std::size_t end = MessageHeaderSize + length;
	if (end > size) return false;

	while (offset + AttributeHeaderSize <= end) {
		AttrType at = static_cast<AttrType>(readU16Be(data + offset));
		std::uint16_t vlen = readU16Be(data + offset + 2);
		offset += AttributeHeaderSize;
		if (offset + vlen > end) return false;
		Attribute a;
		a.type = at;
		a.value.assign(data + offset, data + offset + vlen);
		attributes.push_back(std::move(a));
		// Skip padding.
		offset += paddedSize(vlen);
	}
	return true;
}

bool Message::isMessage(const unsigned char *data, std::size_t size) {
	if (!data || size < MessageHeaderSize) return false;
	// Top 2 bits of first byte MUST be 0.
	if ((data[0] & 0xC0) != 0) return false;
	std::uint32_t cookie = readU32Be(data + 4);
	if (cookie != MagicCookie) return false;
	std::uint16_t length = readU16Be(data + 2);
	if ((length & 0x03) != 0) return false; // multiple of 4
	if (size != MessageHeaderSize + length) return false;
	return true;
}

std::size_t Message::findIntegrityOffset(std::size_t &attrStart) const {
	std::size_t offset = MessageHeaderSize;
	std::uint16_t length = readU16Be(raw.data() + 2);
	std::size_t end = MessageHeaderSize + length;
	while (offset + AttributeHeaderSize <= end) {
		AttrType at = static_cast<AttrType>(readU16Be(raw.data() + offset));
		std::uint16_t vlen = readU16Be(raw.data() + offset + 2);
		attrStart = offset;
		if (at == AttrType::MessageIntegrity) {
			return offset + AttributeHeaderSize;
		}
		offset += AttributeHeaderSize + paddedSize(vlen);
	}
	return 0;
}

bool Message::checkIntegrity(const unsigned char *key, std::size_t keyLen, bool allowMissing) const {
	std::size_t attrStart = 0;
	std::size_t valueOff = findIntegrityOffset(attrStart);
	if (valueOff == 0) return allowMissing;
	if (valueOff + HmacSha1Size > raw.size()) return false;

	// Compute HMAC over header + body before MI (NOT including MI TLV).
	// Patch length to include full MI TLV (header + value = 24 bytes).
	std::size_t bodyBeforeMi = attrStart - MessageHeaderSize;
	bytes copy(raw.begin(), raw.begin() + attrStart); // header + body before MI
	unsigned char lenBuf[2];
	writeU16Be(lenBuf, static_cast<std::uint16_t>(bodyBeforeMi + AttributeHeaderSize + HmacSha1Size));
	std::memcpy(copy.data() + 2, lenBuf, 2);

	auto hmac = crypto::hmacSha1(key, keyLen, copy.data(), copy.size());
	return std::memcmp(hmac.data(), raw.data() + valueOff, HmacSha1Size) == 0;
}

bool Message::checkFingerprint(bool allowMissing) const {
	// Find FINGERPRINT attribute (must be last).
	std::size_t offset = MessageHeaderSize;
	std::uint16_t length = readU16Be(raw.data() + 2);
	std::size_t end = MessageHeaderSize + length;
	std::size_t fpAttrStart = 0;
	while (offset + AttributeHeaderSize <= end) {
		AttrType at = static_cast<AttrType>(readU16Be(raw.data() + offset));
		std::uint16_t vlen = readU16Be(raw.data() + offset + 2);
		if (at == AttrType::Fingerprint) {
			fpAttrStart = offset;
		}
		offset += AttributeHeaderSize + paddedSize(vlen);
	}
	if (fpAttrStart == 0) return allowMissing;
	std::size_t valueOff = fpAttrStart + AttributeHeaderSize;
	if (valueOff + 4 > raw.size()) return false;

	// Compute CRC over header + body before FP (NOT including FP TLV).
	// Patch length to include full FP TLV (header + value = 8 bytes).
	std::size_t bodyBeforeFp = fpAttrStart - MessageHeaderSize;
	bytes copy(raw.begin(), raw.begin() + fpAttrStart); // header + body before FP
	unsigned char lenBuf[2];
	writeU16Be(lenBuf, static_cast<std::uint16_t>(bodyBeforeFp + AttributeHeaderSize + 4));
	std::memcpy(copy.data() + 2, lenBuf, 2);

	std::uint32_t crc = crypto::crc32(copy.data(), copy.size());
	std::uint32_t expected = readU32Be(raw.data() + valueOff) ^ FingerprintXor;
	return crc == expected;
}

} // namespace stice::stun
