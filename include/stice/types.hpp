// SPDX-License-Identifier: MPL-2.0
// Common types and platform abstractions for stice.

#ifndef STICE_TYPES_HPP
#define STICE_TYPES_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace stice {

using bytes = std::vector<unsigned char>;

// 4-byte alignment for STUN attribute values (RFC 5389 §15.1).
inline std::size_t paddedSize(std::size_t n) {
	return (n + 3) & ~static_cast<std::size_t>(3);
}

// Big-endian read/write helpers (STUN is network byte order).
inline uint16_t readU16Be(const unsigned char *p) {
	return static_cast<uint16_t>((uint16_t{p[0]} << 8) | p[1]);
}
inline uint32_t readU32Be(const unsigned char *p) {
	return (uint32_t{p[0]} << 24) | (uint32_t{p[1]} << 16) | (uint32_t{p[2]} << 8) | p[3];
}
inline void writeU16Be(unsigned char *p, uint16_t v) {
	p[0] = static_cast<unsigned char>(v >> 8);
	p[1] = static_cast<unsigned char>(v & 0xFF);
}
inline void writeU32Be(unsigned char *p, uint32_t v) {
	p[0] = static_cast<unsigned char>(v >> 24);
	p[1] = static_cast<unsigned char>(v >> 16);
	p[2] = static_cast<unsigned char>(v >> 8);
	p[3] = static_cast<unsigned char>(v & 0xFF);
}

} // namespace stice

#endif
