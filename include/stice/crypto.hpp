// SPDX-License-Identifier: MPL-2.0
// stice crypto primitives: MD5, SHA-1, SHA-256, HMAC-SHA1, HMAC-SHA256,
// CRC32 (IEEE 802.3) and a CSPRNG. These are required by STUN/TURN
// (MESSAGE-INTEGRITY, FINGERPRINT, long-term credential key derivation,
// transaction IDs, ufrag/pwd). Implementations are self-contained so the
// core ICE/STUN/TURN path has no hard OpenSSL dependency; OpenSSL is only
// used optionally for TURN over TLS.

#ifndef STICE_CRYPTO_HPP
#define STICE_CRYPTO_HPP

#include "stice/types.hpp"
#include <cstdint>
#include <cstddef>
#include <string>
#include <array>

namespace stice::crypto {

constexpr std::size_t MD5_SIZE = 16;
constexpr std::size_t SHA1_SIZE = 20;
constexpr std::size_t SHA256_SIZE = 32;

std::array<unsigned char, MD5_SIZE> md5(const unsigned char *data, std::size_t len);
std::array<unsigned char, SHA1_SIZE> sha1(const unsigned char *data, std::size_t len);
std::array<unsigned char, SHA256_SIZE> sha256(const unsigned char *data, std::size_t len);

// HMAC over a single message.
std::array<unsigned char, SHA1_SIZE> hmacSha1(const unsigned char *key, std::size_t keyLen,
                                              const unsigned char *msg, std::size_t msgLen);
std::array<unsigned char, SHA256_SIZE> hmacSha256(const unsigned char *key, std::size_t keyLen,
                                                  const unsigned char *msg, std::size_t msgLen);

// CRC32 (IEEE 802.3, poly 0xEDB88320). Matches zlib/IEEE and the value
// STUN FINGERPRINT expects before the 0x5354554E XOR.
uint32_t crc32(const unsigned char *data, std::size_t len);

// CSPRNG. Fills `out` with `len` bytes. Returns false on failure.
bool randomBytes(unsigned char *out, std::size_t len);
// Random 32/64-bit values.
uint32_t randomU32();
uint64_t randomU64();
// Random string over the base64 alphabet (used for ufrag/pwd).
std::string randomStr64(std::size_t len);

// Long-term credential HMAC key per RFC 5389 §15.4: MD5(username:realm:password).
std::array<unsigned char, MD5_SIZE> longTermKey(const std::string &username,
                                                const std::string &realm,
                                                const std::string &password);

} // namespace stice::crypto

#endif
