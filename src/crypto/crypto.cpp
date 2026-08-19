/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
#include "stice/crypto.hpp"

#include "stice/log.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#endif

#include <cstdio>
#include <cstring>

namespace stice::crypto {

// ---------------------------------------------------------------------------
// MD5 (RFC 1321)
// ---------------------------------------------------------------------------
namespace {
struct MD5Ctx {
	uint32_t a, b, c, d;
	uint64_t len; // total bytes
	unsigned char buf[64];
	std::size_t bufLen;
};

void md5Init(MD5Ctx &c) {
	c.a = 0x67452301;
	c.b = 0xefcdab89;
	c.c = 0x98badcfe;
	c.d = 0x10325476;
	c.len = 0;
	c.bufLen = 0;
}

const uint32_t md5K[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
const uint32_t md5S[64] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

void md5Block(MD5Ctx &c, const unsigned char *p) {
	uint32_t M[16];
	for (int i = 0; i < 16; ++i)
		M[i] = uint32_t{p[i * 4]} | (uint32_t{p[i * 4 + 1]} << 8) | (uint32_t{p[i * 4 + 2]} << 16) |
		       (uint32_t{p[i * 4 + 3]} << 24);
	uint32_t a = c.a, b = c.b, cc = c.c, d = c.d;
	for (int i = 0; i < 64; ++i) {
		uint32_t f;
		int g;
		if (i < 16) { f = (b & cc) | (~b & d); g = i; }
		else if (i < 32) { f = (d & b) | (~d & cc); g = (5 * i + 1) % 16; }
		else if (i < 48) { f = b ^ cc ^ d; g = (3 * i + 5) % 16; }
		else { f = cc ^ (b | ~d); g = (7 * i) % 16; }
		uint32_t temp = d;
		d = cc;
		cc = b;
		b = b + rotl32(a + f + md5K[i] + M[g], md5S[i]);
		a = temp;
	}
	c.a += a; c.b += b; c.c += cc; c.d += d;
}

void md5Update(MD5Ctx &c, const unsigned char *data, std::size_t len) {
	c.len += len;
	if (c.bufLen) {
		std::size_t need = 64 - c.bufLen;
		std::size_t take = std::min(need, len);
		std::memcpy(c.buf + c.bufLen, data, take);
		c.bufLen += take;
		data += take;
		len -= take;
		if (c.bufLen == 64) { md5Block(c, c.buf); c.bufLen = 0; }
	}
	while (len >= 64) { md5Block(c, data); data += 64; len -= 64; }
	if (len) { std::memcpy(c.buf, data, len); c.bufLen = len; }
}

void md5Final(MD5Ctx &c, unsigned char out[16]) {
	uint64_t bits = c.len * 8;
	unsigned char pad = 0x80;
	md5Update(c, &pad, 1);
	unsigned char zero = 0;
	while (c.bufLen != 56) md5Update(c, &zero, 1);
	unsigned char lenBytes[8];
	for (int i = 0; i < 8; ++i) lenBytes[i] = static_cast<unsigned char>(bits >> (8 * i));
	md5Update(c, lenBytes, 8);
	uint32_t vals[4] = {c.a, c.b, c.c, c.d};
	for (int i = 0; i < 4; ++i) {
		out[i * 4] = static_cast<unsigned char>(vals[i]);
		out[i * 4 + 1] = static_cast<unsigned char>(vals[i] >> 8);
		out[i * 4 + 2] = static_cast<unsigned char>(vals[i] >> 16);
		out[i * 4 + 3] = static_cast<unsigned char>(vals[i] >> 24);
	}
}
} // namespace

std::array<unsigned char, MD5_SIZE> md5(const unsigned char *data, std::size_t len) {
	MD5Ctx c;
	md5Init(c);
	md5Update(c, data, len);
	std::array<unsigned char, MD5_SIZE> out{};
	md5Final(c, out.data());
	return out;
}

// ---------------------------------------------------------------------------
// SHA-1 (FIPS 180-4)
// ---------------------------------------------------------------------------
namespace {
struct SHA1Ctx {
	uint32_t h[5];
	uint64_t len;
	unsigned char buf[64];
	std::size_t bufLen;
};
void sha1Init(SHA1Ctx &c) {
	c.h[0] = 0x67452301; c.h[1] = 0xEFCDAB89; c.h[2] = 0x98BADCFE; c.h[3] = 0x10325476; c.h[4] = 0xC3D2E1F0;
	c.len = 0; c.bufLen = 0;
}
void sha1Block(SHA1Ctx &c, const unsigned char *p) {
	uint32_t w[80];
	for (int i = 0; i < 16; ++i)
		w[i] = (uint32_t{p[i * 4]} << 24) | (uint32_t{p[i * 4 + 1]} << 16) | (uint32_t{p[i * 4 + 2]} << 8) | p[i * 4 + 3];
	for (int i = 16; i < 80; ++i)
		w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
	uint32_t a = c.h[0], b = c.h[1], cc = c.h[2], d = c.h[3], e = c.h[4];
	for (int i = 0; i < 80; ++i) {
		uint32_t f, k;
		if (i < 20) { f = (b & cc) | (~b & d); k = 0x5A827999; }
		else if (i < 40) { f = b ^ cc ^ d; k = 0x6ED9EBA1; }
		else if (i < 60) { f = (b & cc) | (b & d) | (cc & d); k = 0x8F1BBCDC; }
		else { f = b ^ cc ^ d; k = 0xCA62C1D6; }
		uint32_t t = rotl32(a, 5) + f + e + k + w[i];
		e = d; d = cc; cc = rotl32(b, 30); b = a; a = t;
	}
	c.h[0] += a; c.h[1] += b; c.h[2] += cc; c.h[3] += d; c.h[4] += e;
}
void sha1Update(SHA1Ctx &c, const unsigned char *data, std::size_t len) {
	c.len += len;
	if (c.bufLen) {
		std::size_t need = 64 - c.bufLen;
		std::size_t take = std::min(need, len);
		std::memcpy(c.buf + c.bufLen, data, take);
		c.bufLen += take; data += take; len -= take;
		if (c.bufLen == 64) { sha1Block(c, c.buf); c.bufLen = 0; }
	}
	while (len >= 64) { sha1Block(c, data); data += 64; len -= 64; }
	if (len) { std::memcpy(c.buf, data, len); c.bufLen = len; }
}
void sha1Final(SHA1Ctx &c, unsigned char out[20]) {
	uint64_t bits = c.len * 8;
	unsigned char pad = 0x80;
	sha1Update(c, &pad, 1);
	unsigned char zero = 0;
	while (c.bufLen != 56) sha1Update(c, &zero, 1);
	unsigned char lenBytes[8];
	for (int i = 0; i < 8; ++i) lenBytes[i] = static_cast<unsigned char>(bits >> (56 - 8 * i));
	sha1Update(c, lenBytes, 8);
	for (int i = 0; i < 5; ++i) {
		out[i * 4] = static_cast<unsigned char>(c.h[i] >> 24);
		out[i * 4 + 1] = static_cast<unsigned char>(c.h[i] >> 16);
		out[i * 4 + 2] = static_cast<unsigned char>(c.h[i] >> 8);
		out[i * 4 + 3] = static_cast<unsigned char>(c.h[i]);
	}
}
} // namespace

std::array<unsigned char, SHA1_SIZE> sha1(const unsigned char *data, std::size_t len) {
	SHA1Ctx c; sha1Init(c); sha1Update(c, data, len);
	std::array<unsigned char, SHA1_SIZE> out{};
	sha1Final(c, out.data());
	return out;
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------
namespace {
const uint32_t sha256K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
struct SHA256Ctx {
	uint32_t h[8];
	uint64_t len;
	unsigned char buf[64];
	std::size_t bufLen;
};
void sha256Init(SHA256Ctx &c) {
	c.h[0] = 0x6a09e667; c.h[1] = 0xbb67ae85; c.h[2] = 0x3c6ef372; c.h[3] = 0xa54ff53a;
	c.h[4] = 0x510e527f; c.h[5] = 0x9b05688c; c.h[6] = 0x1f83d9ab; c.h[7] = 0x5be0cd19;
	c.len = 0; c.bufLen = 0;
}
void sha256Block(SHA256Ctx &c, const unsigned char *p) {
	uint32_t w[64];
	for (int i = 0; i < 16; ++i)
		w[i] = (uint32_t{p[i * 4]} << 24) | (uint32_t{p[i * 4 + 1]} << 16) | (uint32_t{p[i * 4 + 2]} << 8) | p[i * 4 + 3];
	for (int i = 16; i < 64; ++i) {
		uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	uint32_t a = c.h[0], b = c.h[1], cc = c.h[2], d = c.h[3], e = c.h[4], f = c.h[5], g = c.h[6], h = c.h[7];
	for (int i = 0; i < 64; ++i) {
		uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
		uint32_t ch = (e & f) ^ (~e & g);
		uint32_t t1 = h + S1 + ch + sha256K[i] + w[i];
		uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
		uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
		uint32_t t2 = S0 + maj;
		h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
	}
	c.h[0] += a; c.h[1] += b; c.h[2] += cc; c.h[3] += d; c.h[4] += e; c.h[5] += f; c.h[6] += g; c.h[7] += h;
}
void sha256Update(SHA256Ctx &c, const unsigned char *data, std::size_t len) {
	c.len += len;
	if (c.bufLen) {
		std::size_t need = 64 - c.bufLen;
		std::size_t take = std::min(need, len);
		std::memcpy(c.buf + c.bufLen, data, take);
		c.bufLen += take; data += take; len -= take;
		if (c.bufLen == 64) { sha256Block(c, c.buf); c.bufLen = 0; }
	}
	while (len >= 64) { sha256Block(c, data); data += 64; len -= 64; }
	if (len) { std::memcpy(c.buf, data, len); c.bufLen = len; }
}
void sha256Final(SHA256Ctx &c, unsigned char out[32]) {
	uint64_t bits = c.len * 8;
	unsigned char pad = 0x80;
	sha256Update(c, &pad, 1);
	unsigned char zero = 0;
	while (c.bufLen != 56) sha256Update(c, &zero, 1);
	unsigned char lenBytes[8];
	for (int i = 0; i < 8; ++i) lenBytes[i] = static_cast<unsigned char>(bits >> (56 - 8 * i));
	sha256Update(c, lenBytes, 8);
	for (int i = 0; i < 8; ++i) {
		out[i * 4] = static_cast<unsigned char>(c.h[i] >> 24);
		out[i * 4 + 1] = static_cast<unsigned char>(c.h[i] >> 16);
		out[i * 4 + 2] = static_cast<unsigned char>(c.h[i] >> 8);
		out[i * 4 + 3] = static_cast<unsigned char>(c.h[i]);
	}
}
} // namespace

std::array<unsigned char, SHA256_SIZE> sha256(const unsigned char *data, std::size_t len) {
	SHA256Ctx c; sha256Init(c); sha256Update(c, data, len);
	std::array<unsigned char, SHA256_SIZE> out{};
	sha256Final(c, out.data());
	return out;
}

// ---------------------------------------------------------------------------
// HMAC (FIPS 198-1 / RFC 2104). Generic block size 64 (SHA-1, SHA-256, MD5).
// ---------------------------------------------------------------------------
namespace {
template <typename Ctx, void (*Init)(Ctx &), void (*Update)(Ctx &, const unsigned char *, std::size_t),
          void (*Final)(Ctx &, unsigned char *), std::size_t Out>
std::array<unsigned char, Out> hmacImpl(const unsigned char *key, std::size_t keyLen,
                                        const unsigned char *msg, std::size_t msgLen) {
	unsigned char k0[64] = {};
	if (keyLen <= 64) {
		std::memcpy(k0, key, keyLen);
	} else {
		Ctx c;
		Init(c);
		Update(c, key, keyLen);
		Final(c, k0);
	}
	unsigned char ipad[64], opad[64];
	for (int i = 0; i < 64; ++i) {
		ipad[i] = k0[i] ^ 0x36;
		opad[i] = k0[i] ^ 0x5c;
	}
	Ctx inner;
	Init(inner);
	Update(inner, ipad, 64);
	Update(inner, msg, msgLen);
	unsigned char innerDigest[Out];
	Final(inner, innerDigest);
	Ctx outer;
	Init(outer);
	Update(outer, opad, 64);
	Update(outer, innerDigest, Out);
	std::array<unsigned char, Out> out{};
	Final(outer, out.data());
	return out;
}
} // namespace

std::array<unsigned char, SHA1_SIZE> hmacSha1(const unsigned char *key, std::size_t keyLen,
                                              const unsigned char *msg, std::size_t msgLen) {
	return hmacImpl<SHA1Ctx, sha1Init, sha1Update, sha1Final, SHA1_SIZE>(key, keyLen, msg, msgLen);
}
std::array<unsigned char, SHA256_SIZE> hmacSha256(const unsigned char *key, std::size_t keyLen,
                                                  const unsigned char *msg, std::size_t msgLen) {
	return hmacImpl<SHA256Ctx, sha256Init, sha256Update, sha256Final, SHA256_SIZE>(key, keyLen, msg, msgLen);
}

// ---------------------------------------------------------------------------
// CRC32 (IEEE 802.3, poly 0xEDB88320) — matches zlib crc32 / STUN FINGERPRINT.
// ---------------------------------------------------------------------------
uint32_t crc32(const unsigned char *data, std::size_t len) {
	static uint32_t table[256];
	static bool init = false;
	if (!init) {
		for (uint32_t i = 0; i < 256; ++i) {
			uint32_t c = i;
			for (int k = 0; k < 8; ++k)
				c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
			table[i] = c;
		}
		init = true;
	}
	uint32_t crc = 0xFFFFFFFFu;
	for (std::size_t i = 0; i < len; ++i)
		crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
	return crc ^ 0xFFFFFFFFu;
}

// ---------------------------------------------------------------------------
// CSPRNG
// ---------------------------------------------------------------------------
bool randomBytes(unsigned char *out, std::size_t len) {
#ifdef _WIN32
	NTSTATUS status = BCryptGenRandom(nullptr, out, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	return status == 0;
#else
#if defined(__linux__) && defined(SYS_getrandom)
	if (syscall(SYS_getrandom, out, len, 0) == static_cast<long>(len))
		return true;
#endif
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) return false;
	std::size_t got = 0;
	while (got < len) {
		ssize_t n = read(fd, out + got, len - got);
		if (n <= 0) { close(fd); return false; }
		got += static_cast<std::size_t>(n);
	}
	close(fd);
	return true;
#endif
}

uint32_t randomU32() {
	unsigned char b[4];
	if (!randomBytes(b, 4)) return 0;
	return readU32Be(b);
}
uint64_t randomU64() {
	unsigned char b[8];
	if (!randomBytes(b, 8)) return 0;
	return (uint64_t{readU32Be(b)} << 32) | readU32Be(b + 4);
}

std::string randomStr64(std::size_t len) {
	static const char alphabet[] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	std::string s;
	s.reserve(len);
	unsigned char buf[32];
	std::size_t i = 0;
	while (s.size() < len) {
		if (i == 0) {
			if (!randomBytes(buf, sizeof(buf))) {
				// extremely unlikely; fill deterministically to make progress
				for (auto &b : buf) b = 0;
			}
		}
		s.push_back(alphabet[buf[i] & 0x3F]);
		i = (i + 1) % sizeof(buf);
	}
	return s;
}

std::array<unsigned char, MD5_SIZE> longTermKey(const std::string &username, const std::string &realm,
                                                const std::string &password) {
	std::string combined = username + ":" + realm + ":" + password;
	return md5(reinterpret_cast<const unsigned char *>(combined.data()), combined.size());
}

} // namespace stice::crypto
