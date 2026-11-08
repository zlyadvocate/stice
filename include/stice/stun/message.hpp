// SPDX-License-Identifier: MPL-2.0
// stice STUN message codec (RFC 5389 / RFC 8489). Ported from libjuice's
// stun.c and pion-stun's message.go.
//
// A STUN message has a 20-byte header (type, length, magic cookie,
// transaction id) followed by a sequence of TLV attributes padded to 4
// bytes. MESSAGE-INTEGRITY (HMAC-SHA1) and FINGERPRINT (CRC32) are
// special: they cover the message up to (but not including) themselves,
// with the header length field temporarily adjusted.

#ifndef STICE_STUN_MESSAGE_HPP
#define STICE_STUN_MESSAGE_HPP

#include "stice/types.hpp"
#include "stice/crypto.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace stice::stun {

constexpr std::size_t TransactionIDSize = 12;
constexpr std::size_t MessageHeaderSize = 20;
constexpr std::size_t AttributeHeaderSize = 4;
constexpr std::size_t Padding = 4;
constexpr std::uint32_t MagicCookie = 0x2112A442u;
constexpr std::uint32_t FingerprintXor = 0x5354554Eu;
constexpr std::size_t HmacSha1Size = 20;
constexpr std::size_t HmacSha256Size = 32;

// STUN methods (12-bit values).
enum class Method : std::uint16_t {
	Binding = 0x001,
	Allocate = 0x003,
	Refresh = 0x004,
	Send = 0x006,
	Data = 0x007,
	CreatePermission = 0x008,
	ChannelBind = 0x009,
	Connect = 0x00A,
	ConnectionBind = 0x00B,
	ConnectionAttempt = 0x00C,
};

// STUN classes (2-bit values per RFC 5389 §6: C1C0).
//   Request       = 0b00, Indication    = 0b01,
//   SuccessResp   = 0b10, ErrorResp     = 0b11.
// encodeType/decodeType handle the bit placement in the 16-bit type field.
enum class Class : std::uint16_t {
	Request = 0,
	Indication = 1,
	SuccessResponse = 2,
	ErrorResponse = 3,
};

// Attribute type IDs (RFC 5389 / RFC 8656 / RFC 8445).
enum class AttrType : std::uint16_t {
	MappedAddress = 0x0001,
	Username = 0x0006,
	MessageIntegrity = 0x0008,
	ErrorCode = 0x0009,
	UnknownAttributes = 0x000A,
	Realm = 0x0014,
	Nonce = 0x0015,
	MessageIntegritySha256 = 0x001C,
	PasswordAlgorithm = 0x001D,
	Userhash = 0x001E,
	XorMappedAddress = 0x0020,
	Priority = 0x0024,
	UseCandidate = 0x0025,
	// TCP-TYPE encodes the TCP candidate type (active/passive/so) as a 32-bit
	// enum, used in connectivity checks over TCP. RFC 6544 does not actually
	// allocate a STUN code point for it, and 0x0026 (the value previously used
	// here) is assigned by IANA to PADDING (RFC 5780) in the comprehension-
	// required range — a real collision. Use an unassigned comprehension-
	// optional value (IANA: 0xC004-0xC055 unassigned) so peers that do not
	// understand it simply ignore it instead of rejecting it with 420.
	TcpType = 0xC004,
	ChannelNumber = 0x000C,
	Lifetime = 0x000D,
	XorPeerAddress = 0x0012,
	Data = 0x0013,
	XorRelayedAddress = 0x0016,
	EvenPort = 0x0018,
	RequestedTransport = 0x0019,
	DontFragment = 0x001A,
	ReservationToken = 0x0022,
	RequestedAddressFamily = 0x0017,
	ConnectionId = 0x002A,
	// RFC 8489 §14.1: list of 16-bit password algorithm IDs the server accepts.
	// Comprehension-optional, so a peer that does not know it simply ignores it.
	PasswordAlgorithms = 0x8002,
	Software = 0x8022,
	AlternateServer = 0x8023,
	Fingerprint = 0x8028,
	IceControlled = 0x8029,
	IceControlling = 0x802A,
	// draft-thatcher-ice-renomination: custom nomination attribute.
	Nomination = 0xC001,
};

// Encode method + class into the 16-bit STUN type field using the pion
// bit-packing formula (handles methods up to 12 bits correctly).
inline std::uint16_t encodeType(Method method, Class cls) {
	std::uint16_t m = static_cast<std::uint16_t>(method);
	std::uint16_t c = static_cast<std::uint16_t>(cls);
	std::uint16_t a = m & 0x000F;
	std::uint16_t b = m & 0x0070;
	std::uint16_t d = m & 0x0F80;
	std::uint16_t msgBits = a + (b << 1) + (d << 2);
	std::uint16_t c0 = static_cast<std::uint16_t>((c & 0x0001) << 4);
	std::uint16_t c1 = static_cast<std::uint16_t>((c & 0x0002) << 7);
	return static_cast<std::uint16_t>(msgBits + c0 + c1);
}

// Decode a 16-bit STUN type field into method + class.
inline void decodeType(std::uint16_t type, Method &method, Class &cls) {
	std::uint16_t c0 = static_cast<std::uint16_t>((type >> 4) & 0x0001);
	std::uint16_t c1 = static_cast<std::uint16_t>((type >> 7) & 0x0002);
	cls = static_cast<Class>(c0 | c1);
	std::uint16_t a = type & 0x000F;
	std::uint16_t b = static_cast<std::uint16_t>((type >> 1) & 0x0070);
	std::uint16_t d = static_cast<std::uint16_t>((type >> 2) & 0x0F80);
	method = static_cast<Method>(a | b | d);
}

inline bool isResponseType(Class cls) {
	return (static_cast<std::uint16_t>(cls) & 0x02) != 0;
}

// RFC 8489 §6.3.1 / RFC 8656: only the methods this implementation defines are
// valid. decode() stays permissive so a server can answer an unknown method with
// 400 instead of silently dropping it; callers that act on a decoded message
// use this whitelist.
inline bool isKnownMethod(Method method) {
	switch (method) {
	case Method::Binding:
	case Method::Allocate:
	case Method::Refresh:
	case Method::Send:
	case Method::Data:
	case Method::CreatePermission:
	case Method::ChannelBind:
	case Method::Connect:
	case Method::ConnectionBind:
	case Method::ConnectionAttempt:
		return true;
	default:
		return false;
	}
}

// Address families for XOR-MAPPED-ADDRESS / MAPPED-ADDRESS.
constexpr std::uint8_t FamilyIPv4 = 0x01;
constexpr std::uint8_t FamilyIPv6 = 0x02;

// STUN error codes (RFC 5389 §6 / RFC 8656 §6).
constexpr int StunErrorTryAlternate = 300;
constexpr int StunErrorBadRequest = 400;
constexpr int StunErrorUnauthenticated = 401;
constexpr int StunErrorForbidden = 403;
constexpr int StunErrorUnknownAttribute = 420;
constexpr int StunErrorAllocationMismatch = 437;
constexpr int StunErrorStaleNonce = 438;
constexpr int StunErrorAddressFamilyNotSupported = 440;
constexpr int StunErrorWrongCredentials = 441;
constexpr int StunErrorUnsupportedTransport = 442;
constexpr int StunErrorPeerAddressFamilyMismatch = 443;
constexpr int StunErrorAllocationQuotaReached = 486;
constexpr int StunErrorServerError = 500;
constexpr int StunErrorInsufficientCapacity = 508;
// RFC 6062 §5.3.5: CONNECT-specific recoverable errors.
constexpr int StunErrorConnectionAlreadyExists = 446;
constexpr int StunErrorConnectionTimeoutOrFailure = 447;
// libjuice-internal sentinel: not on the wire.
constexpr int StunErrorInternalValidationFailed = 599;

const char *errorReason(int code);

struct Attribute {
	AttrType type;
	bytes value;
};

// Password algorithm IDs for PASSWORD-ALGORITHMS (RFC 8489 §14.1) and
// PASSWORD-ALGORITHM (0x001D). 0x0001 is MD5 (the RFC 5389 default) and 0x0002
// is SHA-256 (introduced by RFC 8489 for MESSAGE-INTEGRITY-SHA256).
constexpr std::uint16_t PasswordAlgorithmMd5 = 0x0001;
constexpr std::uint16_t PasswordAlgorithmSha256 = 0x0002;

// Which integrity attribute a message carries / should be signed with.
enum class IntegrityAlgo : std::uint8_t { HmacSha1 = 0, HmacSha256 = 1 };

// Long-term credentials captured from a 401/438 response.
struct Credentials {
	std::string username;
	std::string realm;
	std::string nonce;
	// Long-term HMAC key for MESSAGE-INTEGRITY: MD5(username:realm:password).
	bytes key;
	// Long-term HMAC key for MESSAGE-INTEGRITY-SHA256:
	// SHA-256(username:realm:password) (RFC 8489 §9.2.2).
	bytes keySha256;
	// Integrity algorithm negotiated with the server. HmacSha1 keeps the
	// RFC 5389 behaviour; HmacSha256 makes encode() emit MESSAGE-INTEGRITY-SHA256
	// INSTEAD of MESSAGE-INTEGRITY (RFC 8489 §9.2.4 allows only one integrity
	// attribute per message).
	IntegrityAlgo algo = IntegrityAlgo::HmacSha1;
	// Emit USERHASH instead of USERNAME (RFC 8489 §14.2). The value is the
	// binary SHA-256 of "username:realm"; the server resolves the user by
	// hashing each known username the same way.
	bool useUserhash = false;
	// PASSWORD-ALGORITHMS echoed verbatim from the 401/438 challenge (RFC 8489
	// §9.2.4): a client that received the attribute MUST repeat it unchanged in
	// every authenticated request, otherwise the server cannot tell whether an
	// on-path attacker stripped it to force MD5 (bid-down). Empty when the
	// server did not advertise a list.
	bytes passwordAlgorithms;
};

// Build the 16-byte XOR mask used by XOR-MAPPED-ADDRESS and friends:
// mask[0:4] = magic cookie, mask[4:16] = transaction id.
inline std::array<unsigned char, 16> xorMask(const std::array<unsigned char, TransactionIDSize> &tid) {
	std::array<unsigned char, 16> m{};
	m[0] = 0x21; m[1] = 0x12; m[2] = 0xA4; m[3] = 0x42;
	std::memcpy(m.data() + 4, tid.data(), TransactionIDSize);
	return m;
}

class Message {
public:
	Method method = Method::Binding;
	Class cls = Class::Request;
	std::array<unsigned char, TransactionIDSize> transactionID{};
	std::vector<Attribute> attributes;
	bytes raw; // encoded form (valid after encode() / decode())
	// Comprehension-required attribute types (< 0x8000) that decode() found but
	// this implementation does not understand (RFC 8489 §6.3.4). A recipient
	// MUST reject such a request with 420 (Unknown Attribute) listing these
	// types; comprehension-optional (>= 0x8000) attributes are never collected.
	std::vector<std::uint16_t> unknownComprehensionRequired;

	// Generate a random transaction ID.
	void newTransactionID();

	// Encode the message into `raw`. If `password` is non-empty and the
	// message is not an indication, MESSAGE-INTEGRITY (HMAC-SHA1 keyed
	// with `longTermKey` if present, else the password) is appended.
	// FINGERPRINT is always appended last.
	// If `creds` is non-null, USERNAME/REALM/NONCE are emitted before MI —
	// except on responses when `emitAuthAttributes` is false. A server signs
	// its responses with the long-term key but must not echo the client's
	// USERNAME/REALM/NONCE back (RFC 8489 §9.2.2).
	bool encode(const char *password = nullptr, const Credentials *creds = nullptr,
	            const char *software = "stice", bool emitAuthAttributes = true);

	// Decode a STUN message from a wire buffer. Validates magic cookie
	// and length. Does not verify MESSAGE-INTEGRITY or FINGERPRINT —
	// call checkIntegrity/checkFingerprint explicitly.
	bool decode(const unsigned char *data, std::size_t size);

	// Find the first attribute of the given type, or nullptr.
	const Attribute *find(AttrType type) const;
	Attribute *find(AttrType type);

	// Add a raw attribute. Does not pad; padding is applied at encode time.
	void addAttribute(AttrType type, const unsigned char *value, std::size_t len);
	void addAttribute(AttrType type, const bytes &value) {
		addAttribute(type, value.data(), value.size());
	}

	// Verify MESSAGE-INTEGRITY against the given HMAC key (raw password for
	// short-term, MD5/SHA256 hash for long-term). The attribute type present on
	// the wire selects the HMAC: MESSAGE-INTEGRITY (0x0008) uses HMAC-SHA1,
	// MESSAGE-INTEGRITY-SHA256 (0x001C) uses HMAC-SHA256 over the same key.
	// When both are present the SHA-256 attribute is preferred. If
	// `allowMissing` is true, returns true when neither attribute is present.
	bool checkIntegrity(const unsigned char *key, std::size_t keyLen, bool allowMissing = false) const;

	// Long-term variant: each attribute type is verified with its own key
	// (MESSAGE-INTEGRITY with `sha1Key`, MESSAGE-INTEGRITY-SHA256 with
	// `sha256Key`). SHA-256 is preferred when both attributes are present.
	bool checkIntegrityDual(const unsigned char *sha1Key, std::size_t sha1KeyLen,
	                        const unsigned char *sha256Key, std::size_t sha256KeyLen,
	                        bool allowMissing = false) const;

	// Verify FINGERPRINT. Returns true if present and matches.
	bool checkFingerprint(bool allowMissing = false) const;

	// Quick demultiplexer: does this buffer look like a STUN message?
	// Implements libjuice's strict is_stun_datagram test.
	static bool isMessage(const unsigned char *data, std::size_t size);

	// Helper: locate the MESSAGE-INTEGRITY attribute and return the byte
	// offset in `raw` where its value begins, or 0 if absent. Also returns
	// the offset of the attribute header in *attrStart.
	std::size_t findIntegrityOffset(std::size_t &attrStart) const;
};

} // namespace stice::stun

#endif
