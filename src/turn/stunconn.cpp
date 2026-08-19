/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "stice/turn/stunconn.hpp"

#include <cstdint>
#include <cstring>

namespace stice::turn {

namespace {
// Protocol constants (kept local to avoid pulling in stun/message.hpp and
// turn/channeldata.hpp, which would create header dependencies).
constexpr std::size_t kStunHeaderSize = 20;
constexpr std::uint32_t kStunMagicCookie = 0x2112A442u;
constexpr std::uint16_t kChannelMin = 0x4000;
constexpr std::uint16_t kChannelMax = 0x7FFF;
constexpr std::size_t kChannelDataHeaderSize = 4;
constexpr std::size_t kChannelDataPadding = 4;

inline std::uint16_t readU16BE(const unsigned char *p) {
	return (static_cast<std::uint16_t>(p[0]) << 8) | p[1];
}

inline std::uint32_t readU32BE(const unsigned char *p) {
	return (static_cast<std::uint32_t>(p[0]) << 24) |
	       (static_cast<std::uint32_t>(p[1]) << 16) |
	       (static_cast<std::uint32_t>(p[2]) << 8) |
	       static_cast<std::uint32_t>(p[3]);
}

// Determine the total frame size (including headers) of the STUN or
// ChannelData frame at the start of `buf`. Returns 0 if the buffer
// doesn't yet contain a complete frame, or SIZE_MAX if the data is
// invalid (not STUN or ChannelData).
std::size_t consumeSingleTurnFrame(const unsigned char *buf, std::size_t size) {
	// Need at least 4 bytes to read the first 2 fields (type/length).
	if (size < 4) return 0;

	// Check for STUN: magic cookie at bytes 4-7.
	// The first byte of a STUN message has its top 2 bits clear (RFC 5389 §6),
	// so it's always < 0x40. ChannelData's first byte is 0x40-0x7F.
	if (buf[0] < 0x40) {
		// Could be STUN. Need at least 8 bytes to verify the magic cookie.
		if (size < 8) return 0; // incomplete
		if (readU32BE(buf + 4) != kStunMagicCookie) {
			// Not STUN and not ChannelData (first byte < 0x40).
			return static_cast<std::size_t>(-1);
		}
		// STUN message: total size = header (20) + length field.
		std::uint16_t length = readU16BE(buf + 2);
		std::size_t frameSize = kStunHeaderSize + length;
		if (size < frameSize) return 0; // incomplete
		return frameSize;
	}

	// Check for ChannelData: channel number 0x4000-0x7FFF.
	std::uint16_t channel = readU16BE(buf);
	if (channel >= kChannelMin && channel <= kChannelMax) {
		std::uint16_t length = readU16BE(buf + 2);
		std::size_t frameSize = kChannelDataHeaderSize + length;
		// On TCP, ChannelData is padded to a 4-byte boundary.
		std::size_t padding = frameSize % kChannelDataPadding;
		if (padding != 0) {
			frameSize += kChannelDataPadding - padding;
		}
		if (size < frameSize) return 0; // incomplete
		return frameSize;
	}

	// Not STUN and not ChannelData.
	return static_cast<std::size_t>(-1);
}
} // namespace

void StunConn::feed(const unsigned char *data, std::size_t size) {
	if (size == 0) return;
	// Compact: if more than half the buffer has been consumed, erase the
	// consumed prefix to avoid unbounded growth. This also ensures that
	// pointers returned by readFrame() (which point into buf_) are not
	// invalidated while the caller is still using them.
	if (consumed_ > 0 && consumed_ >= buf_.size() / 2) {
		buf_.erase(buf_.begin(), buf_.begin() + consumed_);
		consumed_ = 0;
	}
	buf_.insert(buf_.end(), data, data + size);
}

std::size_t StunConn::readFrame(const unsigned char *&out) {
	if (consumed_ >= buf_.size()) return 0;

	std::size_t available = buf_.size() - consumed_;
	std::size_t frameSize = consumeSingleTurnFrame(buf_.data() + consumed_, available);
	if (frameSize == 0) return 0; // incomplete frame
	if (frameSize == static_cast<std::size_t>(-1)) {
		// Invalid data at the head of the buffer. Aligned with pion-turn's
		// STUNConn, which returns errInvalidTURNFrame to the caller. We
		// discard one byte and return SIZE_MAX so the caller can signal a
		// fatal stream error (the TCP connection should be closed). The
		// one-byte discard gives the caller a chance to observe the error
		// without the buffer staying permanently stuck.
		++consumed_;
		return static_cast<std::size_t>(-1);
	}

	out = buf_.data() + consumed_;
	consumed_ += frameSize;
	return frameSize;
}

} // namespace stice::turn
