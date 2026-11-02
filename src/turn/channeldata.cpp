/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
#include "stice/turn/channeldata.hpp"

#include "stice/crypto.hpp"

#include <cstring>

namespace stice::turn {

std::size_t wrapChannelData(std::uint16_t channel, const unsigned char *data,
                            std::size_t size, bytes &out, bool pad) {
	if (!channelValid(channel)) return 0;
	// F1: the 16-bit length field cannot express payloads > 65535; reject
	// rather than silently truncate (callers must fragment large payloads).
	if (size > 0xFFFF) return 0;
	std::size_t padded = pad ? paddedSize(size) : size;
	out.resize(ChannelDataHeaderSize + padded);
	out[0] = static_cast<unsigned char>(channel >> 8);
	out[1] = static_cast<unsigned char>(channel & 0xFF);
	out[2] = static_cast<unsigned char>(size >> 8);
	out[3] = static_cast<unsigned char>(size & 0xFF);
	if (size) std::memcpy(out.data() + 4, data, size);
	for (std::size_t i = size; i < padded; ++i) out[4 + i] = 0;
	return out.size();
}

std::size_t unwrapChannelData(const unsigned char *buf, std::size_t size,
                              std::uint16_t &channel, const unsigned char *&outData,
                              std::size_t &frameSize) {
	if (size < ChannelDataHeaderSize) return 0;
	channel = (static_cast<std::uint16_t>(buf[0]) << 8) | buf[1];
	// Accept the legacy RFC 5766 upper half on receive: older peers may still
	// allocate 0x5000-0x7FFF even though RFC 8656 §12.1 dropped it.
	if (!channelAcceptable(channel)) return 0;
	std::size_t len = (static_cast<std::size_t>(buf[2]) << 8) | buf[3];
	if (len > size - ChannelDataHeaderSize) return 0;
	outData = buf + ChannelDataHeaderSize;
	// On TCP/TLS the frame is padded to 4 bytes; on UDP it is exactly len.
	std::size_t padded = paddedSize(len);
	frameSize = ChannelDataHeaderSize + std::min(padded, size - ChannelDataHeaderSize);
	return len;
}

std::uint16_t randomChannelNumber() {
	std::uint32_t r = crypto::randomU32();
	// 0x4000-0x4FFF: the RFC 8656 §12.1 range is 4096 numbers, hence 12 bits.
	return static_cast<std::uint16_t>(ChannelMin | (r & 0x0FFF));
}

} // namespace stice::turn
