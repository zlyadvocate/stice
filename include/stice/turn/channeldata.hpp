// SPDX-License-Identifier: MPL-2.0
// stice TURN ChannelData framing (RFC 8656 §12.4).
//
// ChannelData frame:
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |         Channel Number        |            Length             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  /                          Application Data                     /
//  /                                                               /
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// Length is the data size NOT counting padding; padding to 4 bytes is added
// on TCP/TLS but not on UDP.

#ifndef STICE_TURN_CHANNELDATA_HPP
#define STICE_TURN_CHANNELDATA_HPP

#include "stice/types.hpp"

#include <cstdint>
#include <cstddef>

namespace stice::turn {

// RFC 5766/8656: channel numbers 0x4000 through 0x7FFF.
constexpr std::uint16_t ChannelMin = 0x4000;
constexpr std::uint16_t ChannelMax = 0x7FFF;
constexpr std::size_t ChannelDataHeaderSize = 4;

inline bool channelValid(std::uint16_t c) { return c >= ChannelMin && c <= ChannelMax; }

// Demultiplex: does this datagram look like ChannelData?
// Per RFC 7982, must check both the first byte (0x40..0x7F for channel
// numbers 0x4000-0x7FFF) AND that the length field is consistent with the
// packet size. Without the length check, application data whose first byte
// happens to fall in 0x40-0x7F (e.g. ASCII 'h'=0x68) would be misidentified.
inline bool isChannelData(const unsigned char *data, std::size_t size) {
	if (size < ChannelDataHeaderSize) return false;
	if (data[0] < 0x40 || data[0] > 0x7F) return false;
	// Length field (bytes 2-3) is the data length without padding.
	// On UDP the frame is exactly 4 + len bytes; on TCP it may be padded
	// to 4 bytes, so 4 + padded(len) <= size. For demultiplexing we accept
	// if 4 + len <= size (len could be smaller if there's TCP padding).
	std::size_t len = (static_cast<std::size_t>(data[2]) << 8) | data[3];
	return len + ChannelDataHeaderSize <= size;
}

// Wrap application data in a ChannelData frame. `out` will contain the 4-byte
// header + data + zero padding to 4-byte boundary (padded form is safe on both
// UDP and TCP). Returns the total frame size.
std::size_t wrapChannelData(std::uint16_t channel, const unsigned char *data,
                            std::size_t size, bytes &out);

// Unwrap a ChannelData frame. Returns the data length (without padding) and
// writes a pointer to the data into `outData`. Returns 0 if the buffer is too
// small or not a ChannelData frame.
std::size_t unwrapChannelData(const unsigned char *buf, std::size_t size,
                              std::uint16_t &channel, const unsigned char *&outData,
                              std::size_t &frameSize);

// Pick a random channel number in 0x4000..0x4FFF.
std::uint16_t randomChannelNumber();

} // namespace stice::turn

#endif
