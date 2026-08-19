// SPDX-License-Identifier: MPL-2.0
// stice self-delimiting STUN/TURN stream parser for TURN over TCP/TLS.
//
// Aligned with pion-turn's proto.STUNConn: TURN over TCP does NOT use the
// RFC 4571 2-byte length prefix. Instead, STUN messages and ChannelData
// frames are self-delimiting on the TCP stream:
//
//   - STUN messages carry a 20-byte header with a 16-bit length field
//     (bytes 2-3) giving the payload size. Total frame = 20 + length.
//   - ChannelData frames carry a 4-byte header with a 16-bit length field
//     (bytes 2-3) giving the data size. On TCP the data is padded to a
//     4-byte boundary. Total frame = 4 + padded(length).
//
// The first byte of a STUN message is always < 0x40 (top 2 bits are 0 per
// RFC 5389 §6), while ChannelData's first byte is 0x40-0x7F (channel numbers
// 0x4000-0x7FFF). This allows unambiguous demultiplexing on a TCP stream.

#ifndef STICE_TURN_STUNCONN_HPP
#define STICE_TURN_STUNCONN_HPP

#include "stice/types.hpp"

#include <cstddef>
#include <vector>

namespace stice::turn {

class StunConn {
public:
	// Accumulate received bytes from the TCP stream.
	void feed(const unsigned char *data, std::size_t size);

	// Pull one complete self-delimited STUN or ChannelData frame from the
	// buffer. Sets `out` to point to the frame data in the internal buffer
	// and returns the frame size (including STUN/ChannelData headers).
	// Returns 0 if no complete frame is available yet. The returned frame
	// is consumed (the read offset advances), but the pointer remains valid
	// until the next call to feed().
	// On invalid (non-STUN, non-ChannelData) data at the head of the
	// buffer, returns SIZE_MAX and discards one byte to allow resync.
	// Callers should treat SIZE_MAX as a fatal stream error (close the
	// connection), aligned with pion-turn's errInvalidTURNFrame behavior.
	std::size_t readFrame(const unsigned char *&out);

	// Returns the number of bytes currently buffered (not yet consumed).
	std::size_t buffered() const { return buf_.size() - consumed_; }

private:
	bytes buf_;
	std::size_t consumed_ = 0;
};

} // namespace stice::turn

#endif // STICE_TURN_STUNCONN_HPP
