// SPDX-License-Identifier: MPL-2.0
// stice TCP transport for ICE-TCP (RFC 6544) and TURN over TCP/TLS (RFC 8656 §4).
// Implements RFC 4571 2-byte length framing and optional TLS via OpenSSL.
// Ported from libjuice's tcp.c / tls.c.

#ifndef STICE_NET_TCP_HPP
#define STICE_NET_TCP_HPP

#include "stice/net/addr.hpp"
#include "stice/net/platform.hpp"
#include "stice/net/udp.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <vector>

namespace stice::net {

enum class TcpState {
	Disconnected,
	Connecting,
	TlsHandshaking,
	Connected,
	Failed,
};

// Framing mode for the TCP transport.
// RFC4571: 2-byte big-endian length prefix before each message (ICE-TCP).
// Raw:     no prefix; the caller handles framing (TURN over TCP/TLS, where
//          STUN messages and ChannelData are self-delimiting).
enum class FramingMode {
	RFC4571,
	Raw,
};

class TcpTransport {
public:
	TcpTransport() = default;
	~TcpTransport();
	TcpTransport(const TcpTransport &) = delete;
	TcpTransport &operator=(const TcpTransport &) = delete;

	// Begin a non-blocking connect to `dst`. useTls=true enables TLS after
	// connect. When useTls is true, skipVerify controls whether the server
	// certificate is validated against the system trust store (false = verify,
	// matching pion's default; true = skip, for testing only).
	bool beginConnect(const AddrRecord &dst, const std::string &sni, bool useTls,
	                  bool skipVerify = false);
	// Wrap an already-accepted socket fd (passive side of ICE-TCP). The fd
	// must already be non-blocking and connected. Sets state=Connected and
	// records peerAddr for routing. Used by TCPMux when accepting inbound
	// ICE-TCP connections.
	bool attach(socket_t fd, const AddrRecord &peerAddr);
	void close();

	// Peer address (set by beginConnect or attach). Used for routing inbound
	// frames back to the correct candidate pair.
	const AddrRecord &peerAddr() const { return peerAddr_; }

	// Application-layer connect timeout. If the non-blocking connect has not
	// completed (Connected/Failed) by `connectDeadline`, onWritable/onReadable
	// will transition to Failed. Returns true if a connect is in progress and
	// the deadline has expired (caller should treat as connect failure).
	bool connectTimedOut() const;

	// Set the connect deadline to now + timeoutMs. Only meaningful while
	// state_ == Connecting/TlsHandshaking.
	void setConnectTimeoutMs(int timeoutMs);

	// Absolute steady-clock ms of the connect deadline. Returns INT64_MAX
	// when no deadline is set. Lets the poll loop wake exactly when a
	// black-holed connect (no writable event ever fires) must time out.
	int64_t connectDeadlineMs() const {
		return connectDeadlineMs_.load(std::memory_order_acquire);
	}

	// Set the framing mode. Must be called before send/recv. Default: RFC4571.
	void setFramingMode(FramingMode mode) { framing_ = mode; }
	FramingMode framingMode() const { return framing_; }

	TcpState state() const { return state_; }
	socket_t handle() const { return sock_; }

	// Drive writable/readable events from the poll loop. Returns the set of
	// poll events now desired (POLLIN / POLLOUT).
	short onWritable();
	short onReadable();

	// Enqueue a message to be written. In RFC4571 mode, prepends a 2-byte
	// length prefix. In Raw mode, writes the data as-is. Returns false on
	// hard failure.
	bool send(const char *data, std::size_t size);
	// Pull one complete framed message out of the read buffer (RFC4571 mode),
	// or raw bytes from the buffer (Raw mode). Returns the number of bytes
	// written to `out` (0 if no data yet), or -1 on failure.
	int recv(char *out, std::size_t outSize, AddrRecord & /*peer*/);

	// True when the socket should be armed for POLLOUT: queued data or an
	// in-progress connect. Thread-safe: sendQueue_ is mutated by senders on
	// any thread (e.g. stice_send from the user thread, STUN responses from
	// the poll thread) and drained by the poll thread's flushSends.
	bool wantsWrite() const {
		std::lock_guard<std::mutex> lk(sendMtx_);
		return !sendQueue_.empty() || state_ == TcpState::Connecting;
	}

private:
	short flushSends();
	short driveTlsHandshake();

	socket_t sock_ = STICE_INVALID_SOCKET;
	// State is read by sender threads and written by the poll thread
	// (connect completion, error transitions) — atomic for torn-free reads.
	std::atomic<TcpState> state_{TcpState::Disconnected};
	bool useTls_ = false;
	bool skipVerify_ = false;
	std::string sni_;
	FramingMode framing_ = FramingMode::RFC4571;
	AddrRecord peerAddr_{};  // remote peer address (set by beginConnect/attach)

	// OpenSSL session (opaque to the header).
	void *ssl_ = nullptr;        // SSL*
	void *sslCtx_ = nullptr;     // SSL_CTX* (owned briefly)
	bool tlsWantRead_ = false;
	bool tlsWantWrite_ = false;

	// Write queue. In RFC4571 mode each entry is 2-byte prefix + payload.
	// In Raw mode each entry is just the payload.
	// Guarded by sendMtx_: send() (any thread) appends while the poll
	// thread drains via onWritable()/flushSends(). Unserialized
	// insert/erase on this vector caused heap corruption (0xC0000374 /
	// 0xC0000005) when app data was sent from the user thread while the
	// poll thread flushed a pending queue.
	std::vector<unsigned char> sendQueue_;
	mutable std::mutex sendMtx_;

	// Read buffer accumulation for framing. Guarded by recvMtx_
	// (onReadable appends on the poll thread; recv drains on the caller's
	// thread).
	std::vector<unsigned char> recvBuf_;
	mutable std::mutex recvMtx_;

	// Application-layer connect deadline (absolute steady-clock ms, -1 =
	// none). Single atomic so the poll thread can read it race-free while
	// the worker thread arms it (previously a non-atomic bool + time_point
	// pair could tear, making the poll loop miss the wakeup and sleep the
	// full 60 s clamp).
	std::atomic<int64_t> connectDeadlineMs_{-1};
};

} // namespace stice::net

#endif
