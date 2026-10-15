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
	// Enqueue a CONTROL frame (STUN connectivity check / TURN Refresh,
	// CreatePermission, ChannelBind, CONNECTION-BIND). Control frames are
	// flushed ahead of the bulk application queue, so a saturated data
	// stream can never starve keepalives: head-of-line blocking of Refresh
	// or ConnectionBind makes the server drop the allocation/connection
	// (observed as 9s+ Binding RTT and "connection lost state=4" under
	// 100 MiB/round floods). Control frames also bypass the send-queue
	// high watermark — they are small and protocol-critical.
	bool sendControl(const char *data, std::size_t size);
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
		// E1: while TLS handshaking, arm POLLOUT when the handshake needs to
		// write (SSL_ERROR_WANT_WRITE) even if the send queue is empty,
		// otherwise the handshake stalls until connect timeout.
		return ctrlOff_ < ctrlQueue_.size() || sendOff_ < sendQueue_.size() ||
		       state_ == TcpState::Connecting ||
		       (state_ == TcpState::TlsHandshaking && tlsWantWrite_);
	}

	// D2: true when the pending-send backlog exceeds the high-water mark.
	// A stalled peer (TCP flow control) otherwise grows sendQueue_ without
	// bound; data-path callers poll this and surface EWOULDBLOCK backpressure
	// to the application instead of buffering forever.
	bool sendQueueFull() const {
		std::lock_guard<std::mutex> lk(sendMtx_);
		return (sendQueue_.size() - sendOff_) >= kSendQueueHighWater;
	}

	// High-water mark for the send backlog (8 MiB). Beyond this, senders get
	// backpressure; below it, bursts of up to 8 MiB are absorbed losslessly.
	static constexpr std::size_t kSendQueueHighWater = 8u * 1024 * 1024;

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
	// sendOff_ tracks the consumed prefix: draining sends from
	// data()+sendOff_ instead of erase()-ing the front, so a large
	// backlog (bulk send while the peer stalls) doesn't memmove the whole
	// queue on every 64 KiB chunk. The prefix is compacted only when it
	// exceeds kTcpBufCompactThreshold bytes.
	std::vector<unsigned char> sendQueue_;
	std::size_t sendOff_ = 0;
	// Control-frame queue (sendControl): flushed before sendQueue_ so bulk
	// application data can never delay STUN/TURN signalling. Same locking
	// discipline as sendQueue_ (sendMtx_ guards both queues).
	std::vector<unsigned char> ctrlQueue_;
	std::size_t ctrlOff_ = 0;
	mutable std::mutex sendMtx_;

	// Read buffer accumulation for framing. Guarded by recvMtx_
	// (onReadable appends on the poll thread; recv drains on the caller's
	// thread). recvOff_ is the consumed prefix — same amortized-consumption
	// scheme as sendQueue_ (no per-frame front erase).
	std::vector<unsigned char> recvBuf_;
	std::size_t recvOff_ = 0;
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
