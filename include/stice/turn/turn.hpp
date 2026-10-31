// SPDX-License-Identifier: MPL-2.0
// stice TURN client (RFC 8656). Ported from pion-turn's internal/client
// and libjuice's TURN integration in agent.c.
//
// The TURN client owns the long-term credential handshake, allocation
// lifecycle (Allocate / Refresh with lifetime=0 on close), permission and
// channel bookkeeping, and the Send-indication vs ChannelData send-path
// choice. It does NOT own a socket — the ICE agent supplies a UDP socket
// (or TcpTransport for TURN over TCP/TLS) and the TURN client sends raw
// STUN messages / ChannelData frames through it via a callback. This
// mirrors libjuice's design where the agent owns the socket and the TURN
// state machine is just bookkeeping + message builders.
//
// State machine (per allocation):
//   Idle -> Allocating -> Allocated -> (Refreshing) -> Allocated
//                                        |
//                                        v
//                                     Deallocated
// On fatal error -> Failed.

#ifndef STICE_TURN_TURN_HPP
#define STICE_TURN_TURN_HPP

#include "stice/net/addr.hpp"
#include "stice/net/udp.hpp"
#include "stice/stun/message.hpp"
#include "stice/turn/channeldata.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace stice::turn {

// Retransmission parameters aligned with pion-turn (transaction.go / client.go).
// RTO starts at 200ms, doubles each retransmit, capped at 1600ms, max 7 retries.
constexpr int TurnRtoMs = 200;
constexpr int TurnMaxRtxIntervalMs = 1600;
constexpr int TurnMaxRtxCount = 7;
// Max 438 StaleNonce retries before giving up (prevents infinite nonce-refresh loops).
constexpr int MaxNonceRetries = 3;

enum class TurnTransport { UDP, TCP, TLS };

enum class AllocState {
	Idle,
	Allocating,
	Allocated,
	Deallocated, // Refresh(0) sent; no further refresh timers may re-arm
	Failed,
};

// One bound peer: a permission (and optionally a channel) for sending
// data to this peer through the relay.
struct PeerBinding {
	net::AddrRecord peer;
	std::uint16_t channel = 0;          // 0 if not channel-bound
	bool permissionPermitted = false;    // CreatePermission succeeded
	bool channelReady = false;           // ChannelBind succeeded
	std::chrono::steady_clock::time_point permissionRefreshAt;
	std::chrono::steady_clock::time_point channelRefreshAt;
	// In-flight transaction IDs (so retransmits reuse the same id).
	std::array<unsigned char, 12> permissionTid{};
	std::array<unsigned char, 12> channelTid{};
	bool permissionTidFresh = false;
	bool channelTidFresh = false;
	// Buffered data sent before CreatePermission completed; flushed on success.
	std::vector<bytes> pendingData;
};

struct TurnConfig {
	std::string serverHost;
	std::uint16_t serverPort = 3478;
	std::string username;
	std::string password;
	TurnTransport transport = TurnTransport::UDP;
	// Optional SNI for TLS.
	std::string sni;
	// Requested lifetime (seconds). Server may return a smaller value.
	std::uint32_t requestedLifetime = 600;
	// RFC 6062 TCP relayed-transport allocation opt-in. When false (the
	// default) the allocation is always a UDP relay (REQUESTED-TRANSPORT=17)
	// even when `transport` is TCP/TLS (RFC 8656: control over TCP, media
	// relayed over UDP, ChannelData over the control connection). This is
	// what browsers and coturn interoperate with. When true, a TCP
	// relayed-transport allocation (REQUESTED-TRANSPORT=6) is used — this
	// requires the full RFC 6062 CONNECT/CONNECTION-BIND machinery and is
	// only interoperable between stice agents, not browsers.
	bool tcpAllocation = false;
};

// Callbacks the TURN client uses to talk to the agent's network layer.
struct TurnSink {
	// Send a raw STUN message or ChannelData frame to the TURN server.
	// Returns the number of bytes sent, or a negative platform errno
	// (negated, e.g. -STICE_SENOBUFS) on failure so data-path callers can
	// propagate backpressure to the application.
	std::function<int(const unsigned char *data, std::size_t size)> sendRaw;
	// A relayed candidate is available (after Allocate success).
	std::function<void(const net::AddrRecord &relayed, std::uint32_t lifetime)> onAllocated;
	// Allocation failed permanently.
	std::function<void(int errorCode, const std::string &reason)> onFailed;
	// Application data arrived via the relay (Data indication or ChannelData).
	std::function<void(const net::AddrRecord &peer, const unsigned char *data, std::size_t size)> onData;
	// Log message.
	std::function<void(int level, const char *msg)> onLog;
	// --- RFC 6062 TCP allocation callbacks (only invoked for TCP allocations) ---
	// CONNECT request succeeded (active mode): the agent should open a new TCP
	// data connection to the TURN server and send a CONNECTION-BIND with this id.
	std::function<void(std::uint32_t connectionId, const net::AddrRecord &peer)> onConnectSuccess;
	// CONNECTION-ATTEMPT indication received (passive mode): a peer initiated a
	// TCP connection to our relayed address. The agent should open a new TCP
	// data connection and send a CONNECTION-BIND with this id.
	std::function<void(std::uint32_t connectionId, const net::AddrRecord &peer)> onConnectionAttempt;
	// CONNECT request failed (active mode): the TURN server could not
	// establish a TCP connection to the peer's relayed address. The agent
	// should mark the candidate pair as Failed.
	std::function<void(int errorCode, const std::string &reason, const net::AddrRecord &peer)> onConnectFailed;
};

class Client {
public:
	Client() = default;
	~Client() = default;

	void init(TurnConfig cfg, TurnSink sink);

	// Kick off the allocation. Calls onAllocated on success.
	// Uses REQUESTED-TRANSPORT based on cfg_.tcpAllocation: UDP(17) for
	// RFC 8656 (default, all control transports), TCP(6) for RFC 6062
	// TCP allocations (opt-in, stice-to-stice only).
	void allocate();

	// Send application data to `peer` via the relay. Handles the
	// permission/channel state machine internally: if a channel is bound,
	// uses ChannelData; otherwise uses a Send indication and kicks off
	// CreatePermission + ChannelBind in the background.
	// Returns a non-negative value on acceptance (bytes buffered pending
	// permission count as accepted), or a negative platform errno on
	// transport failure, so callers can surface backpressure (EAGAIN /
	// ENOBUFS) instead of silently dropping the data.
	int sendData(const net::AddrRecord &peer, const unsigned char *data, std::size_t size);

	// Fast path for the hot app-data send loop: if a ChannelData channel is
	// already bound for `peer`, render the payload as a ChannelData frame into
	// `out` and return 1 so the ICE agent can send the frame OUTSIDE the agent
	// lock (removing lock contention between the send loop and the poll thread,
	// which libjuice avoids with its independent send_mutex). Returns 0 when no
	// usable channel is ready yet (caller must fall back to sendData), or a
	// negative value on error. Const: only reads binding/channel state.
	int prepareChannelData(const net::AddrRecord &peer, const unsigned char *data,
	                       std::size_t size, bytes &out) const;

	// Tear down the allocation. Sends Refresh with LIFETIME=0.
	void deallocate();

	// Feed an inbound STUN message or ChannelData frame received from the
	// TURN server. `data` is the raw frame (no RFC 4571 prefix).
	void handleInbound(const unsigned char *data, std::size_t size);

	// Periodic tick. Drives permission/channel refresh and allocation
	// refresh. Returns the next wake-up timestamp (ms since epoch), or 0
	// if nothing is pending.
	std::chrono::steady_clock::time_point tick();
	std::chrono::steady_clock::time_point nextTick() const { return nextTick_; }

	AllocState state() const { return state_; }
	const net::AddrRecord &relayedAddr() const { return relayedAddr_; }
	std::uint32_t lifetime() const { return lifetime_; }

	// True if a permission has been established for `peer` (port ignored
	// per RFC 5766). Used by the ICE agent to decide whether to send a
	// Send indication immediately or wait.
	bool hasPermission(const net::AddrRecord &peer) const;

	// Proactively request CreatePermission for a peer (no-op if already
	// permitted or in flight). Called by the ICE agent when forming pairs
	// with relayed local candidates so the TURN server is ready to forward
	// data by the time connectivity checks are sent.
	void ensurePermission(const net::AddrRecord &peer) { sendCreatePermission(peer); }

	// --- RFC 6062 TCP allocation support ---
	// True if this allocation uses TCP relayed transport (REQUESTED-TRANSPORT=6).
	bool isTcpAllocation() const { return isTcpAllocation_; }
	// Send a CONNECT request for active mode: asks the TURN server to make a
	// TCP connection to `peer` (the peer's relayed TCP address). On success,
	// onConnectSuccess(connectionId, peer) is invoked.
	void sendConnect(const net::AddrRecord &peer);
	// Build a raw CONNECTION-BIND request for a data connection. The agent
	// sends these bytes on a newly-opened TCP connection to the TURN server.
	// After the server's success response, raw application data flows on
	// that connection. Returns the encoded message (with MESSAGE-INTEGRITY).
	std::vector<unsigned char> buildConnectionBindRequest(std::uint32_t connectionId);

private:
	// Send a STUN request, applying long-term credentials if we have them.
	void sendRequest(stun::Message &msg);
	// Apply credentials + encode MESSAGE-INTEGRITY into msg.raw (no send).
	// Kept separate from the actual send so callers can register the pending
	// transaction BEFORE the datagram leaves the socket. The TURN response
	// arrives on the poll thread while the request is sent from the gather
	// thread; if the response beats the pending_ registration it is dropped as
	// "no pending TID match" and the relay candidate never becomes ready.
	void prepareRequest(stun::Message &msg);
	// Send an already-encoded, already-registered request.
	void sendPrepared(const stun::Message &msg);
	// Handle a STUN response (success or error).
	void handleStunResponse(const stun::Message &msg);
	// Centralized 401/438 handling shared by all request types. Captures
	// realm/nonce (401) or refreshes the nonce (438), bounded by
	// MaxNonceRetries. `retryAuthed` is false for Allocate (a 401 after we
	// already sent credentials means wrong password -> fatal) and true for
	// post-allocation requests (401 there is usually a rotated nonce).
	// Returns true when the request should be re-sent with refreshed creds.
	bool handleAuthError(const stun::Message &msg, int code, bool retryAuthed);
	// Transition to Failed and emit onFailed AT MOST ONCE per allocation.
	void failAllocation(int errorCode, const std::string &reason);
	// Handle an Allocate response (success: store relayed addr + lifetime,
	// start refresh timers; error 401: capture realm/nonce and retry;
	// error 438: refresh nonce and retry).
	void handleAllocateResponse(const stun::Message &msg, bool isError);
	// Handle a Refresh response.
	void handleRefreshResponse(const stun::Message &msg, bool isError);
	// Handle CreatePermission response.
	void handleCreatePermissionResponse(const stun::Message &msg, bool isError,
	                                    const net::AddrRecord &peer);
	// Flush data buffered for `b` while its permission was pending (or while the
	// transport was under backpressure). Packets the transport refuses
	// (sendRaw < 0) stay queued in order; returns the number still buffered.
	std::size_t flushPendingData(PeerBinding &b);
	// Handle ChannelBind response.
	void handleChannelBindResponse(const stun::Message &msg, bool isError,
	                               const net::AddrRecord &peer);
	// Handle a Data indication.
	void handleDataIndication(const stun::Message &msg);
	// Handle a ChannelData frame.
	void handleChannelData(const unsigned char *data, std::size_t size);
	// Handle a CONNECT response (RFC 6062 active mode): extract CONNECTION-ID.
	void handleConnectResponse(const stun::Message &msg, bool isError,
	                           const net::AddrRecord &peer);
	// Handle a CONNECTION-ATTEMPT indication (RFC 6062 passive mode).
	void handleConnectionAttempt(const stun::Message &msg);

	// Build the long-term credentials block (USERNAME/REALM/NONCE/MI key)
	// from the current creds and password.
	void applyCredentials(stun::Message &msg);

	// Find or create a PeerBinding for `peer` (keyed by address, port ignored).
	PeerBinding &getBinding(const net::AddrRecord &peer);
	// Send a CreatePermission request for `peer` (idempotent: reuses an
	// in-flight tid if one exists).
	void sendCreatePermission(const net::AddrRecord &peer);
	// Send a ChannelBind request for `peer` (allocates a channel number).
	void sendChannelBind(const net::AddrRecord &peer);
	// Send a Refresh request with the given lifetime.
	void sendRefresh(std::uint32_t lifetime);

	void log(int level, const char *fmt, ...);

	TurnConfig cfg_;
	TurnSink sink_;
	AllocState state_ = AllocState::Idle;
	std::optional<stun::Credentials> creds_;
	int nonceRetries_ = 0; // 438 StaleNonce retry counter (reset on successful auth)
	// onFailed is a terminal event for this allocation: the ICE agent decrements
	// its pending-relay counter in the callback, so it must fire AT MOST ONCE.
	// Set once we emit onFailed (auth failure, timeout, transport loss, refresh
	// failure). Prevents the "allocated then transport-lost" double-decrement
	// (which underflows the counter in multi-server scenarios).
	bool failedEmitted_ = false;
	net::AddrRecord relayedAddr_;
	std::uint32_t lifetime_ = 0;
	std::chrono::steady_clock::time_point refreshAt_{};
	// In-flight guard for Refresh, mirroring PeerBinding::permissionTidFresh /
	// channelTidFresh. Without it, any Refresh that did not get a successful
	// response was re-issued on EVERY tick: sendRefresh() never moved refreshAt_,
	// so tick() kept returning a past-due nextTick_ and the poll loop spun,
	// emitting one Refresh per iteration. That flooded the server (observed as a
	// continuous "REFRESH(method=4) -> ERROR(cls=2)" stream during teardown),
	// grew pending_ without bound, and pinned the poll thread.
	bool refreshTidFresh_ = false;
	std::chrono::steady_clock::time_point nextTick_{};
	// Allocate transaction ID (for tracking the in-flight allocate).
	std::array<unsigned char, 12> allocateTid_{};
	// Transaction ID -> handler (so responses can be dispatched).
	struct PendingTx {
		enum class Kind { Allocate, Refresh, CreatePermission, ChannelBind, Connect } kind;
		net::AddrRecord peer; // for CreatePermission / ChannelBind / Connect
		std::chrono::steady_clock::time_point sentAt;
		std::chrono::steady_clock::time_point nextRetransmitAt;
		int retries = 0;
		// Encoded raw bytes for retransmission (same TID must be reused per RFC 5389).
		std::vector<unsigned char> rawBytes;
	};
	std::map<std::string, PendingTx> pending_;
	std::vector<PeerBinding> bindings_;
	// RFC 6062: true when REQUESTED-TRANSPORT=TCP(6) was used in Allocate.
	bool isTcpAllocation_ = false;
};

} // namespace stice::turn

#endif
