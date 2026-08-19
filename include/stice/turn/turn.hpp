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
};

// Callbacks the TURN client uses to talk to the agent's network layer.
struct TurnSink {
	// Send a raw STUN message or ChannelData frame to the TURN server.
	std::function<void(const unsigned char *data, std::size_t size)> sendRaw;
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
	// Uses REQUESTED-TRANSPORT based on cfg_.transport: UDP(17) for UDP/TLS
	// control connections (RFC 5766), TCP(6) for TCP allocations (RFC 6062).
	void allocate();

	// Send application data to `peer` via the relay. Handles the
	// permission/channel state machine internally: if a channel is bound,
	// uses ChannelData; otherwise uses a Send indication and kicks off
	// CreatePermission + ChannelBind in the background.
	void sendData(const net::AddrRecord &peer, const unsigned char *data, std::size_t size);

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
	// Handle a STUN response (success or error).
	void handleStunResponse(const stun::Message &msg);
	// Handle an Allocate response (success: store relayed addr + lifetime,
	// start refresh timers; error 401: capture realm/nonce and retry;
	// error 438: refresh nonce and retry).
	void handleAllocateResponse(const stun::Message &msg, bool isError);
	// Handle a Refresh response.
	void handleRefreshResponse(const stun::Message &msg, bool isError);
	// Handle CreatePermission response.
	void handleCreatePermissionResponse(const stun::Message &msg, bool isError,
	                                    const net::AddrRecord &peer);
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
	net::AddrRecord relayedAddr_;
	std::uint32_t lifetime_ = 0;
	std::chrono::steady_clock::time_point refreshAt_{};
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
