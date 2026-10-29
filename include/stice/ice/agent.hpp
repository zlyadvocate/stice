// SPDX-License-Identifier: MPL-2.0
// stice ICE agent (RFC 8445). Ported from libjuice's agent.c and
// pion-ice's agent.go / selection.go.
//
// The agent owns:
//   - the local UDP socket (and optional TCP transport)
//   - the local + remote ICE descriptions (ufrag, pwd, candidates)
//   - the candidate pair list (sorted by priority)
//   - STUN entries (one per candidate pair, plus server/relay entries)
//   - TURN allocations (one per TURN server)
//   - the controlling/controlled role and tiebreaker
//
// It runs in POLL concurrency mode: it registers as a PollParticipant
// with the shared PollRegistry, and the registry's background thread
// drives its IO (onUdpReadable) and periodic bookkeeping (onBookkeeping).

#ifndef STICE_ICE_AGENT_HPP
#define STICE_ICE_AGENT_HPP

#include "stice/stice.h"
#include "stice/ice/addr_rewrite.hpp"
#include "stice/ice/candidate.hpp"
#include "stice/ice/candidatepair.hpp"
#include "stice/ice/pairing_strategy.hpp"
#include "stice/ice/sdp.hpp"
#include "stice/net/addr.hpp"
#include "stice/net/mdns.hpp"
#include "stice/net/platform.hpp"
#include "stice/net/poll.hpp"
#include "stice/net/tcp.hpp"
#include "stice/net/udp.hpp"
#include "stice/net/udp_mux.hpp"
#include "stice/net/tcp_mux.hpp"
#include "stice/stun/message.hpp"
#include "stice/turn/stunconn.hpp"
#include "stice/turn/turn.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace stice::ice {

// LifetimeGuard protects async callbacks from use-after-free when the
// Agent is destroyed while the poll thread is mid-callback.
//
// Problem: the PollRegistry background thread dispatches onUdpReadable /
// onBookkeeping / onTcpEvents to the Agent, and UDPMux/TCPMux/TURN sinks
// capture a raw `this` pointer. If ~Agent runs on the user thread while
// the poll thread is inside such a callback, the Agent's members get
// destroyed mid-callback → UAF.
//
// Solution: every async entry point acquires the guard (atomically
// increments inFlight after checking alive). ~Agent calls shutdown()
// which sets alive=false and blocks until inFlight drops to zero,
// guaranteeing no callback is executing (or will execute) before
// destruction proceeds.
// Budget for LifetimeGuard::shutdown() to drain in-flight async scopes before
// ~Agent gives up, proceeds, and reports it loudly. Kept BOUNDED on purpose: a
// wedged scope-holder must not be able to hang teardown forever.
constexpr int LifetimeDrainTimeoutMs = 5000;

class LifetimeGuard {
public:
	std::atomic<bool> alive{true};
	std::atomic<int> inFlight{0};
	std::mutex cvMutex;
	std::condition_variable cv;

	bool acquire() {
		if (!alive.load(std::memory_order_acquire)) return false;
		inFlight.fetch_add(1, std::memory_order_acq_rel);
		// Re-check after increment to close the race with shutdown().
		if (!alive.load(std::memory_order_acquire)) {
			release();
			return false;
		}
		return true;
	}

	void release() {
		if (inFlight.fetch_sub(1, std::memory_order_acq_rel) == 1) {
			std::lock_guard<std::mutex> lock(cvMutex);
			cv.notify_all();
		}
	}

	// Drain in-flight async scopes. BOUNDED on purpose: a scope-holder that is
	// itself wedged (e.g. a poll-thread callback stuck behind a lock) must not be
	// able to hang teardown forever - that was the failure mode behind
	// "tearing down A" never returning. Returns true when everything drained;
	// false means we gave up and the caller proceeds anyway (a deliberately
	// bounded hang -> diagnosable failure trade-off, because the leaked thread
	// may still reference this agent).
	bool shutdown(int timeoutMs = LifetimeDrainTimeoutMs) {
		alive.store(false, std::memory_order_release);
		std::unique_lock<std::mutex> lock(cvMutex);
		return cv.wait_for(lock, std::chrono::milliseconds(timeoutMs), [this] {
			return inFlight.load(std::memory_order_acquire) == 0;
		});
	}
	int inFlightCount() const { return static_cast<int>(inFlight.load(std::memory_order_acquire)); }
};

// RAII scope guard for LifetimeGuard. Construct at the top of each async
// callback; if `!scope` the Agent is being destroyed — return immediately.
class LifetimeScope {
public:
	explicit LifetimeScope(std::shared_ptr<LifetimeGuard> g) : guard_(std::move(g)) {
		ok_ = guard_ && guard_->acquire();
	}
	~LifetimeScope() {
		if (ok_) guard_->release();
	}
	explicit operator bool() const { return ok_; }
	LifetimeScope(const LifetimeScope &) = delete;
	LifetimeScope &operator=(const LifetimeScope &) = delete;

private:
	std::shared_ptr<LifetimeGuard> guard_;
	bool ok_ = false;
};

// Timing constants (mirrors libjuice agent.h).
constexpr int MinStunRetransmissionTimeoutMs = 500;
constexpr int LastStunRetransmissionTimeoutMs = 500 * 16; // 8000
constexpr int MaxStunCheckRetransmissions = 6;            // ~39.5s total
constexpr int MaxStunServerRetransmissions = 5;
constexpr int StunTcpTimeoutMs = 8000;
// Soft gathering timeout. If srflx/relay entries stay pending (STUN server
// unreachable, or high-load packet loss) the gathering MUST still complete so
// the ICE session can proceed; late candidates are trickled. Mirrors libjuice
// completing gathering even when no srflx is obtained. 15s bounds the worst
// case while letting the normal 500ms-exp-backoff srflx path finish.
constexpr int GatherTimeoutMs = 15000;
// Application-layer TCP connect timeout. Prevents an active TCP connect to an
// unresponsive remote (e.g. black-holed address) from hanging indefinitely;
// the poll loop only fires onWritable when the kernel completes the connect,
// so a silent peer would otherwise never advance. Aligned with the ICE-TCP
// check retransmission budget (StunTcpTimeoutMs).
constexpr int TcpConnectTimeoutMs = 8000;
// Bounded wait for the parallel DNS phase of the gather worker. getaddrinfo has
// no timeout of its own, so an unresponsive resolver must never be able to pin
// the worker (and therefore stice_destroy) indefinitely: after this the item is
// treated as unresolved and its resolver thread is abandoned (it touches no
// Agent state).
constexpr int GatherDnsTimeoutMs = 5000;
// Bounded wait in ~Agent for the gather worker to exit after cancellation. The
// DNS phase is bounded/detachable and the entry-building phase now acquires the
// agent lock with a bounded budget too (GatherLockTimeoutMs), so the worker can
// never sit on a LifetimeScope indefinitely; this budget covers both.
constexpr int GatherWorkerJoinTimeoutMs = 3000;
// Budget for the gather worker to acquire Agent::mutex_ in its entry-building
// phase. std::recursive_mutex has no timed lock, so this is a try_lock poll loop.
// Bounding it is what keeps the worker's LifetimeScope hold time finite - without
// it, a wedged mutex holder left that scope alive forever and ~Agent's drain
// blocked on it permanently (the "tearing down A" hang).
constexpr int GatherLockTimeoutMs = 1000;
constexpr int StunPacingTimeMs = 50; // Ta
constexpr int StunKeepalivePeriodMs = 15000;
// RFC 8863 (Patiently Awaiting Connectivity) recommends the PAC timer be the
// agent's connectivity check transaction timeout, i.e. 39.5 s.
constexpr int IcePacTimeoutMs = 39500;
constexpr int ConsentTimeoutMs = 30000;
// RFC 7675 §5.1: the consent check period is randomized within [0.8, 1.2] x the
// basic period, "SHOULD set a default interval of 5 seconds" -> 4-6 s, and
// "MUST NOT set the period between checks to less than 4 seconds".
constexpr int DefaultConsentCheckPeriodMs = 5000;
constexpr int MinConsentCheckPeriodMs = 4000;
constexpr int MaxConsentCheckPeriodMs = 6000;
// Idle consent freshness: when no application data has flowed for
// IdleThresholdMs, stretch the consent check interval to IdleConsentCheckMs
// to reduce traffic on quiescent sessions. Kept within ~1/3 of
// ConsentTimeoutMs so that at least three checks land inside the 30 s window
// even with packet loss (RFC 7675 expects ~5-7 checks in that window; a 15 s
// interval left only two chances and made premature consent expiry under loss
// materially more likely).
constexpr int IdleConsentCheckMs = 10000;
constexpr int IdleThresholdMs = 30000;
constexpr int NominationTimeoutMs = 2000;
// Nomination delay by candidate type (aligned with pion-ice defaultNominationDelay).
// host=0, srflx=500ms, prflx=1000ms, relay=2000ms.
constexpr int NominationDelayHostMs = 0;
constexpr int NominationDelaySrflxMs = 500;
constexpr int NominationDelayPrflxMs = 1000;
constexpr int NominationDelayRelayMs = 2000;
constexpr std::uint32_t DefaultTurnLifetime = 600;
constexpr std::uint32_t DefaultTurnRefreshPeriod = 540;

constexpr std::size_t MaxCandidatePairs = 90;
constexpr std::size_t MaxStunEntries = 92;
constexpr std::size_t MaxPeerReflexiveCandidates = 14;

enum class AgentMode { Unknown, Controlling, Controlled };

enum class StunEntryType { Empty, Server, Relay, Check };

enum class StunEntryState {
	Pending,
	Cancelled,
	Failed,
	Succeeded,
	SucceededKeepalive,
	Idle,
};

struct StunEntry {
	StunEntryType type = StunEntryType::Empty;
	StunEntryState state = StunEntryState::Idle;
	AgentMode mode = AgentMode::Unknown;
	CandidatePair *pair = nullptr;
	net::AddrRecord record;       // remote target (CHECK) or server addr (SERVER/RELAY)
	net::AddrRecord relayed;      // relayed addr (RELAY entries)
	std::array<unsigned char, 12> transactionID{};
	std::chrono::steady_clock::time_point nextTransmission{};
	std::chrono::milliseconds retransmissionTimeout{MinStunRetransmissionTimeoutMs};
	int retransmissions = 0;
	bool transactionIdExpired = true;
	// For TURN RELAY entries: the underlying TURN client.
	std::unique_ptr<turn::Client> turn;
	// For TURN RELAY entries over TCP/TLS: dedicated control transport +
	// self-delimiting frame reassembler. Per-entry ownership lets multiple
	// TCP/TLS TURN servers allocate concurrently (the old agent-wide single
	// turnTcpTransport_ allowed one). shared_ptr because the entry's sendRaw
	// closure also holds it: if the relay entry is ever reset/erased while a
	// TURN client callback still routes through sendRaw, the transport stays
	// alive until every owner drops it (no UAF).
	std::shared_ptr<net::TcpTransport> turnTcp;
	turn::StunConn turnTcpConn;
	bool tcpTurn = false; // entry uses a TCP/TLS control connection
	// TLS parameters of the control connection (inherited by the RFC 6062
	// data connection so turns: relay does not silently downgrade to plain).
	bool turnTcpUseTls = false;
	std::string turnTcpSni;
	bool turnTcpSkipVerify = false;
	// Per-server CA bundle (empty -> process-wide STICE_TLS_CA_FILE). Copied
	// from stice_turn_server_t::ca_file so several TURN servers in one agent
	// can each pin a different private CA.
	std::string turnTcpCaFile;
	// Terminal-event guard: pendingRelayAllocations_ is decremented exactly
	// once per relay entry, by the first of onAllocated/onFailed that fires.
	std::shared_ptr<std::atomic<bool>> relayCounted;
	// Shared allocation-start time for RTT-based relay priority correction.
	std::shared_ptr<std::chrono::steady_clock::time_point> allocStart;
};

struct AgentConfig {
	stice_config_t publicConfig; // mirrors the C API config
};

class Agent : public net::PollParticipant {
public:
	Agent();
	~Agent();

	// Initialize with the C API config. Returns false on failure (e.g.
	// could not create the UDP socket). `self` is the stice_agent_t*
	// that owns this Agent, passed back to user callbacks.
	bool init(const stice_config_t *cfg, stice_agent_t *self);

	// C API entry points.
	int gatherCandidates();
	int getLocalDescription(char *buf, std::size_t size) const;
	int setRemoteDescription(const char *sdp);
	int addRemoteCandidate(const char *sdp);
	int addTurnServer(const stice_turn_server_t *srv);
	int addStunServer(const char *host, uint16_t port);
	// Unified ICE server from URL (stun:/turn:/turns:). Auto-populates both
	// STUN and TURN internal storage from a single URL, eliminating duplicate
	// configuration. A turn: URL adds both a TURN relay server AND a STUN
	// server (since coturn supports both on the same port).
	int addIceServer(const char *url, const char *username, const char *password);
	int setRemoteGatheringDone();
	int send(const char *data, std::size_t size, int ds = -1);
	stice_state_t state() const { return state_; }
	int getSelectedCandidates(char *local, std::size_t localSize, char *remote,
	                          std::size_t remoteSize) const;
	int getSelectedAddresses(char *local, std::size_t localSize, char *remote,
	                         std::size_t remoteSize) const;
	int setLocalIceAttributes(const char *ufrag, const char *pwd);
	int setIceTcpMode(stice_ice_tcp_mode_t mode);
	int addAddressRewriteRule(const stice_address_rewrite_rule_t *rule);
	int setMulticastDnsMode(stice_multicast_dns_mode_t mode);
	// Bind this agent to a shared UDPMux. Must be called before init/gather.
	// When set, the agent does not create its own UDP socket; instead it
	// sends/receives through the mux's shared socket.
	int setUDPMux(net::UDPMux *mux);
	// Bind this agent to a shared TCPMux (for ICE-TCP passive mode).
	// Must be called before gatherCandidates. When set and iceTcpMode_
	// includes PASSIVE, the agent generates a TCPPassive candidate using
	// the TCPMux's listener address and receives inbound TCP connections
	// through the mux.
	int setTCPMux(net::TCPMux *mux);
	// Set the pairing-strategy configuration. Applies on the next
	// gatherCandidates / ICE-Restart; calling it on a running session
	// only takes effect for the next restart. See pairing_strategy.hpp.
	int setPairingConfig(const IcePairingConfig &cfg);
	const IcePairingConfig &pairingConfig() const { return pairingCfg_; }

	// PollParticipant interface (called from the PollRegistry thread).
	socket_t udpSocket() const override { return sock_.valid() ? sock_.handle() : STICE_INVALID_SOCKET; }
	bool hasTcp() const override { return tcpTransport_ != nullptr; }
	socket_t tcpSocket() const override;
	short tcpDesiredEvents() const override;
	// Indexed TURN-TCP slots: one control transport per TCP/TLS relay entry
	// (base-class legacy single-slot hooks stay at their defaults).
	int turnTcpSlotCount() const override;
	socket_t turnTcpSocketAt(int i) const override;
	short turnTcpDesiredEventsAt(int i) const override;
	void onTurnTcpEventsSock(socket_t sock, short events) override;
	bool hasTurnDataTcp() const override;
	socket_t turnDataTcpSocket() const override;
	short turnDataDesiredEvents() const override;
	int64_t nextTimestampMs() const override;
	void onUdpReadable() override;
	void onTcpEvents(short events) override;
	void onTurnDataTcpEvents(short events) override;
	void onBookkeeping(int64_t nowMs) override;

	// Lock used by the PollParticipant callbacks. The agent's mutable
	// state is guarded by this mutex; the PollRegistry holds it while
	// dispatching IO events.
	std::recursive_mutex &mutex() { return mutex_; }

private:
	// Helper: send a STUN Binding request for a CHECK entry.
	void sendStunBinding(StunEntry &e, stun::Class cls, int errorCode,
	                     const std::array<unsigned char, 12> *replyTid = nullptr,
	                     const net::AddrRecord *mapped = nullptr);
	// Send a STUN Binding Indication keepalive / consent freshness request.
	void sendKeepalive(StunEntry &e);
	// Build a Binding success/error response to an incoming request.
	void sendBindingResponse(const stun::Message &req, const net::AddrRecord &dst,
	                         int errorCode);
	// Process an incoming STUN message (request / response / indication).
	// `transport` indicates the transport the message arrived on (UDP/TCP),
	// used to create peer-reflexive candidates with the correct transport type.
	void handleStunMessage(const stun::Message &msg, const net::AddrRecord &src,
	                       CandidateTransport transport = CandidateTransport::UDP);
	void handleBindingRequest(const stun::Message &msg, const net::AddrRecord &src,
	                          CandidateTransport transport = CandidateTransport::UDP);
	void handleBindingResponse(const stun::Message &msg, const net::AddrRecord &src,
	                           StunEntry &e);
	// Handle a STUN Binding success/error response for a Server (srflx) entry.
	void handleServerReflexiveResponse(const stun::Message &msg, const net::AddrRecord &src,
	                                   StunEntry &e);
	// Verify USERNAME / MESSAGE-INTEGRITY of an incoming request.
	bool verifyBindingRequest(const stun::Message &msg);
	// Find or create a candidate pair for an incoming request from `src`.
	CandidatePair *findOrCreatePair(const net::AddrRecord &src, std::uint32_t priority,
	                                CandidateTransport transport);
	// When a remote passive TCP candidate is added and active TCP is enabled,
	// create a local active TCP candidate by dialing the remote address.
	// Aligned with pion-ice addRemotePassiveTCPCandidate.
	void addRemotePassiveTcpCandidate(const Candidate &remote);
	// Establish an active TCP connection to a remote passive candidate.
	// Returns the local port used, or 0 on failure.
	bool beginActiveTcpConnect(const net::AddrRecord &remoteAddr, net::AddrRecord &localAddr);
	// Find or create a STUN entry for a pair (or nullptr).
	StunEntry *findEntry(CandidatePair *pair);
	// Arm a STUN entry's next transmission time with the given delay.
	void armTransmission(StunEntry &e, int delayMs);
	void armKeepalive(StunEntry &e);
	// Sort the candidate pairs by priority descending.
	void updateOrderedPairs();
	// Arm the next Frozen pair(s) per the active pairing-strategy schedule
	// mode (RFC8445_STRICT / SERIAL / LIMITED_CONCURRENT / PHASED_UDP_FIRST).
	void armNextFrozenPair();
	// Count currently InProgress Check entries (Pending Check type).
	std::size_t countInProgressChecks() const;
	// PHASED_UDP_FIRST: evaluate UDP-phase end and enter TCP phase.
	void maybeEnterTcpPhase();
	// Create RFC 6062 Mode-B allocations deferred from gatherCandidates.
	void createDeferredTcpRelayAllocations();
	// Re-examine state and possibly transition (CONNECTING -> CONNECTED -> COMPLETED).
	void updateState();
	void changeState(stice_state_t newState);
	// Worker-thread gathering: resolve all STUN/TURN servers' DNS in parallel
	// on a dedicated thread, then create StunEntry objects under the mutex.
	// This eliminates serial getaddrinfo blocking that stalls the poll thread.
	void gatherCandidatesWorker(std::vector<struct GatherItem> items,
	                            std::shared_ptr<LifetimeGuard> lifetime,
	                            std::shared_ptr<std::atomic<bool>> cancel,
	                            std::shared_ptr<std::atomic<bool>> done);
	// Create a STUN server-reflexive entry from a pre-resolved address.
	void createServerReflexiveEntry(const std::string &host, uint16_t port,
	                                const net::AddrRecord &resolved);
	// Create a TURN relay entry from a pre-resolved address.
	void createRelayEntry(const stice_turn_server_t &srv, int serverIndex,
	                      const net::AddrRecord &resolved);
	// Acceptance min wait: returns the delay before a candidate of the given
	// type may be nominated, measured from checking start. Aligned with
	// pion-ice isNominatable (selection.go L40-55). Relay-only mode uses 0
	// (pion-ice defaultRelayOnlyAcceptanceMinWait).
	std::chrono::milliseconds acceptanceMinWaitMs(CandidateType type) const;
	// Check if both local and remote candidates of a pair have exceeded their
	// acceptance min wait since checking started. Aligned with pion-ice
	// ContactCandidates (selection.go L76: isNominatable(Local) && isNominatable(Remote)).
	bool isNominatable(const CandidatePair *pair) const;
	// Trigger the user callbacks (state, candidate, gathering_done, recv).
	void emitCandidate(const Candidate &c);
	void emitGatheringDone();
	void emitRecv(const char *data, std::size_t size);
	void emitState(stice_state_t s);
	// Resolve a hostname:port into a list of AddrRecords.
	std::vector<net::AddrRecord> resolveServer(const std::string &host, std::uint16_t port,
	                                           int socktype);
	// Gather host candidates (enumerate local interface addresses).
	void gatherHostCandidates();
	// Gather srflx candidate (STUN binding to a single STUN server).
	void gatherServerReflexive(const char *host, uint16_t port);
	// Gather relay candidate (TURN allocate). `serverIndex` is the position
	// of this TURN server in the configuration array, used to differentiate
	// relay candidates from multiple TURN servers: earlier servers get
	// higher priority (aligned with pion-ice relay candidate ordering).
	void gatherRelay(const stice_turn_server_t &srv, int serverIndex);
	// Add a local candidate (takes ownership of nothing — local candidates
	// live in local_.candidates).
	void addLocalCandidate(Candidate c);
	// Apply address rewrite rules to a candidate. Returns the list of
	// candidates to emit (may be empty to drop the candidate, or multiple
	// for append mode). If no rules match, returns a single-element vector
	// with the original candidate.
	std::vector<Candidate> applyAddressRewrite(const Candidate &c, const std::string &localIP,
	                                            const std::string &iface);
	// Initialize the mDNS client if configured. Called from gatherCandidates.
	void initMDns();
	// Resolve a remote mDNS hostname candidate asynchronously.
	// Returns true if resolution was initiated (the candidate will be added
	// when resolution completes), false if it's not an mDNS name.
	bool resolveRemoteMDnsCandidate(const Candidate &c);
	// Add a peer-reflexive candidate learned from an incoming STUN request.
	void addPeerReflexiveCandidate(const net::AddrRecord &src, std::uint32_t priority,
	                               CandidateTransport transport);
	// Form candidate pairs from local x remote candidates.
	void formPairs();
	// Wake the poll thread so it re-evaluates timers immediately.
	void wakePoll();
	// Send application data via the selected pair (direct or via TURN).
	int sendViaSelectedPair(const char *data, std::size_t size, int ds);
	// Demultiplex inbound UDP: STUN / ChannelData / app data.
	void handleInboundUdp(const char *buf, int len, const net::AddrRecord &src,
	                      CandidateTransport transport = CandidateTransport::UDP);
	// Demultiplex inbound TCP: RFC 4571 framed STUN / app data.
	void handleInboundTcp();
	// Process a single de-framed TCP packet (from TcpMuxConn or handleInboundTcp).
	void handleInboundTcpPacket(const char *data, int len, const net::AddrRecord &src);
	// Demultiplex inbound TURN TCP: self-delimited STUN / ChannelData frames
	// parsed by StunConn, then routed to the TURN client.
	void handleInboundTurnTcp(StunEntry &entry);
	// Find the first relay entry that uses a TCP/TLS control connection (the
	// RFC 6062 machinery drives one TCP allocation at a time per agent).
	StunEntry *findTcpTurnEntry();
	const StunEntry *findTcpTurnEntry() const;
	// --- UDPMux helpers ---
	// Send a UDP packet via the agent's own socket or the shared mux socket.
	// `control=true` marks STUN connectivity signalling (ICE checks /
	// keepalives / binding responses / TURN control frames). When the socket
	// backs up (SO_SNDBUF full under a bulk-data flood), control frames are
	// queued and flushed ahead of bulk data on the next onBookkeeping pass, so
	// signalling is never dropped by application flooding on UDP transports.
	int sendUdp(const char *data, std::size_t size, const net::AddrRecord &dst,
	            bool control = false);
	// Drain the UDP control-frame queue with priority (sendUdp control=true
	// frames refused by a backed-up socket). Called from onBookkeeping.
	void flushUdpControlQueue();
	// Send a RFC 4571-framed packet over the TCP transport (if connected).
	// If the pair's local candidate is TCPPassive and a TCPMux is set,
	// routes through the TCPMux's established connection instead.
	// `control=true` sends via the control-frame queue (STUN signalling),
	// which is flushed ahead of queued bulk application data so connectivity
	// checks are never starved by an application flood.
	int sendTcp(const char *data, std::size_t size, const CandidatePair *pair = nullptr,
	            bool control = false);
	// Check if a candidate pair uses TCP transport.
	bool pairIsTcp(const CandidatePair *p) const;
	// Check if a candidate pair uses TURN TCP-relayed transport (RFC 6062).
	// Such pairs route data through turnDataConn_ instead of tcpTransport_.
	bool pairIsTurnTcpRelay(const CandidatePair *p) const;
	// Begin a TURN over TCP/TLS connection for one relay entry. Called from
	// createRelayEntry when the transport is TCP or TLS. The transport is
	// stored in the entry (per-server), so multiple TCP/TLS TURN servers
	// connect concurrently. Returns false on immediate failure.
	bool beginTurnTcpConnect(StunEntry &entry, const net::AddrRecord &turnServer,
	                         bool useTls, const std::string &sni, bool skipVerify,
	                         const std::string &caFile);
	// Called when a relay entry's TCP transport becomes connected: sends the
	// buffered Allocate request now that the control connection is ready.
	void onTurnTcpConnected(StunEntry &entry);
	// Enumerate local addresses via the agent's socket or the shared mux socket.
	std::vector<net::AddrRecord> localAddrsUdp(int family = AF_UNSPEC) const;
	// Get the bound address via the agent's socket or the shared mux socket.
	bool boundAddrUdp(net::AddrRecord &out) const;
	// Register this agent with the UDPMux (called from gatherCandidates).
	void registerWithMux();
	// Register this agent with the TCPMux (called from gatherCandidates).
	void registerWithTcpMux();
	// Called when a TURN allocation completes or fails. If all pending relay
	// allocations are done, signals gathering complete.
	void checkGatheringComplete();
	// Mark every STUN entry as Cancelled and tear down TURN allocations.
	// Called from the destructor to guarantee no timer fires after the
	// Agent's members begin destructing (the lifetime barrier only waits
	// for in-flight callbacks; entries armed for FUTURE firing must be
	// cancelled explicitly so the poll thread never re-enters the Agent).
	void cancelAllEntries();

	stice_config_t config_;
	// Pairing-strategy configuration (scheduling / nomination / TCP-relay
	// fallback / reselection). Applied at gatherCandidates / ICE-Restart.
	IcePairingConfig pairingCfg_{};
	stice_state_t state_ = STICE_STATE_DISCONNECTED;
	stice_ice_tcp_mode_t iceTcpMode_ = STICE_ICE_TCP_MODE_NONE;
	AgentMode mode_ = AgentMode::Unknown;
	std::uint64_t tiebreaker_ = 0;
	// Lifetime guard shared with all async callback lambdas. ~Agent calls
	// shutdown() to wait for in-flight callbacks before destroying members.
	std::shared_ptr<LifetimeGuard> lifetime_;
	// The owning stice_agent_t* (C API handle). Passed back to user callbacks
	// as the first argument so the user can correlate callbacks to agents.
	stice_agent_t *self_ = nullptr;
	// Internal storage for TURN servers added via add_turn_server (so we
	// own stable memory the C API config_.turn_servers can point into).
	std::vector<stice_turn_server_t> turnServersInternal_;
	// Backing storage for C strings in turnServersInternal_ (added via
	// addIceServer URL parsing or addTurnServer, which create strings
	// dynamically). MUST be std::deque: push_back never invalidates
	// references to existing elements, so the c_str() pointers stored in
	// turnServersInternal_ stay valid as more servers are added. A vector
	// reallocates on growth and left every previously-added TURN server's
	// host/username/password dangling (garbage hosts like "could not
	// resolve <mojibake>" when 2+ servers were registered).
	std::deque<std::string> turnServerHostStorage_;
	std::deque<std::string> turnServerUserStorage_;
	std::deque<std::string> turnServerPassStorage_;
	// Backing storage for stice_turn_server_t::ca_file (same deque rationale:
	// the pointer stays valid while more servers are registered).
	std::deque<std::string> turnServerCaStorage_;
	// Internal storage for STUN servers added via add_stun_server or
	// config_.stun_servers. Each entry is a host:port pair. All are
	// queried concurrently during gatherServerReflexive.
	struct StunServerEntry { std::string host; uint16_t port; };
	std::vector<StunServerEntry> stunServersInternal_;
	// TCP-transport TURN servers (RFC 6062) deferred from gatherCandidates
	// when tcp_relay_fallback == ON_ALL_UDP_FAIL. Created lazily when the
	// UDP phase ends. Owns stable memory for stice_turn_server_t.host etc.
	std::vector<stice_turn_server_t> deferredTcpTurnServers_;
	// Original configuration-array index for each deferred TCP TURN server,
	// used for relay candidate priority differentiation.
	std::vector<int> deferredTcpTurnIndices_;
	// Backing storage for the C strings in deferredTcpTurnServers_.
	std::vector<std::string> deferredTcpTurnHostStorage_;
	std::vector<std::string> deferredTcpTurnUserStorage_;
	std::vector<std::string> deferredTcpTurnPassStorage_;

	mutable std::recursive_mutex mutex_;
	net::UdpSocket sock_;
	// Diagnostic: local UDP bound port (set after socket bind) so log lines
	// identify which peer (A/B) is acting. 0 until bound.
	std::uint16_t diagLocalPort_ = 0;
	// Optional shared UDP mux. When non-null, the agent sends/receives through
	// the mux's shared socket instead of its own sock_.
	net::UDPMux *mux_ = nullptr;
	bool muxRegistered_ = false;
	// Optional shared TCP mux for ICE-TCP passive mode.
	net::TCPMux *tcpMux_ = nullptr;
	bool tcpMuxRegistered_ = false;
	std::unique_ptr<net::TcpTransport> tcpTransport_;
	net::AddrRecord tcpPeerAddr_;
	std::string tcpSni_;
	// RFC 6062 TCP allocation data connection. Separate TCP connection to the
	// TURN server, bound via CONNECTION-BIND. After binding, raw application
	// data (STUN checks + app data) flows end-to-end through the TURN server.
	// One at a time is sufficient for ICE (one selected pair).
	struct TurnDataConn {
		std::uint32_t connectionId = 0;
		net::AddrRecord peer;
		std::unique_ptr<net::TcpTransport> transport;
		turn::StunConn stunConn;
		bool bound = false;      // CONNECTION-BIND succeeded
		bool connecting = false;  // TCP connect in progress
		bool connectionBindSent = false;
		// RFC 4571 frame buffer for data after CONNECTION-BIND (the tunnel
		// is transparent, so we frame STUN + app data with 2-byte prefix).
		std::vector<unsigned char> rfc4571Buf;
	};
	std::unique_ptr<TurnDataConn> turnDataConn_;
	// Begin opening a data connection to the TURN server for RFC 6062.
	// After connect, sends CONNECTION-BIND with the given connectionId.
	void beginTurnDataConnect(std::uint32_t connectionId, const net::AddrRecord &peer);
	void sendTurnDataConnectionBind();
	void handleInboundTurnDataTcp();
	// Send data through the TURN data connection with RFC 4571 framing.
	int sendTurnDataConn(const char *data, std::size_t size);
	// RFC 6062: deterministically decide which side sends CONNECT based on
	// ufrag comparison. Both agents compute the same result (one true, one
	// false), so only one side initiates CONNECT. This avoids both sides
	// sending CONNECT simultaneously before ICE role conflict resolution
	// (487) can occur, which would cause the TURN server to reject one.
	// Falls back to mode_==Controlling when remote ufrag is unavailable.
	//
	// INTEROP CAVEAT - NON-STANDARD CONNECT. RFC 6062 / RFC 6544 do not define
	// a ufrag comparison: there, the candidate roles (active dials, passive
	// listens) decide who sends CONNECT, and the server itself may dial the
	// peer. The rule below is stice's own convention (mirrored from libjuice),
	// so this TCP-relay link is only known to interoperate with peers that
	// implement the same rule, i.e. stice <-> stice and stice <-> libjuice.
	// Against a generic RFC 6062 implementation either both sides send CONNECT
	// (one is rejected) or neither does, and the relayed TCP pair never comes
	// up. Do not treat this path as a general RFC 6062 client.
	bool shouldInitiateTcpConnect() const;

	// RFC 6062 CONNECT retry state. The TURN server may return 447 (Connection
	// Timeout or Failure) if the peer's relay listener isn't fully ready when
	// the CONNECT is processed. We retry up to MaxConnectRetries times with
	// ConnectRetryDelayMs between attempts, so the retry budget spans
	// MaxConnectRetries * ConnectRetryDelayMs = 20 s.
	//
	// The delay used to be 500 ms, i.e. a 1.5 s total window - far too short:
	// before a CONNECT can succeed the peer must finish its own TCP allocation,
	// CREATE_PERMISSION and CONNECTION-ATTEMPT handling, which under load takes
	// longer than 1.5 s, so the first 447 was already terminal and the relay pair
	// failed although the peer became ready moments later.
	//
	// The spacing is now >= 10 s as RFC 6062 §4.3 requires of the client's retry
	// pacing. An interval below 10 s (a 5 s x 3 compromise) was rejected: the
	// RFC's floor governs how fast a client may re-issue CONNECT, and compliance
	// wins over the small latency saving there. MaxConnectRetries is reduced 3 -> 2
	// so the worst-case wait before a genuinely dead pair is detected stays close
	// to the previous budget (20 s vs 15 s) and does not fight the profile's
	// fast-failure tuning (tight RTO / max_check_retransmit).
	static constexpr int MaxConnectRetries = 2;
	static constexpr int ConnectRetryDelayMs = 10000;
	int connectRetries_ = 0;
	net::AddrRecord pendingConnectPeer_;
	bool pendingConnectRetry_ = false;
	std::chrono::steady_clock::time_point nextConnectRetry_{};
	// Tracks whether the initial RFC 6062 CONNECT has been sent for the
	// current TCP allocation. If the allocation was still pending when
	// formPairs() ran, the CONNECT is (re)triggered from onBookkeeping
	// once the allocation transitions to Allocated. Reset to false when
	// a new TCP allocation begins or after the data connection is bound.
	bool tcpConnectSent_ = false;
	// pion-mode: defer the RFC 6062 CONNECT until the local CreatePermission
	// for the peer has completed (turn::hasPermission). Mirrors pion's
	// createPermission-before-Connect so the TURN server has the permission
	// it needs to forward CONNECTION-ATTEMPT (RFC 6062 §4.4), eliminating the
	// race where coturn returns CONNECT success but never forwards ATTEMPT
	// because the permission wasn't installed yet.
	bool pendingConnectWaitPerm_ = false;

	// RFC 6062 data-connection (CONNECTION-BIND) retry state. The TURN server
	// may close the data TCP connection before CONNECTION-BIND completes if
	// the peer's CREATE_PERMISSION has not been processed yet (coturn:
	// "tcp_peer_accept_connection: peer has no permission to connect"). This
	// is a transient ordering race; retrying the data connect a few times with
	// a short delay lets the permission propagate and the bind succeed.
	static constexpr int MaxTurnDataConnectRetries = 4;
	static constexpr int TurnDataRetryDelayMs = 300;
	int turnDataRetryCount_ = 0;
	bool pendingTurnDataRetry_ = false;
	std::chrono::steady_clock::time_point nextTurnDataRetry_{};
	std::uint32_t turnDataRetryConnId_ = 0;
	net::AddrRecord turnDataRetryPeer_;

	// NAT 1:1 IP address rewrite mapper.
	std::unique_ptr<AddressRewriteMapper> addrRewrite_;
	std::vector<AddressRewriteRule> pendingRewriteRules_;

	// mDNS client.
	std::unique_ptr<net::MDnsClient> mdns_;
	stice_multicast_dns_mode_t mdnsMode_ = STICE_MDNS_MODE_DISABLED;
	std::string mdnsHostname_;
	bool mdnsInitialized_ = false;

	Description local_;
	Description remote_;
	bool gatheringDone_ = false;
	std::chrono::steady_clock::time_point gatherStartedAt_{}; // soft gathering deadline
	bool remoteGatheringDone_ = false;
	int pendingRelayAllocations_ = 0;
	int pendingServerReflexive_ = 0;

	std::deque<StunEntry> entries_;
	std::vector<std::unique_ptr<CandidatePair>> pairs_;
	std::vector<CandidatePair *> orderedPairs_;
	CandidatePair *selectedPair_ = nullptr;
	CandidatePair *nominatedPair_ = nullptr;
	// Re-nomination counter (draft-thatcher-ice-renomination). Increments each
	// time the controlling agent switches to a higher-priority pair.
	std::uint32_t nominationValue_ = 0;

	std::chrono::steady_clock::time_point pacTimestamp_{};
	std::chrono::steady_clock::time_point nominationTimestamp_{};
	std::chrono::steady_clock::time_point nextTick_{};
	// UDP control-frame queue: control frames refused by a backed-up socket are
	// held here and drained by flushUdpControlQueue() on the poll loop ahead of
	// bulk data, so ICE/TURN signalling is not dropped under a data flood.
	// Guarded by udpCtrlMutex_ (control-frame send sites include the gather
	// worker, which runs off-thread).
	std::deque<std::pair<net::AddrRecord, std::vector<unsigned char>>> udpCtrlQueue_;
	std::mutex udpCtrlMutex_;
	// Serializes outbound socket writes that happen OUTSIDE the main mutex_
	// (Agent::send fast paths). Mirrors libjuice send_mutex: the app send
	// loop runs concurrently with the poll thread, so sendto / relayTurnTcp
	// writes must not race a socket close/rebuild. Writes stay inside the
	// ICE lock only for the snapshot; the actual socket write takes sendMutex_.
	std::mutex sendMutex_;

	// Time when the agent entered CONNECTING (checking started). Used for
	// acceptance min wait calculation, aligned with pion-ice selector.startTime.
	std::chrono::steady_clock::time_point checkingStartTime_{};
	// True when no host/srflx local candidates exist (relay-only mode).
	// In this mode, relay acceptance min wait is 0 (pion-ice
	// defaultRelayOnlyAcceptanceMinWait).
	bool relayOnlyMode_ = false;
	// Last time application data was sent or received. Used to detect idle
	// sessions and stretch the consent freshness interval (P1-2).
	std::chrono::steady_clock::time_point lastAppDataAt_{};
	// RFC 8863 (Patiently Awaiting Connectivity): deadline until which the agent
	// must NOT transition Running -> Failed even though every pair has already
	// failed. Zero means "no PAC wait in progress". Armed the first time the
	// checklist is found fully failed while CONNECTING, cleared as soon as any
	// pair is no longer Failed (connectivity is being attempted again) and once
	// the transition happens. Exposed through nextTimestampMs() so the poll
	// thread wakes exactly at the deadline.
	std::chrono::steady_clock::time_point pacDeadline_{};

	// Worker thread for parallel candidate gathering. Resolves all STUN/TURN
	// server DNS in parallel, then creates entries under the mutex. Stopped in
	// ~Agent with a BOUNDED wait (see gatherCancel_/gatherWorkerDone_) and at
	// restart. An unbounded join here used to hang stice_destroy whenever the
	// worker got stuck.
	std::thread gatherWorker_;
	// Cancellation / completion flags handed to the gather worker BY VALUE.
	// shared_ptr so the worker can safely read and set them even if it outlives
	// a bounded-join teardown - the Agent's raw `this` must not be dereferenced
	// once the worker has been asked to stop.
	std::shared_ptr<std::atomic<bool>> gatherCancel_ =
		std::make_shared<std::atomic<bool>>(false);
	std::shared_ptr<std::atomic<bool>> gatherWorkerDone_ =
		std::make_shared<std::atomic<bool>>(false);

	// Per-agent PollRegistry instance (per-agent independent thread model).
	// Each Agent owns its own PollRegistry + background thread, aligned with
	// libjuice's conn_thread.c model. Acquired in init() (or setUDPMux /
	// setTCPMux when transitioning to mux mode), released in ~Agent.
	net::PollRegistry *pollReg_ = nullptr;
};

// Item queued for parallel DNS resolution during gatherCandidates.
struct GatherItem {
	enum class Type { Stun, TurnUdp, TurnTcp } type = Type::Stun;
	std::string host;
	uint16_t port = 3478;
	int turnIndex = 0;             // config array index for TURN servers
	stice_turn_server_t turnSrv{}; // copy of TURN server config
};

} // namespace stice::ice

#endif
