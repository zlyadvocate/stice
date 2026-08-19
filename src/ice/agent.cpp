/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
#include "stice/ice/agent.hpp"
#include "stice/stun/attributes.hpp"
#include "stice/stun/client.hpp"
#include "stice/turn/channeldata.hpp"
#include "stice/turn/stunconn.hpp"

#include "stice/log.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <future>
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace stice::ice {

namespace {
std::string tidKey(const std::array<unsigned char, 12> &tid) {
	return std::string(reinterpret_cast<const char *>(tid.data()), 12);
}

int64_t toMs(std::chrono::steady_clock::time_point tp) {
	return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}
} // namespace

Agent::Agent() {
	tiebreaker_ = crypto::randomU64();
	lifetime_ = std::make_shared<LifetimeGuard>();
	// Library default = RFC8445_COMPAT to preserve backward compatibility
	// (pion-ice creates all TURN allocations eagerly, including RFC 6062
	// Mode-B). The IcePairingConfig struct defaults match EMBEDDED_STABLE
	// per the strategy spec, but the Agent itself must not change behavior
	// for existing callers who never invoke setPairingConfig. Products that
	// want the EMBEDDED_STABLE profile must opt in explicitly before
	// gatherCandidates.
	pairingCfg_ = makeIcePairingConfig(IcePairingProfile::RFC8445_COMPAT);
}

Agent::~Agent() {
	// Join the gather worker thread before touching any members. The worker
	// may be mid-DNS-resolution (no mutex held) when ~Agent runs; joining
	// ensures it completes before members are destroyed.
	if (gatherWorker_.joinable()) gatherWorker_.join();
	cancelAllEntries();
	if (lifetime_) lifetime_->shutdown();
	if (mux_) {
		if (muxRegistered_) {
			mux_->removeAgent(local_.iceUfrag);
		}
	}
	if (tcpMux_) {
		if (tcpMuxRegistered_) {
			tcpMux_->removeAgent(local_.iceUfrag);
		}
	}
	// Per-agent PollRegistry: remove self, sync to ensure the poll thread
	// is not holding a raw pointer to this Agent, then release (delete)
	// the instance which joins the background thread.
	if (pollReg_) {
		pollReg_->remove(this);
		pollReg_->sync();
		pollReg_->release();
		pollReg_ = nullptr;
	}
}

void Agent::cancelAllEntries() {
	// Acquire the mutex: the poll thread may be mid-callback (onBookkeeping)
	// and we must not race on entries_/tcpTransport_ while cancelling.
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	// Cancel every STUN entry so the bookkeeping loop will never fire it
	// again. StunEntryState::Cancelled entries are skipped by onBookkeeping.
	for (auto &e : entries_) {
		e.state = StunEntryState::Cancelled;
	}
	// Tear down TURN allocations: send Refresh(LIFETIME=0) to release the
	// relayed address on the server immediately (RFC 8656 §7). This runs
	// BEFORE the lifetime barrier so the sendRaw callback (which checks
	// lifetime_->alive) still succeeds and the transport is still open.
	for (auto &e : entries_) {
		if (e.type == StunEntryType::Relay && e.turn &&
		    e.turn->state() == turn::AllocState::Allocated) {
			STICE_LOG_INFO("Agent destroy: deallocating TURN relay (Refresh LIFETIME=0)");
			e.turn->deallocate();
		}
	}
	// Close TCP transports so their poll registrations stop firing.
	tcpTransport_.reset();
	turnTcpTransport_.reset();
}

bool Agent::init(const stice_config_t *cfg, stice_agent_t *self) {
	config_ = *cfg;
	self_ = self;
	// Apply runtime TCP priority offset override (P2-1). A non-zero
	// config value overrides the global default; 0 leaves the global
	// (which itself defaults to TcpPenalty=27).
	if (config_.tcp_priority_offset)
		g_tcpPriorityOffset.store(config_.tcp_priority_offset, std::memory_order_release);
	// Load multi-STUN-server array from config into internal storage.
	// When stun_servers is non-NULL, it takes precedence over the legacy
	// single stun_server_host/stun_server_port fields.
	if (config_.stun_servers && config_.stun_servers_count > 0) {
		for (int i = 0; i < config_.stun_servers_count; ++i) {
			if (config_.stun_servers[i]) {
				uint16_t p = config_.stun_server_ports
				                 ? config_.stun_server_ports[i]
				                 : (config_.stun_server_port ? config_.stun_server_port : 3478);
				stunServersInternal_.push_back({std::string(config_.stun_servers[i]),
				                               p ? p : static_cast<uint16_t>(3478)});
			}
		}
	} else if (config_.stun_server_host) {
		// Copy the legacy single STUN server into internal storage so we
		// own the string. The config_.stun_server_host pointer is borrowed
		// from the caller and may become dangling after init() returns.
		uint16_t p = config_.stun_server_port ? config_.stun_server_port : 3478;
		stunServersInternal_.push_back({std::string(config_.stun_server_host),
		                               p ? p : static_cast<uint16_t>(3478)});
		config_.stun_server_host = nullptr; // prevent use-after-free in gatherCandidatesInternal
	}
	// Generate local ufrag/pwd unless caller overrides via set_local_ice_attributes.
	local_.iceUfrag = generateUfrag();
	local_.icePwd = generatePwd();

	// Reserve capacity so candidate pointers stored in CandidatePair remain
	// stable. Without this, vector reallocation on push_back would invalidate
	// the raw `local`/`remote` pointers held by existing pairs, causing
	// use-after-free crashes when new candidates arrive after pairs are formed.
	local_.candidates.reserve(MaxCandidates);
	remote_.candidates.reserve(MaxCandidates);
	// Reserve entries_ so turnTcpEntry_ / relayEntry_ raw pointers stay valid
	// after subsequent push_back calls (formPairs, peer-reflexive, etc.).
	entries_.reserve(MaxStunEntries);

	// In UDPMux mode, the agent does not create its own socket. The mux
	// owns the shared socket and registers with the PollRegistry.
	if (mux_) return true;

	// Create the UDP socket.
	net::UdpSocketConfig sc;
	sc.bindAddress = cfg->bind_address ? cfg->bind_address : "";
	sc.portBegin = cfg->local_port_range_begin;
	sc.portEnd = cfg->local_port_range_end;
	sock_ = net::UdpSocket::create(sc);
	if (!sock_.valid()) {
		STICE_LOG_ERROR("Agent: failed to create UDP socket");
		state_ = STICE_STATE_FAILED;
		return false;
	}

	// Register with this Agent's own PollRegistry (per-agent thread model).
	pollReg_ = net::PollRegistry::acquire();
	pollReg_->add(this);
	return true;
}

int Agent::setUDPMux(net::UDPMux *mux) {
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	if (state_ != STICE_STATE_DISCONNECTED && state_ != STICE_STATE_FAILED) {
		return STICE_ERR_FAILED;
	}
	if (!mux) return STICE_ERR_INVALID;
	// If the agent already created its own socket (from init()), close it
	// and tear down its own PollRegistry. The mux owns the shared socket
	// and its own PollRegistry from now on.
	if (sock_.valid()) {
		if (pollReg_) {
			pollReg_->remove(this);
			pollReg_->release();
			pollReg_ = nullptr;
		}
		sock_.close();
	}
	mux_ = mux;
	return STICE_ERR_SUCCESS;
}

int Agent::setTCPMux(net::TCPMux *mux) {
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	if (state_ != STICE_STATE_DISCONNECTED && state_ != STICE_STATE_FAILED) {
		return STICE_ERR_FAILED;
	}
	if (!mux) return STICE_ERR_INVALID;
	tcpMux_ = mux;
	STICE_LOG_INFO("Agent: TCPMux set (iceTcpMode=%d)", static_cast<int>(iceTcpMode_));
	return STICE_ERR_SUCCESS;
}

int Agent::setPairingConfig(const IcePairingConfig &cfg) {
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	// Strategy applies on next gather / restart. Allow setting even when
	// running so the next restart picks it up; current session keeps its
	// already-applied scheduling state.
	pairingCfg_ = cfg;
	// Reset phase-tracking state so a fresh gather starts in the UDP phase.
	pairingCfg_.tcp_phase_entered = false;
	pairingCfg_.tcp_relay_allocation_created = false;
	pairingCfg_.udp_phase_start = std::chrono::steady_clock::time_point{};
	pairingCfg_.checking_start = std::chrono::steady_clock::time_point{};
	pairingCfg_.early_phase_active = false;
	STICE_LOG_INFO("Agent: pairing config set (schedule=%d nominate=%d tcp_fallback=%d reselect=%d "
	               "pre_alloc_tcp=%d early_conc=%d early_ms=%lld)",
	               static_cast<int>(cfg.schedule_mode), static_cast<int>(cfg.nomination_mode),
	               static_cast<int>(cfg.tcp_relay_fallback), static_cast<int>(cfg.reselect_policy),
	               static_cast<int>(cfg.pre_allocate_tcp_relay),
	               static_cast<int>(cfg.early_phase_max_concurrent),
	               static_cast<long long>(cfg.early_phase_duration.count()));
	return STICE_ERR_SUCCESS;
}

socket_t Agent::tcpSocket() const {
	return tcpTransport_ ? tcpTransport_->handle() : STICE_INVALID_SOCKET;
}

short Agent::tcpDesiredEvents() const {
	if (!tcpTransport_) return 0;
	short ev = POLLIN;
	if (tcpTransport_->wantsWrite()) ev |= POLLOUT;
	return ev;
}

socket_t Agent::turnTcpSocket() const {
	return turnTcpTransport_ ? turnTcpTransport_->handle() : STICE_INVALID_SOCKET;
}

short Agent::turnTcpDesiredEvents() const {
	if (!turnTcpTransport_) return 0;
	short ev = POLLIN;
	if (turnTcpTransport_->wantsWrite()) ev |= POLLOUT;
	return ev;
}

int64_t Agent::nextTimestampMs() const {
	// Return the ABSOLUTE timestamp (ms since steady_clock epoch) of the
	// earliest pending entry's next transmission. The PollRegistry computes
	// (nextTimestampMs - nowMs) to derive the poll timeout, so we MUST return
	// an absolute value here, not a relative delta. Returning a relative delta
	// would make (delta - nowMs) hugely negative, clamping the timeout to 0
	// and causing the poll loop to spin at 100% CPU without advancing real
	// time toward nextTransmission.
	auto t = std::chrono::steady_clock::time_point::max();
	bool hasPending = false;
	for (const auto &e : entries_) {
		if (e.state == StunEntryState::Pending || e.state == StunEntryState::SucceededKeepalive ||
		    (e.type == StunEntryType::Relay && e.state == StunEntryState::Idle)) {
			hasPending = true;
			if (e.nextTransmission < t) t = e.nextTransmission;
		}
	}
	// Account for pending CONNECT retry timer (RFC 6062).
	if (pendingConnectRetry_ && nextConnectRetry_ < t) {
		hasPending = true;
		t = nextConnectRetry_;
	}
	if (!hasPending) return 0; // 0 = no pending timer (per PollParticipant contract)
	return toMs(t);            // absolute; if <= nowMs, computeTimeoutMs clamps to 0
}

void Agent::changeState(stice_state_t newState) {
	if (state_ == newState) return;
	state_ = newState;
	// Record checking start time for acceptance min wait calculation.
	// Aligned with pion-ice controllingSelector.Start() (selection.go L35-38).
	if (newState == STICE_STATE_CONNECTING) {
		checkingStartTime_ = std::chrono::steady_clock::now();
		// Initialize early-phase speed-optimization window. The early
		// phase allows a higher temporary concurrency for the first
		// early_phase_duration of checking, then falls back to
		// max_concurrent_check to suppress STUN storms on embedded CPUs.
		pairingCfg_.checking_start = checkingStartTime_;
		pairingCfg_.early_phase_active =
		    pairingCfg_.early_phase_max_concurrent > 0 &&
		    pairingCfg_.early_phase_duration.count() > 0;
		// Detect relay-only mode: if no host/srflx local candidates exist,
		// relay acceptance min wait is 0 (pion-ice defaultRelayOnlyAcceptanceMinWait).
		relayOnlyMode_ = true;
		for (const auto &c : local_.candidates) {
			if (c.type == CandidateType::Host || c.type == CandidateType::ServerReflexive) {
				relayOnlyMode_ = false;
				break;
			}
		}
	}
	emitState(newState);
}

// True if the pair's local candidate is a TCP-relay (RFC 6062 passive).
// Used by PHASED_UDP_FIRST to defer TCP-relay checks until the UDP phase
// expires or all UDP pairs have failed, and by REGULAR_STABLE_CHECK /
// STICKY_SELECTED to apply TCP-relay-specific nomination/reselection rules.
static bool pairIsTcpRelay(const CandidatePair *p) {
	if (!p || !p->local) return false;
	return p->local->transport == CandidateTransport::TCPPassive &&
	       p->local->type == CandidateType::Relayed;
}

std::chrono::milliseconds Agent::acceptanceMinWaitMs(CandidateType type) const {
	switch (type) {
	case CandidateType::Host:
		return std::chrono::milliseconds(NominationDelayHostMs);
	case CandidateType::ServerReflexive:
		return std::chrono::milliseconds(NominationDelaySrflxMs);
	case CandidateType::PeerReflexive:
		return std::chrono::milliseconds(NominationDelayPrflxMs);
	case CandidateType::Relayed:
		// Relay-only mode: skip the relay acceptance wait (pion-ice
		// defaultRelayOnlyAcceptanceMinWait = 0).
		if (relayOnlyMode_) return std::chrono::milliseconds(0);
		return std::chrono::milliseconds(NominationDelayRelayMs);
	default:
		return std::chrono::milliseconds(NominationTimeoutMs);
	}
}

bool Agent::isNominatable(const CandidatePair *pair) const {
	if (!pair || !pair->local || !pair->remote) return false;
	// Aligned with pion-ice ContactCandidates (selection.go L76):
	// isNominatable(Local) && isNominatable(Remote).
	// Both local and remote candidate types must have exceeded their
	// acceptance min wait, measured from checking start time.
	auto now = std::chrono::steady_clock::now();
	auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
		now - checkingStartTime_);
	auto localWait = acceptanceMinWaitMs(pair->local->type);
	auto remoteWait = acceptanceMinWaitMs(pair->remote->type);
	return elapsed >= localWait && elapsed >= remoteWait;
}

void Agent::emitState(stice_state_t s) {
	if (config_.cb_state_changed) config_.cb_state_changed(self_, s, config_.user_ptr);
}

void Agent::emitCandidate(const Candidate &c) {
	if (!config_.cb_candidate) return;
	std::string sdp = c.toSdp();
	config_.cb_candidate(self_, sdp.c_str(), config_.user_ptr);
}

void Agent::emitGatheringDone() {
	if (config_.cb_gathering_done) config_.cb_gathering_done(self_, config_.user_ptr);
}

void Agent::emitRecv(const char *data, std::size_t size) {
	lastAppDataAt_ = std::chrono::steady_clock::now();
	if (config_.cb_recv) config_.cb_recv(self_, data, size, config_.user_ptr);
}

std::vector<net::AddrRecord> Agent::resolveServer(const std::string &host, std::uint16_t port,
                                                  int socktype) {
	std::vector<net::AddrRecord> out;
	// Try numeric parse first.
	net::AddrRecord rec;
	if (net::parseAddr(host, port, rec.addr, rec.len)) {
		rec.socktype = socktype;
		out.push_back(rec);
		return out;
	}
	// Otherwise resolve via getaddrinfo.
	auto records = net::resolve(host, std::to_string(port), socktype);
	for (auto &r : records) out.push_back(std::move(r));
	return out;
}

void Agent::addLocalCandidate(Candidate c) {
	if (local_.candidates.size() >= MaxCandidates) return;
	local_.candidates.push_back(std::move(c));
	local_.sortCandidates();
}

void Agent::gatherHostCandidates() {
	auto addrs = localAddrsUdp(AF_UNSPEC);

	// Apply interface IP whitelist/blacklist filtering (pion #779).
	// Whitelist takes precedence: if set, only listed IPs are kept.
	if (config_.interface_whitelist || config_.interface_blacklist) {
		std::vector<net::AddrRecord> filtered;
		filtered.reserve(addrs.size());
		for (const auto &a : addrs) {
			char host[NI_MAXHOST];
			auto *sa = reinterpret_cast<const sockaddr *>(&a.addr);
			if (getnameinfo(sa, net::addrLen(sa), host, sizeof(host), nullptr, 0,
			                NI_NUMERICHOST) != 0)
				continue;
			std::string ip(host);
			bool allowed = true;
			if (config_.interface_whitelist) {
				allowed = false;
				for (auto p = config_.interface_whitelist; *p; ++p) {
					if (ip == *p) {
						allowed = true;
						break;
					}
				}
				if (!allowed)
					STICE_LOG_DEBUG("gatherHostCandidates: %s not in whitelist, skipping", ip.c_str());
			}
			if (allowed && config_.interface_blacklist) {
				for (auto p = config_.interface_blacklist; *p; ++p) {
					if (ip == *p) {
						allowed = false;
						STICE_LOG_DEBUG("gatherHostCandidates: %s in blacklist, skipping", ip.c_str());
						break;
					}
				}
			}
			if (allowed) filtered.push_back(a);
		}
		addrs = std::move(filtered);
	}

	int idx = 0;
	for (const auto &a : addrs) {
		Candidate c;
		c.type = CandidateType::Host;
		c.transport = CandidateTransport::UDP;
		c.component = 1;
		c.resolved = a;
		c.hostname = a.toString(); // "host:port"
		// Extract host and port separately.
		auto *sa = reinterpret_cast<const sockaddr *>(&a.addr);
		char host[NI_MAXHOST];
		char serv[NI_MAXSERV];
		if (getnameinfo(sa, net::addrLen(sa), host, sizeof(host), serv, sizeof(serv),
		                NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
			c.hostname = host;
			c.service = serv;
		}
		c.priority = c.computePriority(idx++);
		c.foundation = Candidate::computeFoundation(c.type, c.hostname, c.transport);

		// Apply address rewrite (NAT 1:1 IP mapping).
		auto candidates = applyAddressRewrite(c, c.hostname, "");
		for (auto &cc : candidates) {
			// In QueryAndGather mode, replace the hostname with the mDNS name.
			if (mdnsMode_ == STICE_MDNS_MODE_QUERY_AND_GATHER && !mdnsHostname_.empty()) {
				cc.hostname = mdnsHostname_;
			}
			addLocalCandidate(cc);
			emitCandidate(cc);
		}
	}

	// Gather TCP passive host candidates if a TCPMux is configured and
	// iceTcpMode_ includes PASSIVE. The candidate address is the TCPMux's
	// listener address/port, enumerated over local interfaces (mirrors
	// pion-ice's TCPMuxAddr).
	if (tcpMux_ && (iceTcpMode_ == STICE_ICE_TCP_MODE_PASSIVE ||
	                iceTcpMode_ == STICE_ICE_TCP_MODE_SO)) {
		auto tcpAddrs = tcpMux_->localAddrs(AF_UNSPEC);
		int tcpIdx = 0;
		for (const auto &a : tcpAddrs) {
			Candidate c;
			c.type = CandidateType::Host;
			c.transport = CandidateTransport::TCPPassive;
			c.component = 1;
			c.resolved = a;
			auto *sa = reinterpret_cast<const sockaddr *>(&a.addr);
			char host[NI_MAXHOST];
			char serv[NI_MAXSERV];
			if (getnameinfo(sa, net::addrLen(sa), host, sizeof(host), serv, sizeof(serv),
			                NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
				c.hostname = host;
				c.service = serv;
			} else {
				c.hostname = a.toString();
			}
			c.priority = c.computePriority(tcpIdx++);
			c.foundation = Candidate::computeFoundation(c.type, c.hostname, c.transport);
			addLocalCandidate(c);
			emitCandidate(c);
			STICE_LOG_INFO("Agent: gathered TCP passive candidate %s:%s (priority=%u)",
			               c.hostname.c_str(), c.service.c_str(), c.priority);
		}
	}
}

void Agent::gatherServerReflexive(const char *host, uint16_t port) {
	if (!host) return;
	std::uint16_t stunPort = port ? port : 3478;
	auto servers = resolveServer(host, stunPort, SOCK_DGRAM);
	if (servers.empty()) {
		STICE_LOG_WARN("Agent: could not resolve STUN server %s", host);
		return;
	}
	createServerReflexiveEntry(host, stunPort, servers[0]);
}

void Agent::createServerReflexiveEntry(const std::string &host, uint16_t port,
                                       const net::AddrRecord &resolved) {
	if (entries_.size() >= MaxStunEntries) return;

	// Asynchronous STUN gathering: create a Server-type StunEntry, send a
	// Binding request, and let the PollRegistry deliver the response. This
	// avoids the race condition where the blocking sendBindingRequest and
	// the PollRegistry thread both call WSAPoll on the same socket (on
	// Windows, WSAPoll only notifies one of the two waiters).
	StunEntry e;
	e.type = StunEntryType::Server;
	e.state = StunEntryState::Pending;
	e.record = resolved;

	stun::Message m = stun::buildBindingRequest();
	e.transactionID = m.transactionID;
	// Encode with FINGERPRINT (no auth → no MESSAGE-INTEGRITY). The
	// FINGERPRINT calculation now matches RFC 5389 / pion-stun.
	if (!m.encode(nullptr, nullptr, "stice")) {
		STICE_LOG_WARN("Agent: STUN binding request encode failed");
		return;
	}
	int sent = sendUdp(reinterpret_cast<const char *>(m.raw.data()), m.raw.size(), resolved);
	if (sent < 0) {
		STICE_LOG_WARN("Agent: STUN binding request sendto failed, errno=%d", sticeSockerrno);
		return;
	}
	STICE_LOG_DEBUG("STUN binding request sent to %s (tid=%02x%02x%02x%02x)",
	                resolved.toString().c_str(),
	                e.transactionID[0], e.transactionID[1], e.transactionID[2], e.transactionID[3]);

	e.nextTransmission = std::chrono::steady_clock::now() + e.retransmissionTimeout;
	++pendingServerReflexive_;
	entries_.push_back(std::move(e));
	wakePoll();
	(void)host; (void)port; // used for logging only
}

void Agent::gatherRelay(const stice_turn_server_t &srv, int serverIndex) {
	if (!srv.host) return;
	std::uint16_t port = srv.port ? srv.port : 3478;
	bool useTcp = (srv.transport == STICE_TURN_TRANSPORT_TCP ||
	               srv.transport == STICE_TURN_TRANSPORT_TLS);
	int socktype = useTcp ? SOCK_STREAM : SOCK_DGRAM;
	auto servers = resolveServer(srv.host, port, socktype);
	if (servers.empty()) {
		STICE_LOG_WARN("TURN: could not resolve TURN server %s:%u", srv.host, port);
		return;
	}
	createRelayEntry(srv, serverIndex, servers[0]);
}

void Agent::createRelayEntry(const stice_turn_server_t &srv, int serverIndex,
                             const net::AddrRecord &resolved) {
	std::uint16_t port = srv.port ? srv.port : 3478;
	bool useTcp = (srv.transport == STICE_TURN_TRANSPORT_TCP ||
	               srv.transport == STICE_TURN_TRANSPORT_TLS);
	const char *transportName = useTcp
	                                ? (srv.transport == STICE_TURN_TRANSPORT_TLS ? "TLS" : "TCP")
	                                : "UDP";
	STICE_LOG_INFO("TURN: creating relay entry via %s transport, server=%s:%u user=%s",
	               transportName, srv.host, port, srv.username ? srv.username : "");
	// Allocate a STUN entry for the TURN client.
	if (entries_.size() >= MaxStunEntries) return;
	StunEntry e;
	e.type = StunEntryType::Relay;
	e.state = StunEntryState::Idle;
	e.record = resolved;
	e.turn = std::make_unique<turn::Client>();
	turn::TurnConfig tc;
	tc.serverHost = srv.host;
	tc.serverPort = port;
	tc.username = srv.username ? srv.username : "";
	tc.password = srv.password ? srv.password : "";
	tc.transport = turn::TurnTransport::UDP;
	if (srv.transport == STICE_TURN_TRANSPORT_TCP) tc.transport = turn::TurnTransport::TCP;
	else if (srv.transport == STICE_TURN_TRANSPORT_TLS) {
		tc.transport = turn::TurnTransport::TLS;
		tc.sni = srv.host;
	}
	turn::TurnSink sink;
	net::AddrRecord turnServerAddr = resolved;
	auto lifetime = lifetime_;
	sink.sendRaw = [lifetime, this, turnServerAddr, useTcp](const unsigned char *data, std::size_t size) {
		LifetimeScope ls(lifetime);
		if (!ls) return;
		// Route the raw STUN/ChannelData frame to the TURN server. For
		// TCP/TLS, use the dedicated turnTcpTransport_ (Raw framing); for
		// UDP, send through the agent's UDP socket (or shared mux).
		int ret = -1;
		if (useTcp) {
			if (turnTcpTransport_ && turnTcpTransport_->state() == net::TcpState::Connected) {
				turnTcpTransport_->send(reinterpret_cast<const char *>(data), size);
				ret = static_cast<int>(size);
			} else {
				STICE_LOG_DEBUG("TURN sendRaw: TCP transport not ready, dropping %zu bytes", size);
			}
		} else {
			ret = sendUdp(reinterpret_cast<const char *>(data), size, turnServerAddr);
		}
		STICE_LOG_DEBUG("TURN sendRaw: %zu bytes to %s ret=%d", size, turnServerAddr.toString().c_str(), ret);
	};
	// Shared allocation start time for RTT measurement. For UDP TURN, it is
	// set just before allocate() below. For TCP TURN, it is set in
	// onTurnTcpConnected (via turnTcpAllocStart_).
	auto allocStart = std::make_shared<std::chrono::steady_clock::time_point>();
	sink.onAllocated = [lifetime, this, useTcp, serverIndex, allocStart](const net::AddrRecord &relayed, std::uint32_t lifetimeSec) {
		LifetimeScope ls(lifetime);
		if (!ls) return;
		auto *sa = reinterpret_cast<const sockaddr *>(&relayed.addr);
		char host[NI_MAXHOST];
		char serv[NI_MAXSERV];
		getnameinfo(sa, net::addrLen(sa), host, sizeof(host), serv, sizeof(serv),
		            NI_NUMERICHOST | NI_NUMERICSERV);
		STICE_LOG_INFO("TURN: allocation SUCCESS, relayed=%s:%s lifetime=%us",
		               host, serv, lifetimeSec);
		// Compute allocation RTT for relay priority dynamic correction.
		// Every 50ms of RTT costs 1 localPref point (<<8 = 256 priority),
		// capped at 200 (10s). This allows a fast TURN server to outrank a
		// slow one even if the slow one has a lower config index.
		int rttPenalty = 0;
		long long rttMs = 0;
		if (*allocStart != std::chrono::steady_clock::time_point{}) {
			rttMs = std::chrono::duration_cast<std::chrono::milliseconds>(
			    std::chrono::steady_clock::now() - *allocStart).count();
			rttPenalty = static_cast<int>(rttMs / 50);
			if (rttPenalty > 200) rttPenalty = 200;
		}
		// Add a relay candidate.
		Candidate c;
		c.type = CandidateType::Relayed;
		// RFC 6062 TCP allocation: relayed transport is TCP. The TURN server
		// listens on the relayed address (passive), and the client can also
		// actively CONNECT to peers. Mark as TCPPassive since the server
		// accepts incoming connections on behalf of the client.
		c.transport = useTcp ? CandidateTransport::TCPPassive : CandidateTransport::UDP;
		c.component = 1;
		c.resolved = relayed;
		c.hostname = host;
		c.service = serv;
		if (boundAddrUdp(c.related)) c.hasRelated = true;
		// Static priority (RFC 8445) + dynamic RTT correction: pass
		// (serverIndex + rttPenalty) to computePriority, which subtracts
		// the sum from localPref. Lower RTT → higher priority.
		c.priority = c.computePriority(serverIndex + rttPenalty);
		c.foundation = Candidate::computeFoundation(c.type, c.hostname, c.transport);
		STICE_LOG_INFO("TURN: relay priority: rtt=%lldms penalty=%d index=%d priority=%u",
		               rttMs, rttPenalty, serverIndex, c.priority);
		addLocalCandidate(c);
		emitCandidate(c);
		--pendingRelayAllocations_;
		STICE_LOG_DEBUG("TURN: pendingRelayAllocations_=%d after allocation",
		                pendingRelayAllocations_);
		checkGatheringComplete();
	};
	sink.onFailed = [lifetime, this](int code, const std::string &reason) {
		LifetimeScope ls(lifetime);
		if (!ls) return;
		STICE_LOG_WARN("TURN allocation failed: %d %s", code, reason.c_str());
		// NOTE: do NOT reset turnTcpTransport_ here — the onFailed callback
		// may be invoked from within onTurnTcpEvents / handleInboundTurnTcp,
		// and resetting the transport mid-callback causes a UAF when
		// onTurnTcpEvents continues after handleInboundTurnTcp returns.
		// Transport cleanup is handled in onBookkeeping (after tick()) and
		// in onTurnTcpEvents (on transport state change).
		--pendingRelayAllocations_;
		checkGatheringComplete();
	};
	sink.onData = [lifetime, this](const net::AddrRecord &peer, const unsigned char *data, std::size_t size) {
		LifetimeScope ls(lifetime);
		if (!ls) return;
		// Incoming data from a peer via the TURN relay. Deliver as if
		// received directly from that peer.
		handleInboundUdp(reinterpret_cast<const char *>(data), static_cast<int>(size), peer);
	};
	sink.onLog = [](int level, const char *msg) {
		STICE_LOG(static_cast<stice_log_level_t>(level), "%s", msg);
	};
	sink.onConnectSuccess = [lifetime, this](std::uint32_t connectionId, const net::AddrRecord &peer) {
		// RFC 6062 active mode: CONNECT succeeded, open data connection.
		LifetimeScope ls(lifetime);
		if (!ls) return;
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		connectRetries_ = 0; // reset for future re-connects
		pendingConnectRetry_ = false;
		beginTurnDataConnect(connectionId, peer);
	};
	sink.onConnectionAttempt = [lifetime, this](std::uint32_t connectionId, const net::AddrRecord &peer) {
		// RFC 6062 passive mode: peer connected to our relayed address,
		// accept by opening a data connection.
		LifetimeScope ls(lifetime);
		if (!ls) return;
		beginTurnDataConnect(connectionId, peer);
	};
	sink.onConnectFailed = [lifetime, this](int code, const std::string &reason, const net::AddrRecord &peer) {
		// RFC 6062: CONNECT failed. If the error is 447 (Connection Timeout
		// or Failure), the peer's relay listener may not be fully ready yet.
		// Retry up to MaxConnectRetries times with ConnectRetryDelayMs delay
		// before marking the pair as Failed.
		LifetimeScope ls(lifetime);
		if (!ls) return;
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		STICE_LOG_WARN("RFC 6062: CONNECT failed code=%d reason=%s peer=%s (retries=%d/%d)",
		               code, reason.c_str(), peer.toString().c_str(),
		               connectRetries_, MaxConnectRetries);
		if (code == 447 && connectRetries_ < MaxConnectRetries) {
			++connectRetries_;
			pendingConnectPeer_ = peer;
			pendingConnectRetry_ = true;
			nextConnectRetry_ = std::chrono::steady_clock::now() +
			                    std::chrono::milliseconds(ConnectRetryDelayMs);
			wakePoll();
			return;
		}
		// Retries exhausted or non-447 error: mark pairs as Failed.
		for (auto &p : pairs_) {
			if (p->remote && p->remote->type == CandidateType::Relayed &&
			    p->remote->resolved == peer) {
				p->state = PairState::Failed;
			}
		}
		// Remove STUN check entries for the failed pairs.
		for (auto it = entries_.begin(); it != entries_.end();) {
			if (it->type == StunEntryType::Check && it->pair &&
			    it->pair->state == PairState::Failed)
				it = entries_.erase(it);
			else
				++it;
		}
		armNextFrozenPair();
		wakePoll();
		updateState();
	};
	e.turn->init(tc, std::move(sink));
	++pendingRelayAllocations_;
	entries_.push_back(std::move(e));
	// entries_ is reserved (MaxStunEntries) in init(), so &entries_.back()
	// stays valid across subsequent push_back calls.
	auto &entry = entries_.back();
	if (useTcp) {
		// TURN over TCP/TLS: establish the TCP connection first. The
		// allocate() request is sent once the connection completes (see
		// onTurnTcpConnected). Buffering the request here would be
		// pointless since sendRaw drops data while the transport is
		// not yet connected.
		turnTcpEntry_ = &entry;
		turnTcpAllocStart_ = allocStart; // populated in onTurnTcpConnected
		bool useTls = (srv.transport == STICE_TURN_TRANSPORT_TLS);
		std::string sni = useTls ? std::string(srv.host) : std::string();
		bool skipVerify = (srv.skip_tls_verify != 0);
		if (!beginTurnTcpConnect(resolved, useTls, sni, skipVerify)) {
			STICE_LOG_WARN("Agent: TURN TCP connect failed immediately for %s", srv.host);
		}
	} else {
		// TURN over UDP: send the allocate request right away.
		// Record allocation start time for RTT-based priority correction.
		*allocStart = std::chrono::steady_clock::now();
		entry.allocateStartTime = *allocStart;
		entry.turn->allocate();
		entry.nextTransmission = entry.turn->nextTick();
	}
	wakePoll();
}

int Agent::gatherCandidates() {
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	if (state_ != STICE_STATE_DISCONNECTED && state_ != STICE_STATE_FAILED) return STICE_ERR_FAILED;
	changeState(STICE_STATE_GATHERING);
	// Determine role: controlling if we have a higher ufrag lexicographically
	// (libjuice's heuristic; pion uses an explicit role setting). For stice,
	// we follow libjuice: the agent that calls gather first is controlling by
	// default, but role conflict resolution will fix it at runtime.
	if (mode_ == AgentMode::Unknown) mode_ = AgentMode::Controlling;

	// Register with the UDPMux if one is set. This wires the mux's onPacket
	// callback to handleInboundUdp and onBookkeeping to the agent's timer.
	registerWithMux();
	// Register with the TCPMux if one is set. This wires the mux's onPacket
	// callback to handleInboundTcpPacket for inbound TCP connections.
	registerWithTcpMux();

	// Initialize mDNS if configured.
	initMDns();

	// Build the address rewrite mapper if rules were added.
	if (!pendingRewriteRules_.empty() && !addrRewrite_) {
		addrRewrite_ = std::make_unique<AddressRewriteMapper>();
		addrRewrite_->build(pendingRewriteRules_);
	}

	gatherHostCandidates();

	// Collect all STUN/TURN servers that need DNS resolution into GatherItems.
	// The worker thread resolves all items' DNS in parallel (via std::async),
	// eliminating serial getaddrinfo blocking that stalls the poll thread.
	std::vector<GatherItem> items;
	// STUN servers.
	if (!stunServersInternal_.empty()) {
		for (const auto &s : stunServersInternal_) {
			GatherItem item;
			item.type = GatherItem::Type::Stun;
			item.host = s.host;
			item.port = s.port ? s.port : 3478;
			items.push_back(std::move(item));
		}
	} else if (config_.stun_server_host) {
		// Legacy single STUN server fallback.
		GatherItem item;
		item.type = GatherItem::Type::Stun;
		item.host = config_.stun_server_host;
		item.port = config_.stun_server_port ? config_.stun_server_port : 3478;
		items.push_back(std::move(item));
	}
	// TURN servers: decide eager vs deferred based on pairing strategy.
	for (int i = 0; i < config_.turn_servers_count; ++i) {
		const auto &srv = config_.turn_servers[i];
		bool is_tcp = (srv.transport == STICE_TURN_TRANSPORT_TCP ||
		               srv.transport == STICE_TURN_TRANSPORT_TLS);
		if (is_tcp) {
			if (pairingCfg_.tcp_relay_fallback == TcpRelayFallbackMode::ALWAYS_ENABLE) {
				GatherItem item;
				item.type = GatherItem::Type::TurnTcp;
				item.host = srv.host ? srv.host : "";
				item.port = srv.port ? srv.port : 3478;
				item.turnIndex = i;
				item.turnSrv = srv;
				items.push_back(std::move(item));
			} else if (pairingCfg_.tcp_relay_fallback == TcpRelayFallbackMode::ON_ALL_UDP_FAIL) {
				if (pairingCfg_.pre_allocate_tcp_relay) {
					STICE_LOG_INFO("Agent: pre-allocating RFC 6062 TCP relay in background "
					               "(server=%s:%u)", srv.host ? srv.host : "", srv.port);
					GatherItem item;
					item.type = GatherItem::Type::TurnTcp;
					item.host = srv.host ? srv.host : "";
					item.port = srv.port ? srv.port : 3478;
					item.turnIndex = i;
					item.turnSrv = srv;
					items.push_back(std::move(item));
					pairingCfg_.tcp_relay_allocation_created = true;
				} else {
					// Defer: stash a copy so we can create the allocation
					// later when the UDP phase ends. Deep-copy the strings
					// into our own storage.
					stice_turn_server_t copy{};
					copy.port = srv.port;
					copy.transport = srv.transport;
					if (srv.host) {
						deferredTcpTurnHostStorage_.emplace_back(srv.host);
						copy.host = deferredTcpTurnHostStorage_.back().c_str();
					}
					if (srv.username) {
						deferredTcpTurnUserStorage_.emplace_back(srv.username);
						copy.username = deferredTcpTurnUserStorage_.back().c_str();
					}
					if (srv.password) {
						deferredTcpTurnPassStorage_.emplace_back(srv.password);
						copy.password = deferredTcpTurnPassStorage_.back().c_str();
					}
					deferredTcpTurnServers_.push_back(copy);
					deferredTcpTurnIndices_.push_back(i);
					STICE_LOG_INFO("Agent: deferring RFC 6062 TCP allocation (server=%s:%u)",
					               srv.host ? srv.host : "", srv.port);
				}
			}
			// DISABLE: skip entirely.
		} else {
			// UDP TURN allocation is always created eagerly.
			GatherItem item;
			item.type = GatherItem::Type::TurnUdp;
			item.host = srv.host ? srv.host : "";
			item.port = srv.port ? srv.port : 3478;
			item.turnIndex = i;
			item.turnSrv = srv;
			items.push_back(std::move(item));
		}
	}
	// Mark the start of the UDP phase for PHASED_UDP_FIRST.
	if (pairingCfg_.schedule_mode == IceCheckScheduleMode::PHASED_UDP_FIRST) {
		pairingCfg_.udp_phase_start = std::chrono::steady_clock::now();
		pairingCfg_.tcp_phase_entered = false;
		pairingCfg_.tcp_relay_allocation_created =
		    (pairingCfg_.tcp_relay_fallback == TcpRelayFallbackMode::ALWAYS_ENABLE);
	}

	// If there are no items to resolve, signal gathering complete now.
	if (items.empty()) {
		if (pendingRelayAllocations_ == 0 && pendingServerReflexive_ == 0) {
			checkGatheringComplete();
		}
		return STICE_ERR_SUCCESS;
	}

	// Join any previous worker thread (for restart scenarios).
	if (gatherWorker_.joinable()) gatherWorker_.join();

	// Spawn the worker thread: resolves all DNS in parallel, then creates
	// StunEntry objects under the mutex. This eliminates serial getaddrinfo
	// blocking that stalls the poll thread during gathering.
	STICE_LOG_INFO("Agent: spawning gather worker thread for %zu items", items.size());
	gatherWorker_ = std::thread(&Agent::gatherCandidatesWorker, this, std::move(items), lifetime_);

	return STICE_ERR_SUCCESS;
}

void Agent::gatherCandidatesWorker(std::vector<GatherItem> items,
                                   std::shared_ptr<LifetimeGuard> lifetime) {
	// Phase 1: Resolve all DNS in parallel (no mutex needed).
	// Each item gets its own std::async task, so all getaddrinfo calls
	// run concurrently on the OS thread pool. This eliminates the serial
	// blocking that occurs when resolving N STUN + M TURN servers one by
	// one on the caller's thread while holding the mutex.
	std::vector<std::future<std::vector<net::AddrRecord>>> futures;
	futures.reserve(items.size());
	for (auto &item : items) {
		int socktype = (item.type == GatherItem::Type::TurnTcp) ? SOCK_STREAM : SOCK_DGRAM;
		futures.push_back(std::async(std::launch::async,
		    [item, socktype]() -> std::vector<net::AddrRecord> {
			    // Try numeric parse first (no DNS needed).
			    net::AddrRecord rec;
			    if (net::parseAddr(item.host, item.port, rec.addr, rec.len)) {
				    rec.socktype = socktype;
				    return {rec};
			    }
			    // Otherwise resolve via getaddrinfo (blocking).
			    return net::resolve(item.host, std::to_string(item.port), socktype);
		    }));
	}

	// Collect results (blocks until all DNS resolutions complete or fail).
	std::vector<std::vector<net::AddrRecord>> results;
	results.reserve(items.size());
	for (auto &f : futures) results.push_back(f.get());

	// Phase 2: Create StunEntry objects under the mutex.
	LifetimeScope ls(lifetime);
	if (!ls) return; // Agent destroyed during DNS resolution.
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	for (std::size_t i = 0; i < items.size(); ++i) {
		if (results[i].empty()) {
			STICE_LOG_WARN("Agent: could not resolve %s:%u (%s)",
			               items[i].host.c_str(), items[i].port,
			               items[i].type == GatherItem::Type::Stun ? "STUN" : "TURN");
			continue;
		}
		const auto &resolved = results[i][0];
		if (items[i].type == GatherItem::Type::Stun) {
			createServerReflexiveEntry(items[i].host, items[i].port, resolved);
		} else {
			// TurnUdp or TurnTcp — both use createRelayEntry.
			createRelayEntry(items[i].turnSrv, items[i].turnIndex, resolved);
		}
	}
	// If all items failed resolution and no entries were created, signal
	// gathering complete so the agent doesn't hang in GATHERING.
	if (pendingRelayAllocations_ == 0 && pendingServerReflexive_ == 0) {
		checkGatheringComplete();
	}
}

int Agent::getLocalDescription(char *buf, std::size_t size) const {
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	std::string sdp = local_.generateSdp();
	if (sdp.size() + 1 > size) return STICE_ERR_TOO_LARGE;
	std::memcpy(buf, sdp.data(), sdp.size());
	buf[sdp.size()] = '\0';
	return STICE_ERR_SUCCESS;
}

int Agent::setRemoteDescription(const char *sdp) {
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	Description d;
	if (!d.parse(sdp)) return STICE_ERR_INVALID;
	remote_ = std::move(d);
	// Re-reserve after move-assigning a new Description, since the reserved
	// capacity from init() is lost when remote_ is replaced. Without this,
	// later addRemoteCandidate calls would reallocate remote_.candidates and
	// invalidate the raw Candidate* pointers stored in CandidatePair::remote.
	remote_.candidates.reserve(MaxCandidates);
	if (mode_ == AgentMode::Unknown) {
		// We are the controlled agent if we set the remote description first.
		mode_ = AgentMode::Controlled;
	}
	// Process remote passive TCP candidates: create local active TCP
	// candidates and initiate connections. This was previously only done
	// in addRemoteCandidate (trickle path), leaving non-trickle ICE-TCP
	// without any TCP connection attempt.
	// Aligned with pion-ice: skip when DisableActiveTCP is set.
	for (const auto &rc : remote_.candidates) {
		if (rc.transport == CandidateTransport::TCPPassive &&
		    iceTcpMode_ != STICE_ICE_TCP_MODE_NONE &&
		    !config_.disable_active_tcp) {
			addRemotePassiveTcpCandidate(rc);
		}
	}
	if (gatheringDone_ && state_ == STICE_STATE_GATHERING) {
		formPairs();
		changeState(STICE_STATE_CONNECTING);
	}
	return STICE_ERR_SUCCESS;
}

int Agent::addRemoteCandidate(const char *sdp) {
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	if (!remote_.addCandidateFromSdp(sdp)) return STICE_ERR_INVALID;
	// Get the just-added remote candidate (last one in the list).
	if (!remote_.candidates.empty()) {
		const auto &rc = remote_.candidates.back();
		// pion-ice: remote TCP active candidates are ignored because the
		// remote active side will probe our passive listener. We only
		// process passive (and SO) remote TCP candidates.
		if (rc.transport == CandidateTransport::TCPActive) {
			STICE_LOG_DEBUG("addRemoteCandidate: ignoring remote TCP active candidate");
			// Remove it from the list since we won't use it.
			remote_.candidates.pop_back();
			return STICE_ERR_SUCCESS;
		}
		// If remote is TCP passive and we have active TCP enabled, create
		// a local active TCP candidate by dialing the remote address.
		// Aligned with pion-ice: skip when DisableActiveTCP is set.
		if (rc.transport == CandidateTransport::TCPPassive &&
		    iceTcpMode_ != STICE_ICE_TCP_MODE_NONE &&
		    !config_.disable_active_tcp) {
			addRemotePassiveTcpCandidate(rc);
		}
	}
	if (state_ == STICE_STATE_CONNECTING || state_ == STICE_STATE_CONNECTED ||
	    state_ == STICE_STATE_COMPLETED) {
		formPairs();
	}
	return STICE_ERR_SUCCESS;
}

int Agent::addTurnServer(const stice_turn_server_t *srv) {
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	if (config_.turn_servers_count >= 8) return STICE_ERR_TOO_LARGE;
	// Append to the config's turn server list. The C API gives us a pointer
	// to a stice_turn_server_t; we copy it. We assume config_ owns a stable
	// array; for simplicity we grow a vector kept alongside config_.
	// NOTE: config_.turn_servers points into user memory, so we maintain a
	// separate internal vector.
	turnServersInternal_.push_back(*srv);
	config_.turn_servers = turnServersInternal_.data();
	config_.turn_servers_count = static_cast<int>(turnServersInternal_.size());
	return STICE_ERR_SUCCESS;
}

int Agent::addStunServer(const char *host, uint16_t port) {
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	if (!host) return STICE_ERR_INVALID;
	if (stunServersInternal_.size() >= 8) return STICE_ERR_TOO_LARGE;
	stunServersInternal_.push_back({std::string(host), port ? port : static_cast<uint16_t>(3478)});
	return STICE_ERR_SUCCESS;
}

int Agent::addIceServer(const char *url, const char *username, const char *password) {
	if (!url) return STICE_ERR_INVALID;
	std::lock_guard<std::recursive_mutex> lock(mutex_);

	// Parse URL: scheme:host[:port][?transport=tcp]
	// Supported schemes: stun, turn, turns (aligned with pion ICEServer URLs).
	std::string s(url);
	std::string scheme, hostPart;
	uint16_t port = 3478;
	stice_turn_transport_t transport = STICE_TURN_TRANSPORT_UDP;

	// Extract scheme.
	auto colonPos = s.find(':');
	if (colonPos == std::string::npos) return STICE_ERR_INVALID;
	scheme = s.substr(0, colonPos);
	std::string rest = s.substr(colonPos + 1);
	// Strip leading "//" if present (e.g. "stun://host:port").
	if (rest.size() >= 2 && rest[0] == '/' && rest[1] == '/')
		rest = rest.substr(2);

	// Extract query string (e.g. "?transport=tcp").
	std::string query;
	auto queryPos = rest.find('?');
	if (queryPos != std::string::npos) {
		query = rest.substr(queryPos + 1);
		rest = rest.substr(0, queryPos);
	}
	// Parse transport=tcp from query.
	if (query.find("transport=tcp") != std::string::npos ||
	    query.find("transport=TCP") != std::string::npos) {
		transport = STICE_TURN_TRANSPORT_TCP;
	}

	// Extract host and port.
	hostPart = rest;
	auto lastColon = rest.rfind(':');
	if (lastColon != std::string::npos) {
		// Check if the part after ':' is numeric (port) vs IPv6 address.
		std::string maybePort = rest.substr(lastColon + 1);
		bool isNumeric = !maybePort.empty();
		for (char c : maybePort) {
			if (!std::isdigit(static_cast<unsigned char>(c))) { isNumeric = false; break; }
		}
		if (isNumeric) {
			hostPart = rest.substr(0, lastColon);
			try { port = static_cast<uint16_t>(std::stoul(maybePort)); }
			catch (...) { port = 3478; }
			if (port == 0) port = 3478;
		}
	}
	if (hostPart.empty()) return STICE_ERR_INVALID;

	bool isTurn = (scheme == "turn" || scheme == "turns");
	bool isStun = (scheme == "stun");
	if (!isTurn && !isStun) return STICE_ERR_INVALID;

	// For turn:/turns: URLs, add BOTH a TURN server (relay) AND a STUN
	// server (srflx), since coturn supports both on the same port. This
	// eliminates duplicate configuration (user only configures one URL).
	if (isTurn) {
		if (turnServersInternal_.size() >= 8) return STICE_ERR_TOO_LARGE;
		stice_turn_server_t ts{};
		// Backing storage for C strings (must outlive the struct).
		turnServerHostStorage_.emplace_back(hostPart);
		ts.host = turnServerHostStorage_.back().c_str();
		ts.port = port;
		if (username) {
			turnServerUserStorage_.emplace_back(username);
			ts.username = turnServerUserStorage_.back().c_str();
		}
		if (password) {
			turnServerPassStorage_.emplace_back(password);
			ts.password = turnServerPassStorage_.back().c_str();
		}
		if (scheme == "turns") {
			ts.transport = STICE_TURN_TRANSPORT_TLS;
		} else {
			ts.transport = transport;
		}
		turnServersInternal_.push_back(ts);
		config_.turn_servers = turnServersInternal_.data();
		config_.turn_servers_count = static_cast<int>(turnServersInternal_.size());
		STICE_LOG_INFO("Agent: addIceServer turn: added TURN server %s:%u (transport=%d)",
		               hostPart.c_str(), port, static_cast<int>(ts.transport));
	}

	// Add STUN server entry (for both stun: and turn: URLs).
	if (stunServersInternal_.size() >= 8) return STICE_ERR_TOO_LARGE;
	// For turns: (TLS), STUN over UDP is still useful for srflx — the coturn
	// server listens on UDP 3478 for STUN even if TLS is on TCP 5349. Use the
	// same port (3478) for STUN UDP regardless of TURN transport.
	stunServersInternal_.push_back({hostPart, port});
	STICE_LOG_INFO("Agent: addIceServer %s: added STUN server %s:%u",
	               scheme.c_str(), hostPart.c_str(), port);

	return STICE_ERR_SUCCESS;
}

int Agent::setRemoteGatheringDone() {
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	remote_.finished = true;
	remoteGatheringDone_ = true;
	return STICE_ERR_SUCCESS;
}

int Agent::setLocalIceAttributes(const char *ufrag, const char *pwd) {
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	// RFC 8445: ufrag 4-256 chars, pwd 22-256 chars, both "ice-char" alphabet
	// (ALPHA / DIGIT / "+" / "/").
	auto isValidIceString = [](const char *s, std::size_t minLen) -> bool {
		if (!s) return false;
		std::size_t len = std::strlen(s);
		if (len < minLen || len > MaxUfragLen) return false;
		for (std::size_t i = 0; i < len; ++i) {
			char c = s[i];
			if (!std::isalnum(static_cast<unsigned char>(c)) && c != '+' && c != '/') return false;
		}
		return true;
	};
	if (ufrag && !isValidIceString(ufrag, 4)) return STICE_ERR_INVALID;
	if (pwd && !isValidIceString(pwd, 22)) return STICE_ERR_INVALID;
	if (ufrag) local_.iceUfrag = ufrag;
	if (pwd) local_.icePwd = pwd;
	return STICE_ERR_SUCCESS;
}

int Agent::setIceTcpMode(stice_ice_tcp_mode_t mode) {
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	iceTcpMode_ = mode;
	return STICE_ERR_SUCCESS;
}

int Agent::addAddressRewriteRule(const stice_address_rewrite_rule_t *rule) {
	if (!rule) return STICE_ERR_INVALID;
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	if (state_ != STICE_STATE_DISCONNECTED && state_ != STICE_STATE_FAILED) {
		// Rules must be added before gathering starts.
		return STICE_ERR_FAILED;
	}
	AddressRewriteRule r;
	if (rule->external_ips) {
		for (auto *p = rule->external_ips; *p; ++p) {
			r.external.push_back(*p);
		}
	}
	if (rule->local_ip) r.local = rule->local_ip;
	if (rule->iface) r.iface = rule->iface;
	if (rule->cidr) r.cidr = rule->cidr;
	switch (rule->as_candidate_type) {
	case STICE_REWRITE_CANDIDATE_TYPE_HOST: r.asCandidateType = CandidateType::Host; break;
	case STICE_REWRITE_CANDIDATE_TYPE_SRFLX: r.asCandidateType = CandidateType::ServerReflexive; break;
	case STICE_REWRITE_CANDIDATE_TYPE_RELAY: r.asCandidateType = CandidateType::Relayed; break;
	default: r.asCandidateType = CandidateType::Unknown; break;
	}
	switch (rule->mode) {
	case STICE_ADDR_REWRITE_MODE_REPLACE: r.mode = AddressRewriteMode::Replace; break;
	case STICE_ADDR_REWRITE_MODE_APPEND: r.mode = AddressRewriteMode::Append; break;
	default: r.mode = AddressRewriteMode::Unspecified; break;
	}
	pendingRewriteRules_.push_back(std::move(r));
	return STICE_ERR_SUCCESS;
}

int Agent::setMulticastDnsMode(stice_multicast_dns_mode_t mode) {
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	if (state_ != STICE_STATE_DISCONNECTED && state_ != STICE_STATE_FAILED) {
		return STICE_ERR_FAILED;
	}
	mdnsMode_ = mode;
	// Use the config's hostname if provided, otherwise generate one in initMDns.
	if (config_.multicast_dns_hostname) {
		mdnsHostname_ = config_.multicast_dns_hostname;
	}
	return STICE_ERR_SUCCESS;
}

void Agent::initMDns() {
	if (mdnsInitialized_) return;
	mdnsInitialized_ = true;

	// Read mDNS mode from config if not explicitly set.
	if (mdnsMode_ == STICE_MDNS_MODE_DISABLED && config_.multicast_dns_mode != 0) {
		mdnsMode_ = config_.multicast_dns_mode;
	}

	if (mdnsMode_ == STICE_MDNS_MODE_DISABLED) return;

	// Generate hostname if not set.
	if (mdnsHostname_.empty()) {
		mdnsHostname_ = net::MDnsClient::generateHostname();
	}

	// Determine the local address to advertise (for QueryAndGather mode).
	std::string localAddr;
	if (mdnsMode_ == STICE_MDNS_MODE_QUERY_AND_GATHER) {
		// Use the first local address from the socket.
		auto addrs = localAddrsUdp(AF_INET);
		if (!addrs.empty()) {
			auto *sa = reinterpret_cast<const sockaddr *>(&addrs[0].addr);
			char host[NI_MAXHOST];
			if (getnameinfo(sa, net::addrLen(sa), host, sizeof(host), nullptr, 0,
			                NI_NUMERICHOST) == 0) {
				localAddr = host;
			}
		}
	}

	auto mode = net::MulticastDNSMode::Disabled;
	switch (mdnsMode_) {
	case STICE_MDNS_MODE_QUERY_ONLY: mode = net::MulticastDNSMode::QueryOnly; break;
	case STICE_MDNS_MODE_QUERY_AND_GATHER: mode = net::MulticastDNSMode::QueryAndGather; break;
	default: return;
	}

	mdns_ = std::make_unique<net::MDnsClient>();
	if (!mdns_->init(mode, mdnsHostname_, localAddr)) {
		STICE_LOG_WARN("Agent: mDNS init failed, continuing without mDNS");
		mdns_.reset();
	}
}

std::vector<Candidate> Agent::applyAddressRewrite(const Candidate &c,
                                                   const std::string &localIP,
                                                   const std::string &iface) {
	if (!addrRewrite_ || addrRewrite_->empty()) {
		return {c};
	}
	auto result = addrRewrite_->findExternalIPs(c.type, localIP, iface);
	if (!result.matched) {
		return {c};
	}
	std::vector<Candidate> out;
	if (result.mode != AddressRewriteMode::Replace) {
		// Append mode: keep the original candidate.
		out.push_back(c);
	}
	for (const auto &extIP : result.externalIPs) {
		Candidate mapped = c;
		mapped.hostname = extIP;
		// Update the resolved address to the external IP (keep port).
		std::uint16_t portNum = static_cast<std::uint16_t>(std::atoi(c.service.c_str()));
		if (net::parseAddr(extIP, portNum, mapped.resolved.addr, mapped.resolved.len)) {
			mapped.resolved.socktype = SOCK_DGRAM;
		}
		mapped.foundation = Candidate::computeFoundation(c.type, extIP, c.transport);
		out.push_back(std::move(mapped));
	}
	return out;
}

bool Agent::resolveRemoteMDnsCandidate(const Candidate &c) {
	if (!mdns_ || mdnsMode_ == STICE_MDNS_MODE_DISABLED) return false;
	if (!net::MDnsClient::isMDnsName(c.hostname)) return false;

	// Copy the candidate so we can fill in the resolved address later.
	auto hostname = c.hostname;
	// Capture the needed fields by value since the callback runs async.
	auto port = c.service;
	auto type = c.type;
	auto transport = c.transport;
	auto component = c.component;
	auto priority = c.priority;
	auto foundation = c.foundation;

	mdns_->query(hostname, [this, lifetime = lifetime_, hostname, port, type, transport, component,
	                        priority, foundation](const std::string &address) {
		LifetimeScope ls(lifetime);
		if (!ls) return;
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		if (address.empty()) {
			STICE_LOG_DEBUG("mDNS: resolution failed for %s", hostname.c_str());
			return;
		}
		// Add the resolved remote candidate.
		Candidate resolved;
		resolved.type = type;
		resolved.transport = transport;
		resolved.component = component;
		resolved.priority = priority;
		resolved.foundation = foundation;
		resolved.hostname = address;
		resolved.service = port;
		std::uint16_t portNum = static_cast<std::uint16_t>(std::atoi(port.c_str()));
		if (net::parseAddr(address, portNum, resolved.resolved.addr, resolved.resolved.len)) {
			resolved.resolved.socktype = (transport == CandidateTransport::UDP) ? SOCK_DGRAM : SOCK_STREAM;
		}
		remote_.candidates.push_back(std::move(resolved));
		if (state_ == STICE_STATE_CONNECTING || state_ == STICE_STATE_CONNECTED ||
		    state_ == STICE_STATE_COMPLETED) {
			formPairs();
		}
		STICE_LOG_DEBUG("mDNS: resolved %s to %s", hostname.c_str(), address.c_str());
	});
	return true;
}

void Agent::wakePoll() {
	// Wake the poll thread so it re-evaluates timers immediately. Called
	// after state changes (e.g. formPairs arming a new entry) that happen
	// on the caller's thread, not the poll thread.
	if (pollReg_) {
		pollReg_->interrupt();
	} else if (mux_) {
		// In UDPMux mode, the Agent doesn't own a PollRegistry; the mux
		// does. Wake the mux's poll thread instead.
		mux_->interrupt();
	} else if (tcpMux_) {
		tcpMux_->interrupt();
	}
}

void Agent::formPairs() {
	STICE_LOG_DEBUG("formPairs: local=%zu remote=%zu mode=%d",
	                local_.candidates.size(), remote_.candidates.size(), static_cast<int>(mode_));
	for (const auto &rc : remote_.candidates)
		STICE_LOG_DEBUG("  remote cand: host=%s port=%s resolved=%s",
		                rc.hostname.c_str(), rc.service.c_str(), rc.resolved.toString().c_str());
	// Form pairs from local x remote candidates (same component, same family).
	for (const auto &local : local_.candidates) {
		for (const auto &remote : remote_.candidates) {
			if (local.component != remote.component) continue;
			if (local.resolved.addr.ss_family != remote.resolved.addr.ss_family) continue;
			// RFC 6544 §5.2: TCP candidate pair filtering.
			// - active-active: illegal (neither side connects)
			// - passive-passive: illegal (neither side connects)
			// - active-passive: legal (active side connects to passive)
			// - SO with anything: legal (SO can both initiate and accept)
			// Also: UDP cannot pair with TCP (different transports).
			bool localIsTcp = (local.transport != CandidateTransport::UDP);
			bool remoteIsTcp = (remote.transport != CandidateTransport::UDP);
			if (localIsTcp != remoteIsTcp) continue; // cross-transport pair not allowed
			if (localIsTcp && remoteIsTcp) {
				bool localActive = (local.transport == CandidateTransport::TCPActive);
				bool remoteActive = (remote.transport == CandidateTransport::TCPActive);
				bool localPassive = (local.transport == CandidateTransport::TCPPassive);
				bool remotePassive = (remote.transport == CandidateTransport::TCPPassive);
				if (localActive && remoteActive) continue; // active-active illegal
				// RFC 6062: two TCP-relayed (passive) candidates CAN pair — the
				// controlling side sends CONNECT, the controlled side receives
				// CONNECTION-ATTEMPT. Only filter non-relayed passive-passive.
				if (localPassive && remotePassive &&
				    !(local.type == CandidateType::Relayed && remote.type == CandidateType::Relayed))
					continue; // passive-passive illegal (non-relayed)
			}
			bool exists = false;
			for (const auto &p : pairs_) {
				if (p->local == &local && p->remote == &remote) { exists = true; break; }
			}
			if (exists) continue;
			if (pairs_.size() >= MaxCandidatePairs) break;
			auto p = std::make_unique<CandidatePair>();
			p->local = &local;
			p->remote = &remote;
			p->state = PairState::Frozen;
			p->updatePriority(mode_ == AgentMode::Controlling);
			pairs_.push_back(std::move(p));
		}
	}
	updateOrderedPairs();
	// Proactively request CreatePermission on our TURN relay for each remote
	// candidate address when the local candidate is relayed. This is critical
	// because the TURN server won't forward outgoing Send indications (or
	// incoming data from peers) without a permission, and the remote agent's
	// TURN server similarly won't forward our check to the remote allocation
	// unless the remote has a permission for our relayed address. By requesting
	// permission early, both sides are ready by the time checks are sent.
	for (const auto &p : orderedPairs_) {
		if (p->local && p->local->type == CandidateType::Relayed) {
			for (auto &re : entries_) {
				if (re.type == StunEntryType::Relay && re.turn &&
				    re.turn->state() == turn::AllocState::Allocated) {
					// RFC 6062 TCP allocation: no CreatePermission needed.
					// Instead, one side sends CONNECT to the remote relayed
					// address; the other waits for CONNECTION-ATTEMPT.
					// We use ufrag comparison (shouldInitiateTcpConnect) to
					// deterministically pick the CONNECT initiator, since
					// both agents may default to Controlling before 487
					// role conflict resolution.
					if (re.turn->isTcpAllocation()) {
						// RFC 6062: CreatePermission is still required for
						// TCP allocations. The passive side's TURN server
						// checks permissions when accepting inbound TCP
						// connections on the relayed address; without a
						// permission, it closes the connection and does NOT
						// send CONNECTION-ATTEMPT (RFC 6062 §4.4).
						re.turn->ensurePermission(p->remote->resolved);
						// The active side additionally sends CONNECT.
					if (shouldInitiateTcpConnect() &&
					    p->remote && p->remote->type == CandidateType::Relayed &&
					    p->remote->transport == CandidateTransport::TCPPassive) {
						STICE_LOG_INFO("RFC 6062: sending CONNECT to peer relayed=%s",
						               p->remote->resolved.toString().c_str());
						re.turn->sendConnect(p->remote->resolved);
						tcpConnectSent_ = true;
						pendingConnectPeer_ = p->remote->resolved;
					}
					} else {
						re.turn->ensurePermission(p->remote->resolved);
					}
				}
			}
		}
	}
	// Arm the first wave of frozen pairs per the active schedule mode
	// (RFC8445_STRICT arms many; SERIAL arms one; LIMITED_CONCURRENT /
	// PHASED_UDP_FIRST respect max_concurrent_check and the UDP phase).
	armNextFrozenPair();
	// Wake the poll thread so it picks up the newly armed entry immediately.
	wakePoll();
}

void Agent::updateOrderedPairs() {
	orderedPairs_.clear();
	for (auto &p : pairs_) orderedPairs_.push_back(p.get());
	std::stable_sort(orderedPairs_.begin(), orderedPairs_.end(),
	                 [](const CandidatePair *a, const CandidatePair *b) { return a->priority > b->priority; });
}

StunEntry *Agent::findEntry(CandidatePair *pair) {
	for (auto &e : entries_)
		if (e.pair == pair) return &e;
	return nullptr;
}

void Agent::armTransmission(StunEntry &e, int delayMs) {
	e.nextTransmission = std::chrono::steady_clock::now() + std::chrono::milliseconds(delayMs);
	e.retransmissions = 0;
	// RFC 6544: TCP provides reliable delivery, so application-layer STUN
	// retransmission is unnecessary. Use a single fixed timeout
	// (StunTcpTimeoutMs) for TCP pairs; UDP pairs use exponential backoff
	// starting from the configured rto_initial (default 500ms, matching
	// pion-ice).
	if (pairIsTcp(e.pair)) {
		e.retransmissionTimeout = std::chrono::milliseconds(StunTcpTimeoutMs);
	} else {
		auto rto = pairingCfg_.rto_initial.count() > 0
		               ? pairingCfg_.rto_initial
		               : std::chrono::milliseconds(MinStunRetransmissionTimeoutMs);
		e.retransmissionTimeout = rto;
	}
	e.transactionIdExpired = true;
	e.state = StunEntryState::Pending;
}

void Agent::armKeepalive(StunEntry &e) {
	e.state = StunEntryState::SucceededKeepalive;
	auto now = std::chrono::steady_clock::now();
	// Idle backoff (P1-2): if no application data has flowed for
	// IdleThresholdMs, stretch the consent check interval to
	// IdleConsentCheckMs (still safely under ConsentTimeoutMs=30s) to
	// reduce keepalive traffic on quiescent sessions. Active sessions use
	// the configured keepalive interval (keepalive_udp / keepalive_tcp_relay)
	// jittered +/- 1s to avoid synchronization storms. Falls back to the
	// compiled-in defaults if the config value is 0.
	bool idle = (lastAppDataAt_.time_since_epoch().count() == 0) ||
	            (now - lastAppDataAt_ > std::chrono::milliseconds(IdleThresholdMs));
	int period;
	if (idle) {
		period = IdleConsentCheckMs;
	} else {
		bool is_relay = e.pair && pairIsTcpRelay(e.pair);
		std::chrono::milliseconds cfg_period =
		    is_relay ? pairingCfg_.keepalive_tcp_relay : pairingCfg_.keepalive_udp;
		int base = cfg_period.count() > 0
		               ? static_cast<int>(cfg_period.count())
		               : (MinConsentCheckPeriodMs +
		                  static_cast<int>(crypto::randomU32() %
		                                   (MaxConsentCheckPeriodMs - MinConsentCheckPeriodMs + 1)));
		// Jitter +/- 1s around the configured period to desynchronize.
		int jitter = static_cast<int>(crypto::randomU32() % 2001) - 1000;
		period = std::max(MinConsentCheckPeriodMs, base + jitter);
	}
	e.nextTransmission = now + std::chrono::milliseconds(period);
}

void Agent::sendStunBinding(StunEntry &e, stun::Class cls, int errorCode,
                            const std::array<unsigned char, 12> *replyTid,
                            const net::AddrRecord *mapped) {
	stun::Message m;
	m.method = stun::Method::Binding;
	m.cls = cls;
	if (replyTid) m.transactionID = *replyTid;
	else {
		if (e.transactionIdExpired) {
			if (!crypto::randomBytes(e.transactionID.data(), 12)) return;
			e.transactionIdExpired = false;
		}
		m.transactionID = e.transactionID;
	}

	if (cls == stun::Class::Request) {
		// USERNAME = "<remote_ufrag>:<local_ufrag>" (short-term cred).
		std::string username = remote_.iceUfrag + ":" + local_.iceUfrag;
		stun::addString(m, stun::AttrType::Username, username);
		// PRIORITY (peer-reflexive type preference, for learning prflx).
		if (e.pair && e.pair->local) {
			int fam = e.pair->local->resolved.addr.ss_family;
			std::uint32_t pri = Candidate::computePriority(CandidateType::PeerReflexive,
			                                              fam, 1, 0, CandidateTransport::UDP);
			stun::addPriority(m, pri);
		}
		// ICE-CONTROLLING / ICE-CONTROLLED.
		if (mode_ == AgentMode::Controlling) stun::addIceControlling(m, tiebreaker_);
		else stun::addIceControlled(m, tiebreaker_);
		// USE-CANDIDATE if controlling and nomination requested.
		// draft-thatcher-ice-renomination: include NOMINATION attribute
		// (a monotonically increasing uint32) so the controlled peer can
		// detect re-nomination and switch the selected pair when a higher
		// value arrives. Aligned with pion-ice: the first nomination
		// (value=1) sends only USE-CANDIDATE; re-nominations (value>1)
		// also include the NOMINATION attribute.
		if (mode_ == AgentMode::Controlling && e.pair && e.pair->nominationRequested &&
		    !e.pair->nominated) {
			stun::addUseCandidate(m);
			if (nominationValue_ > 1) {
				stun::addNomination(m, nominationValue_);
			}
		}
		// RFC 6544 §8.1: include TCP-TYPE on connectivity checks over TCP so
		// the peer can verify the pair's TCP direction matches. Maps the
		// local candidate transport to the wire enum value.
		if (e.pair && e.pair->local &&
		    e.pair->local->transport != CandidateTransport::UDP) {
			std::uint32_t tcpTypeVal = stun::TcpTypeActive;
			switch (e.pair->local->transport) {
			case CandidateTransport::TCPActive: tcpTypeVal = stun::TcpTypeActive; break;
			case CandidateTransport::TCPPassive: tcpTypeVal = stun::TcpTypePassive; break;
			case CandidateTransport::TCPSimultaneousOpen: tcpTypeVal = stun::TcpTypeSo; break;
			default: break;
			}
			stun::addTcpType(m, tcpTypeVal);
		}
		e.mode = mode_;
	} else if (cls == stun::Class::SuccessResponse && mapped) {
		stun::writeXorAddress(m, stun::AttrType::XorMappedAddress, *mapped, m.transactionID);
	} else if (cls == stun::Class::ErrorResponse) {
		stun::addErrorCode(m, errorCode);
	}

	// Encode with the appropriate password:
	// - requests: remote pwd (incoming checks) -> for outgoing checks, password = remote pwd
	// - responses: local pwd (responses use local pwd for MI verification by peer)
	const char *password = nullptr;
	if (cls == stun::Class::Request) password = remote_.icePwd.c_str();
	else password = local_.icePwd.c_str();
	m.encode(password, nullptr, "stice");

	STICE_LOG_DEBUG("sendStunBinding: cls=%d method=%d to=%s tid=%02x%02x%02x%02x useCand=%d",
	                static_cast<int>(cls), static_cast<int>(m.method),
	                e.record.toString().c_str(),
	                m.transactionID[0], m.transactionID[1], m.transactionID[2], m.transactionID[3],
	                (e.pair && e.pair->nominationRequested) ? 1 : 0);

	// RFC 6062: route through TURN data connection for TCP-relayed pairs.
	// If the data connection is not yet bound, defer the check (do NOT
	// fall through to UDP or ICE-TCP). Once CONNECTION-BIND succeeds,
	// STUN messages flow through the transparent TCP tunnel with RFC 4571
	// framing.
	if (pairIsTurnTcpRelay(e.pair)) {
		if (turnDataConn_ && turnDataConn_->bound) {
			sendTurnDataConn(reinterpret_cast<const char *>(m.raw.data()), m.raw.size());
		}
		return;
	}

	// Route via TCP if the pair uses TCP transport. RFC 6544: STUN messages
	// over TCP use RFC 4571 framing. If TCP is not yet connected, do NOT
	// fall through to UDP — the check is deferred until the connection
	// completes (handled in onTcpEvents).
	if (pairIsTcp(e.pair)) {
		if ((tcpTransport_ && tcpTransport_->state() == net::TcpState::Connected) ||
		    (tcpMux_ && e.pair && e.pair->local &&
		     e.pair->local->transport == CandidateTransport::TCPPassive)) {
			sendTcp(reinterpret_cast<const char *>(m.raw.data()), m.raw.size(), e.pair);
		}
		return;
	}

	// Send via UDP (or via the TURN relay if the local candidate is relayed,
	// or if the remote candidate is relayed and we have a TURN allocation).
	bool routeViaRelay = (e.pair && e.pair->local &&
	                      e.pair->local->type == CandidateType::Relayed);
	if (!routeViaRelay && e.pair && e.pair->remote &&
	    e.pair->remote->type == CandidateType::Relayed) {
		// Remote is relayed: direct UDP to the relayed address will be dropped
		// by the remote TURN server unless it has a permission for our source
		// address. Route through our own TURN relay instead so the traffic
		// appears to come from our relayed address (which the remote can
		// create a permission for).
		for (const auto &re : entries_) {
			if (re.type == StunEntryType::Relay && re.turn &&
			    re.turn->state() == turn::AllocState::Allocated) {
				routeViaRelay = true;
				break;
			}
		}
	}
	if (routeViaRelay) {
		for (auto &re : entries_) {
			if (re.type == StunEntryType::Relay && re.turn &&
			    re.turn->state() == turn::AllocState::Allocated) {
				re.turn->sendData(e.record, m.raw.data(), m.raw.size());
				return;
			}
		}
	}
	sendUdp(reinterpret_cast<const char *>(m.raw.data()), m.raw.size(), e.record);
}

void Agent::sendKeepalive(StunEntry &e) {
	// Consent freshness: Binding request (the response refreshes consent_expiry).
	sendStunBinding(e, stun::Class::Request, 0);
}

void Agent::sendBindingResponse(const stun::Message &req, const net::AddrRecord &dst, int errorCode) {
	// Find or create a transient entry for the response. We don't track it
	// as a real STUN entry; we just send the response and discard.
	stun::Message m;
	m.method = stun::Method::Binding;
	m.cls = (errorCode == 0) ? stun::Class::SuccessResponse : stun::Class::ErrorResponse;
	m.transactionID = req.transactionID;
	if (errorCode == 0) {
		// Include XOR-MAPPED-ADDRESS of the source (the peer's address as seen by us).
		stun::writeXorAddress(m, stun::AttrType::XorMappedAddress, dst, m.transactionID);
	} else {
		stun::addErrorCode(m, errorCode);
	}
	m.encode(local_.icePwd.c_str(), nullptr, "stice");

	// RFC 6062: if the request arrived via the TURN TCP data connection,
	// send the response back through the same data connection (not via
	// UDP TURN ChannelData or the raw UDP socket). The peer's TURN server
	// would drop a direct UDP response to the relayed address.
	if (turnDataConn_ && turnDataConn_->bound && dst.isEqual(turnDataConn_->peer, true)) {
		sendTurnDataConn(reinterpret_cast<const char *>(m.raw.data()), m.raw.size());
		return;
	}

	// If the request came over TCP, send the response over the same TCP
	// transport. Check TCPMux first (passive side), then tcpTransport_ (active).
	if (tcpMux_) {
		int ret = tcpMux_->sendto(reinterpret_cast<const char *>(m.raw.data()),
		                          m.raw.size(), dst);
		if (ret > 0) return;
	}
	if (tcpTransport_ && tcpTransport_->state() == net::TcpState::Connected &&
	    dst.isEqual(tcpPeerAddr_, true)) {
		sendTcp(reinterpret_cast<const char *>(m.raw.data()), m.raw.size());
		return;
	}

	// If the destination is a remote relayed candidate, route the response
	// through our local TURN relay (the peer's TURN server won't forward
	// direct UDP to the relayed address without a permission).
	bool remoteIsRelayed = false;
	for (const auto &rc : remote_.candidates) {
		if (rc.type == CandidateType::Relayed && rc.resolved.isEqual(dst, true)) {
			remoteIsRelayed = true;
			break;
		}
	}
	if (remoteIsRelayed) {
		for (auto &re : entries_) {
			if (re.type == StunEntryType::Relay && re.turn) {
				re.turn->sendData(dst, m.raw.data(), m.raw.size());
				return;
			}
		}
	}
	sendUdp(reinterpret_cast<const char *>(m.raw.data()), m.raw.size(), dst);
}

bool Agent::verifyBindingRequest(const stun::Message &msg) {
	// USERNAME is "<sender's remote ufrag>:<sender's local ufrag>".
	// From the recipient's perspective that is "<our local ufrag>:<our remote ufrag>".
	auto username = stun::getString(msg, stun::AttrType::Username);
	auto pos = username.find(':');
	if (pos == std::string::npos) return false;
	std::string localUfrag = username.substr(0, pos);
	std::string remoteUfrag = username.substr(pos + 1);
	if (localUfrag != local_.iceUfrag) return false;
	if (!remote_.iceUfrag.empty() && remoteUfrag != remote_.iceUfrag) return false;
	// Verify MESSAGE-INTEGRITY using the local pwd (since request was
	// authenticated with the *recipient's* password = our local pwd).
	return msg.checkIntegrity(reinterpret_cast<const unsigned char *>(local_.icePwd.data()),
	                          local_.icePwd.size());
}

CandidatePair *Agent::findOrCreatePair(const net::AddrRecord &src, std::uint32_t priority,
                                       CandidateTransport transport) {
	// Look for an existing remote candidate matching `src` AND the transport
	// the request arrived on. Without the transport check, a UDP remote
	// candidate at the same address would be wrongly matched to an incoming
	// TCP check (and vice versa), producing a cross-transport pair that can
	// never succeed and confusing the pair state machine.
	bool srcIsTcp = (transport != CandidateTransport::UDP);
	const Candidate *remote = nullptr;
	for (const auto &c : remote_.candidates) {
		bool cIsTcp = (c.transport != CandidateTransport::UDP);
		if (c.resolved.isEqual(src, true) && cIsTcp == srcIsTcp) {
			remote = &c;
			break;
		}
	}
	if (!remote) {
		// Create a peer-reflexive remote candidate.
		if (remote_.candidates.size() >= MaxCandidates) return nullptr;
		Candidate c;
		c.type = CandidateType::PeerReflexive;
		c.transport = transport;
		c.component = 1;
		c.resolved = src;
		c.priority = priority;
		auto *sa = reinterpret_cast<const sockaddr *>(&src.addr);
		char host[NI_MAXHOST];
		char serv[NI_MAXSERV];
		getnameinfo(sa, net::addrLen(sa), host, sizeof(host), serv, sizeof(serv),
		            NI_NUMERICHOST | NI_NUMERICSERV);
		c.hostname = host;
		c.service = serv;
		c.foundation = Candidate::computeFoundation(c.type, c.hostname, c.transport);
		remote_.candidates.push_back(std::move(c));
		remote = &remote_.candidates.back();
	}
	// Find a local candidate to pair with. Prefer same family AND same
	// transport class (TCP with TCP, UDP with UDP). For TCP, the local
	// candidate may be TCPPassive/TCPActive/TCPSO while the incoming
	// transport is TCPActive — both are "TCP class" and should match.
	bool transportIsTcp = (transport != CandidateTransport::UDP);
	const Candidate *local = nullptr;
	for (const auto &l : local_.candidates) {
		bool localIsTcp = (l.transport != CandidateTransport::UDP);
		if (l.resolved.addr.ss_family == remote->resolved.addr.ss_family &&
		    localIsTcp == transportIsTcp) {
			local = &l;
			break;
		}
	}
	if (!local) {
		// No same-transport local candidate: do NOT fall back to a
		// cross-transport match (UDP local with TCP remote would violate
		// RFC 6544 §5.2 and the pair could never succeed). Returning
		// nullptr drops the incoming check instead of creating a broken
		// pair.
		return nullptr;
	}
	// Find or create the pair.
	for (auto &p : pairs_) {
		if (p->local == local && p->remote == remote) return p.get();
	}
	if (pairs_.size() >= MaxCandidatePairs) return nullptr;
	auto p = std::make_unique<CandidatePair>();
	p->local = local;
	p->remote = remote;
	p->state = PairState::Frozen;
	p->updatePriority(mode_ == AgentMode::Controlling);
	CandidatePair *out = p.get();
	pairs_.push_back(std::move(p));
	updateOrderedPairs();
	if (transportIsTcp) {
		STICE_LOG_INFO("ICE-TCP: created pair local=%s(%s) remote=%s(%s) priority=%u",
		               local->hostname.c_str(),
		               transportString(local->transport),
		               remote->hostname.c_str(),
		               transportString(remote->transport),
		               out->priority);
	}
	return out;
}

void Agent::handleBindingRequest(const stun::Message &msg, const net::AddrRecord &src,
                                 CandidateTransport transport) {
	STICE_LOG_DEBUG("handleBindingRequest: from=%s transport=%s tid=%02x%02x%02x%02x useCand=%d",
	                src.toString().c_str(), transportString(transport),
	                msg.transactionID[0], msg.transactionID[1], msg.transactionID[2], msg.transactionID[3],
	                static_cast<int>(stun::hasUseCandidate(msg)));
	// Verify integrity (unless this is an indication).
	if (!verifyBindingRequest(msg)) {
		STICE_LOG_DEBUG("handleBindingRequest: verification FAILED");
		// Send 401 if no integrity, else 400.
		int code = (msg.find(stun::AttrType::MessageIntegrity) == nullptr) ? 401 : 400;
		sendBindingResponse(msg, src, code);
		return;
	}
	STICE_LOG_DEBUG("handleBindingRequest: verification OK");

	// Role conflict handling (RFC 8445 §7.3.1.1).
	std::uint64_t peerTb = 0;
	if (msg.find(stun::AttrType::IceControlling)) {
		stun::readIceControlling(msg, peerTb);
		if (mode_ == AgentMode::Controlling) {
			if (tiebreaker_ >= peerTb) {
				// We win: tell peer to switch.
				sendBindingResponse(msg, src, 487);
				return;
			}
			mode_ = AgentMode::Controlled;
			updateOrderedPairs();
		}
	} else if (msg.find(stun::AttrType::IceControlled)) {
		stun::readIceControlled(msg, peerTb);
		if (mode_ == AgentMode::Controlled) {
			if (tiebreaker_ >= peerTb) {
				mode_ = AgentMode::Controlling;
				updateOrderedPairs();
			} else {
				sendBindingResponse(msg, src, 487);
				return;
			}
		}
	}

	// Read PRIORITY (for peer-reflexive learning).
	std::uint32_t priority = 0;
	stun::readPriority(msg, priority);
	bool useCandidate = stun::hasUseCandidate(msg);
	// draft-thatcher-ice-renomination: read NOMINATION value. When present
	// alongside USE-CANDIDATE, the controlled side tracks the highest value
	// seen for the pair and treats the pair as nominated only when the value
	// is strictly greater than the previously applied one. This lets the
	// controlling side switch the selected pair mid-session.
	std::uint32_t nominationValue = 0;
	bool hasNomination = stun::readNomination(msg, nominationValue);

	// Find or create the candidate pair.
	CandidatePair *pair = findOrCreatePair(src, priority, transport);
	if (!pair) {
		sendBindingResponse(msg, src, 500);
		return;
	}

	// USE-CANDIDATE: nominating.
	if (useCandidate) {
		if (hasNomination) {
			// Re-nomination draft: only apply when the value is strictly
			// greater than what we've already applied for this pair. This
			// guards against retransmitted/stale nomination requests
			// toggling the selected pair back.
			if (nominationValue > pair->nominationValue) {
				pair->nominationValue = nominationValue;
				if (pair->state == PairState::Succeeded) pair->nominated = true;
				else pair->nominationRequested = true;
			}
		} else {
			// Classic USE-CANDIDATE (RFC 8445): always nominate.
			if (pair->state == PairState::Succeeded) pair->nominated = true;
			else pair->nominationRequested = true;
		}
	}

	// Send success response.
	sendBindingResponse(msg, src, 0);

	// Triggered check: if pair not SUCCEEDED, queue a check.
	if (pair->state != PairState::Succeeded && !remote_.iceUfrag.empty()) {
		pair->state = PairState::Pending;
		StunEntry *e = findEntry(pair);
		if (!e && entries_.size() < MaxStunEntries) {
			StunEntry ne;
			ne.type = StunEntryType::Check;
			ne.state = StunEntryState::Pending;
			ne.pair = pair;
			ne.record = pair->remote->resolved;
			ne.mode = mode_;
			entries_.push_back(std::move(ne));
			e = &entries_.back();
		}
		if (e) {
			armTransmission(*e, StunPacingTimeMs);
			// Wake the agent's own PollRegistry so it picks up the new
			// entry immediately. Without this, the poll thread may sleep
			// for up to 60s (default timeout) and the triggered check
			// won't fire until then. This is critical when the binding
			// request arrived via TCPMux (on the TCPMux's poll thread)
			// — the agent's own poll thread is a separate thread that
			// has no idea a new entry was just armed.
			wakePoll();
		}
	}
}

void Agent::handleBindingResponse(const stun::Message &msg, const net::AddrRecord &src,
                                  StunEntry &e) {
	STICE_LOG_DEBUG("handleBindingResponse: from=%s cls=%d",
	                src.toString().c_str(), static_cast<int>(msg.cls));
	// Symmetric response check (RFC 8445 §7.2.5.2.1): response source must
	// match the request's destination. If mismatched, DISCARD the response
	// (do not mark the pair as Failed — the pair can still be retried).
	if (!e.record.isEqual(src, true)) {
		STICE_LOG_DEBUG("handleBindingResponse: src mismatch (expected %s got %s), discarding",
		                e.record.toString().c_str(), src.toString().c_str());
		return;
	}
	if (msg.cls == stun::Class::ErrorResponse) {
		int code = 0;
		std::string reason;
		stun::readErrorCode(msg, code, reason);
		if (code == 487) {
			// Role conflict: switch role. RFC 8445 §7.3.1.1 does not
			// require regenerating the tiebreaker — pion-ice preserves it.
			if (e.mode == mode_) {
				mode_ = (mode_ == AgentMode::Controlling) ? AgentMode::Controlled : AgentMode::Controlling;
				updateOrderedPairs();
				if (e.state != StunEntryState::Idle) {
					armTransmission(e, 0);
				}
			}
			return;
		}
		e.state = StunEntryState::Failed;
		if (e.pair) e.pair->state = PairState::Failed;
		// Arm the next frozen pair so connectivity checks continue,
		// and re-evaluate state (may transition to FAILED if all pairs
		// have failed). Without this, a 400 error response would leave
		// the agent stuck in CONNECTING with no pending timers.
		if (e.type == StunEntryType::Check) {
			armNextFrozenPair();
			wakePoll();
		}
		updateState();
		return;
	}
	// Success.
	if (e.pair) {
		e.pair->state = PairState::Succeeded;
		e.pair->consentExpiry = std::chrono::steady_clock::now() +
		                        std::chrono::milliseconds(ConsentTimeoutMs);
		if (e.pair->nominationRequested) e.pair->nominated = true;
		// Controlling-side nomination: select the best (highest-priority)
		// succeeded pair and schedule nomination with a candidate-type-based
		// delay (aligned with pion-ice defaultNominationDelay).
		if (mode_ == AgentMode::Controlling) {
			CandidatePair *best = nullptr;
			for (const auto &p : pairs_)
				if (p->state == PairState::Succeeded &&
				    (!best || p->priority > best->priority))
					best = p.get();
			if (best) {
				bool shouldNominate = false;
				if (!selectedPair_) {
					shouldNominate = true;
					// First nomination: start the counter at 1.
					++nominationValue_;
				} else if (best != selectedPair_ && best->priority > selectedPair_->priority) {
					// Re-nomination: a better pair succeeded after the current
					// selected pair. Switch and re-nominate (draft-thatcher).
					shouldNominate = true;
					++nominationValue_;
					STICE_LOG_DEBUG("renomination: switching to higher-priority pair (value=%u)",
					                nominationValue_);
				}
				if (shouldNominate) {
					selectedPair_ = best;
					// Acceptance min wait is now enforced in the periodic loop
					// via isNominatable(), aligned with pion-ice
					// ContactCandidates (selection.go L76). No timestamp
					// calculation needed here.
				}
			}
		}
		if (e.pair->nominated) nominatedPair_ = e.pair;
		armKeepalive(e);
		// When this response arrived via TCPMux (passive side), we're on
		// the TCPMux's poll thread, not the agent's own. Wake the agent's
		// poll thread so it picks up the keepalive timer and runs
		// updateState() via onBookkeeping to transition to CONNECTED.
		wakePoll();
	}
}

void Agent::handleServerReflexiveResponse(const stun::Message &msg,
                                          const net::AddrRecord &src, StunEntry &e) {
	// Validate response source: the STUN binding response must come from the
	// same server we sent the request to (RFC 5389 §7.3.1: "The response
	// MUST be from the same IP address from which the request was sent").
	// Without this check, a forged response with a guessed transaction ID
	// could inject a bogus reflexive address. e.record holds the server addr.
	if (!e.record.isEqual(src, false)) {
		STICE_LOG_WARN("Agent: STUN srflx response from wrong source %s (expected %s), ignoring",
		               src.toString().c_str(), e.record.toString().c_str());
		return;
	}
	if (msg.cls == stun::Class::ErrorResponse) {
		int code = 0;
		std::string reason;
		stun::readErrorCode(msg, code, reason);
		STICE_LOG_WARN("Agent: STUN binding error response: %d %s", code, reason.c_str());
		e.state = StunEntryState::Failed;
		--pendingServerReflexive_;
		checkGatheringComplete();
		return;
	}
	// Success: extract XOR-MAPPED-ADDRESS (or MAPPED-ADDRESS fallback).
	net::AddrRecord reflexive;
	if (!stun::readXorAddress(msg, stun::AttrType::XorMappedAddress, reflexive, msg.transactionID)) {
		if (!stun::readMappedAddress(msg, reflexive)) {
			STICE_LOG_WARN("Agent: STUN binding response missing XOR-MAPPED-ADDRESS");
			e.state = StunEntryState::Failed;
			--pendingServerReflexive_;
			checkGatheringComplete();
			return;
		}
	}
	// Create the srflx candidate.
	Candidate c;
	c.type = CandidateType::ServerReflexive;
	c.transport = CandidateTransport::UDP;
	c.component = 1;
	c.resolved = reflexive;
	auto *sa = reinterpret_cast<const sockaddr *>(&reflexive.addr);
	char host[NI_MAXHOST];
	char serv[NI_MAXSERV];
	getnameinfo(sa, net::addrLen(sa), host, sizeof(host), serv, sizeof(serv),
	            NI_NUMERICHOST | NI_NUMERICSERV);
	c.hostname = host;
	c.service = serv;
	if (boundAddrUdp(c.related)) c.hasRelated = true;
	c.priority = c.computePriority(0);
	c.foundation = Candidate::computeFoundation(c.type, c.hostname, c.transport);
	addLocalCandidate(c);
	emitCandidate(c);
	STICE_LOG_DEBUG("STUN srflx candidate gathered: %s:%s", host, serv);

	e.state = StunEntryState::Succeeded;
	--pendingServerReflexive_;
	checkGatheringComplete();
}

void Agent::handleStunMessage(const stun::Message &msg, const net::AddrRecord &src,
                              CandidateTransport transport) {
	if (msg.method != stun::Method::Binding) return;
	if (msg.cls == stun::Class::Request) {
		handleBindingRequest(msg, src, transport);
		return;
	}
	if (stun::isResponseType(msg.cls)) {
		// Find the entry with matching transaction ID.
		for (auto &e : entries_) {
			if (std::memcmp(e.transactionID.data(), msg.transactionID.data(), 12) == 0) {
				if (e.type == StunEntryType::Server)
					handleServerReflexiveResponse(msg, src, e);
				else
					handleBindingResponse(msg, src, e);
				return;
			}
		}
		return;
	}
	// Indication: ignore (or treat as keepalive).
}

void Agent::handleInboundUdp(const char *buf, int len, const net::AddrRecord &src,
                             CandidateTransport transport) {
	if (len <= 0) return;
	const auto *data = reinterpret_cast<const unsigned char *>(buf);
	STICE_LOG_DEBUG("handleInboundUdp: %d bytes from %s transport=%d", len, src.toString().c_str(),
	                static_cast<int>(transport));
	// Demux: STUN / ChannelData / app data.
	if (stun::Message::isMessage(data, static_cast<std::size_t>(len))) {
		stun::Message m;
		if (!m.decode(data, static_cast<std::size_t>(len))) return;
		if (m.method == stun::Method::Binding) {
			handleStunMessage(m, src, transport);
		} else {
			// TURN STUN response or indication (Allocate, CreatePermission,
			// ChannelBind, Refresh, Data, etc.): forward to all relay entries'
			// TURN clients. Each client checks if it has a matching pending TID.
			for (auto &e : entries_) {
				if (e.type == StunEntryType::Relay && e.turn) {
					e.turn->handleInbound(data, static_cast<std::size_t>(len));
				}
			}
		}
		return;
	}
	if (turn::isChannelData(data, static_cast<std::size_t>(len))) {
		// ChannelData from a TURN server: find the relay entry and let its
		// turn::Client decode it.
		for (auto &e : entries_) {
			if (e.type == StunEntryType::Relay && e.turn) {
				e.turn->handleInbound(data, static_cast<std::size_t>(len));
				return;
			}
		}
		return;
	}
	// Application data: deliver to the user.
	// Before delivering, find the candidate pair matching the source address
	// and update selectedPair_ if that pair has succeeded. Without this, the
	// response (via stice_send → sendViaSelectedPair) would go through
	// selectedPair_ which is the highest-priority succeeded pair — not
	// necessarily the pair that data arrived on. When multiple candidate
	// pairs have succeeded (e.g. after role conflict resolution), the
	// response could be sent to a different remote address than the one that
	// sent the data, causing the peer to never receive it.
	for (auto &p : pairs_) {
		if (p->state == PairState::Succeeded && p->remote &&
		    p->remote->resolved.isEqual(src, true)) {
			if (selectedPair_ != p.get()) {
				STICE_LOG_DEBUG("handleInboundUdp: updating selectedPair_ to match data source %s",
				                src.toString().c_str());
				selectedPair_ = p.get();
			}
			break;
		}
	}
	emitRecv(buf, static_cast<std::size_t>(len));
}

int Agent::sendUdp(const char *data, std::size_t size, const net::AddrRecord &dst) {
	if (mux_) return mux_->sendto(data, size, dst, local_.iceUfrag);
	return sock_.sendto(data, size, dst);
}

int Agent::sendTcp(const char *data, std::size_t size, const CandidatePair *pair) {
	const CandidatePair *p = pair ? pair : selectedPair_;
	// Route through TCPMux if the local candidate is TCPPassive.
	if (tcpMux_ && p && p->local &&
	    p->local->transport == CandidateTransport::TCPPassive && p->remote) {
		STICE_LOG_DEBUG("sendTcp: routing via TCPMux to %s (%zu bytes)",
		                p->remote->resolved.toString().c_str(), size);
		int ret = tcpMux_->sendto(data, size, p->remote->resolved);
		if (ret > 0) return ret;
		STICE_LOG_WARN("sendTcp: TCPMux sendto failed for %s (ret=%d)",
		               p->remote->resolved.toString().c_str(), ret);
		return STICE_ERR_FAILED;
	}
	if (!tcpTransport_ || tcpTransport_->state() != net::TcpState::Connected) {
		STICE_LOG_DEBUG("sendTcp: direct transport not connected (state=%d), dropping %zu bytes",
		                tcpTransport_ ? static_cast<int>(tcpTransport_->state()) : -1, size);
		return STICE_ERR_FAILED;
	}
	if (!tcpTransport_->send(data, size)) {
		STICE_LOG_WARN("sendTcp: direct transport send failed (%zu bytes)", size);
		return STICE_ERR_FAILED;
	}
	return static_cast<int>(size);
}

bool Agent::pairIsTcp(const CandidatePair *p) const {
	if (!p || !p->local || !p->remote) return false;
	return p->local->transport != CandidateTransport::UDP &&
	       p->remote->transport != CandidateTransport::UDP;
}

bool Agent::pairIsTurnTcpRelay(const CandidatePair *p) const {
	if (!p || !p->local) return false;
	return p->local->type == CandidateType::Relayed &&
	       p->local->transport == CandidateTransport::TCPPassive;
}

void Agent::handleInboundTcp() {
	if (!tcpTransport_) return;
	// Drain all complete RFC 4571-framed messages from the receive buffer.
	char buf[65536];
	net::AddrRecord peer;
	while (true) {
		int n = tcpTransport_->recv(buf, sizeof(buf), peer);
		if (n <= 0) break;
		handleInboundTcpPacket(buf, n, tcpPeerAddr_);
	}
}

void Agent::handleInboundTcpPacket(const char *data, int len, const net::AddrRecord &src) {
	const auto *udata = reinterpret_cast<const unsigned char *>(data);
	STICE_LOG_DEBUG("ICE-TCP: inbound packet %d bytes from %s", len, src.toString().c_str());
	// Demultiplex: STUN / app data (no ChannelData over ICE-TCP).
	if (stun::Message::isMessage(udata, static_cast<std::size_t>(len))) {
		stun::Message m;
		if (!m.decode(udata, static_cast<std::size_t>(len))) {
			STICE_LOG_WARN("ICE-TCP: STUN decode failed (%d bytes from %s)", len, src.toString().c_str());
			return;
		}
		STICE_LOG_DEBUG("ICE-TCP: STUN %s message (method=%d, class=%d) from %s",
		                m.method == stun::Method::Binding ? "Binding" : "Unknown",
		                static_cast<int>(m.method), static_cast<int>(m.cls),
		                src.toString().c_str());
		if (m.method == stun::Method::Binding) {
			// Transport is TCPActive: remote is the active connector
			// (we are passive listener side) OR we are the active
			// connector receiving a request from the passive side.
			handleStunMessage(m, src, CandidateTransport::TCPActive);
		}
		return;
	}
	// Application data: deliver to the user.
	STICE_LOG_DEBUG("ICE-TCP: application data %d bytes from %s", len, src.toString().c_str());
	emitRecv(data, static_cast<std::size_t>(len));
}

void Agent::addRemotePassiveTcpCandidate(const Candidate &remote) {
	// Aligned with pion-ice addRemotePassiveTCPCandidate: create a local
	// active TCP candidate by dialing the remote passive candidate's address.
	// We use a single tcpTransport_ per agent (limitation: only one TCP pair
	// at a time). If a transport already exists and is connected, skip.
	STICE_LOG_INFO("ICE-TCP: addRemotePassiveTcpCandidate host=%s:%s",
	               remote.hostname.c_str(), remote.service.c_str());
	if (tcpTransport_ && tcpTransport_->state() == net::TcpState::Connected) {
		STICE_LOG_DEBUG("ICE-TCP: TCP transport already connected, skipping new connect");
		return;
	}
	// If a previous (failed/disconnected) transport exists, clean it up first
	// to avoid fd leakage and duplicate PollRegistry registration.
	if (tcpTransport_) {
		STICE_LOG_DEBUG("ICE-TCP: resetting previous transport (state=%d) before new connect",
		                static_cast<int>(tcpTransport_->state()));
		tcpTransport_.reset();
	}
	// Resolve the remote candidate address if not already resolved.
	net::AddrRecord remoteAddr = remote.resolved;
	if (remoteAddr.len == 0) {
		auto records = resolveServer(remote.hostname,
		                             static_cast<std::uint16_t>(std::atoi(remote.service.c_str())),
		                             SOCK_STREAM);
		if (records.empty()) {
			STICE_LOG_WARN("ICE-TCP: failed to resolve remote passive candidate %s:%s",
			               remote.hostname.c_str(), remote.service.c_str());
			return;
		}
		remoteAddr = records[0];
	}
	STICE_LOG_INFO("ICE-TCP: beginning active TCP connect to %s", remoteAddr.toString().c_str());

	// Begin the non-blocking connect. The TcpTransport will complete the
	// connection asynchronously via onWritable callbacks from the PollRegistry.
	tcpTransport_ = std::make_unique<net::TcpTransport>();
	tcpPeerAddr_ = remoteAddr;
	// Store SNI for potential TLS upgrade (not used for plain ICE-TCP).
	tcpSni_ = remote.hostname;

	if (!tcpTransport_->beginConnect(remoteAddr, "", false)) {
		STICE_LOG_WARN("ICE-TCP: failed to begin TCP connect to %s (errno=%d)",
		               remoteAddr.toString().c_str(), sticeSockerrno);
		tcpTransport_.reset();
		return;
	}
	// Arm an application-layer connect timeout so a black-holed remote
	// (no SYN-ACK) does not leave the transport stuck in Connecting forever.
	tcpTransport_->setConnectTimeoutMs(TcpConnectTimeoutMs);

	// Create a local active TCP host candidate. The local address/port is
	// determined by the socket's local address after connect begins.
	net::AddrRecord localAddr{};
	// We don't know the local address yet (connect is async). We'll use a
	// placeholder and update it when the connection completes. For now,
	// create the candidate with the remote address's family.
	Candidate c;
	c.type = CandidateType::Host;
	c.transport = CandidateTransport::TCPActive;
	c.component = 1;
	c.resolved = remoteAddr; // placeholder; will be updated on connect
	// Get the local address from the socket (may be INADDR_ANY:ephemeral).
	auto localSock = tcpTransport_->handle();
	if (localSock != STICE_INVALID_SOCKET) {
		sockaddr_storage la{};
		socklen_t laLen = sizeof(la);
		if (getsockname(localSock, reinterpret_cast<sockaddr *>(&la), &laLen) == 0) {
			localAddr.addr = la;
			localAddr.len = laLen;
			localAddr.socktype = SOCK_STREAM;
			c.resolved = localAddr;
			auto *sa = reinterpret_cast<const sockaddr *>(&la);
			char host[NI_MAXHOST];
			char serv[NI_MAXSERV];
			if (getnameinfo(sa, net::addrLen(sa), host, sizeof(host), serv, sizeof(serv),
			                NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
				c.hostname = host;
				c.service = serv;
			}
		}
	}
	if (c.hostname.empty()) {
		c.hostname = "0.0.0.0";
		c.service = "0";
	}
	c.priority = c.computePriority(0);
	c.foundation = Candidate::computeFoundation(c.type, c.hostname, c.transport);
	addLocalCandidate(c);
	emitCandidate(c);

	// Register with the PollRegistry so we get onTcpEvents callbacks.
	// Register this Agent (with its TCP socket) on its own PollRegistry.
	// add() is idempotent (deduplicates by pointer), so this is safe if the
	// Agent was already registered from init().
	if (pollReg_) pollReg_->add(this);

	STICE_LOG_INFO("ICE-TCP: began active TCP connect to %s (local=%s:%s, fd=%d)",
	               remoteAddr.toString().c_str(), c.hostname.c_str(), c.service.c_str(),
	               static_cast<int>(tcpTransport_->handle()));
}

std::vector<net::AddrRecord> Agent::localAddrsUdp(int family) const {
	if (mux_) return mux_->localAddrs(family);
	return sock_.localAddrs(family);
}

bool Agent::boundAddrUdp(net::AddrRecord &out) const {
	if (mux_) return mux_->boundAddr(out);
	return sock_.boundAddr(out);
}

void Agent::registerWithMux() {
	if (!mux_ || muxRegistered_) return;
	muxRegistered_ = true;
	auto lifetime = lifetime_; // shared_ptr copy keeps guard alive
	mux_->registerAgent(
	    local_.iceUfrag,
	    [lifetime, this](const char *data, int len, const net::AddrRecord &src) {
		    LifetimeScope ls(lifetime);
		    if (!ls) return;
		    std::lock_guard<std::recursive_mutex> lock(mutex_);
		    handleInboundUdp(data, len, src);
	    },
	    [lifetime, this](int64_t nowMs) {
		    LifetimeScope ls(lifetime);
		    if (!ls) return;
		    std::lock_guard<std::recursive_mutex> lock(mutex_);
		    onBookkeeping(nowMs);
	    },
	    [lifetime, this]() -> int64_t {
		    LifetimeScope ls(lifetime);
		    if (!ls) return 0;
		    return nextTimestampMs();
	    });
}

void Agent::registerWithTcpMux() {
	if (!tcpMux_ || tcpMuxRegistered_) return;
	tcpMuxRegistered_ = true;
	STICE_LOG_INFO("ICE-TCP: registering agent with TCPMux (ufrag=%s)", local_.iceUfrag.c_str());
	auto lifetime = lifetime_;
	tcpMux_->registerAgent(
	    local_.iceUfrag,
	    [lifetime, this](const char *data, int len, const net::AddrRecord &src) {
		    LifetimeScope ls(lifetime);
		    if (!ls) return;
		    std::lock_guard<std::recursive_mutex> lock(mutex_);
		    handleInboundTcpPacket(data, len, src);
	    },
	    // TCPMux calls onBookkeeping for timer-driven agents. Since the
	    // agent is already registered with UDPMux (or its own socket) for
	    // bookkeeping, pass a no-op here to avoid double bookkeeping.
	    [](int64_t) {},
	    []() -> int64_t { return 0; });
}

void Agent::checkGatheringComplete() {
	if (pendingRelayAllocations_ > 0) return;
	if (pendingServerReflexive_ > 0) return;
	if (gatheringDone_) return;
	gatheringDone_ = true;
	local_.finished = true;
	emitGatheringDone();
	// If remote description was set before gathering finished, transition to CONNECTING.
	if (!remote_.iceUfrag.empty() && !remote_.icePwd.empty()) {
		formPairs();
		changeState(STICE_STATE_CONNECTING);
	}
}

void Agent::onUdpReadable() {
	// In UDPMux mode, the mux reads packets and calls handleInboundUdp
	// directly via the onPacket callback. This method is never called by
	// the PollRegistry because the agent is not registered as a participant.
	if (mux_) return;
	LifetimeScope ls(lifetime_);
	if (!ls) return;
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	STICE_LOG_DEBUG("onUdpReadable: fd=%d", static_cast<int>(sock_.handle()));
	char buf[1500];
	net::AddrRecord src;
	while (true) {
		int n = sock_.recvfrom(buf, sizeof(buf), src);
		if (n <= 0) break;
		handleInboundUdp(buf, n, src);
	}
}

void Agent::onTcpEvents(short events) {
	LifetimeScope ls(lifetime_);
	if (!ls) return;
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	if (!tcpTransport_) return;
	// Application-layer connect timeout: if the non-blocking connect has not
	// completed by the deadline, transition to Failed so the pair is failed
	// and the next frozen pair is armed. Without this, a black-holed remote
	// (no SYN-ACK) leaves the transport stuck in Connecting forever.
	if (tcpTransport_->connectTimedOut()) {
		STICE_LOG_WARN("ICE-TCP: connect timeout (peer=%s), failing transport",
		               tcpPeerAddr_.toString().c_str());
		tcpTransport_->close();
	}
	auto prevState = tcpTransport_->state();
	STICE_LOG_DEBUG("ICE-TCP: events=0x%x state=%d peer=%s",
	                static_cast<unsigned>(events),
	                static_cast<int>(prevState),
	                tcpPeerAddr_.toString().c_str());
	// Handle POLLERR/POLLHUP: some platforms report these without POLLIN/POLLOUT.
	// Trigger both readable/writable to let the transport detect the error via
	// recv() == 0 or send() < 0 or SO_ERROR, then transition to Failed/Disconnected.
	if (events & (POLLERR | POLLHUP)) {
		STICE_LOG_DEBUG("ICE-TCP: POLLERR/POLLHUP (0x%x), draining transport",
		                static_cast<unsigned>(events & (POLLERR | POLLHUP)));
		if (!(events & POLLIN)) tcpTransport_->onReadable();
		if (!(events & POLLOUT)) tcpTransport_->onWritable();
	}
	if (events & POLLOUT) tcpTransport_->onWritable();
	if (events & POLLIN) {
		tcpTransport_->onReadable();
		// Drain all complete RFC 4571-framed messages from the transport.
		handleInboundTcp();
	}
	// If the transport just transitioned to Connected, flush any pending
	// STUN checks that were queued for this pair.
	if (tcpTransport_->state() == net::TcpState::Connected) {
		if (prevState != net::TcpState::Connected) {
			STICE_LOG_INFO("ICE-TCP: transport Connected (peer=%s), arming pending CHECK entries",
			               tcpPeerAddr_.toString().c_str());
		}
		// Find any pending CHECK entries for TCP pairs and arm them.
		for (auto &e : entries_) {
			if (e.type == StunEntryType::Check && e.state == StunEntryState::Pending &&
			    e.pair && pairIsTcp(e.pair)) {
				// The entry may have been waiting for the TCP connection.
				// Reset its transmission timer to fire immediately, and apply
				// the TCP fixed timeout (StunTcpTimeoutMs, no backoff).
				if (e.retransmissions == 0) {
					e.nextTransmission = std::chrono::steady_clock::now();
					e.retransmissionTimeout = std::chrono::milliseconds(StunTcpTimeoutMs);
					STICE_LOG_DEBUG("ICE-TCP: armed CHECK entry for pair (local=%s remote=%s)",
					                e.pair->local ? e.pair->local->hostname.c_str() : "?",
					                e.pair->remote ? e.pair->remote->hostname.c_str() : "?");
					wakePoll();
				}
			}
		}
	} else if (tcpTransport_->state() == net::TcpState::Failed ||
	           tcpTransport_->state() == net::TcpState::Disconnected) {
		STICE_LOG_WARN("ICE-TCP: transport %s (peer=%s, prevState=%d), failing TCP pairs",
		               tcpTransport_->state() == net::TcpState::Failed ? "Failed" : "Disconnected",
		               tcpPeerAddr_.toString().c_str(),
		               static_cast<int>(prevState));
		// TCP connection failed or remote closed: mark TCP pairs as failed and
		// cancel their pending STUN entries so the bookkeeping loop doesn't
		// keep retrying on a dead transport.
		for (auto &p : pairs_) {
			if (pairIsTcp(p.get()) && p->state != PairState::Failed) {
				p->state = PairState::Failed;
			}
		}
		for (auto &e : entries_) {
			if (e.type == StunEntryType::Check && e.pair && pairIsTcp(e.pair) &&
			    e.state == StunEntryState::Pending) {
				e.state = StunEntryState::Failed;
			}
		}
		// Destroy the transport and close the fd to prevent fd leakage.
		// Aligns with onTurnTcpEvents which resets turnTcpTransport_ on failure.
		tcpTransport_.reset();
		updateState();
	}
}

void Agent::onTurnTcpEvents(short events) {
	LifetimeScope ls(lifetime_);
	if (!ls) return;
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	if (!turnTcpTransport_) return;
	// Application-layer connect timeout for TURN-over-TCP/TLS.
	if (turnTcpTransport_->connectTimedOut()) {
		STICE_LOG_WARN("TURN TCP: connect timeout, failing transport");
		turnTcpTransport_->close();
	}
	STICE_LOG_DEBUG("TURN TCP: events=0x%x state=%d",
	                static_cast<unsigned>(events),
	                static_cast<int>(turnTcpTransport_->state()));
	if (events & POLLOUT) {
		turnTcpTransport_->onWritable();
		// Check if the connection just completed.
		if (turnTcpTransport_->state() == net::TcpState::Connected) {
			STICE_LOG_INFO("TURN TCP: POLLOUT -> Connected transition");
			onTurnTcpConnected();
		}
	}
	if (events & POLLIN) {
		turnTcpTransport_->onReadable();
		handleInboundTurnTcp();
	}
	if (turnTcpTransport_ && (turnTcpTransport_->state() == net::TcpState::Failed ||
	    turnTcpTransport_->state() == net::TcpState::Disconnected)) {
		STICE_LOG_WARN("TURN TCP: connection lost (state=%d, events=0x%x)",
		               static_cast<int>(turnTcpTransport_->state()),
		               static_cast<unsigned>(events));
		// Mark the TURN entry as failed so allocation doesn't hang.
		if (turnTcpEntry_ && turnTcpEntry_->turn) {
			turnTcpEntry_->turn->handleInbound(nullptr, 0); // signal failure
		}
		turnTcpTransport_.reset();
	}
}

void Agent::handleInboundTurnTcp() {
	if (!turnTcpTransport_) return;
	// Drain raw bytes from the transport and feed them to StunConn for
	// self-delimited parsing (no RFC 4571 prefix for TURN over TCP).
	char buf[4096];
	net::AddrRecord peer; // unused for TCP
	int totalRaw = 0;
	while (true) {
		int n = turnTcpTransport_->recv(buf, sizeof(buf), peer);
		if (n <= 0) break;
		totalRaw += n;
		turnStunConn_.feed(reinterpret_cast<const unsigned char *>(buf),
		                   static_cast<std::size_t>(n));
	}
	if (totalRaw > 0) {
		STICE_LOG_DEBUG("TURN TCP: received %d raw bytes, draining frames", totalRaw);
	}
	// Pull complete frames and route to the TURN client.
	const unsigned char *frame = nullptr;
	int frameCount = 0;
	while (true) {
		std::size_t frameSize = turnStunConn_.readFrame(frame);
		if (frameSize == 0 || !frame) break;
		if (frameSize == static_cast<std::size_t>(-1)) {
			// StunConn detected invalid (non-STUN, non-ChannelData) data on
			// the TCP stream. Aligned with pion-turn's STUNConn which
			// returns errInvalidTURNFrame: treat this as a fatal stream
			// error. Signal failure to the TURN client and tear down the
			// transport so gathering doesn't hang on a corrupted stream.
			STICE_LOG_WARN("TURN TCP: invalid stream data, closing connection");
			if (turnTcpEntry_ && turnTcpEntry_->turn) {
				turnTcpEntry_->turn->handleInbound(nullptr, 0); // signal failure
			}
			turnTcpTransport_.reset();
			return;
		}
		++frameCount;
		STICE_LOG_DEBUG("TURN TCP: frame #%d (%zu bytes) -> TURN client", frameCount, frameSize);
		// Find the TURN StunEntry and deliver the frame.
		if (turnTcpEntry_ && turnTcpEntry_->turn) {
			turnTcpEntry_->turn->handleInbound(frame, frameSize);
		}
	}
}

bool Agent::beginTurnTcpConnect(const net::AddrRecord &turnServer, bool useTls,
                                const std::string &sni, bool skipVerify) {
	STICE_LOG_INFO("TURN TCP: beginning %s connect to %s (sni=%s skipVerify=%d)",
	               useTls ? "TLS" : "TCP", turnServer.toString().c_str(),
	               sni.c_str(), static_cast<int>(skipVerify));
	turnTcpTransport_ = std::make_unique<net::TcpTransport>();
	turnTcpTransport_->setFramingMode(net::FramingMode::Raw);
	if (!turnTcpTransport_->beginConnect(turnServer, sni, useTls, skipVerify)) {
		STICE_LOG_WARN("TURN TCP: failed to begin connect to %s (errno=%d)",
		               turnServer.toString().c_str(), sticeSockerrno);
		turnTcpTransport_.reset();
		// Signal the failure to the TURN Client so it transitions to
		// Failed, invokes onFailed, decrements pendingRelayAllocations_,
		// and allows gathering to complete. Without this, gathering hangs
		// forever when the TURN server is unreachable (e.g. ECONNREFUSED,
		// ENETUNREACH returned synchronously by connect()).
		if (turnTcpEntry_ && turnTcpEntry_->turn) {
			turnTcpEntry_->turn->handleInbound(nullptr, 0); // signal failure
		}
		return false;
	}
	// Arm an application-layer connect timeout so an unreachable TURN server
	// does not leave the transport stuck in Connecting forever.
	turnTcpTransport_->setConnectTimeoutMs(TcpConnectTimeoutMs);
	// Register this Agent (with its TURN TCP socket) on its own PollRegistry.
	// add() is idempotent (deduplicates by pointer).
	if (pollReg_) pollReg_->add(this);
	// If connect succeeded immediately (rare), trigger the connected callback.
	if (turnTcpTransport_->state() == net::TcpState::Connected) {
		STICE_LOG_INFO("TURN TCP: connect succeeded immediately (synchronous)");
		onTurnTcpConnected();
	} else {
		STICE_LOG_INFO("TURN TCP: connect pending (async), state=%d",
		               static_cast<int>(turnTcpTransport_->state()));
	}
	return true;
}

void Agent::onTurnTcpConnected() {
	STICE_LOG_INFO("TURN TCP: transport connected, sending ALLOCATE request");
	// The TURN client's allocate() was already called from gatherRelay.
	// Its first request was buffered in sendRaw (which detected that the
	// transport wasn't connected yet and sent via UDP as fallback, or
	// dropped). Re-trigger the allocation now by ticking the TURN client.
	if (turnTcpEntry_ && turnTcpEntry_->turn) {
		// Record allocation start time for RTT-based priority correction.
		auto now = std::chrono::steady_clock::now();
		turnTcpEntry_->allocateStartTime = now;
		if (turnTcpAllocStart_) *turnTcpAllocStart_ = now;
		// Re-send the allocate request now that the TCP transport is ready.
		turnTcpEntry_->turn->allocate();
		turnTcpEntry_->nextTransmission = turnTcpEntry_->turn->nextTick();
		wakePoll();
	}
}

// --- RFC 6062 TCP allocation data connection ---

bool Agent::hasTurnDataTcp() const {
	return turnDataConn_ && turnDataConn_->transport != nullptr;
}
socket_t Agent::turnDataTcpSocket() const {
	if (!turnDataConn_ || !turnDataConn_->transport) return STICE_INVALID_SOCKET;
	return turnDataConn_->transport->handle();
}
short Agent::turnDataDesiredEvents() const {
	if (!turnDataConn_ || !turnDataConn_->transport) return 0;
	if (turnDataConn_->transport->state() == net::TcpState::Connecting)
		return POLLOUT;
	return POLLIN;
}

bool Agent::shouldInitiateTcpConnect() const {
	// RFC 6062: use ufrag comparison to deterministically pick the CONNECT
	// initiator. This is necessary because both agents default to Controlling
	// (role conflict resolved later via 487), but CONNECT must happen before
	// STUN checks can flow through the TCP relay. Using ufrag comparison
	// ensures only one side sends CONNECT, matching libjuice's approach.
	if (remote_.iceUfrag.empty() || local_.iceUfrag.empty())
		return mode_ == AgentMode::Controlling;
	return local_.iceUfrag >= remote_.iceUfrag;
}

void Agent::beginTurnDataConnect(std::uint32_t connectionId, const net::AddrRecord &peer) {
	STICE_LOG_INFO("TURN data: opening data connection connId=%u peer=%s",
	               connectionId, peer.toString().c_str());
	// Close any existing data connection (one at a time for ICE).
	turnDataConn_.reset();
	turnDataConn_ = std::make_unique<TurnDataConn>();
	turnDataConn_->connectionId = connectionId;
	turnDataConn_->peer = peer;
	// RFC 6062 data connections are always TCP. The peer address may have
	// been parsed from a STUN XOR-PEER-ADDRESS attribute (which defaults
	// socktype to SOCK_DGRAM). Force SOCK_STREAM so that AddrRecord::isEqual
	// can match the remote relay candidate (which has SOCK_STREAM from SDP
	// parsing). Without this, findOrCreatePair fails to match the existing
	// relay candidate and creates a spurious PeerReflexive candidate, and
	// handleBindingResponse discards valid responses due to socktype mismatch.
	turnDataConn_->peer.socktype = SOCK_STREAM;
	turnDataConn_->connecting = true;
	turnDataConn_->transport = std::make_unique<net::TcpTransport>();
	turnDataConn_->transport->setFramingMode(net::FramingMode::Raw);
	// Connect to the same TURN server as the control connection.
	if (!turnTcpEntry_ || !turnTcpEntry_->turn) {
		STICE_LOG_WARN("TURN data: no control connection entry");
		turnDataConn_.reset();
		return;
	}
	// Reuse the TURN server address from the control connection's config.
	// We stored the server address in the StunEntry's record field.
	net::AddrRecord turnServer = turnTcpEntry_->record;
	if (!turnDataConn_->transport->beginConnect(turnServer, "", false, false)) {
		STICE_LOG_WARN("TURN data: failed to begin connect (errno=%d)", sticeSockerrno);
		turnDataConn_.reset();
		return;
	}
	turnDataConn_->transport->setConnectTimeoutMs(TcpConnectTimeoutMs);
	// Register this Agent (with its TURN data TCP socket) on its own
	// PollRegistry. add() is idempotent (deduplicates by pointer).
	if (pollReg_) pollReg_->add(this);
	// If connect succeeded immediately, send ConnectionBind now.
	if (turnDataConn_->transport->state() == net::TcpState::Connected) {
		sendTurnDataConnectionBind();
	}
}

void Agent::sendTurnDataConnectionBind() {
	if (!turnDataConn_ || !turnTcpEntry_ || !turnTcpEntry_->turn) return;
	auto raw = turnTcpEntry_->turn->buildConnectionBindRequest(turnDataConn_->connectionId);
	turnDataConn_->transport->send(reinterpret_cast<const char *>(raw.data()), raw.size());
	turnDataConn_->connectionBindSent = true;
	STICE_LOG_INFO("TURN data: sent CONNECTION-BIND connId=%u", turnDataConn_->connectionId);
}

int Agent::sendTurnDataConn(const char *data, std::size_t size) {
	if (!turnDataConn_ || !turnDataConn_->transport || !turnDataConn_->bound)
		return STICE_ERR_FAILED;
	// RFC 4571: 2-byte big-endian length prefix + payload.
	std::vector<char> framed(size + 2);
	framed[0] = static_cast<char>((size >> 8) & 0xFF);
	framed[1] = static_cast<char>(size & 0xFF);
	std::memcpy(framed.data() + 2, data, size);
	return turnDataConn_->transport->send(framed.data(), framed.size())
	           ? STICE_ERR_SUCCESS
	           : STICE_ERR_FAILED;
}

void Agent::onTurnDataTcpEvents(short events) {
	LifetimeScope ls(lifetime_);
	if (!ls) return;
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	if (!turnDataConn_ || !turnDataConn_->transport) return;
	if (turnDataConn_->transport->connectTimedOut()) {
		STICE_LOG_WARN("TURN data: connect timeout");
		turnDataConn_->transport->close();
	}
	if (events & POLLOUT) {
		turnDataConn_->transport->onWritable();
		if (turnDataConn_->transport->state() == net::TcpState::Connected && !turnDataConn_->connectionBindSent) {
			STICE_LOG_INFO("TURN data: connected, sending CONNECTION-BIND");
			sendTurnDataConnectionBind();
		}
	}
	if (events & POLLIN) {
		turnDataConn_->transport->onReadable();
		handleInboundTurnDataTcp();
	}
	if (turnDataConn_ && turnDataConn_->transport &&
	    (turnDataConn_->transport->state() == net::TcpState::Failed ||
	     turnDataConn_->transport->state() == net::TcpState::Disconnected)) {
		STICE_LOG_WARN("TURN data: connection lost (state=%d)",
		               static_cast<int>(turnDataConn_->transport->state()));
		turnDataConn_.reset();
	}
}

void Agent::handleInboundTurnDataTcp() {
	if (!turnDataConn_ || !turnDataConn_->transport) return;
	char buf[4096];
	net::AddrRecord peer; // unused
	while (true) {
		int n = turnDataConn_->transport->recv(buf, sizeof(buf), peer);
		if (n <= 0) break;
		if (!turnDataConn_->bound) {
			// Before binding: use StunConn to parse the CONNECTION-BIND
			// response (STUN framing on the TURN TCP control connection).
			turnDataConn_->stunConn.feed(
			    reinterpret_cast<const unsigned char *>(buf), n);
		} else {
			// After binding: the connection is a transparent tunnel.
			// All data uses RFC 4571 framing (2-byte length prefix).
			turnDataConn_->rfc4571Buf.insert(
			    turnDataConn_->rfc4571Buf.end(),
			    reinterpret_cast<unsigned char *>(buf),
			    reinterpret_cast<unsigned char *>(buf) + n);
		}
	}
	// Phase 1: parse StunConn frames (CONNECTION-BIND response).
	if (!turnDataConn_->bound) {
		while (true) {
			const unsigned char *frame = nullptr;
			std::size_t frameSize = turnDataConn_->stunConn.readFrame(frame);
			if (frameSize == 0 || !frame) break;
			if (frameSize == static_cast<std::size_t>(-1)) {
				STICE_LOG_WARN("TURN data: invalid frame before binding, closing");
				turnDataConn_->transport->close();
				return;
			}
			if (!stun::Message::isMessage(frame, frameSize)) continue;
			stun::Message m;
			if (!m.decode(frame, frameSize)) continue;
			if (stun::isResponseType(m.cls) && m.cls != stun::Class::ErrorResponse &&
			    m.method == stun::Method::ConnectionBind) {
				turnDataConn_->bound = true;
				turnDataConn_->connecting = false;
				STICE_LOG_INFO(
				    "TURN data: CONNECTION-BIND success, data conn established peer=%s",
				    turnDataConn_->peer.toString().c_str());
				// Immediately trigger the STUN connectivity check for the
				// TURN-TCP-relay pair. The check was suspended while the
				// data connection was being established; now that it's
				// bound, send the first STUN binding request right away
				// instead of waiting for the next bookkeeping tick.
				for (auto &e : entries_) {
					if (e.state == StunEntryState::Pending &&
					    e.type == StunEntryType::Check &&
					    pairIsTurnTcpRelay(e.pair)) {
						e.nextTransmission = std::chrono::steady_clock::now();
						e.retransmissions = 0;
						break;
					}
				}
				wakePoll();
			}
		}
	}
	// Phase 2: parse RFC 4571 frames (ICE STUN checks + app data).
	// The TURN data connection carries TCP-relayed traffic (RFC 6062). The
	// relay candidates on both sides are TCPPassive, so inbound STUN checks
	// and app data must be dispatched with CandidateTransport::TCPPassive.
	// Passing UDP (the default) would cause findOrCreatePair to fail matching
	// the remote TCPPassive relay candidate (cIsTcp != srcIsTcp), dropping
	// every STUN binding request and preventing the pair from succeeding.
	if (turnDataConn_->bound) {
		auto &bufRef = turnDataConn_->rfc4571Buf;
		std::size_t consumed = 0;
		while (bufRef.size() - consumed >= 2) {
			std::uint16_t len = (static_cast<std::uint16_t>(bufRef[consumed]) << 8) |
			                    bufRef[consumed + 1];
			if (bufRef.size() - consumed - 2 < len) break; // incomplete
			const char *payload =
			    reinterpret_cast<const char *>(bufRef.data() + consumed + 2);
			handleInboundUdp(payload, static_cast<int>(len),
			                 turnDataConn_->peer, CandidateTransport::TCPPassive);
			consumed += 2 + len;
		}
		if (consumed > 0) {
			bufRef.erase(bufRef.begin(), bufRef.begin() + consumed);
		}
	}
}

void Agent::onBookkeeping(int64_t nowMs) {
	LifetimeScope ls(lifetime_);
	if (!ls) return;
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	auto now = std::chrono::steady_clock::now();
	(void)nowMs;
	STICE_LOG_DEBUG("onBookkeeping: entries=%zu state=%d", entries_.size(), static_cast<int>(state_));

	// Enforce application-layer TCP connect timeouts. The poll loop may not
	// deliver onTcpEvents/onTurnTcpEvents for a black-holed connect (no
	// writable event ever fires), so the bookkeeping pass is the safety net.
	if (tcpTransport_ && tcpTransport_->connectTimedOut()) {
		STICE_LOG_WARN("ICE-TCP: connect timeout in bookkeeping (peer=%s)",
		               tcpPeerAddr_.toString().c_str());
		tcpTransport_->close();
	}
	if (turnTcpTransport_ && turnTcpTransport_->connectTimedOut()) {
		STICE_LOG_WARN("TURN TCP: connect timeout in bookkeeping");
		turnTcpTransport_->close();
	}

	// RFC 6062 CONNECT retry: if a previous CONNECT failed with 447 and the
	// retry delay has elapsed, re-send the CONNECT to the peer's relayed addr.
	if (pendingConnectRetry_ && now >= nextConnectRetry_) {
		pendingConnectRetry_ = false;
		STICE_LOG_INFO("RFC 6062: retrying CONNECT to peer=%s (attempt %d/%d)",
		               pendingConnectPeer_.toString().c_str(),
		               connectRetries_, MaxConnectRetries);
		if (turnTcpEntry_ && turnTcpEntry_->turn &&
		    turnTcpEntry_->turn->state() == turn::AllocState::Allocated) {
			turnTcpEntry_->turn->sendConnect(pendingConnectPeer_);
		}
	}

	// RFC 6062: if the TCP allocation was still pending when formPairs()
	// ran, the initial CONNECT was never sent. Retrigger it here once the
	// allocation transitions to Allocated. This fixes the race where
	// formPairs() is called before the TURN-TCP ALLOCATE response arrives.
	if (!tcpConnectSent_ && shouldInitiateTcpConnect() &&
	    turnTcpEntry_ && turnTcpEntry_->turn &&
	    turnTcpEntry_->turn->state() == turn::AllocState::Allocated &&
	    turnTcpEntry_->turn->isTcpAllocation()) {
		// Find the remote TCP relay candidate to CONNECT to.
		for (const auto &p : orderedPairs_) {
			if (p->remote && p->remote->type == CandidateType::Relayed &&
			    p->remote->transport == CandidateTransport::TCPPassive) {
				STICE_LOG_INFO("RFC 6062: deferred CONNECT to peer relayed=%s",
				               p->remote->resolved.toString().c_str());
				turnTcpEntry_->turn->ensurePermission(p->remote->resolved);
				turnTcpEntry_->turn->sendConnect(p->remote->resolved);
				tcpConnectSent_ = true;
				pendingConnectPeer_ = p->remote->resolved;
				break;
			}
		}
	}

	// Drive each STUN entry.
	for (auto &e : entries_) {
		if (e.state == StunEntryState::Pending) {
			STICE_LOG_DEBUG("  entry[%p]: state=%d nextTx=%lld now=%lld diff=%lld type=%d",
			                static_cast<void *>(&e),
			                static_cast<int>(e.state),
			                static_cast<long long>(toMs(e.nextTransmission)),
			                static_cast<long long>(toMs(now)),
			                static_cast<long long>(toMs(e.nextTransmission) - toMs(now)),
			                static_cast<int>(e.type));
		}
		if (e.state == StunEntryState::Pending && now >= e.nextTransmission) {
			// RFC 6544: TCP pairs use a single fixed timeout (StunTcpTimeoutMs).
			// TCP delivers retransmissions internally; we only retry once after
			// the full timeout to defend against silent connection death.
			bool isTcp = pairIsTcp(e.pair);
			// RFC 6062: TURN-over-TCP relay pairs need the full Mode-B setup
			// (CONNECT → CONNECTION-ATTEMPT → new TCP connect → CONNECTION-BIND)
			// before STUN checks can flow. Suspend the retransmission counter
			// while the data connection is being established, and give these
			// pairs a larger retransmission budget to accommodate the setup
			// latency (up to ~30s with 447 retries + data connect).
			bool isTurnTcpRelay = pairIsTurnTcpRelay(e.pair);
			bool turnTcpDataPending = isTurnTcpRelay &&
			    (!turnDataConn_ || !turnDataConn_->bound);
			if (turnTcpDataPending) {
				// Don't count this as a retransmission — just re-arm the
				// timer. The STUN check will be sent once the data connection
				// is bound (sendStunBinding routes through turnDataConn_).
				e.nextTransmission = now + std::chrono::milliseconds(StunTcpTimeoutMs);
				continue;
			}
			// Honor the configured max_check_retransmit for UDP pairs
			// (default 3-4). A lower value fails pairs faster at the
			// cost of resilience on lossy links.
			int maxRetrans;
			if (isTurnTcpRelay) {
				// RFC 6062: allow 3 retransmits (≈24s) for the data connection
				// to come up after CONNECTION-BIND, in case the first few STUN
				// checks are lost.
				maxRetrans = 3;
			} else if (isTcp) {
				maxRetrans = 1;
			} else if (pairingCfg_.max_check_retransmit > 0) {
				maxRetrans = pairingCfg_.max_check_retransmit;
			} else {
				maxRetrans = MaxStunCheckRetransmissions;
			}
			if (e.retransmissions >= maxRetrans) {
				e.state = StunEntryState::Failed;
				if (e.type == StunEntryType::Server) {
					--pendingServerReflexive_;
					checkGatheringComplete();
				}
				if (e.pair) e.pair->state = PairState::Failed;
				// Arm the next frozen pair so connectivity checks continue.
				if (e.type == StunEntryType::Check) {
					armNextFrozenPair();
				}
				continue;
			}
			if (e.type == StunEntryType::Server) {
				// Retransmit a simple STUN Binding request (no ICE attributes).
				stun::Message m = stun::buildBindingRequest();
				std::memcpy(m.transactionID.data(), e.transactionID.data(), 12);
				m.encode(nullptr, nullptr, "stice");
				sendUdp(reinterpret_cast<const char *>(m.raw.data()), m.raw.size(), e.record);
			} else {
				sendStunBinding(e, stun::Class::Request, 0);
			}
			++e.retransmissions;
			// TCP: keep the fixed timeout (no exponential backoff). UDP: double.
			if (!isTcp) {
				e.retransmissionTimeout = std::min(e.retransmissionTimeout * 2,
				                                   std::chrono::milliseconds(LastStunRetransmissionTimeoutMs));
			}
			e.nextTransmission = now + e.retransmissionTimeout;
		} else if (e.state == StunEntryState::SucceededKeepalive) {
			if (e.pair && e.pair->consentExpiry <= now) {
				// Consent expired.
				e.pair->state = PairState::Failed;
				e.state = StunEntryState::Failed;
				continue;
			}
			if (now >= e.nextTransmission) {
				sendKeepalive(e);
				armKeepalive(e);
			}
		}
		// Drive TURN client (Allocate retransmission, refresh, permissions).
		if (e.type == StunEntryType::Relay && e.turn) {
			auto nextTick = e.turn->tick();
			if (nextTick != std::chrono::steady_clock::time_point{})
				e.nextTransmission = nextTick;
			// If the TURN client failed (e.g. allocate timeout), clean up the
			// TURN-over-TCP transport to prevent fd leakage. This handles the
			// timeout path that onTurnTcpEvents doesn't see (the TCP connection
			// itself may still be alive when the STUN transaction times out).
			// Aligned with pion turn PR#513.
			if (e.turn->state() == turn::AllocState::Failed && turnTcpTransport_) {
				turnTcpTransport_.reset();
			}
		}
	}

	// Controlling-side nomination. Only arm once — after arming, the entry
	// loop handles retransmissions. Re-arming every cycle would reset the
	// transaction ID, causing the peer's response to never match.
	if (mode_ == AgentMode::Controlling && selectedPair_ &&
	    !selectedPair_->nominated && !selectedPair_->nominationRequested) {
		// Aligned with pion-ice ContactCandidates (selection.go L74-84):
		// nominate when the best valid pair is nominatable (both local and
		// remote have exceeded their acceptance min wait since checking
		// started). We also nominate when all checks are done (pendingCount
		// == 0) AND the pair is nominatable, to avoid waiting indefinitely
		// if no better pairs can appear.
		bool should_nominate = false;
		if (pairingCfg_.nomination_mode == IceNominationMode::AGGRESSIVE) {
			// Aggressive: nominate as soon as the pair is nominatable,
			// without waiting for better pairs. Matches pion-ice default.
			should_nominate = isNominatable(selectedPair_);
		} else if (pairingCfg_.nomination_mode == IceNominationMode::REGULAR_STABLE_CHECK &&
		           pairIsTcpRelay(selectedPair_)) {
			// Regular-stable-check: for TCP-relay pairs, require a
			// stability precheck window to elapse since the pair became
			// Succeeded before nominating. This avoids nominating a
			// flaky Mode-B link that fails shortly after the first
			// successful check. We approximate "pair became Succeeded"
			// by the consentExpiry timestamp (set when the response
			// succeeded) and require at least tcp_nomination_precheck
			// to have elapsed since then.
			//
			// Speed optimization: if application data (RTP/RTCP) has
			// flowed over this pair during the precheck window, the
			// link is demonstrably usable — end the precheck early
			// instead of waiting the full tcp_nomination_precheck.
			// Only when STUN succeeds but media never arrives do we
			// wait the full window before trusting the link.
			if (isNominatable(selectedPair_)) {
				auto succ_time = selectedPair_->consentExpiry -
				                 std::chrono::milliseconds(ConsentTimeoutMs);
				auto elapsed = std::chrono::steady_clock::now() - succ_time;
				bool precheck_expired = elapsed >= pairingCfg_.tcp_nomination_precheck;
				bool media_received = lastAppDataAt_.time_since_epoch().count() != 0 &&
				                      lastAppDataAt_ >= succ_time;
				should_nominate = precheck_expired || media_received;
			}
		} else {
			// REGULAR (and REGULAR_STABLE_CHECK for non-TCP pairs):
			// nominate when nominatable. UDP pairs need no extra wait.
			should_nominate = isNominatable(selectedPair_);
		}
		if (should_nominate) {
			selectedPair_->nominationRequested = true;
			StunEntry *e = findEntry(selectedPair_);
			if (e) armTransmission(*e, 0);
		}
	}

	// Once a pair is nominated, freeze all other pending pairs.
	if (nominatedPair_) {
		for (auto &p : pairs_) {
			if (p.get() != nominatedPair_ && p->state == PairState::Pending)
				p->state = PairState::Frozen;
		}
	}

	updateState();
}

// Count currently InProgress Check entries (Pending state with a Check
// type). Used by LIMITED_CONCURRENT to enforce max_concurrent_check.
std::size_t Agent::countInProgressChecks() const {
	std::size_t n = 0;
	for (const auto &e : entries_) {
		if (e.type == StunEntryType::Check &&
		    e.state == StunEntryState::Pending)
			++n;
	}
	return n;
}

// PHASED_UDP_FIRST: evaluate whether the UDP phase is over and the TCP
// phase should begin. Called from armNextFrozenPair before arming. When
// the transition happens, also triggers lazy RFC 6062 Mode-B allocation
// (if tcp_relay_fallback == ON_ALL_UDP_FAIL).
void Agent::maybeEnterTcpPhase() {
	if (pairingCfg_.schedule_mode != IceCheckScheduleMode::PHASED_UDP_FIRST)
		return;
	if (pairingCfg_.tcp_phase_entered) return;

	const auto now = std::chrono::steady_clock::now();
	bool timeout_expired = false;
	if (pairingCfg_.udp_phase_timeout.count() > 0 &&
	    pairingCfg_.udp_phase_start.time_since_epoch().count() != 0) {
		timeout_expired = (now - pairingCfg_.udp_phase_start) >=
		                  pairingCfg_.udp_phase_timeout;
	}
	// All UDP pairs failed?
	bool all_udp_failed = true;
	bool any_udp_pair = false;
	for (const auto &p : pairs_) {
		bool is_tcp_relay = pairIsTcpRelay(p.get());
		if (!is_tcp_relay) {
			any_udp_pair = true;
			if (p->state != PairState::Failed) {
				all_udp_failed = false;
				break;
			}
		}
	}
	// Enter TCP phase if: UDP phase timeout expired (and there are UDP
	// pairs), OR all UDP pairs have failed. If there are no UDP pairs at
	// all, enter immediately so TCP-relay-only sessions still progress.
	bool enter = (!any_udp_pair) || timeout_expired ||
	             (all_udp_failed && any_udp_pair);
	if (!enter) return;

	pairingCfg_.tcp_phase_entered = true;
	STICE_LOG_INFO("Agent: entering TCP-relay phase (timeout=%d all_udp_failed=%d)",
	               static_cast<int>(timeout_expired),
	               static_cast<int>(all_udp_failed && any_udp_pair));

	// Lazy RFC 6062 Mode-B allocation: if we have TURN TCP servers
	// configured but haven't created the allocation yet, do it now.
	if (pairingCfg_.tcp_relay_fallback == TcpRelayFallbackMode::ON_ALL_UDP_FAIL &&
	    !pairingCfg_.tcp_relay_allocation_created) {
		// gatherRelay for TCP-transport TURN servers deferred from
		// gatherCandidates is handled by createDeferredTcpRelayAllocations.
		createDeferredTcpRelayAllocations();
	}
}

// Create RFC 6062 Mode-B allocations that were deferred during
// gatherCandidates because tcp_relay_fallback == ON_ALL_UDP_FAIL.
void Agent::createDeferredTcpRelayAllocations() {
	if (pairingCfg_.tcp_relay_allocation_created) return;
	pairingCfg_.tcp_relay_allocation_created = true;
	for (std::size_t k = 0; k < deferredTcpTurnServers_.size(); ++k) {
		const auto &srv = deferredTcpTurnServers_[k];
		int idx = k < deferredTcpTurnIndices_.size() ? deferredTcpTurnIndices_[k] : 0;
		STICE_LOG_INFO("Agent: creating deferred RFC 6062 TCP allocation (server=%s:%u)",
		               srv.host ? srv.host : "", srv.port);
		gatherRelay(srv, idx);
	}
}

void Agent::armNextFrozenPair() {
	// PHASED_UDP_FIRST: gate TCP-relay pairs until the UDP phase ends.
	maybeEnterTcpPhase();

	// Refresh early-phase window state. The window opens on transition
	// to CONNECTING (changeState) and closes after early_phase_duration
	// elapses. While open, early_phase_max_concurrent overrides
	// max_concurrent_check to speed up the first wave of checks.
	if (pairingCfg_.early_phase_active) {
		auto now = std::chrono::steady_clock::now();
		if (pairingCfg_.checking_start.time_since_epoch().count() == 0 ||
		    (now - pairingCfg_.checking_start) >= pairingCfg_.early_phase_duration) {
			pairingCfg_.early_phase_active = false;
		}
	}
	const auto &cfg = pairingCfg_;

	// Determine how many pairs to arm this call based on schedule mode.
	std::size_t budget = 1; // default Ta pacing (one at a time)
	switch (cfg.schedule_mode) {
	case IceCheckScheduleMode::RFC8445_STRICT:
		// Arm as many frozen pairs as capacity allows.
		budget = MaxStunEntries;
		break;
	case IceCheckScheduleMode::SERIAL:
		budget = 1;
		break;
	case IceCheckScheduleMode::LIMITED_CONCURRENT: {
		std::size_t in_prog = countInProgressChecks();
		// Early-phase boost: use the larger early_phase_max_concurrent
		// during the early window, then fall back to max_concurrent_check.
		std::size_t base_cap = cfg.max_concurrent_check > 0
		                           ? cfg.max_concurrent_check
		                           : MaxStunEntries;
		std::size_t cap = base_cap;
		if (cfg.early_phase_active && cfg.early_phase_max_concurrent > 0) {
			std::size_t early_cap = cfg.early_phase_max_concurrent;
			if (early_cap > cap) cap = early_cap;
		}
		budget = (in_prog < cap) ? (cap - in_prog) : 0;
		break;
	}
	case IceCheckScheduleMode::PHASED_UDP_FIRST:
		// Same concurrency logic as LIMITED_CONCURRENT, but TCP-relay
		// pairs are skipped until tcp_phase_entered.
		{
			std::size_t in_prog = countInProgressChecks();
			std::size_t base_cap = cfg.max_concurrent_check > 0
			                           ? cfg.max_concurrent_check
			                           : MaxStunEntries;
			std::size_t cap = base_cap;
			if (cfg.early_phase_active && cfg.early_phase_max_concurrent > 0) {
				std::size_t early_cap = cfg.early_phase_max_concurrent;
				if (early_cap > cap) cap = early_cap;
			}
			budget = (in_prog < cap) ? (cap - in_prog) : 0;
		}
		break;
	}
	if (budget == 0) return;

	std::size_t armed = 0;
	for (auto *np : orderedPairs_) {
		if (np->state != PairState::Frozen) continue;
		// PHASED_UDP_FIRST: skip TCP-relay pairs until phase entered.
		if (cfg.schedule_mode == IceCheckScheduleMode::PHASED_UDP_FIRST &&
		    pairIsTcpRelay(np) && !cfg.tcp_phase_entered)
			continue;
		// DISABLE fallback: skip TCP-relay pairs entirely.
		if (cfg.tcp_relay_fallback == TcpRelayFallbackMode::DISABLE &&
		    pairIsTcpRelay(np))
			continue;
		bool found = false;
		for (auto &ce : entries_)
			if (ce.pair == np) { found = true; break; }
		if (!found && entries_.size() < MaxStunEntries) {
			StunEntry ne;
			ne.type = StunEntryType::Check;
			ne.state = StunEntryState::Pending;
			ne.pair = np;
			ne.record = np->remote->resolved;
			ne.mode = mode_;
			armTransmission(ne, StunPacingTimeMs);
			entries_.push_back(std::move(ne));
			++armed;
			if (armed >= budget) break;
		}
		// SERIAL: only one pair per call. Other modes fill the budget
		// via the armed counter above.
		if (cfg.schedule_mode == IceCheckScheduleMode::SERIAL) break;
	}
}

void Agent::updateState() {
	// Find best succeeded pair. Under STICKY_SELECTED, if the previously
	// selected pair was a TCP-relay link, prefer remaining TCP-relay
	// valid pairs over higher-priority UDP pairs — this keeps the link
	// on TCP-relay until every TCP-relay pair fails, avoiding flapping
	// between UDP and TCP-relay on transient UDP recovery. Only an
	// ICE-Restart resets this preference (see restart()).
	CandidatePair *best = nullptr;
	CandidatePair *best_tcp = nullptr;
	CandidatePair *best_udp = nullptr;
	bool sticky_tcp = pairingCfg_.reselect_policy == LinkReselectPolicy::STICKY_SELECTED &&
	                  selectedPair_ && pairIsTcpRelay(selectedPair_);
	for (auto &p : pairs_) {
		if (p->state != PairState::Succeeded) continue;
		if (pairIsTcpRelay(p.get())) {
			if (!best_tcp || p->priority > best_tcp->priority)
				best_tcp = p.get();
		} else {
			if (!best_udp || p->priority > best_udp->priority)
				best_udp = p.get();
		}
	}
	if (sticky_tcp) {
		// Prefer TCP-relay if any exists; fall back to UDP only when no
		// TCP-relay pair is currently Succeeded.
		best = best_tcp ? best_tcp : best_udp;
	} else {
		// RFC8445: pure highest-priority across all transports.
		best = best_tcp && (!best_udp || best_tcp->priority > best_udp->priority)
		           ? best_tcp
		           : best_udp;
	}
	if (best) {
		selectedPair_ = best;
		if (best->nominated) {
			nominatedPair_ = best;
			if (state_ == STICE_STATE_CONNECTING) {
				changeState(STICE_STATE_CONNECTED);
				changeState(STICE_STATE_COMPLETED);
			} else if (state_ == STICE_STATE_CONNECTED) {
				changeState(STICE_STATE_COMPLETED);
			}
		} else {
			if (state_ == STICE_STATE_CONNECTING) changeState(STICE_STATE_CONNECTED);
		}
		return;
	}
	// No succeeded pair. Check if all pairs failed.
	bool allFailed = true;
	for (const auto &p : pairs_) {
		if (p->state != PairState::Failed) { allFailed = false; break; }
	}
	// Transition to FAILED from CONNECTING, CONNECTED, or COMPLETED.
	// Consent expiry can cause all pairs to fail even after connection
	// was established — aligned with pion-ice (Connected→Disconnected→Failed).
	if (allFailed && !pairs_.empty() &&
	    (state_ == STICE_STATE_CONNECTING ||
	     state_ == STICE_STATE_CONNECTED ||
	     state_ == STICE_STATE_COMPLETED)) {
		changeState(STICE_STATE_FAILED);
	}
}

int Agent::send(const char *data, std::size_t size, int ds) {
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	lastAppDataAt_ = std::chrono::steady_clock::now();
	return sendViaSelectedPair(data, size, ds);
}

int Agent::sendViaSelectedPair(const char *data, std::size_t size, int ds) {
	if (!selectedPair_ || !selectedPair_->local || !selectedPair_->remote)
		return STICE_ERR_FAILED;

	// RFC 6062: route through TURN data connection for TCP-relayed pairs.
	// After CONNECTION-BIND, the data connection is a transparent tunnel.
	// App data is sent with RFC 4571 framing (the peer's
	// handleInboundTurnDataTcp parses it and delivers via handleInboundUdp).
	if (pairIsTurnTcpRelay(selectedPair_)) {
		return sendTurnDataConn(data, size);
	}

	// Route via TCP when the selected pair uses TCP transport (RFC 6544).
	// App data over ICE-TCP uses the same RFC 4571 framing as STUN messages.
	if (pairIsTcp(selectedPair_)) {
		return sendTcp(data, size, selectedPair_);
	}

	// Route via TURN relay when:
	//  (a) the local candidate is relayed (our relayed address is the source), OR
	//  (b) the remote candidate is relayed AND we have a TURN allocation.
	//      Direct UDP to a relayed remote address is dropped by the remote
	//      TURN server unless it has a permission for our source address.
	//      Routing through our own relay makes the traffic appear to come
	//      from our relayed address, which the remote can permission.
	// This mirrors the routing decision in sendStunBinding so that app data
	// follows the same path as connectivity checks.
	bool routeViaRelay = (selectedPair_->local->type == CandidateType::Relayed);
	if (!routeViaRelay && selectedPair_->remote->type == CandidateType::Relayed) {
		for (const auto &re : entries_) {
			if (re.type == StunEntryType::Relay && re.turn &&
			    re.turn->state() == turn::AllocState::Allocated) {
				routeViaRelay = true;
				break;
			}
		}
	}
	if (routeViaRelay) {
		for (auto &e : entries_) {
			if (e.type == StunEntryType::Relay && e.turn &&
			    e.turn->state() == turn::AllocState::Allocated) {
				STICE_LOG_DEBUG("TURN: routing app data via relay -> %s (%zu bytes)",
				                selectedPair_->remote->resolved.toString().c_str(), size);
				e.turn->sendData(selectedPair_->remote->resolved,
				                 reinterpret_cast<const unsigned char *>(data), size);
				return static_cast<int>(size);
			}
		}
		STICE_LOG_WARN("TURN: routeViaRelay=true but no allocated relay entry found");
		return STICE_ERR_FAILED;
	}

	// Direct UDP send.
	STICE_LOG_DEBUG("sendViaSelectedPair: direct UDP -> %s (%zu bytes)",
	                selectedPair_->remote->resolved.toString().c_str(), size);
	if (ds >= 0) {
		if (mux_) mux_->setDiffserv(ds);
		else sock_.setDiffserv(ds);
	}
	int n = sendUdp(data, size, selectedPair_->remote->resolved);
	if (ds >= 0) {
		if (mux_) mux_->setDiffserv(0);
		else sock_.setDiffserv(0); // reset
	}
	// Follow libjuice convention: on failure, return -errno so the C API
	// wrapper can distinguish EAGAIN/EMSGSIZE from other errors.
	if (n < 0) return -sticeSockerrno;
	return n;
}

int Agent::getSelectedCandidates(char *local, std::size_t localSize, char *remote,
                                 std::size_t remoteSize) const {
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	if (!selectedPair_) return STICE_ERR_NOT_AVAIL;
	std::string ls = selectedPair_->local ? selectedPair_->local->toSdp() : "";
	std::string rs = selectedPair_->remote ? selectedPair_->remote->toSdp() : "";
	// Allow caller to request only local or only remote by passing NULL+0 for the other.
	if (local && ls.size() + 1 > localSize) return STICE_ERR_TOO_LARGE;
	if (remote && rs.size() + 1 > remoteSize) return STICE_ERR_TOO_LARGE;
	if (local) {
		std::memcpy(local, ls.data(), ls.size());
		local[ls.size()] = '\0';
	}
	if (remote) {
		std::memcpy(remote, rs.data(), rs.size());
		remote[rs.size()] = '\0';
	}
	return STICE_ERR_SUCCESS;
}

int Agent::getSelectedAddresses(char *local, std::size_t localSize, char *remote,
                                std::size_t remoteSize) const {
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	if (!selectedPair_ || !selectedPair_->local || !selectedPair_->remote) return STICE_ERR_NOT_AVAIL;
	std::string la = selectedPair_->local->resolved.toString();
	std::string ra = selectedPair_->remote->resolved.toString();
	// Allow caller to request only local or only remote by passing NULL+0 for the other.
	if (local && la.size() + 1 > localSize) return STICE_ERR_TOO_LARGE;
	if (remote && ra.size() + 1 > remoteSize) return STICE_ERR_TOO_LARGE;
	if (local) {
		std::memcpy(local, la.data(), la.size());
		local[la.size()] = '\0';
	}
	if (remote) {
		std::memcpy(remote, ra.data(), ra.size());
		remote[ra.size()] = '\0';
	}
	return STICE_ERR_SUCCESS;
}

} // namespace stice::ice
