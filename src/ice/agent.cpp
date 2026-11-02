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
#include <cstdlib>
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
		// draft-thatcher-ice-renomination is an opt-in escape hatch only: nothing
		// negotiates it, so the default is RFC 8445 §8.1.1 strict — an agent
		// nominates once and MUST NOT switch afterwards (only an ICE restart may).
		bool renominationAllowed() {
			static const bool allowed = []() {
				const char* v = std::getenv("STICE_ICE_RENOMINATION");
				return v && v[0] == '1';
			}();
			return allowed;
		}
		std::string tidKey(const std::array<unsigned char, 12>& tid) {
			return std::string(reinterpret_cast<const char*>(tid.data()), 12);
		}
		// P1-N3: nomination state is part of the pair lifecycle and dies with the
		// pair. A pair revived from Failed (ICE-TCP redial) must not inherit
		// nomination flags — the controlled side would otherwise report COMPLETED
		// without a fresh UseCandidate, and the controlling side's re-nomination
		// block is gated on the same flags.
		void resetNomination(CandidatePair& p) {
			p.nominated = false;
			p.nominationRequested = false;
			p.nominationValue = 0;
		}
		int64_t toMs(std::chrono::steady_clock::time_point tp) {
			return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
		}
		// RFC 8489 §14.5: discard messages whose FINGERPRINT is present but
		// wrong. Missing FINGERPRINT is tolerated for legacy peers; STICE_FP_STRICT=0
		// downgrades the drop to a log for grayscale rollout.
		bool fingerprintAcceptable(const stun::Message& m, const char* where) {
			static const bool strict = []() {
				const char* v = std::getenv("STICE_FP_STRICT");
				return !(v && v[0] == '0');
			}();
			if (m.checkFingerprint(true)) return true;
			if (strict) {
				STICE_LOG_WARN("%s: FINGERPRINT mismatch, dropping message", where);
				return false;
			}
			STICE_LOG_DEBUG("%s: FINGERPRINT mismatch tolerated (STICE_FP_STRICT=0)", where);
			return true;
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
		// Stop the gather worker before touching any members. This MUST be bounded:
		// an unbounded join here is exactly what made stice_destroy hang forever
		// when the worker got stuck (observed: teardown mid-gather never returned).
		//
		// Why detaching after the timeout is safe:
		//   * the DNS phase runs on detached resolver threads that capture only
		//     by-value copies (item/socktype/slot) and never touch the Agent, and
		//     the worker's wait for them is bounded - so a stuck worker cannot be
		//     sitting on Agent state there;
		//   * the entry-building phase acquires the agent lock with a BOUNDED
		//     budget (GatherLockTimeoutMs) and re-checks *gatherCancel per item, so
		//     its LifetimeScope is never held indefinitely - which is what makes
		//     the drain below unable to hang on it. (An earlier revision let this
		//     phase block on Agent::mutex_ without a bound; a wedged mutex holder
		//     then orphaned the scope and ~Agent's drain blocked forever.)
		//   * the cancel/done flags are shared_ptrs handed to the worker by value,
		//     so reading/setting them after this object dies is still valid.
		if (gatherCancel_) gatherCancel_->store(true, std::memory_order_release);
		if (gatherWorker_.joinable()) {
			const auto deadline = std::chrono::steady_clock::now() +
				std::chrono::milliseconds(GatherWorkerJoinTimeoutMs);
			while (std::chrono::steady_clock::now() < deadline &&
			       !(gatherWorkerDone_ && gatherWorkerDone_->load(std::memory_order_acquire))) {
				std::this_thread::sleep_for(std::chrono::milliseconds(2));
			}
			if (gatherWorkerDone_ && gatherWorkerDone_->load(std::memory_order_acquire)) {
				gatherWorker_.join();
			} else {
				STICE_LOG_ERROR("~Agent agent=%p: gather worker did not exit within %d ms; detaching it (it cannot be holding Agent state at this point)",
				                (void*)this, GatherWorkerJoinTimeoutMs);
				gatherWorker_.detach();
			}
		}
		// Detach from the PollRegistry FIRST and sync so the poll thread has
		// finished its current iteration and will never touch this Agent again.
		// The poll thread reads our members (hasTurnTcp()/turnTcpSocket()/
		// turnTcpDesiredEvents()/hasTcp()/tcpSocket(), entries_, ...) WITHOUT
		// Agent::mutex_ while building its pollfd set and dispatching, so no
		// member mutation below may start before it stops. Running
		// cancelAllEntries() first raced turnTcpTransport_.reset() (store null
		// + delete) against the poll thread's unlocked reads, dereferencing a
		// freed TcpTransport and crashing the process on teardown bursts.
		if (pollReg_) {
			pollReg_->remove(this);
			pollReg_->sync();
		}
		cancelAllEntries();
		if (lifetime_ && !lifetime_->shutdown()) {
			// Bounded drain timed out: an async callback is still inside this
			// agent (or was detached mid-flight). Proceeding is deliberate - an
			// unbounded wait here is exactly what made teardown hang forever - but
			// it is a real anomaly, so make it loud and specific.
			STICE_LOG_ERROR("~Agent agent=%p: %d async callback(s) still in flight after %d ms; proceeding with teardown (bounded)",
			                (void*)this, lifetime_->inFlightCount(), LifetimeDrainTimeoutMs);
		}
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
		// All members are torn down; now release the PollRegistry. With the shared
		// pool this is a no-op (instances are process-lifetime).
		if (pollReg_) {
			pollReg_->release();
			pollReg_ = nullptr;
		}
	}
	void Agent::cancelAllEntries() {
		// Acquire the mutex: the poll thread may be mid-callback (onBookkeeping)
		// and we must not race on entries_/tcpConns_ while cancelling.
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		// Cancel every STUN entry so the bookkeeping loop will never fire it
		// again. StunEntryState::Cancelled entries are skipped by onBookkeeping.
		for (auto& e : entries_) {
			e.state = StunEntryState::Cancelled;
		}
		// Tear down TURN allocations: send Refresh(LIFETIME=0) to release the
		// relayed address on the server immediately (RFC 8656 §7). This runs
		// BEFORE the lifetime barrier so the sendRaw callback (which checks
		// lifetime_->alive) still succeeds and the transport is still open.
		for (auto& e : entries_) {
			if (e.type == StunEntryType::Relay && e.turn &&
				e.turn->state() == turn::AllocState::Allocated) {
				STICE_LOG_INFO("Agent destroy: deallocating TURN relay (Refresh LIFETIME=0)");
				e.turn->deallocate();
			}
		}
		// Close TCP transports so their poll registrations stop firing.
		tcpConns_.clear();
		for (auto& e : entries_)
			if (e.type == StunEntryType::Relay && e.turnTcp)
				e.turnTcp->close();
	}
	bool Agent::init(const stice_config_t* cfg, stice_agent_t* self) {
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
					stunServersInternal_.push_back({ std::string(config_.stun_servers[i]),
												   p ? p : static_cast<uint16_t>(3478) });
				}
			}
		}
		else if (config_.stun_server_host) {
			// Copy the legacy single STUN server into internal storage so we
			// own the string. The config_.stun_server_host pointer is borrowed
			// from the caller and may become dangling after init() returns.
			uint16_t p = config_.stun_server_port ? config_.stun_server_port : 3478;
			stunServersInternal_.push_back({ std::string(config_.stun_server_host),
										   p ? p : static_cast<uint16_t>(3478) });
			config_.stun_server_host = nullptr; // prevent use-after-free in gatherCandidatesInternal
		}
		// Deep-copy the TURN server array into owned stable storage. The C API
		// config_.turn_servers points into caller memory (e.g. a temporary array
		// in the libjuice compat layer) that may dangle after init() returns.
		// Copying into turnServersInternal_ mirrors addTurnServer's pattern so
		// host/username/password stay valid for the Agent's lifetime.
		if (config_.turn_servers && config_.turn_servers_count > 0) {
			turnServersInternal_.reserve(config_.turn_servers_count);
			for (int i = 0; i < config_.turn_servers_count; ++i) {
				const stice_turn_server_t& srv = config_.turn_servers[i];
				stice_turn_server_t ts = srv;
				if (srv.host) {
					turnServerHostStorage_.emplace_back(srv.host);
					ts.host = turnServerHostStorage_.back().c_str();
				}
				if (srv.username) {
					turnServerUserStorage_.emplace_back(srv.username);
					ts.username = turnServerUserStorage_.back().c_str();
				}
				if (srv.password) {
					turnServerPassStorage_.emplace_back(srv.password);
					ts.password = turnServerPassStorage_.back().c_str();
				}
				if (srv.ca_file) {
					turnServerCaStorage_.emplace_back(srv.ca_file);
					ts.ca_file = turnServerCaStorage_.back().c_str();
				}
				turnServersInternal_.push_back(ts);
			}
			config_.turn_servers = turnServersInternal_.data();
		}
		// Generate local ufrag/pwd unless caller overrides via set_local_ice_attributes.
		local_.iceUfrag = generateUfrag();
		local_.icePwd = generatePwd();
		// draft-ietf-ice-trickle §3: only advertise the "trickle" ice-option when
		// the session actually trickles. The token is part of the local
		// description handed to the application, so it must reflect the
		// configured mode at gather time.
		local_.trickleEnabled = pairingCfg_.enable_trickle;
		// candidates is std::deque (see Description): push_back never
		// invalidates pointers into it, so CandidatePair's raw local/remote
		// pointers stay valid as trickle candidates arrive after pairing.
		// entries_ is std::deque (see agent.hpp): push_back/erase never move
		// OTHER elements, so raw StunEntry* handles captured by relay-entry sink
		// callbacks stay valid for the entry's lifetime. A vector realloc or
		// erase-shift would dangle them (previous turnTcpEntry_ design risk).
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
	int Agent::setUDPMux(net::UDPMux* mux) {
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
				// Sync before release: ensure the poll thread has finished its
				// current iteration on this Agent before sock_.close() below.
				pollReg_->sync();
				pollReg_->release();
				pollReg_ = nullptr;
			}
			// Close under sendMutex_ so it can never race an outbound sendto
			// running outside mutex_ in Agent::send (UAF / EBADF guard).
			{
				std::lock_guard<std::mutex> sl(sendMutex_);
				sock_.close();
			}
		}
		mux_ = mux;
		return STICE_ERR_SUCCESS;
	}
	int Agent::setTCPMux(net::TCPMux* mux) {
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		if (state_ != STICE_STATE_DISCONNECTED && state_ != STICE_STATE_FAILED) {
			return STICE_ERR_FAILED;
		}
		if (!mux) return STICE_ERR_INVALID;
		tcpMux_ = mux;
		STICE_LOG_INFO("Agent: TCPMux set (iceTcpMode=%d)", static_cast<int>(iceTcpMode_));
		return STICE_ERR_SUCCESS;
	}
	int Agent::setPairingConfig(const IcePairingConfig& cfg) {
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
		// Snapshot under the agent lock like nextTimestampMs()/onUdpReadable() do:
		// these getters run on the poll thread and must not rely on the implicit
		// happens-before of "write tcpConns_ then pollReg_->add(this)", which any
		// future writer that forgets the add() would silently break (data race).
		// Prefer a connected connection so the legacy single slot is the one that
		// actually carries data; fall back to the first entry.
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		for (const auto &c : tcpConns_)
			if (c.transport && c.transport->state() == net::TcpState::Connected)
				return c.transport->handle();
		for (const auto &c : tcpConns_)
			if (c.transport) return c.transport->handle();
		return STICE_INVALID_SOCKET;
	}
	short Agent::tcpDesiredEvents() const {
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		for (const auto &c : tcpConns_) {
			if (!c.transport) continue;
			short ev = POLLIN;
			if (c.transport->wantsWrite()) ev |= POLLOUT;
			return ev;
		}
		return 0;
	}
	int Agent::iceTcpSlotCount() const {
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		return static_cast<int>(tcpConns_.size());
	}
	socket_t Agent::iceTcpSocketAt(int i) const {
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		if (i < 0 || i >= static_cast<int>(tcpConns_.size())) return STICE_INVALID_SOCKET;
		const auto &c = tcpConns_[static_cast<std::size_t>(i)];
		return c.transport ? c.transport->handle() : STICE_INVALID_SOCKET;
	}
	short Agent::iceTcpDesiredEventsAt(int i) const {
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		if (i < 0 || i >= static_cast<int>(tcpConns_.size())) return 0;
		const auto &c = tcpConns_[static_cast<std::size_t>(i)];
		if (!c.transport) return 0;
		short ev = POLLIN;
		if (c.transport->wantsWrite()) ev |= POLLOUT;
		return ev;
	}
	void Agent::onIceTcpEventsSock(socket_t sock, short events) {
		LifetimeScope ls(lifetime_);
		if (!ls) return;
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		// Re-find by fd: an earlier callback in this dispatch batch may have
		// changed the connection list, so an index would be stale.
		TcpConnection *conn = findTcpConnBySocket(sock);
		if (!conn) return;
		onTcpConnEvents(*conn, events);
	}
	Agent::TcpConnection *Agent::findTcpConnBySocket(socket_t sock) {
		for (auto &c : tcpConns_)
			if (c.transport && c.transport->handle() == sock) return &c;
		return nullptr;
	}
	Agent::TcpConnection *Agent::tcpConnForPair(const CandidatePair *pair) {
		if (!pair) return nullptr;
		for (auto &c : tcpConns_)
			if (c.pair == pair) return &c;
		if (pair->remote) {
			for (auto &c : tcpConns_) {
				if (c.peerAddr.isEqual(pair->remote->resolved, true)) {
					c.pair = const_cast<CandidatePair *>(pair);
					return &c;
				}
			}
		}
		return nullptr;
	}
	Agent::TcpConnection *Agent::primaryTcpConn() {
		for (auto &c : tcpConns_)
			if (c.transport && c.transport->state() == net::TcpState::Connected) return &c;
		for (auto &c : tcpConns_)
			if (c.transport) return &c;
		return nullptr;
	}
	bool Agent::hasConnectedTcpForPair(const CandidatePair *pair) const {
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		for (const auto &c : tcpConns_) {
			if (!c.transport || c.transport->state() != net::TcpState::Connected) continue;
			if (!pair) return true;
			if (c.pair == pair) return true;
			if (pair->remote && c.peerAddr.isEqual(pair->remote->resolved, true)) return true;
		}
		return false;
	}
	int64_t Agent::nextTimestampMs() const {
	// Called by the poll thread under the registry mutex_; snapshot agent state here to avoid a cross-thread data race (TSan)
	std::lock_guard<std::recursive_mutex> lock(mutex_);
		// Return the ABSOLUTE timestamp (ms since steady_clock epoch) of the
		// earliest pending entry's next transmission. The PollRegistry computes
		// (nextTimestampMs - nowMs) to derive the poll timeout, so we MUST return
		// an absolute value here, not a relative delta. Returning a relative delta
		// would make (delta - nowMs) hugely negative, clamping the timeout to 0
		// and causing the poll loop to spin at 100% CPU without advancing real
		// time toward nextTransmission.
		auto t = std::chrono::steady_clock::time_point::max();
		bool hasPending = false;
		for (const auto& e : entries_) {
			if (e.state == StunEntryState::Pending || e.state == StunEntryState::SucceededKeepalive ||
				(e.type == StunEntryType::Relay && e.state == StunEntryState::Idle)) {
				hasPending = true;
				if (e.nextTransmission < t) t = e.nextTransmission;
			}
		}
		// Controlling-side nomination deadline. isNominatable() becomes true at
		// checkingStartTime_ + max(acceptanceMinWait(local), acceptanceMinWait(remote)),
		// but nomination is only armed inside onBookkeeping, which only runs when
		// the poll thread wakes. If all entries have transitioned to
		// SucceededKeepalive and the peer (controlled agent awaiting
		// USE-CANDIDATE) goes silent, no inbound traffic wakes the poll — the
		// next wake would be the keepalive deadline, delaying nomination (and
		// everything gated on it: DTLS/SCTP handshake, peer "connected") by the
		// full keepalive period. Expose the deadline so the poll wakes exactly
		// when the selected pair becomes nominatable.
		if (mode_ == AgentMode::Controlling && selectedPair_ &&
			!selectedPair_->nominated && !selectedPair_->nominationRequested &&
			selectedPair_->local && selectedPair_->remote) {
			auto wait = std::max(acceptanceMinWaitMs(selectedPair_->local->type),
				acceptanceMinWaitMs(selectedPair_->remote->type));
			auto t_nom = checkingStartTime_ + wait;
			if (t_nom < t) {
				hasPending = true;
				t = t_nom;
			}
		}
		// Account for in-progress TCP connects and scheduled redials. A black-
		// holed connect (e.g. unroutable TURN-over-TCP server) never fires a poll
		// event, so without exposing the deadline here the poll loop would sleep
		// until its 60 s clamp and the bookkeeping pass (which detects the
		// timeout) would run far too late, hanging gathering.
		for (const auto& c : tcpConns_) {
			if (c.reconnectPending) {
				if (!hasPending || c.nextReconnect < t) {
					hasPending = true;
					t = c.nextReconnect;
				}
				continue;
			}
			if (!c.transport) continue;
			if (c.transport->state() == net::TcpState::Connecting ||
				c.transport->state() == net::TcpState::TlsHandshaking) {
				int64_t dl = c.transport->connectDeadlineMs(); // -1 = none (atomic)
				if (dl > 0) {
					auto dlTp = std::chrono::steady_clock::time_point{ std::chrono::milliseconds(dl) };
					if (!hasPending || dlTp < t) {
						hasPending = true;
						t = dlTp;
					}
				}
			}
		}
		for (const auto& e : entries_) {
			if (e.type == StunEntryType::Relay && e.tcpTurn && e.turnTcp &&
				(e.turnTcp->state() == net::TcpState::Connecting ||
					e.turnTcp->state() == net::TcpState::TlsHandshaking)) {
				int64_t dl = e.turnTcp->connectDeadlineMs(); // -1 = none (atomic)
				if (dl > 0) {
					auto dlTp = std::chrono::steady_clock::time_point{ std::chrono::milliseconds(dl) };
					if (!hasPending || dlTp < t) {
						hasPending = true;
						t = dlTp;
					}
				}
			}
		}
		// Account for pending CONNECT retry timer (RFC 6062).
		if (pendingConnectRetry_ && nextConnectRetry_ < t) {
			hasPending = true;
			t = nextConnectRetry_;
		}
		// Account for pending data-connection retry timer (RFC 6062 CONNECTION-BIND).
		if (pendingTurnDataRetry_ && nextTurnDataRetry_ < t) {
			hasPending = true;
			t = nextTurnDataRetry_;
		}
		// Soft gathering deadline: if srflx/relay entries stay pending, poll MUST
		// wake at gatherStartedAt_ + GatherTimeoutMs so onBookkeeping can force
		// gathering complete. Otherwise a stuck srflx entry could let the poll
		// sleep past the deadline and the gathering would never complete.
		if (!gatheringDone_ && gatherStartedAt_.time_since_epoch().count() != 0) {
			auto dlTp = gatherStartedAt_ + std::chrono::milliseconds(GatherTimeoutMs);
			if (!hasPending || dlTp < t) { hasPending = true; t = dlTp; }
		}
		// RFC 8863 PAC deadline: while patiently awaiting connectivity every pair
		// has already failed, so no entry is armed and nothing else is pending -
		// without exposing this the poll thread would never wake to perform the
		// final Running -> Failed transition.
		if (pacDeadline_.time_since_epoch().count() != 0) {
			if (!hasPending || pacDeadline_ < t) {
				hasPending = true;
				t = pacDeadline_;
			}
		}
		if (!hasPending) return 0; // 0 = no pending timer (per PollParticipant contract)
		return toMs(t);            // absolute; if <= nowMs, computeTimeoutMs clamps to 0
	}
	void Agent::changeState(stice_state_t newState) {
		if (state_ == newState) return;
		state_ = newState;
		// The new generation is established (or dead): a peer's next credential
		// change is a new restart, not the completion of this one.
		if (newState == STICE_STATE_CONNECTED || newState == STICE_STATE_COMPLETED ||
			newState == STICE_STATE_FAILED)
			restartingLocally_ = false;
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
			for (const auto& c : local_.candidates) {
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
	static bool pairIsTcpRelay(const CandidatePair* p) {
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
	bool Agent::isNominatable(const CandidatePair* pair) const {
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
	void Agent::emitCandidate(const Candidate& c) {
		if (!config_.cb_candidate) return;
		// RFC 8838 §4: once the end-of-candidates indication has been sent the
		// agent MUST NOT generate any more candidates. Late TCP-active
		// candidates are the RFC 6544 §7.1 exception: they are created in
		// response to a remote passive candidate after local gathering, and
		// dropping them would silently lose the only usable TCP path.
		if (pairingCfg_.enable_trickle && gatheringDone_ &&
			c.transport != CandidateTransport::TCPActive) {
			STICE_LOG_DEBUG("emitCandidate: gathering done (EOC sent), suppressing late %s candidate",
				c.hostname.c_str());
			return;
		}
		std::string sdp = c.toSdp();
		// enable_trickle=false (non-trickle ICE): hold the candidate until
		// gathering completes so the application receives the full candidate
		// set in one batch. Candidates gathered after the batch (e.g. an active
		// TCP candidate created from a trickled remote passive candidate) are
		// still delivered immediately — dropping them would silently lose a
		// usable path.
		if (!pairingCfg_.enable_trickle && !gatheringDone_) {
			deferredCandidates_.push_back(std::move(sdp));
			return;
		}
		config_.cb_candidate(self_, sdp.c_str(), config_.user_ptr);
	}
	void Agent::flushDeferredCandidates() {
		for (const auto& sdp : deferredCandidates_)
			if (config_.cb_candidate) config_.cb_candidate(self_, sdp.c_str(), config_.user_ptr);
		deferredCandidates_.clear();
	}
	void Agent::emitGatheringDone() {
		if (config_.cb_gathering_done) config_.cb_gathering_done(self_, config_.user_ptr);
	}
	void Agent::emitRecv(const char* data, std::size_t size, CandidatePair* onPair) {
		const auto now = std::chrono::steady_clock::now();
		lastAppDataAt_ = now;
		// N-7: inbound application data is live traffic on the pair that carried
		// it, yet only outbound sends used to refresh the consent window — a
		// one-way media stream therefore let that pair expire at 30 s even though
		// the peer was demonstrably reachable. Refresh the delivering pair (or the
		// selected pair when the transport could not name one), and only when it
		// has actually succeeded.
		CandidatePair* p = onPair ? onPair : selectedPair_;
		if (p && p->state == PairState::Succeeded)
			p->consentExpiry = now + std::chrono::milliseconds(ConsentTimeoutMs);
		if (config_.cb_recv) config_.cb_recv(self_, data, size, config_.user_ptr);
	}
	std::vector<net::AddrRecord> Agent::resolveServer(const std::string& host, std::uint16_t port,
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
		for (auto& r : records) out.push_back(std::move(r));
		return out;
	}
	void Agent::addLocalCandidate(Candidate c) {
		// RFC 8445 §5.1.3: candidates that describe the same transport address
		// are redundant and must not be added twice. Without this, two STUN
		// servers behind the same NAT mapping produced two identical srflx
		// candidates with the same priority, and multi-homed gathering could add
		// the same host address more than once.
		for (const auto& existing : local_.candidates) {
			if (existing.type == c.type && existing.transport == c.transport &&
				existing.component == c.component &&
				existing.resolved.isEqual(c.resolved, true))
				return;
		}
		if (local_.candidates.size() >= MaxCandidates) {
			STICE_LOG_WARN("Agent: local candidate limit (%zu) reached, dropping %s:%s",
				static_cast<std::size_t>(MaxCandidates), c.hostname.c_str(), c.service.c_str());
			return;
		}
		local_.candidates.push_back(std::move(c));
		// Sort only before any pair is formed: stable_sort permutes elements,
		// which would silently change which candidate an existing pair's
		// `local` pointer refers to. Pair priority is computed per-pair, so the
		// list order is irrelevant once checking has started. `pairs_.empty()` is
		// checked too because GATHERING can already have formed pairs (see the
		// incremental pairing branch below), which would otherwise leave the
		// sort running after Candidate* values were captured by a pair.
		if ((state_ == STICE_STATE_DISCONNECTED || state_ == STICE_STATE_GATHERING) &&
			pairs_.empty())
			local_.sortCandidates();
		// Late local candidate (e.g. a second TURN server's allocation succeeded
		// while checks are already running, or local candidate gathered after the
		// remote description triggered early pair formation): pair it
		// incrementally with all remote candidates. formPairs dedups by pointer
		// identity, so existing pairs are untouched.
		if (state_ == STICE_STATE_CONNECTING || state_ == STICE_STATE_CONNECTED ||
			state_ == STICE_STATE_COMPLETED) {
			formPairs();
		}
		else if (state_ == STICE_STATE_GATHERING && !remote_.iceUfrag.empty() &&
			!remote_.icePwd.empty() && !remote_.candidates.empty()) {
			// Remote description is already available while we are still
			// gathering (e.g. a slow/dead TURN server keeps the gathering phase
			// open). Pair with what we have now instead of waiting for the
			// gathering-done gate, which used to leave a pairing gap for the
			// whole gathering window.
			std::size_t before = pairs_.size();
			formPairs();
			if (pairs_.size() > before) changeState(STICE_STATE_CONNECTING);
		}
	}
	// Semantic comparison of two IP literals, so a whitelist/blacklist entry
	// matches regardless of spelling: "::1" vs "0:0:0:0:0:0:0:1", or a
	// link-local written with a zone ("fe80::1%3", as getnameinfo may render it).
	// A raw string compare silently missed those. Non-literals (i.e. neither side
	// parses) fall back to an exact string compare.
	static bool ipLiteralEqual(const std::string& a, const std::string& b) {
		unsigned char ba[16] = {0}, bb[16] = {0};
		int fa = 0, fb = 0;
		auto parse = [](const std::string& s, unsigned char* out, int& fam) -> bool {
			std::string t = s;
			auto pct = t.find('%'); // strip an IPv6 zone id
			if (pct != std::string::npos) t = t.substr(0, pct);
			if (t.empty()) return false;
			if (inet_pton(AF_INET, t.c_str(), out) == 1) { fam = AF_INET; return true; }
			if (inet_pton(AF_INET6, t.c_str(), out) == 1) { fam = AF_INET6; return true; }
			return false;
		};
		if (parse(a, ba, fa) && parse(b, bb, fb)) {
			if (fa != fb) return false;
			return std::memcmp(ba, bb, (fa == AF_INET) ? 4u : 16u) == 0;
		}
		return a == b;
	}

	void Agent::gatherHostCandidates() {
		// UDP gathering disabled (TCP-only ICE testing, RFC 6544): emit no UDP
		// host candidate at all. A local UDP candidate is the only way a UDP
		// pair can form (formPairs rejects cross-transport pairs), so skipping
		// gathering here deterministically removes the UDP path. TCP passive
		// candidates below are still gathered when a TCPMux is bound.
		std::vector<net::AddrRecord> addrs;
		if (config_.disable_udp_gathering || config_.relay_only_local) {
			STICE_LOG_INFO("Agent: UDP gathering disabled, skipping UDP host candidates");
		}
		else {
			addrs = localAddrsUdp(AF_UNSPEC);
		}
		// Apply interface IP whitelist/blacklist filtering (pion #779).
		// Whitelist takes precedence: if set, only listed IPs are kept.
		if (config_.interface_whitelist || config_.interface_blacklist) {
			std::vector<net::AddrRecord> filtered;
			filtered.reserve(addrs.size());
			for (const auto& a : addrs) {
				char host[NI_MAXHOST];
				auto* sa = reinterpret_cast<const sockaddr*>(&a.addr);
				if (getnameinfo(sa, net::addrLen(sa), host, sizeof(host), nullptr, 0,
					NI_NUMERICHOST) != 0)
					continue;
				std::string ip(host);
				bool allowed = true;
				if (config_.interface_whitelist) {
					allowed = false;
					for (auto p = config_.interface_whitelist; *p; ++p) {
						if (ipLiteralEqual(ip, *p)) {
							allowed = true;
							break;
						}
					}
					if (!allowed)
						STICE_LOG_DEBUG("gatherHostCandidates: %s not in whitelist, skipping", ip.c_str());
				}
				if (allowed && config_.interface_blacklist) {
					for (auto p = config_.interface_blacklist; *p; ++p) {
						if (ipLiteralEqual(ip, *p)) {
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
		for (const auto& a : addrs) {
			Candidate c;
			c.type = CandidateType::Host;
			c.transport = CandidateTransport::UDP;
			c.component = 1;
			c.resolved = a;
			c.hostname = a.toString(); // "host:port"
			// Extract host and port separately.
			auto* sa = reinterpret_cast<const sockaddr*>(&a.addr);
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
			for (auto& cc : candidates) {
				// In QueryAndGather mode, advertise the candidate under an mDNS
				// name instead of its IP. §3.1 requires a DISTINCT name per
				// address: reusing one name for every interface would let a peer
				// correlate all of them into a single device.
				if (mdnsMode_ == STICE_MDNS_MODE_QUERY_AND_GATHER && mdns_) {
					auto* msa = reinterpret_cast<const sockaddr*>(&cc.resolved.addr);
					char ipStr[NI_MAXHOST];
					if (getnameinfo(msa, net::addrLen(msa), ipStr, sizeof(ipStr), nullptr, 0,
					                NI_NUMERICHOST) != 0) {
						// Without a numeric host we cannot register a record, and
						// emitting the candidate would advertise its real IP —
						// exactly what QueryAndGather exists to avoid. Drop it.
						STICE_LOG_WARN("mDNS: cannot name local address, skipping candidate to avoid leaking its IP");
						continue;
					}
					std::string hn = net::MDnsClient::generateHostname();
					if (!mdns_->addRecord(hn, ipStr)) {
						STICE_LOG_WARN("mDNS: addRecord failed for local address, skipping candidate");
						continue;
					}
					cc.hostname = hn;
				}
				addLocalCandidate(cc);
				emitCandidate(cc);
			}
		}
		// Gather TCP passive host candidates if a TCPMux is configured and
		// iceTcpMode_ includes PASSIVE. The candidate address is the TCPMux's
		// listener address/port, enumerated over local interfaces (mirrors
		// pion-ice's TCPMuxAddr).
		//
		// SO (experimental, "AUTO" semantics): stice only implements the
		// symmetric-breakout *framework* (codec, priority table, pairing rules),
		// so an SO agent gathers PASSIVE candidates and lets the peer's active
		// side dial. Emitting `tcptype so` candidates and the dual-connect
		// dedupe state machine are not implemented; see README's protocol table.
		if (tcpMux_ && (iceTcpMode_ == STICE_ICE_TCP_MODE_PASSIVE ||
			iceTcpMode_ == STICE_ICE_TCP_MODE_SO)) {
			auto tcpAddrs = tcpMux_->localAddrs(AF_UNSPEC);
			int tcpIdx = 0;
			for (const auto& a : tcpAddrs) {
				Candidate c;
				c.type = CandidateType::Host;
				c.transport = CandidateTransport::TCPPassive;
				c.component = 1;
				c.resolved = a;
				auto* sa = reinterpret_cast<const sockaddr*>(&a.addr);
				char host[NI_MAXHOST];
				char serv[NI_MAXSERV];
				bool numeric = getnameinfo(sa, net::addrLen(sa), host, sizeof(host), serv, sizeof(serv),
					NI_NUMERICHOST | NI_NUMERICSERV) == 0;
				if (numeric) {
					c.hostname = host;
					c.service = serv;
				}
				else {
					c.hostname = a.toString();
				}
				// QueryAndGather must advertise the listener under an mDNS name
				// like every other host candidate, not its real address.
				if (mdnsMode_ == STICE_MDNS_MODE_QUERY_AND_GATHER && mdns_) {
					if (!numeric) {
						STICE_LOG_WARN("mDNS: cannot name TCP listener address, skipping candidate");
						continue;
					}
					std::string hn = net::MDnsClient::generateHostname();
					if (!mdns_->addRecord(hn, host)) {
						STICE_LOG_WARN("mDNS: addRecord failed for TCP listener, skipping candidate");
						continue;
					}
					c.hostname = hn;
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
	void Agent::gatherServerReflexive(const char* host, uint16_t port) {
		if (!host) return;
		std::uint16_t stunPort = port ? port : 3478;
		auto servers = resolveServer(host, stunPort, SOCK_DGRAM);
		if (servers.empty()) {
			STICE_LOG_WARN("Agent: could not resolve STUN server %s", host);
			return;
		}
		createServerReflexiveEntry(host, stunPort, servers[0]);
	}
	void Agent::createServerReflexiveEntry(const std::string& host, uint16_t port,
		const net::AddrRecord& resolved) {
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
		int sent = sendUdp(reinterpret_cast<const char*>(m.raw.data()), m.raw.size(), resolved, /*control=*/true);
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
	void Agent::gatherRelay(const stice_turn_server_t& srv, int serverIndex) {
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
	void Agent::createRelayEntry(const stice_turn_server_t& srv, int serverIndex,
		const net::AddrRecord& resolved) {
		// Called from the gather worker thread; entries_ is also traversed by the
		// poll thread (onBookkeeping / turnTcpSlotCount etc.) — hold the agent
		// lock so the push_back / state mutation is not a cross-thread race.
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		std::uint16_t port = srv.port ? srv.port : 3478;
		bool useTcp = (srv.transport == STICE_TURN_TRANSPORT_TCP ||
			srv.transport == STICE_TURN_TRANSPORT_TLS);
		const char* transportName = useTcp
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
		bool rfc6062Relay = false; // true only for an opt-in RFC 6062 TCP allocation
		if (srv.transport == STICE_TURN_TRANSPORT_TCP || srv.transport == STICE_TURN_TRANSPORT_TLS) {
			// RFC 6062 (REQUESTED-TRANSPORT=TCP(6), relaying TCP data
			// connections) is opt-in via STICE_TURN_TCP_RFC6062=1: only
			// stice<->stice speaks it. The default is RFC 8656: the relayed
			// transport stays UDP even though the control connection is carried
			// over TCP/TLS (what browsers and coturn interoperate with).
			const char* rfc6062 = std::getenv("STICE_TURN_TCP_RFC6062");
			rfc6062Relay = rfc6062 && rfc6062[0] == '1';
			tc.tcpAllocation = rfc6062Relay;
			if (srv.transport == STICE_TURN_TRANSPORT_TCP) {
				tc.transport = turn::TurnTransport::TCP;
			}
			else {
				tc.transport = turn::TurnTransport::TLS;
				tc.sni = srv.host;
			}
		}
		turn::TurnSink sink;
		// Shared so a 300 Try Alternate redirect (RFC 8489 §14.11) can retarget
		// the send path before the client retries the Allocate.
		auto turnServerAddr = std::make_shared<net::AddrRecord>(resolved);
		auto lifetime = lifetime_;
		// Per-entry TURN-over-TCP/TLS control transport (RFC 8656 control-over-TCP
		// and RFC 6062). Created here so the sendRaw closure shares it; the transport
		// is also stored on the StunEntry (e.turnTcp) so multiple TCP/TLS TURN servers
		// can allocate concurrently (A1 containerization).
		std::shared_ptr<net::TcpTransport> turnTcp;
		if (useTcp) {
			turnTcp = std::make_shared<net::TcpTransport>();
			turnTcp->setFramingMode(net::FramingMode::Raw);
		}
		sink.sendRaw = [lifetime, this, turnServerAddr, useTcp, turnTcp](const unsigned char* data, std::size_t size) -> int {
			LifetimeScope ls(lifetime);
			if (!ls) return -1;
			// Route the raw STUN/ChannelData frame to the TURN server. For
			// TCP/TLS, use the dedicated turnTcpTransport_ (Raw framing); for
			// UDP, send through the agent's UDP socket (or shared mux).
			int ret = -1;
			if (useTcp) {
				if (turnTcp && turnTcp->state() == net::TcpState::Connected) {
					// Signalling STUN frames (Allocate/Refresh/CreatePermission/
					// ChannelBind/Connect) jump ahead of bulk ChannelData on the
					// same control connection: head-of-line blocking of Refresh
					// under a data flood made coturn expire the allocation.
					// ChannelData (first byte 0x40-0x7F) is not a STUN message
					// (RFC 8483 requires the leading 2 bits to be 0) and keeps
					// FIFO ordering behind the bulk data queue.
					bool isControl = stun::Message::isMessage(data, size);
					bool ok = isControl ? turnTcp->sendControl(reinterpret_cast<const char*>(data),
						size)
						: turnTcp->send(reinterpret_cast<const char*>(data), size);
					if (ok)
						ret = static_cast<int>(size);
					else
						// D2: send() rejected the write because the backlog hit the
						// high watermark (peer stalled). Surface EWOULDBLOCK so the
						// app gets backpressure (STICE_ERR_AGAIN), matching the UDP
						// path — instead of a silent drop or a hard FAILED.
						ret = -STICE_SEWOULDBLOCK;
				}
				else {
					STICE_LOG_DEBUG("TURN sendRaw: TCP transport not ready, dropping %zu bytes", size);
				}
			}
			else {
				// STUN control frames (Allocate/Refresh/CreatePermission/ChannelBind)
				// get UDP control-frame priority; ChannelData bulk keeps FIFO behind.
				bool isControl = stun::Message::isMessage(data, size);
				ret = sendUdp(reinterpret_cast<const char*>(data), size, *turnServerAddr,
					isControl);
				// Propagate the platform errno (negated) so data-path callers can
				// surface EAGAIN/ENOBUFS backpressure instead of silent drops.
				if (ret < 0) ret = -sticeSockerrno;
			}
			STICE_LOG_DEBUG("TURN sendRaw: %zu bytes to %s ret=%d", size, turnServerAddr->toString().c_str(), ret);
			return ret;
			};
		// Shared allocation start time for RTT measurement. For UDP TURN, it is
		// set just before allocate() below. For TCP TURN, it is set in
		// onTurnTcpConnected (via turnTcpAllocStart_).
		auto allocStart = std::make_shared<std::chrono::steady_clock::time_point>();
		// Terminal-event guard: pendingRelayAllocations_ is decremented exactly once
		// per entry by the first of onAllocated/onFailed to fire (C1).
		auto relayCounted = std::make_shared<std::atomic<bool>>(false);
		sink.onAllocated = [lifetime, this, rfc6062Relay, serverIndex, allocStart, relayCounted](const net::AddrRecord& relayed, std::uint32_t lifetimeSec) {
			LifetimeScope ls(lifetime);
			if (!ls) return;
			auto* sa = reinterpret_cast<const sockaddr*>(&relayed.addr);
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
			// The relayed candidate transport follows the ALLOCATION protocol,
			// not the control-connection transport: an RFC 6062 TCP allocation
			// (opt-in) relays TCP and the server listens on the relayed address
			// (passive), so the candidate is TCPPassive. RFC 8656 (the default,
			// including TURN over TCP/TLS control connections) relays UDP, so the
			// candidate must be a UDP relay candidate even though the control
			// connection runs over TCP/TLS.
			c.transport = rfc6062Relay ? CandidateTransport::TCPPassive : CandidateTransport::UDP;
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
			if (relayCounted->exchange(true) == false) {
				--pendingRelayAllocations_;
				STICE_LOG_DEBUG("TURN: pendingRelayAllocations_=%d after allocation",
					pendingRelayAllocations_);
				checkGatheringComplete();
			}
			};
		sink.onFailed = [lifetime, this, relayCounted](int code, const std::string& reason) {
			LifetimeScope ls(lifetime);
			if (!ls) return;
			STICE_LOG_WARN("TURN allocation failed: %d %s", code, reason.c_str());
			// NOTE: do NOT reset turnTcpTransport_ here — the onFailed callback
			// may be invoked from within onTurnTcpEvents / handleInboundTurnTcp,
			// and resetting the transport mid-callback causes a UAF when
			// onTurnTcpEvents continues after handleInboundTurnTcp returns.
			// Transport cleanup is handled in onBookkeeping (after tick()) and
			// in onTurnTcpEvents (on transport state change).
			if (relayCounted->exchange(true) == false) {
				--pendingRelayAllocations_;
				checkGatheringComplete();
			}
			};
		sink.onData = [lifetime, this, turnSelf = e.turn.get()](
			const net::AddrRecord& peer, const unsigned char* data, std::size_t size) {
			LifetimeScope ls(lifetime);
			if (!ls) return;
			// Incoming data from a peer via the TURN relay. Deliver as if
			// received directly from that peer, but remember which allocation
			// carried it: binding responses must be sent back out the same
			// allocation (RFC 8445 §7.2.5.2.1), otherwise the peer sees a
			// source address different from the one it targeted and fails the
			// pair as non-symmetric.
			turn::Client* prevTurn = inboundTurn_;
			inboundTurn_ = turnSelf;
			handleInboundUdp(reinterpret_cast<const char*>(data), static_cast<int>(size), peer);
			inboundTurn_ = prevTurn;
			};
		sink.onLog = [this](int level, const char* msg) {
			STICE_LOG(static_cast<stice_log_level_t>(level), "[local=%u] %s", diagLocalPort_, msg);
			};
		sink.onConnectSuccess = [lifetime, this](std::uint32_t connectionId, const net::AddrRecord& peer) {
			// RFC 6062 active mode: CONNECT succeeded, open data connection.
			LifetimeScope ls(lifetime);
			if (!ls) return;
			std::lock_guard<std::recursive_mutex> lock(mutex_);
			connectRetries_ = 0; // reset for future re-connects
			pendingConnectRetry_ = false;
			turnDataRetryCount_ = 0; // fresh CONNECT -> fresh data-connect budget
			pendingTurnDataRetry_ = false;
			beginTurnDataConnect(connectionId, peer);
			};
		sink.onConnectionAttempt = [lifetime, this](std::uint32_t connectionId, const net::AddrRecord& peer) {
			// RFC 6062 passive mode: peer connected to our relayed address,
			// accept by opening a data connection.
			LifetimeScope ls(lifetime);
			if (!ls) return;
			turnDataRetryCount_ = 0; // fresh attempt -> fresh data-connect budget
			pendingTurnDataRetry_ = false;
			beginTurnDataConnect(connectionId, peer);
			};
		sink.onConnectFailed = [lifetime, this](int code, const std::string& reason, const net::AddrRecord& peer) {
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
			// 447 (Connection Timeout or Failure) and 446 (Connection Already
			// Exists) are the RFC 6062 recoverable CONNECT errors: the peer may
			// become reachable once the server's dial window / the existing
			// connection settles.
			if ((code == stun::StunErrorConnectionTimeoutOrFailure ||
			     code == stun::StunErrorConnectionAlreadyExists) &&
			    connectRetries_ < MaxConnectRetries) {
				++connectRetries_;
				pendingConnectPeer_ = peer;
				pendingConnectRetry_ = true;
				// P2-N3: a fixed 10 s CONNECT retry makes every client retry in
				// lockstep after a server-wide dial storm. Spread it by ±20%.
				const int retrySpan = std::max(1, ConnectRetryDelayMs / 5);
				const int retryJitter =
					static_cast<int>(crypto::randomU32() % (2 * retrySpan + 1)) - retrySpan;
				nextConnectRetry_ = std::chrono::steady_clock::now() +
					std::chrono::milliseconds(ConnectRetryDelayMs + retryJitter);
				wakePoll();
				return;
			}
			// Retries exhausted or non-447 error: mark pairs as Failed.
			for (auto& p : pairs_) {
				if (p->remote && p->remote->type == CandidateType::Relayed &&
					p->remote->resolved == peer) {
					p->state = PairState::Failed;
					resetNomination(*p);
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
		// Stable index into entries_ (std::deque, reserved in init): the redirect
		// callback may fire long after this function returns.
		auto entryIndex = std::make_shared<std::size_t>(entries_.size());
		sink.onAlternateServer = [lifetime, this, turnServerAddr, useTcp, entryIndex](
			const net::AddrRecord& alt) {
			LifetimeScope ls(lifetime);
			if (!ls) return;
			if (useTcp) {
				// The TCP/TLS control connection is pinned to the original
				// server; following a redirect would require opening a new
				// connection, which this client does not do.
				STICE_LOG_WARN("TURN 300 Try Alternate over TCP/TLS unsupported, "
					"staying with %s", alt.toString().c_str());
				return;
			}
			std::lock_guard<std::recursive_mutex> lock(mutex_);
			*turnServerAddr = alt;
			if (*entryIndex < entries_.size()) {
				auto& re = entries_[*entryIndex];
				if (re.type == StunEntryType::Relay) re.record = alt;
			}
			STICE_LOG_INFO("TURN: retargeting allocation to alternate server %s",
				alt.toString().c_str());
		};
		e.turn->init(tc, std::move(sink));
		e.tcpTurn = useTcp;
		e.relayCounted = relayCounted;
		e.allocStart = allocStart;
		if (useTcp) {
			e.turnTcp = turnTcp; // per-entry control transport (shared with sendRaw closure)
			e.turnTcpUseTls = (srv.transport == STICE_TURN_TRANSPORT_TLS);
			e.turnTcpSni = e.turnTcpUseTls ? std::string(srv.host) : std::string();
			e.turnTcpSkipVerify = (srv.skip_tls_verify != 0);
			// Per-server CA bundle (empty -> STICE_TLS_CA_FILE, then platform
			// store). Each relay entry keeps its own copy, so one agent can hold
			// allocations on several TURN servers with different private CAs.
			e.turnTcpCaFile = (e.turnTcpUseTls && srv.ca_file) ? std::string(srv.ca_file) : std::string();
		}
		++pendingRelayAllocations_;
		entries_.push_back(std::move(e));
		// entries_ is reserved (MaxStunEntries) in init(), so &entries_.back()
		// stays valid across subsequent push_back calls.
		auto& entry = entries_.back();
		if (useTcp) {
			// TURN over TCP/TLS: establish the TCP connection first. The
			// allocate() request is sent once the connection completes (see
			// onTurnTcpConnected). Buffering the request here would be
			// pointless since sendRaw drops data while the transport is
			// not yet connected.
			// Per-entry control transport and TLS params were already set on the
			// entry before push_back (createRelayEntry). No agent-wide single slot.
			bool useTls = entry.turnTcpUseTls;
			std::string sni = entry.turnTcpSni;
			bool skipVerify = entry.turnTcpSkipVerify;
			std::string caFile = entry.turnTcpCaFile;
			// Seed the entry's nextTransmission so an Idle relay entry never
			// reads as time-point-zero (which would poison nextTimestampMs).
			entry.nextTransmission = std::chrono::steady_clock::now() +
				std::chrono::milliseconds(TcpConnectTimeoutMs / 2);
			if (!beginTurnTcpConnect(entry, resolved, useTls, sni, skipVerify, caFile)) {
				STICE_LOG_WARN("Agent: TURN TCP connect failed immediately for %s", srv.host);
			}
		}
		else {
			// TURN over UDP: send the allocate request right away.
			// Record allocation start time for RTT-based priority correction.
			*allocStart = std::chrono::steady_clock::now();
			if (entry.allocStart) *entry.allocStart = *allocStart;
			entry.turn->allocate();
			entry.nextTransmission = entry.turn->nextTick();
		}
		wakePoll();
	}
	// Pairs hold raw pointers into remote_.candidates, so every path that swaps
	// the remote description to a new generation MUST drop the checklist BEFORE
	// the swap — otherwise nomination/selection keep pointing into freed deque
	// storage. Used by Agent::restart and by setRemoteDescription when a peer's
	// fresh generation completes our own restart handshake.
	void Agent::resetChecklist() {
		cancelAllEntries();
		// Check entries point into pairs_, which is cleared below; Relay entries
		// hold deallocated TURN clients and can never fire again. Their async
		// callbacks capture the lifetime barrier and serverIndex, not the entry
		// address, so clearing the table is safe here.
		entries_.clear();
		pairs_.clear();
		orderedPairs_.clear();
		selectedPair_ = nullptr;
		nominatedPair_ = nullptr;
		nominationValue_ = 0;
		nominationTimestamp_ = {};
		pacTimestamp_ = {};
		pacDeadline_ = {};
		checkingStartTime_ = {};
		deferredCandidates_.clear();
		// N-2: the mDNS de-duplication keys are per-generation. Keeping them
		// across a restart meant a `.local` candidate re-signalled in the new
		// generation (same hostname|port|transport|component key) was suppressed
		// as a "duplicate" while the old query was still unanswered, so the pair
		// was never formed. The in-flight counter is deliberately NOT zeroed:
		// those callbacks still decrement it, and forcing it to 0 first would
		// underflow it below zero.
		mdnsQueryKeys_.clear();
	}
	// N-11: remember the remote credentials currently in `remote_` as superseded,
	// so a later delivery of that generation can be recognised as stale.
	void Agent::noteRemoteGeneration(const Description& d) {
		if (d.iceUfrag.empty() || d.icePwd.empty()) return;
		// Same credentials as the generation already recorded: nothing changed
		// (e.g. a peer that accepts our restart without restarting itself).
		if (remoteGenUfrag_ == d.iceUfrag && remoteGenPwd_ == d.icePwd) return;
		if (!remoteGenUfrag_.empty() || !remoteGenPwd_.empty()) {
			retiredRemoteCreds_.emplace_back(remoteGenUfrag_, remoteGenPwd_);
			// Bounded: only recently superseded generations can still be in flight
			// in the signalling channel; an unbounded list would grow per restart.
			if (retiredRemoteCreds_.size() > 8) retiredRemoteCreds_.erase(retiredRemoteCreds_.begin());
		}
		remoteGenUfrag_ = d.iceUfrag;
		remoteGenPwd_ = d.icePwd;
	}
	bool Agent::isRetiredRemoteGeneration(const Description& d) const {
		if (d.iceUfrag.empty() || d.icePwd.empty()) return false;
		// The generation last applied is still current — accept it. This is the
		// "peer accepted our restart but did not restart itself" case.
		if (d.iceUfrag == remoteGenUfrag_ && d.icePwd == remoteGenPwd_) return false;
		for (const auto& g : retiredRemoteCreds_)
			if (g.first == d.iceUfrag && g.second == d.icePwd) return true;
		return false;
	}
	int Agent::restart() {
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		STICE_LOG_INFO("Agent: ICE restart (previous state=%d)", static_cast<int>(state_));
		// RFC 8445 §9.1.1: an ICE restart starts a new generation — new
		// ufrag/pwd, fresh candidate gathering, and a clean checklist. The old
		// generation's checks, pairs and selected/nominated pointers must not
		// survive, otherwise a stale pair could be nominated in the new
		// generation (the ufrag no longer matches the peer's credentials either).
		cancelAllEntries();
		for (auto& c : tcpConns_)
			if (c.transport) c.transport->close();
		tcpConns_.clear();
		turnDataConn_.reset();
		resetChecklist();
		nextTick_ = {};
		relayOnlyMode_ = false;
		local_.candidates.clear();
		local_.finished = false;
		remote_.candidates.clear();
		remote_.finished = false;
		mdnsQueryKeys_.clear();
		pendingMdnsResolutions_.store(0);
		pendingServerReflexive_ = 0;
		// #7: an allocation still in flight belongs to the dead generation —
		// its turn::Client is destroyed with entries_ (silencing the late
		// decrement), so zero the counter here or the new generation's gathering
		// would wait out the soft timeout before completing.
		pendingRelayAllocations_ = 0;
		disconnectedAt_ = {};
		// Our own restart is pending until the peer's fresh generation arrives;
		// setRemoteDescription relies on this to not restart again on it.
		restartingLocally_ = true;
		pendingTurnDataRetry_ = false;
		gatheringDone_ = false;
		gatherStartedAt_ = {};
		remoteGatheringDone_ = false;
		// The muxes demux inbound traffic by ufrag: drop the old generation's
		// registration so gatherCandidates() re-registers under the new ufrag.
		// Without this, a passive TCP dial (or UDPMux-routed packet) addressed
		// to the new ufrag finds no agent entry and is rejected — after an ICE
		// restart the endpoint would be permanently deaf to new inbound.
		if (mux_ || tcpMux_) {
			const std::string oldUfrag = local_.iceUfrag;
			if (mux_) {
				mux_->removeAgent(oldUfrag);
				muxRegistered_ = false;
			}
			if (tcpMux_) {
				tcpMux_->removeAgent(oldUfrag);
				tcpMuxRegistered_ = false;
			}
		}
		// In-flight RFC 6062 data-connection rebinds belong to the old
		// generation's turnDataConn_, which was reset above.
		pendingTurnDataRebind_ = false;
		turnDataRebindAttempts_ = 0;
		// New generation = new credentials on BOTH sides: stale remote ufrag/pwd
		// would let checks from the old generation authenticate against the old
		// key and let formPairs build pairs against credentials the peer has
		// already retired. The peer re-signals its fresh description (pion
		// agent.go:1929 requires explicit credentials for the same reason).
		remote_.iceUfrag.clear();
		remote_.icePwd.clear();
		local_.iceUfrag = generateUfrag();
		local_.icePwd = generatePwd();
		// gatherCandidates() only accepts DISCONNECTED/FAILED as a starting
		// state; present the new generation as freshly initialised.
		state_ = STICE_STATE_DISCONNECTED;
		return gatherCandidates();
	}
	int Agent::gatherCandidates() {
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		if (state_ != STICE_STATE_DISCONNECTED && state_ != STICE_STATE_FAILED) return STICE_ERR_FAILED;
		// draft-ietf-ice-trickle §3: re-sync the advertised ice-option on every
		// gather, including the gather a restart() triggers. init() set it once
		// from the construction-time config, so a later change of the trickle
		// mode would otherwise keep describing the old generation's local
		// description as (non-)trickling.
		local_.trickleEnabled = pairingCfg_.enable_trickle;
		changeState(STICE_STATE_GATHERING);
		if (gatherStartedAt_.time_since_epoch().count() == 0)
			STICE_LOG_DEBUG("GATHER-START: gatherCandidates executing, setting gatherStartedAt_ (agent=%p)", (void*)this);
		gatherStartedAt_ = std::chrono::steady_clock::now(); // soft gathering deadline
		{ net::AddrRecord ba; if (diagLocalPort_ == 0 && boundAddrUdp(ba)) diagLocalPort_ = net::addrPort(reinterpret_cast<sockaddr*>(&ba.addr)); }
		wakePoll(); // recompute poll deadline: expose soft gathering timeout now
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
		// STUN servers. TCP-only ICE skips srflx gathering: it is UDP-based and
		// would only produce UDP-transport candidates that can never pair.
		if (config_.disable_udp_gathering || config_.relay_only_local) {
			STICE_LOG_INFO("Agent: UDP gathering disabled, skipping STUN/srflx gathering");
		}
		else if (!stunServersInternal_.empty()) {
			for (const auto& s : stunServersInternal_) {
				GatherItem item;
				item.type = GatherItem::Type::Stun;
				item.host = s.host;
				item.port = s.port ? s.port : 3478;
				items.push_back(std::move(item));
			}
		}
		else if (config_.stun_server_host) {
			// Legacy single STUN server fallback.
			GatherItem item;
			item.type = GatherItem::Type::Stun;
			item.host = config_.stun_server_host;
			item.port = config_.stun_server_port ? config_.stun_server_port : 3478;
			items.push_back(std::move(item));
		}
		// TURN servers: decide eager vs deferred based on pairing strategy.
		// TCP-only ICE skips all TURN allocations: a UDP-transport TURN server
		// would produce a UDP relayed candidate that can never pair with our
		// TCP-only locals, and even a TCP allocation reintroduces a relay path
		// the test means to exclude. Without TURN the connection must succeed
		// over direct TCP or fail explicitly — no silent relay fallback.
		if (config_.disable_udp_gathering && config_.turn_servers_count > 0)
			STICE_LOG_INFO("Agent: UDP gathering disabled, skipping %d TURN server(s)",
				config_.turn_servers_count);
		for (int i = 0; !config_.disable_udp_gathering && i < config_.turn_servers_count; ++i) {
			const auto& srv = config_.turn_servers[i];
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
				}
				else if (pairingCfg_.tcp_relay_fallback == TcpRelayFallbackMode::ON_ALL_UDP_FAIL) {
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
					}
					else {
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
			}
			else {
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
		// Restart: stop and reap any previous worker with the same BOUNDED wait
		// used by ~Agent (a bare join could hang here too).
		if (gatherWorker_.joinable()) {
			if (gatherCancel_) gatherCancel_->store(true, std::memory_order_release);
			const auto deadline = std::chrono::steady_clock::now() +
				std::chrono::milliseconds(GatherWorkerJoinTimeoutMs);
			while (std::chrono::steady_clock::now() < deadline &&
			       !(gatherWorkerDone_ && gatherWorkerDone_->load(std::memory_order_acquire))) {
				std::this_thread::sleep_for(std::chrono::milliseconds(2));
			}
			if (gatherWorkerDone_ && gatherWorkerDone_->load(std::memory_order_acquire)) {
				gatherWorker_.join();
			} else {
				STICE_LOG_ERROR("Agent::gatherCandidates: previous gather worker did not exit within %d ms; detaching",
				                GatherWorkerJoinTimeoutMs);
				gatherWorker_.detach();
			}
		}
		// Fresh flags for the new worker: an old worker may still hold copies of
		// the previous shared_ptrs, so never reuse them.
		gatherCancel_ = std::make_shared<std::atomic<bool>>(false);
		gatherWorkerDone_ = std::make_shared<std::atomic<bool>>(false);
		// Spawn the worker thread: resolves all DNS in parallel, then creates
		// StunEntry objects under the mutex. This eliminates serial getaddrinfo
		// blocking that stalls the poll thread during gathering.
		STICE_LOG_INFO("Agent: spawning gather worker thread for %zu items", items.size());
		gatherWorker_ = std::thread(&Agent::gatherCandidatesWorker, this, std::move(items),
		                            lifetime_, gatherCancel_, gatherWorkerDone_);
		return STICE_ERR_SUCCESS;
	}
	void Agent::gatherCandidatesWorker(std::vector<GatherItem> items,
	std::shared_ptr<LifetimeGuard> lifetime,
	std::shared_ptr<std::atomic<bool>> cancel,
	std::shared_ptr<std::atomic<bool>> done) {
	// Mark the worker finished on EVERY exit path, so ~Agent's bounded join can
	// distinguish "still running" from "exited" without racing Agent lifetime.
	struct DoneScope {
		std::shared_ptr<std::atomic<bool>> f;
		~DoneScope() { if (f) f->store(true, std::memory_order_release); }
	} doneScope{done};
	auto cancelled = [&] { return cancel && cancel->load(std::memory_order_acquire); };
		// Phase 1: Resolve all DNS in parallel (no mutex needed).
		// Each item gets its own std::async task, so all getaddrinfo calls
		// run concurrently on the OS thread pool. This eliminates the serial
		// blocking that occurs when resolving N STUN + M TURN servers one by
		// one on the caller's thread while holding the mutex.
		// Phase 1: resolve all DNS in parallel WITHOUT blocking this worker on any
		// single resolver. getaddrinfo has no timeout, so each item is resolved on
		// a detached thread that writes into its own heap slot; we wait at most
		// GatherDnsTimeoutMs in total and then abandon stragglers. A resolver
		// touches only its slot (never the Agent), so abandoning it is safe - and
		// it keeps this worker (and therefore stice_destroy) from being pinned.
		struct DnsSlot {
			std::mutex m;
			bool ready = false;
			std::vector<net::AddrRecord> recs;
		};
		std::vector<std::shared_ptr<DnsSlot>> slots;
		slots.reserve(items.size());
		for (auto& item : items) {
			auto slot = std::make_shared<DnsSlot>();
			slots.push_back(slot);
			int socktype = (item.type == GatherItem::Type::TurnTcp) ? SOCK_STREAM : SOCK_DGRAM;
			std::thread([item, socktype, slot]() {
				std::vector<net::AddrRecord> out;
				// Try numeric parse first (no DNS needed).
				net::AddrRecord rec;
				if (net::parseAddr(item.host, item.port, rec.addr, rec.len)) {
					rec.socktype = socktype;
					out.push_back(rec);
				} else {
					// Otherwise resolve via getaddrinfo (blocking, bounded here).
					out = net::resolve(item.host, std::to_string(item.port), socktype);
				}
				std::lock_guard<std::mutex> lk(slot->m);
				slot->recs = std::move(out);
				slot->ready = true;
			}).detach();
		}
		std::vector<std::vector<net::AddrRecord>> results(items.size());
		{
			const auto deadline = std::chrono::steady_clock::now() +
				std::chrono::milliseconds(GatherDnsTimeoutMs);
			while (!cancelled()) {
				bool allReady = true;
				for (auto& s : slots) {
					std::lock_guard<std::mutex> lk(s->m);
					if (!s->ready) { allReady = false; break; }
				}
				if (allReady) break;
				if (std::chrono::steady_clock::now() >= deadline) {
					STICE_LOG_WARN("Agent: gather DNS phase timed out after %d ms; proceeding with partial results",
					               GatherDnsTimeoutMs);
					break;
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(2));
			}
			for (std::size_t i = 0; i < slots.size(); ++i) {
				std::lock_guard<std::mutex> lk(slots[i]->m);
				if (slots[i]->ready) results[i] = slots[i]->recs;
			}
		}
		if (cancelled()) return; // Agent being destroyed: never touch members.
		// Phase 2: create the StunEntry objects.
		//
		// The agent lock is acquired with a BOUNDED budget (try_lock polling -
		// std::recursive_mutex has no timed lock). This is essential, not just
		// tidiness: this thread holds a LifetimeScope from here on, so blocking
		// indefinitely behind a wedged mutex holder would keep that scope alive
		// forever and ~Agent's drain (which waits for in-flight scopes) would
		// then block permanently - observed as "tearing down A" never returning
		// while the worker sat on the lock.
		LifetimeScope ls(lifetime);
		if (!ls) return; // Agent destroyed during DNS resolution.
		const auto lockDeadline = std::chrono::steady_clock::now() +
			std::chrono::milliseconds(GatherLockTimeoutMs);
		bool locked = false;
		while (std::chrono::steady_clock::now() < lockDeadline) {
			if (cancelled()) return;
			if (mutex_.try_lock()) { locked = true; break; }
			std::this_thread::sleep_for(std::chrono::milliseconds(2));
		}
		if (!locked) {
			STICE_LOG_ERROR("Agent: gather worker could not acquire the agent lock within %d ms; abandoning entry creation (gathering falls back to the soft deadline)",
			                GatherLockTimeoutMs);
			return;
		}
		std::unique_lock<std::recursive_mutex> lock(mutex_, std::adopt_lock);
		if (cancelled()) return;
		for (std::size_t i = 0; i < items.size(); ++i) {
			// Cancellation is re-checked per item: this phase is short and
			// non-blocking, so a stop request is honoured within microseconds.
			if (cancelled()) return;
			if (results[i].empty()) {
				STICE_LOG_WARN("Agent: could not resolve %s:%u (%s)",
					items[i].host.c_str(), items[i].port,
					items[i].type == GatherItem::Type::Stun ? "STUN" : "TURN");
				continue;
			}
			const auto& resolved = results[i][0];
			if (items[i].type == GatherItem::Type::Stun) {
				createServerReflexiveEntry(items[i].host, items[i].port, resolved);
			}
			else {
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
	int Agent::getLocalDescription(char* buf, std::size_t size) const {
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		std::string sdp = local_.generateSdp();
		if (sdp.size() + 1 > size) return STICE_ERR_TOO_LARGE;
		std::memcpy(buf, sdp.data(), sdp.size());
		buf[sdp.size()] = '\0';
		return STICE_ERR_SUCCESS;
	}
	int Agent::setRemoteDescription(const char* sdp) {
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		Description d;
		if (!d.parse(sdp)) return STICE_ERR_INVALID;
		// N-11: monotonic generation guard. Signalling can deliver a peer's
		// description out of order (or a peer may re-send a pre-restart copy):
		// applying an older generation after a newer one has been accepted
		// would look like another credential change and trigger a second
		// restart, tearing down a checklist that is already converging. Drop
		// anything that belongs to a superseded generation.
		if (isRetiredRemoteGeneration(d)) {
			STICE_LOG_WARN("setRemoteDescription: ignoring description from a retired ICE generation (ufrag=%s)",
				d.iceUfrag.c_str());
			return STICE_ERR_SUCCESS;
		}
		// RFC 8445 §9: a changed peer ufrag/pwd mid-session signals an ICE
		// restart initiated by the peer — this side MUST restart too, or the
		// surviving generation limps on with a half-dead checklist (its pairs
		// reference credentials and sockets the peer has already retired).
		// When the change completes OUR OWN pending restart
		// (restartingLocally_), rebuilding the checklist suffices: the local
		// credentials are already fresh, and pairs formed against the peer's
		// retired pre-restart description must go. Both paths reset the
		// checklist BEFORE remote_ is replaced (pairs point into it).
		const bool hadRemoteCreds = !remote_.iceUfrag.empty() || !remote_.icePwd.empty();
		const bool peerCredsChanged =
			hadRemoteCreds && (remote_.iceUfrag != d.iceUfrag || remote_.icePwd != d.icePwd);
		bool checklistRebuilt = false;
		if (peerCredsChanged) {
			if (restartingLocally_) {
				STICE_LOG_INFO("setRemoteDescription: peer's new generation accepted — rebuilding checklist");
				resetChecklist();
			} else {
				STICE_LOG_INFO("setRemoteDescription: peer ufrag/pwd changed (RFC 8445 §9) — restarting local side");
				restart();
			}
			checklistRebuilt = true;
		}
		// N-11: record the generation being replaced (or first applied) before the
		// move consumes `d`.
		noteRemoteGeneration(d);
		remote_ = std::move(d);
		// RFC 8839 §5.1: `a=end-of-candidates` in the remote description means
		// the peer will not trickle anything further. Consume it instead of
		// letting it sit as a dead parse flag: it gates the "no pair can ever
		// form" fast failure below and tells the checker not to wait for more.
		if (remote_.finished) {
			remoteGatheringDone_ = true;
			STICE_LOG_DEBUG("setRemoteDescription: a=end-of-candidates present (remote gathering done)");
		}
		// candidates is std::deque: pointers into remote_.candidates stay valid
		// across later addRemoteCandidate (trickle) push_back calls — no reserve
		// needed. (Move-assigning a deque also moves its storage, but pairs are
		// only formed after this point in the same call.)
		if (mode_ == AgentMode::Unknown) {
			// We are the controlled agent if we set the remote description first.
			mode_ = AgentMode::Controlled;
		}
		// mDNS: `.local` remote candidates cannot be resolved by getaddrinfo in
		// the common no-nss-mdns setup (they used to be silently dropped there).
		// Hand every one of them to the mDNS resolver; the resolved copy is
		// appended asynchronously (remote_.candidates is a deque, so existing
		// pointers stay valid) and paired from the callback.
		for (const auto& rc : remote_.candidates) resolveRemoteMDnsCandidate(rc);
		// Process remote passive TCP candidates: create local active TCP
		// candidates and initiate connections. This was previously only done
		// in addRemoteCandidate (trickle path), leaving non-trickle ICE-TCP
		// without any TCP connection attempt.
		// Aligned with pion-ice: skip when DisableActiveTCP is set.
		for (const auto& rc : remote_.candidates) {
			// `.local` candidates have no address until the mDNS resolver
			// finishes; dialing one now would reset the existing TCP transport
			// and then fail the DNS fallback. The resolver callback runs the
			// passive-TCP dial once the address is known.
			if (!rc.fromMdns &&
				rc.transport == CandidateTransport::TCPPassive &&
				iceTcpMode_ != STICE_ICE_TCP_MODE_NONE &&
				!config_.disable_active_tcp) {
				addRemotePassiveTcpCandidate(rc);
			}
		}
		if (state_ == STICE_STATE_GATHERING) {
			// Trickle ICE / multi-TURN: start connectivity checks as soon as the
			// remote description is set and at least one local candidate can be
			// paired. Waiting for gatheringDone lets one dead TURN server's ~10s
			// allocate timeout stall the entire checking phase (we are likely the
			// controlling side, so the peer is waiting for our checks and times
			// out). Candidates gathered later (slow/dead servers) are paired
			// incrementally in addLocalCandidate.
			auto pairsBefore = pairs_.size();
			formPairs();
			if (gatheringDone_ || pairs_.size() > pairsBefore) {
				changeState(STICE_STATE_CONNECTING);
			}
		} else if (checklistRebuilt) {
			// Restart-generation accepted while not gathering (gather already
			// completed): re-form pairs against the fresh description; the
			// bookkeeping tick arms the new connectivity checks (same mechanism
			// the trickle path uses). The state machine takes it from there —
			// including the DISCONNECTED grace revival when the pre-restart
			// generation had already been reported lost.
			formPairs();
		}
		return STICE_ERR_SUCCESS;
	}
	int Agent::addRemoteCandidate(const char* sdp) {
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		// draft-ietf-ice-trickle §2.2: candidates that arrive after the remote
		// end-of-candidates indication MUST be ignored. Accepting them would
		// form pairs against a candidate set the peer has already declared
		// final.
		if (remote_.finished) {
			STICE_LOG_DEBUG("addRemoteCandidate: remote EOC already received, ignoring late candidate");
			return STICE_ERR_SUCCESS;
		}
		if (!remote_.addCandidateFromSdp(sdp)) return STICE_ERR_INVALID;
		// Get the just-added remote candidate (last one in the list).
		if (!remote_.candidates.empty()) {
			const auto& rc = remote_.candidates.back();
			if (rc.fromMdns) {
				// Async mDNS resolution replaces the getaddrinfo path; pairing
				// (and the passive-TCP dial) happens from the resolver callback.
				resolveRemoteMDnsCandidate(rc);
			} else if (rc.transport == CandidateTransport::TCPActive) {
				// pion-ice: remote TCP active candidates are ignored because the
				// remote active side will probe our passive listener. Only remote
				// passive TCP candidates are dialed here; remote `tcptype so`
				// candidates are not yet supported (SO is experimental and our own
				// gatherer never emits them).
				STICE_LOG_DEBUG("addRemoteCandidate: ignoring remote TCP active candidate");
				// Remove it from the list since we won't use it.
				remote_.candidates.pop_back();
				return STICE_ERR_SUCCESS;
			} else if (rc.transport == CandidateTransport::TCPSimultaneousOpen) {
				STICE_LOG_DEBUG("addRemoteCandidate: remote tcptype so not supported yet, ignoring");
				remote_.candidates.pop_back();
				return STICE_ERR_SUCCESS;
			} else if (rc.transport == CandidateTransport::TCPPassive &&
				iceTcpMode_ != STICE_ICE_TCP_MODE_NONE &&
				!config_.disable_active_tcp) {
				// If remote is TCP passive and we have active TCP enabled, create
				// a local active TCP candidate by dialing the remote address.
				// Aligned with pion-ice: skip when DisableActiveTCP is set.
				addRemotePassiveTcpCandidate(rc);
			}
		}
		if (state_ == STICE_STATE_CONNECTING || state_ == STICE_STATE_CONNECTED ||
			state_ == STICE_STATE_COMPLETED) {
			formPairs();
		}
		else if (state_ == STICE_STATE_GATHERING && !local_.candidates.empty()) {
			// Remote trickle candidate arrived while local gathering is still
			// in progress (e.g. one TURN server of a multi-server deployment is
			// slow/dead). Form pairs with the local candidates we already have
			// and start checking instead of waiting for gathering to complete.
			formPairs();
			changeState(STICE_STATE_CONNECTING);
		}
		return STICE_ERR_SUCCESS;
	}
	int Agent::addTurnServer(const stice_turn_server_t* srv) {
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		if (config_.turn_servers_count >= 8) return STICE_ERR_TOO_LARGE;
		// Append to the config's turn server list. The C API gives us a pointer
		// to a stice_turn_server_t whose host/username/password are raw pointers
		// into caller memory (e.g. a temporary IceServer in libdatachannel).
		// Deep-copy those strings into owned backing storage so they stay valid
		// after the caller's copy is destroyed (same pattern as addIceServer).
		// NOTE: config_.turn_servers points into user memory, so we maintain a
		// separate internal vector.
		stice_turn_server_t ts = *srv;
		if (srv->host) {
			turnServerHostStorage_.emplace_back(srv->host);
			ts.host = turnServerHostStorage_.back().c_str();
		}
		if (srv->username) {
			turnServerUserStorage_.emplace_back(srv->username);
			ts.username = turnServerUserStorage_.back().c_str();
		}
		if (srv->password) {
			turnServerPassStorage_.emplace_back(srv->password);
			ts.password = turnServerPassStorage_.back().c_str();
		}
		if (srv->ca_file) {
			// Per-server trust bundle: copied like the other strings so the
			// caller may free its own copy immediately.
			turnServerCaStorage_.emplace_back(srv->ca_file);
			ts.ca_file = turnServerCaStorage_.back().c_str();
		}
		turnServersInternal_.push_back(ts);
		config_.turn_servers = turnServersInternal_.data();
		config_.turn_servers_count = static_cast<int>(turnServersInternal_.size());
		return STICE_ERR_SUCCESS;
	}
	int Agent::addStunServer(const char* host, uint16_t port) {
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		if (!host) return STICE_ERR_INVALID;
		if (stunServersInternal_.size() >= 8) return STICE_ERR_TOO_LARGE;
		stunServersInternal_.push_back({ std::string(host), port ? port : static_cast<uint16_t>(3478) });
		return STICE_ERR_SUCCESS;
	}
	int Agent::addIceServer(const char* url, const char* username, const char* password) {
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
		// Extract host and port. An IPv6 literal MUST be bracketed when a port is
		// appended (RFC 3986 §3.2.2) and a bare IPv6 literal carries no port at
		// all. The previous "is everything after the LAST colon numeric?"
		// heuristic got both cases wrong: `turn:2001:db8::1` became host
		// "2001:db8:" + port 1, and the bracketed form (the WebRTC convention,
		// e.g. `turn:[2001:db8::1]:3478`) left the ']' in the host so resolution
		// failed outright.
		hostPart = rest;
		if (!rest.empty() && rest.front() == '[') {
			auto close = rest.find(']');
			if (close == std::string::npos) return STICE_ERR_INVALID; // malformed
			hostPart = rest.substr(1, close - 1);
			if (close + 1 < rest.size()) {
				if (rest[close + 1] != ':') return STICE_ERR_INVALID;
				std::string maybePort = rest.substr(close + 2);
				bool isNumeric = !maybePort.empty();
				for (char c : maybePort) {
					if (!std::isdigit(static_cast<unsigned char>(c))) { isNumeric = false; break; }
				}
				if (isNumeric) {
					try { port = static_cast<uint16_t>(std::stoul(maybePort)); }
					catch (...) { port = 3478; }
					if (port == 0) port = 3478;
				}
			}
		} else {
			// More than one colon can only be an unbracketed IPv6 literal, which
			// has no port syntax - splitting it would corrupt the host.
			std::size_t colons = 0;
			for (char c : rest) if (c == ':') ++colons;
			if (colons == 1) {
				auto lastColon = rest.rfind(':');
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
			}
			else {
				ts.transport = transport;
			}
			turnServersInternal_.push_back(ts);
			config_.turn_servers = turnServersInternal_.data();
			config_.turn_servers_count = static_cast<int>(turnServersInternal_.size());
			STICE_LOG_INFO("Agent: addIceServer turn: added TURN server %s:%u (transport=%d)",
				hostPart.c_str(), port, static_cast<int>(ts.transport));
		}
		// Add STUN server entry (for both stun: and turn: URLs).
		// Deduplicate by host:port — registering several TURN URLs against the
		// same server (udp/tcp/tls variants) must not create duplicate STUN
		// entries (each would gather a redundant server-reflexive candidate).
		for (const auto& s : stunServersInternal_) {
			if (s.port == port && s.host == hostPart) {
				STICE_LOG_INFO("Agent: addIceServer %s: STUN server %s:%u already "
					"registered, skipping duplicate",
					scheme.c_str(), hostPart.c_str(), port);
				return STICE_ERR_SUCCESS;
			}
		}
		if (stunServersInternal_.size() >= 8) return STICE_ERR_TOO_LARGE;
		// For turns: (TLS), STUN over UDP is still useful for srflx — the coturn
		// server listens on UDP 3478 for STUN even if TLS is on TCP 5349. Use the
		// same port (3478) for STUN UDP regardless of TURN transport.
		stunServersInternal_.push_back({ hostPart, port });
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
	int Agent::setLocalIceAttributes(const char* ufrag, const char* pwd) {
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		// RFC 8445: ufrag 4-256 chars, pwd 22-256 chars, both "ice-char" alphabet
		// (ALPHA / DIGIT / "+" / "/").
		auto isValidIceString = [](const char* s, std::size_t minLen) -> bool {
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
	int Agent::addAddressRewriteRule(const stice_address_rewrite_rule_t* rule) {
		if (!rule) return STICE_ERR_INVALID;
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		if (state_ != STICE_STATE_DISCONNECTED && state_ != STICE_STATE_FAILED) {
			// Rules must be added before gathering starts.
			return STICE_ERR_FAILED;
		}
		AddressRewriteRule r;
		if (rule->external_ips) {
			for (auto* p = rule->external_ips; *p; ++p) {
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
		// Client identity label only: each gathered address is registered under
		// its own generated name (draft §3.1) and only those reach SDP.
		std::string hostname = config_.multicast_dns_hostname
			? config_.multicast_dns_hostname
			: net::MDnsClient::generateHostname();
		// Determine the local address to advertise (for QueryAndGather mode).
		std::string localAddr;
		if (mdnsMode_ == STICE_MDNS_MODE_QUERY_AND_GATHER) {
			// Use the first local address from the socket.
			auto addrs = localAddrsUdp(AF_INET);
			if (!addrs.empty()) {
				auto* sa = reinterpret_cast<const sockaddr*>(&addrs[0].addr);
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
		if (!mdns_->init(mode, hostname, localAddr)) {
			STICE_LOG_WARN("Agent: mDNS init failed, continuing without mDNS");
			mdns_.reset();
		}
		else if (mdns_->degraded()) {
			// Port 5353 was taken, so the client dropped to QueryOnly and local
			// candidates are NOT advertised under an mDNS name. Surface it: a
			// silently degraded QueryAndGather session looks healthy while the
			// privacy promise (and .local pairing) is no longer delivered.
			STICE_LOG_WARN("Agent: mDNS degraded to QueryOnly (port %d unavailable); "
			               "local candidates will not be advertised via mDNS", 5353);
		}
	}
	std::vector<Candidate> Agent::applyAddressRewrite(const Candidate& c,
		const std::string& localIP,
		const std::string& iface) {
		if (!addrRewrite_ || addrRewrite_->empty()) {
			return { c };
		}
		auto result = addrRewrite_->findExternalIPs(c.type, localIP, iface);
		if (!result.matched) {
			return { c };
		}
		std::vector<Candidate> out;
		if (result.mode != AddressRewriteMode::Replace) {
			// Append mode: keep the original candidate.
			out.push_back(c);
		}
		for (const auto& extIP : result.externalIPs) {
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
	bool Agent::resolveRemoteMDnsCandidate(const Candidate& c) {
		if (!mdns_ || mdnsMode_ == STICE_MDNS_MODE_DISABLED) return false;
		if (!net::MDnsClient::isMDnsName(c.hostname)) return false;
		// One query per distinct candidate identity. A duplicate arrival (batch
		// description + trickle, or a repeated trickle line) must not start a
		// second query: it would append a second resolved copy of the same
		// address and form duplicate pairs.
		const std::string key = c.hostname + "|" + c.service + "|" +
			std::to_string(static_cast<int>(c.transport)) + "|" +
			std::to_string(c.component);
		if (!mdnsQueryKeys_.insert(key).second) {
			STICE_LOG_DEBUG("mDNS: %s already queried, ignoring duplicate candidate", c.hostname.c_str());
			return false;
		}
		// Copy the candidate so we can fill in the resolved address later.
		auto hostname = c.hostname;
		// Capture the needed fields by value since the callback runs async.
		auto port = c.service;
		auto type = c.type;
		auto transport = c.transport;
		auto component = c.component;
		auto priority = c.priority;
		auto foundation = c.foundation;
		++pendingMdnsResolutions_;
		bool started = mdns_->query(hostname, [this, lifetime = lifetime_, hostname, port, type, transport, component,
			priority, foundation, key](const std::string& address) {
				// Balance the counter before the teardown guard: a query that is
				// still in flight when the Agent is destroyed must not leave the
				// count elevated (the poll thread may already be gone).
				pendingMdnsResolutions_.fetch_sub(1);
				LifetimeScope ls(lifetime);
				if (!ls) return;
				std::lock_guard<std::recursive_mutex> lock(mutex_);
				if (address.empty()) {
					// Allow a later duplicate to retry the resolution.
					mdnsQueryKeys_.erase(key);
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
				resolved.fromMdns = true;
				std::uint16_t portNum = static_cast<std::uint16_t>(std::atoi(port.c_str()));
				if (net::parseAddr(address, portNum, resolved.resolved.addr, resolved.resolved.len)) {
					resolved.resolved.socktype = (transport == CandidateTransport::UDP) ? SOCK_DGRAM : SOCK_STREAM;
				}
				remote_.candidates.push_back(std::move(resolved));
				const auto& added = remote_.candidates.back();
				// A resolved mDNS passive TCP candidate still needs the same
				// active-dial treatment as one that arrived with a numeric IP.
				if (added.transport == CandidateTransport::TCPPassive &&
					iceTcpMode_ != STICE_ICE_TCP_MODE_NONE && !config_.disable_active_tcp) {
					addRemotePassiveTcpCandidate(added);
				}
				if (state_ == STICE_STATE_CONNECTING || state_ == STICE_STATE_CONNECTED ||
					state_ == STICE_STATE_COMPLETED) {
					formPairs();
				}
				STICE_LOG_DEBUG("mDNS: resolved %s to %s", hostname.c_str(), address.c_str());
			});
		if (!started) {
			--pendingMdnsResolutions_;
			mdnsQueryKeys_.erase(key);
		}
		return started;
	}
	void Agent::wakePoll() {
		// Wake the poll thread so it re-evaluates timers immediately. Called
		// after state changes (e.g. formPairs arming a new entry) that happen
		// on the caller's thread, not the poll thread.
		if (pollReg_) {
			pollReg_->interrupt();
		}
		else if (mux_) {
			// In UDPMux mode, the Agent doesn't own a PollRegistry; the mux
			// does. Wake the mux's poll thread instead.
			mux_->interrupt();
		}
		else if (tcpMux_) {
			tcpMux_->interrupt();
		}
	}
	void Agent::formPairs() {
		STICE_LOG_DEBUG("formPairs: local=%zu remote=%zu mode=%d",
			local_.candidates.size(), remote_.candidates.size(), static_cast<int>(mode_));
		for (const auto& rc : remote_.candidates)
			STICE_LOG_DEBUG("  remote cand: host=%s port=%s resolved=%s",
				rc.hostname.c_str(), rc.service.c_str(), rc.resolved.toString().c_str());
		// Form pairs from local x remote candidates (same component, same family).
		for (const auto& local : local_.candidates) {
			for (const auto& remote : remote_.candidates) {
				if (local.component != remote.component) continue;
				if (local.resolved.addr.ss_family != remote.resolved.addr.ss_family) continue;
				// Link-local remote candidates (169.254.0.0/16, fe80::/10) are not
				// pairable: without a zone scope they are unroutable off-link, and
				// in same-host / multi-adapter setups (browsers disable mDNS on
				// localhost pages and expose APIPA host candidates from virtual
				// adapters) they produce asymmetric self-loop paths whose STUN
				// checks "succeed" locally while DTLS traffic blackholes. Blocking
				// them here also covers batch setRemoteDescription candidates and
				// mDNS-resolved results, which do not pass through
				// addRemoteCandidate. Loopback (127.0.0.0/8) is deliberately NOT
				// filtered — local test topologies legitimately use it.
				if (net::addrIsLinkLocal(reinterpret_cast<const sockaddr*>(&remote.resolved.addr))) {
					STICE_LOG_DEBUG("formPairs: skipping link-local remote candidate %s",
						remote.hostname.c_str());
					continue;
				}
				// draft-ietf-rtcweb-mdns-ice-candidates §3.3.2 (MUST NOT): a
				// relayed local candidate must never be paired with an mDNS
				// remote candidate. The TURN server cannot resolve `.local`
				// names, and the address a resolver returns here is private to
				// the peer's link, so relaying to it can only blackhole.
				if (local.type == CandidateType::Relayed && remote.fromMdns) {
					STICE_LOG_DEBUG("formPairs: skipping relay x mDNS pair (local relay, remote %s)",
						remote.hostname.c_str());
					continue;
				}
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
					bool localSo = (local.transport == CandidateTransport::TCPSimultaneousOpen);
					bool remoteSo = (remote.transport == CandidateTransport::TCPSimultaneousOpen);
					// RFC 6544 §6.2 pair table: active pairs only with passive
					// (and vice versa); simultaneous-open pairs only with another
					// simultaneous-open candidate. Mixed SO/active or SO/passive
					// combinations are outside the table and must not be formed.
					if (localSo != remoteSo) continue;
					if (localActive && remoteActive) continue; // active-active illegal
					// RFC 6062: two TCP-relayed (passive) candidates CAN pair — the
					// controlling side sends CONNECT, the controlled side receives
					// CONNECTION-ATTEMPT. Only filter non-relayed passive-passive.
					if (localPassive && remotePassive &&
						!(local.type == CandidateType::Relayed && remote.type == CandidateType::Relayed))
						continue; // passive-passive illegal (non-relayed)
				}
				bool exists = false;
				for (const auto& p : pairs_) {
					if (p->local == &local && p->remote == &remote) { exists = true; break; }
				}
				if (exists) continue;
				if (pairs_.size() >= MaxCandidatePairs) pruneFailedPairs();
				if (pairs_.size() >= MaxCandidatePairs) {
					STICE_LOG_WARN("Agent: candidate pair limit (%zu) reached, truncating pair list",
						static_cast<std::size_t>(MaxCandidatePairs));
					break;
				}
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
		for (const auto& p : orderedPairs_) {
			if (p->local && p->local->type == CandidateType::Relayed) {
				for (auto& re : entries_) {
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
								if (re.turn->hasPermission(p->remote->resolved)) {
									STICE_LOG_INFO("RFC 6062: CONNECT permission ready peer=%s",
										p->remote->resolved.toString().c_str());
									re.turn->sendConnect(p->remote->resolved);
									tcpConnectSent_ = true;
									pendingConnectPeer_ = p->remote->resolved;
								}
								else {
									STICE_LOG_INFO("RFC 6062: deferring CONNECT until permission ready peer=%s",
										p->remote->resolved.toString().c_str());
									pendingConnectPeer_ = p->remote->resolved;
									pendingConnectWaitPerm_ = true;
								}
							}
						}
						else {
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
		for (auto& p : pairs_) orderedPairs_.push_back(p.get());
		std::stable_sort(orderedPairs_.begin(), orderedPairs_.end(),
			[](const CandidatePair* a, const CandidatePair* b) { return a->priority > b->priority; });
	}
	void Agent::updateAllPairPriorities() {
		// RFC 8445 §7.3.1.1: after a role switch the G/D assignment changes, so
		// every existing pair's priority MUST be recomputed and the checklist
		// re-ordered. updatePriority() was previously only called when a pair was
		// created, leaving stale priorities (and thus a stale checklist order)
		// after any 487-driven role flip.
		for (auto& p : pairs_) p->updatePriority(mode_ == AgentMode::Controlling);
		updateOrderedPairs();
	}
	void Agent::applyRoleSwitch() {
		// RFC 8445 §7.2.5.1: the tiebreaker MUST be regenerated when the role
		// switches, so a second 487 is broken by a fresh random value instead of
		// repeating the same comparison forever. Enabled by default; set
		// STICE_ICE_ROLE_TB_REGEN=0 to preserve the old tiebreaker (interop
		// debugging only).
		static const bool regenTiebreaker = []() {
			const char* v = std::getenv("STICE_ICE_ROLE_TB_REGEN");
			return !(v && v[0] == '0');
		}();
		if (regenTiebreaker) tiebreaker_ = crypto::randomU64();
		updateAllPairPriorities();
	}
	StunEntry* Agent::findEntry(CandidatePair* pair) {
		for (auto& e : entries_)
			if (e.pair == pair) return &e;
		return nullptr;
	}
	bool Agent::reclaimDeadEntries() {
		// RFC 8445 §8.1.2: after nomination the remaining checks are cancelled;
		// those entries can never fire again. Without reclamation the table only
		// grows and a long-lived session eventually hits MaxStunEntries, at which
		// point a newly learned valid pair gets no entry and therefore no
		// consent keepalive. Reclaim only entries that are terminal AND belong to
		// a failed pair that is not selected/nominated, so no live path is lost.
		for (auto it = entries_.begin(); it != entries_.end();) {
			const bool dead = it->type == StunEntryType::Check &&
				(it->state == StunEntryState::Cancelled || it->state == StunEntryState::Failed) &&
				it->pair && it->pair != selectedPair_ && it->pair != nominatedPair_ &&
				it->pair->state == PairState::Failed;
			// N-5: Relay entries were never reclaimed, so a long session only grew
			// the table until MaxStunEntries and a newly learned valid pair got no
			// entry (and therefore no consent keepalive). A terminal allocation
			// (Failed / Deallocated) can never fire again — unless a transaction
			// is still awaiting its response, which vetoes the reclaim so a late
			// reply still finds its handler.
			const bool deadRelay = it->type == StunEntryType::Relay && it->turn &&
				(it->turn->state() == turn::AllocState::Failed ||
				 it->turn->state() == turn::AllocState::Deallocated) &&
				!it->turn->hasPendingTransaction();
			if (dead || deadRelay) it = entries_.erase(it);
			else ++it;
		}
		return entries_.size() < MaxStunEntries;
	}
	bool Agent::pruneFailedPairs() {
		// RFC 8445 §6.1.2.4: the check list can be pruned of pairs that can never
		// succeed. Remove their terminal entries first, then drop the pairs that
		// nothing references any more, so a full table cannot permanently reject
		// a newly learned pair.
		for (auto it = entries_.begin(); it != entries_.end();) {
			const bool dead = it->type == StunEntryType::Check && it->pair &&
				it->pair != selectedPair_ && it->pair != nominatedPair_ &&
				it->pair->state == PairState::Failed &&
				(it->state == StunEntryState::Cancelled || it->state == StunEntryState::Failed);
			if (dead) it = entries_.erase(it);
			else ++it;
		}
		auto referenced = [&](const CandidatePair* p) {
			for (const auto& e : entries_)
				if (e.pair == p) return true;
			for (const auto& c : tcpConns_)
				if (c.pair == p) return true;
			return false;
		};
		const std::size_t before = pairs_.size();
		pairs_.erase(std::remove_if(pairs_.begin(), pairs_.end(),
			[&](const std::unique_ptr<CandidatePair>& p) {
				if (p->state != PairState::Failed) return false;
				if (p.get() == selectedPair_ || p.get() == nominatedPair_) return false;
				return !referenced(p.get());
			}), pairs_.end());
		if (pairs_.size() == before) return false;
		updateOrderedPairs();
		STICE_LOG_DEBUG("Agent: pruned %zu failed candidate pair(s), %zu remain",
			before - pairs_.size(), pairs_.size());
		return true;
	}
	void Agent::armTransmission(StunEntry& e, int delayMs) {
		e.nextTransmission = std::chrono::steady_clock::now() + std::chrono::milliseconds(delayMs);
		e.retransmissions = 0;
		// RFC 6544: TCP provides reliable delivery, so application-layer STUN
		// retransmission is unnecessary. Use a single fixed timeout
		// (StunTcpTimeoutMs) for TCP pairs; UDP pairs use exponential backoff
		// starting from the configured rto_initial (default 500ms, matching
		// pion-ice).
		if (pairIsTcp(e.pair)) {
			e.retransmissionTimeout = std::chrono::milliseconds(StunTcpTimeoutMs);
		}
		else {
			auto rto = pairingCfg_.rto_initial.count() > 0
				? pairingCfg_.rto_initial
				: std::chrono::milliseconds(MinStunRetransmissionTimeoutMs);
			e.retransmissionTimeout = rto;
		}
		e.transactionIdExpired = true;
		e.state = StunEntryState::Pending;
	}
	void Agent::armKeepalive(StunEntry& e) {
		e.state = StunEntryState::SucceededKeepalive;
		auto now = std::chrono::steady_clock::now();
		// RFC 7675 §5.1: "Each STUN binding request for consent MUST use a new
		// STUN transaction identifier ... transmitted once only." A keepalive
		// reuses the entry that carried the last connectivity check, whose
		// sendStunBinding() already consumed its fresh ID (setting
		// transactionIdExpired=false). Without re-arming the flag here every
		// consent request replayed that one ID: it broke the MUST, weakened the
		// replay protection the 96-bit ID exists for, and let a peer that
		// de-duplicates on transaction ID drop the requests entirely - consent
		// then expires at 30 s even though the peer is alive.
		e.transactionIdExpired = true;
		// Idle backoff (P1-2): if application data HAS flowed and none has for
		// IdleThresholdMs, stretch the consent check interval to
		// IdleConsentCheckMs (still safely under ConsentTimeoutMs=30s) to
		// reduce keepalive traffic on quiescent sessions. Active sessions use
		// the configured keepalive interval (keepalive_udp / keepalive_tcp_relay)
		// jittered +/- 1s to avoid synchronization storms. Falls back to the
		// compiled-in defaults if the config value is 0.
		// Note: lastAppDataAt_ == 0 (no app data yet) is NOT idle — that is the
		// normal state right after a pair succeeds, before the DTLS handshake
		// starts. Treating it as idle stretched the first post-connect keepalive
		// to IdleConsentCheckMs (15s), which also stalled the poll thread (see
		// nextTimestampMs) and delayed nomination by the full 15s.
		bool idle = lastAppDataAt_.time_since_epoch().count() != 0 &&
			(now - lastAppDataAt_ > std::chrono::milliseconds(IdleThresholdMs));
		int period;
		if (idle) {
			period = IdleConsentCheckMs;
		}
		else {
			bool is_relay = e.pair && pairIsTcpRelay(e.pair);
			std::chrono::milliseconds cfg_period =
				is_relay ? pairingCfg_.keepalive_tcp_relay : pairingCfg_.keepalive_udp;
			// RFC 7675 §5.1: randomize within [0.8, 1.2] x the basic period
			// (5 s default -> 4-6 s) and never below 4 s. Randomizing the BASE in
			// 4-6 s and then adding +/-1 s produced 4-7 s, which broke the 6 s
			// upper bound the SHOULD describes; the base is now deterministic
			// (configured period, else the 5 s basic period) and the +/-20 %
			// jitter IS the randomization the RFC asks for.
			int base = cfg_period.count() > 0
				? static_cast<int>(cfg_period.count())
				: DefaultConsentCheckPeriodMs;
			int span = std::max(1, base / 5); // 20 %
			int jitter = static_cast<int>(crypto::randomU32() % (2 * span + 1)) - span;
			period = std::max(MinConsentCheckPeriodMs, base + jitter);
			// RFC 7675 §5.1 upper bound applies to the UDP consent freshness the
			// RFC governs; a TCP-relay keepalive configured above 6 s (e.g. the
			// STRICT profile's 10 s) is a deliberate product deviation and stays.
			if (!is_relay) period = std::min(MaxConsentCheckPeriodMs, period);
		}
		e.nextTransmission = now + std::chrono::milliseconds(period);
	}
	void Agent::sendStunBinding(StunEntry& e, stun::Class cls, int errorCode,
		const std::array<unsigned char, 12>* replyTid,
		const net::AddrRecord* mapped) {
		stun::Message m;
		m.method = stun::Method::Binding;
		m.cls = cls;
		if (replyTid) m.transactionID = *replyTid;
		else {
			if (e.transactionIdExpired) {
				if (!crypto::randomBytes(e.transactionID.data(), 12)) { STICE_LOG_ERROR("sendStunBinding: randomBytes failed, dropping check"); return; }
				e.transactionIdExpired = false;
			}
			m.transactionID = e.transactionID;
		}
		if (cls == stun::Class::Request) {
			// USERNAME = "<remote_ufrag>:<local_ufrag>" (short-term cred).
			std::string username = remote_.iceUfrag + ":" + local_.iceUfrag;
			stun::addString(m, stun::AttrType::Username, username);
			// PRIORITY (peer-reflexive type preference, for learning prflx).
			// RFC 6544 §5.1: a check over TCP must advertise the priority of the
			// TCP peer-reflexive candidate it would create, so the transport type
			// (and its TCP preference penalty) comes from the local candidate
			// rather than being hardcoded to UDP.
			if (e.pair && e.pair->local) {
				int fam = e.pair->local->resolved.addr.ss_family;
				std::uint32_t pri = Candidate::computePriority(CandidateType::PeerReflexive,
					fam, e.pair->local->component, 0, e.pair->local->transport);
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
			// TCP-TYPE is carried at 0xC004 (comprehension-optional; 0x0026 is
			// IANA PADDING per RFC 5780), so a peer that does not know it ignores
			// the attribute instead of rejecting the check with 420. Still send it
			// only when BOTH sides of the pair are TCP — cross-transport pairs are
			// never formed, so the attribute would be dead weight. Maps the local
			// candidate transport to the wire enum value.
			if (e.pair && e.pair->local && e.pair->remote &&
				e.pair->local->transport != CandidateTransport::UDP &&
				e.pair->remote->transport != CandidateTransport::UDP) {
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
		}
		else if (cls == stun::Class::SuccessResponse && mapped) {
			stun::writeXorAddress(m, stun::AttrType::XorMappedAddress, *mapped, m.transactionID);
		}
		else if (cls == stun::Class::ErrorResponse) {
			stun::addErrorCode(m, errorCode);
		}
		// Encode with the appropriate password:
		// - requests: remote pwd (incoming checks) -> for outgoing checks, password = remote pwd
		// - responses: local pwd (responses use local pwd for MI verification by peer)
		const char* password = nullptr;
		if (cls == stun::Class::Request) password = remote_.icePwd.c_str();
		else password = local_.icePwd.c_str();
		m.encode(password, nullptr, "stice");
		STICE_LOG_DEBUG("sendStunBinding: local=%u cls=%d method=%d to=%s tid=%02x%02x%02x%02x useCand=%d", diagLocalPort_,
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
				sendTurnDataConn(reinterpret_cast<const char*>(m.raw.data()), m.raw.size());
			}
			return;
		}
		// Route via TCP if the pair uses TCP transport. RFC 6544: STUN messages
		// over TCP use RFC 4571 framing. If TCP is not yet connected, do NOT
		// fall through to UDP — the check is deferred until the connection
		// completes (handled in onTcpEvents).
		if (pairIsTcp(e.pair)) {
			if (hasConnectedTcpForPair(e.pair) ||
				(tcpMux_ && e.pair && e.pair->local &&
					e.pair->local->transport == CandidateTransport::TCPPassive)) {
				sendTcp(reinterpret_cast<const char*>(m.raw.data()), m.raw.size(), e.pair,
					/*control=*/true);
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
			for (const auto& re : entries_) {
				if (re.type == StunEntryType::Relay && re.turn &&
					re.turn->state() == turn::AllocState::Allocated) {
					routeViaRelay = true;
					break;
				}
			}
		}
		// Even if the pair local/remote are typed prflx (learned from a relayed
	// peer Binding), route via our TURN relay whenever the destination matches
	// a remote relayed candidate. Direct UDP to the peer relayed is dropped by
	// the remote TURN server (no permission) and stalls ICE in checking.
		if (!routeViaRelay) {
			for (const auto& rc : remote_.candidates) {
				if (rc.type != CandidateType::Relayed) continue;
				if (!rc.resolved.isEqual(e.record, true)) continue;
				for (auto& re : entries_) {
					if (re.type == StunEntryType::Relay && re.turn &&
						re.turn->state() == turn::AllocState::Allocated) {
						routeViaRelay = true; break;
					}
				}
				break;
			}
		}
		if (routeViaRelay) {
			for (auto& re : entries_) {
				if (re.type == StunEntryType::Relay && re.turn &&
					re.turn->state() == turn::AllocState::Allocated) {
					bool selfLoop = false;
					for (const auto &lc : local_.candidates)
						if (lc.type == CandidateType::Relayed && lc.resolved.isEqual(e.record, true)) { selfLoop = true; break; }
					if (selfLoop) {
						STICE_LOG_DEBUG("BINDING-OUT BLOCKED: self-loop local=%u to=%s tid=%02x%02x%02x%02x",
							diagLocalPort_, e.record.toString().c_str(),
							m.transactionID[0], m.transactionID[1], m.transactionID[2], m.transactionID[3]);
						if (e.pair) {
							e.pair->state = PairState::Failed;
							resetNomination(*e.pair);
						}
						return;
					}
					STICE_LOG_DEBUG("BINDING-OUT local=%u to=%s via_relay=1 raw_len=%zu tid=%02x%02x%02x%02x SELF_LOOP=%d",
						diagLocalPort_, e.record.toString().c_str(),
						m.raw.size(), m.transactionID[0], m.transactionID[1], m.transactionID[2], m.transactionID[3],
						selfLoop ? 1 : 0);
					int sent = re.turn->sendData(e.record, m.raw.data(), m.raw.size());
					if (sent <= 0)
						STICE_LOG_WARN("sendStunBinding: sendData to relayed %s failed n=%d",
							e.record.toString().c_str(), sent);
					return;
				}
			}
		}
		int sentUdp = sendUdp(reinterpret_cast<const char*>(m.raw.data()), m.raw.size(), e.record, /*control=*/true);
		if (sentUdp <= 0)
			STICE_LOG_WARN("sendStunBinding: sendUdp to %s failed n=%d",
				e.record.toString().c_str(), sentUdp);
	}
	void Agent::sendKeepalive(StunEntry& e) {
		// Consent freshness: Binding request (the response refreshes consent_expiry).
		sendStunBinding(e, stun::Class::Request, 0);
	}
	void Agent::sendBindingResponse(const stun::Message& req, const net::AddrRecord& dst, int errorCode,
			const std::vector<std::uint16_t>* unknown) {
		// Find or create a transient entry for the response. We don't track it
		// as a real STUN entry; we just send the response and discard.
		stun::Message m;
		m.method = stun::Method::Binding;
		m.cls = (errorCode == 0) ? stun::Class::SuccessResponse : stun::Class::ErrorResponse;
		m.transactionID = req.transactionID;
		if (errorCode == 0) {
			// Include XOR-MAPPED-ADDRESS of the source (the peer's address as seen by us).
			stun::writeXorAddress(m, stun::AttrType::XorMappedAddress, dst, m.transactionID);
		}
		else {
			stun::addErrorCode(m, errorCode);
			// RFC 8489 §14.9: 420 responses list the offending attribute types.
			if (errorCode == stun::StunErrorUnknownAttribute && unknown && !unknown->empty())
				stun::addUnknownAttributes(m, *unknown);
		}
		m.encode(local_.icePwd.c_str(), nullptr, "stice");
		// RFC 6062: if the request arrived via the TURN TCP data connection,
		// send the response back through the same data connection (not via
		// UDP TURN ChannelData or the raw UDP socket). The peer's TURN server
		// would drop a direct UDP response to the relayed address.
		if (turnDataConn_ && turnDataConn_->bound && dst.isEqual(turnDataConn_->peer, true)) {
			sendTurnDataConn(reinterpret_cast<const char*>(m.raw.data()), m.raw.size());
			return;
		}
		// If the request came over TCP, send the response over the same TCP
		// transport. Check TCPMux first (passive side), then the per-pair
		// connections (active side).
		// Binding responses are signalling: use the control queue so a bulk-data
		// backlog on the shared connection cannot delay them.
		if (tcpMux_) {
			int ret = tcpMux_->sendto(reinterpret_cast<const char*>(m.raw.data()),
				m.raw.size(), dst, /*control=*/true);
			if (ret > 0) return;
		}
		// If the request came over one of the direct ICE-TCP connections, answer
		// on that same connection (each pair owns its own socket now).
		for (auto& c : tcpConns_) {
			if (c.transport && c.transport->state() == net::TcpState::Connected &&
				dst.isEqual(c.peerAddr, true)) {
				sendTcp(reinterpret_cast<const char*>(m.raw.data()), m.raw.size(), c.pair,
					/*control=*/true);
				return;
			}
		}
		// RFC 8445 §7.2.5.2.1 (Symmetric Transport Addresses): the response must
		// originate from the address the request was sent to. When the request
		// arrived through a TURN relay, answer through that same allocation even
		// if the peer's address is a direct host candidate we could reach
		// ourselves. Sending it directly would expose our host address instead
		// of the relayed address, and the peer would (correctly) fail the pair.
		if (inboundTurn_ && inboundTurn_->state() == turn::AllocState::Allocated) {
			inboundTurn_->sendData(dst, m.raw.data(), m.raw.size());
			return;
		}
		// If the destination is a remote relayed candidate, route the response
		// through our local TURN relay (the peer's TURN server won't forward
		// direct UDP to the relayed address without a permission).
		bool remoteIsRelayed = false;
		for (const auto& rc : remote_.candidates) {
			if (rc.type == CandidateType::Relayed && rc.resolved.isEqual(dst, true)) {
				remoteIsRelayed = true;
				break;
			}
		}
		if (remoteIsRelayed) {
			for (auto& re : entries_) {
				// Only route through ALLOCATED relays. With multiple TURN servers,
				// entries_ may contain a dead server's relay (allocate timeout)
				// before the live one — sendData on an unallocated TURN silently
				// drops the message, so binding responses (and triggered-check
				// replies) would never reach the peer, stalling its ICE state in
				// "checking" until consent timeout.
				if (re.type == StunEntryType::Relay && re.turn &&
					re.turn->state() == turn::AllocState::Allocated) {
					re.turn->sendData(dst, m.raw.data(), m.raw.size());
					return;
				}
			}
		}
		sendUdp(reinterpret_cast<const char*>(m.raw.data()), m.raw.size(), dst, /*control=*/true);
	}
	bool Agent::verifyBindingRequest(const stun::Message& msg) {
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
		return msg.checkIntegrity(reinterpret_cast<const unsigned char*>(local_.icePwd.data()),
			local_.icePwd.size());
	}
	CandidatePair* Agent::findOrCreatePair(const net::AddrRecord& src, std::uint32_t priority,
		CandidateTransport transport) {
		// Link-local sources never form pairs (see formPairs for the rationale).
		// This guards the peer-reflexive path: inbound checks from 169.254/fe80
		// addresses still get a binding response (the caller sends an error
		// response so the peer's check fails fast), but no candidate pair is
		// created, so such a source can never be nominated or become the
		// selected pair.
		if (net::addrIsLinkLocal(reinterpret_cast<const sockaddr*>(&src.addr))) {
			STICE_LOG_DEBUG("findOrCreatePair: ignoring link-local source %s",
				src.toString().c_str());
			return nullptr;
		}
		// Look for an existing remote candidate matching `src` AND the transport
		// the request arrived on. Without the transport check, a UDP remote
		// candidate at the same address would be wrongly matched to an incoming
		// TCP check (and vice versa), producing a cross-transport pair that can
		// never succeed and confusing the pair state machine.
		bool srcIsTcp = (transport != CandidateTransport::UDP);
		const Candidate* remote = nullptr;
		for (const auto& c : remote_.candidates) {
			bool cIsTcp = (c.transport != CandidateTransport::UDP);
			if (c.resolved.isEqual(src, true) && cIsTcp == srcIsTcp) {
				remote = &c;
				break;
			}
		}
		if (!remote) {
			// Create a peer-reflexive remote candidate.
			if (remote_.candidates.size() >= MaxCandidates) {
				STICE_LOG_WARN("Agent: remote candidate limit (%zu) reached, dropping prflx %s",
					static_cast<std::size_t>(MaxCandidates), src.toString().c_str());
				return nullptr;
			}
			Candidate c;
			c.type = CandidateType::PeerReflexive;
			c.transport = transport;
			c.component = 1;
			c.resolved = src;
			c.priority = priority;
			auto* sa = reinterpret_cast<const sockaddr*>(&src.addr);
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
		//
		// RFC 8445 §7.2.5.2.1: when the datagram arrived through a TURN
		// allocation, the pair's local candidate is the relayed candidate of
		// that allocation — the transport address the peer actually targeted.
		// Falling back to the first same-family UDP candidate (usually the host
		// one) would make the triggered check leave from the host address, and
		// the peer would fail the relay pair as non-symmetric.
		bool transportIsTcp = (transport != CandidateTransport::UDP);
		const Candidate* local = nullptr;
		if (inboundTurn_ && inboundTurn_->state() == turn::AllocState::Allocated) {
			for (const auto& l : local_.candidates) {
				if (l.type == CandidateType::Relayed &&
					l.resolved.isEqual(inboundTurn_->relayedAddr(), true)) {
					local = &l;
					break;
				}
			}
		}
		if (!local) {
			for (const auto& l : local_.candidates) {
				bool localIsTcp = (l.transport != CandidateTransport::UDP);
				if (l.resolved.addr.ss_family == remote->resolved.addr.ss_family &&
					localIsTcp == transportIsTcp) {
					local = &l;
					break;
				}
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
		for (auto& p : pairs_) {
			if (p->local == local && p->remote == remote) return p.get();
		}
		if (pairs_.size() >= MaxCandidatePairs) pruneFailedPairs();
		if (pairs_.size() >= MaxCandidatePairs) {
			STICE_LOG_WARN("Agent: candidate pair limit (%zu) reached, dropping pair local=%s remote=%s",
				static_cast<std::size_t>(MaxCandidatePairs), local->hostname.c_str(),
				remote->hostname.c_str());
			return nullptr;
		}
		auto p = std::make_unique<CandidatePair>();
		p->local = local;
		p->remote = remote;
		p->state = PairState::Frozen;
		p->updatePriority(mode_ == AgentMode::Controlling);
		CandidatePair* out = p.get();
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
	void Agent::handleBindingRequest(const stun::Message& msg, const net::AddrRecord& src,
		CandidateTransport transport) {
		for (const auto &lc : local_.candidates) {
			if (lc.type == CandidateType::Relayed && lc.resolved.isEqual(src, true)) {
				STICE_LOG_DEBUG("HBR REJECTED: loopback from own relay %s tid=%02x%02x%02x%02x",
					src.toString().c_str(),
					msg.transactionID[0], msg.transactionID[1], msg.transactionID[2], msg.transactionID[3]);
				return;
			}
		}
		STICE_LOG_DEBUG("handleBindingRequest: from=%s transport=%s tid=%02x%02x%02x%02x useCand=%d",
			src.toString().c_str(), transportString(transport),
			msg.transactionID[0], msg.transactionID[1], msg.transactionID[2], msg.transactionID[3],
			static_cast<int>(stun::hasUseCandidate(msg)));
		// RFC 8489 §6.3.4/§9.3: a request carrying comprehension-required
		// attributes we do not understand MUST be rejected with 420 listing them
		// (400/420 are exempt from MESSAGE-INTEGRITY per §9.2.2).
		if (!msg.unknownComprehensionRequired.empty()) {
			STICE_LOG_WARN("handleBindingRequest: 420 Unknown-Attribute (%zu type(s)) from %s",
				msg.unknownComprehensionRequired.size(), src.toString().c_str());
			sendBindingResponse(msg, src, stun::StunErrorUnknownAttribute,
				&msg.unknownComprehensionRequired);
			return;
		}
		// Verify integrity (unless this is an indication).
		if (!verifyBindingRequest(msg)) {
			STICE_LOG_DEBUG("handleBindingRequest: verification FAILED");
			STICE_LOG_DEBUG("HBR local=%u VERIFY-FAIL from=%s mi=%d", diagLocalPort_, src.toString().c_str(),
				(msg.find(stun::AttrType::MessageIntegrity) == nullptr) ? 0 : 1);
			// RFC 8489 §9.2.2: a request whose MESSAGE-INTEGRITY is missing or
			// whose HMAC does not verify is answered with 401 (Unauthorized) -
			// the same code in both cases, so a peer that sent the wrong key and
			// one that sent none get an identical, unambiguous rejection.
			sendBindingResponse(msg, src, stun::StunErrorUnauthenticated);
			return;
		}
		STICE_LOG_DEBUG("handleBindingRequest: verification OK");
		// RFC 7675 §5.1 (pion agent.go:1726/1840 wide criterion): a validated
		// inbound Binding Request is itself proof the peer considers this path
		// alive. Refresh the matching pair's consent freshness on our side too —
		// relying only on our own keepalive responses misses peers that send
		// requests/media but answer our checks slowly, and then expires their
		// pair at 30 s while traffic is still flowing.
		{
			CandidatePair* inboundPair = nullptr;
			for (auto& p : pairs_) {
				if (p->remote && p->remote->resolved.isEqual(src, true) &&
					p->state == PairState::Succeeded) {
					inboundPair = p.get();
					break;
				}
			}
			if (inboundPair) {
				inboundPair->consentExpiry = std::chrono::steady_clock::now() +
					std::chrono::milliseconds(ConsentTimeoutMs);
			}
		}
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
				applyRoleSwitch();
			}
		}
		else if (msg.find(stun::AttrType::IceControlled)) {
			stun::readIceControlled(msg, peerTb);
			if (mode_ == AgentMode::Controlled) {
				if (tiebreaker_ >= peerTb) {
					mode_ = AgentMode::Controlling;
					applyRoleSwitch();
				}
				else {
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
		// RFC 6544 §6.2.1: TCP-TYPE used to be write-only on our side. Read it
		// back and use it as the peer's own candidate direction when the check
		// arrived over TCP — the inbound channel only says "TCP", not whether
		// the peer is active or passive, so this is what lets a peer-reflexive
		// remote candidate be classified correctly.
		CandidateTransport peerTcpTransport = transport;
		if (transport != CandidateTransport::UDP) {
			std::uint32_t tcpType = 0;
			if (stun::readTcpType(msg, tcpType)) {
				switch (tcpType) {
				case stun::TcpTypeActive: peerTcpTransport = CandidateTransport::TCPActive; break;
				case stun::TcpTypePassive: peerTcpTransport = CandidateTransport::TCPPassive; break;
				case stun::TcpTypeSo: peerTcpTransport = CandidateTransport::TCPSimultaneousOpen; break;
				default:
					STICE_LOG_WARN("handleBindingRequest: unknown TCP-TYPE 0x%x from %s, ignoring",
						static_cast<unsigned>(tcpType), src.toString().c_str());
					break;
				}
			}
		}
		// Find or create the candidate pair.
		CandidatePair* pair = findOrCreatePair(src, priority, peerTcpTransport);
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
			}
			else {
				// Classic USE-CANDIDATE (RFC 8445): always nominate.
				if (pair->state == PairState::Succeeded) pair->nominated = true;
				else pair->nominationRequested = true;
			}
		}
		STICE_LOG_DEBUG("HBR local=%u SEND-RESP from=%s useCand=%d mode=%d", diagLocalPort_, src.toString().c_str(),
			static_cast<int>(useCandidate), static_cast<int>(mode_));
		// Send success response.
		sendBindingResponse(msg, src, 0);
		// Triggered check (RFC 8445 §7.3.1.4): a pair that is not yet Succeeded
		// must be (re-)queued so both agents validate it.
		if (pair->state != PairState::Succeeded && !remote_.iceUfrag.empty()) {
			// Do not resurrect a Cancelled entry. After another pair was
			// nominated, the remaining pairs were frozen and their checks
			// cancelled (RFC 8445 §8.1.2); a late/duplicate binding request on
			// one of them must not restart checks on the abandoned path (nor
			// move its pair out of Frozen without an armed entry).
			StunEntry* e = findEntry(pair);
			if (e && e->state == StunEntryState::Cancelled) {
				STICE_LOG_DEBUG("HBR: pair entry Cancelled, not scheduling triggered check");
			}
			else {
				if (!e && (entries_.size() < MaxStunEntries || reclaimDeadEntries())) {
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
					// armTransmission issues a NEW transaction ID and resets the
					// retransmission counter. For an In-Progress pair that is
					// exactly RFC 8445 §7.3.1.4's cancellation: the in-flight
					// transaction is no longer retransmitted and its missing
					// response is not counted as a failure; the fresh check
					// validates the pair immediately instead of waiting for the
					// old transaction to time out. For a Waiting/Frozen/Failed
					// pair it re-queues the check (a Failed pair moves back to
					// Pending, which may in turn revive the checklist).
					// The pair state only flips once an entry is actually armed:
					// leaving it untouched when the table is full keeps a Failed
					// pair Failed instead of parking it in Pending forever with
					// nothing scheduled.
					const bool revivedFailedPair = pair->state == PairState::Failed;
					pair->state = PairState::Pending;
					// P1-N3: a plain check reviving a previously nominated pair
					// must not inherit stale nomination flags — the controlled
					// side would auto-report COMPLETED without a fresh
					// UseCandidate. A request that carries UseCandidate just set
					// them above, so keep those.
					if (revivedFailedPair && !useCandidate) resetNomination(*pair);
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
	}
	void Agent::handleBindingResponse(const stun::Message& msg, const net::AddrRecord& src,
		StunEntry& e) {
		STICE_LOG_DEBUG("handleBindingResponse: from=%s cls=%d",
			src.toString().c_str(), static_cast<int>(msg.cls));
		// RFC 8445 §7.2.5.2.1 (Non-Symmetric Transport Addresses): if the
		// response source does not equal the destination the request was sent
		// to, the agent MUST set the candidate pair state to Failed. It is not
		// merely discarded: a reply arriving from a different 5-tuple means the
		// pair cannot work, so retrying it would just burn the check budget.
		if (!e.record.isEqual(src, true)) {
			STICE_LOG_DEBUG("handleBindingResponse: non-symmetric response (expected %s got %s), pair failed",
				e.record.toString().c_str(), src.toString().c_str());
			e.state = StunEntryState::Failed;
			if (e.pair) {
				e.pair->state = PairState::Failed;
				resetNomination(*e.pair);
			}
			if (e.type == StunEntryType::Check) {
				armNextFrozenPair();
				wakePoll();
			}
			updateState();
			return;
		}
		// A Cancelled entry belongs to a pair whose checks were cancelled when
		// another pair was nominated (RFC 8445 §8.1.2). A late/duplicate response
		// must not resurrect it: flipping the pair back to Succeeded re-arms its
		// keepalive and can re-select the path we deliberately abandoned. This
		// guard covers both success and error responses, so a stale 487 cannot
		// also re-arm the entry via applyRoleSwitch.
		if (e.state == StunEntryState::Cancelled) {
			STICE_LOG_DEBUG("handleBindingResponse: entry Cancelled, ignoring response");
			return;
		}
		if (msg.cls == stun::Class::ErrorResponse) {
			int code = 0;
			std::string reason;
			stun::readErrorCode(msg, code, reason);
			if (code == stun::StunErrorUnknownAttribute) {
				// RFC 8489 §6.3.4: our check carried an attribute the peer does not
				// understand. Log the rejected types so the wire mismatch is visible,
				// then fail the pair like any other terminal error.
				std::vector<std::uint16_t> rejected;
				stun::readUnknownAttributes(msg, rejected);
				STICE_LOG_WARN("handleBindingResponse: 420 Unknown-Attribute from %s (%zu type(s))",
					src.toString().c_str(), rejected.size());
			}
			if (code == 487) {
				// Role conflict: switch role. RFC 8445 §7.3.1.1 does not
				// require regenerating the tiebreaker — pion-ice preserves it.
				if (e.mode == mode_) {
					mode_ = (mode_ == AgentMode::Controlling) ? AgentMode::Controlled : AgentMode::Controlling;
					applyRoleSwitch();
					if (e.state != StunEntryState::Idle) {
						armTransmission(e, 0);
					}
				}
				return;
			}
			// Transient error responses get a bounded retry buffer before the
			// pair is failed: a 401 can race the credential exchange across an
			// ICE restart and 500 can be momentary overload. 400 stays terminal
			// on purpose — a ufrag/pwd mismatch never heals within a generation,
			// and the fast-failure product choice (integration test: wrong-ufrag
			// must fail in seconds) outweighs a retry that cannot succeed. Each
			// retry is a fresh transaction (armTransmission regenerates the TID);
			// persistent errors exhaust the budget and fail the pair below.
			if ((code == 401 || code == 500) &&
				e.errorRetries < MaxStunErrorResponseRetries) {
				++e.errorRetries;
				STICE_LOG_WARN("handleBindingResponse: %d from %s, retrying (%d/%d)",
					code, src.toString().c_str(), e.errorRetries, MaxStunErrorResponseRetries);
				if (e.state != StunEntryState::Idle) {
					armTransmission(e, 0);
					wakePoll();
				}
				return;
			}
			e.state = StunEntryState::Failed;
			if (e.pair) {
				e.pair->state = PairState::Failed;
				resetNomination(*e.pair);
			}
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
		// Late success response for a pair that already timed out: ignore it.
		// Without this, a delayed-but-correctly-matched response resurrects the
		// Failed pair (sets it Succeeded and re-arms the keepalive), which can
		// re-select a dead path.
		if (e.type == StunEntryType::Check && e.pair && e.pair->state == PairState::Failed) {
			STICE_LOG_DEBUG("handleBindingResponse: pair already Failed, ignoring late response");
			return;
		}
		// Success.
		// Fresh retry budget: keepalives reuse this entry, so a later transient
		// consent error must not inherit the check phase's exhausted budget.
		e.errorRetries = 0;
		if (e.pair) {
			// RFC 8445 §7.2.5.3.2: the valid pair is built from the mapped address
			// in the response (our transport address as seen by the peer) and the
			// destination the check was sent to — not blindly from the pair that
			// generated the check. Only meaningful for UDP (the mapped address over
			// TCP is the local socket address, which the active-TCP candidate does
			// not track) and only when the mapped address is a real address.
			net::AddrRecord mapped{};
			bool haveMapped = stun::readXorAddress(msg, stun::AttrType::XorMappedAddress,
				mapped, msg.transactionID);
			if (!haveMapped) haveMapped = stun::readMappedAddress(msg, mapped);
			if (haveMapped && e.pair->local && e.pair->remote &&
				e.pair->local->transport == CandidateTransport::UDP &&
				!net::addrIsAny(reinterpret_cast<const sockaddr*>(&mapped.addr)) &&
				!e.pair->local->resolved.isEqual(mapped, true)) {
				classifyValidPair(*e.pair, mapped);
			}
			e.pair->state = PairState::Succeeded;
			e.pair->consentExpiry = std::chrono::steady_clock::now() +
				std::chrono::milliseconds(ConsentTimeoutMs);
			if (e.pair->nominationRequested) e.pair->nominated = true;
			// Controlling-side nomination: select the best (highest-priority)
			// succeeded pair and schedule nomination with a candidate-type-based
			// delay (aligned with pion-ice defaultNominationDelay).
			if (mode_ == AgentMode::Controlling) {
				CandidatePair* best = nullptr;
				for (const auto& p : pairs_)
					if (p->state == PairState::Succeeded &&
						(!best || p->priority > best->priority))
						best = p.get();
				if (best) {
					// RFC 8445 §8.1.1: regular nomination picks the highest-
					// priority valid pair once and MUST NOT switch afterwards
					// (only an ICE restart may). Re-nomination is a
					// draft-thatcher-ice-renomination extension that requires
					// negotiation; nothing here negotiates it, so it stays an
					// opt-in escape hatch.
					const bool allowRenomination = renominationAllowed();
					bool shouldNominate = false;
					if (!selectedPair_) {
						shouldNominate = true;
						// First nomination: start the counter at 1.
						++nominationValue_;
					}
					else if (best != selectedPair_ && best->priority > selectedPair_->priority) {
						if (allowRenomination) {
							// Re-nomination: a better pair succeeded after the
							// current selected pair. Switch and re-nominate
							// (draft-thatcher).
							shouldNominate = true;
							++nominationValue_;
							STICE_LOG_DEBUG("renomination: switching to higher-priority pair (value=%u)",
								nominationValue_);
						}
						else {
							STICE_LOG_DEBUG("nomination locked: ignoring higher-priority pair "
								"(RFC 8445 §8.1.1; set STICE_ICE_RENOMINATION=1 to allow)");
						}
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
	void Agent::classifyValidPair(CandidatePair& generating, const net::AddrRecord& mapped) {
		const Candidate* remote = generating.remote;
		// Case 2: the mapped address already belongs to one of our local
		// candidates (e.g. the srflx candidate the NAT actually exposes). The
		// pair (that local candidate, same remote) is the RFC-valid pair.
		const Candidate* local = nullptr;
		for (const auto& l : local_.candidates) {
			if (l.transport == CandidateTransport::UDP && l.resolved.isEqual(mapped, true)) {
				local = &l;
				break;
			}
		}
		bool learnedPrflx = false;
		if (!local) {
			// Case 3: no local candidate covers the mapped address — learn a local
			// peer-reflexive candidate. RFC 8445 §7.2.5.3.2: its priority is the
			// PRIORITY attribute carried by the check that just completed, which is
			// what the local candidate of this pair was checked with.
			std::size_t before = local_.candidates.size();
			Candidate c;
			c.type = CandidateType::PeerReflexive;
			c.transport = CandidateTransport::UDP;
			c.component = generating.local->component;
			c.resolved = mapped;
			auto* sa = reinterpret_cast<const sockaddr*>(&mapped.addr);
			char host[NI_MAXHOST];
			char serv[NI_MAXSERV];
			if (getnameinfo(sa, net::addrLen(sa), host, sizeof(host), serv, sizeof(serv),
				NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
				c.hostname = host;
				c.service = serv;
			}
			// RFC 8445 §7.2.5.3.2: the priority of a learned peer-reflexive
			// candidate is the PRIORITY attribute of the check, i.e. the value the
			// sending side computed for the peer-reflexive candidate it would learn
			// (see sendStunBinding: computePriority(PeerReflexive, ...)). Copying the
			// checking candidate's own priority here instead inflated prflx pairs in
			// the checklist ordering relative to what the peer advertised.
			c.priority = c.computePriority(0);
			c.foundation = Candidate::computeFoundation(c.type, c.hostname, c.transport);
			addLocalCandidate(std::move(c));
			if (local_.candidates.size() <= before) {
				STICE_LOG_WARN("valid pair: could not learn peer-reflexive %s (candidate limit reached)",
					mapped.toString().c_str());
				return;
			}
			local = &local_.candidates.back();
			learnedPrflx = true;
		}
		// Find or create the pair (mapped local candidate × the check's remote).
		// addLocalCandidate() already ran formPairs(), so the pair usually exists.
		CandidatePair* validPair = nullptr;
		for (auto& p : pairs_) {
			if (p->local == local && p->remote == remote) {
				validPair = p.get();
				break;
			}
		}
		if (!validPair && pairs_.size() < MaxCandidatePairs) {
			auto np = std::make_unique<CandidatePair>();
			np->local = local;
			np->remote = remote;
			np->state = PairState::Frozen;
			np->updatePriority(mode_ == AgentMode::Controlling);
			validPair = np.get();
			pairs_.push_back(std::move(np));
			updateOrderedPairs();
		}
		if (!validPair) {
			STICE_LOG_WARN("valid pair: no pair for mapped %s (pair limit reached)", mapped.toString().c_str());
			return;
		}
		validPair->state = PairState::Succeeded;
		validPair->consentExpiry = std::chrono::steady_clock::now() +
			std::chrono::milliseconds(ConsentTimeoutMs);
		// Give the valid pair an entry so nomination / consent keepalive can
		// address it (a succeeded pair without an entry can never be nominated).
		StunEntry* ve = findEntry(validPair);
		if (!ve && (entries_.size() < MaxStunEntries || reclaimDeadEntries())) {
			StunEntry ne;
			ne.type = StunEntryType::Check;
			ne.state = StunEntryState::Pending;
			ne.pair = validPair;
			ne.record = validPair->remote->resolved;
			ne.mode = mode_;
			entries_.push_back(std::move(ne));
			ve = &entries_.back();
		}
		if (ve) armKeepalive(*ve);
		STICE_LOG_INFO("valid pair: mapped=%s remote=%s local=%s%s (generating pair priority=%llu)",
			mapped.toString().c_str(), remote->resolved.toString().c_str(),
			local->resolved.toString().c_str(), learnedPrflx ? " (peer-reflexive)" : "",
			static_cast<unsigned long long>(generating.priority));
		wakePoll();
	}
	void Agent::handleServerReflexiveResponse(const stun::Message& msg,
		const net::AddrRecord& src, StunEntry& e) {
		// Terminal-state guard (at-most-once). The response matching loop keys
		// on the transaction ID alone, so a retransmitted or duplicated response
		// matches the SAME entry again. Re-running the success path decremented
		// pendingServerReflexive_ a second time, driving it negative and
		// permanently breaking every `pendingServerReflexive_ == 0` condition in
		// the gather-complete checks. The relay path already guards this way.
		if (e.state != StunEntryState::Pending) {
			STICE_LOG_DEBUG("Agent: duplicate STUN srflx response for terminal entry, ignoring");
			return;
		}
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
		auto* sa = reinterpret_cast<const sockaddr*>(&reflexive.addr);
		char host[NI_MAXHOST];
		char serv[NI_MAXSERV];
		getnameinfo(sa, net::addrLen(sa), host, sizeof(host), serv, sizeof(serv),
			NI_NUMERICHOST | NI_NUMERICSERV);
		c.hostname = host;
		c.service = serv;
		if (boundAddrUdp(c.related)) c.hasRelated = true;
		// RFC 8445 §5.1.2.1: distinct candidate addresses should not share the
		// same local preference. With several STUN servers each reflexive address
		// gets its own index; duplicate mappings are dropped by addLocalCandidate.
		int srflxIndex = 0;
		for (const auto& lc : local_.candidates)
			if (lc.type == CandidateType::ServerReflexive) ++srflxIndex;
		c.priority = c.computePriority(srflxIndex);
		c.foundation = Candidate::computeFoundation(c.type, c.hostname, c.transport);
		addLocalCandidate(c);
		emitCandidate(c);
		STICE_LOG_DEBUG("STUN srflx candidate gathered: %s:%s", host, serv);
		e.state = StunEntryState::Succeeded;
		--pendingServerReflexive_;
		checkGatheringComplete();
	}
	void Agent::handleStunMessage(const stun::Message& msg, const net::AddrRecord& src,
		CandidateTransport transport) {
		if (msg.method != stun::Method::Binding) return;
		if (msg.cls == stun::Class::Request) {
			handleBindingRequest(msg, src, transport);
			return;
		}
		if (stun::isResponseType(msg.cls)) {
			// Find the entry with matching transaction ID.
			bool matched = false;
			for (auto& e : entries_) {
				if (std::memcmp(e.transactionID.data(), msg.transactionID.data(), 12) == 0) {
					matched = true;
					STICE_LOG_DEBUG("STUN-RESP: tid=%02x%02x%02x%02x MATCH type=%d from=%s entries=%zu",
						msg.transactionID[0], msg.transactionID[1], msg.transactionID[2],
						msg.transactionID[3], static_cast<int>(e.type),
						src.toString().c_str(), entries_.size());
					if (e.type == StunEntryType::Server)
						handleServerReflexiveResponse(msg, src, e);
					else
						handleBindingResponse(msg, src, e);
					return;
				}
			}
			if (!matched)
				STICE_LOG_DEBUG("STUN-RESP: tid=%02x%02x%02x%02x NO-MATCH from=%s entries=%zu",
					msg.transactionID[0], msg.transactionID[1], msg.transactionID[2],
					msg.transactionID[3], src.toString().c_str(), entries_.size());
			return;
		}
		// Indication: ignore (or treat as keepalive).
	}
	void Agent::handleInboundUdp(const char* buf, int len, const net::AddrRecord& src,
		CandidateTransport transport) {
		if (len <= 0) return;
		const auto* data = reinterpret_cast<const unsigned char*>(buf);
		STICE_LOG_DEBUG("handleInboundUdp: %d bytes from %s transport=%d", len, src.toString().c_str(),
			static_cast<int>(transport));
		// Demux: STUN / ChannelData / app data.
		if (stun::Message::isMessage(data, static_cast<std::size_t>(len))) {
			stun::Message m;
			if (!m.decode(data, static_cast<std::size_t>(len))) return;
			if (!fingerprintAcceptable(m, "ICE-UDP")) return;
			STICE_LOG_DEBUG("ICE-STUN-IN method=%d cls=%d(%s) tid=%02x%02x%02x%02x src=%s len=%d",
				static_cast<int>(m.method), static_cast<int>(m.cls),
				(m.cls == stun::Class::Request) ? "REQ" : "RESP",
				m.transactionID[0], m.transactionID[1], m.transactionID[2], m.transactionID[3],
				src.toString().c_str(), len);
			if (m.method == stun::Method::Binding) {
				handleStunMessage(m, src, transport);
			}
			else {
				// TURN STUN response or indication (Allocate, CreatePermission,
				// ChannelBind, Refresh, Data, etc.): forward to all relay entries'
				// TURN clients. Each client checks if it has a matching pending TID.
				bool turnHandled = false;
				for (auto& e : entries_) {
					if (e.type == StunEntryType::Relay && e.turn &&
						e.record.isEqual(src, true)) {
						e.turn->handleInbound(data, static_cast<std::size_t>(len));
						turnHandled = true;
						break;
					}
				}
				if (!turnHandled) {
					STICE_LOG_WARN("STUN-IN: unmatched TURN response from %s method=%d cls=%d",
						src.toString().c_str(), static_cast<int>(m.method), static_cast<int>(m.cls));
				}
			}
			return;
		}
		if (turn::isChannelData(data, static_cast<std::size_t>(len))) {
			// ChannelData from a TURN server: find the relay entry and let its
			// turn::Client decode it. Source-address discrimination: only frames
			// from the entry's TURN control endpoint (e.record, e.g. port 3478)
			// are ChannelData. Raw application data from a relay port / peer
			// whose first bytes merely look like a ChannelData frame (first byte
			// 0x40-0x7F and a plausible length field) must fall through to app
			// delivery instead of being silently dropped as an invalid channel.
			for (auto& e : entries_) {
				if (e.type == StunEntryType::Relay && e.turn && e.record.isEqual(src, true)) {
					e.turn->handleInbound(data, static_cast<std::size_t>(len));
					return;
				}
			}
			// Not from a TURN control endpoint: treat as application data below.
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
		CandidatePair* dataPair = nullptr;
		for (auto& p : pairs_) {
			if (p->state == PairState::Succeeded && p->remote &&
				p->remote->resolved.isEqual(src, true)) {
				if (selectedPair_ != p.get()) {
					STICE_LOG_DEBUG("handleInboundUdp: updating selectedPair_ to match data source %s",
						src.toString().c_str());
					selectedPair_ = p.get();
				}
				dataPair = p.get();
				break;
			}
		}
		emitRecv(buf, static_cast<std::size_t>(len), dataPair);
	}
	int Agent::sendUdp(const char* data, std::size_t size, const net::AddrRecord& dst,
		bool control) {
		int r = mux_ ? mux_->sendto(data, size, dst, local_.iceUfrag)
			: sock_.sendto(data, size, dst);
		// Control frames refused by a backed-up socket (bulk-data flood filling
		// SO_SNDBUF) are queued and retried with priority by
		// flushUdpControlQueue() on the next onBookkeeping pass, instead of being
		// dropped. Bulk data keeps the existing backpressure contract (-errno).
		if (r < 0 && control) {
			int e = sticeSockerrno;
			if (e == STICE_SEAGAIN || e == STICE_SEWOULDBLOCK || e == STICE_SENOBUFS) {
				std::lock_guard<std::mutex> lock(udpCtrlMutex_);
				udpCtrlQueue_.emplace_back(dst,
					std::vector<unsigned char>(data, data + size));
				return static_cast<int>(size); // accepted; flushed with priority
			}
		}
		return r;
	}
	void Agent::flushUdpControlQueue() {
		std::lock_guard<std::mutex> lock(udpCtrlMutex_);
		while (!udpCtrlQueue_.empty()) {
			auto& item = udpCtrlQueue_.front();
			int r = mux_ ? mux_->sendto(reinterpret_cast<const char*>(item.second.data()),
				item.second.size(), item.first, local_.iceUfrag)
				: sock_.sendto(reinterpret_cast<const char*>(item.second.data()),
					item.second.size(), item.first);
			if (r < 0) {
				int e = sticeSockerrno;
				if (e == STICE_SEAGAIN || e == STICE_SEWOULDBLOCK || e == STICE_SENOBUFS)
					break; // socket still backed up; retry next pass
			}
			udpCtrlQueue_.pop_front();
		}
	}
	int Agent::sendTcp(const char* data, std::size_t size, const CandidatePair* pair,
		bool control) {
		const CandidatePair* p = pair ? pair : selectedPair_;
		// Route through TCPMux if the local candidate is TCPPassive.
		if (tcpMux_ && p && p->local &&
			p->local->transport == CandidateTransport::TCPPassive && p->remote) {
			int ret = tcpMux_->sendto(data, size, p->remote->resolved, control);
			if (ret > 0) return ret;
			STICE_LOG_WARN("sendTcp: TCPMux sendto failed for %s (ret=%d)",
				p->remote->resolved.toString().c_str(), ret);
			return STICE_ERR_FAILED;
		}
		// RFC 6544 §7.1: each active pair owns its own connection, so route the
		// frame to the connection backing this pair instead of a single transport.
		TcpConnection* conn = tcpConnForPair(p);
		if (!conn || !conn->transport || conn->transport->state() != net::TcpState::Connected) {
			STICE_LOG_DEBUG("sendTcp: direct transport not connected (state=%d), dropping %zu bytes",
				conn && conn->transport ? static_cast<int>(conn->transport->state()) : -1, size);
			return STICE_ERR_FAILED;
		}
		// Control frames (STUN checks/responses) jump the bulk-data backlog so a
		// saturated application stream cannot starve connectivity signalling.
		bool ok = control ? conn->transport->sendControl(data, size)
			: conn->transport->send(data, size);
		if (!ok) {
			STICE_LOG_WARN("sendTcp: direct transport send failed (%zu bytes)", size);
			return STICE_ERR_FAILED;
		}
		return static_cast<int>(size);
	}
	bool Agent::pairIsTcp(const CandidatePair* p) const {
		if (!p || !p->local || !p->remote) return false;
		return p->local->transport != CandidateTransport::UDP &&
			p->remote->transport != CandidateTransport::UDP;
	}
	bool Agent::pairIsTurnTcpRelay(const CandidatePair* p) const {
		if (!p || !p->local) return false;
		return p->local->type == CandidateType::Relayed &&
			p->local->transport == CandidateTransport::TCPPassive;
	}
	void Agent::handleInboundTcp(TcpConnection& conn) {
		// Drain all complete RFC 4571-framed messages from the receive buffer.
		// Re-check the transport every iteration: dispatch can reach updateState()
		// and closeUnselectedTcpConns(), which resets the transport of a losing
		// connection while this loop is still reading from it.
		char buf[65536];
		net::AddrRecord peer;
		while (conn.transport) {
			int n = conn.transport->recv(buf, sizeof(buf), peer);
			if (n <= 0) break;
			handleInboundTcpPacket(buf, n, conn.peerAddr, &conn);
		}
	}
	void Agent::handleInboundTcpPacket(const char* data, int len, const net::AddrRecord& src,
		TcpConnection* conn) {
		const auto* udata = reinterpret_cast<const unsigned char*>(data);
		STICE_LOG_DEBUG("ICE-TCP: inbound packet %d bytes from %s", len, src.toString().c_str());
		// Demultiplex: STUN / app data (no ChannelData over ICE-TCP).
		if (stun::Message::isMessage(udata, static_cast<std::size_t>(len))) {
			stun::Message m;
			if (!m.decode(udata, static_cast<std::size_t>(len))) {
				STICE_LOG_WARN("ICE-TCP: STUN decode failed (%d bytes from %s)", len, src.toString().c_str());
				return;
			}
			if (!fingerprintAcceptable(m, "ICE-TCP")) return;
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
		// RFC 6544 §7.1: on a direct TCP connection, if the peer's first
		// connectivity check is not a STUN message, the remote candidate's
		// address apparently is not one of the peer's addresses. The agent
		// SHOULD close the connection and consider all pairs with that remote
		// candidate Failed, instead of accepting unvalidated application data.
		if (conn && conn->pair && conn->pair->state != PairState::Succeeded) {
			const Candidate* remote = conn->pair->remote;
			STICE_LOG_WARN("ICE-TCP: first frame from %s is not STUN before validation, "
			               "closing connection and failing the remote candidate",
			               src.toString().c_str());
			for (auto& p : pairs_)
				if (p->remote == remote && p->state != PairState::Failed) {
					p->state = PairState::Failed;
					resetNomination(*p);
				}
			if (conn->transport) conn->transport->close();
			updateState();
			return;
		}
		STICE_LOG_DEBUG("ICE-TCP: application data %d bytes from %s", len, src.toString().c_str());
		emitRecv(data, static_cast<std::size_t>(len), conn ? conn->pair : nullptr);
	}
	bool Agent::startTcpConn(TcpConnection& conn, const net::AddrRecord& remoteAddr,
		const std::string& sni) {
		conn.transport = std::make_unique<net::TcpTransport>();
		conn.peerAddr = remoteAddr;
		// SNI is kept for a potential TLS upgrade; plain ICE-TCP ignores it.
		conn.sni = sni;
		// P1-C6: bind the outgoing connection to a gathered host address so the
		// resulting local candidate is an address we actually know about instead
		// of an OS routing choice. Only when exactly one non-loopback host
		// candidate of the remote's family exists — multi-homed hosts keep the
		// OS default route rather than guessing an interface.
		net::AddrRecord bindAddr{};
		const net::AddrRecord* bindPtr = nullptr;
		// A loopback/link-local destination must be reached from a source of the
		// same scope: binding a non-loopback host address and then connecting to
		// 127.0.0.1 fails with EADDRNOTAVAIL/WSAEADDRNOTAVAIL. Leave such dials
		// to the OS routing choice (which picks the matching local address).
		if (!net::addrIsLocal(reinterpret_cast<const sockaddr*>(&remoteAddr.addr))) {
			int count = 0;
			const net::AddrRecord* only = nullptr;
			for (const auto& lc : local_.candidates) {
				if (lc.type != CandidateType::Host) continue;
				if (lc.resolved.addr.ss_family != remoteAddr.addr.ss_family) continue;
				if (net::addrIsLocal(reinterpret_cast<const sockaddr*>(&lc.resolved.addr))) continue;
				++count;
				only = &lc.resolved;
			}
			if (count == 1) {
				bindAddr = *only;
				net::addrSetPort(reinterpret_cast<sockaddr*>(&bindAddr.addr), 0);
				bindPtr = &bindAddr;
			}
		}
		if (!conn.transport->beginConnect(remoteAddr, "", false, false, std::string(), bindPtr)) {
			conn.transport.reset();
			return false;
		}
		// Arm an application-layer connect timeout so a black-holed remote
		// (no SYN-ACK) does not leave the transport stuck in Connecting forever.
		conn.transport->setConnectTimeoutMs(TcpConnectTimeoutMs);
		return true;
	}
	void Agent::addRemotePassiveTcpCandidate(const Candidate& remote) {
		// Aligned with pion-ice addRemotePassiveTCPCandidate: create a local
		// active TCP candidate by dialing the remote passive candidate's address.
		// One connection per active pair (RFC 6544 §7.1): a second remote passive
		// candidate gets its own socket instead of resetting the first.
		STICE_LOG_INFO("ICE-TCP: addRemotePassiveTcpCandidate host=%s:%s",
			remote.hostname.c_str(), remote.service.c_str());
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
		// Reuse an existing connection to this exact endpoint when it is still
		// live; otherwise recreate it. Its local candidate already exists, so a
		// redial must not add a duplicate candidate.
		for (auto& c : tcpConns_) {
			if (!c.peerAddr.isEqual(remoteAddr, true)) continue;
			if (c.transport &&
				(c.transport->state() == net::TcpState::Connected ||
				 c.transport->state() == net::TcpState::Connecting ||
				 c.transport->state() == net::TcpState::TlsHandshaking)) {
				STICE_LOG_DEBUG("ICE-TCP: connection to %s already in progress/connected, skipping",
					remoteAddr.toString().c_str());
				return;
			}
			STICE_LOG_DEBUG("ICE-TCP: redialing dead connection to %s", remoteAddr.toString().c_str());
			if (!startTcpConn(c, remoteAddr, remote.hostname)) {
				STICE_LOG_WARN("ICE-TCP: failed to redial %s", remoteAddr.toString().c_str());
				return;
			}
			if (pollReg_) pollReg_->add(this);
			return;
		}
		// RFC 6544 §12: cap the number of simultaneous connections to one IP.
		int sameIp = 0;
		for (const auto& c : tcpConns_) {
			if (net::addrEqual(reinterpret_cast<const sockaddr*>(&c.peerAddr.addr),
				reinterpret_cast<const sockaddr*>(&remoteAddr.addr), false))
				++sameIp;
		}
		if (sameIp >= 5) {
			STICE_LOG_WARN("ICE-TCP: refusing %s: already %d connections to this IP (RFC 6544 §12)",
				remoteAddr.toString().c_str(), sameIp);
			return;
		}
		STICE_LOG_INFO("ICE-TCP: beginning active TCP connect to %s", remoteAddr.toString().c_str());
		tcpConns_.emplace_back();
		TcpConnection& conn = tcpConns_.back();
		// Begin the non-blocking connect. The TcpTransport completes it
		// asynchronously via writable callbacks from the PollRegistry.
		if (!startTcpConn(conn, remoteAddr, remote.hostname)) {
			STICE_LOG_WARN("ICE-TCP: failed to begin TCP connect to %s (errno=%d)",
				remoteAddr.toString().c_str(), sticeSockerrno);
			tcpConns_.pop_back();
			return;
		}
		// P1-C6 bind logic + connect start live in startTcpConn() so the
		// reconnect path reuses exactly the same setup.
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
		auto localSock = conn.transport->handle();
		if (localSock != STICE_INVALID_SOCKET) {
			sockaddr_storage la{};
			socklen_t laLen = sizeof(la);
			if (getsockname(localSock, reinterpret_cast<sockaddr*>(&la), &laLen) == 0) {
				localAddr.addr = la;
				localAddr.len = laLen;
				localAddr.socktype = SOCK_STREAM;
				c.resolved = localAddr;
				auto* sa = reinterpret_cast<const sockaddr*>(&la);
				char host[NI_MAXHOST];
				char serv[NI_MAXSERV];
				if (getnameinfo(sa, net::addrLen(sa), host, sizeof(host), serv, sizeof(serv),
					NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
					c.hostname = host;
					c.service = serv;
				}
			}
		}
		// If getsockname failed we have no usable local address. Emitting a
		// synthetic 0.0.0.0:0 candidate would advertise an unroutable path to
		// the peer, so keep the connection but skip the candidate (RFC 6544
		// §4.1: a candidate MUST carry a reachable transport address).
		if (c.hostname.empty()) {
			STICE_LOG_WARN("ICE-TCP: active connect to %s has no local address, not emitting candidate",
				remoteAddr.toString().c_str());
		} else {
			c.priority = c.computePriority(0);
			c.foundation = Candidate::computeFoundation(c.type, c.hostname, c.transport);
			addLocalCandidate(c);
			emitCandidate(c);
		}
		// Register with the PollRegistry so we get onTcpEvents callbacks.
		// Register this Agent (with its TCP socket) on its own PollRegistry.
		// add() is idempotent (deduplicates by pointer), so this is safe if the
		// Agent was already registered from init().
		if (pollReg_) pollReg_->add(this);
		STICE_LOG_INFO("ICE-TCP: began active TCP connect to %s (local=%s:%s, fd=%d)",
			remoteAddr.toString().c_str(), c.hostname.c_str(), c.service.c_str(),
			static_cast<int>(conn.transport->handle()));
	}
	std::vector<net::AddrRecord> Agent::localAddrsUdp(int family) const {
		if (mux_) return mux_->localAddrs(family);
		return sock_.localAddrs(family);
	}
	bool Agent::boundAddrUdp(net::AddrRecord& out) const {
		if (mux_) return mux_->boundAddr(out);
		return sock_.boundAddr(out);
	}
	void Agent::registerWithMux() {
		if (!mux_ || muxRegistered_) return;
		muxRegistered_ = true;
		auto lifetime = lifetime_; // shared_ptr copy keeps guard alive
		mux_->registerAgent(
			local_.iceUfrag,
			[lifetime, this](const char* data, int len, const net::AddrRecord& src) {
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
			[lifetime, this](const char* data, int len, const net::AddrRecord& src) {
				LifetimeScope ls(lifetime);
				if (!ls) return;
				std::lock_guard<std::recursive_mutex> lock(mutex_);
				handleInboundTcpPacket(data, len, src, nullptr);
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
		STICE_LOG_DEBUG("GATHER-DONE local=%u: setting gatheringDone_ (pendingSrflx=%d relay=%d cand=%zu state=%d remote_set=%d)", diagLocalPort_,
			pendingServerReflexive_, pendingRelayAllocations_,
			local_.candidates.size(), static_cast<int>(state_),
			(remote_.iceUfrag.empty() || remote_.icePwd.empty()) ? 0 : 1);
		for (const auto& c : local_.candidates) if (c.type == CandidateType::Relayed)
			STICE_LOG_DEBUG("GATHER-RELAY local=%u relayed=%s priority=%u", diagLocalPort_,
				c.resolved.toString().c_str(), c.priority);
		gatheringDone_ = true;
		local_.finished = true;
		// Non-trickle mode: the complete candidate set is delivered now, so the
		// application sees every candidate before gathering_done.
		flushDeferredCandidates();
		emitGatheringDone();
		// If remote description was set before gathering finished and early pair
		// formation (setRemoteDescription/addRemoteCandidate) has not already
		// moved us to CONNECTING, do it now. The state guard prevents a spurious
		// CONNECTING transition (and a second formPairs call) when checks are
		// already running.
		if (!remote_.iceUfrag.empty() && !remote_.icePwd.empty() &&
			state_ == STICE_STATE_GATHERING) {
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
		// 64KB buffer: TURN-relayed datagrams (e.g. ChannelData carrying large
		// application payloads) exceed the 1500-byte MTU. A too-small buffer
		// makes recvfrom fail with EMSGSIZE on Windows (or truncate on Linux),
		// silently dropping every jumbo application packet.
		char buf[65536];
		net::AddrRecord src;
		while (true) {
			int n = sock_.recvfrom(buf, sizeof(buf), src);
			if (n <= 0) break;
			STICE_LOG_DEBUG("AGENT-RECV fd=%d n=%d from=%s",
			                 static_cast<int>(sock_.handle()), n, src.toString().c_str());
			handleInboundUdp(buf, n, src);
		}
	}
	void Agent::onTcpEvents(short events) {
		LifetimeScope ls(lifetime_);
		if (!ls) return;
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		// Legacy single-slot entry: drive the primary connection. Every other
		// connection arrives through onIceTcpEventsSock().
		TcpConnection* conn = primaryTcpConn();
		if (!conn) return;
		onTcpConnEvents(*conn, events);
	}
	void Agent::onTcpConnEvents(TcpConnection& conn, short events) {
		if (!conn.transport) return;
		// Application-layer connect timeout: if the non-blocking connect has not
		// completed by the deadline, transition to Failed so the pair is failed
		// and the next frozen pair is armed. Without this, a black-holed remote
		// (no SYN-ACK) leaves the transport stuck in Connecting forever.
		if (conn.transport->connectTimedOut()) {
			STICE_LOG_WARN("ICE-TCP: connect timeout (peer=%s), failing transport",
				conn.peerAddr.toString().c_str());
			conn.transport->close();
		}
		auto prevState = conn.transport->state();
		STICE_LOG_DEBUG("ICE-TCP: events=0x%x state=%d peer=%s",
			static_cast<unsigned>(events),
			static_cast<int>(prevState),
			conn.peerAddr.toString().c_str());
		// Handle POLLERR/POLLHUP: some platforms report these without POLLIN/POLLOUT.
		// Trigger both readable/writable to let the transport detect the error via
		// recv() == 0 or send() < 0 or SO_ERROR, then transition to Failed/Disconnected.
		if (events & (POLLERR | POLLHUP)) {
			STICE_LOG_DEBUG("ICE-TCP: POLLERR/POLLHUP (0x%x), draining transport",
				static_cast<unsigned>(events & (POLLERR | POLLHUP)));
			if (!(events & POLLIN)) conn.transport->onReadable();
			if (!(events & POLLOUT)) conn.transport->onWritable();
		}
		if (events & POLLOUT) conn.transport->onWritable();
		if (events & POLLIN) {
			conn.transport->onReadable();
			// Drain all complete RFC 4571-framed messages from the transport.
			handleInboundTcp(conn);
			// closeUnselectedTcpConns() may have dropped this losing connection
			// from inside the dispatch above.
			if (!conn.transport) return;
		}
		// Resolve the pair this connection backs (lazily, once the pair exists).
		if (!conn.pair) {
			for (auto& p : pairs_) {
				if (pairIsTcp(p.get()) && p->remote &&
					conn.peerAddr.isEqual(p->remote->resolved, true)) {
					conn.pair = p.get();
					break;
				}
			}
		}
		if (conn.transport->state() == net::TcpState::Connected) {
			const bool justConnected = prevState != net::TcpState::Connected;
			if (justConnected) {
				STICE_LOG_INFO("ICE-TCP: transport Connected (peer=%s), arming CHECK entries",
					conn.peerAddr.toString().c_str());
				// A successful (re)dial clears the RFC 6544 §11.1 retry budget.
				conn.everConnected = true;
				conn.reconnectAttempts = 0;
				conn.reconnectPending = false;
				conn.redialStart = {};
			}
			// (Re)arm pending CHECK entries for this connection's pair so the
			// check fires as soon as the socket is up. On a reconnect the entry
			// was marked Failed, so revive it as Pending too.
			for (auto& e : entries_) {
				if (e.type != StunEntryType::Check || !e.pair || !pairIsTcp(e.pair)) continue;
				if (!conn.pair || e.pair != conn.pair) continue;
				if (e.state == StunEntryState::Failed) e.state = StunEntryState::Pending;
				if (e.state != StunEntryState::Pending) continue;
				if (e.retransmissions == 0) {
					e.nextTransmission = std::chrono::steady_clock::now();
					e.retransmissionTimeout = std::chrono::milliseconds(StunTcpTimeoutMs);
					STICE_LOG_DEBUG("ICE-TCP: armed CHECK entry for pair (local=%s remote=%s)",
						e.pair->local ? e.pair->local->hostname.c_str() : "?",
						e.pair->remote ? e.pair->remote->hostname.c_str() : "?");
					wakePoll();
				}
			}
			// A reconnected pair goes back to Pending so the check above can
			// re-establish it (RFC 6544 §11.1 recovery). Belt and braces with the
			// resetNomination at the failure site: a revived pair must come back
			// un-nominated, so the controlling side re-nominates and the
			// controlled side waits for a fresh UseCandidate (P1-N3).
			if (justConnected && conn.everConnected && conn.pair &&
				conn.pair->state == PairState::Failed) {
				conn.pair->state = PairState::Pending;
				resetNomination(*conn.pair);
			}
		}
		else if (conn.transport->state() == net::TcpState::Failed ||
			conn.transport->state() == net::TcpState::Disconnected) {
			STICE_LOG_WARN("ICE-TCP: transport %s (peer=%s, prevState=%d), failing its pair",
				conn.transport->state() == net::TcpState::Failed ? "Failed" : "Disconnected",
				conn.peerAddr.toString().c_str(),
				static_cast<int>(prevState));
			// Decide recovery BEFORE mutating pair state: a connection that ever
			// carried the selected/succeeded pair must be redialed (RFC 6544 §11.1).
			const bool backsSelected = conn.everConnected && conn.pair &&
				(conn.pair == selectedPair_ || conn.pair->state == PairState::Succeeded);
			const bool matchesSelectedAddr = conn.everConnected && selectedPair_ &&
				pairIsTcp(selectedPair_) && selectedPair_->remote &&
				conn.peerAddr.isEqual(selectedPair_->remote->resolved, true);
			const bool mustReconnect = backsSelected || matchesSelectedAddr;
			// Fail only the pair backed by this connection (other connections are
			// independent now), and cancel its pending STUN entries so the
			// bookkeeping loop does not keep retrying on a dead transport.
			for (auto& p : pairs_) {
				if (!pairIsTcp(p.get())) continue;
				const bool mine = conn.pair ? p.get() == conn.pair
					: (p->remote && conn.peerAddr.isEqual(p->remote->resolved, true));
				if (mine && p->state != PairState::Failed) {
					p->state = PairState::Failed;
					resetNomination(*p);
				}
			}
			for (auto& e : entries_) {
				if (e.type != StunEntryType::Check || !e.pair || !pairIsTcp(e.pair)) continue;
				const bool mine = conn.pair ? e.pair == conn.pair
					: (e.pair->remote && conn.peerAddr.isEqual(e.pair->remote->resolved, true));
				if (mine && e.state == StunEntryState::Pending) e.state = StunEntryState::Failed;
			}
			if (mustReconnect) {
				// Keep the session state: the redial below revives the pair, so
				// declaring failure now would tear down a recoverable link.
				scheduleTcpReconnect(conn);
			}
			else {
				// Close the fd; keep the (empty) entry so a later re-dial reuses
				// its identity and local candidate.
				conn.transport.reset();
				updateState();
			}
		}
	}
	// RFC 6544 §8: after ICE completes, close every direct TCP connection that
	// does not carry the selected/nominated pair. Losing dials stay open
	// otherwise, wasting descriptors and answering checks on a connection that
	// will never carry media.
	void Agent::closeUnselectedTcpConns() {
		const CandidatePair* keep = nominatedPair_ ? nominatedPair_ : selectedPair_;
		if (!keep) return;
		for (auto& c : tcpConns_) {
			if (!c.transport) continue;
			bool carried = c.pair == keep;
			// `pair` is resolved lazily after the first inbound frame, and
			// updateState() can run from that same frame, so the selected pair may
			// not be bound yet. Match by endpoint in that case.
			if (!carried && !c.pair && pairIsTcp(keep) && keep->remote &&
				c.peerAddr.isEqual(keep->remote->resolved, true))
				carried = true;
			if (carried) continue;
			STICE_LOG_DEBUG("ICE-TCP: closing unselected connection to %s (RFC 6544 §8)",
				c.peerAddr.toString().c_str());
			c.transport->close();
			c.transport.reset();
			c.reconnectPending = false;
			// Fail the pair it backed: the connection is gone, so it must not be
			// reselected later on a transport that no longer exists.
			for (auto& p : pairs_) {
				if (!pairIsTcp(p.get()) || p.get() == keep) continue;
				const bool mine = c.pair ? p.get() == c.pair
					: (p->remote && c.peerAddr.isEqual(p->remote->resolved, true));
				if (mine && p->state != PairState::Failed) {
					p->state = PairState::Failed;
					resetNomination(*p);
				}
			}
		}
	}
	void Agent::scheduleTcpReconnect(TcpConnection& conn) {
		if (conn.reconnectPending) return;
		const auto now = std::chrono::steady_clock::now();
		// Fail every pair this connection backs and drop its nomination state,
		// matching closeUnselectedTcpConns(): a connection that is gone must not
		// leave a pair that later nomination/selection can pick up.
		auto failPairsForConn = [this, &conn]() {
			for (auto& p : pairs_) {
				if (!pairIsTcp(p.get())) continue;
				const bool mine = conn.pair ? p.get() == conn.pair
					: (p->remote && conn.peerAddr.isEqual(p->remote->resolved, true));
				if (mine && p->state != PairState::Failed) {
					p->state = PairState::Failed;
					resetNomination(*p);
				}
			}
		};
		// Total wall-clock budget for the redial campaign: reconnectAttempts
		// resets on every transient success, so a flapping link could redial
		// forever. 60 s from the first loss ends the campaign.
		if (conn.redialStart.time_since_epoch().count() == 0)
			conn.redialStart = now;
		if (now - conn.redialStart >= std::chrono::milliseconds(TcpRedialWallBudgetMs)) {
			STICE_LOG_WARN("ICE-TCP: giving up redial to %s (wall-clock budget exhausted)",
				conn.peerAddr.toString().c_str());
			// The campaign is over, so the pairs this connection backed can never be
			// revived. Leaving them in their previous state let a later nomination or
			// selection resurrect a link with no transport behind it.
			failPairsForConn();
			conn.transport.reset();
			updateState();
			return;
		}
		if (conn.reconnectAttempts >= 5) {
			STICE_LOG_WARN("ICE-TCP: giving up redial to %s after %d attempts",
				conn.peerAddr.toString().c_str(), conn.reconnectAttempts);
			failPairsForConn();
			conn.transport.reset();
			updateState();
			return;
		}
		// Exponential backoff capped at 8 s: 1 s, 2 s, 4 s, 8 s, 8 s,
		// jittered +/-20% so simultaneous losses don't re-sync their dials.
		const int shift = conn.reconnectAttempts < 3 ? conn.reconnectAttempts : 3;
		auto delay = std::chrono::milliseconds(1000 << shift);
		const int span = std::max(1, static_cast<int>(delay.count() / 5));
		const int jitter = static_cast<int>(crypto::randomU32() % (2 * span + 1)) - span;
		delay += std::chrono::milliseconds(jitter);
		conn.reconnectPending = true;
		conn.nextReconnect = now + delay;
		conn.transport.reset();
		STICE_LOG_WARN("ICE-TCP: selected connection to %s lost; redialing in %lldms (RFC 6544 §11.1)",
			conn.peerAddr.toString().c_str(), static_cast<long long>(delay.count()));
		wakePoll();
	}
	void Agent::onTurnTcpEventsSock(socket_t sock, short events) {
		LifetimeScope ls(lifetime_);
		if (!ls) return;
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		// A1: dispatch by socket fd to the relay entry that owns this transport, so
		// multiple TCP/TLS TURN servers can run concurrently.
		for (auto& e : entries_) {
			if (e.type != StunEntryType::Relay || !e.tcpTurn || !e.turnTcp ||
				e.turnTcp->handle() != sock)
				continue;
			auto& tt = e.turnTcp;
			// Application-layer connect timeout for TURN-over-TCP/TLS.
			if (tt->connectTimedOut()) {
				STICE_LOG_WARN("TURN TCP: connect timeout, failing transport");
				tt->close();
			}
			STICE_LOG_DEBUG("TURN TCP: events=0x%x state=%d",
				static_cast<unsigned>(events),
				static_cast<int>(tt->state()));
			// Detect "reached Connected" across BOTH drives. With plain TCP the
			// connect completes on the writable event, but with TLS the handshake
			// finishes on a READABLE event (server Finished/handshake flight), so
			// a Connected check on the POLLOUT branch alone left TLS relays stuck
			// in TlsHandshaking: the ALLOCATE was never sent and gathering timed
			// out.
			const net::TcpState before = tt->state();
			if (events & POLLOUT) tt->onWritable();
			if (events & POLLIN) {
				tt->onReadable();
				handleInboundTurnTcp(e);
			}
			if (before != net::TcpState::Connected && tt->state() == net::TcpState::Connected) {
				STICE_LOG_INFO("TURN TCP: transport reached Connected (events=0x%x)",
					static_cast<unsigned>(events));
				onTurnTcpConnected(e);
			}
			if (tt && (tt->state() == net::TcpState::Failed ||
				tt->state() == net::TcpState::Disconnected)) {
				STICE_LOG_WARN("TURN TCP: connection lost (state=%d, events=0x%x)",
					static_cast<int>(tt->state()),
					static_cast<unsigned>(events));
				// Mark the TURN entry as failed so allocation doesn't hang.
				if (e.turn) e.turn->handleInbound(nullptr, 0); // signal failure
				// Do not destroy the per-entry transport here (the poll thread may
				// still hold it this dispatch); onBookkeeping / entry cleanup handles
				// teardown, and close() stops the fd from firing.
				tt->close();
				e.turnTcp.reset();
			}
			return;
		}
	}
	void Agent::handleInboundTurnTcp(StunEntry& entry) {
		if (!entry.turnTcp) return;
		// Drain raw bytes from the per-entry transport and feed them to the entry's
		// StunConn for self-delimited parsing (no RFC 4571 prefix for TURN over TCP).
		char buf[4096];
		net::AddrRecord peer; // unused for TCP
		int totalRaw = 0;
		while (true) {
			int n = entry.turnTcp->recv(buf, sizeof(buf), peer);
			if (n <= 0) break;
			totalRaw += n;
			entry.turnTcpConn.feed(reinterpret_cast<const unsigned char*>(buf),
				static_cast<std::size_t>(n));
		}
		if (totalRaw > 0) {
			STICE_LOG_DEBUG("TURN TCP: received %d raw bytes, draining frames", totalRaw);
		}
		// Pull complete frames and route to the TURN client.
		const unsigned char* frame = nullptr;
		int frameCount = 0;
		while (true) {
			std::size_t frameSize = entry.turnTcpConn.readFrame(frame);
			if (frameSize == 0 || !frame) break;
			if (frameSize == static_cast<std::size_t>(-1)) {
				// StunConn detected invalid (non-STUN, non-ChannelData) data on the
				// TCP stream. Treat as a fatal stream error: signal failure and tear
				// down the transport so gathering doesn't hang on a corrupted stream.
				STICE_LOG_WARN("TURN TCP: invalid stream data, closing connection");
				if (entry.turn) entry.turn->handleInbound(nullptr, 0); // signal failure
				entry.turnTcp->close();
					entry.turnTcp.reset();
				return;
			}
			++frameCount;
			STICE_LOG_DEBUG("TURN TCP: frame #%d (%zu bytes) -> TURN client", frameCount, frameSize);
			if (entry.turn) entry.turn->handleInbound(frame, frameSize);
		}
	}
	bool Agent::beginTurnTcpConnect(StunEntry& entry, const net::AddrRecord& turnServer,
		bool useTls, const std::string& sni, bool skipVerify, const std::string& caFile) {
		STICE_LOG_INFO("TURN TCP: beginning %s connect to %s (sni=%s skipVerify=%d caFile=%s)",
			useTls ? "TLS" : "TCP", turnServer.toString().c_str(),
			sni.c_str(), static_cast<int>(skipVerify),
			caFile.empty() ? "<env/platform>" : caFile.c_str());
		if (!entry.turnTcp) entry.turnTcp = std::make_shared<net::TcpTransport>();
		auto& tt = entry.turnTcp;
		tt->setFramingMode(net::FramingMode::Raw);
		if (!tt->beginConnect(turnServer, sni, useTls, skipVerify, caFile)) {
			STICE_LOG_WARN("TURN TCP: failed to begin connect to %s (errno=%d)",
				turnServer.toString().c_str(), sticeSockerrno);
			// Signal the failure to the TURN Client so it transitions to Failed,
			// invokes onFailed, decrements pendingRelayAllocations_ (guarded by
			// relayCounted), and allows gathering to complete.
			if (entry.turn) entry.turn->handleInbound(nullptr, 0); // signal failure
			return false;
		}
		// Arm an application-layer connect timeout so an unreachable TURN server
		// does not leave the transport stuck in Connecting forever. Half the
		// ICE-TCP timeout: TURN servers are known infrastructure (LAN/deployed
		// endpoint), and the "connection failure must not hang gathering" tests
		// expect completion within 5 s even for a black-holed connect.
		tt->setConnectTimeoutMs(TcpConnectTimeoutMs / 2);
		// Register this Agent (with its TURN TCP sockets) on its own PollRegistry.
		// add() is idempotent (deduplicates by pointer).
		if (pollReg_) pollReg_->add(this);
		// If connect succeeded immediately (rare), trigger the connected callback.
		if (tt->state() == net::TcpState::Connected) {
			STICE_LOG_INFO("TURN TCP: connect succeeded immediately (synchronous)");
			onTurnTcpConnected(entry);
		}
		else {
			STICE_LOG_INFO("TURN TCP: connect pending (async), state=%d",
				static_cast<int>(tt->state()));
		}
		return true;
	}
	void Agent::onTurnTcpConnected(StunEntry& entry) {
		STICE_LOG_INFO("TURN TCP: transport connected, sending ALLOCATE request");
		// The TURN client's allocate() was already called from gatherRelay. Its first
		// request was buffered in sendRaw (which dropped while the transport wasn't
		// connected). Re-trigger the allocation now that the TCP transport is ready.
		if (entry.turn) {
			// Record allocation start time for RTT-based priority correction.
			auto now = std::chrono::steady_clock::now();
			if (entry.allocStart) *entry.allocStart = now;
			// Re-send the allocate request now that the TCP transport is ready.
			entry.turn->allocate();
			entry.nextTransmission = entry.turn->nextTick();
			wakePoll();
		}
	}
	// --- RFC 6062 TCP allocation data connection ---
	StunEntry* Agent::findTcpTurnEntry() {
		for (auto& e : entries_)
			if (e.type == StunEntryType::Relay && e.tcpTurn && e.turnTcp && e.turn)
				return &e;
		return nullptr;
	}
	const StunEntry* Agent::findTcpTurnEntry() const {
		for (const auto& e : entries_)
			if (e.type == StunEntryType::Relay && e.tcpTurn && e.turnTcp && e.turn)
				return &e;
		return nullptr;
	}
	int Agent::turnTcpSlotCount() const {
	// poll-thread getter: snapshot entries_ under agent lock
	std::lock_guard<std::recursive_mutex> lock(mutex_);
		int n = 0;
		for (const auto& e : entries_)
			if (e.type == StunEntryType::Relay && e.tcpTurn && e.turnTcp)
				++n;
		return n;
	}
	socket_t Agent::turnTcpSocketAt(int i) const {
	// poll-thread getter: snapshot entries_ under agent lock
	std::lock_guard<std::recursive_mutex> lock(mutex_);
		int k = 0;
		for (const auto& e : entries_) {
			if (e.type != StunEntryType::Relay || !e.tcpTurn || !e.turnTcp) continue;
			if (k == i) return e.turnTcp->handle();
			++k;
		}
		return STICE_INVALID_SOCKET;
	}
	short Agent::turnTcpDesiredEventsAt(int i) const {
	// poll-thread getter: snapshot entries_ under agent lock
	std::lock_guard<std::recursive_mutex> lock(mutex_);
		int k = 0;
		for (const auto& e : entries_) {
			if (e.type != StunEntryType::Relay || !e.tcpTurn || !e.turnTcp) continue;
			if (k == i) {
				short ev = POLLIN;
				// wantsWrite() also covers TlsHandshaking WANT_WRITE (E1).
				if (e.turnTcp->wantsWrite()) ev |= POLLOUT;
				return ev;
			}
			++k;
		}
		return 0;
	}
	bool Agent::hasTurnDataTcp() const {
		return turnDataConn_ && turnDataConn_->transport != nullptr;
	}
	socket_t Agent::turnDataTcpSocket() const {
		if (!turnDataConn_ || !turnDataConn_->transport) return STICE_INVALID_SOCKET;
		return turnDataConn_->transport->handle();
	}
	short Agent::turnDataDesiredEvents() const {
		if (!turnDataConn_ || !turnDataConn_->transport) return 0;
		short ev = POLLIN;
		// RFC 6062 data connection: keep POLLOUT armed whenever the write queues
		// are non-empty (wantsWrite also covers Connecting and TLS WANT_WRITE).
		// Previously this only returned POLLIN once Connected, so if the data
		// socket hit EAGAIN under TCP flow control (sendQueue_ backlog), poll
		// never re-armed POLLOUT and flushSends never ran again -> in-flight data
		// at the tail of a flood was silently stuck (receiver missed the last
		// ~20x1200-byte blocks until timeout).
		if (turnDataConn_->transport->wantsWrite()) ev |= POLLOUT;
		return ev;
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
	void Agent::beginTurnDataConnect(std::uint32_t connectionId, const net::AddrRecord& peer) {
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
		StunEntry* ctrl = findTcpTurnEntry();
		if (!ctrl || !ctrl->turn) {
			STICE_LOG_WARN("TURN data: no control connection entry");
			turnDataConn_.reset();
			return;
		}
		// Reuse the TURN server address from the control connection's config.
		// We stored the server address in the StunEntry's record field.
		net::AddrRecord turnServer = ctrl->record;
		// B2: the RFC 6062 data connection inherits the control connection's TLS
		// parameters (including its per-server CA bundle) so a turns: relay does
		// not silently downgrade to plain TCP or to a different trust anchor.
		if (!turnDataConn_->transport->beginConnect(
			turnServer, ctrl->turnTcpUseTls ? ctrl->turnTcpSni : std::string(),
			ctrl->turnTcpUseTls, ctrl->turnTcpSkipVerify,
			ctrl->turnTcpUseTls ? ctrl->turnTcpCaFile : std::string())) {
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
		if (!turnDataConn_) return;
		StunEntry* ctrl = findTcpTurnEntry();
		if (!ctrl || !ctrl->turn) return;
		auto raw = ctrl->turn->buildConnectionBindRequest(turnDataConn_->connectionId);
		// CONNECTION-BIND is signalling: control queue, never behind app data.
		turnDataConn_->transport->sendControl(reinterpret_cast<const char*>(raw.data()), raw.size());
		turnDataConn_->connectionBindSent = true;
		STICE_LOG_INFO("TURN data: sent CONNECTION-BIND connId=%u", turnDataConn_->connectionId);
	}
	int Agent::sendTurnDataConn(const char* data, std::size_t size) {
		if (!turnDataConn_ || !turnDataConn_->transport || !turnDataConn_->bound)
			return STICE_ERR_FAILED;
		// RFC 4571: 2-byte big-endian length prefix + payload.
		std::vector<char> framed(size + 2);
		framed[0] = static_cast<char>((size >> 8) & 0xFF);
		framed[1] = static_cast<char>(size & 0xFF);
		std::memcpy(framed.data() + 2, data, size);
		// Everything on the data connection goes through the SAME framed FIFO.
		// This stream is de-framed by the peer with RFC 4571 length prefixes, so
		// there is no such thing as a safe "priority" insertion: writing a STUN
		// frame (ICE consent check) between the bytes of a partially-sent
		// application frame makes the peer read a length out of the middle of the
		// payload and mis-frame the rest of the stream -- measured under load as
		// rx_total > sent_total with a bogus payload length of 0x7878 (the bench's
		// 'x' fill byte; 0x7878 is why the bogus "frame" was 30840 bytes). The STUN
		// frames here are periodic consent checks -- unlike Refresh or
		// CONNECTION-BIND, which travel on the control connection -- so FIFO
		// ordering costs them at most the queued backlog, far below consent
		// expiry, whereas a separate priority queue corrupts the framing.
		bool ok = turnDataConn_->transport->send(framed.data(), framed.size());
		return ok ? STICE_ERR_SUCCESS : STICE_ERR_FAILED;
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
			// RFC 6062 permission race: coturn may close the data connection before
			// CONNECTION-BIND completes if the peer's CREATE_PERMISSION hasn't been
			// processed yet ("tcp_peer_accept_connection: peer has no permission to
			// connect"). Retry the data connect a few times with a short delay; the
			// permission propagates within a few hundred ms and the bind succeeds.
			if (!turnDataConn_->bound && turnDataRetryCount_ < MaxTurnDataConnectRetries) {
				net::AddrRecord peer = turnDataConn_->peer;
				std::uint32_t connId = turnDataConn_->connectionId;
				turnDataRetryCount_++;
				turnDataRetryConnId_ = connId;
				turnDataRetryPeer_ = peer;
				pendingTurnDataRetry_ = true;
				nextTurnDataRetry_ = std::chrono::steady_clock::now() +
					std::chrono::milliseconds(TurnDataRetryDelayMs * turnDataRetryCount_);
				STICE_LOG_WARN("TURN data: connection lost (state=%d), retrying data connect (attempt %d/%d)",
					static_cast<int>(turnDataConn_->transport->state()),
					turnDataRetryCount_, MaxTurnDataConnectRetries);
				turnDataConn_.reset();
				wakePoll();
				return;
			}
			// RFC 6062 §3.2: a data connection that drops after CONNECTION-BIND
			// must not silently abandon the relayed pair (P1-TD1). The server
			// keeps the connection binding, so rebuild the data connection with
			// the SAME connection-id; if the server has already dropped the
			// binding the bind fails and the pre-bind CONNECT retry path above
			// establishes a fresh one. Bounded retries: once exhausted the pair
			// dies through consent expiry like any other broken link.
			if (turnDataConn_->bound && turnDataRebindAttempts_ < MaxTurnDataRebindRetries) {
				turnDataRebindConnId_ = turnDataConn_->connectionId;
				turnDataRebindPeer_ = turnDataConn_->peer;
				++turnDataRebindAttempts_;
				pendingTurnDataRebind_ = true;
				nextTurnDataRebind_ = std::chrono::steady_clock::now() +
					std::chrono::milliseconds(TurnDataRebindDelayMs * turnDataRebindAttempts_);
				STICE_LOG_WARN("TURN data: bound connection lost (state=%d), scheduling rebind of connId=%u (attempt %d/%d)",
					static_cast<int>(turnDataConn_->transport->state()),
					turnDataRebindConnId_, turnDataRebindAttempts_, MaxTurnDataRebindRetries);
				turnDataConn_.reset();
				wakePoll();
				return;
			}
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
					reinterpret_cast<const unsigned char*>(buf), n);
			}
			else {
				// After binding: the connection is a transparent tunnel.
				// All data uses RFC 4571 framing (2-byte length prefix).
				turnDataConn_->rfc4571Buf.insert(
					turnDataConn_->rfc4571Buf.end(),
					reinterpret_cast<unsigned char*>(buf),
					reinterpret_cast<unsigned char*>(buf) + n);
			}
		}
		// Phase 1: parse StunConn frames (CONNECTION-BIND response).
		if (!turnDataConn_->bound) {
			while (true) {
				const unsigned char* frame = nullptr;
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
					// P2-N4: the CONNECTION-BIND success response is the credential
					// handshake for this side channel (RFC 6062 §6.3). Without MI/FP
					// verification an off-path peer could flip the connection into
					// "bound" and inject data, so a verification failure closes it.
					StunEntry* ctrlEntry = findTcpTurnEntry();
					if (ctrlEntry && ctrlEntry->turn &&
						!ctrlEntry->turn->verifySideChannelResponse(m)) {
						STICE_LOG_WARN("TURN data: CONNECTION-BIND response failed MI/FP "
						               "verification, closing data connection");
						turnDataConn_->transport->close();
						return;
					}
					turnDataConn_->bound = true;
					turnDataConn_->connecting = false;
					turnDataRetryCount_ = 0; // bind succeeded, reset retry budget
					pendingTurnDataRetry_ = false;
					// A STUN frame is self-delimited, so the bind response does not
					// consume the whole TCP segment: app-data RFC 4571 frames can
					// follow it in the SAME read. Hand the leftover bytes to the
					// RFC 4571 buffer, otherwise the data stream starts mid-frame
					// and every subsequent length prefix is read from the wrong
					// offset (frames merge into oversized payloads -> rx > sent).
					{
						bytes rest = turnDataConn_->stunConn.takeBuffered();
						if (!rest.empty())
							turnDataConn_->rfc4571Buf.insert(
								turnDataConn_->rfc4571Buf.end(), rest.begin(), rest.end());
					}
					STICE_LOG_INFO(
						"TURN data: CONNECTION-BIND success, data conn established peer=%s",
						turnDataConn_->peer.toString().c_str());
					// Immediately trigger the STUN connectivity check for the
					// TURN-TCP-relay pair. The check was suspended while the
					// data connection was being established; now that it's
					// bound, send the first STUN binding request right away
					// instead of waiting for the next bookkeeping tick.
					for (auto& e : entries_) {
						if (e.state == StunEntryState::Pending &&
							e.type == StunEntryType::Check &&
							pairIsTurnTcpRelay(e.pair)) {
							e.nextTransmission = std::chrono::steady_clock::now();
							e.retransmissions = 0;
							break;
						}
					}
					wakePoll();
					// Everything after the bind response on this connection is
					// RFC 4571 data: stop parsing the buffer as self-delimited STUN
					// frames so phase 2 consumes it in order from the top.
					break;
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
			auto& bufRef = turnDataConn_->rfc4571Buf;
			std::size_t consumed = 0;
			while (bufRef.size() - consumed >= 2) {
				std::uint16_t len = (static_cast<std::uint16_t>(bufRef[consumed]) << 8) |
					bufRef[consumed + 1];
				if (bufRef.size() - consumed - 2 < len) break; // incomplete
				const char* payload =
					reinterpret_cast<const char*>(bufRef.data() + consumed + 2);
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
		// Flush queued UDP control frames (ICE/TURN signalling refused by a
		// backed-up socket) ahead of any further bulk data.
		flushUdpControlQueue();
		// Soft gathering timeout: if srflx/relay entries stay pending (STUN
		// server unreachable, or high-load packet loss) gathering must still
		// complete so the ICE session proceeds; late candidates are trickled.
		if (!gatheringDone_ && state_ == STICE_STATE_GATHERING &&
		    gatherStartedAt_.time_since_epoch().count() == 0) {
			// Defensive only: gatherCandidates() sets gatherStartedAt_ while
			// holding the same mutex that sets state_ = GATHERING, so this is
			// unreachable in practice. Gating on state_ matters because a
			// bookkeeping tick can fire BEFORE gatherCandidates() is called (state_
			// still DISCONNECTED): without the gate it seeded a deadline early and
			// logged a misleading "gatherCandidates likely never ran" error on
			// every such tick.
			gatherStartedAt_ = std::chrono::steady_clock::now();
			STICE_LOG_WARN("GATHER: state=GATHERING but no gather deadline recorded; seeding one (agent=%p)", (void*)this);
		}
		if (!gatheringDone_ && gatherStartedAt_.time_since_epoch().count() != 0 &&
			(now - gatherStartedAt_) > std::chrono::milliseconds(GatherTimeoutMs)) {
			STICE_LOG_WARN("GATHER-SOFT-TIMEOUT forcing complete after %d ms (pendingSrflx=%d relay=%d)",
				static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
					now - gatherStartedAt_).count()),
				pendingServerReflexive_, pendingRelayAllocations_);
			pendingRelayAllocations_ = 0;
			pendingServerReflexive_ = 0;
			checkGatheringComplete();
		}
		STICE_LOG_DEBUG("onBookkeeping: entries=%zu state=%d", entries_.size(), static_cast<int>(state_));
		if (!gatheringDone_) {
			auto ageMs = static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(now - gatherStartedAt_).count());
			STICE_LOG_DEBUG("GATHER-CHECK local=%u: gStartSet=%d pendingSrflx=%d relay=%d age=%lldms entries=%zu done=%d cand=%zu state=%d", diagLocalPort_,
				gatherStartedAt_.time_since_epoch().count() != 0, pendingServerReflexive_,
				pendingRelayAllocations_, ageMs, entries_.size(),
				gatheringDone_ ? 1 : 0, local_.candidates.size(), static_cast<int>(state_));
		}
		// Enforce application-layer TCP connect timeouts and drive the RFC 6544
		// §11.1 redial. The poll loop may not deliver onTcpEvents for a black-
		// holed connect (no writable event ever fires), so this pass is the
		// safety net for both.
		{
			const auto tcpNow = std::chrono::steady_clock::now();
			for (auto& c : tcpConns_) {
				if (c.transport && c.transport->connectTimedOut()) {
					STICE_LOG_WARN("ICE-TCP: connect timeout in bookkeeping (peer=%s)",
						c.peerAddr.toString().c_str());
					c.transport->close();
				}
				if (!c.reconnectPending || tcpNow < c.nextReconnect) continue;
				c.reconnectPending = false;
				++c.reconnectAttempts;
				STICE_LOG_WARN("ICE-TCP: redialing %s (attempt %d, RFC 6544 §11.1)",
					c.peerAddr.toString().c_str(), c.reconnectAttempts);
				if (startTcpConn(c, c.peerAddr, c.sni)) {
					if (pollReg_) pollReg_->add(this);
				}
				else {
					scheduleTcpReconnect(c);
				}
			}
		}
		for (auto& e : entries_) {
			if (e.type == StunEntryType::Relay && e.tcpTurn && e.turnTcp &&
				e.turnTcp->connectTimedOut()) {
				STICE_LOG_WARN("TURN TCP: connect timeout in bookkeeping");
				e.turnTcp->close();
				// Signal failure to the TURN client so the pending allocation entry
				// completes and gathering can finish. Without this, a black-holed
				// connect (unroutable server) times out here but the entry stays
				// pending forever.
				if (e.turn) e.turn->handleInbound(nullptr, 0); // signal failure
			}
		}
		// RFC 6062 CONNECT retry: if a previous CONNECT failed with 447 and the
		// retry delay has elapsed, re-send the CONNECT to the peer's relayed addr.
		if (pendingConnectRetry_ && now >= nextConnectRetry_) {
			pendingConnectRetry_ = false;
			STICE_LOG_INFO("RFC 6062: retrying CONNECT to peer=%s (attempt %d/%d)",
				pendingConnectPeer_.toString().c_str(),
				connectRetries_, MaxConnectRetries);
			StunEntry* te = findTcpTurnEntry();
			if (te && te->turn &&
				te->turn->state() == turn::AllocState::Allocated) {
				te->turn->sendConnect(pendingConnectPeer_);
			}
		}
		// RFC 6062 data-connection retry: if a previous CONNECTION-BIND attempt
		// failed (coturn permission race) and the retry delay has elapsed, re-issue
		// the CONNECT to get a fresh connectionId + pending. Reusing the old
		// connectionId after coturn closed the data connection always fails because
		// the pending is gone; a fresh CONNECT creates a new pending that the
		// retried data connection can bind to.
		if (pendingTurnDataRetry_ && now >= nextTurnDataRetry_) {
			pendingTurnDataRetry_ = false;
			StunEntry* te = findTcpTurnEntry();
			if (!turnDataConn_ && te && te->turn &&
				te->turn->state() == turn::AllocState::Allocated) {
				STICE_LOG_INFO("RFC 6062: data connect failed, re-sending CONNECT to peer=%s (attempt %d/%d)",
					turnDataRetryPeer_.toString().c_str(),
					turnDataRetryCount_, MaxTurnDataConnectRetries);
				te->turn->sendConnect(turnDataRetryPeer_);
				tcpConnectSent_ = true;
			}
		}
		// RFC 6062: rebuild a data connection that dropped after CONNECTION-BIND
		// (P1-TD1). beginTurnDataConnect re-issues CONNECTION-BIND with the same
		// connection-id; a server that already dropped the binding rejects it
		// and the pre-bind CONNECT retry above takes over with a fresh id.
		if (pendingTurnDataRebind_ && now >= nextTurnDataRebind_) {
			pendingTurnDataRebind_ = false;
			StunEntry* te = findTcpTurnEntry();
			if (!turnDataConn_ && te && te->turn &&
				te->turn->state() == turn::AllocState::Allocated) {
				STICE_LOG_INFO("RFC 6062: rebinding data connection connId=%u peer=%s (attempt %d/%d)",
					turnDataRebindConnId_, turnDataRebindPeer_.toString().c_str(),
					turnDataRebindAttempts_, MaxTurnDataRebindRetries);
				beginTurnDataConnect(turnDataRebindConnId_, turnDataRebindPeer_);
			}
		}
		// RFC 6062: if the TCP allocation was still pending when formPairs()
		// ran, the initial CONNECT was never sent. Retrigger it here once the
		// allocation transitions to Allocated. This fixes the race where
		// formPairs() is called before the TURN-TCP ALLOCATE response arrives.
		StunEntry* te = findTcpTurnEntry();
		// pion-mode: if CONNECT is waiting on CreatePermission, send once ready.
		if (pendingConnectWaitPerm_ && !tcpConnectSent_ && te && te->turn &&
			te->turn->state() == turn::AllocState::Allocated &&
			te->turn->hasPermission(pendingConnectPeer_)) {
			STICE_LOG_INFO("RFC 6062: permission ready, sending deferred CONNECT to peer=%s",
				pendingConnectPeer_.toString().c_str());
			te->turn->sendConnect(pendingConnectPeer_);
			tcpConnectSent_ = true;
			pendingConnectWaitPerm_ = false;
			pendingConnectRetry_ = false;
		}
		if (!tcpConnectSent_ && shouldInitiateTcpConnect() &&
			te && te->turn &&
			te->turn->state() == turn::AllocState::Allocated &&
			te->turn->isTcpAllocation()) {
			// Find the remote TCP relay candidate to CONNECT to.
			for (const auto& p : orderedPairs_) {
				if (p->remote && p->remote->type == CandidateType::Relayed &&
					p->remote->transport == CandidateTransport::TCPPassive) {
					if (te->turn->hasPermission(p->remote->resolved)) {
						STICE_LOG_INFO("RFC 6062: deferred CONNECT to peer relayed=%s",
							p->remote->resolved.toString().c_str());
						te->turn->ensurePermission(p->remote->resolved);
						te->turn->sendConnect(p->remote->resolved);
						tcpConnectSent_ = true;
						pendingConnectPeer_ = p->remote->resolved;
					}
					else {
						STICE_LOG_INFO("RFC 6062: deferred CONNECT waiting permission peer=%s",
							p->remote->resolved.toString().c_str());
						pendingConnectPeer_ = p->remote->resolved;
						pendingConnectWaitPerm_ = true;
					}
					break;
				}
			}
		}
		// Drive each STUN entry.
		for (auto& e : entries_) {
			if (e.state == StunEntryState::Pending) {
				STICE_LOG_DEBUG("  entry[%p]: state=%d nextTx=%lld now=%lld diff=%lld type=%d",
					static_cast<void*>(&e),
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
				}
				else if (isTcp) {
					maxRetrans = 1;
				}
				else if (pairingCfg_.max_check_retransmit > 0) {
					maxRetrans = pairingCfg_.max_check_retransmit;
				}
				else {
					maxRetrans = MaxStunCheckRetransmissions;
				}
				if (e.retransmissions >= maxRetrans) {
					e.state = StunEntryState::Failed;
					if (e.type == StunEntryType::Server) {
						--pendingServerReflexive_;
						checkGatheringComplete();
					}
					if (e.pair) {
						e.pair->state = PairState::Failed;
						resetNomination(*e.pair);
					}
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
					int sentUdp = sendUdp(reinterpret_cast<const char*>(m.raw.data()), m.raw.size(), e.record, /*control=*/true);
					if (sentUdp <= 0)
						STICE_LOG_WARN("sendStunBinding: sendUdp to %s failed n=%d",
							e.record.toString().c_str(), sentUdp);
				}
				else {
					sendStunBinding(e, stun::Class::Request, 0);
				}
				++e.retransmissions;
				// TCP: keep the fixed timeout (no exponential backoff). UDP: double.
				if (!isTcp) {
					e.retransmissionTimeout = std::min(e.retransmissionTimeout * 2,
						std::chrono::milliseconds(LastStunRetransmissionTimeoutMs));
				}
				e.nextTransmission = now + e.retransmissionTimeout;
			}
			else if (e.state == StunEntryState::SucceededKeepalive) {
				if (e.pair && e.pair->consentExpiry <= now) {
					// Consent expired.
					e.pair->state = PairState::Failed;
					resetNomination(*e.pair);
					e.state = StunEntryState::Failed;
					continue;
				}
				if (now >= e.nextTransmission) {
					sendKeepalive(e);
					armKeepalive(e);
				}
			}
			// Drive TURN client (Allocate retransmission, refresh, permissions).
			// Skip Cancelled entries (cancelAllEntries during teardown): the
			// TURN client must not retransmit an allocation being deallocated.
			if (e.type == StunEntryType::Relay && e.turn &&
				e.state != StunEntryState::Cancelled) {
				auto nextTick = e.turn->tick();
				// tick() returns {} when the TURN client has NOTHING scheduled
				// (e.g. after its allocation attempt settled or failed). Skipping
				// the assignment in that case would leave the PREVIOUS -- now
				// past-due -- deadline in nextTransmission. nextTimestampMs()
				// keeps advertising it, so PollRegistry::computeTimeoutMs()
				// clamps the poll timeout to 0 and run() spins on epoll_wait(0)
				// at 100% CPU, never advancing. "Nothing scheduled" must read as
				// "not before forever" instead. Measured: two agents whose TURN
				// server was unreachable (one relay entry each) pegged two poll
				// threads at ~100% for the whole gathering window.
				e.nextTransmission = (nextTick == std::chrono::steady_clock::time_point{})
				                         ? std::chrono::steady_clock::time_point::max()
				                         : nextTick;
				// If the TURN client failed (e.g. allocate timeout), clean up the
				// TURN-over-TCP transport to prevent fd leakage. This handles the
				// timeout path that onTurnTcpEvents doesn't see (the TCP connection
				// itself may still be alive when the STUN transaction times out).
				// Aligned with pion turn PR#513.
				if (e.turn->state() == turn::AllocState::Failed && e.turnTcp) {
					e.turnTcp->close();
					e.turnTcp.reset();
				}
			}
		}
		// Controlling-side nomination. Only arm once — after arming, the entry
		// loop handles retransmissions. Re-arming every cycle would reset the
		// transaction ID, causing the peer's response to never match.
		// RFC 8445 §8.1.1: while a nomination is active (nominatedPair_ set) no
		// second nomination may be triggered, even if updateState drifted
		// selectedPair_ to a fresher higher-priority succeeded pair — selecting
		// a data path is not nominating it. Only the opt-in renomination draft
		// may switch.
		if (mode_ == AgentMode::Controlling && selectedPair_ &&
			!selectedPair_->nominated && !selectedPair_->nominationRequested &&
			(!nominatedPair_ || renominationAllowed())) {
			// Aligned with pion-ice ContactCandidates (selection.go L74-84):
			// nominate when the best valid pair is nominatable (both local and
			// remote have exceeded their acceptance min wait since checking
			// started). We also nominate when all checks are done (pendingCount
			// == 0) AND the pair is nominatable, to avoid waiting indefinitely
			// if no better pairs can appear.
			bool should_nominate = false;
			// RFC 6544 §8: regular nomination is required when TCP candidates are
			// present; aggressive nomination is not defined for them. The decision
			// must key on the LOCAL candidate set, not on pairs_: during trickle
			// there is a window where a local TCP candidate exists but the remote
			// candidate (and therefore the pair) has not arrived yet, and an
			// aggressive nomination in that window would violate the MUST.
			IceNominationMode nomMode = pairingCfg_.nomination_mode;
			if (nomMode == IceNominationMode::AGGRESSIVE) {
				for (const auto& c : local_.candidates) {
					if (c.transport != CandidateTransport::UDP) {
						nomMode = IceNominationMode::REGULAR;
						break;
					}
				}
			}
			if (nomMode == IceNominationMode::AGGRESSIVE) {
				// Aggressive: nominate as soon as the pair is nominatable,
				// without waiting for better pairs. Matches pion-ice default.
				should_nominate = isNominatable(selectedPair_);
			}
			else if (nomMode == IceNominationMode::REGULAR_STABLE_CHECK &&
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
			}
			else {
				// REGULAR (and REGULAR_STABLE_CHECK for non-TCP pairs):
				// nominate when nominatable. UDP pairs need no extra wait.
				should_nominate = isNominatable(selectedPair_);
			}
			// Early lock: if every other connectivity check has concluded (no
			// Check entry is still Pending or not yet armed), no better pair can
			// appear from the current candidate set — skip the acceptance min
			// wait and nominate immediately instead of idling for the full
			// NominationDelayRelayMs. Renomination (draft-thatcher-ice-
			// renomination) still switches to a higher-priority pair if one
			// succeeds later (e.g. candidates arriving via trickle), so early
			// locking never sticks to a suboptimal link.
			bool tcp_relay_precheck_path =
				nomMode == IceNominationMode::REGULAR_STABLE_CHECK &&
				pairIsTcpRelay(selectedPair_);
			if (!should_nominate && !tcp_relay_precheck_path) {
				StunEntry* sel = findEntry(selectedPair_);
				bool all_settled = true;
				for (const auto& e : entries_) {
					if (e.type == StunEntryType::Check && &e != sel &&
						(e.state == StunEntryState::Pending ||
							e.state == StunEntryState::Idle)) {
						all_settled = false;
						break;
					}
				}
				if (all_settled) should_nominate = true;
			}
			if (should_nominate) {
				selectedPair_->nominationRequested = true;
				StunEntry* e = findEntry(selectedPair_);
				if (e) armTransmission(*e, 0);
			}
		}
		// Once a pair is nominated, freeze all other pending pairs and cancel
		// their in-flight checks (RFC 8445 §8.1.2: once a pair is nominated,
		// connectivity checks are no longer needed). Leaving the entries Pending
		// kept retransmitting for the whole STUN timeout window (~31.5 s) after
		// nomination — a pointless check storm during the handshake tail.
		if (nominatedPair_) {
			for (auto& p : pairs_) {
				if (p.get() != nominatedPair_ && p->state == PairState::Pending)
					p->state = PairState::Frozen;
			}
			for (auto& e : entries_) {
				if (e.type == StunEntryType::Check && e.pair != nominatedPair_ &&
					e.state == StunEntryState::Pending) {
					e.state = StunEntryState::Cancelled;
				}
			}
		}
		updateState();
	}
	// Count currently InProgress Check entries (Pending state with a Check
	// type). Used by LIMITED_CONCURRENT to enforce max_concurrent_check.
	std::size_t Agent::countInProgressChecks() const {
		std::size_t n = 0;
		for (const auto& e : entries_) {
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
		for (const auto& p : pairs_) {
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
			const auto& srv = deferredTcpTurnServers_[k];
			int idx = k < deferredTcpTurnIndices_.size() ? deferredTcpTurnIndices_[k] : 0;
			STICE_LOG_INFO("Agent: creating deferred RFC 6062 TCP allocation (server=%s:%u)",
				srv.host ? srv.host : "", srv.port);
			gatherRelay(srv, idx);
		}
	}
	void Agent::armNextFrozenPair() {
		// RFC 8445 §8.1.2: once a pair has been nominated the controlling agent
		// MUST cancel the remaining checks. A failure callback still reaches
		// this function, and without the guard it would re-arm a Frozen pair
		// that survived cancelAllEntries and restart checks after nomination.
		if (nominatedPair_) {
			STICE_LOG_DEBUG("armNextFrozenPair: pair already nominated, not arming further checks");
			return;
		}
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
		const auto& cfg = pairingCfg_;
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
		for (auto* np : orderedPairs_) {
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
			for (auto& ce : entries_)
				if (ce.pair == np) { found = true; break; }
			if (!found && (entries_.size() < MaxStunEntries || reclaimDeadEntries())) {
				StunEntry ne;
				ne.type = StunEntryType::Check;
				ne.state = StunEntryState::Pending;
				ne.pair = np;
				ne.record = np->remote->resolved;
				ne.mode = mode_;
				// RFC 8445 §6.1.4: consecutive checks are paced by Ta. When a
				// mode arms several pairs in one pass (strict / limited-concurrent
				// / phased), stagger them by Ta so they do not all fire on the
				// same tick and flood the peer with a simultaneous check burst.
				armTransmission(ne, StunPacingTimeMs * static_cast<int>(armed + 1));
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
		// Agent-level Checking ceiling (pion agent.go:696): while CONNECTING and
		// no pair has succeeded, cap the whole phase at 30 s regardless of PAC.
		// A peer that never answers and never signals end-of-candidates would
		// otherwise hold the session in CONNECTING for the full 31.5 s PAC window
		// before FAILED. Checking starts when CONNECTING is entered
		// (checkingStartTime_), so this only bounds the check phase itself.
		if (state_ == STICE_STATE_CONNECTING &&
			checkingStartTime_.time_since_epoch().count() != 0) {
			auto checkingElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now() - checkingStartTime_);
			if (checkingElapsed.count() >= MaxCheckingWallMs) {
				bool anySucceeded = false;
				for (const auto& p : pairs_)
					if (p->state == PairState::Succeeded) { anySucceeded = true; break; }
				if (!anySucceeded) {
					STICE_LOG_WARN("updateState: checking phase exceeded %dms with no succeeded pair; failing",
						MaxCheckingWallMs);
					pacDeadline_ = {};
					changeState(STICE_STATE_FAILED);
					return;
				}
			}
		}
		// RFC 8445 §8.1.1/§8.1.2: the nominated pair is the single active path.
		// A nomination whose pair is no longer Succeeded must be released:
		// keeping the pointer would keep the §8.1.2 freeze active forever (every
		// other pair stays Frozen, every other check entry stays Cancelled),
		// block armNextFrozenPair via its nominatedPair_ guard and block
		// pruneFailedPairs from recycling the dead pair — a consent-expiry or
		// check-failure redial could then never recover.
		if (nominatedPair_ && nominatedPair_->state != PairState::Succeeded) {
			CandidatePair* dead = nominatedPair_;
			STICE_LOG_WARN("Agent: nominated pair no longer succeeded (%s), releasing nomination",
				dead->remote ? dead->remote->resolved.toString().c_str() : "?");
			nominatedPair_ = nullptr;
			if (selectedPair_ == dead) selectedPair_ = nullptr;
			// Cancelled check entries (frozen by §8.1.2 when the nomination was
			// made) can never fire again; drop them so armNextFrozenPair re-arms
			// the frozen pairs with fresh entries.
			for (auto it = entries_.begin(); it != entries_.end();) {
				if (it->type == StunEntryType::Check && it->state == StunEntryState::Cancelled)
					it = entries_.erase(it);
				else
					++it;
			}
			armNextFrozenPair();
		}
		// Find best succeeded pair. Under STICKY_SELECTED, if the previously
		// selected pair was a TCP-relay link, prefer remaining TCP-relay
		// valid pairs over higher-priority UDP pairs — this keeps the link
		// on TCP-relay until every TCP-relay pair fails, avoiding flapping
		// between UDP and TCP-relay on transient UDP recovery. Only an
		// ICE-Restart resets this preference (see restart()).
		CandidatePair* best = nullptr;
		CandidatePair* best_tcp = nullptr;
		CandidatePair* best_udp = nullptr;
		bool sticky_tcp = pairingCfg_.reselect_policy == LinkReselectPolicy::STICKY_SELECTED &&
			selectedPair_ && pairIsTcpRelay(selectedPair_);
		for (auto& p : pairs_) {
			if (p->state != PairState::Succeeded) continue;
			if (pairIsTcpRelay(p.get())) {
				if (!best_tcp || p->priority > best_tcp->priority)
					best_tcp = p.get();
			}
			else {
				if (!best_udp || p->priority > best_udp->priority)
					best_udp = p.get();
			}
		}
		if (sticky_tcp) {
			// Prefer TCP-relay if any exists; fall back to UDP only when no
			// TCP-relay pair is currently Succeeded.
			best = best_tcp ? best_tcp : best_udp;
		}
		else {
			// RFC8445: pure highest-priority across all transports.
			best = best_tcp && (!best_udp || best_tcp->priority > best_udp->priority)
				? best_tcp
				: best_udp;
		}
		if (best) {
			// RFC 8445 §8.1.1: while a nomination is active the data path stays
			// on it. Unconditionally drifting selectedPair_ to a fresher
			// higher-priority succeeded pair moves media onto a path the peer
			// never accepted — and, together with the periodic nomination
			// block, used to trigger an illegal second nomination.
			if (nominatedPair_ && nominatedPair_->state == PairState::Succeeded &&
				!renominationAllowed())
				selectedPair_ = nominatedPair_;
			else
				selectedPair_ = best;
			if (selectedPair_->nominated) {
				nominatedPair_ = selectedPair_;
				if (state_ == STICE_STATE_CONNECTING) {
					changeState(STICE_STATE_CONNECTED);
					changeState(STICE_STATE_COMPLETED);
				}
				else if (state_ == STICE_STATE_CONNECTED) {
					changeState(STICE_STATE_COMPLETED);
				}
				else if (state_ == STICE_STATE_DISCONNECTED &&
					disconnectedAt_.time_since_epoch().count() != 0) {
					// Revival inside the disconnect grace window (#10): a TCP
					// redial or a late check brought a nominated pair back.
					disconnectedAt_ = {};
					changeState(STICE_STATE_COMPLETED);
				}
				closeUnselectedTcpConns();
			}
			else {
				if (state_ == STICE_STATE_CONNECTING) changeState(STICE_STATE_CONNECTED);
				else if (state_ == STICE_STATE_DISCONNECTED &&
					disconnectedAt_.time_since_epoch().count() != 0) {
					disconnectedAt_ = {};
					changeState(STICE_STATE_CONNECTED);
				}
			}
			return;
		}
		// A TCP dial in flight means a pair can still materialise: ICE-TCP only
		// creates the pair once the TCP connection is up and the first STUN check
		// arrives, so pairs_ is legitimately empty right after both sides finish
		// gathering. Failing fast here aborted a connect that completed
		// milliseconds later (observed as tcp-ice never connecting).
		bool tcpDialPending = false;
		for (const auto& c : tcpConns_) {
			if (!c.transport) {
				if (c.reconnectPending) { tcpDialPending = true; break; }
				continue;
			}
			const auto st = c.transport->state();
			if (st == net::TcpState::Connecting || st == net::TcpState::TlsHandshaking ||
				st == net::TcpState::Connected) {
				tcpDialPending = true;
				break;
			}
		}
		// The passive side of ICE-TCP owns no direct connection: the TCPMux holds
		// the accepted connection. While this agent's passive candidate is
		// registered with the mux, the peer can still dial in and create a pair,
		// so an empty checklist is not terminal here either.
		const bool tcpInboundPossible = tcpMux_ != nullptr && tcpMuxRegistered_;
		// Both sides have declared end-of-candidates and no pair exists at all:
		// no further candidate can appear (an in-flight mDNS resolution or a TCP
		// dial is the only exception), so waiting out the PAC window would just
		// delay a certain failure by 31.5 s.
		if (pairs_.empty() && gatheringDone_ && remoteGatheringDone_ &&
			pendingMdnsResolutions_ == 0 && !tcpDialPending) {
			if (!tcpInboundPossible) {
				pacDeadline_ = {};
				STICE_LOG_WARN("updateState: no pairs and both sides finished gathering; failing fast");
				if (state_ == STICE_STATE_CONNECTING) changeState(STICE_STATE_FAILED);
				return;
			}
			// Passive ICE-TCP: the peer may still dial our listener, so give the
			// inbound connection one PAC window before declaring failure.
			auto now = std::chrono::steady_clock::now();
			if (pacDeadline_.time_since_epoch().count() == 0) {
				pacDeadline_ = now + std::chrono::milliseconds(IcePacTimeoutMs);
				STICE_LOG_DEBUG("updateState: ICE-TCP passive listener waiting %dms for inbound connection",
					IcePacTimeoutMs);
				return;
			}
			if (now < pacDeadline_) return;
			pacDeadline_ = {};
			STICE_LOG_WARN("updateState: ICE-TCP passive listener saw no inbound connection; failing");
			if (state_ == STICE_STATE_CONNECTING) changeState(STICE_STATE_FAILED);
			return;
		}
		// No succeeded pair. Check if all pairs failed.
		bool allFailed = true;
		for (const auto& p : pairs_) {
			if (p->state != PairState::Failed) { allFailed = false; break; }
		}
		if (!allFailed || pairs_.empty()) {
			// Connectivity is still being attempted: cancel any PAC wait so that
			// a later "everything failed" starts a fresh patience window.
			pacDeadline_ = {};
			return;
		}
		// RFC 8863 §4 (Patiently Awaiting Connectivity): while the agent is still
		// Running, a checklist with no pairs left to check MUST NOT be moved to
		// Failed immediately - a peer-reflexive pair can still be discovered from
		// inbound traffic (and trickled remote candidates may still arrive). Wait
		// for one connectivity-check transaction timeout (31.5 s, the RFC's
		// RECOMMENDED duration) instead. This is what IcePacTimeoutMs - declared
		// but never used - was for.
		//
		// The patience only makes sense while new pairs are still possible. Once
		// the remote has declared end-of-candidates (and no local mDNS resolution
		// or TCP dial is outstanding) no further pair can appear, so failing
		// immediately is both correct and avoids a pointless 31.5 s wait.
		const bool morePairsPossible = !remoteGatheringDone_ ||
			pendingMdnsResolutions_ > 0 || tcpDialPending;
		if (state_ == STICE_STATE_CONNECTING && morePairsPossible) {
			auto now = std::chrono::steady_clock::now();
			if (pacDeadline_.time_since_epoch().count() == 0) {
				pacDeadline_ = now + std::chrono::milliseconds(IcePacTimeoutMs);
				STICE_LOG_DEBUG("updateState: every pair failed while connecting; "
					"patiently awaiting connectivity for %dms", IcePacTimeoutMs);
				return;
			}
			if (now < pacDeadline_) return;
			STICE_LOG_WARN("updateState: PAC timer expired with no pair left; failing");
			pacDeadline_ = {};
		}
		// Transition to FAILED from CONNECTING, CONNECTED, or COMPLETED.
		// Consent expiry can cause all pairs to fail even after connection
		// was established. CONNECTING stays immediate: RFC 8863's PAC timer
		// governs the Running state, and a connect that never formed must fail
		// promptly. Post-connection loss reports DISCONNECTED first (#10,
		// pion-aligned lifecycle) and holds a short grace window before the
		// terminal FAILED, so the application can observe the loss and an
		// in-flight TCP redial can revive the session (recovery branch above).
		if (state_ == STICE_STATE_CONNECTING) {
			changeState(STICE_STATE_FAILED);
			return;
		}
		// Grace re-entry: after the first report state_ is DISCONNECTED, so the
		// pre-loss states alone would never re-arm this branch. Gate on the
		// timestamp — it is only non-zero for a post-connection loss (initial
		// and post-restart DISCONNECTED both carry pairs_ empty and exit above).
		const bool postConnectLoss =
			state_ == STICE_STATE_CONNECTED || state_ == STICE_STATE_COMPLETED ||
			(state_ == STICE_STATE_DISCONNECTED &&
			 disconnectedAt_.time_since_epoch().count() != 0);
		if (postConnectLoss) {
			const auto now = std::chrono::steady_clock::now();
			if (disconnectedAt_.time_since_epoch().count() == 0) {
				disconnectedAt_ = now;
				STICE_LOG_WARN("updateState: all pairs lost after connect; reporting DISCONNECTED (grace %dms)",
					DisconnectedGraceMs);
				changeState(STICE_STATE_DISCONNECTED);
				return;
			}
			if (now - disconnectedAt_ < std::chrono::milliseconds(DisconnectedGraceMs)) return;
			disconnectedAt_ = {};
			changeState(STICE_STATE_FAILED);
		}
	}
	int Agent::send(const char* data, std::size_t size, int ds) {
	// Fast path: snapshot destination / framed ChannelData under mutex_, then
	// perform the actual socket write outside the main lock under sendMutex_
	// (libjuice send_mutex model). This removes main-lock contention between
	// the app send loop and the poll thread (onUdpReadable / onBookkeeping).
	// All outbound writes on sock_ / the TCP control transport are serialized
	// by sendMutex_ so they never race a socket close / rebuild.
	net::AddrRecord dst;
	bool direct = false;
	net::AddrRecord relayRecord;
	bool useTcpRelay = false;
	std::shared_ptr<net::TcpTransport> relayTurnTcp;
	bytes relayFrame;
	bool viaRelay = false;
	{
		std::lock_guard<std::recursive_mutex> lock(mutex_);
		lastAppDataAt_ = std::chrono::steady_clock::now();
		if (!selectedPair_ || !selectedPair_->local || !selectedPair_->remote)
			return STICE_ERR_FAILED;
		if (!mux_ && ds < 0 && !pairIsTurnTcpRelay(selectedPair_) &&
		    !pairIsTcp(selectedPair_)) {
			bool routeViaRelay =
			    (selectedPair_->local->type == CandidateType::Relayed);
			if (!routeViaRelay &&
			    selectedPair_->remote->type == CandidateType::Relayed) {
				for (const auto &re : entries_)
					if (re.type == StunEntryType::Relay && re.turn &&
					    re.turn->state() == turn::AllocState::Allocated) {
						routeViaRelay = true;
						break;
					}
			}
			if (!routeViaRelay) { // snapshot, send outside the lock
				dst = selectedPair_->remote->resolved;
				direct = true;
			} else {
				for (auto &e : entries_) {
					if (e.type == StunEntryType::Relay && e.turn &&
					    e.turn->state() == turn::AllocState::Allocated) {
						int r = e.turn->prepareChannelData(
						    selectedPair_->remote->resolved,
						    reinterpret_cast<const unsigned char *>(data), size,
						    relayFrame);
						if (r == 1) {
							viaRelay = true;
							relayRecord = e.record;
							useTcpRelay = e.tcpTurn;
							relayTurnTcp = e.turnTcp;
						}
						break;
					}
				}
			}
		}
	}
	if (direct) {
		std::lock_guard<std::mutex> sl(sendMutex_);
		int n = sock_.sendto(data, size, dst);
		if (n < 0) return -sticeSockerrno;
		return n;
	}
	if (viaRelay) {
		std::lock_guard<std::mutex> sl(sendMutex_);
		if (useTcpRelay) {
			if (relayTurnTcp &&
			    relayTurnTcp->state() == net::TcpState::Connected) {
				bool ok = relayTurnTcp->send(
				    reinterpret_cast<const char *>(relayFrame.data()),
				    relayFrame.size());
				return ok ? static_cast<int>(size) : -STICE_SEWOULDBLOCK;
			}
			return -STICE_SEWOULDBLOCK;
		}
		int n = sock_.sendto(reinterpret_cast<const char *>(relayFrame.data()),
		                     relayFrame.size(), relayRecord);
		if (n < 0) return -sticeSockerrno;
		return static_cast<int>(size);
	}
	std::lock_guard<std::recursive_mutex> lock(mutex_);
	lastAppDataAt_ = std::chrono::steady_clock::now();
	return sendViaSelectedPair(data, size, ds);
}
int Agent::sendViaSelectedPair(const char* data, std::size_t size, int ds) {
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
			for (const auto& re : entries_) {
				if (re.type == StunEntryType::Relay && re.turn &&
					re.turn->state() == turn::AllocState::Allocated) {
					routeViaRelay = true;
					break;
				}
			}
		}
		if (routeViaRelay) {
			for (auto& e : entries_) {
				if (e.type == StunEntryType::Relay && e.turn &&
					e.turn->state() == turn::AllocState::Allocated) {
					STICE_LOG_DEBUG("TURN: routing app data via relay -> %s (%zu bytes)",
						selectedPair_->remote->resolved.toString().c_str(), size);
					int r = e.turn->sendData(selectedPair_->remote->resolved,
						reinterpret_cast<const unsigned char*>(data), size);
					// Propagate transport failures (e.g. -EAGAIN/-ENOBUFS) so the
					// C API can report STICE_ERR_AGAIN and the application gets
					// backpressure instead of a silent drop.
					if (r < 0) return r;
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
			// DSCP/TOS is per-socket state: set+send+reset must be a single
			// serialized operation on the socket, otherwise agents sharing one
			// UDPMux interleave their marks (and the trailing reset clobbers a
			// concurrent set).
			int n = mux_
				? mux_->sendtoWithDiffserv(data, size, selectedPair_->remote->resolved, ds,
				                           local_.iceUfrag)
				: sock_.sendtoWithDiffserv(data, size, selectedPair_->remote->resolved, ds);
			if (n < 0) return -sticeSockerrno;
			return n;
		}
		int n = sendUdp(data, size, selectedPair_->remote->resolved);
		// Follow libjuice convention: on failure, return -errno so the C API
		// wrapper can distinguish EAGAIN/EMSGSIZE from other errors.
		if (n < 0) return -sticeSockerrno;
		return n;
	}
	int Agent::getSelectedCandidates(char* local, std::size_t localSize, char* remote,
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
	int Agent::getSelectedAddresses(char* local, std::size_t localSize, char* remote,
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
