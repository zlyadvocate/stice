/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
// stice C API wrapper. Mirrors libjuice's juice.c so that consumers
// (libdatachannel's IceTransport) can adopt stice with a mechanical rename
// of juice_* -> stice_*.
//
// The stice_agent_t handle is an opaque struct wrapping a stice::ice::Agent.
// All functions validate their arguments and translate the Agent's return
// values into the STICE_ERR_* codes declared in stice.h.

#include "stice/stice.h"
#include "stice/ice/agent.hpp"
#include "stice/log.hpp"
#include "stice/net/platform.hpp"
#include "stice/net/udp_mux.hpp"
#include "stice/net/tcp_mux.hpp"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <new>
#include <thread>

// ---------------------------------------------------------------------------
// stice_agent_t: the opaque handle. Defined here (not in a header) so the
// stice::ice::Agent member is invisible to consumers.
//
// Threading contract (P0-5): all stice_* API calls on a given agent MUST be
// made from the same thread that called stice_create. The ICE agent's poll
// loop runs on its own internal thread; user-facing API calls are NOT
// thread-safe. The owner thread is recorded at creation and checked (debug
// builds log a warning on violation).
//
// Destroy idempotency (P0-6): `destroyed` is set atomically by stice_destroy;
// a second stice_destroy call on the same handle is a no-op (the handle is
// responsible for never passing a freed pointer, but the atomic guards
// against double-destroy of a still-valid handle).
// ---------------------------------------------------------------------------
struct stice_agent {
	stice::ice::Agent agent;
	std::atomic<bool> destroyed{false};
	std::thread::id ownerThread;
};

// Helper: validate the agent handle and enforce the single-thread constraint.
// Returns nullptr (and logs in debug) if the handle is invalid, already
// destroyed, or called from the wrong thread.
static inline stice_agent *agent_check(stice_agent_t *agent) {
	if (!agent) return nullptr;
	auto *a = reinterpret_cast<stice_agent *>(agent);
	if (a->destroyed.load(std::memory_order_acquire)) {
		STICE_LOG_WARN("stice: API call on destroyed agent");
		return nullptr;
	}
#ifndef NDEBUG
	if (a->ownerThread != std::this_thread::get_id()) {
		STICE_LOG_WARN("stice: API call from wrong thread (single-thread constraint violated)");
	}
#endif
	return a;
}

extern "C" {

STICE_EXPORT stice_agent_t *stice_create(const stice_config_t *config) {
	if (!config)
		return nullptr;
	auto *a = new (std::nothrow) stice_agent;
	if (!a)
		return nullptr;
	a->ownerThread = std::this_thread::get_id();
	// init() creates the UDP socket and registers with the poll registry.
	// It may call changeState (which fires cb_state_changed) before returning,
	// so self_ must be wired up first; pass &a->agent's owning handle.
	if (!a->agent.init(config, reinterpret_cast<stice_agent_t *>(a))) {
		delete a;
		return nullptr;
	}
	return reinterpret_cast<stice_agent_t *>(a);
}

STICE_EXPORT void stice_destroy(stice_agent_t *agent) {
	if (!agent)
		return;
	auto *a = reinterpret_cast<stice_agent *>(agent);
	// Idempotent destroy (P0-6): if already destroyed, do nothing. The
	// exchange ensures exactly one caller proceeds to delete.
	bool expected = false;
	if (!a->destroyed.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
		return;
	delete a;
}

STICE_EXPORT int stice_gather_candidates(stice_agent_t *agent) {
	auto *a = agent_check(agent);
	if (!a) return STICE_ERR_INVALID;
	return a->agent.gatherCandidates();
}

STICE_EXPORT int stice_get_local_description(stice_agent_t *agent, char *buffer, size_t size) {
	auto *a = agent_check(agent);
	if (!a || (!buffer && size))
		return STICE_ERR_INVALID;
	return a->agent.getLocalDescription(buffer, size);
}

STICE_EXPORT int stice_set_remote_description(stice_agent_t *agent, const char *sdp) {
	auto *a = agent_check(agent);
	if (!a || !sdp)
		return STICE_ERR_INVALID;
	return a->agent.setRemoteDescription(sdp);
}

STICE_EXPORT int stice_add_remote_candidate(stice_agent_t *agent, const char *sdp) {
	auto *a = agent_check(agent);
	if (!a || !sdp)
		return STICE_ERR_INVALID;
	return a->agent.addRemoteCandidate(sdp);
}

STICE_EXPORT int stice_add_turn_server(stice_agent_t *agent, const stice_turn_server_t *turn_server) {
	auto *a = agent_check(agent);
	if (!a || !turn_server)
		return STICE_ERR_INVALID;
	return a->agent.addTurnServer(turn_server);
}

STICE_EXPORT int stice_add_stun_server(stice_agent_t *agent, const char *host, uint16_t port) {
	auto *a = agent_check(agent);
	if (!a || !host)
		return STICE_ERR_INVALID;
	return a->agent.addStunServer(host, port);
}

STICE_EXPORT int stice_add_ice_server(stice_agent_t *agent, const stice_ice_server_t *server) {
	auto *a = agent_check(agent);
	if (!a || !server || !server->url)
		return STICE_ERR_INVALID;
	return a->agent.addIceServer(server->url, server->username, server->password);
}

STICE_EXPORT int stice_set_remote_gathering_done(stice_agent_t *agent) {
	auto *a = agent_check(agent);
	if (!a) return STICE_ERR_INVALID;
	return a->agent.setRemoteGatheringDone();
}

STICE_EXPORT int stice_send(stice_agent_t *agent, const char *data, size_t size) {
	return stice_send_diffserv(agent, data, size, 0);
}

STICE_EXPORT int stice_send_diffserv(stice_agent_t *agent, const char *data, size_t size, int ds) {
	auto *a = agent_check(agent);
	if (!a || (!data && size))
		return STICE_ERR_INVALID;
	int ret = a->agent.send(data, size, ds);
	if (ret >= 0)
		return STICE_ERR_SUCCESS;
	// ret is the negative of a platform errno (STICE_SE*).
	if (ret == -STICE_SEAGAIN || ret == -STICE_SEWOULDBLOCK)
		return STICE_ERR_AGAIN;
	if (ret == -STICE_SEMSGSIZE)
		return STICE_ERR_TOO_LARGE;
	return STICE_ERR_FAILED;
}

STICE_EXPORT stice_state_t stice_get_state(stice_agent_t *agent) {
	auto *a = agent_check(agent);
	if (!a) return STICE_STATE_DISCONNECTED;
	return a->agent.state();
}

STICE_EXPORT int stice_get_selected_candidates(stice_agent_t *agent, char *local, size_t local_size,
                                               char *remote, size_t remote_size) {
	auto *a = agent_check(agent);
	if (!a || (!local && local_size) || (!remote && remote_size))
		return STICE_ERR_INVALID;
	return a->agent.getSelectedCandidates(local, local_size, remote, remote_size);
}

STICE_EXPORT int stice_get_selected_addresses(stice_agent_t *agent, char *local, size_t local_size,
                                              char *remote, size_t remote_size) {
	auto *a = agent_check(agent);
	if (!a || (!local && local_size) || (!remote && remote_size))
		return STICE_ERR_INVALID;
	return a->agent.getSelectedAddresses(local, local_size, remote, remote_size);
}

STICE_EXPORT int stice_set_local_ice_attributes(stice_agent_t *agent, const char *ufrag,
                                                const char *pwd) {
	auto *a = agent_check(agent);
	if (!a || !ufrag || !pwd)
		return STICE_ERR_INVALID;
	return a->agent.setLocalIceAttributes(ufrag, pwd);
}

STICE_EXPORT const char *stice_state_to_string(stice_state_t state) {
	switch (state) {
	case STICE_STATE_DISCONNECTED:
		return "disconnected";
	case STICE_STATE_GATHERING:
		return "gathering";
	case STICE_STATE_CONNECTING:
		return "connecting";
	case STICE_STATE_CONNECTED:
		return "connected";
	case STICE_STATE_COMPLETED:
		return "completed";
	case STICE_STATE_FAILED:
		return "failed";
	default:
		return "unknown";
	}
}

STICE_EXPORT int stice_set_ice_tcp_mode(stice_agent_t *agent, stice_ice_tcp_mode_t ice_tcp_mode) {
	auto *a = agent_check(agent);
	if (!a) return STICE_ERR_INVALID;
	return a->agent.setIceTcpMode(ice_tcp_mode);
}

// Translate the C ABI pairing config to the C++ struct.
static stice::ice::IcePairingConfig toCppPairingConfig(const stice_ice_pairing_config_t &c) {
	stice::ice::IcePairingConfig cfg;
	switch (c.schedule_mode) {
	case STICE_SCHEDULE_RFC8445_STRICT: cfg.schedule_mode = stice::ice::IceCheckScheduleMode::RFC8445_STRICT; break;
	case STICE_SCHEDULE_SERIAL: cfg.schedule_mode = stice::ice::IceCheckScheduleMode::SERIAL; break;
	case STICE_SCHEDULE_LIMITED_CONCURRENT: cfg.schedule_mode = stice::ice::IceCheckScheduleMode::LIMITED_CONCURRENT; break;
	case STICE_SCHEDULE_PHASED_UDP_FIRST: default: cfg.schedule_mode = stice::ice::IceCheckScheduleMode::PHASED_UDP_FIRST; break;
	}
	cfg.max_concurrent_check = c.max_concurrent_check;
	cfg.udp_phase_timeout = std::chrono::milliseconds(c.udp_phase_timeout_ms);
	switch (c.nomination_mode) {
	case STICE_NOMINATION_AGGRESSIVE: cfg.nomination_mode = stice::ice::IceNominationMode::AGGRESSIVE; break;
	case STICE_NOMINATION_REGULAR: cfg.nomination_mode = stice::ice::IceNominationMode::REGULAR; break;
	case STICE_NOMINATION_REGULAR_STABLE_CHECK: default: cfg.nomination_mode = stice::ice::IceNominationMode::REGULAR_STABLE_CHECK; break;
	}
	cfg.tcp_nomination_precheck = std::chrono::milliseconds(c.tcp_nomination_precheck_ms);
	switch (c.tcp_relay_fallback) {
	case STICE_TCP_RELAY_DISABLE: cfg.tcp_relay_fallback = stice::ice::TcpRelayFallbackMode::DISABLE; break;
	case STICE_TCP_RELAY_ALWAYS_ENABLE: cfg.tcp_relay_fallback = stice::ice::TcpRelayFallbackMode::ALWAYS_ENABLE; break;
	case STICE_TCP_RELAY_ON_ALL_UDP_FAIL: default: cfg.tcp_relay_fallback = stice::ice::TcpRelayFallbackMode::ON_ALL_UDP_FAIL; break;
	}
	switch (c.reselect_policy) {
	case STICE_RESELECT_RFC8445: cfg.reselect_policy = stice::ice::LinkReselectPolicy::RFC8445; break;
	case STICE_RESELECT_STICKY_SELECTED: default: cfg.reselect_policy = stice::ice::LinkReselectPolicy::STICKY_SELECTED; break;
	}
	cfg.rto_initial = std::chrono::milliseconds(c.rto_initial_ms);
	cfg.max_check_retransmit = c.max_check_retransmit;
	cfg.keepalive_udp = std::chrono::milliseconds(c.keepalive_udp_ms);
	cfg.keepalive_tcp_relay = std::chrono::milliseconds(c.keepalive_tcp_relay_ms);
	cfg.enable_trickle = c.enable_trickle;
	cfg.pre_allocate_tcp_relay = c.pre_allocate_tcp_relay;
	cfg.early_phase_max_concurrent = c.early_phase_max_concurrent;
	cfg.early_phase_duration = std::chrono::milliseconds(c.early_phase_duration_ms);
	return cfg;
}

STICE_EXPORT int stice_make_pairing_config(stice_ice_pairing_profile_t profile,
                                           stice_ice_pairing_config_t *out_config) {
	if (!out_config) return STICE_ERR_INVALID;
	stice::ice::IcePairingProfile cpp_profile;
	switch (profile) {
	case STICE_PAIRING_RFC8445_COMPAT: cpp_profile = stice::ice::IcePairingProfile::RFC8445_COMPAT; break;
	case STICE_PAIRING_EMBEDDED_STABLE: cpp_profile = stice::ice::IcePairingProfile::EMBEDDED_STABLE; break;
	case STICE_PAIRING_DEBUG_FAST: cpp_profile = stice::ice::IcePairingProfile::DEBUG_FAST; break;
	case STICE_PAIRING_MINIMAL_RESOURCE: default: cpp_profile = stice::ice::IcePairingProfile::MINIMAL_RESOURCE; break;
	}
	auto cfg = stice::ice::makeIcePairingConfig(cpp_profile);
	// Translate back to C struct.
	std::memset(out_config, 0, sizeof(*out_config));
	switch (cfg.schedule_mode) {
	case stice::ice::IceCheckScheduleMode::RFC8445_STRICT: out_config->schedule_mode = STICE_SCHEDULE_RFC8445_STRICT; break;
	case stice::ice::IceCheckScheduleMode::SERIAL: out_config->schedule_mode = STICE_SCHEDULE_SERIAL; break;
	case stice::ice::IceCheckScheduleMode::LIMITED_CONCURRENT: out_config->schedule_mode = STICE_SCHEDULE_LIMITED_CONCURRENT; break;
	case stice::ice::IceCheckScheduleMode::PHASED_UDP_FIRST: out_config->schedule_mode = STICE_SCHEDULE_PHASED_UDP_FIRST; break;
	}
	out_config->max_concurrent_check = cfg.max_concurrent_check;
	out_config->udp_phase_timeout_ms = static_cast<uint32_t>(cfg.udp_phase_timeout.count());
	switch (cfg.nomination_mode) {
	case stice::ice::IceNominationMode::AGGRESSIVE: out_config->nomination_mode = STICE_NOMINATION_AGGRESSIVE; break;
	case stice::ice::IceNominationMode::REGULAR: out_config->nomination_mode = STICE_NOMINATION_REGULAR; break;
	case stice::ice::IceNominationMode::REGULAR_STABLE_CHECK: out_config->nomination_mode = STICE_NOMINATION_REGULAR_STABLE_CHECK; break;
	}
	out_config->tcp_nomination_precheck_ms = static_cast<uint32_t>(cfg.tcp_nomination_precheck.count());
	switch (cfg.tcp_relay_fallback) {
	case stice::ice::TcpRelayFallbackMode::DISABLE: out_config->tcp_relay_fallback = STICE_TCP_RELAY_DISABLE; break;
	case stice::ice::TcpRelayFallbackMode::ALWAYS_ENABLE: out_config->tcp_relay_fallback = STICE_TCP_RELAY_ALWAYS_ENABLE; break;
	case stice::ice::TcpRelayFallbackMode::ON_ALL_UDP_FAIL: out_config->tcp_relay_fallback = STICE_TCP_RELAY_ON_ALL_UDP_FAIL; break;
	}
	switch (cfg.reselect_policy) {
	case stice::ice::LinkReselectPolicy::RFC8445: out_config->reselect_policy = STICE_RESELECT_RFC8445; break;
	case stice::ice::LinkReselectPolicy::STICKY_SELECTED: out_config->reselect_policy = STICE_RESELECT_STICKY_SELECTED; break;
	}
	out_config->rto_initial_ms = static_cast<uint32_t>(cfg.rto_initial.count());
	out_config->max_check_retransmit = cfg.max_check_retransmit;
	out_config->keepalive_udp_ms = static_cast<uint32_t>(cfg.keepalive_udp.count());
	out_config->keepalive_tcp_relay_ms = static_cast<uint32_t>(cfg.keepalive_tcp_relay.count());
	out_config->enable_trickle = cfg.enable_trickle;
	out_config->pre_allocate_tcp_relay = cfg.pre_allocate_tcp_relay;
	out_config->early_phase_max_concurrent = cfg.early_phase_max_concurrent;
	out_config->early_phase_duration_ms = static_cast<uint32_t>(cfg.early_phase_duration.count());
	return STICE_ERR_SUCCESS;
}

STICE_EXPORT int stice_set_pairing_config(stice_agent_t *agent,
                                          const stice_ice_pairing_config_t *config) {
	auto *a = agent_check(agent);
	if (!a || !config) return STICE_ERR_INVALID;
	return a->agent.setPairingConfig(toCppPairingConfig(*config));
}

STICE_EXPORT int stice_add_address_rewrite_rule(stice_agent_t *agent,
                                                const stice_address_rewrite_rule_t *rule) {
	auto *a = agent_check(agent);
	if (!a || !rule)
		return STICE_ERR_INVALID;
	return a->agent.addAddressRewriteRule(rule);
}

STICE_EXPORT int stice_set_multicast_dns_mode(stice_agent_t *agent, stice_multicast_dns_mode_t mode) {
	auto *a = agent_check(agent);
	if (!a) return STICE_ERR_INVALID;
	return a->agent.setMulticastDnsMode(mode);
}

// Override the global TCP priority offset (P2-1). Affects all agents.
// Pass 0 to restore the default (27).
STICE_EXPORT void stice_set_tcp_priority_offset(uint32_t offset) {
	stice::ice::g_tcpPriorityOffset.store(offset ? offset : stice::ice::TcpPenalty,
	                                      std::memory_order_release);
}

// --- UDPMux ----------------------------------------------------------------

struct stice_udp_mux {
	stice::net::UDPMux mux;
};

STICE_EXPORT stice_udp_mux_t *stice_create_udp_mux(const char *bind_address,
                                                   uint16_t local_port_range_begin,
                                                   uint16_t local_port_range_end) {
	auto *m = new (std::nothrow) stice_udp_mux;
	if (!m)
		return nullptr;
	stice::net::UdpSocketConfig cfg;
	cfg.bindAddress = bind_address ? bind_address : "";
	cfg.portBegin = local_port_range_begin;
	cfg.portEnd = local_port_range_end;
	if (!m->mux.init(cfg)) {
		delete m;
		return nullptr;
	}
	return reinterpret_cast<stice_udp_mux_t *>(m);
}

STICE_EXPORT void stice_destroy_udp_mux(stice_udp_mux_t *mux) {
	if (mux)
		delete reinterpret_cast<stice_udp_mux *>(mux);
}

STICE_EXPORT int stice_agent_use_udp_mux(stice_agent_t *agent, stice_udp_mux_t *mux) {
	auto *a = agent_check(agent);
	if (!a || !mux)
		return STICE_ERR_INVALID;
	return a->agent.setUDPMux(&reinterpret_cast<stice_udp_mux *>(mux)->mux);
}

// --- TCPMux ----------------------------------------------------------------

struct stice_tcp_mux {
	stice::net::TCPMux mux;
};

STICE_EXPORT stice_tcp_mux_t *stice_create_tcp_mux(const char *bind_address, uint16_t port) {
	auto *m = new (std::nothrow) stice_tcp_mux;
	if (!m)
		return nullptr;
	if (!m->mux.init(bind_address ? bind_address : "", port)) {
		delete m;
		return nullptr;
	}
	return reinterpret_cast<stice_tcp_mux_t *>(m);
}

STICE_EXPORT void stice_destroy_tcp_mux(stice_tcp_mux_t *mux) {
	if (mux)
		delete reinterpret_cast<stice_tcp_mux *>(mux);
}

STICE_EXPORT int stice_agent_use_tcp_mux(stice_agent_t *agent, stice_tcp_mux_t *mux) {
	auto *a = agent_check(agent);
	if (!a || !mux)
		return STICE_ERR_INVALID;
	return a->agent.setTCPMux(&reinterpret_cast<stice_tcp_mux *>(mux)->mux);
}

// --- Logging ---------------------------------------------------------------

STICE_EXPORT void stice_set_log_level(stice_log_level_t level) {
	stice::Logger::instance().setLevel(level);
}

STICE_EXPORT void stice_set_log_handler(stice_log_cb_t cb) {
	stice::Logger::instance().setHandler(cb);
}

} // extern "C"
