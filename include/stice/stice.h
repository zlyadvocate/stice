// SPDX-License-Identifier: MPL-2.0
//
// stice: a C++17 ICE + TURN client library ported from pion/webrtc (Go),
// designed as a drop-in replacement for libjuice in libdatachannel.
//
// This C ABI mirrors libjuice's juice.h so that consumers (libdatachannel's
// IceTransport) can adopt stice with a mechanical rename (juice_* -> stice_*).
// The implementation is C++17 internally.

#ifndef STICE_H
#define STICE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef STICE_STATIC
#  ifdef _WIN32
#    ifdef STICE_EXPORTS
#      define STICE_EXPORT __declspec(dllexport)
#    else
#      define STICE_EXPORT __declspec(dllimport)
#    endif
#  else
#    if defined(__has_attribute)
#      if __has_attribute(visibility)
#        define STICE_EXPORT __attribute__((visibility("default")))
#      endif
#    endif
#  endif
#endif
#ifndef STICE_EXPORT
#  define STICE_EXPORT
#endif

#define STICE_ERR_SUCCESS 0
#define STICE_ERR_INVALID -1
#define STICE_ERR_FAILED -2
#define STICE_ERR_NOT_AVAIL -3
#define STICE_ERR_IGNORED -4
#define STICE_ERR_AGAIN -5
#define STICE_ERR_TOO_LARGE -6

// ICE Agent
#define STICE_MAX_ADDRESS_STRING_LEN 64
#define STICE_MAX_CANDIDATE_SDP_STRING_LEN 256
#define STICE_MAX_SDP_STRING_LEN 4096

typedef struct stice_agent stice_agent_t;

typedef enum stice_state {
	STICE_STATE_DISCONNECTED = 0,
	STICE_STATE_GATHERING,
	STICE_STATE_CONNECTING,
	STICE_STATE_CONNECTED,
	STICE_STATE_COMPLETED,
	STICE_STATE_FAILED
} stice_state_t;

typedef void (*stice_cb_state_changed_t)(stice_agent_t *agent, stice_state_t state, void *user_ptr);
typedef void (*stice_cb_candidate_t)(stice_agent_t *agent, const char *sdp, void *user_ptr);
typedef void (*stice_cb_gathering_done_t)(stice_agent_t *agent, void *user_ptr);
typedef void (*stice_cb_recv_t)(stice_agent_t *agent, const char *data, size_t size, void *user_ptr);

// TURN server transport protocol (RFC 8656).
typedef enum stice_turn_transport {
	STICE_TURN_TRANSPORT_UDP = 0,
	STICE_TURN_TRANSPORT_TCP,
	STICE_TURN_TRANSPORT_TLS,
} stice_turn_transport_t;

typedef struct stice_turn_server {
	const char *host;
	const char *username;
	const char *password;
	uint16_t port;
	stice_turn_transport_t transport;
	// When transport == STICE_TURN_TRANSPORT_TLS, controls whether the
	// server's TLS certificate is verified against the system trust store.
	// 0 = verify (default, secure), 1 = skip verification (insecure, use
	// only for testing with self-signed certificates).
	int skip_tls_verify;
} stice_turn_server_t;

typedef enum stice_concurrency_mode {
	STICE_CONCURRENCY_MODE_POLL = 0, // default: connections share one background thread
	STICE_CONCURRENCY_MODE_MUX,      // multiplexed on a single shared UDP socket
	STICE_CONCURRENCY_MODE_THREAD,   // each agent runs its own thread
} stice_concurrency_mode_t;

// ICE-TCP mode (RFC 6544). Determines which TCP candidate types the agent
// will gather/accept. Aligned with pion-ice TCPType.
typedef enum stice_ice_tcp_mode {
	STICE_ICE_TCP_MODE_NONE = 0,
	STICE_ICE_TCP_MODE_ACTIVE,      // Local active: initiates TCP connections
	STICE_ICE_TCP_MODE_PASSIVE,     // Local passive: listens for incoming TCP (requires TcpMux)
	STICE_ICE_TCP_MODE_SO,          // Simultaneous-Open: both directions
} stice_ice_tcp_mode_t;

// Multicast DNS mode (aligned with pion-ice MulticastDNSMode).
typedef enum stice_multicast_dns_mode {
	STICE_MDNS_MODE_DISABLED = 1,     // Discard remote mDNS candidates, use IPs locally
	STICE_MDNS_MODE_QUERY_ONLY = 2,   // Accept remote mDNS candidates, use IPs locally
	STICE_MDNS_MODE_QUERY_AND_GATHER = 3, // Accept remote mDNS, use mDNS for local host candidates
} stice_multicast_dns_mode_t;

// Address rewrite mode (NAT 1:1 IP mapping, aligned with pion-ice).
typedef enum stice_address_rewrite_mode {
	STICE_ADDR_REWRITE_MODE_UNSPECIFIED = 0,
	STICE_ADDR_REWRITE_MODE_REPLACE = 1,
	STICE_ADDR_REWRITE_MODE_APPEND = 2,
} stice_address_rewrite_mode_t;

// Candidate type for address rewrite rules.
typedef enum stice_rewrite_candidate_type {
	STICE_REWRITE_CANDIDATE_TYPE_UNSPECIFIED = 0,
	STICE_REWRITE_CANDIDATE_TYPE_HOST = 1,
	STICE_REWRITE_CANDIDATE_TYPE_SRFLX = 2,
	STICE_REWRITE_CANDIDATE_TYPE_RELAY = 3,
} stice_rewrite_candidate_type_t;

// Address rewrite rule for NAT 1:1 IP mapping.
typedef struct stice_address_rewrite_rule {
	const char *const *external_ips; // NULL-terminated array of external IP strings
	const char *local_ip;            // optional: pin to a specific local IP
	const char *iface;               // optional: interface name filter
	const char *cidr;                // optional: CIDR filter
	stice_rewrite_candidate_type_t as_candidate_type;
	stice_address_rewrite_mode_t mode;
} stice_address_rewrite_rule_t;

typedef struct stice_config {
	stice_concurrency_mode_t concurrency_mode;

	// Single STUN server (legacy, kept for ABI compatibility). When
	// stun_servers is non-NULL, stun_servers takes precedence and this
	// field is ignored.
	const char *stun_server_host;
	uint16_t stun_server_port;

	// Multiple STUN servers for parallel srflx gathering (aligned with
	// pion-ice's multi-URL gatherServerReflexiveCandidates). Each entry
	// is a host:port pair; all are queried concurrently during gathering.
	// May be NULL (use stun_server_host instead). When non-NULL,
	// stun_server_host/stun_server_port are ignored.
	const char *const *stun_servers;
	const uint16_t *stun_server_ports;
	int stun_servers_count;

	stice_turn_server_t *turn_servers;
	int turn_servers_count;

	const char *bind_address;

	uint16_t local_port_range_begin;
	uint16_t local_port_range_end;

	// Optional interface IP whitelist/blacklist (NULL-terminated arrays of
	// IP string literals, e.g. {"192.168.1.100", "10.0.0.5", NULL}).
	// When whitelist is non-NULL, only local interfaces whose IP matches an
	// entry in the whitelist are used for host candidate gathering.
	// When blacklist is non-NULL, matching interfaces are excluded.
	// Both may be set simultaneously (whitelist takes precedence).
	// Aligned with pion #779 InterfaceFilter.
	const char *const *interface_whitelist;
	const char *const *interface_blacklist;

	// TCP priority offset (RFC 6544 §4.2). Subtracted from the type
	// preference of TCP candidates to prefer UDP. Default 0 = use the
	// built-in constant (27, aligned with pion-ice defaultTCPPriorityOffset).
	// Set to a non-zero value to override at runtime (P2-1).
	uint32_t tcp_priority_offset;

	// Disable active TCP: when non-zero, the agent will NOT create a local
	// active TCP candidate in response to a remote passive TCP candidate.
	// Aligned with pion-ice AgentConfig.DisableActiveTCP / WithDisableActiveTCP.
	// Use this when you only want passive TCP (listening) and never want to
	// initiate outbound TCP connections to remote passive candidates.
	int disable_active_tcp;

	// mDNS mode (default: STICE_MDNS_MODE_DISABLED).
	stice_multicast_dns_mode_t multicast_dns_mode;
	// Optional: custom mDNS hostname. If NULL, a random UUID.local is generated.
	const char *multicast_dns_hostname;

	stice_cb_state_changed_t cb_state_changed;
	stice_cb_candidate_t cb_candidate;
	stice_cb_gathering_done_t cb_gathering_done;
	stice_cb_recv_t cb_recv;

	void *user_ptr;
} stice_config_t;

// Unified ICE server descriptor (aligned with pion webrtc.ICEServer).
// A single URL auto-populates both STUN and TURN internal storage:
//   "stun:host:port"  → adds a STUN server only
//   "turn:host:port"  → adds both a TURN server (relay) AND a STUN server
//                       (srflx), since coturn supports both on the same port
//   "turns:host:port" → adds a TURN/TLS server (and STUN via UDP)
//   "turn:host:port?transport=tcp" → adds a TURN-over-TCP server
// This eliminates the need to configure the same server twice (once as STUN,
// once as TURN). Must be called before stice_gather_candidates.
typedef struct stice_ice_server {
	const char *url;       // e.g. "stun:192.168.3.223:3478", "turn:host:port?transport=tcp"
	const char *username;  // NULL for stun: URLs
	const char *password;  // NULL for stun: URLs
} stice_ice_server_t;

STICE_EXPORT stice_agent_t *stice_create(const stice_config_t *config);
STICE_EXPORT void stice_destroy(stice_agent_t *agent);

STICE_EXPORT int stice_gather_candidates(stice_agent_t *agent);
STICE_EXPORT int stice_get_local_description(stice_agent_t *agent, char *buffer, size_t size);
STICE_EXPORT int stice_set_remote_description(stice_agent_t *agent, const char *sdp);
STICE_EXPORT int stice_add_remote_candidate(stice_agent_t *agent, const char *sdp);
STICE_EXPORT int stice_add_turn_server(stice_agent_t *agent, const stice_turn_server_t *turn_server);
// Add a STUN server for server-reflexive candidate gathering. Multiple STUN
// servers may be added; all are queried concurrently during gathering.
// Must be called before stice_gather_candidates.
STICE_EXPORT int stice_add_stun_server(stice_agent_t *agent, const char *host, uint16_t port);
// Add an ICE server from a unified URL (stun:/turn:/turns:). Automatically
// populates both STUN and TURN internal storage from a single configuration
// entry, eliminating duplicate configuration. Must be called before
// stice_gather_candidates.
STICE_EXPORT int stice_add_ice_server(stice_agent_t *agent, const stice_ice_server_t *server);
STICE_EXPORT int stice_set_remote_gathering_done(stice_agent_t *agent);
STICE_EXPORT int stice_send(stice_agent_t *agent, const char *data, size_t size);
STICE_EXPORT int stice_send_diffserv(stice_agent_t *agent, const char *data, size_t size, int ds);
STICE_EXPORT stice_state_t stice_get_state(stice_agent_t *agent);
STICE_EXPORT int stice_get_selected_candidates(stice_agent_t *agent, char *local, size_t local_size,
                                               char *remote, size_t remote_size);
STICE_EXPORT int stice_get_selected_addresses(stice_agent_t *agent, char *local, size_t local_size,
                                              char *remote, size_t remote_size);
STICE_EXPORT int stice_set_local_ice_attributes(stice_agent_t *agent, const char *ufrag, const char *pwd);
STICE_EXPORT const char *stice_state_to_string(stice_state_t state);
STICE_EXPORT int stice_set_ice_tcp_mode(stice_agent_t *agent, stice_ice_tcp_mode_t ice_tcp_mode);

// ---------------------------------------------------------------------------
// ICE pairing strategy (C ABI mirror of stice::ice::IcePairingConfig).
// Allows the application to switch scheduling / nomination / RFC 6062
// fallback / reselection behavior without recompiling. See
// pairing_strategy.hpp for the C++ documentation.
// ---------------------------------------------------------------------------
typedef enum stice_ice_check_schedule_mode {
	STICE_SCHEDULE_RFC8445_STRICT = 0,
	STICE_SCHEDULE_SERIAL = 1,
	STICE_SCHEDULE_LIMITED_CONCURRENT = 2,
	STICE_SCHEDULE_PHASED_UDP_FIRST = 3,
} stice_ice_check_schedule_mode_t;

typedef enum stice_ice_nomination_mode {
	STICE_NOMINATION_AGGRESSIVE = 0,
	STICE_NOMINATION_REGULAR = 1,
	STICE_NOMINATION_REGULAR_STABLE_CHECK = 2,
} stice_ice_nomination_mode_t;

typedef enum stice_tcp_relay_fallback_mode {
	STICE_TCP_RELAY_DISABLE = 0,
	STICE_TCP_RELAY_ON_ALL_UDP_FAIL = 1,
	STICE_TCP_RELAY_ALWAYS_ENABLE = 2,
} stice_tcp_relay_fallback_mode_t;

typedef enum stice_link_reselect_policy {
	STICE_RESELECT_RFC8445 = 0,
	STICE_RESELECT_STICKY_SELECTED = 1,
} stice_link_reselect_policy_t;

typedef struct stice_ice_pairing_config {
	stice_ice_check_schedule_mode_t schedule_mode;
	size_t max_concurrent_check;       // 0 = unlimited
	uint32_t udp_phase_timeout_ms;     // 0 = wait until all UDP fail
	stice_ice_nomination_mode_t nomination_mode;
	uint32_t tcp_nomination_precheck_ms;
	stice_tcp_relay_fallback_mode_t tcp_relay_fallback;
	stice_link_reselect_policy_t reselect_policy;
	uint32_t rto_initial_ms;
	int max_check_retransmit;
	uint32_t keepalive_udp_ms;
	uint32_t keepalive_tcp_relay_ms;
	// Speed optimization fields. New fields appended for ABI forward
	// compatibility; callers using stice_make_pairing_config get the
	// profile defaults, callers filling the struct manually should
	// zero-initialize first (the C factory zeroes before populating).
	bool enable_trickle;               // push candidates as they are gathered
	bool pre_allocate_tcp_relay;       // background Mode-B allocation during UDP phase
	size_t early_phase_max_concurrent; // 0 = disabled, else temp boost during early_phase_duration_ms
	uint32_t early_phase_duration_ms;  // 0 = disabled
} stice_ice_pairing_config_t;

// Preset profiles (mirror of stice::ice::IcePairingProfile).
typedef enum stice_ice_pairing_profile {
	STICE_PAIRING_RFC8445_COMPAT = 0,
	STICE_PAIRING_EMBEDDED_STABLE = 1,
	STICE_PAIRING_DEBUG_FAST = 2,
	STICE_PAIRING_MINIMAL_RESOURCE = 3,
} stice_ice_pairing_profile_t;

// Build a config from a preset profile. Writes to *out_config.
STICE_EXPORT int stice_make_pairing_config(stice_ice_pairing_profile_t profile,
                                           stice_ice_pairing_config_t *out_config);

// Apply a pairing config to an agent. Takes effect on the next
// stice_gather_candidates / ICE-Restart.
STICE_EXPORT int stice_set_pairing_config(stice_agent_t *agent,
                                          const stice_ice_pairing_config_t *config);

// NAT 1:1 IP mapping: add an address rewrite rule.
// Must be called before stice_gather_candidates.
STICE_EXPORT int stice_add_address_rewrite_rule(stice_agent_t *agent,
                                                const stice_address_rewrite_rule_t *rule);

// Set the mDNS mode. Must be called before stice_gather_candidates.
STICE_EXPORT int stice_set_multicast_dns_mode(stice_agent_t *agent,
                                              stice_multicast_dns_mode_t mode);

// Override the global TCP priority offset (P2-1). Affects all agents.
// Pass 0 to restore the default (27, aligned with pion-ice).
STICE_EXPORT void stice_set_tcp_priority_offset(uint32_t offset);

// UDPMux: share a single UDP socket across multiple agents.
// Create a mux, then pass it to each agent before stice_gather_candidates.
typedef struct stice_udp_mux stice_udp_mux_t;

STICE_EXPORT stice_udp_mux_t *stice_create_udp_mux(const char *bind_address,
                                                   uint16_t local_port_range_begin,
                                                   uint16_t local_port_range_end);
STICE_EXPORT void stice_destroy_udp_mux(stice_udp_mux_t *mux);
// Bind an agent to a UDPMux. Must be called before stice_gather_candidates.
STICE_EXPORT int stice_agent_use_udp_mux(stice_agent_t *agent, stice_udp_mux_t *mux);

// TCPMux: share a single TCP listener socket across multiple agents for
// ICE-TCP passive mode (RFC 6544). Create a mux, set ice_tcp_mode to
// PASSIVE or SO, then pass the mux to the agent before stice_gather_candidates.
typedef struct stice_tcp_mux stice_tcp_mux_t;

STICE_EXPORT stice_tcp_mux_t *stice_create_tcp_mux(const char *bind_address, uint16_t port);
STICE_EXPORT void stice_destroy_tcp_mux(stice_tcp_mux_t *mux);
// Bind an agent to a TCPMux. Must be called before stice_gather_candidates.
// The agent's ice_tcp_mode should be set to PASSIVE or SO via stice_set_ice_tcp_mode.
STICE_EXPORT int stice_agent_use_tcp_mux(stice_agent_t *agent, stice_tcp_mux_t *mux);

// Logging
typedef enum stice_log_level {
	STICE_LOG_LEVEL_VERBOSE = 0,
	STICE_LOG_LEVEL_DEBUG,
	STICE_LOG_LEVEL_INFO,
	STICE_LOG_LEVEL_WARN,
	STICE_LOG_LEVEL_ERROR,
	STICE_LOG_LEVEL_FATAL,
	STICE_LOG_LEVEL_NONE
} stice_log_level_t;

typedef void (*stice_log_cb_t)(stice_log_level_t level, const char *message);

STICE_EXPORT void stice_set_log_level(stice_log_level_t level);
STICE_EXPORT void stice_set_log_handler(stice_log_cb_t cb);

#ifdef __cplusplus
}
#endif

#endif
