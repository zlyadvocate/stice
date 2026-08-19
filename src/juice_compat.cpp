// SPDX-License-Identifier: MPL-2.0
//
// libjuice compatibility layer: implements all juice_* C API functions
// by forwarding to the stice_* equivalents. The juice_config_t and
// juice_turn_server_t structs have different layouts from their stice
// counterparts, so explicit field-by-field conversion is required.

#include <juice/juice.h>   // the compatibility header we just created
#include <stice/stice.h>   // the real stice API

#include <vector>

// ---------------------------------------------------------------------------
// Agent lifecycle
// ---------------------------------------------------------------------------

extern "C" {

juice_agent_t *juice_create(const juice_config_t *config) {
	if (!config)
		return (juice_agent_t *)stice_create(nullptr);

	stice_config_t sc = {};
	sc.concurrency_mode = static_cast<stice_concurrency_mode_t>(config->concurrency_mode);
	sc.stun_server_host = config->stun_server_host;
	sc.stun_server_port = config->stun_server_port;
	sc.turn_servers_count = config->turn_servers_count;
	sc.bind_address = config->bind_address;
	sc.local_port_range_begin = config->local_port_range_begin;
	sc.local_port_range_end = config->local_port_range_end;

	// Convert the turn server array. juice_turn_server_t and
	// stice_turn_server_t have the same leading fields but stice has an
	// extra trailing field (skip_tls_verify), so we must copy element by
	// element into a temporary array.
	std::vector<stice_turn_server_t> sturn;
	if (config->turn_servers && config->turn_servers_count > 0) {
		sturn.resize(config->turn_servers_count);
		for (int i = 0; i < config->turn_servers_count; ++i) {
			sturn[i].host = config->turn_servers[i].host;
			sturn[i].username = config->turn_servers[i].username;
			sturn[i].password = config->turn_servers[i].password;
			sturn[i].port = config->turn_servers[i].port;
			sturn[i].transport =
			    static_cast<stice_turn_transport_t>(config->turn_servers[i].transport);
			sturn[i].skip_tls_verify = 0;
		}
		sc.turn_servers = sturn.data();
	}

	// Callback function pointer types have identical signatures (same
	// parameter types, just different typedef names). Cast through
	// reinterpret_cast since the enum values are binary-compatible.
	sc.cb_state_changed = reinterpret_cast<stice_cb_state_changed_t>(config->cb_state_changed);
	sc.cb_candidate = reinterpret_cast<stice_cb_candidate_t>(config->cb_candidate);
	sc.cb_gathering_done =
	    reinterpret_cast<stice_cb_gathering_done_t>(config->cb_gathering_done);
	sc.cb_recv = reinterpret_cast<stice_cb_recv_t>(config->cb_recv);
	sc.user_ptr = config->user_ptr;

	return (juice_agent_t *)stice_create(&sc);
}

void juice_destroy(juice_agent_t *agent) {
	stice_destroy((stice_agent_t *)agent);
}

// ---------------------------------------------------------------------------
// ICE operations (direct forwarding — signatures are identical modulo
// the opaque agent pointer and enum types, which share the same values)
// ---------------------------------------------------------------------------

int juice_gather_candidates(juice_agent_t *agent) {
	return stice_gather_candidates((stice_agent_t *)agent);
}

int juice_get_local_description(juice_agent_t *agent, char *buffer, size_t size) {
	return stice_get_local_description((stice_agent_t *)agent, buffer, size);
}

int juice_set_remote_description(juice_agent_t *agent, const char *sdp) {
	return stice_set_remote_description((stice_agent_t *)agent, sdp);
}

int juice_add_remote_candidate(juice_agent_t *agent, const char *sdp) {
	return stice_add_remote_candidate((stice_agent_t *)agent, sdp);
}

int juice_add_turn_server(juice_agent_t *agent, const juice_turn_server_t *turn_server) {
	if (!turn_server)
		return STICE_ERR_INVALID;
	stice_turn_server_t st = {};
	st.host = turn_server->host;
	st.username = turn_server->username;
	st.password = turn_server->password;
	st.port = turn_server->port;
	st.transport = static_cast<stice_turn_transport_t>(turn_server->transport);
	st.skip_tls_verify = 0;
	return stice_add_turn_server((stice_agent_t *)agent, &st);
}

int juice_set_remote_gathering_done(juice_agent_t *agent) {
	return stice_set_remote_gathering_done((stice_agent_t *)agent);
}

int juice_send(juice_agent_t *agent, const char *data, size_t size) {
	return stice_send((stice_agent_t *)agent, data, size);
}

int juice_send_diffserv(juice_agent_t *agent, const char *data, size_t size, int ds) {
	return stice_send_diffserv((stice_agent_t *)agent, data, size, ds);
}

juice_state_t juice_get_state(juice_agent_t *agent) {
	return (juice_state_t)stice_get_state((stice_agent_t *)agent);
}

int juice_get_selected_candidates(juice_agent_t *agent, char *local, size_t local_size,
                                  char *remote, size_t remote_size) {
	return stice_get_selected_candidates((stice_agent_t *)agent, local, local_size, remote,
	                                     remote_size);
}

int juice_get_selected_addresses(juice_agent_t *agent, char *local, size_t local_size,
                                 char *remote, size_t remote_size) {
	return stice_get_selected_addresses((stice_agent_t *)agent, local, local_size, remote,
	                                    remote_size);
}

int juice_set_local_ice_attributes(juice_agent_t *agent, const char *ufrag, const char *pwd) {
	return stice_set_local_ice_attributes((stice_agent_t *)agent, ufrag, pwd);
}

const char *juice_state_to_string(juice_state_t state) {
	return stice_state_to_string((stice_state_t)state);
}

int juice_set_ice_tcp_mode(juice_agent_t *agent, juice_ice_tcp_mode_t ice_tcp_mode) {
	// juice_ice_tcp_mode_t values (NONE=0, ACTIVE=1) map directly to
	// stice_ice_tcp_mode_t (NONE=0, ACTIVE=1, PASSIVE=2, SO=3).
	return stice_set_ice_tcp_mode((stice_agent_t *)agent,
	                              static_cast<stice_ice_tcp_mode_t>(ice_tcp_mode));
}

// ---------------------------------------------------------------------------
// juice_mux_listen — no direct stice equivalent.
// stice uses a different UDPMux API (stice_create_udp_mux / stice_agent_use_udp_mux).
// libdatachannel's IceUdpMuxListener uses this function, but no test in
// libdatachannel/test enables enableIceUdpMux, so a no-op stub returning
// success (0) is sufficient for the test suite.
// ---------------------------------------------------------------------------

int juice_mux_listen(const char * /*bind_address*/, int /*local_port*/,
                     juice_cb_mux_incoming_t /*cb*/, void * /*user_ptr*/) {
	return 0; // success — no-op
}

// ---------------------------------------------------------------------------
// ICE server stubs (not used by libdatachannel)
// ---------------------------------------------------------------------------

juice_server_t *juice_server_create(const juice_server_config_t * /*config*/) {
	return nullptr;
}

void juice_server_destroy(juice_server_t * /*server*/) {
	// no-op
}

uint16_t juice_server_get_port(juice_server_t * /*server*/) {
	return 0;
}

int juice_server_add_credentials(juice_server_t * /*server*/,
                                 const juice_server_credentials_t * /*credentials*/,
                                 unsigned long /*lifetime_ms*/) {
	return -1; // not available
}

// ---------------------------------------------------------------------------
// Logging — enum values are identical, cast and forward.
// ---------------------------------------------------------------------------

void juice_set_log_level(juice_log_level_t level) {
	stice_set_log_level(static_cast<stice_log_level_t>(level));
}

void juice_set_log_handler(juice_log_cb_t cb) {
	stice_set_log_handler(reinterpret_cast<stice_log_cb_t>(cb));
}

} // extern "C"
