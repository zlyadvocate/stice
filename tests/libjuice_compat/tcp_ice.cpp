/**
 * ICE-TCP connectivity test (RFC 6544).
 *
 * Tests TCP candidate connectivity between two stice agents:
 *   - Agent1 (passive): uses a TCPMux to listen for inbound TCP connections
 *     and generates TCPPassive host candidates.
 *   - Agent2 (active):  uses ICE-TCP ACTIVE mode and generates TCPActive
 *     candidates by dialing agent1's TCPPassive candidate.
 *
 * To force ICE to select the TCP pair, the test filters out UDP candidates
 * in the on_candidate callbacks (only TCP candidates are exchanged).
 *
 * Usage: tcp_ice_test [bind_address]
 *   bind_address : default "0.0.0.0" (TCPMux bind address)
 */

#include "stice/stice.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static void sleep_ms(unsigned int ms) { Sleep(ms); }
#else
#include <unistd.h>
static void sleep_ms(unsigned int ms) { usleep(ms * 1000); }
#endif

#define BUFFER_SIZE 4096

static stice_agent_t *agent1;
static stice_agent_t *agent2;
static stice_tcp_mux_t *tcp_mux;

// Event synchronization
static volatile int state1 = 0;
static volatile int state2 = 0;

// Message reception flags
static volatile int recv1 = 0;
static volatile int recv2 = 0;

// Bidirectional exchange counters
#define EXCHANGE_ROUNDS 2
static volatile int send_count1 = 0;
static volatile int send_count2 = 0;
static volatile int recv_count1 = 0;
static volatile int recv_count2 = 0;

// Default log handler
static void default_log_handler(stice_log_level_t level, const char *msg) {
	const char *prefix = "?";
	switch (level) {
	case STICE_LOG_LEVEL_VERBOSE: prefix = "VRB"; break;
	case STICE_LOG_LEVEL_DEBUG:   prefix = "DBG"; break;
	case STICE_LOG_LEVEL_INFO:    prefix = "INF"; break;
	case STICE_LOG_LEVEL_WARN:    prefix = "WRN"; break;
	case STICE_LOG_LEVEL_ERROR:   prefix = "ERR"; break;
	case STICE_LOG_LEVEL_FATAL:   prefix = "FTL"; break;
	default: break;
	}
	printf("[stice %s] %s\n", prefix, msg);
	fflush(stdout);
}

static void on_state_changed1(stice_agent_t *agent, stice_state_t state, void *user_ptr) {
	printf("[1] State: %s\n", stice_state_to_string(state));
	if (state == STICE_STATE_CONNECTED || state == STICE_STATE_COMPLETED) {
		state1 = 1;
		char msg[64];
		int n = snprintf(msg, sizeof(msg), "Hello TCP %d from agent1", ++send_count1);
		printf("[1] >>> SEND: \"%s\" (%d bytes)\n", msg, n);
		stice_send(agent, msg, (size_t)n);
	} else if (state == STICE_STATE_FAILED) {
		state1 = -1;
	}
}

static void on_state_changed2(stice_agent_t *agent, stice_state_t state, void *user_ptr) {
	printf("[2] State: %s\n", stice_state_to_string(state));
	if (state == STICE_STATE_CONNECTED || state == STICE_STATE_COMPLETED) {
		state2 = 1;
		char msg[64];
		int n = snprintf(msg, sizeof(msg), "Hello TCP %d from agent2", ++send_count2);
		printf("[2] >>> SEND: \"%s\" (%d bytes)\n", msg, n);
		stice_send(agent, msg, (size_t)n);
	} else if (state == STICE_STATE_FAILED) {
		state2 = -1;
	}
}

// Only forward TCP candidates (filter out UDP) to force ICE-TCP.
static void on_candidate1(stice_agent_t *agent, const char *sdp, void *user_ptr) {
	if (strstr(sdp, "tcp")) {
		printf("[1] TCP Candidate: %s", sdp);
		stice_add_remote_candidate(agent2, sdp);
	}
}

static void on_candidate2(stice_agent_t *agent, const char *sdp, void *user_ptr) {
	if (strstr(sdp, "tcp")) {
		printf("[2] TCP Candidate: %s", sdp);
		stice_add_remote_candidate(agent1, sdp);
	}
}

static void on_gathering_done1(stice_agent_t *agent, void *user_ptr) {
	printf("[1] Gathering done\n");
	stice_set_remote_gathering_done(agent2);
}

static void on_gathering_done2(stice_agent_t *agent, void *user_ptr) {
	printf("[2] Gathering done\n");
	stice_set_remote_gathering_done(agent1);
}

static void on_recv1(stice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	char buffer[BUFFER_SIZE];
	if (size > BUFFER_SIZE - 1)
		size = BUFFER_SIZE - 1;
	memcpy(buffer, data, size);
	buffer[size] = '\0';
	printf("[1] <<< RECV: \"%s\" (%zu bytes)\n", buffer, size);
	recv1 = 1;
	recv_count1++;
	if (send_count1 < EXCHANGE_ROUNDS) {
		char msg[64];
		int n = snprintf(msg, sizeof(msg), "Reply %d from agent1", ++send_count1);
		printf("[1] >>> SEND: \"%s\" (%d bytes)\n", msg, n);
		stice_send(agent, msg, (size_t)n);
	}
}

static void on_recv2(stice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	char buffer[BUFFER_SIZE];
	if (size > BUFFER_SIZE - 1)
		size = BUFFER_SIZE - 1;
	memcpy(buffer, data, size);
	buffer[size] = '\0';
	printf("[2] <<< RECV: \"%s\" (%zu bytes)\n", buffer, size);
	recv2 = 1;
	recv_count2++;
	if (send_count2 < EXCHANGE_ROUNDS) {
		char msg[64];
		int n = snprintf(msg, sizeof(msg), "Reply %d from agent2", ++send_count2);
		printf("[2] >>> SEND: \"%s\" (%d bytes)\n", msg, n);
		stice_send(agent, msg, (size_t)n);
	}
}

int main(int argc, char **argv) {
	stice_set_log_level(STICE_LOG_LEVEL_INFO);
	stice_set_log_handler(default_log_handler);

	const char *bind_address = argc > 1 ? argv[1] : "0.0.0.0";

	printf("=== ICE-TCP connectivity test (RFC 6544) ===\n");
	printf("Agent1: passive (TCPMux), Agent2: active\n");
	printf("Exchange rounds: %d (per agent)\n", EXCHANGE_ROUNDS);

	// Create TCPMux for agent1 (passive side).
	// Port 0 = ephemeral; the mux will pick an available port.
	tcp_mux = stice_create_tcp_mux(bind_address, 0);
	if (!tcp_mux) {
		printf("FAIL: could not create TCPMux\n");
		return -1;
	}

	// --- Agent 1 (passive) ---
	stice_config_t config1;
	memset(&config1, 0, sizeof(config1));
	config1.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
	config1.cb_state_changed = on_state_changed1;
	config1.cb_candidate = on_candidate1;
	config1.cb_gathering_done = on_gathering_done1;
	config1.cb_recv = on_recv1;
	config1.user_ptr = NULL;

	agent1 = stice_create(&config1);
	if (!agent1) {
		printf("FAIL: could not create agent1\n");
		stice_destroy_tcp_mux(tcp_mux);
		return -1;
	}

	// Set ICE-TCP mode to PASSIVE and bind to TCPMux.
	stice_set_ice_tcp_mode(agent1, STICE_ICE_TCP_MODE_PASSIVE);
	stice_agent_use_tcp_mux(agent1, tcp_mux);

	// --- Agent 2 (active) ---
	stice_config_t config2;
	memset(&config2, 0, sizeof(config2));
	config2.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
	config2.cb_state_changed = on_state_changed2;
	config2.cb_candidate = on_candidate2;
	config2.cb_gathering_done = on_gathering_done2;
	config2.cb_recv = on_recv2;
	config2.user_ptr = NULL;

	agent2 = stice_create(&config2);
	if (!agent2) {
		printf("FAIL: could not create agent2\n");
		stice_destroy(agent1);
		stice_destroy_tcp_mux(tcp_mux);
		return -1;
	}

	// Set ICE-TCP mode to ACTIVE (will dial agent1's passive candidate).
	stice_set_ice_tcp_mode(agent2, STICE_ICE_TCP_MODE_ACTIVE);

	// Exchange SDP (ufrag/pwd only, before gathering).
	char sdp1[STICE_MAX_SDP_STRING_LEN];
	stice_get_local_description(agent1, sdp1, STICE_MAX_SDP_STRING_LEN);
	printf("\n--- Agent 1 SDP ---\n%s\n", sdp1);
	stice_set_remote_description(agent2, sdp1);

	char sdp2[STICE_MAX_SDP_STRING_LEN];
	stice_get_local_description(agent2, sdp2, STICE_MAX_SDP_STRING_LEN);
	printf("\n--- Agent 2 SDP ---\n%s\n", sdp2);
	stice_set_remote_description(agent1, sdp2);

	// Start gathering (both agents).
	stice_gather_candidates(agent1);
	stice_gather_candidates(agent2);

	// Wait for ICE to complete + bidirectional exchange (max 30s).
	printf("\nWaiting for ICE-TCP to complete...\n");
	int waited = 0;
	while (waited < 30000) {
		int exchange_done = (recv_count1 >= EXCHANGE_ROUNDS) && (recv_count2 >= EXCHANGE_ROUNDS);
		if ((state1 < 0 || state2 < 0) ||
		    (state1 > 0 && state2 > 0 && exchange_done))
			break;
		sleep_ms(100);
		waited += 100;
	}

	// Result evaluation.
	bool exchange_done = (recv_count1 >= EXCHANGE_ROUNDS) && (recv_count2 >= EXCHANGE_ROUNDS);
	bool success = (state1 > 0 && state2 > 0 && recv1 && recv2 && exchange_done);

	// Print selected candidates.
	char local_c[STICE_MAX_CANDIDATE_SDP_STRING_LEN];
	char remote_c[STICE_MAX_CANDIDATE_SDP_STRING_LEN];
	if (stice_get_selected_candidates(agent1, local_c, STICE_MAX_CANDIDATE_SDP_STRING_LEN,
	                                  remote_c, STICE_MAX_CANDIDATE_SDP_STRING_LEN) == 0) {
		printf("\nAgent1 local  candidate: %s", local_c);
		printf("Agent1 remote candidate: %s", remote_c);
		if (strstr(local_c, "tcp") || strstr(remote_c, "tcp"))
			printf("  -> TCP candidate selected\n");
		else
			printf("  -> WARNING: UDP candidate selected (expected TCP)\n");
	}
	if (stice_get_selected_candidates(agent2, local_c, STICE_MAX_CANDIDATE_SDP_STRING_LEN,
	                                  remote_c, STICE_MAX_CANDIDATE_SDP_STRING_LEN) == 0) {
		printf("Agent2 local  candidate: %s", local_c);
		printf("Agent2 remote candidate: %s", remote_c);
		if (strstr(local_c, "tcp") || strstr(remote_c, "tcp"))
			printf("  -> TCP candidate selected\n");
		else
			printf("  -> WARNING: UDP candidate selected (expected TCP)\n");
	}

	printf("\n--- Bidirectional exchange summary ---\n");
	printf("Agent1: sent=%d, received=%d\n", send_count1, recv_count1);
	printf("Agent2: sent=%d, received=%d\n", send_count2, recv_count2);

	stice_destroy(agent1);
	stice_destroy(agent2);
	stice_destroy_tcp_mux(tcp_mux);

	printf("\n=== Test %s (waited %d ms) ===\n", success ? "SUCCESS" : "FAILURE", waited);
	return success ? 0 : -1;
}
