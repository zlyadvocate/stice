/**
 * TURN over TCP/TLS connectivity test against a coturn server.
 *
 * Usage: turn_tcp_test [transport] [turn_host] [turn_port] [user] [pass]
 *   transport  : "tcp" (default) | "tls" | "udp"
 *   turn_host  : default 192.168.3.223
 *   turn_port  : default 3478
 *   user       : default testuser
 *   pass       : default 123456
 *
 * The test creates two agents that both use the same coturn as TURN relay
 * over the requested transport, exchanges SDP, and verifies that a relay
 * candidate gets selected and a data message round-trips.
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

// 事件同步：等待双方都进入 CONNECTED/COMPLETED
static volatile int state1 = 0;
static volatile int state2 = 0;

// 收到消息的标志
static volatile int recv1 = 0;
static volatile int recv2 = 0;

// 双向数据交换统计
#define EXCHANGE_ROUNDS 5
static volatile int send_count1 = 0; // agent1 已发送计数
static volatile int send_count2 = 0; // agent2 已发送计数
static volatile int recv_count1 = 0; // agent1 已接收计数
static volatile int recv_count2 = 0; // agent2 已接收计数

// 期望的 relay 候选 SDP 关键字
static const char *EXPECTED_RELAY_TAG = "relay";

// 解析 transport 参数
static stice_turn_transport_t parse_transport(const char *s) {
	if (!s)
		return STICE_TURN_TRANSPORT_TCP;
	if (strcmp(s, "tls") == 0 || strcmp(s, "TLS") == 0)
		return STICE_TURN_TRANSPORT_TLS;
	if (strcmp(s, "udp") == 0 || strcmp(s, "UDP") == 0)
		return STICE_TURN_TRANSPORT_UDP;
	return STICE_TURN_TRANSPORT_TCP;
}

static const char *transport_name(stice_turn_transport_t t) {
	switch (t) {
	case STICE_TURN_TRANSPORT_UDP: return "UDP";
	case STICE_TURN_TRANSPORT_TCP: return "TCP";
	case STICE_TURN_TRANSPORT_TLS: return "TLS";
	default: return "?";
	}
}

static void on_state_changed1(stice_agent_t *agent, stice_state_t state, void *user_ptr) {
	printf("[1] State: %s\n", stice_state_to_string(state));
	if (state == STICE_STATE_CONNECTED || state == STICE_STATE_COMPLETED) {
		state1 = 1;
		// Agent1 发起首轮 ping
		char msg[64];
		int n = snprintf(msg, sizeof(msg), "PING %d from agent1", ++send_count1);
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
		// Agent2 同时也发一条独立消息
		char msg[64];
		int n = snprintf(msg, sizeof(msg), "HELLO %d from agent2", ++send_count2);
		printf("[2] >>> SEND: \"%s\" (%d bytes)\n", msg, n);
		stice_send(agent, msg, (size_t)n);
	} else if (state == STICE_STATE_FAILED) {
		state2 = -1;
	}
}

static void on_candidate1(stice_agent_t *agent, const char *sdp, void *user_ptr) {
	// 只转发 relay 候选，减少干扰
	if (strstr(sdp, EXPECTED_RELAY_TAG)) {
		printf("[1] Candidate: %s", sdp);
		stice_add_remote_candidate(agent2, sdp);
	}
}

static void on_candidate2(stice_agent_t *agent, const char *sdp, void *user_ptr) {
	if (strstr(sdp, EXPECTED_RELAY_TAG)) {
		printf("[2] Candidate: %s", sdp);
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
	// Agent1 收到后回复 PONG（保持双向交换，直到达到总轮数上限）
	if (send_count1 < EXCHANGE_ROUNDS) {
		char msg[64];
		int n = snprintf(msg, sizeof(msg), "PONG %d from agent1", ++send_count1);
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
	// Agent2 收到后回复 PING（保持双向交换，直到达到总轮数上限）
	if (send_count2 < EXCHANGE_ROUNDS) {
		char msg[64];
		int n = snprintf(msg, sizeof(msg), "PING %d from agent2", ++send_count2);
		printf("[2] >>> SEND: \"%s\" (%d bytes)\n", msg, n);
		stice_send(agent, msg, (size_t)n);
	}
}

// Default log handler: print to stdout with level prefix.
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

int main(int argc, char **argv) {
	stice_set_log_level(STICE_LOG_LEVEL_INFO);
	stice_set_log_handler(default_log_handler);

	const char *transport_str = argc > 1 ? argv[1] : "tcp";
	stice_turn_transport_t transport = parse_transport(transport_str);
	const char *turn_host = argc > 2 ? argv[2] : "192.168.3.223";
	uint16_t turn_port = argc > 3 ? (uint16_t)atoi(argv[3]) : 3478;
	const char *turn_user = argc > 4 ? argv[4] : "testuser";
	const char *turn_pass = argc > 5 ? argv[5] : "123456";

	printf("=== TURN over %s connectivity test ===\n", transport_name(transport));
	printf("TURN server: %s:%u  user=%s\n", turn_host, turn_port, turn_user);
	printf("Bidirectional exchange rounds: %d (per agent)\n", EXCHANGE_ROUNDS);

	// TCP/TLS 必须使用 POLL 并发模式
	stice_concurrency_mode_t mode = (transport == STICE_TURN_TRANSPORT_UDP)
	                                    ? STICE_CONCURRENCY_MODE_THREAD
	                                    : STICE_CONCURRENCY_MODE_POLL;

	// Agent 1 配置
	stice_config_t config1;
	memset(&config1, 0, sizeof(config1));
	config1.concurrency_mode = mode;

	stice_turn_server_t turn1;
	memset(&turn1, 0, sizeof(turn1));
	turn1.host = turn_host;
	turn1.port = turn_port;
	turn1.username = turn_user;
	turn1.password = turn_pass;
	turn1.transport = transport;
	config1.turn_servers = &turn1;
	config1.turn_servers_count = 1;

	config1.cb_state_changed = on_state_changed1;
	config1.cb_candidate = on_candidate1;
	config1.cb_gathering_done = on_gathering_done1;
	config1.cb_recv = on_recv1;
	config1.user_ptr = NULL;

	agent1 = stice_create(&config1);

	// Agent 2 配置
	stice_config_t config2;
	memset(&config2, 0, sizeof(config2));
	config2.concurrency_mode = mode;

	stice_turn_server_t turn2;
	memset(&turn2, 0, sizeof(turn2));
	turn2.host = turn_host;
	turn2.port = turn_port;
	turn2.username = turn_user;
	turn2.password = turn_pass;
	turn2.transport = transport;
	config2.turn_servers = &turn2;
	config2.turn_servers_count = 1;

	config2.cb_state_changed = on_state_changed2;
	config2.cb_candidate = on_candidate2;
	config2.cb_gathering_done = on_gathering_done2;
	config2.cb_recv = on_recv2;
	config2.user_ptr = NULL;

	agent2 = stice_create(&config2);

	// 交换 SDP
	char sdp1[STICE_MAX_SDP_STRING_LEN];
	stice_get_local_description(agent1, sdp1, STICE_MAX_SDP_STRING_LEN);
	printf("\n--- Agent 1 SDP ---\n%s\n", sdp1);
	stice_set_remote_description(agent2, sdp1);

	char sdp2[STICE_MAX_SDP_STRING_LEN];
	stice_get_local_description(agent2, sdp2, STICE_MAX_SDP_STRING_LEN);
	printf("\n--- Agent 2 SDP ---\n%s\n", sdp2);
	stice_set_remote_description(agent1, sdp2);

	// 开始收集候选
	stice_gather_candidates(agent1);
	stice_gather_candidates(agent2);

	// 等待 ICE 完成 + 双向数据交换完成（最多 30 秒）
	printf("\nWaiting for ICE to complete and bidirectional data exchange...\n");
	int waited = 0;
	while (waited < 30000) {
		// 判定退出条件：双方已连接且交换轮数完成（双方各收到 EXCHANGE_ROUNDS 条）
		int exchange_done = (recv_count1 >= EXCHANGE_ROUNDS) && (recv_count2 >= EXCHANGE_ROUNDS);
		if ((state1 < 0 || state2 < 0) ||
		    (state1 > 0 && state2 > 0 && exchange_done))
			break;
		sleep_ms(100);
		waited += 100;
	}

	// 结果判定
	bool exchange_done = (recv_count1 >= EXCHANGE_ROUNDS) && (recv_count2 >= EXCHANGE_ROUNDS);
	bool success = (state1 > 0 && state2 > 0 && recv1 && recv2 && exchange_done);

	// 输出选中的候选
	char local_c[STICE_MAX_CANDIDATE_SDP_STRING_LEN];
	char remote_c[STICE_MAX_CANDIDATE_SDP_STRING_LEN];
	if (stice_get_selected_candidates(agent1, local_c, STICE_MAX_CANDIDATE_SDP_STRING_LEN,
	                                  remote_c, STICE_MAX_CANDIDATE_SDP_STRING_LEN) == 0) {
		printf("\nAgent1 local  candidate: %s", local_c);
		printf("Agent1 remote candidate: %s", remote_c);
		if (strstr(local_c, "relay"))
			printf("  -> Agent1 is using a TURN relay candidate\n");
	}
	if (stice_get_selected_candidates(agent2, local_c, STICE_MAX_CANDIDATE_SDP_STRING_LEN,
	                                  remote_c, STICE_MAX_CANDIDATE_SDP_STRING_LEN) == 0) {
		printf("Agent2 local  candidate: %s", local_c);
		printf("Agent2 remote candidate: %s", remote_c);
		if (strstr(local_c, "relay"))
			printf("  -> Agent2 is using a TURN relay candidate\n");
	}

	// 打印双向交换统计
	printf("\n--- Bidirectional exchange summary ---\n");
	printf("Agent1: sent=%d, received=%d\n", send_count1, recv_count1);
	printf("Agent2: sent=%d, received=%d\n", send_count2, recv_count2);

	stice_destroy(agent1);
	stice_destroy(agent2);

	printf("\n=== Test %s (waited %d ms) ===\n", success ? "SUCCESS" : "FAILURE", waited);
	return success ? 0 : -1;
}
