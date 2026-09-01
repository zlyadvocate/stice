// libjuice dual-agent benchmark against coturn server.
// Both agents obtain a TURN allocation, then only relay candidates are
// exchanged (forcing the coturn relay path), then measures throughput/loss
// with a fixed window - no pacing, no AIMD, no echo reentrancy.
//
// usage: test_libjuice_bench.exe <host> <port> <user> <pass> [duration] [pkt_size] [window]

#include "juice/juice.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#define Sleep(x) usleep((x) * 1000)
#define GetTickCount() (0) /* not used on non-windows */
#endif

#define BUFFER_SIZE 4096
#define MAX_CANDIDATES 32

typedef struct {
    juice_agent_t *agent;
    volatile int connected;
    volatile int gathering_done;
    char candidates[MAX_CANDIDATES][512];
    int candidates_count;
} AgentCtx;

static AgentCtx ctx_a, ctx_b;
// B receives A's data stream
static volatile long long g_recv_count_b;
static volatile long long g_recv_bytes_b;

static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
    AgentCtx *c = (AgentCtx *)user_ptr;
    if (state == JUICE_STATE_CONNECTED || state == JUICE_STATE_COMPLETED) {
        c->connected = 1;
    }
}

static void on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
    AgentCtx *c = (AgentCtx *)user_ptr;
    // Only collect candidates; batch-forward relay candidates after gathering.
    if (c->candidates_count < MAX_CANDIDATES) {
        snprintf(c->candidates[c->candidates_count], 512, "%s", sdp);
        c->candidates_count++;
    }
}

static void on_gathering_done(juice_agent_t *agent, void *user_ptr) {
    ((AgentCtx *)user_ptr)->gathering_done = 1;
}

static void on_recv_b(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
    g_recv_count_b++;
    g_recv_bytes_b += (long long)size;
}

static void swap_relay_candidates(AgentCtx *c1, AgentCtx *c2) {
    for (int i = 0; i < c1->candidates_count; i++) {
        if (strstr(c1->candidates[i], "typ relay") != NULL) {
            juice_add_remote_candidate(c2->agent, c1->candidates[i]);
        }
    }
    for (int i = 0; i < c2->candidates_count; i++) {
        if (strstr(c2->candidates[i], "typ relay") != NULL) {
            juice_add_remote_candidate(c1->agent, c2->candidates[i]);
        }
    }
}

static bool wait_for(volatile int *flag, int timeout_ms) {
    int waited = 0;
    while (waited < timeout_ms) {
        if (*flag) return true;
        Sleep(10);
        waited += 10;
    }
    return false;
}

int main(int argc, char **argv) {
    const char *turn_host = "192.168.3.223";
    int turn_port = 3478;
    const char *username = "testuser";
    const char *password = "123456";
    int test_duration_sec = 5;
    int pkt_size = 1200;
    int window = 32;

    if (argc > 1) turn_host = argv[1];
    if (argc > 2) turn_port = atoi(argv[2]);
    if (argc > 3) username = argv[3];
    if (argc > 4) password = argv[4];
    if (argc > 5) test_duration_sec = atoi(argv[5]);
    if (argc > 6) pkt_size = atoi(argv[6]);
    if (argc > 7) window = atoi(argv[7]);

    printf("=== libjuice dual-agent relay bench: %s:%d ===\n", turn_host, turn_port);
    printf("user=%s, duration=%ds, pkt_size=%d, window=%d\n",
           username, test_duration_sec, pkt_size, window);

    juice_set_log_level(JUICE_LOG_LEVEL_WARN);

    // Configure TURN server (same server instance used by both agents)
    juice_turn_server_t turn_server;
    memset(&turn_server, 0, sizeof(turn_server));
    turn_server.host = turn_host;
    turn_server.port = turn_port;
    turn_server.username = username;
    turn_server.password = password;

    memset(&ctx_a, 0, sizeof(ctx_a));
    memset(&ctx_b, 0, sizeof(ctx_b));

    // Agent A config
    juice_config_t config_a;
    memset(&config_a, 0, sizeof(config_a));
    config_a.stun_server_host = turn_host;
    config_a.stun_server_port = turn_port;
    config_a.turn_servers = &turn_server;
    config_a.turn_servers_count = 1;
    config_a.cb_state_changed = on_state_changed;
    config_a.cb_candidate = on_candidate;
    config_a.cb_gathering_done = on_gathering_done;
    config_a.user_ptr = &ctx_a;
    // A is the pure sender here; no recv callback needed.

    // Agent B config
    juice_config_t config_b;
    memset(&config_b, 0, sizeof(config_b));
    config_b.stun_server_host = turn_host;
    config_b.stun_server_port = turn_port;
    config_b.turn_servers = &turn_server;
    config_b.turn_servers_count = 1;
    config_b.cb_state_changed = on_state_changed;
    config_b.cb_candidate = on_candidate;
    config_b.cb_gathering_done = on_gathering_done;
    config_b.cb_recv = on_recv_b;
    config_b.user_ptr = &ctx_b;

    ctx_a.agent = juice_create(&config_a);
    ctx_b.agent = juice_create(&config_b);
    if (!ctx_a.agent || !ctx_b.agent) {
        printf("FAIL: juice_create failed\n");
        return 1;
    }

    // Exchange local descriptions
    char sdp_a[BUFFER_SIZE], sdp_b[BUFFER_SIZE];
    juice_get_local_description(ctx_a.agent, sdp_a, sizeof(sdp_a));
    juice_get_local_description(ctx_b.agent, sdp_b, sizeof(sdp_b));
    juice_set_remote_description(ctx_a.agent, sdp_b);
    juice_set_remote_description(ctx_b.agent, sdp_a);

    // Start gathering
    juice_gather_candidates(ctx_a.agent);
    juice_gather_candidates(ctx_b.agent);

    // Wait for both to finish gathering, then batch-forward relay candidates.
    if (!(wait_for(&ctx_a.gathering_done, 15000) && wait_for(&ctx_b.gathering_done, 15000))) {
        printf("FAIL: gathering timeout\n");
        juice_destroy(ctx_a.agent);
        juice_destroy(ctx_b.agent);
        return 1;
    }
    swap_relay_candidates(&ctx_a, &ctx_b);

    // Wait for relay connectivity (both must be connected)
    if (!(wait_for(&ctx_a.connected, 15000) && wait_for(&ctx_b.connected, 15000))) {
        printf("FAIL: connection timeout\n");
        juice_destroy(ctx_a.agent);
        juice_destroy(ctx_b.agent);
        return 1;
    }

    printf("[Connected! Measuring RTT...]\n");

    // RTT probe: A->B ping, wait for receive. Doubles as a send sanity check.
    int rtt_samples = 64;
    long long rtt_sum_ms = 0;
    char ping[64];
    memset(ping, 'p', sizeof(ping));
    long long rcnt0 = g_recv_count_b;
    for (int i = 0; i < rtt_samples; i++) {
        unsigned t0 = GetTickCount();
        juice_send(ctx_a.agent, ping, sizeof(ping));
        // Wait for this ping to arrive
        int wait = 0;
        while (g_recv_count_b - rcnt0 < i + 1 && wait < 2000) { Sleep(1); wait++; }
        if (wait >= 2000) { printf("  RTT probe %d timeout\n", i); break; }
        rtt_sum_ms += (long long)(GetTickCount() - t0);
    }
    double rtt_ms = (double)rtt_sum_ms / rtt_samples;
    printf("[RTT=%.2fms] Starting bandwidth test...\n", rtt_ms);

    char *payload = (char *)malloc(pkt_size);
    memset(payload, 'X', pkt_size);

    long long sent = 0;
    long long recvd0 = g_recv_count_b;
    unsigned int start_time = GetTickCount();
    int no_progress_loops = 0;

    while (GetTickCount() - start_time < (unsigned)test_duration_sec * 1000) {
        long long recvd = g_recv_count_b - recvd0;
        long long inflight = sent - recvd;

        if (inflight < window) {
            if (juice_send(ctx_a.agent, payload, pkt_size) >= 0) {
                sent++;
                no_progress_loops = 0;
            }
        } else {
            no_progress_loops++;
            // safety: no recv progress over ~2s with an open window => deadlock
            if (no_progress_loops > 200) break;
            Sleep(1);
        }
    }

    // Active-phase throughput (stop clock immediately at loop exit, before drain)
    unsigned int active_ms = GetTickCount() - start_time;

    // Drain remaining in-flight packets
    int drain_waits = 0;
    while (g_recv_count_b - recvd0 < sent && drain_waits < 500) {
        Sleep(10);
        drain_waits++;
    }

    long long recvd = g_recv_count_b - recvd0;
    long long lost = sent - recvd;
    double elapsed = active_ms / 1000.0;
    // Wire rate over the whole active send window (includes in-flight at cutoff)
    double send_mbps = elapsed > 0 ? (sent * pkt_size * 8.0) / elapsed / 1e6 : 0;
    double goodput_mbps = elapsed > 0 ? (recvd * pkt_size * 8.0) / elapsed / 1e6 : 0;

    printf("\n=== RESULTS ===\n");
    printf("RTT=%.2f ms, sent=%lld received=%lld lost=%lld (%.2f%%)\n",
           rtt_ms, sent, recvd, lost, sent > 0 ? 100.0 * lost / sent : 0);
    printf("send_rate=%.2f Mbps, goodput=%.2f Mbps (active_elapsed=%.3fs)\n",
           send_mbps, goodput_mbps, elapsed);

    juice_destroy(ctx_a.agent);
    juice_destroy(ctx_b.agent);
    free(payload);

    printf("\n=== %s ===\n", lost == 0 ? "PASS" : "FAIL");
    return lost == 0 ? 0 : 1;
}