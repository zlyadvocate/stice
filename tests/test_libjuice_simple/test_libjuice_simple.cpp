// Simple libjuice test against coturn
#include "juice/juice.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#define Sleep(x) usleep((x) * 1000)
#endif

static int connected = 0;
static int gathering_done = 0;
static int recv_count = 0;

static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
    printf("State: %s\n", juice_state_to_string(state));
    if (state == JUICE_STATE_CONNECTED) {
        connected = 1;
    }
}

static void on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
    printf("Candidate: %s\n", sdp);
}

static void on_gathering_done(juice_agent_t *agent, void *user_ptr) {
    printf("Gathering done\n");
    gathering_done = 1;
}

static void on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
    recv_count++;
    if (recv_count <= 5) {
        printf("Received %zu bytes\n", size);
    }
}

int main(int argc, char **argv) {
    const char *turn_host = "192.168.3.223";
    int turn_port = 3478;
    const char *username = "testuser";
    const char *password = "123456";
    int test_duration = 5; // seconds

    if (argc > 1) turn_host = argv[1];
    if (argc > 2) turn_port = atoi(argv[2]);
    if (argc > 3) username = argv[3];
    if (argc > 4) password = argv[4];
    if (argc > 5) test_duration = atoi(argv[5]);

    printf("Testing libjuice with coturn at %s:%d\n", turn_host, turn_port);
    printf("Username: %s, Password: %s\n", username, password);

    juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

    // Create agent 1
    juice_config_t config1;
    memset(&config1, 0, sizeof(config1));
    config1.stun_server_host = turn_host;
    config1.stun_server_port = turn_port;

    juice_turn_server_t turn_server1;
    memset(&turn_server1, 0, sizeof(turn_server1));
    turn_server1.host = turn_host;
    turn_server1.port = turn_port;
    turn_server1.username = username;
    turn_server1.password = password;
    config1.turn_servers = &turn_server1;
    config1.turn_servers_count = 1;

    config1.cb_state_changed = on_state_changed;
    config1.cb_candidate = on_candidate;
    config1.cb_gathering_done = on_gathering_done;
    config1.cb_recv = on_recv;

    juice_agent_t *agent1 = juice_create(&config1);
    if (!agent1) {
        printf("Failed to create agent1\n");
        return 1;
    }

    // Get local description
    char sdp1[4096];
    juice_get_local_description(agent1, sdp1, sizeof(sdp1));
    printf("\nLocal description (agent1):\n%s\n", sdp1);

    // Wait for gathering
    int timeout = 10;
    while (!gathering_done && timeout > 0) {
        Sleep(100);
        timeout--;
    }

    if (!gathering_done) {
        printf("Gathering timeout\n");
        juice_destroy(agent1);
        return 1;
    }

    // Wait for connection (in real scenario, we'd exchange SDP with peer)
    printf("\nWaiting for connection...\n");
    timeout = 10;
    while (!connected && timeout > 0) {
        Sleep(100);
        timeout--;
    }

    if (connected) {
        printf("Connected!\n");

        // Send some test data
        printf("\nSending test data for %d seconds...\n", test_duration);
        char data[1200];
        memset(data, 'A', sizeof(data));

        int sent = 0;
        int start_time = GetTickCount();
        while (GetTickCount() - start_time < test_duration * 1000) {
            juice_send(agent1, data, sizeof(data));
            sent++;
            Sleep(10); // 100 packets per second
        }

        printf("Sent %d packets\n", sent);
        printf("Received %d packets\n", recv_count);
    } else {
        printf("Connection timeout (expected - need peer to exchange SDP)\n");
    }

    juice_destroy(agent1);
    printf("\nTest completed\n");
    return 0;
}
