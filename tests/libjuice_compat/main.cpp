/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "stice/stice.h"

#include <stdio.h>

int test_connectivity(void);
int test_thread(void);
int test_mux(void);
int test_notrickle(void);
int test_gathering(void);
int test_turn(void);
int test_conflict(void);
int test_bind(void);
int test_ufrag(void);

int main(int argc, char **argv) {
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	fprintf(stderr, "=== test_libjuice_compat starting ===\n");
	stice_set_log_level(STICE_LOG_LEVEL_WARN);

	printf("\nRunning candidates gathering test...\n");
	if (test_gathering()) {
		fprintf(stderr, "Candidates gathering test failed\n");
		return -1;
	}

	printf("\nRunning connectivity test...\n");
	if (test_connectivity()) {
		fprintf(stderr, "Connectivity test failed\n");
		return -1;
	}

// Disabled as the Open Relay TURN server is unreliable
/*
	printf("\nRunning TURN connectivity test...\n");
	if (test_turn()) {
		fprintf(stderr, "TURN connectivity test failed\n");
		return -1;
	}
*/
	printf("\nRunning thread-mode connectivity test...\n");
	if (test_thread()) {
		fprintf(stderr, "Thread-mode connectivity test failed\n");
		return -1;
	}

	printf("\nRunning mux-mode connectivity test...\n");
	if (test_mux()) {
		fprintf(stderr, "Mux-mode connectivity test failed\n");
		return -1;
	}

	printf("\nRunning non-trickled connectivity test...\n");
	if (test_notrickle()) {
		fprintf(stderr, "Non-trickled connectivity test failed\n");
		return -1;
	}

	printf("\nRunning connectivity test with role conflict...\n");
	if (test_conflict()) {
		fprintf(stderr, "Connectivity test with role conflict failed\n");
		return -1;
	}

	printf("\nRunning connectivity test with bind address...\n");
	if (test_bind()) {
		fprintf(stderr, "Connectivity test with bind address failed\n");
		return -1;
	}

	printf("\nRunning ufrag test...\n");
	if (test_ufrag()) {
		fprintf(stderr, "Ufrag test failed\n");
		return -1;
	}

	return 0;
}
