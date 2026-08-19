/**
 * Copyright (c) 2024 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "stice/stice.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int test_ufrag() {
	stice_agent_t *agent;
	bool success = true;
	int ret;

	stice_set_log_level(STICE_LOG_LEVEL_DEBUG);

	// Create agent
	stice_config_t config;
	memset(&config, 0, sizeof(config));

	agent = stice_create(&config);

	if (stice_set_local_ice_attributes(agent, NULL, NULL) != STICE_ERR_INVALID)
		success = false;

	if (stice_set_local_ice_attributes(agent, "ufrag", NULL) != STICE_ERR_INVALID)
		success = false;

	if (stice_set_local_ice_attributes(agent, NULL, "pw01234567890123456789") != STICE_ERR_INVALID)
		success = false;

	if (stice_set_local_ice_attributes(agent, "ufrag", "pw0123456789012345678") != STICE_ERR_INVALID)
		success = false;

	if (stice_set_local_ice_attributes(agent, "usr", "pw01234567890123456789") != STICE_ERR_INVALID)
		success = false;

	if (stice_set_local_ice_attributes(agent, "ufrag:", "pw01234567890123456789") != STICE_ERR_INVALID)
		success = false;

	if (stice_set_local_ice_attributes(agent, "ufrag", "pw0123456789012345678?") != STICE_ERR_INVALID)
		success = false;

	// Set local ICE attributes
	stice_set_local_ice_attributes(agent, "ufrag", "pw01234567890123456789");

	// Generate local description
	char sdp[STICE_MAX_SDP_STRING_LEN];
	stice_get_local_description(agent, sdp, STICE_MAX_SDP_STRING_LEN);
	printf("Local description:\n%s\n", sdp);

	if (strstr(sdp, "a=ice-ufrag:ufrag\r\n") == NULL)
		success = false;

	if (strstr(sdp, "a=ice-pwd:pw01234567890123456789\r\n") == NULL)
		success = false;

	// Destroy
	stice_destroy(agent);

	if (success) {
		printf("Success\n");
		return 0;
	} else {
		printf("Failure\n");
		return -1;
	}
}
