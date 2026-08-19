// SPDX-License-Identifier: MPL-2.0
// Author: zlyadvocate
// Version: 0.10.0
// stserver entry point: load stserver.conf, configure logging, run the TURN
// server event loop until interrupted.

#ifdef _WIN32
#ifndef FD_SETSIZE
#define FD_SETSIZE 8192
#endif
#endif

#ifndef STICE_STATIC
#define STICE_STATIC
#endif

#include "stice/stserver/config.hpp"
#include "stice/stserver/turn_server.hpp"

#include "stice/stice.h"
#include "stice/log.hpp"

#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#endif

static stserver::TurnServer *g_server = nullptr;

#ifdef _WIN32
static BOOL WINAPI consoleHandler(DWORD ctrl) {
	if (ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT || ctrl == CTRL_CLOSE_EVENT) {
		if (g_server) g_server->stop();
		return TRUE;
	}
	return FALSE;
}
#else
static void sigHandler(int) {
	if (g_server) g_server->stop();
}
#endif

static stice_log_level_t parseLogLevel(const std::string &s) {
	if (s == "verbose") return STICE_LOG_LEVEL_VERBOSE;
	if (s == "debug") return STICE_LOG_LEVEL_DEBUG;
	if (s == "info") return STICE_LOG_LEVEL_INFO;
	if (s == "warn") return STICE_LOG_LEVEL_WARN;
	if (s == "error") return STICE_LOG_LEVEL_ERROR;
	if (s == "fatal") return STICE_LOG_LEVEL_FATAL;
	if (s == "none") return STICE_LOG_LEVEL_NONE;
	return STICE_LOG_LEVEL_INFO;
}

// Route stice logs to stderr so the server is observable without a GUI.
static void logHandler(stice_log_level_t level, const char *message) {
	const char *tag = "?";
	switch (level) {
	case STICE_LOG_LEVEL_VERBOSE: tag = "VRB"; break;
	case STICE_LOG_LEVEL_DEBUG:   tag = "DBG"; break;
	case STICE_LOG_LEVEL_INFO:    tag = "INF"; break;
	case STICE_LOG_LEVEL_WARN:    tag = "WRN"; break;
	case STICE_LOG_LEVEL_ERROR:   tag = "ERR"; break;
	case STICE_LOG_LEVEL_FATAL:   tag = "FTL"; break;
	default: break;
	}
	std::fprintf(stderr, "[stserver/%s] %s\n", tag, message ? message : "");
}

int main(int argc, char **argv) {
#ifdef _WIN32
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		std::fprintf(stderr, "stserver: WSAStartup failed\n");
		return 1;
	}
#endif

	std::string confPath = "stserver.conf";
	for (int i = 1; i < argc; ++i) {
		std::string a = argv[i];
		if ((a == "-c" || a == "--config") && i + 1 < argc) {
			confPath = argv[++i];
		} else if (a == "-h" || a == "--help") {
			std::printf("stserver - TURN/STUN server\n"
			            "usage: stserver [-c stserver.conf]\n");
			return 0;
		}
	}

	Config cfg;
	if (!cfg.load(confPath)) {
		std::fprintf(stderr, "stserver: failed to load config %s\n", confPath.c_str());
		return 1;
	}
	stice_set_log_level(parseLogLevel(cfg.logLevel));
	stice_set_log_handler(logHandler);

	stserver::TurnServer server;
	if (!server.init(cfg)) {
		std::fprintf(stderr, "stserver: init failed\n");
		return 1;
	}
	g_server = &server;

#ifdef _WIN32
	SetConsoleCtrlHandler(consoleHandler, TRUE);
#else
	std::signal(SIGINT, sigHandler);
	std::signal(SIGTERM, sigHandler);
#endif

	STICE_LOG_INFO("stserver: running (config=%s)", confPath.c_str());
	server.run();

#ifdef _WIN32
	WSACleanup();
#endif
	return 0;
}
