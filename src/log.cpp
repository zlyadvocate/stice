/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
#include "stice/log.hpp"

#include <cstdio>

namespace stice {

Logger &Logger::instance() {
	static Logger inst;
	return inst;
}

void Logger::setLevel(stice_log_level_t level) {
	// Relaxed store: level is set once at startup (before worker threads run);
	// shouldLog() reads it lock-free on every hot-path call site.
	level_.store(static_cast<int>(level), std::memory_order_relaxed);
}

void Logger::setHandler(stice_log_cb_t cb) {
	std::lock_guard<std::mutex> lock(mutex_);
	cb_ = cb;
}

void Logger::log(stice_log_level_t level, const char *fmt, ...) {
	// Fast lock-free rejection (callers normally guard via shouldLog(), this
	// covers direct callers and keeps the common disabled case lock-free).
	if (!shouldLog(level))
		return;
	stice_log_cb_t cb;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		cb = cb_;
	}
	if (!cb)
		return; // no handler installed: silent by default

	char buf[1024];
	va_list args;
	va_start(args, fmt);
	std::vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	cb(level, buf);
}

} // namespace stice
