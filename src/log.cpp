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
	std::lock_guard<std::mutex> lock(mutex_);
	level_ = level;
}

void Logger::setHandler(stice_log_cb_t cb) {
	std::lock_guard<std::mutex> lock(mutex_);
	cb_ = cb;
}

void Logger::log(stice_log_level_t level, const char *fmt, ...) {
	stice_log_cb_t cb;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		if (level < level_)
			return;
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
