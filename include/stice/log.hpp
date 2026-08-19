// SPDX-License-Identifier: MPL-2.0
// stice leveled logging. A user may install a callback via stice_set_log_handler;
// otherwise messages go nowhere.

#ifndef STICE_LOG_HPP
#define STICE_LOG_HPP

#include "stice.h"
#include <cstdarg>
#include <mutex>
#include <string>

namespace stice {

class Logger {
public:
	static Logger &instance();

	void setLevel(stice_log_level_t level);
	void setHandler(stice_log_cb_t cb);

	void log(stice_log_level_t level, const char *fmt, ...);

private:
	Logger() = default;
	std::mutex mutex_;
	stice_log_level_t level_ = STICE_LOG_LEVEL_NONE;
	stice_log_cb_t cb_ = nullptr;
};

} // namespace stice

#define STICE_LOG(level, ...) stice::Logger::instance().log(level, __VA_ARGS__)
#define STICE_LOG_VERBOSE(...) STICE_LOG(STICE_LOG_LEVEL_VERBOSE, __VA_ARGS__)
#define STICE_LOG_DEBUG(...) STICE_LOG(STICE_LOG_LEVEL_DEBUG, __VA_ARGS__)
#define STICE_LOG_INFO(...) STICE_LOG(STICE_LOG_LEVEL_INFO, __VA_ARGS__)
#define STICE_LOG_WARN(...) STICE_LOG(STICE_LOG_LEVEL_WARN, __VA_ARGS__)
#define STICE_LOG_ERROR(...) STICE_LOG(STICE_LOG_LEVEL_ERROR, __VA_ARGS__)
#define STICE_LOG_FATAL(...) STICE_LOG(STICE_LOG_LEVEL_FATAL, __VA_ARGS__)

#endif
