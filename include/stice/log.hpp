// SPDX-License-Identifier: MPL-2.0
// stice leveled logging. A user may install a callback via stice_set_log_handler;
// otherwise messages go nowhere.

#ifndef STICE_LOG_HPP
#define STICE_LOG_HPP

#include "stice.h"
#include <atomic>
#include <cstdarg>
#include <mutex>
#include <string>

namespace stice {

class Logger {
public:
	static Logger &instance();

	void setLevel(stice_log_level_t level);
	void setHandler(stice_log_cb_t cb);

	// Cheap, lock-free level test. Hot-path call sites (relay data plane, ICE
	// send/recv) guard on this so that expensive argument expressions - most
	// notably AddrRecord::toString(), which performs getnameinfo() + std::string
	// allocation - are NOT evaluated when the message is below the configured
	// level. Previously every STICE_LOG_* argument was constructed unconditionally
	// because the level check lived inside log(): at the default WARN level that
	// added two getnameinfo() calls per relayed datagram, throttling the stserver
	// UDP relay to ~70 MB/s and dropping ~9% of packets under 100-way load.
	bool shouldLog(stice_log_level_t level) const {
		return static_cast<int>(level) >= level_.load(std::memory_order_relaxed);
	}

	void log(stice_log_level_t level, const char *fmt, ...);

private:
	Logger() = default;
	std::mutex mutex_;
	std::atomic<int> level_{static_cast<int>(STICE_LOG_LEVEL_NONE)};
	stice_log_cb_t cb_ = nullptr;
};

} // namespace stice

// Lazy: the format arguments are only evaluated when the level is enabled.
#define STICE_LOG(level, ...)                                     \
	do {                                                          \
		if (stice::Logger::instance().shouldLog(level))           \
			stice::Logger::instance().log(level, __VA_ARGS__);    \
	} while (0)
#define STICE_LOG_VERBOSE(...) STICE_LOG(STICE_LOG_LEVEL_VERBOSE, __VA_ARGS__)
#define STICE_LOG_DEBUG(...) STICE_LOG(STICE_LOG_LEVEL_DEBUG, __VA_ARGS__)
#define STICE_LOG_INFO(...) STICE_LOG(STICE_LOG_LEVEL_INFO, __VA_ARGS__)
#define STICE_LOG_WARN(...) STICE_LOG(STICE_LOG_LEVEL_WARN, __VA_ARGS__)
#define STICE_LOG_ERROR(...) STICE_LOG(STICE_LOG_LEVEL_ERROR, __VA_ARGS__)
#define STICE_LOG_FATAL(...) STICE_LOG(STICE_LOG_LEVEL_FATAL, __VA_ARGS__)

#endif
