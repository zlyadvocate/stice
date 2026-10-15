// SPDX-License-Identifier: MPL-2.0
// Linux-only epoll(7)-backed replacement for poll(2).
//
// On Windows the same one-shot wait is served by wepoll
// (src/net/wepoll_poll.cpp, IOCP-based). Backing the Linux version with the
// native epoll API keeps the synchronous waits — the server-reflexive STUN
// resolution in stun/client.cpp and a few tests — on the same readiness model
// as the PollRegistry event loop (src/net/poll.cpp), instead of falling back
// to poll(2).
//
// A fresh epoll fd is created per call, so a socket is never re-registered on
// the same handle across calls. Registration is level-triggered, matching
// poll(2): an fd that is still readable is reported again on the next call.

#ifdef __linux__

#include "stice/net/platform.hpp"

#include <cerrno>
#include <cstdint>
#include <vector>

#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

namespace stice::net {
static short mapToPollEvents(std::uint32_t ev) {
	short r = 0;
	if (ev & EPOLLIN) r |= POLLIN;
	if (ev & EPOLLOUT) r |= POLLOUT;
	if (ev & EPOLLERR) r |= POLLERR;
	if (ev & EPOLLHUP) r |= POLLHUP;
	return r;
}
} // namespace stice::net

// poll() semantics, backed by epoll(7). Returns the number of fds with
// non-zero revents, 0 on timeout, or -1 with errno set on failure.
int sticePoll(struct pollfd *fds, nfds_t nfds, int timeout) {
	if (nfds == 0) {
		if (timeout > 0) {
			struct timespec ts;
			ts.tv_sec = timeout / 1000;
			ts.tv_nsec = static_cast<long>(timeout % 1000) * 1000000L;
			nanosleep(&ts, nullptr);
		}
		return 0;
	}

	int eph = ::epoll_create1(EPOLL_CLOEXEC);
	if (eph < 0) return -1;

	std::vector<bool> registered(nfds, false);
	int ready = 0;

	for (nfds_t i = 0; i < nfds; ++i) {
		pollfd &p = fds[i];
		p.revents = 0;
		if (p.fd < 0) continue; // negative fd: ignored, as in poll(2)
		struct epoll_event ee{};
		if (p.events & POLLIN) ee.events |= EPOLLIN;
		if (p.events & POLLOUT) ee.events |= EPOLLOUT;
		if (p.events & POLLERR) ee.events |= EPOLLERR;
		if (p.events & POLLHUP) ee.events |= EPOLLHUP;
		if (ee.events == 0) continue;
		ee.data.u32 = static_cast<std::uint32_t>(i);
		if (::epoll_ctl(eph, EPOLL_CTL_ADD, p.fd, &ee) != 0) {
			// A duplicate fd within the same array (EEXIST) is still valid
			// poll() input; update the interest instead of failing it.
			if (errno == EEXIST &&
			    ::epoll_ctl(eph, EPOLL_CTL_MOD, p.fd, &ee) == 0) {
				registered[i] = true;
				continue;
			}
			p.revents = POLLNVAL;
			++ready;
			continue;
		}
		registered[i] = true;
	}

	if (ready == 0 && timeout != 0) {
		std::vector<struct epoll_event> out(nfds);
		int n = ::epoll_wait(eph, out.data(), static_cast<int>(nfds), timeout);
		if (n > 0) {
			for (int k = 0; k < n; ++k) {
				std::uint32_t idx = out[k].data.u32;
				if (idx < nfds) {
					fds[idx].revents |= stice::net::mapToPollEvents(out[k].events);
					++ready;
				}
			}
		} else if (n < 0) {
			int err = errno;
			for (nfds_t i = 0; i < nfds; ++i)
				if (registered[i]) ::epoll_ctl(eph, EPOLL_CTL_DEL, fds[i].fd, nullptr);
			::close(eph);
			errno = err;
			return -1;
		}
	}

	for (nfds_t i = 0; i < nfds; ++i)
		if (registered[i]) ::epoll_ctl(eph, EPOLL_CTL_DEL, fds[i].fd, nullptr);
	::close(eph);

	return ready;
}

#endif // __linux__
