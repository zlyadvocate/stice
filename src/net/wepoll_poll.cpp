// SPDX-License-Identifier: MPL-2.0
// Windows-only replacement for WSAPoll, backed by wepoll
// (https://github.com/piscisaureus/wepoll, IOCP-based epoll for Windows).
//
// WSAPoll is unreliable under high concurrency / repeated socket churn: it can
// intermittently fail to report readability on a registered socket (observed
// as TURN Allocate responses arriving but never dispatched). wepoll is built
// on IOCP and is deterministic about reporting events.
//
// This free function serves callers that do a one-shot poll() on a small fd set
// (e.g. the synchronous server-reflexive STUN wait in stun/client.cpp). A fresh
// epoll handle is created per call so a socket is never re-registered on the
// same handle (wepoll returns EEXIST if you ADD the same socket twice without
// DEL, and does not support rapid ADD/DEL churn). The PollRegistry hot path
// does NOT use this function; it uses its own persistent wepoll registration.

#ifdef _WIN32

#include "stice/net/platform.hpp"
#include <winsock2.h>

#include "wepoll/wepoll.h"
#include <cstdint>
#include <vector>

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

// Free function (replaces the WSAPoll macro). poll() semantics on Windows,
// backed by wepoll. Returns number of fds with non-zero revents, 0 on timeout,
// or -1 with sticeSockerrno set on failure.
int sticePoll(struct pollfd *fds, nfds_t nfds, int timeout) {
	if (nfds == 0) {
		if (timeout > 0) Sleep(static_cast<DWORD>(timeout));
		return 0;
	}

	HANDLE eph = epoll_create(static_cast<int>(nfds) + 1);
	if (!eph) {
		WSASetLastError(WSAEINVAL);
		return -1;
	}

	std::vector<bool> registered(nfds, false);
	int ready = 0;

	for (nfds_t i = 0; i < nfds; ++i) {
		pollfd &p = fds[i];
		p.revents = 0;
		if (static_cast<int>(p.fd) < 0) continue; // ignored fd
		struct epoll_event ee{};
		if (p.events & POLLIN) ee.events |= EPOLLIN;
		if (p.events & POLLOUT) ee.events |= EPOLLOUT;
		if (p.events & POLLERR) ee.events |= EPOLLERR;
		if (p.events & POLLHUP) ee.events |= EPOLLHUP;
		if (ee.events == 0) continue;
		ee.data.u32 = static_cast<std::uint32_t>(i);
		if (epoll_ctl(eph, EPOLL_CTL_ADD, p.fd, &ee) != 0) {
			p.revents = POLLNVAL;
			++ready;
			continue;
		}
		registered[i] = true;
	}

	if (ready == 0 && timeout != 0) {
		std::vector<struct epoll_event> out(nfds);
		int n = epoll_wait(eph, out.data(), static_cast<int>(nfds), timeout);
		if (n > 0) {
			for (int k = 0; k < n; ++k) {
				std::uint32_t idx = out[k].data.u32;
				if (idx < nfds) {
					fds[idx].revents |= stice::net::mapToPollEvents(out[k].events);
					++ready;
				}
			}
		} else if (n < 0) {
			int err = WSAGetLastError();
			for (nfds_t i = 0; i < nfds; ++i)
				if (registered[i]) epoll_ctl(eph, EPOLL_CTL_DEL, fds[i].fd, nullptr);
			epoll_close(eph);
			WSASetLastError(err);
			return -1;
		}
	}

	for (nfds_t i = 0; i < nfds; ++i)
		if (registered[i]) epoll_ctl(eph, EPOLL_CTL_DEL, fds[i].fd, nullptr);
	epoll_close(eph);

	return ready;
}

#endif // _WIN32
