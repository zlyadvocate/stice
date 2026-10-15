// SPDX-License-Identifier: MPL-2.0
// stice platform socket abstractions. Ported from libjuice's socket.h.

#ifndef STICE_NET_PLATFORM_HPP
#define STICE_NET_PLATFORM_HPP

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
using socket_t = SOCKET;
using nfds_t = ULONG;
#define STICE_INVALID_SOCKET INVALID_SOCKET
// sticePoll is backed by wepoll (IOCP-based, more reliable than WSAPoll) on
// Windows. Implemented in src/net/wepoll_poll.cpp.
int sticePoll(struct pollfd *fds, nfds_t nfds, int timeout);
#define sticeClosesocket closesocket
#define sticeSockerrno ((int)WSAGetLastError())
#define STICE_SEWOULDBLOCK WSAEWOULDBLOCK
#define STICE_SEINPROGRESS WSAEINPROGRESS
#define STICE_SECONNRESET WSAECONNRESET
#define STICE_SECONNREFUSED WSAECONNREFUSED
#define STICE_SENETRESET WSAENETRESET
#define STICE_SEMSGSIZE WSAEMSGSIZE
#define STICE_SEAGAIN WSAEWOULDBLOCK
#define STICE_SEINTR WSAEINTR
#define STICE_SENOBUFS WSAENOBUFS
#define STICE_SEADDRINUSE WSAEADDRINUSE
#define STICE_SEACCES WSAEACCES
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <ifaddrs.h>
using socket_t = int;
using nfds_t = nfds_t;
#define STICE_INVALID_SOCKET (-1)
#ifdef __linux__
// sticePoll is backed by the native epoll(7) API on Linux (implemented in
// src/net/epoll_poll.cpp): the synchronous one-shot waits (e.g. the
// server-reflexive STUN resolution in stun/client.cpp) then use the same
// readiness model as the PollRegistry event loop and the Windows wepoll
// backend. Other POSIX platforms (macOS/BSD) keep poll(2).
int sticePoll(struct pollfd *fds, nfds_t nfds, int timeout);
#else
#define sticePoll poll
#endif
#define sticeClosesocket ::close
#define sticeSockerrno errno
#define STICE_SEWOULDBLOCK EWOULDBLOCK
#define STICE_SEINPROGRESS EINPROGRESS
#define STICE_SECONNRESET ECONNRESET
#define STICE_SECONNREFUSED ECONNREFUSED
#define STICE_SENETRESET ENETRESET
#define STICE_SEMSGSIZE EMSGSIZE
#define STICE_SEAGAIN EAGAIN
#define STICE_SEINTR EINTR
#define STICE_SENOBUFS ENOBUFS
#define STICE_SEADDRINUSE EADDRINUSE
#define STICE_SEACCES EACCES
#endif

namespace stice::net {
inline bool wouldBlock() {
	return sticeSockerrno == STICE_SEWOULDBLOCK || sticeSockerrno == STICE_SEAGAIN;
}

// Portable non-blocking mode. Windows: ioctlsocket(FIONBIO); POSIX: fcntl(O_NONBLOCK).
inline bool setNonBlocking(socket_t s) {
#ifdef _WIN32
	u_long nbio = 1;
	return ioctlsocket(s, FIONBIO, &nbio) == 0;
#else
	int flags = ::fcntl(s, F_GETFL, 0);
	if (flags < 0) return false;
	return ::fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}
} // namespace stice::net

#endif
