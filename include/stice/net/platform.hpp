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
#define sticePoll WSAPoll
#define sticeClosesocket closesocket
#define sticeSockerrno ((int)WSAGetLastError())
#define STICE_SEWOULDBLOCK WSAEWOULDBLOCK
#define STICE_SEINPROGRESS WSAEINPROGRESS
#define STICE_SECONNRESET WSAECONNRESET
#define STICE_SEMSGSIZE WSAEMSGSIZE
#define STICE_SEAGAIN WSAEWOULDBLOCK
#define STICE_SEINTR WSAEINTR
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
#define sticePoll poll
#define sticeClosesocket close
#define sticeSockerrno errno
#define STICE_SEWOULDBLOCK EWOULDBLOCK
#define STICE_SEINPROGRESS EINPROGRESS
#define STICE_SECONNRESET ECONNRESET
#define STICE_SEMSGSIZE EMSGSIZE
#define STICE_SEAGAIN EAGAIN
#define STICE_SEINTR EINTR
#endif

namespace stice::net {
inline bool wouldBlock() {
	return sticeSockerrno == STICE_SEWOULDBLOCK || sticeSockerrno == STICE_SEAGAIN;
}
} // namespace stice::net

#endif
