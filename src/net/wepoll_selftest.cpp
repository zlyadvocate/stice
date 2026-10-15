// wepoll UDP EPOLLIN self-test: create a UDP socket, register with wepoll,
// another thread sends to it, verify epoll_wait wakes with EPOLLIN.
//
// Each cycle uses a FRESH epoll handle, exactly what sticePoll does per call
// (see src/net/wepoll_poll.cpp): wepoll returns ERROR_ALREADY_EXISTS if you ADD
// the same socket twice to ONE handle without a DEL, so a per-call handle is
// mandatory. This test therefore verifies epoll_create -> ADD -> wait -> DEL ->
// epoll_close across repeated poll cycles, i.e. the steady-state pattern that
// the PollRegistry hot path and the STUN srflx wait drive every iteration.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdio>
#include <thread>
#include <chrono>
#include <cstdint>

#include "wepoll/wepoll.h"

int main() {
    WSADATA d; WSAStartup(MAKEWORD(2,2), &d);

    SOCKET s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in bind4{}; bind4.sin_family=AF_INET; bind4.sin_addr.s_addr=htonl(INADDR_LOOPBACK); bind4.sin_port=0;
    ::bind(s, (sockaddr*)&bind4, sizeof(bind4));
    sockaddr_in me{}; int len=sizeof(me); getsockname(s,(sockaddr*)&me,&len);

    int failures = 0;
    for (int cycle = 0; cycle < 3; ++cycle) {
        HANDLE eph = epoll_create(8);
        if (!eph) { printf("CYCLE %d epoll_create FAIL err=%lu\n", cycle, WSAGetLastError()); ++failures; continue; }
        struct epoll_event ev{}; ev.events = EPOLLIN; ev.data.u32 = 0;
        int rc = epoll_ctl(eph, EPOLL_CTL_ADD, s, &ev);
        if (rc != 0) { printf("CYCLE %d ADD FAIL err=%d\n", cycle, WSAGetLastError()); epoll_close(eph); ++failures; continue; }
        std::thread t([&]{
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            ::sendto(s, "X", 1, 0, (sockaddr*)&me, sizeof(me));
        });
        struct epoll_event out[4];
        auto t1 = std::chrono::steady_clock::now();
        int n = epoll_wait(eph, out, 4, 3000);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-t1).count();
        t.join();
        printf("cycle=%d epoll_wait n=%d after=%lldms events=%u\n", cycle, n, (long long)ms, n>0?out[0].events:0);
        epoll_ctl(eph, EPOLL_CTL_DEL, s, nullptr);
        epoll_close(eph);
        if (!(n==1 && (out[0].events & EPOLLIN))) ++failures;
    }
    closesocket(s);
    printf("failures=%d\n", failures);
    return failures==0 ? 0 : 2;
}
