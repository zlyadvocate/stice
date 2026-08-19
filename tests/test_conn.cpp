// Standalone STUN connectivity test: verify a dual-stack AF_INET6 socket
// can send to and receive from an IPv4 STUN server.
#include "stice/net/platform.hpp"

#include <cstdio>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

int main() {
#ifdef _WIN32
    WSADATA d;
    WSAStartup(MAKEWORD(2, 2), &d);
#endif

    // Create dual-stack AF_INET6 UDP socket (like stice does).
    socket_t sock = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) { printf("socket failed: %d\n", sticeSockerrno); return 1; }

    // Allow IPv4 mappings.
    int v6only = 0;
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&v6only, sizeof(v6only));

    // Set non-blocking.
#ifdef _WIN32
    u_long nbio = 1;
    ioctlsocket(sock, FIONBIO, &nbio);
#else
    int nbio = 1;
    ioctl(sock, FIONBIO, &nbio);
#endif

    // Bind to any.
    sockaddr_in6 bind6{};
    bind6.sin6_family = AF_INET6;
    bind6.sin6_addr = in6addr_any;
    bind6.sin6_port = 0;
    if (::bind(sock, (sockaddr*)&bind6, sizeof(bind6)) != 0) {
        printf("bind failed: %d\n", sticeSockerrno);
        return 1;
    }

    // Get bound port.
    sockaddr_in6 bound{};
    socklen_t blen = sizeof(bound);
    getsockname(sock, (sockaddr*)&bound, &blen);
    printf("Bound to port %d\n", ntohs(bound.sin6_port));

    // Build STUN Binding Request (20 bytes).
    unsigned char req[20] = {
        0x00, 0x01, 0x00, 0x00,             // Type: Binding Request, Length: 0
        0x21, 0x12, 0xA4, 0x42,             // Magic Cookie
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // TID
    };

    // Send to 192.168.3.223:3478 using IPv4-mapped IPv6.
    sockaddr_in6 dst{};
    dst.sin6_family = AF_INET6;
    dst.sin6_port = htons(3478);
    // ::ffff:192.168.3.223 = ::ffff:C0A8:03DF
    dst.sin6_addr.s6_addr[10] = 0xFF;
    dst.sin6_addr.s6_addr[11] = 0xFF;
    dst.sin6_addr.s6_addr[12] = 192;
    dst.sin6_addr.s6_addr[13] = 168;
    dst.sin6_addr.s6_addr[14] = 3;
    dst.sin6_addr.s6_addr[15] = 223;

    int sent = ::sendto(sock, (const char*)req, sizeof(req), 0, (sockaddr*)&dst, sizeof(dst));
    printf("sendto returned %d\n", sent);

    // Poll for response.
    pollfd pfd{};
    pfd.fd = sock;
    pfd.events = POLLIN;
    int n = sticePoll(&pfd, 1, 3000);
    printf("poll returned %d, revents=0x%x\n", n, pfd.revents);

    if (n > 0 && (pfd.revents & POLLIN)) {
        unsigned char buf[1500];
        sockaddr_storage from{};
        socklen_t fromLen = sizeof(from);
        int len = ::recvfrom(sock, (char*)buf, sizeof(buf), 0, (sockaddr*)&from, &fromLen);
        printf("recvfrom returned %d\n", len);
        if (len > 0) {
            printf("Received %d bytes\n", len);
            printf("First 20 bytes (hex):");
            for (int i = 0; i < 20 && i < len; ++i) printf(" %02X", buf[i]);
            printf("\n");
        }
    } else {
        printf("No response received (timeout or error)\n");
    }

#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif
    return 0;
}
