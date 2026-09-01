// SPDX-License-Identifier: MPL-2.0
// libjuice compatible API benchmark against coturn server.
// Tests single-client and multi-client scenarios with throughput measurement.

#include "juice/juice.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace std::chrono_literals;

struct AgentState {
    std::atomic<juice_state_t> state{JUICE_STATE_DISCONNECTED};
    std::vector<std::string> candidates;
    std::mutex candidatesMutex;
    std::atomic<bool> gatheringDone{false};
    std::atomic<size_t> recvCount{0};
    std::atomic<size_t> recvBytes{0};
    std::atomic<std::int64_t> lastRecvMs{0};
    juice_agent_t *agent = nullptr;
    juice_agent_t *peer = nullptr;  // 对端 agent（用于候选转发）
    juice_turn_server_t turnServer;  // 每个 agent 独立的配置

    std::int64_t markLastRecvMs() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }
};

static juice_config_t makeConfig(AgentState &s, const char *host, uint16_t port,
                                  const char *user, const char *pass) {
    juice_config_t cfg{};
    cfg.concurrency_mode = JUICE_CONCURRENCY_MODE_POLL;  // 与已验证可工作的 C 版本一致
    cfg.cb_state_changed = [](juice_agent_t *, juice_state_t st, void *u) {
        static_cast<AgentState *>(u)->state.store(st);
    };
    cfg.cb_candidate = [](juice_agent_t *, const char *c, void *u) {
        auto *s = static_cast<AgentState *>(u);
        // 只收集候选；由 connectPair 在 gather 完成后统一转发 relay 候选。
        std::lock_guard<std::mutex> lk(s->candidatesMutex);
        s->candidates.emplace_back(c);
    };
    cfg.cb_gathering_done = [](juice_agent_t *, void *u) {
        static_cast<AgentState *>(u)->gatheringDone.store(true);
    };
    cfg.cb_recv = [](juice_agent_t *, const char *d, size_t n, void *u) {
        auto *s = static_cast<AgentState *>(u);
        s->recvBytes.fetch_add(n);
        s->recvCount.fetch_add(1);
        s->lastRecvMs.store(s->markLastRecvMs());
    };
    cfg.user_ptr = &s;

    // Configure TURN server (per-agent instance, not static)
    std::memset(&s.turnServer, 0, sizeof(s.turnServer));
    s.turnServer.host = host;
    s.turnServer.port = port;
    s.turnServer.username = user;
    s.turnServer.password = pass;
    cfg.turn_servers = &s.turnServer;
    cfg.turn_servers_count = 1;

    return cfg;
}

static bool waitFor(std::function<bool()> cond, int timeoutMs) {
    auto start = std::chrono::steady_clock::now();
    while (true) {
        if (cond()) return true;
        auto el = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - start);
        if (el.count() >= timeoutMs) return false;
        std::this_thread::sleep_for(5ms);
    }
}

static bool connectPair(AgentState &sa, AgentState &sb, juice_agent_t *a,
                        juice_agent_t *b, int timeoutMs) {
    char bufA[4096], bufB[4096];
    juice_get_local_description(a, bufA, sizeof(bufA));
    juice_get_local_description(b, bufB, sizeof(bufB));

    std::string sdpA = bufA, sdpB = bufB;

    juice_set_remote_description(b, sdpA.c_str());
    juice_set_remote_description(a, sdpB.c_str());

    // 双向候选转发：A 的 relay 候选传给 B，B 的传给 A。
    sa.peer = b;
    sb.peer = a;

    juice_gather_candidates(a);
    juice_gather_candidates(b);

    if (!waitFor([&] { return sa.gatheringDone.load() && sb.gatheringDone.load(); }, timeoutMs)) {
        std::fprintf(stderr, "  FAIL: gathering timeout\n");
        return false;
    }

    // 采集完成后批量双向转发 relay 候选，确保走 TURN relay 路径。
    {
        std::lock_guard<std::mutex> lkA(sa.candidatesMutex);
        for (const auto &c : sa.candidates)
            if (c.find("typ relay") != std::string::npos)
                juice_add_remote_candidate(b, c.c_str());
        std::lock_guard<std::mutex> lkB(sb.candidatesMutex);
        for (const auto &c : sb.candidates)
            if (c.find("typ relay") != std::string::npos)
                juice_add_remote_candidate(a, c.c_str());
    }

    // Wait for connection
    if (!waitFor([&] {
            auto sta = sa.state.load();
            auto stb = sb.state.load();
            return (sta == JUICE_STATE_CONNECTED || sta == JUICE_STATE_COMPLETED) &&
                   (stb == JUICE_STATE_CONNECTED || stb == JUICE_STATE_COMPLETED);
        }, timeoutMs)) {
        std::fprintf(stderr, "  FAIL: connection timeout\n");
        return false;
    }

    return true;
}

struct BenchResult {
    bool connectOk = false;
    double goodputMbps = 0.0;
    size_t sent = 0;
    size_t received = 0;
    size_t lost = 0;
};

static BenchResult runBench(AgentState &sa, AgentState &sb, juice_agent_t *a,
                            const char *mode, int totalPkts, int pktSize, int window) {
    BenchResult res;

    // Latency measurement (A -> B, main thread drives B's echo to avoid
    // re-entering libjuice from its recv callback thread)
    const int rounds = 100;
    std::vector<double> lat;
    lat.reserve(rounds);
    std::string ping(64, 'p');
    size_t baseB = sb.recvCount.load();
    size_t baseA = sa.recvCount.load();
    for (int i = 0; i < rounds; ++i) {
        auto t0 = std::chrono::steady_clock::now();
        juice_send(a, ping.data(), ping.size());                 // A -> B
        if (!waitFor([&] { return sb.recvCount.load() >= baseB + i + 1; }, 5000)) {
            std::fprintf(stderr, "  latency round %d: A->B timeout\n", i);
            break;
        }
        juice_send(sb.agent, ping.data(), ping.size());          // B -> A (echo)
        if (!waitFor([&] { return sa.recvCount.load() >= baseA + i + 1; }, 5000)) {
            std::fprintf(stderr, "  latency round %d: B->A timeout\n", i);
            break;
        }
        auto t1 = std::chrono::steady_clock::now();
        lat.push_back(std::chrono::duration<double, std::milli>(t1 - t0).count() / 2.0);
    }

    if (!lat.empty()) {
        std::sort(lat.begin(), lat.end());
        double sum = 0;
        for (double v : lat) sum += v;
        size_t p95idx = lat.size() * 95 / 100;
        if (p95idx >= lat.size()) p95idx = lat.size() - 1;
        double latAvg = sum / lat.size();
        double latP95 = lat[p95idx];
        std::fprintf(stderr, "  latency (RTT/2, %zu samples): avg=%.3f p95=%.3f ms\n",
                     lat.size(), latAvg, latP95);
    }

    // Throughput measurement
    sb.recvCount.store(0);
    sb.recvBytes.store(0);
    std::string payload(pktSize, 't');
    size_t sent = 0;
    size_t b0 = sb.recvBytes.load();
    size_t c0 = sb.recvCount.load();
    auto t0 = std::chrono::steady_clock::now();

    // Simple windowed sending (no AIMD for libjuice)
    const int win = window;
    auto lastSendProgress = std::chrono::steady_clock::now();
    while (sent < (size_t)totalPkts) {
        long long recvdPkts = (long long)sb.recvCount.load() - (long long)c0;
        long long inflight = (long long)sent - recvdPkts;
        if (inflight < win) {
            if (juice_send(a, payload.data(), payload.size()) >= 0) {
                ++sent;
                lastSendProgress = std::chrono::steady_clock::now();
            }
        } else {
            // 固定窗口 + 丢包会死锁(inflight 卡在窗口值)：无发送进度 2s 视为发送完成
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration<double>(now - lastSendProgress).count() > 2.0)
                break;
            std::this_thread::yield();
        }
    }

    // Wait for all sent packets to be received
    waitFor([&] { return sb.recvCount.load() - c0 >= (size_t)sent * 95 / 100; }, 15000);

    auto t1 = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(t1 - t0).count();

    res.sent = sent;
    res.received = sb.recvCount.load() - c0;
    res.lost = res.sent > res.received ? res.sent - res.received : 0;

    if (elapsed > 0 && res.received > 0) {
        size_t bytes = res.received * pktSize;
        res.goodputMbps = (bytes * 8.0) / elapsed / 1e6;
    }

    return res;
}

int main(int argc, char **argv) {
    const char *host = "192.168.3.223";
    uint16_t port = 3478;
    const char *user = "testuser";
    const char *pass = "123456";
    int clients = 1;
    int pkts = 20000;
    int pktSize = 1200;
    int window = 32;

    if (argc > 1) host = argv[1];
    if (argc > 2) port = static_cast<uint16_t>(std::atoi(argv[2]));
    if (argc > 3) user = argv[3];
    if (argc > 4) pass = argv[4];
    if (argc > 5) clients = std::atoi(argv[5]);
    if (argc > 6) pkts = std::atoi(argv[6]);
    if (argc > 7) pktSize = std::atoi(argv[7]);
    if (argc > 8) window = std::atoi(argv[8]);

    juice_set_log_level(JUICE_LOG_LEVEL_WARN);
    setvbuf(stderr, nullptr, _IONBF, 0);

    std::fprintf(stderr, "=== libjuice bench: %s:%u user=%s clients=%d ===\n",
                 host, port, user, clients);
    std::fprintf(stderr, "params: %d pkts, %dB packets\n", pkts, pktSize);

    std::vector<std::thread> threads;
    std::vector<BenchResult> results(clients);

    auto runClient = [&](int i, std::function<void(BenchResult&)> done) {
        AgentState sa, sb;
        juice_config_t cfgA = makeConfig(sa, host, port, user, pass);
        juice_config_t cfgB = makeConfig(sb, host, port, user, pass);

        sa.agent = juice_create(&cfgA);
        sb.agent = juice_create(&cfgB);

        char label[32];
        std::snprintf(label, sizeof(label), "client-%02d", i + 1);

        BenchResult res;
        if (!connectPair(sa, sb, sa.agent, sb.agent, 10000)) {
            std::fprintf(stderr, "[%s] FAIL: connection failed\n", label);
        } else {
            std::fprintf(stderr, "[%s] CONNECTED\n", label);
            res = runBench(sa, sb, sa.agent, "turn-udp", pkts, pktSize, window);
            std::fprintf(stderr, "[%s] throughput: sent=%zu received=%zu lost=%zu goodput=%.2f Mbps\n",
                         label, res.sent, res.received, res.lost, res.goodputMbps);
        }

        juice_destroy(sa.agent);
        juice_destroy(sb.agent);
        done(res);
    };

    for (int i = 0; i < clients; ++i) {
        if (clients > 1) {
            threads.emplace_back([&, i, runClient]() {
                runClient(i, [&](BenchResult r) { results[i] = r; });
            });
        } else {
            // 单客户端在主线程同步执行，规避 libjuice POLL 注册表非主线程创建导致的崩溃
            runClient(0, [&](BenchResult r) { results[0] = r; });
        }
    }

    for (auto &t : threads) t.join();

    // Summary
    size_t totalSent = 0, totalRecv = 0, totalLost = 0;
    double totalMbps = 0;
    int passCount = 0;

    std::fprintf(stderr, "\n=== SUMMARY (%s:%u) ===\n", host, port);
    std::fprintf(stderr, "client       sent      recv      lost    goodput\n");

    for (int i = 0; i < clients; ++i) {
        auto &r = results[i];
        totalSent += r.sent;
        totalRecv += r.received;
        totalLost += r.lost;
        totalMbps += r.goodputMbps;
        bool ok = r.lost == 0;
        if (ok) ++passCount;
        std::fprintf(stderr, "client-%02d   %-9zu %-9zu %-7zu %.1f Mbps  %s\n",
                     i + 1, r.sent, r.received, r.lost, r.goodputMbps,
                     ok ? "PASS" : "FAIL");
    }

    double lossRate = totalSent > 0 ? (100.0 * totalLost / totalSent) : 0;
    std::fprintf(stderr, "\nTOTAL: %.1f Mbps  recv=%zu/%zu  loss=%.2f%%  pass=%d/%d  %s\n",
                 totalMbps, totalRecv, totalSent, lossRate, passCount, clients,
                 passCount == clients ? "PASS" : "PARTIAL");

    return passCount == clients ? 0 : 1;
}
