// test_longrun_4mode.cpp
//
// Long-duration sustained-throughput + zero-loss soak test for stice, covering
// the same four transports as test_agent_4mode_bigdata.cpp:
//
//     udp-ice   : direct host/host ICE over UDP (no TURN relay)
//     udpturn   : relayed through a TURN server over UDP
//     tcpturn   : relayed through a TURN server over TCP (RFC 6062)
//     tcp-ice   : direct ICE-TCP (RFC 6544) through a shared TCP mux
//
// This is the "long-term test case" built on top of test_agent_4mode_bigdata:
// where that tool proves *one short burst* survives each transport, this one
// proves a *sustained* load survives for hours.
//
//   --clients N      N concurrent client pairs run inside ONE process
//                    (default 100). Each "client" is one ICE pair: A is the
//                    controlling/sending side, B the receiving side, so the
//                    100 clients produce 100 simultaneous data flows.
//   --rate-bps B     per-client offered rate in bytes/s (default 10 MiB/s =
//                    10485760). The sender is time-paced (never sends more
//                    than rate*elapsed) so the *average* rate is the target
//                    even though the OS timer granularity makes the instant
//                    rate bursty.
//   --duration-sec S streaming window in seconds (default 10800 = 3 h).
//
// PASS requires, for EVERY pair, all of:
//   * the ICE connection stayed up for the whole window,
//   * the receiver counted EXACTLY the bytes the sender emitted (zero loss),
//   * the achieved rate was >= 95 % of the target, i.e. the data path really
//     sustained the offered load instead of silently throttling.
// Any violation stops the whole run immediately (long-test policy: a problem
// stops the run) and the offending pair is named with a diagnosis string.
//
// Usage:
//   test_longrun_4mode --mode <udp-ice|udpturn|tcpturn|tcp-ice>
//                      [--clients N=100] [--rate-bps B=10485760]
//                      [--duration-sec S=10800] [--block K=1200]
//                      [--connect-timeout-ms ms=60000] [--stall-sec S=30]
//                      [--inflight B=8388608] [--report-every S=30]
//                      [--turn-host H=127.0.0.1] [--turn-port P=3478]
//                      [--tcp-port P=44444] [--bidir]
//                      [--start-at <epoch_ms>] [--log <level>] [--label S]
#include "stice/stice.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <unistd.h>
#endif

namespace {

using Clock = std::chrono::steady_clock;

enum class Mode { UdpIce, UdpTurn, TcpTurn, TcpIce };
const char* modeName(Mode m) {
    switch (m) { case Mode::UdpIce: return "udp-ice"; case Mode::UdpTurn: return "udpturn";
                 case Mode::TcpTurn: return "tcpturn"; case Mode::TcpIce: return "tcp-ice"; }
    return "?";
}

// Gather wait must exceed stice's internal soft-gathering fallback (15 s).
static constexpr int kGatherWaitMs = 20000;
// After the sender stops, allow the receiver this long to drain in-flight data.
static constexpr int kDrainMs = 20000;

// static storage for TURN server entries (must outlive config use)
static stice_turn_server_t g_turnUdp, g_turnTcp;

struct Options {
    Mode mode = Mode::UdpIce;
    int clients = 100;
    uint64_t rateBps = 10ull * 1024 * 1024;   // 10 MiB/s per client
    long long durationSec = 10800;            // 3 hours
    size_t block = 1200;
    int connectTimeoutMs = 60000;
    int stallSec = 30;
    size_t inflightCap = 8ull * 1024 * 1024;
    std::string turnHost = "127.0.0.1";
    uint16_t turnPort = 3478;
    int tcpPort = 44444;
    int reportEverySec = 30;
    int staggerMs = 0;
    bool bidir = false;
    long long startAtMs = 0;
    stice_log_level_t logLevel = STICE_LOG_LEVEL_WARN;
    std::string label;
};

struct PairState {
    std::atomic<stice_state_t> sa{STICE_STATE_DISCONNECTED};
    std::atomic<stice_state_t> sb{STICE_STATE_DISCONNECTED};
    std::atomic<bool> gdA{false};
    std::atomic<bool> gdB{false};
    std::atomic<size_t> rx{0};      // bytes B received from A (forward)
    std::atomic<size_t> rxRev{0};   // bytes A received from B (bidir only)
    std::atomic<size_t> sentFwd{0};
    std::atomic<size_t> sentRev{0};
    std::atomic<bool> streaming{false}; // reached the sustained streaming phase
    std::atomic<bool> finished{false};
    std::atomic<int> outcome{0};    // 1 = pass, 2 = fail, 3 = aborted by peer failure
    char failMsg[192] = {0};
};

struct Control {
    std::atomic<bool> stop{false};
    std::atomic<int> firstFail{0};  // 1-based client index of the first failure
};

template <typename F>
bool waitFor(F cond, int timeoutMs) {
    auto start = Clock::now();
    while (true) {
        if (cond()) return true;
        auto el = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start);
        if (el.count() >= timeoutMs) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

size_t currentRssMb() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)))
        return (size_t)(pmc.WorkingSetSize >> 20);
    return 0;
#else
    FILE* f = fopen("/proc/self/statm", "r");
    if (!f) return 0;
    unsigned long long tot = 0, res = 0;
    if (fscanf(f, "%llu %llu", &tot, &res) != 2) res = 0;
    fclose(f);
    long ps = sysconf(_SC_PAGESIZE);
    return (size_t)((res * (unsigned long long)(ps > 0 ? ps : 4096)) >> 20);
#endif
}

stice_config_t makeCfg(PairState& s, bool isA, const Options& o) {
    stice_config_t cfg{};
    cfg.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
    if (isA) {
        cfg.cb_state_changed = [](stice_agent_t*, stice_state_t st, void* p) {
            static_cast<PairState*>(p)->sa.store(st); };
        cfg.cb_gathering_done = [](stice_agent_t*, void* p) { static_cast<PairState*>(p)->gdA.store(true); };
        cfg.cb_recv = [](stice_agent_t*, const char*, size_t n, void* p) {
            static_cast<PairState*>(p)->rxRev.fetch_add(n); };
    } else {
        cfg.cb_state_changed = [](stice_agent_t*, stice_state_t st, void* p) {
            static_cast<PairState*>(p)->sb.store(st); };
        cfg.cb_gathering_done = [](stice_agent_t*, void* p) { static_cast<PairState*>(p)->gdB.store(true); };
        cfg.cb_recv = [](stice_agent_t*, const char*, size_t n, void* p) {
            static_cast<PairState*>(p)->rx.fetch_add(n); };
    }
    cfg.cb_candidate = [](stice_agent_t*, const char*, void*) {};
    cfg.user_ptr = &s;
    cfg.bind_address = nullptr;
    // Client UDP sockets must avoid the TURN relay port range (49152-65535).
    cfg.local_port_range_begin = 10000;
    cfg.local_port_range_end = 49000;

    if (o.mode == Mode::UdpTurn || o.mode == Mode::TcpTurn) {
        auto* ts = (o.mode == Mode::UdpTurn) ? &g_turnUdp : &g_turnTcp;
        ts->host = o.turnHost.c_str();
        ts->port = o.turnPort;
        ts->username = "testuser";
        ts->password = "123456";
        ts->transport = (o.mode == Mode::TcpTurn) ? STICE_TURN_TRANSPORT_TCP : STICE_TURN_TRANSPORT_UDP;
        ts->skip_tls_verify = 0;
        cfg.turn_servers = ts;
        cfg.turn_servers_count = 1;
        cfg.relay_only_local = 1;
    }
    if (o.mode == Mode::TcpIce) cfg.disable_udp_gathering = 1;
    return cfg;
}

// In-place SDP filter for TURN modes: keep only 'typ relay' candidates so ICE
// can only pair against relayed remote candidates (forces the relay data path).
void filterNonRelayCandidates(char* sdp) {
    std::string in(sdp), out;
    size_t pos = 0;
    while (pos < in.size()) {
        size_t eol = in.find('\n', pos);
        std::string line = in.substr(pos, eol == std::string::npos ? std::string::npos : eol - pos);
        pos = (eol == std::string::npos) ? in.size() : eol + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        bool isCand = line.rfind("a=candidate:", 0) == 0;
        if (isCand && line.find("typ relay") == std::string::npos) continue;
        out += line;
        out += "\r\n";
    }
    std::strcpy(sdp, out.c_str());
}

// ---------------------------------------------------------------------------
// One client = one ICE pair. Establishes the connection, streams at the paced
// rate for the whole window, verifies zero loss + sustained rate, tears down.
// ---------------------------------------------------------------------------
void runOnePair(int idx, const Options& o, Control& ctl,
                std::vector<std::unique_ptr<PairState>>& states,
                stice_tcp_mux_t* sharedMux) {
    PairState& st = *states[(size_t)idx];
    // Progress markers, flushed immediately: when a client has to be killed
    // (rather than returning) these localize the wedge to a phase. Printed for
    // every pair because the reference deployment runs one pair per process.
    auto mark = [&](const char* m) {
        printf("  [pair%d phase] %s\n", idx + 1, m);
        fflush(stdout);
    };
    auto setFail = [&](const char* msg) {
        std::snprintf(st.failMsg, sizeof(st.failMsg), "%s", msg);
    };

    stice_config_t cfgA = makeCfg(st, true, o);
    stice_config_t cfgB = makeCfg(st, false, o);
    mark("creating agents");
    stice_agent_t* a = stice_create(&cfgA);
    stice_agent_t* b = stice_create(&cfgB);
    mark("agents created");
    if (!a || !b) {
        if (a) stice_destroy(a);
        if (b) stice_destroy(b);
        setFail("stice_create failed");
        st.outcome.store(2); st.finished.store(true);
        ctl.firstFail.compare_exchange_strong(idx, idx + 1);
        ctl.stop.store(true);
        return;
    }

    stice_tcp_mux_t* tcpMux = sharedMux;
    bool ownMux = false;
    if (o.mode == Mode::TcpIce) {
        stice_set_ice_tcp_mode(a, STICE_ICE_TCP_MODE_ACTIVE);
        if (!tcpMux) {
            tcpMux = stice_create_tcp_mux("127.0.0.1", (uint16_t)o.tcpPort);
            ownMux = true;
        }
        if (!tcpMux) {
            stice_destroy(a); stice_destroy(b);
            setFail("tcp mux create failed");
            st.outcome.store(2); st.finished.store(true);
            ctl.stop.store(true);
            return;
        }
        stice_agent_use_tcp_mux(b, tcpMux);
        stice_set_ice_tcp_mode(b, STICE_ICE_TCP_MODE_PASSIVE);
    }

    auto teardown = [&] {
        stice_destroy(a);
        stice_destroy(b);
        if (ownMux) stice_destroy_tcp_mux(tcpMux);
    };
    auto bail = [&](const char* msg) {
        setFail(msg);
        teardown();
        st.outcome.store(2); st.finished.store(true);
        ctl.firstFail.compare_exchange_strong(idx, idx + 1);
        ctl.stop.store(true);
    };

    auto abortPair = [&] { teardown(); st.outcome.store(3); st.finished.store(true); };

    mark("requesting gather");
    if (stice_gather_candidates(b) != STICE_ERR_SUCCESS ||
        stice_gather_candidates(a) != STICE_ERR_SUCCESS) {
        bail("gather_candidates failed");
        return;
    }
    if (!waitFor([&] { return (st.gdA.load() && st.gdB.load()) || ctl.stop.load(); }, kGatherWaitMs)) {
        bail("gather timeout");
        return;
    }
    if (ctl.stop.load()) { abortPair(); return; }
    mark("gathered");
    char bufA[16384], bufB[16384];
    if (stice_get_local_description(a, bufA, sizeof(bufA)) != STICE_ERR_SUCCESS ||
        stice_get_local_description(b, bufB, sizeof(bufB)) != STICE_ERR_SUCCESS) {
        bail("get_local_description failed");
        return;
    }
    mark("local-description-read");
    if (o.mode == Mode::UdpTurn || o.mode == Mode::TcpTurn) {
        filterNonRelayCandidates(bufA);
        filterNonRelayCandidates(bufB);
    }
    if (stice_set_remote_description(a, bufB) != STICE_ERR_SUCCESS ||
        stice_set_remote_description(b, bufA) != STICE_ERR_SUCCESS) {
        bail("set_remote_description failed");
        return;
    }
    stice_set_remote_gathering_done(a);
    stice_set_remote_gathering_done(b);
    mark("remote-description-set");

    bool connected = waitFor([&] {
        if (ctl.stop.load()) return true;
        auto as = st.sa.load(), bs = st.sb.load();
        return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
               (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
    }, o.connectTimeoutMs);
    if (ctl.stop.load()) { abortPair(); return; }
    if (!connected) {
        bail("connect timeout");
        return;
    }

    // Verify the selected pair really exercises the transport under test.
    {
        char selLocal[1024], selRemote[1024];
        if (stice_get_selected_candidates(a, selLocal, sizeof(selLocal),
                                          selRemote, sizeof(selRemote)) == STICE_ERR_SUCCESS) {
            bool remoteRelay = std::strstr(selRemote, "typ relay") != nullptr;
            if (idx == 0)
                printf("  selected pair: local=[%s] remote=[%s]\n", selLocal, selRemote);
            if ((o.mode == Mode::UdpTurn || o.mode == Mode::TcpTurn) && !remoteRelay) {
                bail("TURN mode selected a non-relay remote pair");
                return;
            }
            if ((o.mode == Mode::UdpIce || o.mode == Mode::TcpIce) && remoteRelay) {
                bail("non-TURN mode selected a relay pair");
                return;
            }
        }
    }

    mark("connected");
    // Stagger streaming start so N pairs do not all hit the socket buffer
    // at once (transient 1 GiB/s spike on loopback causes UDP drops + stalls).
    if (o.staggerMs > 0) std::this_thread::sleep_for(std::chrono::milliseconds(idx * o.staggerMs));
    st.streaming.store(true);
    mark("streaming");

    // ---- sustained streaming phase -------------------------------------
    std::vector<char> payload(o.block, 'x');
    auto tStreamStart = Clock::now();
    long againFwd = 0, againRev = 0;

    // sender loop: paced, back-pressured by the receiver's progress, with a
    // stall watchdog. Returns 0 = window completed, 2 = fail, 3 = aborted.
    auto senderLoop = [&](stice_agent_t* ag, std::atomic<size_t>& sentOut,
                          std::atomic<size_t>& rxRef, const char* dir,
                          double* elOut, long& againOut) -> int {
        size_t sent = 0;
        auto lastAdv = Clock::now();
        size_t lastRx = rxRef.load();
        long againStreak = 0;
        while (true) {
            double el = std::chrono::duration<double>(Clock::now() - tStreamStart).count();
            if (el >= (double)o.durationSec) { if (elOut) *elOut = el; return 0; }
            if (ctl.stop.load()) return 3;

            if (o.rateBps) {
                double allowed = (double)o.rateBps * el;
                if ((double)sent >= allowed) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    continue;
                }
            }

            size_t rxv = rxRef.load();
            if (rxv > lastRx) { lastRx = rxv; lastAdv = Clock::now(); }
            size_t lag = sent > rxv ? sent - rxv : 0;
            if (lag >= o.inflightCap) {
                double idle = std::chrono::duration<double>(Clock::now() - lastAdv).count();
                if (idle >= (double)o.stallSec) {
                    char m[192];
                    std::snprintf(m, sizeof(m),
                        "pair%d %s STALL: %zu B in flight, rx frozen %ds (sent=%zu rx=%zu)",
                        idx + 1, dir, lag, o.stallSec, sent, rxv);
                    setFail(m);
                    return 2;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
                continue;
            }

            if (st.sa.load() == STICE_STATE_FAILED) {
                char m[192];
                std::snprintf(m, sizeof(m), "pair%d %s: agent A state=FAILED", idx + 1, dir);
                setFail(m);
                return 2;
            }

            int rc = stice_send(ag, payload.data(), o.block);
            if (rc == STICE_ERR_SUCCESS) {
                sent += o.block;
                sentOut.store(sent);
                againStreak = 0;
            } else if (rc == STICE_ERR_AGAIN) {
                // Transport send queue full: retry IMMEDIATELY (yield) instead
                // of sleeping a whole timer tick. A 1 ms sleep per AGAIN caps
                // the flow at ~1 message/ms (~8 MiB/s for 8 KiB blocks), which
                // is exactly the TURN-over-TCP ceiling this test must rule out.
                // After a bounded spin we do sleep once, so a genuinely stalled
                // peer cannot burn a core forever (the stall watchdog also
                // fires).
                ++againOut;
                // On Linux, yield() busy-spin burns a whole core per 100-thread
                // set. A 1 ms sleep is enough back-pressure; the stall watchdog
                // catches a genuinely wedged peer.
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            } else {
                char m[192];
                std::snprintf(m, sizeof(m), "pair%d %s: stice_send rc=%d (sent=%zu, again=%ld)",
                              idx + 1, dir, rc, sent, againOut);
                setFail(m);
                return 2;
            }
        }
    };

    double fwdElapsed = 0.0, revElapsed = 0.0;
    int revRc = 0;
    std::thread revThread;
    if (o.bidir)
        revThread = std::thread([&] { revRc = senderLoop(b, st.sentRev, st.rxRev, "B->A", &revElapsed, againRev); });
    int fwdRc = senderLoop(a, st.sentFwd, st.rx, "A->B", &fwdElapsed, againFwd);
    if (revThread.joinable()) revThread.join();

    if (fwdRc == 3 || revRc == 3) {
        // A peer failed; this pair is collateral, not the reported root cause.
        teardown();
        st.outcome.store(3); st.finished.store(true);
        return;
    }
    if (fwdRc == 2 || revRc == 2) {
        std::fprintf(stderr, "FAIL %s\n", st.failMsg);
        teardown();
        st.outcome.store(2); st.finished.store(true);
        ctl.firstFail.compare_exchange_strong(idx, idx + 1);
        ctl.stop.store(true);
        return;
    }

    // drain: let in-flight bytes reach the receiver
    size_t sentF = st.sentFwd.load();
    size_t sentR = st.sentRev.load();
    {
        auto td = Clock::now();
        while ((st.rx.load() < sentF || (o.bidir && st.rxRev.load() < sentR)) &&
               std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - td).count() < kDrainMs)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    size_t rxF = st.rx.load();
    size_t rxR = st.rxRev.load();

    // verify: zero loss + sustained rate
    bool loss = (rxF != sentF) || (o.bidir && rxR != sentR);
    bool rateOk = true;
    if (o.rateBps > 0 && fwdElapsed > 10.0) {
        double expected = (double)o.rateBps * fwdElapsed;
        if ((double)sentF < 0.95 * expected) rateOk = false;
    }
    bool ok = !loss && rateOk;
    if (!ok) {
        char m[192];
        if (loss)
            std::snprintf(m, sizeof(m),
                "pair%d LOSS: sent_fwd=%zu rx_fwd=%zu lost=%lld (rev sent=%zu rx=%zu)",
                idx + 1, sentF, rxF, (long long)(sentF - rxF), sentR, rxR);
        else
            std::snprintf(m, sizeof(m),
                "pair%d RATE SHORT: sent=%zu over %.1fs = %.2f MiB/s < 95%% of %.2f MiB/s target",
                idx + 1, sentF, fwdElapsed, (double)sentF / fwdElapsed / 1048576.0,
                (double)o.rateBps / 1048576.0);
        setFail(m);
        std::fprintf(stderr, "FAIL %s\n", st.failMsg);
        teardown();
        st.outcome.store(2); st.finished.store(true);
        ctl.firstFail.compare_exchange_strong(idx, idx + 1);
        ctl.stop.store(true);
        return;
    }

    teardown();
    st.outcome.store(1);
    st.finished.store(true);
    if (idx == 0) {
        printf("  pair1 OK: sent=%zu rx=%zu over %.1fs = %.2f MiB/s again=%ld\n",
               sentF, rxF, fwdElapsed, (double)sentF / fwdElapsed / 1048576.0, againFwd);
        fflush(stdout);
    }
}

} // namespace

int main(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--mode" && i + 1 < argc) {
            std::string m = argv[++i];
            if (m == "udpturn") o.mode = Mode::UdpTurn;
            else if (m == "tcpturn") o.mode = Mode::TcpTurn;
            else if (m == "tcp-ice") o.mode = Mode::TcpIce;
            else o.mode = Mode::UdpIce;
        }
        else if (a == "--clients" && i + 1 < argc) o.clients = atoi(argv[++i]);
        else if (a == "--rate-bps" && i + 1 < argc) o.rateBps = strtoull(argv[++i], nullptr, 10);
        else if (a == "--rate-mib" && i + 1 < argc) o.rateBps = (uint64_t)strtoull(argv[++i], nullptr, 10) * 1024 * 1024;
        else if (a == "--duration-sec" && i + 1 < argc) o.durationSec = atoll(argv[++i]);
        else if (a == "--block" && i + 1 < argc) o.block = (size_t)strtoull(argv[++i], nullptr, 10);
        else if (a == "--connect-timeout-ms" && i + 1 < argc) o.connectTimeoutMs = atoi(argv[++i]);
        else if (a == "--stall-sec" && i + 1 < argc) o.stallSec = atoi(argv[++i]);
        else if (a == "--inflight" && i + 1 < argc) o.inflightCap = (size_t)strtoull(argv[++i], nullptr, 10);
        else if (a == "--report-every" && i + 1 < argc) o.reportEverySec = atoi(argv[++i]);
        else if (a == "--stagger-ms" && i + 1 < argc) o.staggerMs = atoi(argv[++i]);
        else if (a == "--turn-host" && i + 1 < argc) o.turnHost = argv[++i];
        else if (a == "--turn-port" && i + 1 < argc) o.turnPort = (uint16_t)atoi(argv[++i]);
        else if (a == "--tcp-port" && i + 1 < argc) o.tcpPort = atoi(argv[++i]);
        else if (a == "--bidir") o.bidir = true;
        else if (a == "--start-at" && i + 1 < argc) o.startAtMs = atoll(argv[++i]);
        else if (a == "--label" && i + 1 < argc) o.label = argv[++i];
        else if (a == "--log" && i + 1 < argc) {
            std::string l = argv[++i];
            if (l == "verbose") o.logLevel = STICE_LOG_LEVEL_VERBOSE;
            else if (l == "debug") o.logLevel = STICE_LOG_LEVEL_DEBUG;
            else if (l == "info") o.logLevel = STICE_LOG_LEVEL_INFO;
            else if (l == "error") o.logLevel = STICE_LOG_LEVEL_ERROR;
            else if (l == "fatal") o.logLevel = STICE_LOG_LEVEL_FATAL;
            else if (l == "none") o.logLevel = STICE_LOG_LEVEL_NONE;
            else o.logLevel = STICE_LOG_LEVEL_WARN;
        }
    }
    if (o.clients < 1) o.clients = 1;
    if (o.block < 1 || o.block > 16000) o.block = 1200;

    if (o.mode == Mode::TcpTurn) {
#if defined(_WIN32)
        _putenv_s("JUICE_TURN_TCP_NO_FRAMING", "1");
        _putenv_s("STICE_TURN_TCP_RFC6062", "1");
#else
        setenv("JUICE_TURN_TCP_NO_FRAMING", "1", 1);
        setenv("STICE_TURN_TCP_RFC6062", "1", 1);
#endif
    }
    stice_set_log_level(o.logLevel);
    // Install a log handler. Without one the library is SILENT by default
    // (log.cpp returns early when no handler is installed), so a long-run
    // failure would carry no library-side diagnostics at all - the first 3 h
    // run failed with a bare send error for exactly this reason.
    static const auto g_logT0 = Clock::now();
    stice_set_log_handler([](stice_log_level_t level, const char *msg) {
        const char* tag = "?";
        switch (level) {
        case STICE_LOG_LEVEL_VERBOSE: tag = "VRB"; break;
        case STICE_LOG_LEVEL_DEBUG:   tag = "DBG"; break;
        case STICE_LOG_LEVEL_INFO:    tag = "INF"; break;
        case STICE_LOG_LEVEL_WARN:    tag = "WRN"; break;
        case STICE_LOG_LEVEL_ERROR:   tag = "ERR"; break;
        case STICE_LOG_LEVEL_FATAL:   tag = "FTL"; break;
        default: break;
        }
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - g_logT0).count();
        std::fprintf(stderr, "[%lldms %s] %s\n", (long long)ms, tag, msg ? msg : "");
        std::fflush(stderr);
    });
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    // wall-clock start barrier (aligns several processes launched by a driver)
    if (o.startAtMs > 0) {
        auto nowMs = [] {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        };
        while (nowMs() < o.startAtMs) {
            long long remain = o.startAtMs - nowMs();
            std::this_thread::sleep_for(std::chrono::milliseconds(remain > 20 ? 10 : 1));
        }
    }

    const size_t rssFirst = currentRssMb();
    printf("LONGRUN-START mode=%s clients=%d rate_bps=%llu duration_s=%lld block=%zu "
           "inflight=%zu bidir=%d rss=%zuMB%s%s\n",
           modeName(o.mode), o.clients, (unsigned long long)o.rateBps, o.durationSec,
           o.block, o.inflightCap, (int)o.bidir, rssFirst,
           o.label.empty() ? "" : " label=", o.label.c_str());
    fflush(stdout);

    std::vector<std::unique_ptr<PairState>> states;
    states.reserve((size_t)o.clients);
    for (int i = 0; i < o.clients; ++i) states.emplace_back(new PairState());

    stice_tcp_mux_t* sharedMux = nullptr;
    if (o.mode == Mode::TcpIce) {
        sharedMux = stice_create_tcp_mux("127.0.0.1", (uint16_t)o.tcpPort);
        if (!sharedMux) {
            std::fprintf(stderr, "cannot create shared tcp mux on 127.0.0.1:%d\n", o.tcpPort);
            return 1;
        }
    }

    Control ctl;
    std::vector<std::thread> threads;
    threads.reserve((size_t)o.clients);
    auto tp0 = Clock::now();
    for (int i = 0; i < o.clients; ++i)
        threads.emplace_back([&, i] { runOnePair(i, o, ctl, states, sharedMux); });

    // monitor: periodic aggregate progress; hard backstop so a wedged run
    // always terminates instead of hanging the 3-hour window.
    const long long hardLimitSec = o.durationSec + o.connectTimeoutMs / 1000 + 180;
    // Startup watchdog: every client must reach the streaming phase (or finish)
    // within connect-timeout + slack. Otherwise a client wedged in a setup call
    // (gather/connect) would burn the whole --duration window before the hard
    // limit caught it; long-test policy is to stop on the first problem.
    const long long startupLimitSec = o.connectTimeoutMs / 1000 + 120;
    size_t rssMax = rssFirst;
    int tick = 0;
    while (true) {
        bool allDone = true;
        for (auto& sp : states) if (!sp->finished.load()) { allDone = false; break; }
        if (allDone) break;
        double el = std::chrono::duration<double>(Clock::now() - tp0).count();
        if (el > (double)hardLimitSec) {
            printf("LONGRUN-HARDTIMEOUT elapsed=%.0fs > limit=%llds - aborting run\n", el, hardLimitSec);
            fflush(stdout);
            std::_Exit(2);
        }
        if (el > (double)startupLimitSec) {
            for (auto& sp : states) {
                if (!sp->finished.load() && !sp->streaming.load()) {
                    printf("LONGRUN-STARTUP-HANG elapsed=%.0fs > limit=%llds: client never started "
                           "streaming and never returned (wedged in setup); aborting run\n",
                           el, startupLimitSec);
                    fflush(stdout);
                    std::_Exit(3);
                }
            }
        }
        size_t rss = currentRssMb();
        if (rss > rssMax) rssMax = rss;
        ++tick;
        if (o.reportEverySec > 0 && tick % o.reportEverySec == 0) {
            size_t sent = 0, rx = 0, done = 0;
            for (auto& sp : states) {
                sent += sp->sentFwd.load() + sp->sentRev.load();
                rx += sp->rx.load() + sp->rxRev.load();
                if (sp->finished.load()) ++done;
            }
            printf("PROGRESS elapsed=%.0fs clients=%d done=%zu sent_total=%zu rx_total=%zu "
                   "agg=%.2f MiB/s lag=%lld rss=%zuMB(max %zuMB)\n",
                   el, o.clients, done, sent, rx,
                   el > 0 ? (double)rx / el / 1048576.0 : 0.0,
                   (long long)(sent > rx ? sent - rx : 0), rss, rssMax);
            fflush(stdout);
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    for (auto& t : threads) t.join();
    if (sharedMux) stice_destroy_tcp_mux(sharedMux);

    double wall = std::chrono::duration<double>(Clock::now() - tp0).count();
    int pass = 0, fail = 0, abort = 0;
    size_t sentTotal = 0, rxTotal = 0;
    for (int i = 0; i < o.clients; ++i) {
        PairState& sp = *states[(size_t)i];
        sentTotal += sp.sentFwd.load() + sp.sentRev.load();
        rxTotal += sp.rx.load() + sp.rxRev.load();
        int oc = sp.outcome.load();
        if (oc == 1) ++pass;
        else if (oc == 2) { ++fail; }
        else ++abort;
    }
    for (int i = 0; i < o.clients; ++i) {
        PairState& sp = *states[(size_t)i];
        if (sp.outcome.load() == 2)
            printf("  FAILED client %d: %s\n", i + 1, sp.failMsg);
    }
    long long loss = (long long)sentTotal - (long long)rxTotal;
    printf("LONGRUN-RESULT mode=%s clients=%d target_bps=%llu duration_s=%lld bidir=%d "
           "pass=%d fail=%d abort=%d sent_total=%zu rx_total=%zu loss=%lld wall_s=%.1f "
           "rss_first=%zuMB rss_max=%zuMB result=%s\n",
           modeName(o.mode), o.clients, (unsigned long long)o.rateBps, o.durationSec,
           (int)o.bidir, pass, fail, abort, sentTotal, rxTotal, loss, wall,
           rssFirst, rssMax, (fail || abort) ? "FAIL" : "PASS");
    fflush(stdout);
    return (fail || abort) ? 1 : 0;
}
