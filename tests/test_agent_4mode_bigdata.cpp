// test_agent_4mode_bigdata.cpp
// stice-native client-to-client big-data transfer across 4 modes, in-process.
// Isolates the stice ICE/data layer from libdatachannel/usrsctp wrappers:
// A sends big chunks over the established ICE connection, B counts received
// bytes; we report whether the transfer stalls (does stice itself clog?).
//
// Usage: test_agent_4mode_bigdata --mode <udp-ice|udpturn|tcpturn|tcp-ice>
//                                 [--bytes <N> default 104857600]
//                                 [--block <K> default 1200]
//                                 [--timeout <ms> default 60000]
//                                 [--turn-host H --turn-port P]
//                                 [--inflight <bytes> default 4194304]
//                                 [--rate <MiB/s> default 0 = unpaced; caps the
//                                  sender so a weak host (2-core VM running
//                                  coturn + both agents) is not swamped]
//                                 [--duration <sec> loop rounds until elapsed]
//                                 [--start-at <epoch_ms> wall-clock start barrier,
//                                  aligns N concurrently-launched processes]
//                                 [--spawn <N> --spawn-out <dir> fork N aligned
//                                  clients and aggregate; --out-file <path>]
//                                 [--log <verbose|debug|info|warn|error>]
#include "stice/stice.h"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
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

struct State {
    std::atomic<stice_state_t> sa{STICE_STATE_DISCONNECTED};
    std::atomic<stice_state_t> sb{STICE_STATE_DISCONNECTED};
    std::atomic<bool> gdA{false};
    std::atomic<bool> gdB{false};
    std::atomic<size_t> rx{0};
    std::atomic<long long> lastRecvUs{0};   // last cb_recv timestamp (us)
    std::atomic<long long> firstRecvUs{0};  // first cb_recv timestamp (us)
};

enum class Mode { UdpIce, UdpTurn, TcpTurn, TcpIce };
const char* modeName(Mode m) {
    switch (m) { case Mode::UdpIce: return "udp-ice"; case Mode::UdpTurn: return "udpturn";
                 case Mode::TcpTurn: return "tcpturn"; case Mode::TcpIce: return "tcp-ice"; }
    return "?";
}

// static storage for TURN server entries (must outlive config use)
static stice_turn_server_t g_turnUdp, g_turnTcp;

stice_config_t makeCfg(State& s, bool isA, Mode mode, const char* thost, uint16_t tport) {
    stice_config_t cfg{};
    cfg.concurrency_mode = STICE_CONCURRENCY_MODE_POLL;
    if (isA) {
        cfg.cb_state_changed = [](stice_agent_t*, stice_state_t st, void* p) { static_cast<State*>(p)->sa.store(st); };
        cfg.cb_gathering_done = [](stice_agent_t*, void* p) { static_cast<State*>(p)->gdA.store(true); };
        cfg.cb_recv = [](stice_agent_t*, const char*, size_t n, void* p) {
            static_cast<State*>(p)->rx.fetch_add(n);
        };
    } else {
        cfg.cb_state_changed = [](stice_agent_t*, stice_state_t st, void* p) { static_cast<State*>(p)->sb.store(st); };
        cfg.cb_gathering_done = [](stice_agent_t*, void* p) { static_cast<State*>(p)->gdB.store(true); };
        cfg.cb_recv = [](stice_agent_t*, const char*, size_t n, void* p) {
            auto* s = static_cast<State*>(p);
            auto now = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            auto prevRx = s->rx.fetch_add(n);
            if (prevRx == 0) s->firstRecvUs.store(now);
            s->lastRecvUs.store(now);
        };
    }
    cfg.cb_candidate = [](stice_agent_t*, const char*, void*) {};
    cfg.user_ptr = &s;
    cfg.bind_address = nullptr;
    // Client UDP sockets must avoid the TURN relay port range (49152-65535):
    // on-loopback tests the client socket port can otherwise collide with the
    // peer relayed candidate, looping the ICE Binding back to its own socket.
    cfg.local_port_range_begin = 10000;
    cfg.local_port_range_end = 49000;

    if (mode == Mode::UdpTurn || mode == Mode::TcpTurn) {
        auto* ts = (mode == Mode::UdpTurn) ? &g_turnUdp : &g_turnTcp;
        ts->host = thost;
        ts->port = tport;
        ts->username = "testuser";
        ts->password = "123456";
        ts->transport = (mode == Mode::TcpTurn) ? STICE_TURN_TRANSPORT_TCP : STICE_TURN_TRANSPORT_UDP;
        ts->skip_tls_verify = 0;
        cfg.turn_servers = ts;
        cfg.turn_servers_count = 1;
        cfg.relay_only_local = 1;
    }
    if (mode == Mode::TcpIce) {
        cfg.disable_udp_gathering = 1;
    }
    return cfg;
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

bool waitFor(std::function<bool()> cond, int timeoutMs) {
    auto start = std::chrono::steady_clock::now();
    while (true) {
        if (cond()) return true;
        auto el = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        if (el.count() >= timeoutMs) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

struct Result { bool connected = false; bool completed = false; bool stalled = false;
                bool relayPath = true; // selected remote pair matches the mode's expectation
                size_t rx = 0; long sendMs = 0; long totalMs = 0; };

// In-place SDP filter for TURN modes: remove 'a=candidate:' lines that are
// not 'typ relay'. Forcing the exchanged descriptions to relay-only means ICE
// can only pair against relayed remote candidates, so the data path goes
// through the TURN relay (remote relayed => route via own allocation).
// Without this, higher-priority direct pairs (e.g. same-machine srflx) win
// nomination and the relay path is never actually exercised.
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
        if (isCand && line.find("typ relay") == std::string::npos) continue; // drop host/srflx
        out += line;
        out += "\r\n";
    }
    std::strcpy(sdp, out.c_str()); // filtered output is never larger than input
}

// Gather wait must EXCEED stice's internal soft-gathering fallback
// (agent.hpp: GatherTimeoutMs = 15s). Waiting less makes the test tear down in
// the middle of a legitimately slow gather - which is what exposed the
// stice_destroy wedge. 20s lets the library's own fallback complete first.
static constexpr int kGatherWaitMs = 20000;

Result runPair(Mode mode, size_t bytes, size_t block, int timeoutMs,
               const char* thost, uint16_t tport, int iceTcpPort, size_t inflightCap,
               size_t rateBps = 0, stice_tcp_mux_t* sharedMux = nullptr) {
    // Progress markers (flushed immediately): localize a wedge to a phase when a
    // run has to be killed instead of returning.
    auto mark = [](const char* m) { printf("  [phase] %s\n", m); fflush(stdout); };
    State s;
    auto cfgA = makeCfg(s, true, mode, thost, tport);
    auto cfgB = makeCfg(s, false, mode, thost, tport);

    stice_agent_t *a = stice_create(&cfgA);
    stice_agent_t *b = stice_create(&cfgB);
    if (!a || !b) { if (a) stice_destroy(a); if (b) stice_destroy(b); return {}; }

    // TCP mux for the passive side in tcp-ice. When several pairs run in one
    // process (--pairs) they all share ONE mux: the mux IS the passive-side
    // demultiplexer, so concurrency-testing ICE-TCP means many simultaneous
    // connections through a single listener. A per-pair mux would need a
    // distinct port each (that is what the spawn path does) and would merely
    // re-test N listeners instead of the mux. Only a mux we created here (and
    // not the shared one) is ours to destroy.
    stice_tcp_mux_t* tcpMux = sharedMux;
    bool ownMux = false;
    if (mode == Mode::TcpIce) {
        stice_set_ice_tcp_mode(a, STICE_ICE_TCP_MODE_ACTIVE);
        if (!tcpMux) {
            tcpMux = stice_create_tcp_mux("127.0.0.1", (uint16_t)iceTcpPort);
            ownMux = true;
        }
        if (!tcpMux) { stice_destroy(a); stice_destroy(b); return {}; }
        stice_agent_use_tcp_mux(b, tcpMux);
        stice_set_ice_tcp_mode(b, STICE_ICE_TCP_MODE_PASSIVE);
    }

    if (stice_gather_candidates(b) != STICE_ERR_SUCCESS ||
        stice_gather_candidates(a) != STICE_ERR_SUCCESS) {
        stice_destroy(a); stice_destroy(b); if (tcpMux) stice_destroy_tcp_mux(tcpMux); return {};
    }
    if (!waitFor([&]{ return s.gdA.load() && s.gdB.load(); }, kGatherWaitMs)) {
        mark("gather timeout -> tearing down A");
        stice_destroy(a);
        mark("destroyed A -> tearing down B");
        stice_destroy(b);
        if (ownMux) { mark("destroying tcp_mux"); stice_destroy_tcp_mux(tcpMux); }
        mark("teardown complete");
        return {};
    }
    mark("gathered");
    char bufA[16384], bufB[16384];
    if (stice_get_local_description(a, bufA, sizeof(bufA)) != STICE_ERR_SUCCESS ||
        stice_get_local_description(b, bufB, sizeof(bufB)) != STICE_ERR_SUCCESS) {
        mark("get_local_description failed -> tearing down A");
        stice_destroy(a);
        mark("destroyed A -> tearing down B");
        stice_destroy(b);
        if (ownMux) { mark("destroying tcp_mux"); stice_destroy_tcp_mux(tcpMux); }
        mark("teardown complete");
        return {};
    }
    mark("local-description-read");
    if (mode == Mode::UdpTurn || mode == Mode::TcpTurn) {
        filterNonRelayCandidates(bufA);
        filterNonRelayCandidates(bufB);
    }
    if (stice_set_remote_description(a, bufB) != STICE_ERR_SUCCESS ||
        stice_set_remote_description(b, bufA) != STICE_ERR_SUCCESS) {
        mark("set_remote_description failed -> tearing down A");
        stice_destroy(a);
        mark("destroyed A -> tearing down B");
        stice_destroy(b);
        if (ownMux) { mark("destroying tcp_mux"); stice_destroy_tcp_mux(tcpMux); }
        mark("teardown complete");
        return {};
    }
    stice_set_remote_gathering_done(a);
    stice_set_remote_gathering_done(b);
    mark("remote-description-set");

    Result r;
    auto t0 = std::chrono::steady_clock::now();
    r.connected = waitFor([&]{
        auto as = s.sa.load(), bs = s.sb.load();
        return (as == STICE_STATE_CONNECTED || as == STICE_STATE_COMPLETED) &&
               (bs == STICE_STATE_CONNECTED || bs == STICE_STATE_COMPLETED);
    }, timeoutMs);
    if (!r.connected) {
        r.totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-t0).count();
        mark("connect timeout -> tearing down A");
        stice_destroy(a);
        mark("destroyed A -> tearing down B");
        stice_destroy(b);
        if (ownMux) { mark("destroying tcp_mux"); stice_destroy_tcp_mux(tcpMux); }
        mark("teardown complete");
        return r;
    }
    mark("connected");
    // Print + verify the selected pair so the actually-exercised data path is
    // visible and asserted: TURN modes must select a relayed remote candidate.
    {
        char selLocal[1024], selRemote[1024];
        bool got = false;
        for (int i = 0; i < 20 && !got; ++i) {
            if (stice_get_selected_candidates(a, selLocal, sizeof(selLocal),
                                              selRemote, sizeof(selRemote)) == STICE_ERR_SUCCESS)
                got = true;
            else
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        if (got) {
            printf("  selected pair: local=[%s] remote=[%s]\n", selLocal, selRemote);
            bool remoteRelay = std::strstr(selRemote, "typ relay") != nullptr;
            if ((mode == Mode::UdpTurn || mode == Mode::TcpTurn) && !remoteRelay) {
                printf("  ERROR: TURN mode selected a NON-relay remote pair - relay path not exercised\n");
                r.relayPath = false;
            }
            if ((mode == Mode::UdpIce || mode == Mode::TcpIce) && remoteRelay) {
                printf("  ERROR: non-TURN mode selected a relay pair\n");
                r.relayPath = false;
            }
        } else {
            printf("  WARN: selected pair not available (relay-path NOT verified)\n");
        }
    }
    // Big-data send: A sends `bytes` in `block` chunks. stice_send is non-blocking;
    // loop until all sent or timeout. Measure send completion + B's receive progress.
    std::vector<char> buf(block, 'x');
    size_t sent = 0;
    long sendOk=0, sendAgain=0, sendOther=0;
    auto ts = std::chrono::steady_clock::now();
    while (sent < bytes) {
        if (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-ts).count() > timeoutMs) {
            r.stalled = true; r.sendMs = timeoutMs; break;
        }
        // Rate pacing (optional): never let `sent` run ahead of
        // elapsed * rateBps. On a 2-core VM sharing the box with coturn and
        // both agents, an unpaced 100 MiB flood starves the poll loop and
        // inflates every signalling RTT (observed 4-20s receive windows).
        if (rateBps > 0) {
            long long elMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now()-ts).count();
            size_t allowed = static_cast<size_t>(rateBps) * (elMs + 1) / 1000;
            if (sent >= allowed) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
        }
        // rx-lag backpressure: never run more than inflightCap bytes ahead of
        // the receiver, so its 16MB kernel rcv queue cannot overflow on a
        // scheduling pause (which would silently drop UDP bytes). If bytes
        // are lost anyway, rx stops advancing and the sender stalls here -
        // a loud, diagnosable failure instead of a short count at the end.
        size_t rxv = s.rx.load();
        size_t lag = (sent > rxv) ? sent - rxv : 0;
        if (lag >= inflightCap) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        size_t n = std::min(block, bytes - sent);
        int rc = stice_send(a, buf.data(), n);
        if (rc != STICE_ERR_SUCCESS) {
            if (rc == STICE_ERR_AGAIN) sendAgain++;
            else sendOther++;
            std::this_thread::sleep_for(std::chrono::milliseconds(5)); // queue full, backpressure
            continue;
        }
        sendOk++;
        sent += n;
    }
    if (!r.stalled) r.sendMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-ts).count();
    // Wait for B to receive all; sample receive throughput while waiting.
    auto tr = std::chrono::steady_clock::now();
    size_t rxPeakRate=0; size_t rxLastBytes=0; long long rxLastUs=0;
    auto sampleStart = tr;
    while (s.rx.load() < bytes) {
        auto el = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-tr).count();
        if (el >= timeoutMs) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        auto now = std::chrono::steady_clock::now();
        auto elMs = std::chrono::duration_cast<std::chrono::milliseconds>(now - sampleStart).count();
        size_t cur = s.rx.load();
        if (elMs > 0) {
            size_t rate = (size_t)((cur - rxLastBytes) * 1000 / elMs); // B/s
            if (rate > rxPeakRate) rxPeakRate = rate;
        }
        rxLastBytes = cur; sampleStart = now;
        long long lu = s.lastRecvUs.load();
        if (lu > rxLastUs) rxLastUs = lu;
    }
    r.completed = (s.rx.load() >= bytes);
    r.rx = s.rx.load();
    r.totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-t0).count();
    long long fUs = s.firstRecvUs.load(), lUs = s.lastRecvUs.load();
    printf("  send ok=%ld again=%ld other=%ld | rx_peak=%zu B/s | first_recv_%lldus last_recv_%lldus (recv_window_ms=%lld)\n",
           sendOk, sendAgain, sendOther, rxPeakRate, fUs, lUs,
           (fUs && lUs) ? (lUs - fUs)/1000 : -1LL);
    stice_destroy(a); stice_destroy(b); if (ownMux) stice_destroy_tcp_mux(tcpMux);
    return r;
}

} // namespace

#ifdef _WIN32
// ---- Parallel launcher (--spawn N) ---------------------------------------
// Spawn N child instances of this same executable, all aligned to one common
// wall-clock start barrier, then wait for every child and aggregate exit codes.
// Rationale: process creation from a shell is serialized and slow (~0.5-0.7s
// each), so launching 100-200 clients that way makes them run almost
// sequentially (measured: only 1 of 200 was receiving at the window midpoint),
// which silently under-tests the relay. CreateProcess is ~100x cheaper, so the
// clients genuinely overlap. Each child writes its report to its own file.
static long long wallNowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static int runSpawnMode(int argc, char **argv, int spawnCount,
                        const std::string &outDir, bool logExplicit,
                        stice_log_level_t logLevel, int iceTcpPortBase) {
    std::string self = argv[0];
    std::string baseArgs;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--spawn") { ++i; continue; }
        if (a == "--spawn-out") { ++i; continue; }
        // Replace --tcp-port per child: in tcp-ice each child binds its own
        // passive-side mux, so a shared port would let only one child listen and
        // the rest fail. Each child gets iceTcpPortBase + index.
        if (a == "--tcp-port") { ++i; continue; }
        baseArgs += " ";
        baseArgs += a;
    }
    if (!logExplicit) baseArgs += " --log error";
    long long startAt = wallNowMs() + 15000; // ample for CreateProcess of N children
    std::vector<PROCESS_INFORMATION> pis;
    for (int i = 1; i <= spawnCount; ++i) {
        std::string cmd = "\"" + self + "\"" + baseArgs +
                          " --tcp-port " + std::to_string(iceTcpPortBase + (i - 1)) +
                          " --start-at " + std::to_string(startAt);
        if (!outDir.empty())
            cmd += " --out-file \"" + outDir + "\\c" + std::to_string(i) + ".log\"";
        std::vector<char> mutableCmd(cmd.begin(), cmd.end());
        mutableCmd.push_back('\0');
        STARTUPINFOA si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (!CreateProcessA(nullptr, mutableCmd.data(), nullptr, nullptr, FALSE,
                            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            std::fprintf(stderr, "spawn %d failed: %lu\n", i, GetLastError());
            continue;
        }
        pis.push_back(pi);
    }
    auto t0 = std::chrono::steady_clock::now();
    int pass = 0, fail = 0;
    for (auto &pi : pis) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD code = 1;
        GetExitCodeProcess(pi.hProcess, &code);
        if (code == 0) ++pass; else ++fail;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    auto wall = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    std::printf("SPAWN-RESULT clients=%d pass=%d fail=%d wall_ms=%lld\n",
                (int)pis.size(), pass, fail, (long long)wall);
    std::fflush(stdout);
    return fail ? 1 : 0;
}
#endif

int main(int argc, char** argv) {
    Mode mode = Mode::UdpIce;
    size_t bytes = 104857600;
    size_t block = 1200;
    int timeoutMs = 60000;
    std::string thost = "127.0.0.1";
    uint16_t tport = 3478;
    int iceTcpPort = 44444;
    long long durationSec = 0; // 0 = single round
    size_t inflightCap = 4 * 1024 * 1024; // rx-lag backpressure cap
    size_t rateMiB = 0; // --rate MiB/s pacing cap, 0 = unpaced
    long long startAtMs = 0; // --start-at <epoch_ms>: absolute wall-clock barrier
    int spawnCount = 0;      // --spawn N: run N aligned children and aggregate
    int pairs = 0;           // --pairs N: N concurrent pairs in ONE process
                             // (shared mux for tcp-ice) - the correct way to
                             // concurrency-test ICE-TCP without N processes.
    std::string spawnOutDir; // --spawn-out <dir>: per-child log directory
    std::string outFile;     // --out-file <path>: write this client's report to a file
    bool logExplicit = false;
    stice_log_level_t logLevel = STICE_LOG_LEVEL_WARN;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--mode" && i+1 < argc) { std::string m = argv[++i];
            if (m=="udpturn") mode=Mode::UdpTurn; else if (m=="tcpturn") mode=Mode::TcpTurn;
            else if (m=="tcp-ice") mode=Mode::TcpIce; else mode=Mode::UdpIce; }
        else if (a=="--bytes" && i+1<argc) bytes = (size_t)strtoull(argv[++i],nullptr,10);
        else if (a=="--block" && i+1<argc) block = (size_t)strtoull(argv[++i],nullptr,10);
        else if (a=="--timeout" && i+1<argc) timeoutMs = atoi(argv[++i]);
        else if (a=="--turn-host" && i+1<argc) thost = argv[++i];
        else if (a=="--turn-port" && i+1<argc) tport = (uint16_t)atoi(argv[++i]);
        else if (a=="--tcp-port" && i+1<argc) iceTcpPort = atoi(argv[++i]);
        else if (a=="--inflight" && i+1<argc) inflightCap = (size_t)strtoull(argv[++i],nullptr,10);
        else if (a=="--rate" && i+1<argc) rateMiB = (size_t)strtoull(argv[++i],nullptr,10);
        else if (a=="--duration" && i+1<argc) durationSec = atoll(argv[++i]);
        else if (a=="--start-at" && i+1<argc) startAtMs = atoll(argv[++i]);
        else if (a=="--spawn" && i+1<argc) spawnCount = atoi(argv[++i]);
        else if (a=="--pairs" && i+1<argc) pairs = atoi(argv[++i]);
        else if (a=="--spawn-out" && i+1<argc) spawnOutDir = argv[++i];
        else if (a=="--out-file" && i+1<argc) outFile = argv[++i];
        else if (a=="--log" && i+1<argc) { std::string l = argv[++i]; logExplicit = true;
            if (l=="verbose") logLevel=STICE_LOG_LEVEL_VERBOSE;
            else if (l=="debug") logLevel=STICE_LOG_LEVEL_DEBUG;
            else if (l=="info") logLevel=STICE_LOG_LEVEL_INFO;
            else if (l=="error") logLevel=STICE_LOG_LEVEL_ERROR;
            else if (l=="fatal") logLevel=STICE_LOG_LEVEL_FATAL;
            else if (l=="none") logLevel=STICE_LOG_LEVEL_NONE;
            else logLevel=STICE_LOG_LEVEL_WARN; }
    }
    // ---- Parallel launcher mode: fork N aligned clients and aggregate ----
    if (spawnCount > 0) {
#ifdef _WIN32
        return runSpawnMode(argc, argv, spawnCount, spawnOutDir, logExplicit, logLevel, iceTcpPort);
#else
        std::fprintf(stderr, "--spawn is Windows-only\n");
        return 1;
#endif
    }
    // Redirect this client's own report to a file when run as a spawned child,
    // so a 100-200 client run does not interleave N reports on one console.
    if (!outFile.empty()) {
        if (!logExplicit) logLevel = STICE_LOG_LEVEL_ERROR;
        if (!std::freopen(outFile.c_str(), "w", stdout)) {
            std::fprintf(stderr, "cannot open out-file %s\n", outFile.c_str());
        }
    }
    // tcpturn: RFC6062 via env (same as sendfile/libdatachannel path)
    if (mode == Mode::TcpTurn) {
#if defined(_WIN32)
        _putenv_s("JUICE_TURN_TCP_NO_FRAMING", "1");
        _putenv_s("STICE_TURN_TCP_RFC6062", "1");
#else
        setenv("JUICE_TURN_TCP_NO_FRAMING", "1", 1);
        setenv("STICE_TURN_TCP_RFC6062", "1", 1);
#endif
    }
    stice_set_log_level(logLevel);
    // Unbuffered stdout: when a run wedges, buffered output is lost on kill and
    // the failure is undiagnosable. Progress markers below assume this.
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    static const auto g_logT0 = std::chrono::steady_clock::now();
    stice_set_log_handler([](stice_log_level_t level, const char *msg) {
        const char* tag = "?";
        switch (level) {
        case STICE_LOG_LEVEL_VERBOSE: tag = "VRB"; break;
        case STICE_LOG_LEVEL_DEBUG:    tag = "DBG"; break;
        case STICE_LOG_LEVEL_INFO:     tag = "INF"; break;
        case STICE_LOG_LEVEL_WARN:    tag = "WRN"; break;
        case STICE_LOG_LEVEL_ERROR:   tag = "ERR"; break;
        case STICE_LOG_LEVEL_FATAL:   tag = "FTL"; break;
        default: break;
        }
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - g_logT0).count();
        std::fprintf(stderr, "[%lldms %s] %s\n", (long long)ms, tag, msg ? msg : "");
        std::fflush(stderr);
    });

    // Concurrency barrier: wait until an absolute wall-clock instant before
    // starting. A multi-process launcher cannot start N processes
    // simultaneously (process creation is serialized, ~0.5s each), so without
    // this the clients execute almost sequentially and never actually contend.
    // The launcher passes a common --start-at; every client then begins its
    // gather/connect/send phase at the same moment.
    if (startAtMs > 0) {
        auto nowMs = [&] {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        };
        while (nowMs() < startAtMs) {
            long long remain = startAtMs - nowMs();
            std::this_thread::sleep_for(std::chrono::milliseconds(remain > 20 ? 10 : 1));
        }
    }

    // ---- In-process multi-pair mode (--pairs N) --------------------------
    // N pairs run concurrently on N threads in THIS process. For tcp-ice they
    // all share a single TCP mux (one passive listener), which is exactly the
    // concurrency the mux must handle; running N processes instead would bind N
    // listeners (see --spawn, which hands each child its own --tcp-port).
    if (pairs > 1) {
        stice_tcp_mux_t* sharedMux = nullptr;
        if (mode == Mode::TcpIce) {
            sharedMux = stice_create_tcp_mux("127.0.0.1", (uint16_t)iceTcpPort);
            if (!sharedMux) {
                std::fprintf(stderr, "cannot create shared tcp mux on 127.0.0.1:%d\n", iceTcpPort);
                return 1;
            }
        }
        std::vector<Result> results((size_t)pairs);
        std::vector<std::thread> threads;
        threads.reserve((size_t)pairs);
        auto tp0 = std::chrono::steady_clock::now();
        for (int i = 0; i < pairs; ++i) {
            threads.emplace_back([&, i] {
                results[(size_t)i] = runPair(mode, bytes, block, timeoutMs, thost.c_str(),
                                             tport, iceTcpPort, inflightCap,
                                             rateMiB * 1024 * 1024, sharedMux);
            });
        }
        for (auto &t : threads) t.join();
        if (sharedMux) stice_destroy_tcp_mux(sharedMux);
        auto wall = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - tp0).count();
        int pass = 0, fail = 0;
        size_t rxTot = 0;
        std::string failList;
        for (int i = 0; i < pairs; ++i) {
            const Result &r = results[(size_t)i];
            bool ok = r.connected && r.completed && !r.stalled && r.relayPath && r.rx >= bytes;
            if (ok) ++pass; else { ++fail; failList += " " + std::to_string(i + 1); }
            rxTot += r.rx;
        }
        size_t exp = (size_t)pairs * bytes;
        std::printf("PAIRS-RESULT mode=%s pairs=%d pass=%d fail=%d rxsum=%zu expected=%zu loss=%lld wall_ms=%lld\n",
                    modeName(mode), pairs, pass, fail, rxTot, exp,
                    (long long)(exp - rxTot), (long long)wall);
        if (fail) std::printf("  failing pairs:%s\n", failList.c_str());
        std::fflush(stdout);
        return fail ? 1 : 0;
    }

    if (durationSec <= 0) {
        Result r = runPair(mode, bytes, block, timeoutMs, thost.c_str(), tport, iceTcpPort,
                           inflightCap, rateMiB * 1024 * 1024);

        printf("RESULT mode=%s connected=%d completed=%d stalled=%d relay_path=%d\n",
               modeName(mode), (int)r.connected, (int)r.completed, (int)r.stalled, (int)r.relayPath);
        printf("  bytes=%zu block=%zu sent_ms=%ld total_ms=%ld rx=%zu\n", bytes, block, r.sendMs, r.totalMs, r.rx);
        printf("  %s\n", (r.connected && r.completed && r.relayPath) ? "PASS" : "FAIL");
        return (r.connected && r.completed && r.relayPath) ? 0 : 1;
    }

    // Duration mode: loop full connect/transfer/destroy rounds until the wall
    // clock reaches --duration. Stop at the first failing round (long-test
    // policy: a problem stops the run) and report.
    auto tStart = std::chrono::steady_clock::now();
    long long elapsed = 0;
    int round = 0, fails = 0;
    size_t totalRx = 0;
    size_t rssFirst = currentRssMb(), rssMax = rssFirst;
    while (true) {
        elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - tStart).count();
        if (elapsed >= durationSec) break;
        ++round;
        Result r = runPair(mode, bytes, block, timeoutMs, thost.c_str(), tport, iceTcpPort,
                           inflightCap, rateMiB * 1024 * 1024);
        totalRx += r.rx;
        size_t rss = currentRssMb();
        if (rss > rssMax) rssMax = rss;
        bool ok = r.connected && r.completed && !r.stalled && r.relayPath && r.rx >= bytes;
        if (!ok) ++fails;
        printf("ROUND %d ok=%d elapsed=%llds round_ms=%ld rx_total=%zu rss=%zuMB (max %zuMB)\n",
               round, (int)ok, elapsed, r.totalMs, totalRx, rss, rssMax);
        fflush(stdout);
        if (!ok) {
            printf("ROUND %d FAILED: connected=%d completed=%d stalled=%d rx=%zu/%zu - stopping long test\n",
                   round, (int)r.connected, (int)r.completed, (int)r.stalled, r.rx, bytes);
            fflush(stdout);
            break;
        }
    }
    printf("SUMMARY mode=%s duration=%llds rounds=%d fails=%d rx_total=%zu rss_first=%zuMB rss_max=%zuMB\n",
           modeName(mode), elapsed, round, fails, totalRx, rssFirst, rssMax);
    printf("  %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
