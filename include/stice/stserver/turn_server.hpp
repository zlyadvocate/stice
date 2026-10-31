// SPDX-License-Identifier: MPL-2.0
// stserver TURN/STUN server core. Implements STUN Binding (RFC 5389),
// TURN Allocate/Refresh/CreatePermission/ChannelBind/Send/Data (RFC 8656),
// TURN over TCP framing, and RFC 6062 Mode-B (CONNECT/CONNECTION-ATTEMPT/
// CONNECTION-BIND). Designed to replace coturn for stice interop testing.
//
// IO is handled by an abstract IoBackend (see io_backend.hpp). The backend
// can be select-based (B plan: control/data plane separation with thread
// pool) or IOCP/epoll-based (D plan: kernel-level async IO), selected at
// compile time via STSERVER_IOCP. All shared state is protected by a
// shared_mutex since callbacks fire from multiple worker threads.

#ifndef STSERVER_TURN_SERVER_HPP
#define STSERVER_TURN_SERVER_HPP

#include "stice/net/addr.hpp"
#include "stice/net/platform.hpp"
#include "stice/net/udp.hpp"
#include "stice/stun/message.hpp"
#include "stice/stserver/io_backend.hpp"
#include "stice/turn/stunconn.hpp"

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

struct Config;

namespace stserver {

// A permission associates a peer IP address with an allocation (RFC 8656 §2.5).
// Port is ignored when matching incoming relayed data to a permission.
struct Permission {
	stice::net::AddrRecord peer;
	std::int64_t expiryMs = 0;
};

// A channel binds a channel number to a peer (full IP:port) on an allocation.
struct Channel {
	std::uint16_t number = 0;
	stice::net::AddrRecord peer;
	std::int64_t expiryMs = 0;
};

struct Allocation {
	int transport = 0;                          // SOCK_DGRAM or SOCK_STREAM
	stice::net::AddrRecord clientAddr;                 // 5-tuple client endpoint
	socket_t controlSock = STICE_INVALID_SOCKET; // TCP control socket (INVALID for UDP)
	stice::net::UdpSocket relaySock;                   // UDP relay socket (invalid for TCP alloc)
	stice::net::AddrRecord relayedAddr;                // XOR-RELAYED-ADDRESS value
	std::uint16_t relayPort = 0;
	std::string username;
	std::vector<Permission> permissions;
	std::vector<Channel> channels;
	std::int64_t expiryMs = 0;

	// Per-allocation lock: the ONE mutex shared by the IO data plane and the
	// control plane for the containers below (channels, permissions). The IO
	// fast path (handleChannelDataFrame / forwardToClient, on reader threads)
	// traverses channels/permissions and does NOT hold stateMutex_, so
	// stateMutex_ alone cannot serialize against it. Every writer
	// (handleCreatePermission, handleChannelBind, handleSendIndication's read,
	// expireStale's per-allocation cleanup) therefore takes this lock too.
	// Different allocations still run fully in parallel.
	//
	// Lock order: stateMutex_ -> mtx. Never take stateMutex_ while holding mtx,
	// and never call destroyAllocation() while holding mtx (it waits for
	// in-flight IO references, and an IO thread holding one may be blocked on
	// mtx -> deadlock).
	std::mutex mtx;

	// RFC 6062 pending connects (TCP allocations only). A CONNECT request
	// from the local client creates a PendingConnect; the held CONNECT
	// success response is flushed once the peer binds with CONNECTION-BIND.
	struct PendingConnect {
		std::uint32_t connId = 0;
		stice::net::AddrRecord peerRelayAddr;
		socket_t firstDataSock = STICE_INVALID_SOCKET; // first CONNECTION-BIND socket
		std::array<unsigned char, 12> connectTid{};     // CONNECT transaction id (response held)
		bool connectResponded = false;                  // CONNECT success already sent
		std::int64_t expiryMs = 0;
	};
	std::vector<PendingConnect> pendingConnects;

	// IO fast-path lifetime guard. IO threads bump ioUsers_ before touching an
	// Allocation returned from a lookup map (ioOnUdpData / ioOnRelayData), then
	// allocUnref() after use. destroyAllocation sets dying_ under the map locks
	// and waits for ioUsers_==0 before freeing. Closes the take-pointer->
	// unlock->deref race (UAF) between the parallel data plane and the
	// control plane that destroys allocations.
	std::atomic<int> ioUsers_{0};
	std::atomic<bool> dying_{false};
};

// A TCP connection: either a TURN control connection (RFC 8656 §3 over TCP)
// or an RFC 6062 data connection (after CONNECTION-BIND). Uses stice's
// StunConn for self-delimiting STUN/ChannelData framing.
struct TcpConn {
	socket_t sock = STICE_INVALID_SOCKET;
	stice::net::AddrRecord peerAddr;
	stice::turn::StunConn stunConn;
	std::atomic<bool> isData{false}; // true after CONNECTION-BIND (raw data pipe); atomic (P0: IO thread reads, business thread writes)
	std::uint32_t connId = 0;     // for data connections: the bound CONNECTION-ID
	std::vector<unsigned char> writeBuf; // pending bytes for non-blocking send
	// Bytes at the front of writeBuf that have already been handed to send().
	// Tracking an offset instead of erasing the prefix avoids an O(n) memmove on
	// every partial send (the TCP data path used to erase from the front).
	std::size_t writeOff = 0;
	// RFC 6062 data connections are a transparent byte pipe, but for a
	// CONNECTION-ID the pipe only becomes usable once BOTH data connections
	// have sent CONNECTION-BIND (the pair is published in handleConnectionBind).
	// Data that arrives on the half-bound connection during that window is
	// buffered here and flushed when the pair is published, instead of being
	// dropped -- dropping it discarded the peer's first ICE connectivity check.
	// RFC 6062 requires this: "Data received on the associated peer data
	// connection MUST be sent as-is ... This includes data that was received
	// ... before this ConnectionBind request was received" (Section 5.4), and
	// Section 5.2/5.3 say the server MUST buffer data received before the bind.
	// A local-policy cap applies (Section 7): exceeding it closes the
	// connection rather than growing without bound.
	//
	// Appended by the shard that owns this connection, flushed by the business
	// thread when the pair is published. Both sides hold prePairMtx and re-check
	// the pairing state inside it: if the flush wins, the shard forwards instead
	// of buffering; if the append wins, the flush sends the buffered prefix. That
	// closes the window where a chunk appended just after the flush would stay
	// stuck in the buffer forever.
	std::vector<unsigned char> prePairBuf;
	std::mutex prePairMtx;
	// Serializes the non-blocking write state (writeBuf/writeOff + send() +
	// write-pending arming). The RFC 6062 data-pipe fast path writes to a peer
	// connection directly on the IO worker thread, concurrently with the
	// business thread (writability flushes / control-frame writes), so this can
	// no longer be implicit in "the business thread is the only writer".
	std::mutex writeMtx;
	// IO fast-path lifetime guard, same protocol as Allocation::ioUsers_/dying_.
	// dataPipePeerRef() bumps ioUsers_ before an IO thread dereferences the
	// connection; closeTcpConn() sets dying_ and waits for ioUsers_==0 before
	// freeing. Without this the parallel data plane could dereference a
	// connection the business thread just destroyed (UAF).
	std::atomic<int> ioUsers{0};
	std::atomic<bool> dying{false};
};

struct AddrHash {
	std::size_t operator()(const stice::net::AddrRecord &a) const {
		return static_cast<std::size_t>(a.hash(true));
	}
};

class TurnServer : public IoBackendOwner {
public:
	TurnServer();
	~TurnServer();
	TurnServer(const TurnServer &) = delete;
	TurnServer &operator=(const TurnServer &) = delete;

	// Set up listeners and state from `cfg`. Returns false on fatal error.
	bool init(const Config &cfg);
	// Start the IO backend and block until stop() is called. stop() is
	// signal-handler-safe (just sets an atomic flag); this method joins the
	// worker threads after the flag is set.
	void run();
	// Request shutdown (thread-safe, signal-handler-safe). Sets running_
	// to false; run() will then join the backend threads and return.
	void stop() { running_ = false; }

	// Set the number of IO worker threads (must be called before init()).
	void setWorkerCount(int n) { workerCount_ = std::max(1, n); }

private:
	// ---- IoBackendOwner callbacks (called from IO worker threads) ----
	void ioOnUdpData(const unsigned char *data, std::size_t len,
	                 const stice::net::AddrRecord &from) override;
	void ioOnTcpAccepted(socket_t sock, const stice::net::AddrRecord &peer) override;
	void ioOnRelayData(socket_t relaySock, const unsigned char *data,
	                   std::size_t len, const stice::net::AddrRecord &from) override;
	void ioOnTcpConnData(socket_t connSock, const unsigned char *data,
	                     std::size_t len) override;
	void ioOnTcpConnClosed(socket_t connSock) override;
	void ioOnTcpConnWritable(socket_t connSock) override;
	void ioOnTimerTick() override;

	// ---- Allocation key/lookup ----
	// 5-tuple key string: "U|<ip>:<port>" (UDP) or "T|<ip>:<port>" (TCP).
	std::string allocKey(int transport, const stice::net::AddrRecord &client) const;
	Allocation *findAlloc(const std::string &key) const;
	Allocation *findAllocByRelaySock(socket_t s) const;
	Allocation *findTcpAllocByPeer(const stice::net::AddrRecord &peerRelayAddr,
	                               const Allocation *exclude) const;
	Allocation *findPendingByConnId(std::uint32_t connId,
	                                Allocation::PendingConnect **outPc = nullptr);
	// Remove an allocation from all lookup maps, release its relay port
	// (ownership-checked) and erase it. Must be called with stateMutex_ held.
	void destroyAllocation(Allocation *a);

	// ---- Relay port allocation ----
	// Reserve an unused relay port, avoiding both ports already reserved by
	// live allocations and the per-attempt `avoid` set (ports whose bind
	// failed earlier in the same Allocate — prevents retrying unbindable
	// ports). Returns 0 when the range is exhausted.
	std::uint16_t allocRelayPort(const std::set<std::uint16_t> &avoid);
	// Release a relay port owned by `owner`. Ownership is checked so a
	// double release (or a release on behalf of a different allocation)
	// cannot free a port still in use (ports are unique per allocation).
	void releaseRelayPort(std::uint16_t port, const Allocation *owner);
	// Build the relayed AddrRecord advertised to clients, using the server's
	// externally-reachable IP (falls back to loopback for 0.0.0.0 binds).
	bool buildRelayedAddr(std::uint16_t port, stice::net::AddrRecord &out) const;

	// ---- Authentication ----
	void refreshNonce();
	// Returns 0 on success, 401 (unauthenticated), or 438 (stale nonce).
	int authenticate(const stice::stun::Message &msg, std::string &outUsername);

	// ---- Response builders / senders ----
	void sendUdp(const stice::net::AddrRecord &dst, const stice::stun::Message &msg);
	void sendTcp(TcpConn &conn, const stice::stun::Message &msg);
	void sendTcpRaw(TcpConn &conn, const unsigned char *data, std::size_t size);
	bool flushTcp(TcpConn &conn);
	// Locked variants: the caller already holds conn.writeMtx. The fast path
	// (ioOnTcpConnData on an IO worker thread) takes the lock once and then
	// calls these, so the write state cannot interleave with the business
	// thread's flushes.
	void sendTcpRawLocked(TcpConn &conn, const unsigned char *data, std::size_t size);
	bool flushTcpLocked(TcpConn &conn);
	void sendErrorResponseUdp(const stice::net::AddrRecord &dst,
	                           const stice::stun::Message &req, int code);
	void sendAuthErrorResponse(const stice::net::AddrRecord &dst,
	                           const stice::stun::Message &req, int code);
	void sendErrorResponseTcp(TcpConn &conn, const stice::stun::Message &req, int code);
	void sendAuthErrorResponseTcp(TcpConn &conn, const stice::stun::Message &req, int code);
	void sendSuccessResponse(const stice::stun::Message &req, const std::string &username,
	                         stice::stun::Message &resp);

	// ---- STUN/TURN request dispatch ----
	void handleUdpPacket(const unsigned char *data, std::size_t size,
	                     const stice::net::AddrRecord &src);
	void handleTcpFrame(TcpConn &conn, socket_t connSock, const unsigned char *data,
	                    std::size_t size);
	void dispatchStun(stice::stun::Message &msg, const stice::net::AddrRecord &src,
	                  TcpConn *tcpConn, Allocation *alloc);

	// ---- Business dispatch (control queue) ----
	// IO callbacks never process work inline on the hot media path. The single
	// business thread drains one control FIFO (STUN/TURN control: UDP listener
	// data, TCP accepts, closes) in arrival order. Bulk TCP media — control
	// connection ChannelData/STUN frames, RFC 6062 data pipes, relay->client
	// forwarding for TCP-control allocations and write flushes — is routed to
	// the data shards instead (see DataShard).
	struct WorkItem {
		enum class Kind {
			UdpData,
			TcpAccepted,
			RelayData,
			TcpConnData,
			TcpConnClosed,
			TcpConnWritable,
		};
		Kind kind = Kind::UdpData;
		socket_t sock = STICE_INVALID_SOCKET;
		stice::net::AddrRecord from;
		std::vector<unsigned char> data;
	};

	// A TCP data shard: its own FIFO and thread. Bulk TCP media (control-conn
	// ChannelData/STUN frames and RFC 6062 data pipes, both directions) is
	// routed to exactly one shard per socket, so per-connection byte order is
	// preserved without any cross-thread parse buffer, and media never takes
	// stateMutex_. Previously all of it funnelled through the single business
	// thread under stateMutex_, which capped TCP relay throughput at one core
	// and let a large data batch delay STUN/TURN transactions.
	struct DataShard {
		std::deque<WorkItem> queue;
		std::mutex mtx;
		std::condition_variable cv;
		std::thread thread;
	};
	// IO fast-path lookups that take a lifetime reference (caller must
	// allocUnref). Return nullptr if not found or dying.
	Allocation *findAllocByClientRef(const stice::net::AddrRecord &addr);
	Allocation *findAllocByRelayRef(socket_t relaySock);
	// Look up an allocation by the relayed transport address it advertises
	// (XOR-RELAYED-ADDRESS). Used for the local-relay shortcut: when a relaying
	// client's peer address is one of THIS server's own relayed addresses, the
	// datagram is delivered directly instead of being sent out and received back
	// through the kernel loopback (halves the relay's syscalls per frame).
	Allocation *findAllocByRelayAddrRef(const stice::net::AddrRecord &addr);
	void allocUnref(Allocation *a);

	void enqueueControl(WorkItem &&item);
	void businessLoop();
	void processItem(const WorkItem &item);
	void registerTcpConn(socket_t sock, const stice::net::AddrRecord &peer);
	void handleTcpConnData(socket_t connSock, const unsigned char *data, std::size_t len);
	// RFC 6062 §5.2/5.3/5.4: bytes that arrive on a data connection before its
	// pair is published are buffered (appendPrePair) and forwarded as soon as
	// the pair exists (flushPrePair). Both hold conn.prePairMtx.
	void appendPrePair(TcpConn &conn, socket_t connSock, const unsigned char *data,
	                   std::size_t len);
	void flushPrePair(TcpConn &conn);
	// ---- TCP data shards ----
	// Bulk TCP media runs on shard threads instead of the business thread. A
	// socket always maps to the same shard (shardIndexFor is a pure function of
	// the handle), so every chunk of a connection is parsed and forwarded in
	// arrival order by one thread, with no lock on the parse buffer.
	int shardIndexFor(socket_t s) const;
	void enqueueToShard(int idx, WorkItem &&item);
	void shardLoop(int idx);
	void processShardItem(const WorkItem &item);
	// Lifetime-taking lookups for the shard threads (caller must release with
	// connUnref / allocUnref). Guarded by connMapMutex_, never stateMutex_.
	TcpConn *tcpConnRef(socket_t s);
	Allocation *findAllocByControlSockRef(socket_t s);
	// Ask the business thread to tear a connection down. Used by the shards
	// instead of calling closeTcpConn() directly: the shard may be holding a
	// lifetime reference to that connection, and closeTcpConn waits for it to
	// drain.
	void enqueueCloseConn(socket_t s);
	// Destroys connections whose ioUsers reached zero. Runs outside stateMutex_
	// (business thread, after a batch) so a shard blocked on stateMutex_ for a
	// control frame cannot deadlock against the free.
	void reapPendingConns();
	// RFC 6062 data-pipe fast path: resolve the peer connection of a paired data
	// socket and take a lifetime reference on it (the caller MUST call
	// connUnref()). Returns nullptr when the socket is not (yet) a paired data
	// pipe, in which case the caller buffers into prePairBuf under prePairMtx.
	TcpConn *dataPipePeerRef(socket_t connSock);
	void connUnref(TcpConn *conn);

	void handleBinding(stice::stun::Message &req, const stice::net::AddrRecord &src,
	                   TcpConn *tcpConn);
	void handleAllocate(stice::stun::Message &req, const stice::net::AddrRecord &src,
	                    TcpConn *tcpConn, Allocation *alloc);
	void handleRefresh(stice::stun::Message &req, const stice::net::AddrRecord &src,
	                   TcpConn *tcpConn, Allocation *alloc);
	void handleCreatePermission(stice::stun::Message &req, const stice::net::AddrRecord &src,
	                            TcpConn *tcpConn, Allocation *alloc);
	void handleChannelBind(stice::stun::Message &req, const stice::net::AddrRecord &src,
	                       TcpConn *tcpConn, Allocation *alloc);
	void handleSendIndication(stice::stun::Message &req, Allocation *alloc);
	void handleChannelDataFrame(const unsigned char *data, std::size_t size,
	                            Allocation *alloc);
	void handleConnect(stice::stun::Message &req, TcpConn *tcpConn, Allocation *alloc);
	void handleConnectionBind(stice::stun::Message &req, TcpConn *tcpConn);

	// ---- Relay data forwarding (peer -> client) ----
	void forwardToClient(Allocation &alloc, const stice::net::AddrRecord &peer,
	                     const unsigned char *data, std::size_t size);
	void sendConnectionAttempt(Allocation &targetAlloc,
	                           std::uint32_t connId, const stice::net::AddrRecord &peerRelayAddr);

	// ---- TCP connection management ----
	void closeTcpConn(TcpConn *conn);

	// ---- Expiry ----
	std::int64_t nowMs() const;
	void expireStale();

	// ---- Config / state ----
	std::string listenAddress_;
	std::uint16_t udpPort_ = 3478;
	std::uint16_t tcpPort_ = 3478;
	std::string realm_;
	std::map<std::string, std::string> users_;
	int maxAllocations_ = 2000;
	std::uint32_t allocationLifetime_ = 600;
	std::uint16_t relayPortBegin_ = 49152;
	std::uint16_t relayPortEnd_ = 65535;
	int workerCount_ = 4;
	// Externally-reachable server IP for XOR-RELAYED-ADDRESS (loopback when
	// the listener is 0.0.0.0).
	std::string relayIp_;
	// sockaddr form of relayIp_ for building relayed AddrRecords.
	struct sockaddr_storage relayIpAddr_;
	socklen_t relayIpLen_ = 0;

	// Long-term credential nonce (RFC 5389 §15.4). Refreshed periodically.
	std::string nonce_;
	std::int64_t nonceExpiryMs_ = 0;
	// Nonce lifetime (ms). Default 30 min (RFC 5389 §15.4 recommendation);
	// configurable via Config::nonceLifetimeSec so tests can drive the
	// rotation window quickly.
	std::int64_t nonceLifetimeMs_ = 30 * 60 * 1000;

	// Listeners.
	stice::net::UdpSocket udpListener_;
	socket_t tcpListener_ = STICE_INVALID_SOCKET;

	// IO backend (B plan: select + thread pool, D plan: IOCP/epoll).
	std::unique_ptr<IoBackend> ioBackend_;

	// Shared state mutex. All allocation/TCP state below is mutated only on
	// the business thread; IO worker threads take this lock briefly for
	// read-only lookups (tcpBySock_ classification). recursive_mutex is kept
	// because business handlers re-enter locking helpers (e.g. closeTcpConn
	// from handleTcpConnData during frame processing).
	mutable std::recursive_mutex stateMutex_;

	// Guards allocByRelaySock_ for the parallel relay data-plane fast path
	// (relay workers look up the allocation by relay socket concurrently with
	// the business thread inserting/erasing it). Shared: lookups run on every
	// relayed packet from all IO workers, so an exclusive lock here serialized
	// the whole data plane and capped stserver at roughly 60-80k pps (the 128
	// MiB/s / 1200-byte case dropped ~50% at the inbound socket once the
	// workers blocked on this lock).
	mutable std::shared_mutex relayMapMutex_;

	// Client 5-tuple -> allocation, for the ChannelData fast path. IO workers
	// read this concurrently with the business thread. Guarded by its OWN mutex
	// (clientMapMutex_) so the ChannelData lookup never contends with the relay
	// socket lookup (relayMapMutex_) that relay workers take on every packet.
	std::unordered_map<stice::net::AddrRecord, Allocation*, AddrHash> allocByClientAddr_;
	mutable std::shared_mutex clientMapMutex_;

	// Allocations: owned by unique_ptr (stable pointers) in a map keyed by
	// the 5-tuple string. Reverse-lookup maps hold raw pointers.
	std::map<std::string, std::unique_ptr<Allocation>> allocations_;
	std::map<socket_t, Allocation *> allocByRelaySock_;
	// Relayed transport address -> allocation, for the local-relay shortcut.
	// Guarded by relayMapMutex_ (same as allocByRelaySock_).
	std::unordered_map<stice::net::AddrRecord, Allocation *, AddrHash> allocByRelayAddr_;
	std::map<socket_t, Allocation *> allocByControlSock_;
	std::map<std::uint32_t, Allocation *> pendingByConnId_;
	// Relay port reservation with ownership: port -> owning allocation.
	// A port is released only by its owner, so ports stay unique per
	// allocation and cannot be double-released.
	std::map<std::uint16_t, const Allocation *> usedRelayPorts_;
	std::uint32_t nextConnId_ = 1;

	// TCP connections (control + data). Owned by unique_ptr for stability.
	std::vector<std::unique_ptr<TcpConn>> tcpConns_;
	std::map<socket_t, TcpConn *> tcpBySock_;                 // sock -> connection
	std::map<socket_t, socket_t> dataPipe_;                    // RFC 6062 data pairing
	// Socket -> peer TcpConn* of an RFC 6062 data pipe, consulted by IO worker
	// threads in ioOnTcpConnData() (parallel relay fast path). Guarded by its
	// OWN mutex: the TCP data plane must not take stateMutex_, which the
	// business thread holds for the whole duration of every queue item.
	// Lifetime of the pointed-to TcpConn is protected by TcpConn::ioUsers_/dying_.
	std::map<socket_t, TcpConn *> dataPipePeer_;
	mutable std::mutex pipeMapMutex_;

	// Guards tcpBySock_ and allocByControlSock_, and gates TcpConn lifetime for
	// the shard threads. Writers (accept / close / allocate / destroy) run on the
	// business thread under stateMutex_ and take this uniquely; shard threads take
	// it shared and bump TcpConn::ioUsers before dereferencing. Lock order is
	// stateMutex_ -> connMapMutex_ -> Allocation::mtx -> TcpConn::writeMtx; no
	// shard ever takes stateMutex_ while holding connMapMutex_ or a TcpConn ref.
	mutable std::shared_mutex connMapMutex_;

	// TCP data shards (see DataShard).
	std::vector<std::unique_ptr<DataShard>> shards_;
	int shardCount_ = 4;
	// Connections unlinked from the maps but still referenced by a shard. Freed
	// on the business thread once ioUsers drops to zero (see reapPendingConns).
	std::vector<std::unique_ptr<TcpConn>> pendingFreeConns_;

	// Business dispatch queue (see WorkItem). Guarded by queueMutex_. Only
	// control-plane work lands here; bulk TCP media runs on the shards.
	std::deque<WorkItem> controlQueue_;
	mutable std::mutex queueMutex_;
	// NOTE: there is intentionally NO send mutex for udpListener_. The control
	// responses (sendUdp) and the relay data plane (forwardToClient, on several
	// reader threads) both send on it concurrently; Winsock sendto on a UDP
	// socket is thread-safe, and the data plane already relies on that. A mutex
	// used by only one of the two paths (as before) provided no safety while
	// implying protection that did not exist.
	std::condition_variable queueCv_;
	std::thread businessThread_;

	// Deferred-free wait: destroyAllocation() waits for in-flight IO fast-path
	// references (Allocation::ioUsers_) to drop before freeing. The wait is
	// event-driven rather than a bare yield-spin, and allocUnref() only signals
	// when a waiter is actually present (ioUsersWaiters_) so the per-packet
	// unref on the data plane stays a single atomic operation.
	mutable std::mutex ioUsersMutex_;
	std::condition_variable ioUsersCv_;
	std::atomic<int> ioUsersWaiters_{0};

	std::atomic<bool> running_{false};

	// DIAG relay accounting: bytes read from relay sockets by IO threads
	// (relayReadBytes_) vs bytes handed to forwardToClient (forwardBytes_).
	// Hot counters are cache-line padded so the 8 relay workers hammering
	// relayReadBytes_/forwardBytes_ concurrently do not false-share, and all
	// hot increments use memory_order_relaxed (they are diagnostics only).
	alignas(64) std::atomic<std::uint64_t> relayReadBytes_{0};
	alignas(64) std::atomic<std::uint64_t> forwardBytes_{0};
	// Bytes relayed through an RFC 6062 data pipe (the raw TCP media path). The
	// two counters above only see UDP relay sockets, so without this the TCP
	// data-pipe throughput is invisible in RELAY-STAT.
	alignas(64) std::atomic<std::uint64_t> pipeBytes_{0};
	std::atomic<std::uint64_t> forwardOk_{0};
    std::atomic<std::uint64_t> forwardDrop_{0};
    // UDP sendto failures (SNDBUF full / transient would-block). Separate from
    // forwardDrop_ (a policy drop) so kernel-level send starvation is visible.
    std::atomic<std::uint64_t> sendFail_{0};
	std::atomic<std::uint64_t> controlBytes_{0}; // DIAG: bytes from client->server (3478, controlLoop)
	std::atomic<std::uint64_t> ctlHandleNs_{0};   // DIAG: ChannelData handle+sendo cumulative ns
};

} // namespace stserver

#endif // STSERVER_TURN_SERVER_HPP
