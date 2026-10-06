// SPDX-License-Identifier: MPL-2.0
// Author: zlyadvocate
// Version: 0.11.0
// stserver TURN/STUN server implementation.
//
// Implements STUN Binding (RFC 5389), TURN Allocate/Refresh/CreatePermission/
// ChannelBind/Send/Data (RFC 8656), TURN over TCP framing (self-delimiting),
// and RFC 6062 Mode-B (CONNECT/CONNECTION-ATTEMPT/CONNECTION-BIND).
//
// IO is handled by an abstract IoBackend (B plan: select + thread pool,
// D plan: IOCP/epoll). All shared state is protected by stateMutex_ since
// callbacks fire from multiple worker threads. STICE_STATIC must be defined
// before including stice headers so the static library linkage is selected.

// Raise FD_SETSIZE before pulling in winsock2.h (via stice headers) so the
// select() fd_set can hold many relay/TCP sockets when using SelectBackend.
// This only affects stserver's own fd_set usage; it does not change stice.lib
// internals, and is harmless when using IOCP/epoll.
#ifdef _WIN32
#ifndef FD_SETSIZE
#define FD_SETSIZE 8192
#endif
#endif

#ifndef STICE_STATIC
#define STICE_STATIC
#endif

#include "stice/stserver/turn_server.hpp"
#include "stice/stserver/config.hpp"

#include "stice/crypto.hpp"
#include "stice/log.hpp"
#include "stice/net/addr.hpp"
#include "stice/stun/attributes.hpp"
#include "stice/stun/message.hpp"
#include "stice/turn/channeldata.hpp"
#include "stice/turn/stunconn.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h> // TCP_NODELAY
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace stserver {

using namespace stice::stun;
using namespace stice::turn;
using namespace stice::net;

namespace {
constexpr int PermissionLifetimeMs = 5 * 60 * 1000;   // RFC 8656 §2.5
constexpr int ChannelBindLifetimeMs = 10 * 60 * 1000;  // RFC 8656 §2.6
constexpr int PendingConnectLifetimeMs = 30 * 1000;   // RFC 6062 conn attempt
constexpr int NonceLifetimeMs = 30 * 60 * 1000;
constexpr int SelectTimeoutMs = 1000;

std::int64_t steadyNowMs() {
	return std::chrono::duration_cast<std::chrono::milliseconds>(
	           std::chrono::steady_clock::now().time_since_epoch())
	    .count();
}

bool setNonBlocking(socket_t s) {
#ifdef _WIN32
	u_long nb = 1;
	return ioctlsocket(s, FIONBIO, &nb) == 0;
#else
	int fl = fcntl(s, F_GETFL, 0);
	return fcntl(s, F_SETFL, fl | O_NONBLOCK) == 0;
#endif
}

bool setReuseAddr(socket_t s) {
	int yes = 1;
	return setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&yes),
	                  sizeof(yes)) == 0;
}

// Compare two addresses by IP only (port ignored) for TURN permission matching.
bool samePeerIP(const AddrRecord &a, const AddrRecord &b) {
	return addrEqual(reinterpret_cast<const sockaddr *>(&a.addr),
	                 reinterpret_cast<const sockaddr *>(&b.addr), false);
}

// Log a failed UDP sendto (relay forward / client delivery path). These
// failures silently drop TURN data — without logging they are undiagnosable.
void logSendToFailure(const AddrRecord &dst, int n) {
	if (n >= 0) return;
#ifdef _WIN32
	int err = WSAGetLastError();
#else
	int err = errno;
#endif
	STICE_LOG_ERROR("stserver: relay sendto to %s failed: %d",
	                dst.toString().c_str(), err);
}
} // namespace

// Member definitions for the helpers declared in turn_server.hpp.
std::int64_t TurnServer::nowMs() const { return steadyNowMs(); }

std::string TurnServer::allocKey(int transport, const stice::net::AddrRecord &client) const {
	const char *t = (transport == SOCK_STREAM) ? "T" : "U";
	std::string s = t;
	s += '|';
	s += client.toString();
	return s;
}

TurnServer::TurnServer() = default;
TurnServer::~TurnServer() {
	// Stop the business thread first (it may still be draining queues), then
	// the IO backend so no more callbacks fire while we tear down.
	running_ = false;
	queueCv_.notify_all();
	if (businessThread_.joinable()) businessThread_.join();
	if (ioBackend_) {
		ioBackend_->stop();
		ioBackend_.reset();
	}
	if (tcpListener_ != STICE_INVALID_SOCKET) sticeClosesocket(tcpListener_);
	for (auto &c : tcpConns_)
		if (c->sock != STICE_INVALID_SOCKET) sticeClosesocket(c->sock);
}

bool TurnServer::init(const Config &cfg) {
	listenAddress_ = cfg.listenAddress;
	udpPort_ = cfg.udpPort;
	tcpPort_ = cfg.tcpPort;
	realm_ = cfg.realm;
	users_ = cfg.users;
	maxAllocations_ = cfg.maxAllocations;
	allocationLifetime_ = cfg.allocationLifetime;
	relayPortBegin_ = cfg.relayPortBegin;
	relayPortEnd_ = cfg.relayPortEnd;
	workerCount_ = std::max(1, cfg.workerCount);

	// Determine the externally-reachable server IP advertised in
	// XOR-RELAYED-ADDRESS. For an any-address bind we use loopback so local
	// interop tests route relay traffic back to the server.
	relayIp_ = listenAddress_;
	if (relayIp_.empty() || relayIp_ == "0.0.0.0" || relayIp_ == "::")
		relayIp_ = "127.0.0.1";
	if (!parseAddr(relayIp_, 0, relayIpAddr_, relayIpLen_)) {
		STICE_LOG_ERROR("stserver: invalid relay ip %s", relayIp_.c_str());
		return false;
	}

	// UDP listener (STUN Binding + TURN over UDP).
	UdpSocketConfig ucfg;
	ucfg.bindAddress = listenAddress_;
	ucfg.portBegin = udpPort_;
	ucfg.portEnd = udpPort_;
	udpListener_ = UdpSocket::create(ucfg);
	if (!udpListener_.valid()) {
		STICE_LOG_ERROR("stserver: failed to bind UDP listener on %s:%u",
		                listenAddress_.c_str(), udpPort_);
		return false;
	}

	// TCP listener (TURN over TCP / RFC 6062). Prefer IPv4 dual-stack via a
	// single AF_INET listener for simplicity (interop runs on loopback).
	struct sockaddr_storage ss;
	socklen_t ssLen;
	if (!parseAddr(listenAddress_.empty() ? "0.0.0.0" : listenAddress_, tcpPort_, ss, ssLen)) {
		STICE_LOG_ERROR("stserver: invalid listen address %s", listenAddress_.c_str());
		return false;
	}
	tcpListener_ = ::socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (tcpListener_ == STICE_INVALID_SOCKET) {
		STICE_LOG_ERROR("stserver: TCP socket() failed: %d", sticeSockerrno);
		return false;
	}
	setReuseAddr(tcpListener_);
	if (::bind(tcpListener_, reinterpret_cast<sockaddr *>(&ss), ssLen) != 0) {
		STICE_LOG_ERROR("stserver: TCP bind on %s:%u failed: %d",
		                listenAddress_.c_str(), tcpPort_, sticeSockerrno);
		sticeClosesocket(tcpListener_);
		tcpListener_ = STICE_INVALID_SOCKET;
		return false;
	}
	if (::listen(tcpListener_, 64) != 0) {
		STICE_LOG_ERROR("stserver: TCP listen failed: %d", sticeSockerrno);
		sticeClosesocket(tcpListener_);
		tcpListener_ = STICE_INVALID_SOCKET;
		return false;
	}
	setNonBlocking(tcpListener_);

	refreshNonce();

	// Create and initialize the IO backend (B plan: select + thread pool,
	// D plan: IOCP/epoll, selected at compile time via STSERVER_IOCP).
	ioBackend_ = createIoBackend();
	if (!ioBackend_ || !ioBackend_->init(this, udpListener_.handle(), tcpListener_)) {
		STICE_LOG_ERROR("stserver: IO backend init failed");
		return false;
	}
	ioBackend_->setWorkerCount(workerCount_);

	STICE_LOG_INFO("stserver: listening UDP %s:%u  TCP %s:%u  realm=%s  users=%zu  workers=%d",
	               listenAddress_.c_str(), udpPort_, listenAddress_.c_str(), tcpPort_,
	               realm_.c_str(), users_.size(), workerCount_);
	return true;
}

void TurnServer::refreshNonce() {
	nonce_ = stice::crypto::randomStr64(32);
	nonceExpiryMs_ = nowMs() + NonceLifetimeMs;
}

// ---- Allocation key/lookup --------------------------------------------------

Allocation *TurnServer::findAlloc(const std::string &key) const {
	auto it = allocations_.find(key);
	return it == allocations_.end() ? nullptr : it->second.get();
}

Allocation *TurnServer::findAllocByRelaySock(socket_t s) const {
	auto it = allocByRelaySock_.find(s);
	return it == allocByRelaySock_.end() ? nullptr : it->second;
}

Allocation *TurnServer::findTcpAllocByPeer(const AddrRecord &peerRelayAddr,
                                          const Allocation *exclude) const {
	Allocation *found = nullptr;
	for (auto &kv : allocations_) {
		Allocation *a = kv.second.get();
		if (a == exclude) continue;
		if (a->transport != SOCK_STREAM) continue;
		if (a->relayedAddr == peerRelayAddr) {
			found = a;
			break;
		}
	}
	return found;
}

Allocation *TurnServer::findPendingByConnId(std::uint32_t connId,
                                            Allocation::PendingConnect **outPc) {
	auto it = pendingByConnId_.find(connId);
	if (it == pendingByConnId_.end()) return nullptr;
	Allocation *a = it->second;
	for (auto &pc : a->pendingConnects) {
		if (pc.connId == connId) {
			if (outPc) *outPc = &pc;
			return a;
		}
	}
	return nullptr;
}

// ---- Relay port allocation -------------------------------------------------

std::uint16_t TurnServer::allocRelayPort(const std::set<std::uint16_t> &avoid) {
	if (relayPortEnd_ < relayPortBegin_) std::swap(relayPortBegin_, relayPortEnd_);
	std::uint32_t span = std::uint32_t(relayPortEnd_) - relayPortBegin_ + 1;
	for (int tries = 0; tries < 200; ++tries) {
		std::uint32_t r = stice::crypto::randomU32();
		std::uint16_t port = relayPortBegin_ + static_cast<std::uint16_t>(r % span);
		if (usedRelayPorts_.count(port) == 0 && avoid.count(port) == 0) {
			usedRelayPorts_[port] = nullptr; // owner recorded on allocation commit
			return port;
		}
	}
	// Fallback: sequential scan (inclusive of relayPortEnd_).
	for (std::uint32_t p = relayPortBegin_; p <= relayPortEnd_; ++p) {
		std::uint16_t port = static_cast<std::uint16_t>(p);
		if (usedRelayPorts_.count(port) == 0 && avoid.count(port) == 0) {
			usedRelayPorts_[port] = nullptr;
			return port;
		}
	}
	return 0;
}

void TurnServer::releaseRelayPort(std::uint16_t port, const Allocation *owner) {
	auto it = usedRelayPorts_.find(port);
	if (it == usedRelayPorts_.end()) return;
	// Ownership check: only the owner (or a release before the owner is
	// committed, owner == nullptr during Allocate) may free the port. This
	// makes release idempotent and prevents a double release from freeing a
	// port that has already been handed to a different allocation.
	if (it->second != nullptr && it->second != owner) {
		STICE_LOG_WARN("stserver: relay port %u release rejected (owner mismatch)", port);
		return;
	}
	usedRelayPorts_.erase(it);
}

void TurnServer::destroyAllocation(Allocation *a) {
	if (!a) return;
	// Unbind from IO backend first so no further relay data arrives.
	if (a->transport == SOCK_DGRAM && a->relaySock.valid()) {
		if (ioBackend_) ioBackend_->removeRelaySocket(a->relaySock.handle());
		allocByRelaySock_.erase(a->relaySock.handle());
	}
	// TURN-over-TCP with UDP relay keeps both a relay socket and a control
	// socket — clean both lookup entries independently.
	if (a->controlSock != STICE_INVALID_SOCKET) {
		allocByControlSock_.erase(a->controlSock);
	}
	for (const auto &pc : a->pendingConnects) pendingByConnId_.erase(pc.connId);
	releaseRelayPort(a->relayPort, a);
	allocations_.erase(allocKey(a->transport, a->clientAddr));
}

bool TurnServer::buildRelayedAddr(std::uint16_t port, AddrRecord &out) const {
	std::memcpy(&out.addr, &relayIpAddr_, relayIpLen_);
	out.len = relayIpLen_;
	out.socktype = SOCK_DGRAM;
	addrSetPort(reinterpret_cast<sockaddr *>(&out.addr), port);
	return true;
}

// ---- Authentication -------------------------------------------------------

// Authenticate a request using long-term credentials (RFC 5389 §15.4).
// Returns: 0 on success, 401 (no/invalid MESSAGE-INTEGRITY), 438 (stale nonce).
// On success, outUsername holds the verified username.
int TurnServer::authenticate(const Message &msg, std::string &outUsername) {
	const Attribute *mi = msg.find(AttrType::MessageIntegrity);
	if (!mi) return StunErrorUnauthenticated;

	std::string username = getString(msg, AttrType::Username);
	std::string realm = getString(msg, AttrType::Realm);
	std::string nonce = getString(msg, AttrType::Nonce);

	// Nonce staleness check: any mismatch or expiry -> 438.
	if (nonce != nonce_ || nowMs() >= nonceExpiryMs_) {
		refreshNonce();
		return StunErrorStaleNonce;
	}

	auto it = users_.find(username);
	if (it == users_.end()) return StunErrorUnauthenticated;

	auto key = stice::crypto::longTermKey(username, realm, it->second);
	if (!msg.checkIntegrity(key.data(), key.size())) return StunErrorUnauthenticated;

	outUsername = username;
	return 0;
}

// ---- Response builders / senders ------------------------------------------

void TurnServer::sendUdp(const AddrRecord &dst, const Message &msg) {
	if (!msg.raw.empty()) {
		int n = udpListener_.sendto(reinterpret_cast<const char *>(msg.raw.data()),
		                            static_cast<int>(msg.raw.size()), dst);
		if (n < 0) {
#ifdef _WIN32
			int err = WSAGetLastError();
#else
			int err = errno;
#endif
			STICE_LOG_ERROR("stserver: sendto to %s failed: %d",
			                dst.toString().c_str(), err);
		}
	}
}

void TurnServer::sendTcpRaw(TcpConn &conn, const unsigned char *data, std::size_t size) {
	if (size == 0) return;
	bool wasEmpty = conn.writeBuf.empty();
	conn.writeBuf.insert(conn.writeBuf.end(), data, data + size);
	if (wasEmpty && ioBackend_) {
		// Notify backend that this socket now has pending write data.
		ioBackend_->setTcpConnWritePending(conn.sock, true);
	}
	bool ok = flushTcp(conn);
	STICE_LOG_INFO("stserver: sendTcpRaw sock=%llu size=%zu flushOk=%d writeBufRemain=%zu isData=%d",
	               (unsigned long long)conn.sock, size, (int)ok, conn.writeBuf.size(), (int)conn.isData);
}

bool TurnServer::flushTcp(TcpConn &conn) {
	while (!conn.writeBuf.empty()) {
		int n = ::send(conn.sock, reinterpret_cast<const char *>(conn.writeBuf.data()),
		               static_cast<int>(conn.writeBuf.size()), 0);
		if (n > 0) {
			conn.writeBuf.erase(conn.writeBuf.begin(), conn.writeBuf.begin() + n);
			continue;
		}
		if (n < 0 && wouldBlock()) return true; // wait for writable
		return false; // error
	}
	// Write buffer drained — stop monitoring for writability.
	if (ioBackend_) ioBackend_->setTcpConnWritePending(conn.sock, false);
	return true;
}

void TurnServer::sendTcp(TcpConn &conn, const Message &msg) {
	if (!msg.raw.empty()) sendTcpRaw(conn, msg.raw.data(), msg.raw.size());
}

// Error response with REALM + NONCE but NO MESSAGE-INTEGRITY (used for 401/438
// where the client has not yet proven credentials). REALM/NONCE are added as
// raw attributes and encode() is called without a password.
void TurnServer::sendAuthErrorResponse(const AddrRecord &dst, const Message &req, int code) {
	Message resp;
	resp.method = req.method;
	resp.cls = Class::ErrorResponse;
	resp.transactionID = req.transactionID;
	addErrorCode(resp, code);
	addString(resp, AttrType::Realm, realm_);
	addString(resp, AttrType::Nonce, nonce_);
	resp.encode(nullptr, nullptr, "stserver");
	sendUdp(dst, resp);
}

void TurnServer::sendAuthErrorResponseTcp(TcpConn &conn, const Message &req, int code) {
	Message resp;
	resp.method = req.method;
	resp.cls = Class::ErrorResponse;
	resp.transactionID = req.transactionID;
	addErrorCode(resp, code);
	addString(resp, AttrType::Realm, realm_);
	addString(resp, AttrType::Nonce, nonce_);
	resp.encode(nullptr, nullptr, "stserver");
	sendTcp(conn, resp);
}

void TurnServer::sendErrorResponseUdp(const AddrRecord &dst, const Message &req, int code) {
	Message resp;
	resp.method = req.method;
	resp.cls = Class::ErrorResponse;
	resp.transactionID = req.transactionID;
	addErrorCode(resp, code);
	resp.encode(nullptr, nullptr, "stserver");
	sendUdp(dst, resp);
}

void TurnServer::sendErrorResponseTcp(TcpConn &conn, const Message &req, int code) {
	Message resp;
	resp.method = req.method;
	resp.cls = Class::ErrorResponse;
	resp.transactionID = req.transactionID;
	addErrorCode(resp, code);
	resp.encode(nullptr, nullptr, "stserver");
	sendTcp(conn, resp);
}

// Success response carrying MESSAGE-INTEGRITY (long-term credentials). The
// caller must have filled resp's method/attributes; this attaches the auth
// attributes + MI + FINGERPRINT using the long-term key.
void TurnServer::sendSuccessResponse(const Message &req, const std::string &username,
                                     Message &resp) {
	resp.method = req.method;
	resp.cls = Class::SuccessResponse;
	resp.transactionID = req.transactionID;
	auto it = users_.find(username);
	if (it == users_.end()) {
		resp.encode(nullptr, nullptr, "stserver");
		return;
	}
	stice::stun::Credentials creds;
	creds.username = username;
	creds.realm = realm_;
	creds.nonce = nonce_;
	auto key = stice::crypto::longTermKey(username, realm_, it->second);
	creds.key = stice::bytes(key.begin(), key.end());
	// password must be non-null to trigger MESSAGE-INTEGRITY; creds.key is
	// used as the HMAC key.
	resp.encode("", &creds, "stserver");
}

// ---- Dispatch -------------------------------------------------------------

void TurnServer::handleUdpPacket(const unsigned char *data, std::size_t size,
                                  const AddrRecord &src) {
	if (isChannelData(data, size)) {
		Allocation *a = findAlloc(allocKey(SOCK_DGRAM, src));
		if (a) handleChannelDataFrame(data, size, a);
		return;
	}
	if (!Message::isMessage(data, size)) return;
	Message msg;
	if (!msg.decode(data, size)) return;
	Allocation *a = findAlloc(allocKey(SOCK_DGRAM, src));
	dispatchStun(msg, src, nullptr, a);
}

void TurnServer::handleTcpFrame(TcpConn &conn, const unsigned char *data, std::size_t size) {
	if (conn.isData) {
		// RFC 6062 data connection: raw bytes piped to the paired socket.
		auto it = dataPipe_.find(conn.sock);
		if (it != dataPipe_.end()) {
			auto pit = tcpBySock_.find(it->second);
			if (pit != tcpBySock_.end()) sendTcpRaw(*pit->second, data, size);
		}
		return;
	}
	if (isChannelData(data, size)) {
		Allocation *a = nullptr;
		if (conn.sock != STICE_INVALID_SOCKET) {
			auto it = allocByControlSock_.find(conn.sock);
			if (it != allocByControlSock_.end()) a = it->second;
		}
		if (a) handleChannelDataFrame(data, size, a);
		return;
	}
	if (!Message::isMessage(data, size)) return;
	Message msg;
	if (!msg.decode(data, size)) return;
	Allocation *a = nullptr;
	if (conn.sock != STICE_INVALID_SOCKET) {
		auto it = allocByControlSock_.find(conn.sock);
		if (it != allocByControlSock_.end()) a = it->second;
	}
	dispatchStun(msg, conn.peerAddr, &conn, a);
}

void TurnServer::dispatchStun(Message &msg, const AddrRecord &src, TcpConn *tcpConn,
                               Allocation *alloc) {
	if (msg.cls != Class::Request && msg.cls != Class::Indication) return;

	switch (msg.method) {
	case Method::Binding:
		if (msg.cls == Class::Request) handleBinding(msg, src, tcpConn);
		break;
	case Method::Allocate:
		if (msg.cls == Class::Request) {
			if (alloc) {
				if (alloc->expiryMs <= nowMs()) {
					// Expired but not yet reaped: replace it, cleaning the
					// old allocation (relay socket, ports, lookups) fully
					// before creating the new one.
					destroyAllocation(alloc);
					alloc = nullptr;
				} else {
					if (tcpConn)
						sendErrorResponseTcp(*tcpConn, msg, StunErrorAllocationMismatch);
					else
						sendErrorResponseUdp(src, msg, StunErrorAllocationMismatch);
					return;
				}
			}
			std::string user;
			int code = authenticate(msg, user);
			if (code != 0) {
				if (tcpConn) sendAuthErrorResponseTcp(*tcpConn, msg, code);
				else sendAuthErrorResponse(src, msg, code);
				return;
			}
			handleAllocate(msg, src, tcpConn, alloc);
			(void)user;
		}
		break;
	case Method::Refresh:
		if (msg.cls == Class::Request) {
			if (!alloc) {
				if (tcpConn) sendErrorResponseTcp(*tcpConn, msg, StunErrorAllocationMismatch);
				else sendErrorResponseUdp(src, msg, StunErrorAllocationMismatch);
				return;
			}
			std::string user;
			int code = authenticate(msg, user);
			if (code != 0) {
				if (tcpConn) sendAuthErrorResponseTcp(*tcpConn, msg, code);
				else sendAuthErrorResponse(src, msg, code);
				return;
			}
			handleRefresh(msg, src, tcpConn, alloc);
			(void)user;
		}
		break;
	case Method::CreatePermission:
		if (msg.cls == Class::Request) {
			if (!alloc) {
				if (tcpConn) sendErrorResponseTcp(*tcpConn, msg, StunErrorAllocationMismatch);
				else sendErrorResponseUdp(src, msg, StunErrorAllocationMismatch);
				return;
			}
			std::string user;
			int code = authenticate(msg, user);
			if (code != 0) {
				if (tcpConn) sendAuthErrorResponseTcp(*tcpConn, msg, code);
				else sendAuthErrorResponse(src, msg, code);
				return;
			}
			handleCreatePermission(msg, src, tcpConn, alloc);
			(void)user;
		}
		break;
	case Method::ChannelBind:
		if (msg.cls == Class::Request) {
			if (!alloc) {
				if (tcpConn) sendErrorResponseTcp(*tcpConn, msg, StunErrorAllocationMismatch);
				else sendErrorResponseUdp(src, msg, StunErrorAllocationMismatch);
				return;
			}
			std::string user;
			int code = authenticate(msg, user);
			if (code != 0) {
				if (tcpConn) sendAuthErrorResponseTcp(*tcpConn, msg, code);
				else sendAuthErrorResponse(src, msg, code);
				return;
			}
			handleChannelBind(msg, src, tcpConn, alloc);
			(void)user;
		}
		break;
	case Method::Send:
		if (msg.cls == Class::Indication && alloc) handleSendIndication(msg, alloc);
		break;
	case Method::Connect:
		if (msg.cls == Class::Request) {
			if (!alloc || !tcpConn) {
				if (tcpConn) sendErrorResponseTcp(*tcpConn, msg, StunErrorAllocationMismatch);
				return;
			}
			if (alloc->transport != SOCK_STREAM) {
				sendErrorResponseTcp(*tcpConn, msg, StunErrorBadRequest);
				return;
			}
			std::string user;
			int code = authenticate(msg, user);
			if (code != 0) {
				sendAuthErrorResponseTcp(*tcpConn, msg, code);
				return;
			}
			handleConnect(msg, tcpConn, alloc);
			(void)user;
		}
		break;
	case Method::ConnectionBind:
		if (msg.cls == Class::Request) handleConnectionBind(msg, tcpConn);
		break;
	default:
		if (msg.cls == Class::Request) {
			if (tcpConn) sendErrorResponseTcp(*tcpConn, msg, StunErrorBadRequest);
			else sendErrorResponseUdp(src, msg, StunErrorBadRequest);
		}
		break;
	}
}

// ---- STUN Binding ---------------------------------------------------------

void TurnServer::handleBinding(Message &req, const AddrRecord &src, TcpConn *tcpConn) {
	Message resp;
	resp.method = Method::Binding;
	resp.cls = Class::SuccessResponse;
	resp.transactionID = req.transactionID;
	// XOR-MAPPED-ADDRESS reflects the client's reflexive address: the UDP
	// packet source or the TCP control connection's peer.
	writeXorAddress(resp, AttrType::XorMappedAddress, src, req.transactionID);
	resp.encode(nullptr, nullptr, "stserver");
	if (tcpConn) sendTcp(*tcpConn, resp);
	else sendUdp(src, resp);
}

// ---- TURN Allocate --------------------------------------------------------

void TurnServer::handleAllocate(Message &req, const AddrRecord &src, TcpConn *tcpConn,
                                 Allocation *alloc) {
	(void)alloc;
	const Attribute *rt = req.find(AttrType::RequestedTransport);
	if (!rt || rt->value.empty()) {
		if (tcpConn) sendErrorResponseTcp(*tcpConn, req, StunErrorBadRequest);
		else sendErrorResponseUdp(src, req, StunErrorBadRequest);
		return;
	}
	std::uint8_t proto = rt->value[0]; // 17=UDP, 6=TCP

	if (static_cast<int>(allocations_.size()) >= maxAllocations_) {
		if (tcpConn) sendErrorResponseTcp(*tcpConn, req, StunErrorAllocationQuotaReached);
		else sendErrorResponseUdp(src, req, StunErrorAllocationQuotaReached);
		return;
	}

	std::string username = getString(req, AttrType::Username);

	auto a = std::make_unique<Allocation>();
	a->transport = (proto == 6) ? SOCK_STREAM : SOCK_DGRAM;
	a->clientAddr = src;
	a->username = username;

	if (proto == 6) {
		// RFC 6062 TCP allocation: no relay socket, allocate a unique relayed
		// port from the range and advertise the server's TCP relay address.
		std::uint16_t port = allocRelayPort({});
		if (port == 0) {
			if (tcpConn) sendErrorResponseTcp(*tcpConn, req, StunErrorInsufficientCapacity);
			else sendErrorResponseUdp(src, req, StunErrorInsufficientCapacity);
			return;
		}
		a->relayPort = port;
		buildRelayedAddr(port, a->relayedAddr);
		a->controlSock = tcpConn ? tcpConn->sock : STICE_INVALID_SOCKET;
	} else {
		// UDP allocation: bind a relay socket on a port from the range.
		// Ports whose bind fails are remembered in `failed` and excluded from
		// subsequent picks, so the retry loop always advances to a fresh
		// port instead of spinning on the same (unbindable) one.
		std::set<std::uint16_t> failed;
		std::uint16_t port = allocRelayPort(failed);
		if (port == 0) {
			if (tcpConn) sendErrorResponseTcp(*tcpConn, req, StunErrorInsufficientCapacity);
			else sendErrorResponseUdp(src, req, StunErrorInsufficientCapacity);
			return;
		}
		UdpSocketConfig rcfg;
		rcfg.bindAddress = listenAddress_.empty() ? "0.0.0.0" : listenAddress_;
		rcfg.portBegin = port;
		rcfg.portEnd = port;
		UdpSocket rs = UdpSocket::create(rcfg);
		int tries = 0;
		while (!rs.valid() && tries < 50) {
			failed.insert(port);
			releaseRelayPort(port, nullptr);
			port = allocRelayPort(failed);
			if (port == 0) break;
			rcfg.portBegin = port;
			rcfg.portEnd = port;
			rs = UdpSocket::create(rcfg);
			++tries;
		}
		if (!rs.valid()) {
			if (port != 0) releaseRelayPort(port, nullptr);
			if (tcpConn) sendErrorResponseTcp(*tcpConn, req, StunErrorInsufficientCapacity);
			else sendErrorResponseUdp(src, req, StunErrorInsufficientCapacity);
			return;
		}
		// Use the actual bound port. With portBegin==portEnd the bound port
		// equals the reserved one; defensively move the reservation if it
		// differs so release stays exact.
		std::uint16_t reserved = port;
		AddrRecord bound;
		if (rs.boundAddr(bound)) {
			port = addrPort(reinterpret_cast<sockaddr *>(&bound.addr));
		}
		if (port != reserved) {
			releaseRelayPort(reserved, nullptr);
			usedRelayPorts_[port] = nullptr;
		}
		a->relayPort = port;
		a->relaySock = std::move(rs);
		buildRelayedAddr(port, a->relayedAddr);
		// RFC 8656: the allocation's 5-tuple is the control connection it was
		// created on, regardless of the relayed transport. Keep the TCP/TLS
		// control socket so the control plane (CreatePermission, ChannelBind,
		// Refresh, Send, ChannelData) and peer-data forwarding can find and
		// reach this allocation.
		a->controlSock = tcpConn ? tcpConn->sock : STICE_INVALID_SOCKET;
	}

	std::uint32_t lifetime = allocationLifetime_;
	a->expiryMs = nowMs() + static_cast<std::int64_t>(lifetime) * 1000;

	// Build the success response: XOR-RELAYED-ADDRESS, LIFETIME, XOR-MAPPED-ADDRESS.
	Message resp;
	writeXorAddress(resp, AttrType::XorRelayedAddress, a->relayedAddr, req.transactionID);
	writeXorAddress(resp, AttrType::XorMappedAddress, src, req.transactionID);
	addLifetime(resp, lifetime);
	sendSuccessResponse(req, username, resp);

	// Register in lookup maps before sending.
	std::string key = allocKey(a->transport, src);
	Allocation *raw = a.get();
	// Commit relay-port ownership: the reservation held owner=nullptr during
	// Allocate; from here only this allocation may release the port.
	usedRelayPorts_[a->relayPort] = raw;
	if (a->transport == SOCK_DGRAM) {
		allocByRelaySock_[a->relaySock.handle()] = raw;
		// Register the relay socket with the IO backend so it starts
		// monitoring for incoming peer data.
		if (ioBackend_) ioBackend_->addRelaySocket(a->relaySock.handle());
	} else {
		allocByControlSock_[a->controlSock] = raw;
	}
	// RFC 8656 over a TCP/TLS control connection: a UDP-relay allocation is
	// reachable from BOTH its relay socket (peer data plane) and its control
	// connection (control plane + ChannelData). Key it by the control socket
	// as well so handleTcpFrame finds it. destroyAllocation cleans both maps.
	if (tcpConn && a->controlSock != STICE_INVALID_SOCKET)
		allocByControlSock_[a->controlSock] = raw;
	allocations_[key] = std::move(a);

	if (tcpConn) sendTcp(*tcpConn, resp);
	else sendUdp(src, resp);

	STICE_LOG_INFO("stserver: ALLOCATE %s transport=%s relayed=%s user=%s",
	               key.c_str(), proto == 6 ? "TCP" : "UDP",
	               raw->relayedAddr.toString().c_str(), username.c_str());
}

// ---- TURN Refresh ---------------------------------------------------------

void TurnServer::handleRefresh(Message &req, const AddrRecord &src, TcpConn *tcpConn,
                               Allocation *alloc) {
	std::uint32_t lifetime = allocationLifetime_;
	if (readLifetime(req, lifetime)) {
		if (lifetime > allocationLifetime_) lifetime = allocationLifetime_;
	}
	Message resp;
	if (lifetime == 0) {
		addLifetime(resp, 0);
	} else {
		alloc->expiryMs = nowMs() + static_cast<std::int64_t>(lifetime) * 1000;
		addLifetime(resp, lifetime);
	}
	sendSuccessResponse(req, alloc->username, resp);
	if (tcpConn) sendTcp(*tcpConn, resp);
	else sendUdp(src, resp);

	if (lifetime == 0) {
		STICE_LOG_INFO("stserver: REFRESH lifetime=0 deleting allocation %s",
		               alloc->clientAddr.toString().c_str());
		destroyAllocation(alloc);
	}
}

// ---- TURN CreatePermission -----------------------------------------------

void TurnServer::handleCreatePermission(Message &req, const AddrRecord &src, TcpConn *tcpConn,
                                        Allocation *alloc) {
	std::int64_t expiry = nowMs() + PermissionLifetimeMs;
	int added = 0;
	// A single request may carry multiple XOR-PEER-ADDRESS attributes
	// (RFC 8656 §3.3). Decode each against the request transaction id.
	for (const auto &a : req.attributes) {
		if (a.type != AttrType::XorPeerAddress) continue;
		Message tmp;
		tmp.transactionID = req.transactionID;
		tmp.addAttribute(AttrType::XorPeerAddress, a.value);
		AddrRecord peer;
		if (!readXorAddress(tmp, AttrType::XorPeerAddress, peer, req.transactionID)) continue;
		// Replace existing permission for the same peer IP (port ignored).
		bool found = false;
		for (auto &p : alloc->permissions) {
			if (samePeerIP(p.peer, peer)) {
				p.peer = peer;
				p.expiryMs = expiry;
				found = true;
				break;
			}
		}
		if (!found) {
			alloc->permissions.push_back({peer, expiry});
		}
		++added;
	}
	(void)added;
	Message resp;
	sendSuccessResponse(req, alloc->username, resp);
	if (tcpConn) sendTcp(*tcpConn, resp);
	else sendUdp(src, resp);
}

// ---- TURN ChannelBind -----------------------------------------------------

void TurnServer::handleChannelBind(Message &req, const AddrRecord &src, TcpConn *tcpConn,
                                   Allocation *alloc) {
	std::uint16_t channel = 0;
	if (!readChannelNumber(req, channel) || !channelValid(channel)) {
		if (tcpConn) sendErrorResponseTcp(*tcpConn, req, StunErrorBadRequest);
		else sendErrorResponseUdp(src, req, StunErrorBadRequest);
		return;
	}
	AddrRecord peer;
	if (!readXorAddress(req, AttrType::XorPeerAddress, peer, req.transactionID)) {
		if (tcpConn) sendErrorResponseTcp(*tcpConn, req, StunErrorBadRequest);
		else sendErrorResponseUdp(src, req, StunErrorBadRequest);
		return;
	}
	// A channel number may bind to only one peer and vice versa.
	for (auto &c : alloc->channels) {
		if (c.number == channel && !samePeerIP(c.peer, peer)) {
			if (tcpConn) sendErrorResponseTcp(*tcpConn, req, StunErrorBadRequest);
			else sendErrorResponseUdp(src, req, StunErrorBadRequest);
			return;
		}
		if (samePeerIP(c.peer, peer) && c.number != channel) {
			if (tcpConn) sendErrorResponseTcp(*tcpConn, req, StunErrorBadRequest);
			else sendErrorResponseUdp(src, req, StunErrorBadRequest);
			return;
		}
	}
	std::int64_t expiry = nowMs() + ChannelBindLifetimeMs;
	bool updated = false;
	for (auto &c : alloc->channels) {
		if (c.number == channel) {
			c.peer = peer;
			c.expiryMs = expiry;
			updated = true;
			break;
		}
	}
	if (!updated) alloc->channels.push_back({channel, peer, expiry});

	// ChannelBind also installs a permission for the peer (RFC 8656 §2.6).
	bool permFound = false;
	for (auto &p : alloc->permissions) {
		if (samePeerIP(p.peer, peer)) {
			p.expiryMs = nowMs() + PermissionLifetimeMs;
			permFound = true;
			break;
		}
	}
	if (!permFound) alloc->permissions.push_back({peer, nowMs() + PermissionLifetimeMs});

	Message resp;
	sendSuccessResponse(req, alloc->username, resp);
	if (tcpConn) sendTcp(*tcpConn, resp);
	else sendUdp(src, resp);
}

// ---- TURN Send Indication (client -> peer) -------------------------------

void TurnServer::handleSendIndication(Message &req, Allocation *alloc) {
	AddrRecord peer;
	if (!readXorAddress(req, AttrType::XorPeerAddress, peer, req.transactionID)) return;
	const Attribute *dataAttr = req.find(AttrType::Data);
	if (!dataAttr) return;
	// Require a permission for the peer's IP.
	bool permitted = false;
	for (const auto &p : alloc->permissions) {
		if (samePeerIP(p.peer, peer)) { permitted = true; break; }
	}
	if (!permitted) return;
	if (alloc->transport == SOCK_DGRAM && alloc->relaySock.valid())
		logSendToFailure(peer, alloc->relaySock.sendto(
		                     reinterpret_cast<const char *>(dataAttr->value.data()),
		                     static_cast<int>(dataAttr->value.size()), peer));
}

// ---- TURN ChannelData frame (client -> peer) -----------------------------

void TurnServer::handleChannelDataFrame(const unsigned char *data, std::size_t size,
                                         Allocation *alloc) {
	std::uint16_t channel = 0;
	const unsigned char *outData = nullptr;
	std::size_t frameSize = 0;
	std::size_t n = unwrapChannelData(data, size, channel, outData, frameSize);
	if (n == 0) return;
	const Channel *ch = nullptr;
	for (const auto &c : alloc->channels) {
		if (c.number == channel) { ch = &c; break; }
	}
	if (!ch) return;
	if (alloc->transport == SOCK_DGRAM && alloc->relaySock.valid())
		logSendToFailure(ch->peer, alloc->relaySock.sendto(
		                     reinterpret_cast<const char *>(outData),
		                     static_cast<int>(n), ch->peer));
}

// ---- Relay data forwarding (peer -> client) ------------------------------

void TurnServer::forwardToClient(Allocation &alloc, const AddrRecord &peer,
                                 const unsigned char *data, std::size_t size) {
	// The path back to the client is the control connection the allocation was
	// created on (its 5-tuple, RFC 8656 §2.2), NOT the relayed transport. A
	// control socket means TCP/TLS control (both RFC 6062 TCP allocations and
	// RFC 8656 UDP-relay allocations over TCP/TLS control); no control socket
	// means the client is reached over UDP.
	const bool controlIsTcp = (alloc.controlSock != STICE_INVALID_SOCKET);
	// Prefer a bound channel for this peer (full IP:port).
	for (const auto &c : alloc.channels) {
		if (c.peer == peer) {
			stice::bytes frame;
			if (wrapChannelData(c.number, data, size, frame) > 0) {
				if (controlIsTcp) {
					auto it = tcpBySock_.find(alloc.controlSock);
					if (it != tcpBySock_.end()) sendTcpRaw(*it->second, frame.data(), frame.size());
				} else {
					logSendToFailure(alloc.clientAddr, udpListener_.sendto(
					                     reinterpret_cast<const char *>(frame.data()),
					                     static_cast<int>(frame.size()), alloc.clientAddr));
				}
			}
			return;
		}
	}
	// Otherwise, if a permission exists for the peer IP, send a Data indication.
	for (const auto &p : alloc.permissions) {
		if (samePeerIP(p.peer, peer)) {
			Message ind;
			ind.method = Method::Data;
			ind.cls = Class::Indication;
			ind.newTransactionID();
			writeXorAddress(ind, AttrType::XorPeerAddress, peer, ind.transactionID);
			addData(ind, data, size);
			ind.encode(nullptr, nullptr, "stserver");
			if (controlIsTcp) {
				auto it = tcpBySock_.find(alloc.controlSock);
				if (it != tcpBySock_.end()) sendTcp(*it->second, ind);
			} else {
				sendUdp(alloc.clientAddr, ind);
			}
			return;
		}
	}
	// No permission/channel: drop per RFC 8656 §2.5.
}

// ---- RFC 6062: CONNECT / CONNECTION-ATTEMPT / CONNECTION-BIND -------------

void TurnServer::sendConnectionAttempt(Allocation &targetAlloc, std::uint32_t connId,
                                        const AddrRecord &peerRelayAddr) {
	Message ind;
	ind.method = Method::ConnectionAttempt;
	ind.cls = Class::Indication;
	ind.newTransactionID();
	writeXorAddress(ind, AttrType::XorPeerAddress, peerRelayAddr, ind.transactionID);
	addConnectionId(ind, connId);
	ind.encode(nullptr, nullptr, "stserver");
	auto it = tcpBySock_.find(targetAlloc.controlSock);
	if (it != tcpBySock_.end()) sendTcp(*it->second, ind);
}

void TurnServer::handleConnect(Message &req, TcpConn *tcpConn, Allocation *alloc) {
	AddrRecord peer;
	if (!readXorAddress(req, AttrType::XorPeerAddress, peer, req.transactionID)) {
		sendErrorResponseTcp(*tcpConn, req, StunErrorBadRequest);
		return;
	}
	// Find the peer's TCP allocation whose relayed address matches.
	Allocation *target = findTcpAllocByPeer(peer, alloc);
	if (!target) {
		sendErrorResponseTcp(*tcpConn, req, StunErrorForbidden);
		return;
	}
	std::uint32_t connId = nextConnId_++;
	Allocation::PendingConnect pc;
	pc.connId = connId;
	pc.peerRelayAddr = peer;
	pc.firstDataSock = STICE_INVALID_SOCKET;
	pc.connectTid = req.transactionID;
	pc.connectResponded = false;
	pc.expiryMs = nowMs() + PendingConnectLifetimeMs;
	alloc->pendingConnects.push_back(std::move(pc));
	pendingByConnId_[connId] = alloc;

	// Notify the peer so it opens a data connection and sends CONNECTION-BIND.
	sendConnectionAttempt(*target, connId, alloc->relayedAddr);
	STICE_LOG_INFO("stserver: CONNECT connId=%u from %s to peer %s",
	               connId, alloc->clientAddr.toString().c_str(),
	               target->clientAddr.toString().c_str());
}

void TurnServer::handleConnectionBind(Message &req, TcpConn *tcpConn) {
	if (!tcpConn) return;
	// Authenticate on the new connection using supplied long-term credentials.
	std::string user;
	int code = authenticate(req, user);
	if (code != 0) {
		sendAuthErrorResponseTcp(*tcpConn, req, code);
		return;
	}
	std::uint32_t connId = 0;
	if (!readConnectionId(req, connId)) {
		sendErrorResponseTcp(*tcpConn, req, StunErrorBadRequest);
		return;
	}
	Allocation::PendingConnect *pc = nullptr;
	Allocation *connector = findPendingByConnId(connId, &pc);
	if (!pc) {
		sendErrorResponseTcp(*tcpConn, req, StunErrorAllocationMismatch);
		return;
	}

	if (pc->firstDataSock == STICE_INVALID_SOCKET) {
		// First CONNECTION-BIND (typically the peer): record the data socket
		// and release the held CONNECT success response to the connector.
		pc->firstDataSock = tcpConn->sock;
		tcpConn->isData = true;
		tcpConn->connId = connId;

		if (!pc->connectResponded) {
			// Respond to the original CONNECT with CONNECTION-ID + MI.
			Message connectResp;
			addConnectionId(connectResp, connId);
			Message connectReq;
			connectReq.method = Method::Connect;
			connectReq.cls = Class::Request;
			connectReq.transactionID = pc->connectTid;
			sendSuccessResponse(connectReq, connector->username, connectResp);
			auto it = tcpBySock_.find(connector->controlSock);
			if (it != tcpBySock_.end()) sendTcp(*it->second, connectResp);
			pc->connectResponded = true;
		}

		// Respond to this CONNECTION-BIND with success + MI.
		Message bindResp;
		Message bindReq;
		bindReq.method = Method::ConnectionBind;
		bindReq.cls = Class::Request;
		bindReq.transactionID = req.transactionID;
		sendSuccessResponse(bindReq, user, bindResp);
		sendTcp(*tcpConn, bindResp);
		STICE_LOG_INFO("stserver: CONNECTION-BIND first connId=%u", connId);
	} else {
		// Second CONNECTION-BIND (the connector): pair the two data sockets.
		tcpConn->isData = true;
		tcpConn->connId = connId;
		dataPipe_[tcpConn->sock] = pc->firstDataSock;
		dataPipe_[pc->firstDataSock] = tcpConn->sock;

		Message bindResp;
		Message bindReq;
		bindReq.method = Method::ConnectionBind;
		bindReq.cls = Class::Request;
		bindReq.transactionID = req.transactionID;
		sendSuccessResponse(bindReq, user, bindResp);
		sendTcp(*tcpConn, bindResp);
		STICE_LOG_INFO("stserver: CONNECTION-BIND second connId=%u paired", connId);

		// Pending connect is fulfilled; retire it.
		pendingByConnId_.erase(connId);
		auto &v = connector->pendingConnects;
		v.erase(std::remove_if(v.begin(), v.end(),
		                       [connId](const Allocation::PendingConnect &p) { return p.connId == connId; }),
		        v.end());
	}
}

// ---- TCP connection management -------------------------------------------

void TurnServer::closeTcpConn(TcpConn *conn) {
	if (!conn) return;
	socket_t s = conn->sock;
	if (s == STICE_INVALID_SOCKET) return; // already closed (idempotent)
	// If this was a control connection, tear down its allocation.
	Allocation *a = nullptr;
	{
		auto it = allocByControlSock_.find(s);
		if (it != allocByControlSock_.end()) a = it->second;
	}
	if (a) {
		std::string key = allocKey(a->transport, a->clientAddr);
		// Full cleanup: IO unbind, lookup maps, relay port, map entry.
		destroyAllocation(a);
		STICE_LOG_INFO("stserver: allocation deleted (TCP control closed) %s", key.c_str());
	}
	// Remove from RFC 6062 data pipe (both directions).
	auto dp = dataPipe_.find(s);
	if (dp != dataPipe_.end()) {
		dataPipe_.erase(dp->second);
		dataPipe_.erase(dp);
	}
	// Notify the IO backend to stop monitoring this socket.
	if (ioBackend_) ioBackend_->removeTcpConn(s);
	tcpBySock_.erase(s);
	if (s != STICE_INVALID_SOCKET) sticeClosesocket(s);
	conn->sock = STICE_INVALID_SOCKET;
	// Erase from tcpConns_.
	for (auto it = tcpConns_.begin(); it != tcpConns_.end(); ++it) {
		if (it->get() == conn) { tcpConns_.erase(it); break; }
	}
}

// ---- Expiry ---------------------------------------------------------------

void TurnServer::expireStale() {
	std::int64_t now = nowMs();
	if (now >= nonceExpiryMs_) refreshNonce();
	for (auto it = allocations_.begin(); it != allocations_.end();) {
		Allocation *a = it->second.get();
		// Expire permissions.
		auto &p = a->permissions;
		p.erase(std::remove_if(p.begin(), p.end(),
		                       [now](const Permission &perm) { return perm.expiryMs <= now; }),
		        p.end());
		// Expire channels.
		auto &c = a->channels;
		c.erase(std::remove_if(c.begin(), c.end(),
		                       [now](const Channel &ch) { return ch.expiryMs <= now; }),
		        c.end());
		// Expire pending connects.
		auto &pc = a->pendingConnects;
		for (const auto &x : pc)
			if (x.expiryMs <= now) pendingByConnId_.erase(x.connId);
		pc.erase(std::remove_if(pc.begin(), pc.end(),
		                        [now](const Allocation::PendingConnect &p) { return p.expiryMs <= now; }),
		         pc.end());
		// Expire the allocation itself. Advance the iterator first:
		// destroyAllocation() erases the current map node.
		if (a->expiryMs <= now) {
			++it;
			destroyAllocation(a);
		} else {
			++it;
		}
	}
}

// ---- IoBackendOwner callbacks --------------------------------------------
// These are called from IO worker threads. They never touch shared state
// directly: each event is copied into a WorkItem and pushed onto the
// control or data queue. A single business thread (businessLoop) drains
// the control queue first — control (STUN/TURN) is prioritized over data
// but keeps its own arrival order (FIFO) — then the data queue (relay
// forwarding, RFC 6062 data pipes, write flushes).

void TurnServer::ioOnUdpData(const unsigned char *data, std::size_t len,
                              const stice::net::AddrRecord &from) {
	WorkItem it;
	it.kind = WorkItem::Kind::UdpData;
	it.from = from;
	it.data.assign(data, data + len);
	enqueueControl(std::move(it));
}

void TurnServer::ioOnTcpAccepted(socket_t sock, const stice::net::AddrRecord &peer) {
	WorkItem it;
	it.kind = WorkItem::Kind::TcpAccepted;
	it.sock = sock;
	it.from = peer;
	enqueueControl(std::move(it));
}

void TurnServer::ioOnRelayData(socket_t relaySock, const unsigned char *data,
                                std::size_t len, const stice::net::AddrRecord &from) {
	WorkItem it;
	it.kind = WorkItem::Kind::RelayData;
	it.sock = relaySock;
	it.from = from;
	it.data.assign(data, data + len);
	enqueueData(std::move(it));
}

void TurnServer::ioOnTcpConnData(socket_t connSock, const unsigned char *data,
                                  std::size_t len) {
	WorkItem it;
	it.kind = WorkItem::Kind::TcpConnData;
	it.sock = connSock;
	it.data.assign(data, data + len);
	// Data pipes (RFC 6062, post CONNECTION-BIND) carry bulk peer data and
	// go to the data queue; control connections carry STUN/TURN frames and
	// go to the (prioritized, order-preserving) control queue.
	if (connIsDataSock(connSock))
		enqueueData(std::move(it));
	else
		enqueueControl(std::move(it));
}

void TurnServer::ioOnTcpConnClosed(socket_t connSock) {
	WorkItem it;
	it.kind = WorkItem::Kind::TcpConnClosed;
	it.sock = connSock;
	enqueueControl(std::move(it));
}

void TurnServer::ioOnTcpConnWritable(socket_t connSock) {
	WorkItem it;
	it.kind = WorkItem::Kind::TcpConnWritable;
	it.sock = connSock;
	enqueueData(std::move(it));
}

void TurnServer::ioOnTimerTick() {
	// No-op: the business thread drives expireStale() unconditionally on
	// its own 50ms schedule. (Previously only the select backend fired this
	// callback, so epoll/IOCP builds never expired allocations.)
}

// ---- Business dispatch ----------------------------------------------------

void TurnServer::enqueueControl(WorkItem &&item) {
	{
		std::lock_guard<std::mutex> lk(queueMutex_);
		controlQueue_.push_back(std::move(item));
	}
	queueCv_.notify_one();
}

void TurnServer::enqueueData(WorkItem &&item) {
	{
		std::lock_guard<std::mutex> lk(queueMutex_);
		dataQueue_.push_back(std::move(item));
	}
	queueCv_.notify_one();
}

void TurnServer::businessLoop() {
	std::deque<WorkItem> controlBatch, dataBatch;
	std::int64_t lastTickMs = nowMs();
	while (running_) {
		{
			std::unique_lock<std::mutex> lk(queueMutex_);
			queueCv_.wait_for(lk, std::chrono::milliseconds(50), [&] {
				return !controlQueue_.empty() || !dataQueue_.empty() || !running_;
			});
			// Swap queues out so the lock is only held for the swap, not
			// while items are processed.
			controlBatch.swap(controlQueue_);
			dataBatch.swap(dataQueue_);
		}
		// Control first (FIFO within control), then data (FIFO within data).
		while (!controlBatch.empty()) {
			processItem(controlBatch.front());
			controlBatch.pop_front();
		}
		while (!dataBatch.empty()) {
			processItem(dataBatch.front());
			dataBatch.pop_front();
		}
		// Unconditional timer drive (all IO backends): expiry, nonce refresh.
		std::int64_t now = nowMs();
		if (now - lastTickMs >= 50) {
			lastTickMs = now;
			std::lock_guard<std::recursive_mutex> lk(stateMutex_);
			expireStale();
		}
	}
}

void TurnServer::processItem(const WorkItem &item) {
	std::lock_guard<std::recursive_mutex> lk(stateMutex_);
	switch (item.kind) {
	case WorkItem::Kind::UdpData:
		handleUdpPacket(item.data.data(), item.data.size(), item.from);
		break;
	case WorkItem::Kind::TcpAccepted:
		registerTcpConn(item.sock, item.from);
		break;
	case WorkItem::Kind::RelayData: {
		Allocation *a = findAllocByRelaySock(item.sock);
		if (a) forwardToClient(*a, item.from, item.data.data(), item.data.size());
		break;
	}
	case WorkItem::Kind::TcpConnData:
		handleTcpConnData(item.sock, item.data.data(), item.data.size());
		break;
	case WorkItem::Kind::TcpConnClosed: {
		auto it = tcpBySock_.find(item.sock);
		if (it != tcpBySock_.end()) closeTcpConn(it->second);
		break;
	}
	case WorkItem::Kind::TcpConnWritable: {
		auto it = tcpBySock_.find(item.sock);
		if (it != tcpBySock_.end()) {
			if (!flushTcp(*it->second)) closeTcpConn(it->second);
		}
		break;
	}
	}
}

void TurnServer::registerTcpConn(socket_t sock, const stice::net::AddrRecord &peer) {
	auto conn = std::make_unique<TcpConn>();
	conn->sock = sock;
	conn->peerAddr = peer;
	TcpConn *raw = conn.get();
	tcpBySock_[sock] = raw;
	tcpConns_.push_back(std::move(conn));
	// Register with the IO backend so it starts monitoring for readability.
	if (ioBackend_) ioBackend_->addTcpConn(sock, false);
	STICE_LOG_INFO("stserver: TCP accept from %s", raw->peerAddr.toString().c_str());
}

void TurnServer::handleTcpConnData(socket_t connSock, const unsigned char *data,
                                    std::size_t len) {
	auto it = tcpBySock_.find(connSock);
	if (it == tcpBySock_.end()) {
		STICE_LOG_DEBUG("stserver: conn data for unknown sock=%llu len=%zu",
		                (unsigned long long)connSock, len);
		return;
	}
	TcpConn *conn = it->second;
	if (conn->isData) {
		// Raw RFC 6062 data pipe: forward bytes to the paired socket.
		auto pit = dataPipe_.find(connSock);
		if (pit != dataPipe_.end()) {
			auto tit = tcpBySock_.find(pit->second);
			if (tit != tcpBySock_.end()) sendTcpRaw(*tit->second, data, len);
		}
		return;
	}
	// STUN/ChannelData framing.
	conn->stunConn.feed(data, len);
	const unsigned char *frame = nullptr;
	std::size_t fs = 0;
	while ((fs = conn->stunConn.readFrame(frame)) != 0) {
		if (fs == static_cast<std::size_t>(-1)) {
			closeTcpConn(conn);
			return;
		}
		handleTcpFrame(*conn, frame, fs);
	}
}

bool TurnServer::connIsDataSock(socket_t s) const {
	std::lock_guard<std::recursive_mutex> lk(stateMutex_);
	auto it = tcpBySock_.find(s);
	return it != tcpBySock_.end() && it->second->isData;
}

// ---- Event loop -----------------------------------------------------------

void TurnServer::run() {
	running_ = true;
	if (!ioBackend_) {
		STICE_LOG_ERROR("stserver: no IO backend, cannot run");
		return;
	}
	// Start the business thread before the IO backend so no callback can
	// enqueue before the consumer is running.
	businessThread_ = std::thread([this] { businessLoop(); });
	ioBackend_->start();
	STICE_LOG_INFO("stserver: running (IO backend + business thread started)");
	// Block until stop() is called (sets running_ = false). Poll every 200ms
	// since stop() just flips an atomic — no condition variable to keep the
	// signal handler trivially safe.
	while (running_) {
		std::this_thread::sleep_for(std::chrono::milliseconds(200));
	}
	// Stop accepting new events, then join the business thread.
	ioBackend_->stop();
	queueCv_.notify_all();
	if (businessThread_.joinable()) businessThread_.join();
	STICE_LOG_INFO("stserver: stopped");
}

} // namespace stserver
