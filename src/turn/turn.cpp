/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "stice/turn/turn.hpp"
#include "stice/stun/attributes.hpp"
#include "stice/turn/channeldata.hpp"
#include "stice/crypto.hpp"

#include "stice/log.hpp"

#include <algorithm>
#include <cstdarg>
#include <cstring>
#include <map>

namespace stice::turn {

namespace {
std::string tidKey(const std::array<unsigned char, 12> &tid) {
	return std::string(reinterpret_cast<const char *>(tid.data()), 12);
}

// Compare two addresses ignoring port (RFC 5766 permission keying).
bool addrEqualNoPort(const net::AddrRecord &a, const net::AddrRecord &b) {
	return a.isEqual(b, false);
}
} // namespace

void Client::log(int level, const char *fmt, ...) {
	if (!sink_.onLog) return;
	char buf[512];
	va_list ap;
	va_start(ap, fmt);
	std::vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	sink_.onLog(level, buf);
}

void Client::init(TurnConfig cfg, TurnSink sink) {
	cfg_ = std::move(cfg);
	sink_ = std::move(sink);
	state_ = AllocState::Idle;
}

void Client::allocate() {
	log(STICE_LOG_LEVEL_DEBUG, "TURN allocate: called state=%d", static_cast<int>(state_));
	if (state_ != AllocState::Idle) return;
	state_ = AllocState::Allocating;

	// RFC 5766 §14.7: REQUESTED-TRANSPORT=UDP(17) for UDP relay.
	// RFC 6062 §3.2: REQUESTED-TRANSPORT=TCP(6) for TCP allocation.
	// TCP allocation is used when the control connection itself is TCP and
	// the caller wants TCP relayed transport (active+passive dual mode).
	isTcpAllocation_ = (cfg_.transport == TurnTransport::TCP);
	std::uint8_t proto = isTcpAllocation_ ? 6 : 17;

	stun::Message m;
	m.method = stun::Method::Allocate;
	m.cls = stun::Class::Request;
	m.newTransactionID();
	allocateTid_ = m.transactionID;
	stun::addRequestedTransport(m, proto);
	sendRequest(m);

	auto now = std::chrono::steady_clock::now();
	PendingTx tx;
	tx.kind = PendingTx::Kind::Allocate;
	tx.sentAt = now;
	tx.nextRetransmitAt = now + std::chrono::milliseconds(TurnRtoMs);
	tx.rawBytes = m.raw;
	pending_[tidKey(m.transactionID)] = std::move(tx);

	nextTick_ = now + std::chrono::milliseconds(TurnRtoMs);
}

void Client::applyCredentials(stun::Message &m) {
	if (!creds_ || creds_->username.empty()) return;
	// Re-derive the long-term key in case the password changed.
	auto key = crypto::longTermKey(creds_->username, creds_->realm, cfg_.password);
	creds_->key = bytes(key.begin(), key.end());
}

void Client::sendRequest(stun::Message &m) {
	applyCredentials(m);
	if (creds_ && !creds_->username.empty()) {
		m.encode(cfg_.password.c_str(), &*creds_, "stice");
		log(STICE_LOG_LEVEL_DEBUG, "TURN sendRequest: authed method=%d raw=%zu bytes",
		    static_cast<int>(m.method), m.raw.size());
	} else {
		m.encode(nullptr, nullptr, "stice");
		log(STICE_LOG_LEVEL_DEBUG, "TURN sendRequest: unauth method=%d raw=%zu bytes",
		    static_cast<int>(m.method), m.raw.size());
	}
	if (sink_.sendRaw) sink_.sendRaw(m.raw.data(), m.raw.size());
}

void Client::sendRefresh(std::uint32_t lifetime) {
	stun::Message m;
	m.method = stun::Method::Refresh;
	m.cls = stun::Class::Request;
	m.newTransactionID();
	stun::addLifetime(m, lifetime);
	sendRequest(m);
	auto now = std::chrono::steady_clock::now();
	PendingTx tx;
	tx.kind = PendingTx::Kind::Refresh;
	tx.sentAt = now;
	tx.nextRetransmitAt = now + std::chrono::milliseconds(TurnRtoMs);
	tx.rawBytes = m.raw;
	pending_[tidKey(m.transactionID)] = std::move(tx);
}

void Client::deallocate() {
	if (state_ != AllocState::Allocated) return;
	sendRefresh(0);
	state_ = AllocState::Idle;
}

PeerBinding &Client::getBinding(const net::AddrRecord &peer) {
	for (auto &b : bindings_)
		if (addrEqualNoPort(b.peer, peer)) return b;
	PeerBinding b;
	b.peer = peer;
	bindings_.push_back(std::move(b));
	return bindings_.back();
}

bool Client::hasPermission(const net::AddrRecord &peer) const {
	for (const auto &b : bindings_)
		if (addrEqualNoPort(b.peer, peer) && b.permissionPermitted)
			return true;
	return false;
}

void Client::sendCreatePermission(const net::AddrRecord &peer) {
	auto &b = getBinding(peer);
	if (b.permissionTidFresh) return; // already in flight

	stun::Message m;
	m.method = stun::Method::CreatePermission;
	m.cls = stun::Class::Request;
	m.newTransactionID();
	stun::writeXorAddress(m, stun::AttrType::XorPeerAddress, peer, m.transactionID);
	sendRequest(m);

	b.permissionTid = m.transactionID;
	b.permissionTidFresh = true;
	auto now = std::chrono::steady_clock::now();
	PendingTx tx;
	tx.kind = PendingTx::Kind::CreatePermission;
	tx.peer = peer;
	tx.sentAt = now;
	tx.nextRetransmitAt = now + std::chrono::milliseconds(TurnRtoMs);
	tx.rawBytes = m.raw;
	pending_[tidKey(m.transactionID)] = std::move(tx);
}

void Client::sendChannelBind(const net::AddrRecord &peer) {
	auto &b = getBinding(peer);
	if (b.channelTidFresh) return;
	if (b.channel == 0) b.channel = randomChannelNumber();

	stun::Message m;
	m.method = stun::Method::ChannelBind;
	m.cls = stun::Class::Request;
	m.newTransactionID();
	stun::writeXorAddress(m, stun::AttrType::XorPeerAddress, peer, m.transactionID);
	stun::addChannelNumber(m, b.channel);
	sendRequest(m);

	b.channelTid = m.transactionID;
	b.channelTidFresh = true;
	auto now = std::chrono::steady_clock::now();
	PendingTx tx;
	tx.kind = PendingTx::Kind::ChannelBind;
	tx.peer = peer;
	tx.sentAt = now;
	tx.nextRetransmitAt = now + std::chrono::milliseconds(TurnRtoMs);
	tx.rawBytes = m.raw;
	pending_[tidKey(m.transactionID)] = std::move(tx);
}

void Client::sendData(const net::AddrRecord &peer, const unsigned char *data, std::size_t size) {
	if (state_ != AllocState::Allocated) return;
	auto &b = getBinding(peer);

	// Ensure permission exists; create one if missing.
	if (!b.permissionPermitted) {
		if (!b.permissionTidFresh) sendCreatePermission(peer);
		// Buffer the data until CreatePermission completes.
		b.pendingData.emplace_back(data, data + size);
		log(STICE_LOG_LEVEL_DEBUG, "TURN sendData: buffered %zu bytes (permission pending)", size);
		return;
	}

	if (b.channelReady) {
		// ChannelData path (preferred).
		bytes frame;
		wrapChannelData(b.channel, data, size, frame);
		if (sink_.sendRaw) sink_.sendRaw(frame.data(), frame.size());
	} else {
		// Send indication (no auth needed beyond FINGERPRINT).
		stun::Message m;
		m.method = stun::Method::Send;
		m.cls = stun::Class::Indication;
		m.newTransactionID();
		stun::writeXorAddress(m, stun::AttrType::XorPeerAddress, peer, m.transactionID);
		stun::addData(m, data, size);
		m.encode(nullptr, nullptr, "stice");
		if (sink_.sendRaw) sink_.sendRaw(m.raw.data(), m.raw.size());
		// Kick off ChannelBind so future sends use ChannelData.
		if (b.channel == 0) sendChannelBind(peer);
	}
}

void Client::handleInbound(const unsigned char *data, std::size_t size) {
	// Agent signals a transport-level failure (e.g. TCP connection lost,
	// TLS handshake failure) by calling handleInbound(nullptr, 0). The
	// Client must transition to Failed and invoke onFailed so the Agent
	// can decrement pendingRelayAllocations_ and complete gathering;
	// otherwise gathering hangs forever waiting for an allocation that
	// will never succeed. This is a no-op on an idle client (no pending
	// transaction to abort).
	if (data == nullptr && size == 0) {
		// Transport failure signal from the Agent (TCP connection lost or
		// TLS handshake failure). Transition to Failed and notify the sink
		// so the Agent can decrement pendingRelayAllocations_ and complete
		// gathering. This must handle ALL non-terminal states, including
		// Idle (TCP path: allocate() hasn't been called yet because the
		// connection never completed).
		if (state_ != AllocState::Failed) {
			log(STICE_LOG_LEVEL_WARN, "TURN transport failure (state=%d)",
			    static_cast<int>(state_));
			state_ = AllocState::Failed;
			pending_.clear();
			if (sink_.onFailed) sink_.onFailed(0, "transport failure");
		}
		return;
	}
	if (isChannelData(data, size)) {
		handleChannelData(data, size);
		return;
	}
	if (!stun::Message::isMessage(data, size)) {
		log(STICE_LOG_LEVEL_DEBUG, "TURN handleInbound: not a STUN message (%zu bytes)", size);
		return;
	}
	stun::Message m;
	if (!m.decode(data, size)) {
		log(STICE_LOG_LEVEL_WARN, "TURN handleInbound: STUN decode failed (%zu bytes)", size);
		return;
	}
	log(STICE_LOG_LEVEL_DEBUG, "TURN handleInbound: method=%d cls=%d tid=%02x%02x%02x%02x pending=%zu",
	    static_cast<int>(m.method), static_cast<int>(m.cls),
	    m.transactionID[0], m.transactionID[1], m.transactionID[2], m.transactionID[3],
	    pending_.size());
	if (stun::isResponseType(m.cls)) {
		handleStunResponse(m);
	} else if (m.cls == stun::Class::Indication && m.method == stun::Method::Data) {
		handleDataIndication(m);
	} else if (m.cls == stun::Class::Indication && m.method == stun::Method::ConnectionAttempt) {
		handleConnectionAttempt(m);
	}
}

void Client::handleStunResponse(const stun::Message &m) {
	auto it = pending_.find(tidKey(m.transactionID));
	if (it == pending_.end()) {
		log(STICE_LOG_LEVEL_WARN, "TURN handleStunResponse: no pending TID match (tid=%02x%02x%02x%02x)",
		    m.transactionID[0], m.transactionID[1], m.transactionID[2], m.transactionID[3]);
		return;
	}
	log(STICE_LOG_LEVEL_DEBUG, "TURN handleStunResponse: matched pending tx kind=%d",
	    static_cast<int>(it->second.kind));
	auto tx = it->second; // copy; we may erase below
	bool isError = (m.cls == stun::Class::ErrorResponse);
	int errorCode = 0;
	std::string reason;
	if (isError) stun::readErrorCode(m, errorCode, reason);

	switch (tx.kind) {
	case PendingTx::Kind::Allocate:
		pending_.erase(it);
		handleAllocateResponse(m, isError);
		break;
	case PendingTx::Kind::Refresh:
		pending_.erase(it);
		handleRefreshResponse(m, isError);
		break;
	case PendingTx::Kind::CreatePermission:
		// Clear the in-flight tid before dispatch so a retry can start a new one.
		for (auto &b : bindings_)
			if (addrEqualNoPort(b.peer, tx.peer)) { b.permissionTidFresh = false; break; }
		pending_.erase(it);
		handleCreatePermissionResponse(m, isError, tx.peer);
		break;
	case PendingTx::Kind::ChannelBind:
		for (auto &b : bindings_)
			if (addrEqualNoPort(b.peer, tx.peer)) { b.channelTidFresh = false; break; }
		pending_.erase(it);
		handleChannelBindResponse(m, isError, tx.peer);
		break;
	case PendingTx::Kind::Connect:
		pending_.erase(it);
		handleConnectResponse(m, isError, tx.peer);
		break;
	}
}

void Client::handleAllocateResponse(const stun::Message &msg, bool isError) {
	// 401 Unauthenticated: capture REALM + NONCE and retry.
	if (isError) {
		int code = 0;
		std::string reason;
		stun::readErrorCode(msg, code, reason);
		log(STICE_LOG_LEVEL_DEBUG, "TURN allocate error response: code=%d reason=%s", code, reason.c_str());
		if (code == stun::StunErrorUnauthenticated) {
			// If we already sent credentials, a 401 means authentication
			// failed (wrong username/password). Don't retry — this would
			// cause an infinite 401 loop. Aligned with pion-turn, which
			// treats a second 401 as a fatal auth failure.
			if (creds_) {
				log(STICE_LOG_LEVEL_ERROR, "TURN allocate auth failed: credentials rejected (401)");
				state_ = AllocState::Failed;
				if (sink_.onFailed) sink_.onFailed(code, "authentication failed: " + reason);
				return;
			}
			creds_ = stun::Credentials{};
			creds_->username = cfg_.username;
			creds_->realm = stun::getString(msg, stun::AttrType::Realm);
			creds_->nonce = stun::getString(msg, stun::AttrType::Nonce);
			log(STICE_LOG_LEVEL_DEBUG, "TURN 401 retry: user=%s realm=%s nonce_len=%zu",
			    creds_->username.c_str(), creds_->realm.c_str(), creds_->nonce.size());
			// Retry allocate with credentials.
			state_ = AllocState::Idle;
			allocate();
			return;
		}
		if (code == stun::StunErrorStaleNonce) {
			// Guard against infinite 438 loops: limit nonce refreshes.
			if (++nonceRetries_ > MaxNonceRetries) {
				log(STICE_LOG_LEVEL_ERROR, "TURN allocate failed: too many stale nonce retries");
				state_ = AllocState::Failed;
				if (sink_.onFailed) sink_.onFailed(code, "stale nonce loop");
				return;
			}
			if (creds_) creds_->nonce = stun::getString(msg, stun::AttrType::Nonce);
			state_ = AllocState::Idle;
			allocate();
			return;
		}
		log(STICE_LOG_LEVEL_ERROR, "TURN allocate failed: %d %s", code, reason.c_str());
		state_ = AllocState::Failed;
		if (sink_.onFailed) sink_.onFailed(code, reason);
		return;
	}
	// Success: read XOR-RELAYED-ADDRESS and LIFETIME.
	net::AddrRecord relayed;
	if (!stun::readXorAddress(msg, stun::AttrType::XorRelayedAddress, relayed, msg.transactionID)) {
		log(STICE_LOG_LEVEL_ERROR, "TURN allocate success missing XOR-RELAYED-ADDRESS");
		state_ = AllocState::Failed;
		if (sink_.onFailed) sink_.onFailed(0, "missing relayed address");
		return;
	}
	relayedAddr_ = relayed;
	std::uint32_t lt = cfg_.requestedLifetime;
	stun::readLifetime(msg, lt);
	lifetime_ = lt;
	state_ = AllocState::Allocated;
	// Refresh at lifetime/2 with a random jitter of up to 10% of the lifetime
	// to avoid thundering herd when many sessions refresh simultaneously.
	// Aligned with str0m #551 (TURN refresh jitter) and RFC 5389 §7.2.1
	// (retransmission timing should be randomized).
	std::uint32_t baseSecs = std::max(1u, lt / 2);
	std::uint32_t jitterSecs = (lt > 10) ? (crypto::randomU32() % (lt / 10 + 1)) : 0;
	refreshAt_ = std::chrono::steady_clock::now() +
	             std::chrono::seconds(baseSecs + jitterSecs);
	if (sink_.onAllocated) sink_.onAllocated(relayed, lt);
}

void Client::handleRefreshResponse(const stun::Message &msg, bool isError) {
	if (isError) {
		int code = 0;
		std::string reason;
		stun::readErrorCode(msg, code, reason);
		// 438 StaleNonce: update nonce and retry (aligned with pion-turn's
		// refreshAllocation which retries up to 3 times on errTryAgain).
		if (code == stun::StunErrorStaleNonce) {
			if (creds_) creds_->nonce = stun::getString(msg, stun::AttrType::Nonce);
			log(STICE_LOG_LEVEL_DEBUG, "TURN refresh 438 StaleNonce, retrying with new nonce");
			sendRefresh(lifetime_);
			return;
		}
		// 401 Unauthenticated: re-capture realm/nonce and retry.
		if (code == stun::StunErrorUnauthenticated) {
			if (!creds_) creds_ = stun::Credentials{};
			creds_->username = cfg_.username;
			creds_->realm = stun::getString(msg, stun::AttrType::Realm);
			creds_->nonce = stun::getString(msg, stun::AttrType::Nonce);
			log(STICE_LOG_LEVEL_DEBUG, "TURN refresh 401, retrying with credentials");
			sendRefresh(lifetime_);
			return;
		}
		log(STICE_LOG_LEVEL_ERROR, "TURN refresh failed: %d %s", code, reason.c_str());
		state_ = AllocState::Failed;
		if (sink_.onFailed) sink_.onFailed(code, "refresh failed: " + reason);
		return;
	}
	// Refresh succeeded. Server may return a smaller lifetime.
	std::uint32_t lt = cfg_.requestedLifetime;
	stun::readLifetime(msg, lt);
	lifetime_ = lt;
	// Same jitter as allocate: up to 10% of lifetime to avoid herd refresh.
	std::uint32_t baseSecs = std::max(1u, lt / 2);
	std::uint32_t jitterSecs = (lt > 10) ? (crypto::randomU32() % (lt / 10 + 1)) : 0;
	refreshAt_ = std::chrono::steady_clock::now() +
	             std::chrono::seconds(baseSecs + jitterSecs);
}

void Client::handleCreatePermissionResponse(const stun::Message &msg, bool isError,
                                            const net::AddrRecord &peer) {
	auto &b = getBinding(peer);
	if (!isError) {
		b.permissionPermitted = true;
		b.permissionRefreshAt = std::chrono::steady_clock::now() + std::chrono::seconds(120);
		// Flush any data that was buffered while permission was pending.
		if (!b.pendingData.empty()) {
			log(STICE_LOG_LEVEL_DEBUG, "TURN CreatePermission ok: flushing %zu pending packets",
			    b.pendingData.size());
			for (auto &pkt : b.pendingData) {
				if (b.channelReady) {
					bytes frame;
					wrapChannelData(b.channel, pkt.data(), pkt.size(), frame);
					if (sink_.sendRaw) sink_.sendRaw(frame.data(), frame.size());
				} else {
					stun::Message sm;
					sm.method = stun::Method::Send;
					sm.cls = stun::Class::Indication;
					sm.newTransactionID();
					stun::writeXorAddress(sm, stun::AttrType::XorPeerAddress, peer, sm.transactionID);
					stun::addData(sm, pkt.data(), pkt.size());
					sm.encode(nullptr, nullptr, "stice");
					if (sink_.sendRaw) sink_.sendRaw(sm.raw.data(), sm.raw.size());
				}
			}
			b.pendingData.clear();
			if (b.channel == 0) sendChannelBind(peer);
		}
		return;
	}
	int code = 0;
	std::string reason;
	stun::readErrorCode(msg, code, reason);
	if (code == stun::StunErrorStaleNonce) {
		if (creds_) creds_->nonce = stun::getString(msg, stun::AttrType::Nonce);
		// Retry.
		b.permissionTidFresh = false;
		sendCreatePermission(peer);
		return;
	}
	if (code == stun::StunErrorUnauthenticated) {
		// Should not happen post-allocate, but handle anyway.
		if (!creds_) creds_ = stun::Credentials{};
		creds_->username = cfg_.username;
		creds_->realm = stun::getString(msg, stun::AttrType::Realm);
		creds_->nonce = stun::getString(msg, stun::AttrType::Nonce);
		b.permissionTidFresh = false;
		sendCreatePermission(peer);
		return;
	}
	log(STICE_LOG_LEVEL_WARN, "TURN CreatePermission failed: %d %s", code, reason.c_str());
}

void Client::handleChannelBindResponse(const stun::Message &msg, bool isError,
                                       const net::AddrRecord &peer) {
	auto &b = getBinding(peer);
	if (!isError) {
		b.channelReady = true;
		b.channelRefreshAt = std::chrono::steady_clock::now() + std::chrono::seconds(300);
		return;
	}
	int code = 0;
	std::string reason;
	stun::readErrorCode(msg, code, reason);
	if (code == stun::StunErrorStaleNonce) {
		if (creds_) creds_->nonce = stun::getString(msg, stun::AttrType::Nonce);
		b.channelTidFresh = false;
		sendChannelBind(peer);
		return;
	}
	// 400 BadRequest: aligned with pion-turn's recoverChannelBindBadRequest.
	// Coturn may return 400 for "same peer different channel" or channel
	// already bound. If the channel was previously ready (refresh scenario),
	// keep the old binding. Otherwise the initial ChannelBind failed fatally.
	if (code == 400) {
		if (b.channelReady) {
			// Channel was already bound — keep the old binding, Coturn still
			// has it. Just refresh the timer.
			log(STICE_LOG_LEVEL_WARN, "TURN ChannelBind 400 on refresh: keeping existing binding");
			b.channelRefreshAt = std::chrono::steady_clock::now() + std::chrono::seconds(300);
			return;
		}
		log(STICE_LOG_LEVEL_ERROR, "TURN ChannelBind 400 on initial bind: %s", reason.c_str());
		state_ = AllocState::Failed;
		if (sink_.onFailed) sink_.onFailed(code, "ChannelBind bad request: " + reason);
		return;
	}
	log(STICE_LOG_LEVEL_WARN, "TURN ChannelBind failed: %d %s", code, reason.c_str());
}

void Client::handleDataIndication(const stun::Message &msg) {
	net::AddrRecord peer;
	if (!stun::readXorAddress(msg, stun::AttrType::XorPeerAddress, peer, msg.transactionID)) return;
	const auto *data = msg.find(stun::AttrType::Data);
	if (!data) return;
	if (sink_.onData) sink_.onData(peer, data->value.data(), data->value.size());
}

void Client::handleChannelData(const unsigned char *data, std::size_t size) {
	std::uint16_t channel = 0;
	const unsigned char *payload = nullptr;
	std::size_t frameSize = 0;
	std::size_t dataLen = unwrapChannelData(data, size, channel, payload, frameSize);
	if (dataLen == 0) return;
	// Look up the peer for this channel.
	for (auto &b : bindings_) {
		if (b.channel == channel) {
			if (sink_.onData) sink_.onData(b.peer, payload, dataLen);
			return;
		}
	}
}

// --- RFC 6062 TCP allocation ---

void Client::sendConnect(const net::AddrRecord &peer) {
	if (state_ != AllocState::Allocated) {
		log(STICE_LOG_LEVEL_WARN, "TURN sendConnect: not allocated (state=%d)",
		    static_cast<int>(state_));
		return;
	}
	stun::Message m;
	m.method = stun::Method::Connect;
	m.cls = stun::Class::Request;
	m.newTransactionID();
	stun::writeXorAddress(m, stun::AttrType::XorPeerAddress, peer, m.transactionID);
	sendRequest(m);
	auto now = std::chrono::steady_clock::now();
	PendingTx tx;
	tx.kind = PendingTx::Kind::Connect;
	tx.peer = peer;
	tx.sentAt = now;
	tx.nextRetransmitAt = now + std::chrono::milliseconds(TurnRtoMs);
	tx.rawBytes = m.raw;
	pending_[tidKey(m.transactionID)] = std::move(tx);
	log(STICE_LOG_LEVEL_INFO, "TURN CONNECT: sent to peer=%s",
	    peer.toString().c_str());
}

std::vector<unsigned char> Client::buildConnectionBindRequest(std::uint32_t connectionId) {
	stun::Message m;
	m.method = stun::Method::ConnectionBind;
	m.cls = stun::Class::Request;
	m.newTransactionID();
	stun::addConnectionId(m, connectionId);
	applyCredentials(m);
	if (creds_ && !creds_->username.empty()) {
		m.encode(cfg_.password.c_str(), &*creds_, "stice");
	} else {
		m.encode(nullptr, nullptr, "stice");
	}
	return m.raw;
}

void Client::handleConnectResponse(const stun::Message &msg, bool isError,
                                   const net::AddrRecord &peer) {
	if (isError) {
		int code = 0;
		std::string reason;
		stun::readErrorCode(msg, code, reason);
		log(STICE_LOG_LEVEL_WARN, "TURN CONNECT error: code=%d reason=%s peer=%s",
		    code, reason.c_str(), peer.toString().c_str());
		if (sink_.onConnectFailed)
			sink_.onConnectFailed(code, reason, peer);
		return;
	}
	std::uint32_t connId = 0;
	if (!stun::readConnectionId(msg, connId)) {
		log(STICE_LOG_LEVEL_ERROR, "TURN CONNECT success missing CONNECTION-ID");
		return;
	}
	log(STICE_LOG_LEVEL_INFO, "TURN CONNECT success: connId=%u peer=%s",
	    connId, peer.toString().c_str());
	if (sink_.onConnectSuccess) sink_.onConnectSuccess(connId, peer);
}

void Client::handleConnectionAttempt(const stun::Message &msg) {
	net::AddrRecord peer;
	if (!stun::readXorAddress(msg, stun::AttrType::XorPeerAddress, peer, msg.transactionID)) {
		log(STICE_LOG_LEVEL_WARN, "TURN CONNECTION-ATTEMPT: missing XOR-PEER-ADDRESS");
		return;
	}
	std::uint32_t connId = 0;
	if (!stun::readConnectionId(msg, connId)) {
		log(STICE_LOG_LEVEL_WARN, "TURN CONNECTION-ATTEMPT: missing CONNECTION-ID");
		return;
	}
	log(STICE_LOG_LEVEL_INFO, "TURN CONNECTION-ATTEMPT: connId=%u peer=%s",
	    connId, peer.toString().c_str());
	if (sink_.onConnectionAttempt) sink_.onConnectionAttempt(connId, peer);
}

std::chrono::steady_clock::time_point Client::tick() {
	auto now = std::chrono::steady_clock::now();
	nextTick_ = std::chrono::steady_clock::time_point::max();

	// Unified retransmission for ALL pending transactions (aligned with
	// pion-turn's Transaction.StartRtxTimer: RTO=200ms, doubling to 1600ms,
	// max 7 retransmissions). Previously only Allocate had retransmission;
	// CreatePermission/ChannelBind/Refresh would hang silently on packet loss.
	for (auto it = pending_.begin(); it != pending_.end();) {
		auto &tx = it->second;
		if (now >= tx.nextRetransmitAt) {
			if (tx.retries >= TurnMaxRtxCount) {
				// Transaction timeout — handle based on kind.
				auto kind = tx.kind;
				auto peer = tx.peer;
				it = pending_.erase(it);
				switch (kind) {
				case PendingTx::Kind::Allocate:
					log(STICE_LOG_LEVEL_ERROR, "TURN allocate timeout after %d retransmits", TurnMaxRtxCount);
					state_ = AllocState::Failed;
					if (sink_.onFailed) sink_.onFailed(0, "allocate timeout");
					return {};
				case PendingTx::Kind::Refresh:
					log(STICE_LOG_LEVEL_ERROR, "TURN refresh timeout after %d retransmits", TurnMaxRtxCount);
					state_ = AllocState::Failed;
					if (sink_.onFailed) sink_.onFailed(0, "refresh timeout");
					return {};
				case PendingTx::Kind::CreatePermission:
					log(STICE_LOG_LEVEL_WARN, "TURN CreatePermission timeout (retransmits exhausted)");
					for (auto &b : bindings_)
						if (addrEqualNoPort(b.peer, peer)) { b.permissionTidFresh = false; break; }
					break;
				case PendingTx::Kind::ChannelBind:
				log(STICE_LOG_LEVEL_WARN, "TURN ChannelBind timeout (retransmits exhausted)");
				for (auto &b : bindings_)
					if (addrEqualNoPort(b.peer, peer)) { b.channelTidFresh = false; break; }
				break;
			case PendingTx::Kind::Connect:
				log(STICE_LOG_LEVEL_WARN, "TURN CONNECT timeout (retransmits exhausted) peer=%s",
				    peer.toString().c_str());
				break;
			}
			continue;
		}
		// Retransmit with the same TID (RFC 5389 §7.2.1).
		if (!tx.rawBytes.empty() && sink_.sendRaw)
			sink_.sendRaw(tx.rawBytes.data(), tx.rawBytes.size());
		++tx.retries;
		int interval = std::min(TurnRtoMs << tx.retries, TurnMaxRtxIntervalMs);
		tx.nextRetransmitAt = now + std::chrono::milliseconds(interval);
		log(STICE_LOG_LEVEL_DEBUG, "TURN retransmit kind=%d retry=%d next=%dms",
		    static_cast<int>(tx.kind), tx.retries, interval);
	}
		if (tx.nextRetransmitAt < nextTick_)
			nextTick_ = tx.nextRetransmitAt;
		++it;
	}

	// Refresh allocation if due.
	if (state_ == AllocState::Allocated && now >= refreshAt_) {
		sendRefresh(lifetime_);
	}

	// Refresh permissions / channels.
	for (auto &b : bindings_) {
		if (b.permissionPermitted && now >= b.permissionRefreshAt)
			sendCreatePermission(b.peer);
		if (b.channelReady && now >= b.channelRefreshAt)
			sendChannelBind(b.peer);
	}

	// Garbage-collect stale bindings: if a peer's permission refresh has been
	// pending (CreatePermission failed/timeout) for longer than 5 minutes past
	// its refresh time and there's no in-flight transaction, remove the entry
	// to prevent bindings_ from growing unboundedly on high-churn peer sets.
	// Aligned with str0m #574 (TURN permission table GC) and pion turnc#7.
	bindings_.erase(
	    std::remove_if(bindings_.begin(), bindings_.end(),
	                   [&](const PeerBinding &b) {
		                   if (b.permissionPermitted || b.channelReady) return false;
		                   if (b.permissionTidFresh || b.channelTidFresh) return false;
		                   // No active permission/channel: check if it's been
		                   // stale long enough (5 min after the last refresh time).
		                   auto staleDeadline = b.permissionRefreshAt +
		                                        std::chrono::minutes(5);
		                   return now > staleDeadline;
	                   }),
	    bindings_.end());

	// Final pass: include newly-sent transactions (from refresh logic above)
	// in the nextTick_ computation.
	for (const auto & [k, tx] : pending_) {
		if (tx.nextRetransmitAt < nextTick_)
			nextTick_ = tx.nextRetransmitAt;
	}
	for (const auto &b : bindings_) {
		if (b.permissionPermitted && b.permissionRefreshAt < nextTick_)
			nextTick_ = b.permissionRefreshAt;
		if (b.channelReady && b.channelRefreshAt < nextTick_)
			nextTick_ = b.channelRefreshAt;
	}
	if (state_ == AllocState::Allocated && refreshAt_ < nextTick_)
		nextTick_ = refreshAt_;
	if (nextTick_ == std::chrono::steady_clock::time_point::max())
		return {};
	return nextTick_;
}

} // namespace stice::turn
