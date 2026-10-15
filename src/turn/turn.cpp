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
	failedEmitted_ = false;
	nonceRetries_ = 0;
}

bool Client::handleAuthError(const stun::Message &msg, int code, bool retryAuthed) {
	// Centralized 401/438 handling shared by all request types. Returns true
	// when the request should be re-sent with refreshed credentials.
	if (code == stun::StunErrorUnauthenticated) {
		// 401 while we already sent credentials is a wrong-password failure
		// for Allocate (would loop forever); for follow-up requests it is
		// normally a rotated nonce — re-capture and retry bounded.
		if (creds_ && !retryAuthed) return false;
		if (++nonceRetries_ > MaxNonceRetries) return false;
		if (!creds_) creds_ = stun::Credentials{};
		creds_->username = cfg_.username;
		creds_->realm = stun::getString(msg, stun::AttrType::Realm);
		creds_->nonce = stun::getString(msg, stun::AttrType::Nonce);
		return true;
	}
	if (code == stun::StunErrorStaleNonce) {
		// Bound the nonce-refresh loop across ALL transaction types (previously
		// only Allocate counted, so refresh/permission/channelbind could loop
		// against a misbehaving server).
		if (++nonceRetries_ > MaxNonceRetries) return false;
		if (creds_) creds_->nonce = stun::getString(msg, stun::AttrType::Nonce);
		return true;
	}
	return false;
}

void Client::failAllocation(int errorCode, const std::string &reason) {
	// Terminal: transition to Failed and emit onFailed AT MOST ONCE per
	// allocation. The Agent decrements its pending-relay counter in the
	// callback; a second emission would underflow it.
	if (failedEmitted_) return;
	failedEmitted_ = true;
	state_ = AllocState::Failed;
	pending_.clear();
	if (sink_.onFailed) sink_.onFailed(errorCode, reason);
}

void Client::allocate() {
	log(STICE_LOG_LEVEL_DEBUG, "TURN allocate: called state=%d", static_cast<int>(state_));
	if (state_ != AllocState::Idle) return;
	state_ = AllocState::Allocating;

	// RFC 5766 §14.7: REQUESTED-TRANSPORT=UDP(17) for UDP relay.
	// RFC 6062 §3.2: REQUESTED-TRANSPORT=TCP(6) for TCP allocation.
	// RFC 8656 (default): the relay is UDP even when the control connection
	// to the TURN server is carried over TCP/TLS. This is what browsers and
	// coturn interoperate with. RFC 6062 TCP allocation is opt-in and only
	// interoperable between stice agents.
	isTcpAllocation_ = cfg_.tcpAllocation;
	std::uint8_t proto = isTcpAllocation_ ? 6 : 17;

	stun::Message m;
	m.method = stun::Method::Allocate;
	m.cls = stun::Class::Request;
	m.newTransactionID();
	allocateTid_ = m.transactionID;
	stun::addRequestedTransport(m, proto);
	prepareRequest(m);

	auto now = std::chrono::steady_clock::now();
	PendingTx tx;
	tx.kind = PendingTx::Kind::Allocate;
	tx.sentAt = now;
	tx.nextRetransmitAt = now + std::chrono::milliseconds(TurnRtoMs);
	tx.rawBytes = m.raw;
	pending_[tidKey(m.transactionID)] = std::move(tx);

	nextTick_ = now + std::chrono::milliseconds(TurnRtoMs);
	sendPrepared(m);
	log(STICE_LOG_LEVEL_DEBUG, "ALLOC-SENT state=%d tid=%02x%02x%02x%02x tcpAlloc=%d",
	    static_cast<int>(state_), allocateTid_[0], allocateTid_[1], allocateTid_[2], allocateTid_[3],
	    static_cast<int>(isTcpAllocation_));
}

void Client::applyCredentials(stun::Message &m) {
	if (!creds_ || creds_->username.empty()) return;
	// Re-derive the long-term key in case the password changed.
	auto key = crypto::longTermKey(creds_->username, creds_->realm, cfg_.password);
	creds_->key = bytes(key.begin(), key.end());
}

void Client::sendRequest(stun::Message &m) {
	prepareRequest(m);
	sendPrepared(m);
}

void Client::prepareRequest(stun::Message &m) {
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
}

void Client::sendPrepared(const stun::Message &m) {
	log(STICE_LOG_LEVEL_DEBUG, "TURN-SEND method=%d cls=%d tid=%02x%02x%02x%02x raw=%zu",
	    static_cast<int>(m.method), static_cast<int>(m.cls),
	    m.transactionID[0], m.transactionID[1], m.transactionID[2], m.transactionID[3],
	    m.raw.size());
	if (sink_.sendRaw) {
		int n = sink_.sendRaw(m.raw.data(), m.raw.size());
		if (n <= 0)
			log(STICE_LOG_LEVEL_WARN, "TURN sendPrepared: sendRaw failed n=%d method=%d",
			    n, static_cast<int>(m.method));
	}
}

void Client::sendRefresh(std::uint32_t lifetime) {
	// In-flight guard (see refreshTidFresh_): the transaction timer owns
	// retransmission, so a second Refresh must not be issued while one is
	// outstanding. Callers that MUST bypass it clear the flag first (deallocate).
	if (refreshTidFresh_) return;
	stun::Message m;
	m.method = stun::Method::Refresh;
	m.cls = stun::Class::Request;
	m.newTransactionID();
	stun::addLifetime(m, lifetime);
	prepareRequest(m);
	auto now = std::chrono::steady_clock::now();
	PendingTx tx;
	tx.kind = PendingTx::Kind::Refresh;
	tx.sentAt = now;
	tx.nextRetransmitAt = now + std::chrono::milliseconds(TurnRtoMs);
	tx.rawBytes = m.raw;
	pending_[tidKey(m.transactionID)] = std::move(tx);
	refreshTidFresh_ = true;
	// Push the periodic deadline past the retransmit window. The definitive
	// schedule is set from the response's LIFETIME on success; this exists so
	// tick() stops returning a past-due time (which made the poll loop spin and
	// re-send on every iteration).
	refreshAt_ = now + std::chrono::milliseconds(TurnRtoMs);
	sendPrepared(m);
}

void Client::deallocate() {
	if (state_ != AllocState::Allocated) return;
	// The deallocating Refresh(0) must not be swallowed by the in-flight guard.
	refreshTidFresh_ = false;
	sendRefresh(0);
	// Deallocated (not Idle): the allocation is torn down; late Refresh(0)
	// responses must NOT re-arm the refresh timer (that previously
	// "resurrected" a deleted allocation until the next refresh fired on a
	// dead allocation). Terminal event emission is guarded by the sink-side
	// at-most-once contract, not by this state.
	state_ = AllocState::Deallocated;
}

PeerBinding &Client::getBinding(const net::AddrRecord &peer) {
	// Keyed on the FULL peer transport address (IP + port). RFC 5766 §11 keys a
	// permission on the peer IP but a channel binding on the peer transport
	// address; keying bindings on IP alone made every same-IP/different-port
	// peer share one PeerBinding - and therefore one channel number - so
	// ChannelData for one peer could be delivered to another. Permissions stay
	// IP-granular via hasPermission().
	for (auto &b : bindings_)
		if (b.peer == peer) return b;
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
	prepareRequest(m);

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
	sendPrepared(m);
}

void Client::sendChannelBind(const net::AddrRecord &peer) {
	auto &b = getBinding(peer);
	if (b.channelTidFresh) return;
	if (b.channel == 0) {
		// F3: pick a random channel number, skipping ones already bound to a
		// different peer (a collision would silently mis-route ChannelData).
		for (int attempt = 0; attempt < 8; ++attempt) {
			std::uint16_t c = randomChannelNumber();
			bool taken = false;
			for (const auto &ob : bindings_)
				if (&ob != &b && ob.channel == c) { taken = true; break; }
			if (!taken) { b.channel = c; break; }
		}
		if (b.channel == 0) b.channel = randomChannelNumber(); // exhausted: best effort
	}

	stun::Message m;
	m.method = stun::Method::ChannelBind;
	m.cls = stun::Class::Request;
	m.newTransactionID();
	stun::writeXorAddress(m, stun::AttrType::XorPeerAddress, peer, m.transactionID);
	stun::addChannelNumber(m, b.channel);
	prepareRequest(m);

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
	sendPrepared(m);
}

int Client::prepareChannelData(const net::AddrRecord &peer, const unsigned char *data,
                               std::size_t size, bytes &out) const {
	if (state_ != AllocState::Allocated) return -1;
	for (const auto &b : bindings_) {
		if (b.peer == peer) {
			if (!b.channelReady) return 0;
			std::size_t n = wrapChannelData(b.channel, data, size, out);
			if (n == 0) return -1;
			return 1;
		}
	}
	return 0; // no binding yet -> fall back to sendData
}

int Client::sendData(const net::AddrRecord &peer, const unsigned char *data, std::size_t size) {
	if (state_ != AllocState::Allocated) return -1;
	auto &b = getBinding(peer);

	// Ensure a permission exists; create one if missing. The check is
	// IP-granular (hasPermission), because a TURN permission authorises the
	// peer IP - while the binding this data belongs to is address-granular.
	if (!hasPermission(peer)) {
		if (!b.permissionTidFresh) sendCreatePermission(peer);
		// Buffer the data until CreatePermission completes (D1): bound the
		// pending buffer so a stalled CreatePermission (slow/lost response or
		// TCP head-of-line blocking) cannot grow unboundedly. When full, drop
		// the oldest packet and report backpressure to the caller.
		const std::size_t kMaxPendingDataPkts = 512;
		if (b.pendingData.size() >= kMaxPendingDataPkts) {
			b.pendingData.erase(b.pendingData.begin());
			log(STICE_LOG_LEVEL_WARN,
				    "TURN sendData: pending buffer full, dropping oldest packet (backpressure)");
		}
		b.pendingData.emplace_back(data, data + size);
		log(STICE_LOG_LEVEL_DEBUG, "TURN sendData: BUFFERED %zu bytes peer=%s (permission pending, perm=%d chan=%d chanReady=%d)",
		    size, peer.toString().c_str(), b.permissionPermitted ? 1 : 0,
		    (int)b.channel, b.channelReady ? 1 : 0);
		return static_cast<int>(size); // accepted; flushed on permission success
	}

	if (b.channelReady) {
		// ChannelData path (preferred).
		bytes frame;
		if (!wrapChannelData(b.channel, data, size, frame)) {
			log(STICE_LOG_LEVEL_ERROR,
			    "TURN sendData: payload too large for ChannelData (F1)");
			return -1; // reject oversized payload rather than truncate
		}
		if (!sink_.sendRaw) return -1;
		{
			int r = sink_.sendRaw(frame.data(), frame.size());
			log(STICE_LOG_LEVEL_DEBUG, "TURN sendData: SENT-CHDATA %zu bytes peer=%s ch=%u ret=%d",
			    size, peer.toString().c_str(), (int)b.channel, r);
			return r;
		}
	}
	// Send indication (no auth needed beyond FINGERPRINT).
	// F1: DATA's length field is 16-bit; reject oversized payloads instead of
	// silently truncating (callers must fragment). 4-byte header + XOR-PEER-
	// ADDRESS (8+8) + FINGERPRINT (8) + padding: the STUN message length field
	// is also 16-bit, so the whole envelope must stay < 65536 bytes.
	if (size > 0xFFFF - 40) {
		log(STICE_LOG_LEVEL_ERROR, "TURN sendData: payload too large for Send indication (F1)");
		return -1;
	}
	stun::Message m;
	m.method = stun::Method::Send;
	m.cls = stun::Class::Indication;
	m.newTransactionID();
	stun::writeXorAddress(m, stun::AttrType::XorPeerAddress, peer, m.transactionID);
	stun::addData(m, data, size);
	m.encode(nullptr, nullptr, "stice");
	int ret = -1;
	if (sink_.sendRaw) ret = sink_.sendRaw(m.raw.data(), m.raw.size());
	log(STICE_LOG_LEVEL_DEBUG, "TURN sendData: SENT-SEND-IND %zu bytes peer=%s ret=%d perm=%d chanReady=%d",
	    size, peer.toString().c_str(), ret, b.permissionPermitted ? 1 : 0,
	    b.channelReady ? 1 : 0);
	// Kick off ChannelBind so future sends use ChannelData.
	if (b.channel == 0) sendChannelBind(peer);
	return ret;
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
		// gathering. Must handle ALL non-terminal states, including Idle
		// (TCP path: allocate() hasn't run because the connection never
		// completed). failAllocation is idempotent, so an allocation that
		// already succeeded here (Allocated) still fires onFailed exactly
		// once — without the guard the Agent's counter would underflow.
		if (state_ != AllocState::Failed) {
			log(STICE_LOG_LEVEL_WARN, "TURN transport failure (state=%d)",
			    static_cast<int>(state_));
			failAllocation(0, "transport failure");
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
	log(STICE_LOG_LEVEL_DEBUG, "TURN-IN method=%d cls=%d tid=%02x%02x%02x%02x pending=%zu state=%d",
	    static_cast<int>(m.method), static_cast<int>(m.cls),
	    m.transactionID[0], m.transactionID[1], m.transactionID[2], m.transactionID[3],
	    pending_.size(), static_cast<int>(state_));
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
		std::string keys;
		for (const auto &[k, tx] : pending_) {
			if (!keys.empty()) keys += ",";
			keys += k.substr(0, 8);
		}
		log(STICE_LOG_LEVEL_WARN,
		    "TURN handleStunResponse: no pending TID match (tid=%02x%02x%02x%02x method=%d cls=%d) pending=%zu keys=[%s]",
		    m.transactionID[0], m.transactionID[1], m.transactionID[2], m.transactionID[3],
		    static_cast<int>(m.method), static_cast<int>(m.cls), pending_.size(), keys.c_str());
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
		// Clear the in-flight tid before dispatch so a retry can start a new one.
		refreshTidFresh_ = false;
		pending_.erase(it);
		handleRefreshResponse(m, isError);
		break;
	case PendingTx::Kind::CreatePermission:
		// Clear the in-flight tid before dispatch so a retry can start a new one.
		// Bindings are full-address keyed now, so match the exact peer.
		for (auto &b : bindings_)
			if (b.peer == tx.peer) { b.permissionTidFresh = false; break; }
		pending_.erase(it);
		handleCreatePermissionResponse(m, isError, tx.peer);
		break;
	case PendingTx::Kind::ChannelBind:
		// Clear the in-flight tid before dispatch so a retry can start a new one.
		for (auto &b : bindings_)
			if (b.peer == tx.peer) { b.channelTidFresh = false; break; }
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
		log(STICE_LOG_LEVEL_WARN, "TURN-ALLOC-ERR code=%d reason=%s", code, reason.c_str());
		if (code == stun::StunErrorUnauthenticated || code == stun::StunErrorStaleNonce) {
			// Centralized: 401-captured (first) / 438-nonce-refresh, bounded by
			// MaxNonceRetries. A 401 after we already sent credentials is a
			// wrong-password fatal (retrying would loop forever).
			if (handleAuthError(msg, code, /*retryAuthed=*/false)) {
				log(STICE_LOG_LEVEL_DEBUG, "TURN auth retry: code=%d nonce_len=%zu",
				    code, creds_ ? creds_->nonce.size() : 0u);
				state_ = AllocState::Idle;
				allocate();
				return;
			}
			log(STICE_LOG_LEVEL_ERROR, "TURN allocate auth failed: code=%d reason=%s",
			    code, reason.c_str());
			failAllocation(code, code == stun::StunErrorUnauthenticated && creds_
			                     ? "authentication failed: " + reason
			                     : ("allocate failed: " + reason));
			return;
		}
		log(STICE_LOG_LEVEL_ERROR, "TURN allocate failed: %d %s", code, reason.c_str());
		failAllocation(code, reason);
		return;
	}
	// Success: read XOR-RELAYED-ADDRESS and LIFETIME. Reset the nonce-retry
	// budget — the credential path is proven working (aligned with pion).
	nonceRetries_ = 0;
	net::AddrRecord relayed;
	if (!stun::readXorAddress(msg, stun::AttrType::XorRelayedAddress, relayed, msg.transactionID)) {
		log(STICE_LOG_LEVEL_ERROR, "TURN allocate success missing XOR-RELAYED-ADDRESS");
		failAllocation(0, "missing relayed address");
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
		if (handleAuthError(msg, code, /*retryAuthed=*/true)) {
			log(STICE_LOG_LEVEL_DEBUG, "TURN refresh auth refresh: code=%d, retrying", code);
			sendRefresh(lifetime_);
			return;
		}
		log(STICE_LOG_LEVEL_ERROR, "TURN refresh failed: %d %s", code, reason.c_str());
		failAllocation(code, "refresh failed: " + reason);
		return;
	}
	// Refresh succeeded: credentials proven, reset the nonce-retry budget.
	nonceRetries_ = 0;
	// A success response to Refresh(0) (deallocate) must NOT re-arm the
	// refresh timer — the allocation is gone (C2: Deallocated terminal).
	if (state_ == AllocState::Deallocated) return;
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
		// Any authenticated success proves the credential path works, so the
		// nonce-retry budget must track CONSECUTIVE failures only (aligned with
		// the Allocate/Refresh success paths).
		nonceRetries_ = 0;
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
	if (handleAuthError(msg, code, /*retryAuthed=*/true)) {
		// 438/401 with a refreshed nonce: retry the permission request.
		b.permissionTidFresh = false;
		sendCreatePermission(peer);
		return;
	}
	log(STICE_LOG_LEVEL_WARN, "TURN CreatePermission failed: %d %s", code, reason.c_str());
	// Terminal permission failure: drop the data buffered while it was pending so
	// a later successful permission cannot flush long-stale packets.
	if (!b.pendingData.empty()) {
		log(STICE_LOG_LEVEL_DEBUG, "TURN CreatePermission failed: dropping %zu stale buffered packets",
		    b.pendingData.size());
		b.pendingData.clear();
	}
}

void Client::handleChannelBindResponse(const stun::Message &msg, bool isError,
                                       const net::AddrRecord &peer) {
	auto &b = getBinding(peer);
	if (!isError) {
		// See handleCreatePermissionResponse: only consecutive auth failures
		// should count against the nonce-retry budget.
		nonceRetries_ = 0;
		b.channelReady = true;
		b.channelRefreshAt = std::chrono::steady_clock::now() + std::chrono::seconds(300);
		return;
	}
	int code = 0;
	std::string reason;
	stun::readErrorCode(msg, code, reason);
	if (handleAuthError(msg, code, /*retryAuthed=*/true)) {
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
	// Look up the peer for this channel. RFC 8656 ChannelData carries no peer
	// address; the channel number is assigned by the SENDING client and only
	// meaningful to that client + the server. In the ICE-over-TURN topology the
	// two agents each pick their own (independent) channel number, so the
	// RECEIVING client cannot find this channel in its own table. In the common
	// per-agent single-peer case, fall back to the sole binding; otherwise drop
	// (no way to disambiguate multiple peers without the peer address).
	for (auto &b : bindings_) {
		if (b.channel == channel) {
			if (sink_.onData) sink_.onData(b.peer, payload, dataLen);
			return;
		}
	}
	if (bindings_.size() == 1) {
		log(STICE_LOG_LEVEL_WARN,
		    "TURN handleChannelData: channel %u not in local table (peer channel); "
		    "falling back to sole binding peer=%s",
		    (int)channel, bindings_.front().peer.toString().c_str());
		if (sink_.onData) sink_.onData(bindings_.front().peer, payload, dataLen);
		return;
	}
	log(STICE_LOG_LEVEL_WARN,
	    "TURN handleChannelData: unknown channel %u with %zu bindings, dropping %zu bytes",
	    (int)channel, bindings_.size(), dataLen);
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
	prepareRequest(m);
	auto now = std::chrono::steady_clock::now();
	PendingTx tx;
	tx.kind = PendingTx::Kind::Connect;
	tx.peer = peer;
	tx.sentAt = now;
	tx.nextRetransmitAt = now + std::chrono::milliseconds(TurnRtoMs);
	tx.rawBytes = m.raw;
	pending_[tidKey(m.transactionID)] = std::move(tx);
	sendPrepared(m);
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

	// Unified transaction timer for ALL pending transactions.
	//
	// UDP (RFC 5389 §7.2.1): RTO=200ms, doubling to 1600ms, max 7 retransmits.
	// TCP/TLS (RFC 8656 §7): the transport is already reliable, so we MUST NOT
	// retransmit the application-layer transaction (a duplicate Allocate/
	// CreatePermission on the same control connection confuses servers like
	// coturn). We only run the timeout-to-failure clock (~TurnRtoMs * 2^7 =
	// the same overall budget as UDP) and fail the transaction when no
	// response arrives, which in turn drives the Agent's transport-loss path.
	const bool reliable = cfg_.transport != TurnTransport::UDP;
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
					failAllocation(0, "allocate timeout");
					return {};
				case PendingTx::Kind::Refresh:
					log(STICE_LOG_LEVEL_ERROR, "TURN refresh timeout after %d retransmits", TurnMaxRtxCount);
					refreshTidFresh_ = false;
					failAllocation(0, "refresh timeout");
					return {};
				case PendingTx::Kind::CreatePermission:
					log(STICE_LOG_LEVEL_WARN, "TURN CreatePermission timeout (retransmits exhausted)");
					for (auto &b : bindings_) {
						if (b.peer == peer) {
							b.permissionTidFresh = false;
							// Terminal failure: stale buffered data must not be
							// flushed by a later (retried) successful permission.
							if (!b.pendingData.empty()) {
								log(STICE_LOG_LEVEL_DEBUG,
									"TURN CreatePermission timeout: dropping %zu stale buffered packets",
									b.pendingData.size());
								b.pendingData.clear();
							}
							break;
						}
					}
					break;
				case PendingTx::Kind::ChannelBind: {
					log(STICE_LOG_LEVEL_WARN, "TURN ChannelBind timeout (retransmits exhausted)");
					for (auto &b : bindings_) {
						if (b.peer == peer) {
							b.channelTidFresh = false;
							if (!hasPermission(b.peer) && !b.pendingData.empty()) {
								log(STICE_LOG_LEVEL_WARN,
									"TURN ChannelBind timeout + no permission: dropping %zu buffered packets",
									b.pendingData.size());
								b.pendingData.clear();
							}
							break;
						}
					}
					break;
				}
			case PendingTx::Kind::Connect:
				log(STICE_LOG_LEVEL_WARN, "TURN CONNECT timeout (retransmits exhausted) peer=%s",
				    peer.toString().c_str());
				break;
			}
			continue;
		}
		// Retransmit with the same TID (RFC 5389 §7.2.1). On reliable transports
		// (TCP/TLS, RFC 8656 §7) we MUST NOT retransmit the application-layer
		// transaction — the transport already guarantees delivery, and a duplicate
		// Allocate/CreatePermission/ChannelBind with the same TID confuses servers
		// like coturn (400/401 protocol error). Only UDP retransmits; TCP/TLS keeps
		// only the timeout-to-failure clock (B1).
		if (!reliable && !tx.rawBytes.empty() && sink_.sendRaw)
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
