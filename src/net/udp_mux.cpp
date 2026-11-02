/**
 * Copyright (c) 2019-2026 zlyadvocate
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "stice/net/udp_mux.hpp"
#include "stice/log.hpp"
#include "stice/stun/attributes.hpp"
#include "stice/stun/message.hpp"

#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace stice::net {

namespace {
// Upper bound on queued loopback attributions and the age after which an
// unmatched entry is dropped. A healthy loopback turnaround is well under
// 1 ms; the window only absorbs pathological stalls.
constexpr std::size_t MaxLoopbackPending = 64;
constexpr int LoopbackAttributionWindowMs = 50;
} // namespace

UDPMux::UDPMux() = default;

UDPMux::~UDPMux() {
	if (pollReg_) {
		pollReg_->remove(this);
		pollReg_->sync();
		pollReg_->release();
		pollReg_ = nullptr;
	}
}

bool UDPMux::init(const UdpSocketConfig &cfg) {
	sock_ = UdpSocket::create(cfg);
	if (!sock_.valid()) {
		STICE_LOG_ERROR("UDPMux: failed to create shared UDP socket");
		return false;
	}
	pollReg_ = PollRegistry::acquire();
	pollReg_->add(this);
	return true;
}

std::string UDPMux::addrKey(const AddrRecord &addr) {
	return addr.toString();
}

void UDPMux::interrupt() {
	if (pollReg_) pollReg_->interrupt();
}

void UDPMux::registerAgent(const std::string &ufrag,
                           std::function<void(const char *, int, const AddrRecord &)> onPacket,
                           std::function<void(int64_t)> onBookkeeping,
                           std::function<int64_t()> nextTimestampMs) {
	std::lock_guard<std::mutex> lock(mutex_);
	auto entry = std::make_shared<MuxAgentEntry>();
	entry->ufrag = ufrag;
	entry->onPacket = std::move(onPacket);
	entry->onBookkeeping = std::move(onBookkeeping);
	entry->nextTimestampMs = std::move(nextTimestampMs);
	agentsByUfrag_[ufrag] = entry;
	STICE_LOG_INFO("UDPMux: registered agent ufrag=%s", ufrag.c_str());
}

void UDPMux::removeAgent(const std::string &ufrag) {
	std::lock_guard<std::mutex> lock(mutex_);
	auto it = agentsByUfrag_.find(ufrag);
	if (it == agentsByUfrag_.end()) return;

	// Remove address-map entries that still point to this agent. agentsByAddr_
	// keeps one entry per remote address; another agent may have overwritten
	// the same key, so only erase when it still refers to this agent.
	for (const auto &key : it->second->remoteAddressKeys) {
		auto addrIt = agentsByAddr_.find(key);
		if (addrIt != agentsByAddr_.end() && addrIt->second == it->second) {
			agentsByAddr_.erase(addrIt);
		}
	}
	// Purge this agent from the loopback attribution queue: its in-flight
	// packets (if any) then arrive with no matching entry and are broadcast
	// to all agents — a removed generation must never remain the attributed
	// sender that loopback broadcasts exclude.
	for (auto lit = loopbackPending_.begin(); lit != loopbackPending_.end();) {
		if (lit->sender == it->second)
			lit = loopbackPending_.erase(lit);
		else
			++lit;
	}
	agentsByUfrag_.erase(it);
	STICE_LOG_INFO("UDPMux: removed agent ufrag=%s", ufrag.c_str());
}

bool UDPMux::isLoopbackDst(const AddrRecord &dst) const {
	AddrRecord bound;
	if (!boundAddr(bound)) return false;
	auto *boundSa = reinterpret_cast<const struct sockaddr *>(&bound.addr);
	auto *dstSa = reinterpret_cast<const struct sockaddr *>(&dst.addr);
	return addrPort(boundSa) == addrPort(dstSa);
}

int UDPMux::sendto(const char *data, std::size_t size, const AddrRecord &dst,
                   const std::string &ufrag) {
	bool loopback = isLoopbackDst(dst);

	// Loopback non-STUN data: enqueue the per-packet sender attribution and
	// send under ONE critical section, so concurrent agents' enqueue order
	// matches the shared socket's wire order (the recvfrom side pairs by
	// FIFO). STUN loopback packets are routed by USERNAME on receive and
	// carry no attribution. The address map is NOT touched: it only ever
	// holds remote addresses, and registering the mux's own address under
	// any agent would poison loopback routing after a restart.
	if (loopback && !stun::Message::isMessage(reinterpret_cast<const unsigned char *>(data), size)) {
		std::lock_guard<std::mutex> lock(mutex_);
		auto it = agentsByUfrag_.find(ufrag);
		if (it != agentsByUfrag_.end()) {
			loopbackPending_.push_back({std::chrono::steady_clock::now(), it->second});
			while (loopbackPending_.size() > MaxLoopbackPending) loopbackPending_.pop_front();
		}
		// Unknown ufrag (restart window, retired generation): send without
		// attribution — the packet is broadcast to all agents on arrival.
		return sock_.sendto(data, size, dst);
	}

	// Register the remote destination for fast-path routing of replies
	// (only if not already present, to avoid duplicate remoteAddressKeys).
	if (!loopback) {
		std::lock_guard<std::mutex> lock(mutex_);
		auto it = agentsByUfrag_.find(ufrag);
		if (it != agentsByUfrag_.end()) {
			auto key = addrKey(dst);
			if (agentsByAddr_.find(key) == agentsByAddr_.end()) {
				agentsByAddr_[key] = it->second;
				it->second->remoteAddressKeys.push_back(key);
			}
		}
	}
	return sock_.sendto(data, size, dst);
}

std::vector<AddrRecord> UDPMux::localAddrs(int family) const {
	return sock_.localAddrs(family);
}

bool UDPMux::boundAddr(AddrRecord &out) const {
	return sock_.boundAddr(out);
}

int UDPMux::setDiffserv(int ds) {
	return sock_.setDiffserv(ds);
}

int UDPMux::sendtoWithDiffserv(const char *data, std::size_t size,
                               const AddrRecord &dst, int ds,
                               const std::string &ufrag) {
	// Same discipline as sendto(): loopback non-STUN app data gets a
	// per-packet sender attribution (enqueued and sent under one critical
	// section so enqueue order matches wire order); remote destinations get
	// fast-path registration. Without the attribution, app data sent by
	// muxed agents would be broadcast as if the last STUN sender sent it.
	bool loopback = isLoopbackDst(dst);
	if (loopback && !stun::Message::isMessage(reinterpret_cast<const unsigned char *>(data), size)) {
		std::lock_guard<std::mutex> lock(mutex_);
		auto it = agentsByUfrag_.find(ufrag);
		if (it != agentsByUfrag_.end()) {
			loopbackPending_.push_back({std::chrono::steady_clock::now(), it->second});
			while (loopbackPending_.size() > MaxLoopbackPending) loopbackPending_.pop_front();
		}
		// The set/send/reset DSCP window stays serialized on the socket;
		// holding the mux mutex here additionally serializes it against
		// concurrent loopback senders.
		return sock_.sendtoWithDiffserv(data, size, dst, ds);
	}
	{
		std::lock_guard<std::mutex> lock(mutex_);
		auto it = agentsByUfrag_.find(ufrag);
		if (it != agentsByUfrag_.end() && !loopback) {
			auto key = addrKey(dst);
			if (agentsByAddr_.find(key) == agentsByAddr_.end()) {
				agentsByAddr_[key] = it->second;
				it->second->remoteAddressKeys.push_back(key);
			}
		}
	}
	return sock_.sendtoWithDiffserv(data, size, dst, ds);
}

int64_t UDPMux::nextTimestampMs() const {
	// Snapshot the entries under the lock, then invoke the agent callbacks
	// OUTSIDE it. The callbacks take the agent's own mutex, and an agent
	// thread holds that mutex while calling into this mux (restart()'s
	// removeAgent/registerAgent, sendto's sendtoWithDiffserv) — holding
	// mux mutex across the callback would form an AB-BA cycle with the
	// mux poll thread, which runs this function every poll iteration.
	std::vector<std::shared_ptr<MuxAgentEntry>> snapshot;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		snapshot.reserve(agentsByUfrag_.size());
		for (const auto &kv : agentsByUfrag_) snapshot.push_back(kv.second);
	}
	int64_t earliest = 0;
	for (const auto &entry : snapshot) {
		if (!entry->nextTimestampMs) continue;
		int64_t t = entry->nextTimestampMs();
		if (t > 0 && (earliest == 0 || t < earliest)) earliest = t;
	}
	return earliest;
}

void UDPMux::onUdpReadable() {
	// 64KB buffer: TURN-relayed datagrams (ChannelData with large app
	// payloads) exceed the 1500-byte MTU; a small buffer drops them.
	char buf[65536];
	AddrRecord src;
	while (true) {
		int n = sock_.recvfrom(buf, sizeof(buf), src);
		if (n <= 0) break;
		routePacket(buf, n, src);
	}
}

void UDPMux::routePacket(const char *buf, int len, const AddrRecord &src) {
	auto key = addrKey(src);

	const auto *data = reinterpret_cast<const unsigned char *>(buf);
	bool isStun = stun::Message::isMessage(data, static_cast<std::size_t>(len));

	// Loopback detection: the source is our own bound address, i.e. the
	// packet was sent by one of our own agents through the shared socket.
	// The mux may bind to 0.0.0.0 (INADDR_ANY), so compare by port only.
	AddrRecord bound;
	bool isLoopback = false;
	if (boundAddr(bound)) {
		auto *boundSa = reinterpret_cast<const struct sockaddr *>(&bound.addr);
		auto *srcSa = reinterpret_cast<const struct sockaddr *>(&src.addr);
		isLoopback = (addrPort(boundSa) == addrPort(srcSa));
	}

	// For STUN messages with USERNAME (binding requests), route by local
	// ufrag. This is necessary because multiple agents sharing the same
	// socket have the same address, so the address map alone cannot
	// distinguish them.
	//
	// For STUN messages WITHOUT USERNAME (binding responses, indications),
	// broadcast to ALL registered agents. Each agent checks whether the
	// transaction ID matches one of its pending entries and silently drops
	// non-matching messages. This is correct because only the agent that
	// sent the original request will have a matching TID.
	//
	// For non-STUN traffic (application data), use the address map (fast path).
	if (isStun) {
		stun::Message msg;
		if (msg.decode(data, static_cast<std::size_t>(len))) {
			std::string username = stun::getString(msg, stun::AttrType::Username);
			if (!username.empty()) {
				// USERNAME format: "localUfrag:remoteUfrag"
				// Take the part before the colon (local ufrag).
				auto colonPos = username.find(':');
				std::string localUfrag = (colonPos != std::string::npos)
				                             ? username.substr(0, colonPos)
				                             : username;

				std::shared_ptr<MuxAgentEntry> entry;
				{
					std::lock_guard<std::mutex> lock(mutex_);
					auto it = agentsByUfrag_.find(localUfrag);
					if (it != agentsByUfrag_.end()) {
						entry = it->second;
						// Register this remote address for non-STUN
						// fast-path routing. Loopback sources are NOT
						// address-map material: the map only ever holds
						// remote addresses, and registering the mux's own
						// address under the DESTINATION agent would poison
						// loopback attribution (agentsByAddr_ must never
						// mix the two semantics).
						if (!isLoopback &&
						    agentsByAddr_.find(key) == agentsByAddr_.end()) {
							agentsByAddr_[key] = entry;
							entry->remoteAddressKeys.push_back(key);
						}
					}
				}
				// Call onPacket OUTSIDE the mux mutex: the agent's callback
				// may call sendto() on this mux, which acquires the same
				// mutex. std::mutex is non-recursive, so holding it here
				// would deadlock.
				if (entry) {
					if (entry->onPacket) entry->onPacket(buf, len, src);
				} else {
					STICE_LOG_DEBUG("UDPMux: no agent for ufrag=%s", localUfrag.c_str());
				}
				return;
			}
		}

		STICE_LOG_WARN("UDPMUX-ROUTE: STUN resp/ind %dB from=%s agents=%zu", len, src.toString().c_str(), agentsByUfrag_.size());
		// STUN message without USERNAME (response, indication, or decode
		// failure): broadcast to all agents. Only the agent with a matching
		// transaction ID will process it.
		std::vector<std::shared_ptr<MuxAgentEntry>> snapshot;
		{
			std::lock_guard<std::mutex> lock(mutex_);
			snapshot.reserve(agentsByUfrag_.size());
			for (const auto &kv : agentsByUfrag_) {
				snapshot.push_back(kv.second);
			}
		}
		for (const auto &entry : snapshot) {
			if (entry->onPacket) entry->onPacket(buf, len, src);
		}
		return;
	}

	// Non-STUN: use the address map (fast path).
	// Special case: loopback app data (sent by one of our own agents to the
	// shared mux address). Pair with the FIFO attribution queue: the queue
	// head is this in-flight packet's sender (single shared socket delivers
	// loopback datagrams in send order). Broadcast to every agent EXCEPT
	// that sender; no matching entry (expired, purged by removeAgent, or
	// sent by an unknown ufrag) broadcasts to ALL agents — over-delivery is
	// benign, permanent under-delivery is not.
	std::shared_ptr<MuxAgentEntry> senderEntry;
	std::vector<std::shared_ptr<MuxAgentEntry>> snapshot;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		if (isLoopback) {
			auto now = std::chrono::steady_clock::now();
			while (!loopbackPending_.empty()) {
				auto &front = loopbackPending_.front();
				if (now - front.sent >
				    std::chrono::milliseconds(LoopbackAttributionWindowMs)) {
					loopbackPending_.pop_front();
					continue;
				}
				senderEntry = front.sender;
				loopbackPending_.pop_front();
				break;
			}
			snapshot.reserve(agentsByUfrag_.size());
			for (const auto &kv : agentsByUfrag_) {
				if (kv.second != senderEntry) snapshot.push_back(kv.second);
			}
		} else {
			auto it = agentsByAddr_.find(key);
			if (it != agentsByAddr_.end()) snapshot.push_back(it->second);
		}
	}

	if (snapshot.empty()) {
		STICE_LOG_DEBUG("UDPMux: dropping %d bytes from %s", len, src.toString().c_str());
		return;
	}

	for (const auto &e : snapshot) {
		if (e && e->onPacket) e->onPacket(buf, len, src);
	}
}

void UDPMux::onBookkeeping(int64_t nowMs) {
	// Snapshot the agent list to avoid holding the lock while calling back.
	std::vector<std::shared_ptr<MuxAgentEntry>> snapshot;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		snapshot.reserve(agentsByUfrag_.size());
		for (const auto &kv : agentsByUfrag_) {
			snapshot.push_back(kv.second);
		}
	}
	for (const auto &entry : snapshot) {
		if (entry->onBookkeeping) entry->onBookkeeping(nowMs);
	}
}

} // namespace stice::net
