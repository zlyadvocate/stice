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

#include <algorithm>
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

	// Remove all address-map entries that point to this agent.
	for (const auto &key : it->second->remoteAddressKeys) {
		agentsByAddr_.erase(key);
	}
	agentsByUfrag_.erase(it);
	STICE_LOG_INFO("UDPMux: removed agent ufrag=%s", ufrag.c_str());
}

int UDPMux::sendto(const char *data, std::size_t size, const AddrRecord &dst,
                   const std::string &ufrag) {
	// Register the destination address for fast-path routing of replies.
	// For loopback (destination is our own bound address), always overwrite
	// the address map entry with the current sender so routePacket knows
	// who sent the last packet and can deliver the looped-back data to the
	// OTHER agents (excluding the sender). Compare by port only since the
	// mux may bind to 0.0.0.0.
	AddrRecord bound;
	bool isLoopback = false;
	if (boundAddr(bound)) {
		auto *boundSa = reinterpret_cast<const struct sockaddr *>(&bound.addr);
		auto *dstSa = reinterpret_cast<const struct sockaddr *>(&dst.addr);
		isLoopback = (addrPort(boundSa) == addrPort(dstSa));
	}
	{
		std::lock_guard<std::mutex> lock(mutex_);
		auto it = agentsByUfrag_.find(ufrag);
		if (it != agentsByUfrag_.end()) {
			auto key = addrKey(dst);
			if (isLoopback) {
				// Always update to the latest sender for loopback.
				agentsByAddr_[key] = it->second;
				auto &keys = it->second->remoteAddressKeys;
				if (std::find(keys.begin(), keys.end(), key) == keys.end()) {
					keys.push_back(key);
				}
			} else {
				// Only register if not already present (avoid duplicate entries
				// in remoteAddressKeys).
				if (agentsByAddr_.find(key) == agentsByAddr_.end()) {
					agentsByAddr_[key] = it->second;
					it->second->remoteAddressKeys.push_back(key);
				}
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

int64_t UDPMux::nextTimestampMs() const {
	std::lock_guard<std::mutex> lock(mutex_);
	int64_t earliest = 0;
	for (const auto &kv : agentsByUfrag_) {
		if (!kv.second->nextTimestampMs) continue;
		int64_t t = kv.second->nextTimestampMs();
		if (t > 0 && (earliest == 0 || t < earliest)) earliest = t;
	}
	return earliest;
}

void UDPMux::onUdpReadable() {
	char buf[1500];
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
						// Register this address for non-STUN fast-path routing.
						if (agentsByAddr_.find(key) == agentsByAddr_.end()) {
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
	// Special case: when the source address is the mux's own bound address
	// (local loopback with shared socket), the address map entry points to
	// the SENDER, not the receiver. Broadcast to all agents EXCEPT the
	// sender so the data reaches the intended recipient without echoing
	// back to the sender.
	// The mux may bind to 0.0.0.0 (INADDR_ANY), so we compare by port only:
	// if the source port matches the mux's bound port, the packet was sent
	// from our own socket (loopback).
	AddrRecord bound;
	bool isLoopback = false;
	if (boundAddr(bound)) {
		auto *boundSa = reinterpret_cast<const struct sockaddr *>(&bound.addr);
		auto *srcSa = reinterpret_cast<const struct sockaddr *>(&src.addr);
		isLoopback = (addrPort(boundSa) == addrPort(srcSa));
	}

	std::shared_ptr<MuxAgentEntry> senderEntry;
	std::vector<std::shared_ptr<MuxAgentEntry>> snapshot;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		if (isLoopback) {
			auto it = agentsByAddr_.find(key);
			if (it != agentsByAddr_.end()) senderEntry = it->second;
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
