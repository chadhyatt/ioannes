#pragma once

#include "gui.hpp"
#include "libproxy.h"

namespace ioannes::callbacks {

inline void add_log(const char *str) {
	if (gui::wndState == nullptr) {
		return;
	}

	gui::wndState->consoleMutex.lock();
	gui::wndState->console.AddLog("%s\n", str);
	gui::wndState->consoleMutex.unlock();
}

inline void add_packet(ProxyPacket *pkt) {
	gui::wndState->packetMutex.lock();
	if (!gui::wndState->isCapturing) return;

	gui::wndState->packets.push_back(pkt);

	gui::wndState->packetMutex.unlock();
}

}  // namespace ioannes::callbacks
