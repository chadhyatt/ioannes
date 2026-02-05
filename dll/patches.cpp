#include <cassert>
#include <string>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <regex>
#include <io.h>
#include <windows.h>
#include <jansson.h>
#include "xxhash.h"
#include "Pattern16.h"
#include "libproxy_types.h"
#include "safetyhook.hpp"
#include "ulog.h"

#include "patches.hpp"
#include "dll.hpp"
#include "gui.hpp"
#include "types.hpp"
#include "macros.hpp"
#include "libproxy.h"

#define RL_ADDR(addr) reinterpret_cast<void *>(addr + reinterpret_cast<char *>(::ioannes::state->base))

std::regex jsonObjRe(R"(\{.*\})");

namespace ioannes::offsets {

namespace libcurl {
u64 detect_proxy;
}

namespace FWebSocket {
u64 Recv = 0xc1bbe0;
}

namespace PsyNet {
u64 VerifySig = 0xe03410;
}

namespace AES {
u64 appDecryptData = 0x2d2ba0;
}

namespace FAsyncIOSystemBase {
u64 FulfillCompressedRead = 0x30B6A0;
}

}  // namespace ioannes::offsets

namespace ioannes::hooks {

namespace user32 {
namespace ShowCursor {
SafetyHookInline hook;
int func(BOOL bShow) {
	ulog_debug("user32::ShowCursor(%d)", bShow);

	return hook.call<int>(bShow);
}
}  // namespace ShowCursor
}  // namespace user32

namespace ucrtbase {
namespace _stdio_common_vsnwprintf_s {
SafetyHookInline hook;
int func(unsigned __int64 Options, wchar_t *Buffer, size_t BufferCount, size_t MaxCount, const wchar_t *Format,
		 _locale_t Locale, va_list ArgList) {
	ulog_trace(
		"ucrtbase::_stdio_common_vsnwprintf_s(Options: %#x, Buffer: %#x, BufferCount: %d, MaxCount: %d, Format: %s, "
		"Locale: %#x, ArgList: %#x)",
		Options, Buffer, BufferCount, MaxCount, Format, Locale, ArgList);

	return hook.call<int>(Options, Buffer, BufferCount, MaxCount, Format, Locale, ArgList);
}
}  // namespace _stdio_common_vsnwprintf_s
}  // namespace ucrtbase

namespace libcurl {
namespace detect_proxy {
SafetyHookInline hook;
char *func(char *conn) {
	ulog_trace("libcurl::detect_proxy(conn: %#x)", conn);

	return const_cast<char *>("127.0.0.1:8080");  // hook.call<char*>(conn);
}
}  // namespace detect_proxy
}  // namespace libcurl

namespace FWebSocket {

namespace Recv {
SafetyHookInline hook;
i64 __attribute__((target("no-avx"))) func(char *self, char *dstBuf, int a3, int *dstBufLen) {
	ulog_trace("FWebSocket::Recv(%#x, %#x, %d, %#x)", self, dstBuf, a3, dstBufLen);
	auto ok = hook.call<i64>(self, dstBuf, a3, dstBufLen);

	if (ok) {
		ulog_trace("WS recv payload -> %.*s", *dstBufLen, dstBuf);

		std::string payloadStr;
		payloadStr.assign(dstBuf, *dstBufLen);
		if (payloadStr.find("ReservationsReadyMessage_X") != std::string::npos) {
			std::smatch matches;
			if (!std::regex_search(payloadStr, matches, jsonObjRe)) {
				ulog_error("JSON regex match failed");
				goto payloadRet;
			}

			std::string jsonPayload = matches[0];
			auto jsonPayloadIdx = matches.position(0);

			json_t *rt = json_loadb(jsonPayload.data(), jsonPayload.length(), JSON_ALLOW_NUL, NULL);
			if (!rt) {
				ulog_error("Failed to parse outer JSON");
				goto payloadRet;
			}

			json_t *msgPayloadObj = json_object_get(rt, "MessagePayload");
			const char *innerJsonStr = json_string_value(msgPayloadObj);
			json_t *msgPayload = innerJsonStr ? json_loads(innerJsonStr, JSON_ALLOW_NUL, NULL) : NULL;

			if (msgPayload == NULL) {
				ulog_error("Failed to parse inner MessagePayload JSON");
				json_decref(rt);
				goto payloadRet;
			}

			json_t *keysObj = json_object_get(msgPayload, "Keys");
			if (keysObj == NULL) {
				ulog_error("No .Keys ???");
				json_decref(msgPayload);
				json_decref(rt);
				goto payloadRet;
			}

			ProxyServerConfig config = {
				.serverAddr = json_string_value(json_object_get(msgPayload, "ServerAddress")),
				.pingAddr = json_string_value(json_object_get(msgPayload, "PingAddress")),
				.key = json_string_value(json_object_get(keysObj, "Key")),
				.iv = json_string_value(json_object_get(keysObj, "IV")),
				.hmacKey = json_string_value(json_object_get(keysObj, "HMACKey")),
				.sessionId = json_string_value(json_object_get(keysObj, "SessionID")),
				.luaAutoexecScript = NULL,
			};

			gui::wndState->editorMutex.lock();
			std::string editorText = gui::wndState->editor.GetText();
			if (gui::wndState->autoexec) {
				config.luaAutoexecScript = editorText.c_str();
			}
			gui::wndState->editorMutex.unlock();

			ProxyServerConfig mitmConfig = proxy_new_server(config);

			json_object_set_new(msgPayload, "ServerAddress", json_string(mitmConfig.serverAddr));
			json_object_set_new(msgPayload, "PingAddress", json_string(mitmConfig.pingAddr));
			json_object_set_new(keysObj, "Key", json_string(mitmConfig.key));
			json_object_set_new(keysObj, "IV", json_string(mitmConfig.iv));
			json_object_set_new(keysObj, "HMACKey", json_string(mitmConfig.hmacKey));
			json_object_set_new(keysObj, "SessionID", json_string(mitmConfig.sessionId));

			char *innerDump = json_dumps(msgPayload, JSON_COMPACT);
			json_decref(msgPayload);

			if (innerDump) {
				json_object_set_new(rt, "MessagePayload", json_string(innerDump));
				free(innerDump);
			} else {
				ulog_error("Failed to dump inner JSON");
			}

			char *outerDump = json_dumps(rt, JSON_COMPACT);
			json_decref(rt);

			if (outerDump) {
				payloadStr.replace(jsonPayloadIdx, std::string::npos, "");
				payloadStr.insert(jsonPayloadIdx, outerDump);

				free(outerDump);

				ulog_debug("MITM PAYLOAD OUT: %s", payloadStr.c_str());
			} else {
				ulog_error("Failed to dump outer JSON");
			}
		}

	payloadRet:
		// The FWebSocket::Recv heap buffer overflow in question:
		*dstBufLen = payloadStr.length();
		memcpy(dstBuf, payloadStr.data(), *dstBufLen);
	}

	return ok;
}
}  // namespace Recv

}  // namespace FWebSocket

namespace PsyNet {
namespace VerifySig {
SafetyHookInline hook;
BOOL func(void *self, void *reqCtx) {
	ulog_trace("PsyNet::VerifySig(%#x, %#x)", self, reqCtx);

	return TRUE;  // Confirmed real and true
}
}  // namespace VerifySig
}  // namespace PsyNet

namespace AES {
namespace appDecryptData {
SafetyHookInline hook;
i64 __attribute__((target("no-avx"))) func(BYTE *contents, DWORD numBytes, BYTE *key) {
	std::string keyHex = sha256_hex(key);
	ulog_trace("AES::appDecryptData(contents: %#x, numBytes: %d, key: %#x -> %s)", contents, numBytes, key,
			   keyHex.c_str());

	auto ok = hook.call<i64>(contents, numBytes, key);

	if (ok) {
#if DUMP_AES_DECRYPT
		std::string contentsHash = xxh128_hex(XXH3_128bits(contents, numBytes));
		ulog_debug("Dumping decrypted blob %s", contentsHash.c_str());

		RUN_ONCE([] { std::filesystem::create_directories(state->tmpDir / "aes-decrypt-dumps"); });
		std::filesystem::path outPath = state->tmpDir / "aes-decrypt-dumps" / (contentsHash + ".bin");

		FILE *fd = fopen(outPath.string().c_str(), "wb");
		if (fd == NULL) {
			ulog_error("Failed to open %s: %s (errno %d)", outPath.string().c_str(), strerror(errno), errno);
			goto ret;
		}

		fwrite(contents, numBytes, 1, fd);
		fclose(fd);
#endif
	}

ret:
	return ok;
}
}  // namespace appDecryptData
}  // namespace AES

namespace FAsyncIOSystemBase {
namespace FulfillCompressedRead {
SafetyHookInline hook;
i64 func(u64 *a1, i64 a2, __int128 *a3) {
	ulog_trace("FAsyncIOSystemBase::FulfillCompressedRead(%#x, %#x, %#x)", a1, a2, a3);
	auto ok = hook.call<i64>(a1, a2, a3);

	return ok;
}
}  // namespace FulfillCompressedRead
}  // namespace FAsyncIOSystemBase

}  // namespace ioannes::hooks

namespace ioannes {
bool scan_offsets(void) {
	ulog_info("Scanning offset signatures..");
	bool success = true;
#define SCAN(os, sig)                                                                                                 \
	{                                                                                                                 \
		std::string pat = (sig);                                                                                      \
		pat = REPLACE_PAT_FOR_PATTERN16(pat);                                                                         \
		auto baseAddr = reinterpret_cast<char *>(::ioannes::state->base);                                             \
		auto addr = reinterpret_cast<char *>(Pattern16::scan(baseAddr, ::ioannes::state->baseInfo.SizeOfImage, pat)); \
		if (addr) {                                                                                                   \
			offsets::os = (decltype(offsets::os))(addr - baseAddr);                                                   \
			ulog_debug("u64 " #os " = %#x,", offsets::os);                                                            \
		} else {                                                                                                      \
			ulog_error("Failed to find offset for " #os);                                                             \
			success = false;                                                                                          \
		}                                                                                                             \
	}

	// SCAN(libcurl::detect_proxy, "48 89 5C 24 ? 48 89 74 24 ? 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84
	// 24 ? ? ? ? 48 8B 81 ? ? ? ? 48 8D 5C 24");
	SCAN(FWebSocket::Recv, "48 89 5C 24 ? 57 48 83 EC ? 83 79 ? ? 49 8B F9");
	SCAN(PsyNet::VerifySig,
		 "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 "
		 "45 ? 48 8B FA");

	// Quettasig (probably extremely unstable, goes into the next function)
	SCAN(AES::appDecryptData,
		 "48 89 5C 24 ? 55 56 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 49 8B D8 8B FA 48 8B "
		 "F1 33 D2 41 B8 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 41 B8 ? ? ? ? 48 8D 4C 24 ? 48 8B D3 E8 ? ? ? ? 33 DB 8B E8 "
		 "85 FF 74 ? 66 66 0F 1F 84 00 ? ? ? ? 44 8B C3 48 8D 4C 24 ? 4C 03 C6 8B D5 4D 8B C8 E8 ? ? ? ? 83 C3 ? 3B DF "
		 "72 ? 48 8B 8C 24 ? ? ? ? 48 33 CC E8 ? ? ? ? 48 8B 9C 24 ? ? ? ? 48 81 C4 ? ? ? ? 5F 5E 5D C3 ? 48 89 5C 24");

	return success;
}

bool init_hooks(void) {
	ulog_info("Init hooks");
	bool success = true;
#define HOOK(ns)                                                                \
	{                                                                           \
		auto funcAddr = RL_ADDR(offsets::ns);                                   \
		hooks::ns::hook = safetyhook::create_inline(funcAddr, hooks::ns::func); \
		ulog_debug("Hooked " #ns " @ %#x", funcAddr);                           \
	}
#define SYM_HOOK(modName, symName, ns)                                               \
	{                                                                                \
		auto mod = GetModuleHandle(modName);                                         \
		if (!mod) {                                                                  \
			ulog_error("Failed to hook %s:%s: module not loaded", modName, symName); \
			success = false;                                                         \
		}                                                                            \
		auto symAddr = GetProcAddress(mod, symName);                                 \
		if (!symAddr) {                                                              \
			ulog_error("Failed to hook %s:%s: unknown symbol", modName, symName);    \
			success = false;                                                         \
		}                                                                            \
		hooks::ns::hook = safetyhook::create_inline(symAddr, hooks::ns::func);       \
		ulog_debug("Hooked %s:%s @ %#x", modName, symName, symAddr);                 \
	}

	// HOOK(libcurl::detect_proxy);
	HOOK(FWebSocket::Recv);
	HOOK(AES::appDecryptData);
	HOOK(PsyNet::VerifySig);
	// HOOK(FAsyncIOSystemBase::FulfillCompressedRead);

	// SYM_HOOK("ucrtbase.dll", "__stdio_common_vsnwprintf_s", ucrtbase::_stdio_common_vsnwprintf_s);
	// SYM_HOOK("user32.dll", "ShowCursor", user32::ShowCursor);

	return success;
}

bool init_patches(void) {
	ulog_info("Applying code patches");
#if !NO_SIGSCANS
	if (!scan_offsets()) return false;
#endif
	if (!init_hooks()) return false;

	return true;
}

}  // namespace ioannes
