#pragma once
#include <cstdlib>
#include <cstdio>
#include <cinttypes>
#include <mutex>
#include <print>
#include <fmt/format.h>
#include "xxhash.h"
#include "ulog.h"

#include "libproxy.h"

#define DLL_EXPORT __declspec(dllexport)

#define CRIT(...)                                  \
	{                                              \
		ulog_fatal("IOHANCRITICAL: " __VA_ARGS__); \
		exit(2);                                   \
	}

#define GOSTR(s) ((GoString){.p = (char *)(s), .n = (ptrdiff_t)strlen(s)})

#define REPLACE_PAT_FOR_PATTERN16(pat) std::regex_replace(pat, std::regex("\\?"), "??")

inline static std::once_flag _iohanOnceFlag;
#define RUN_ONCE(f)                        \
	{                                      \
		std::call_once(_iohanOnceFlag, f); \
	}

inline std::string xxh128_hex(const XXH128_hash_t &h) {
	return fmt::format("{:016x}{:016x}", static_cast<uint64_t>(h.high64), static_cast<uint64_t>(h.low64));
}

inline std::string sha256_hex(void *h) {
	return fmt::format("{:016x}{:016x}{:016x}{:016x}", reinterpret_cast<const uint64_t *>(h)[0],
					   reinterpret_cast<const uint64_t *>(h)[1], reinterpret_cast<const uint64_t *>(h)[2],
					   reinterpret_cast<const uint64_t *>(h)[3]);
}

inline bool buf_contains(const char *buf, size_t bufLen, const char *needle, size_t nLen, bool caseInsensitive) {
	if (nLen > bufLen) return false;
	if (nLen == 0) return true;

	for (size_t i = 0; i <= bufLen - nLen; i++) {
		if (caseInsensitive) {
			size_t j = 0;
			while (j < nLen) {
				if (tolower((unsigned char)buf[i + j]) != tolower((unsigned char)needle[j])) {
					break;
				}
				j++;
			}

			if (j == nLen) return true;
		} else {
			if (memcmp(buf + i, needle, nLen) == 0) return true;
		}
	}

	return false;
}

inline char *hex_str_decode(char *hexStr, size_t *decodedLen) {
	size_t len = strlen(hexStr);
	if (len % 2 != 0) {
		return nullptr;
	}

	*decodedLen = len / 2;
	char *decodedBuf = (char *)malloc(*decodedLen);
	if (!decodedBuf) return nullptr;

	for (size_t i = 0; i < *decodedLen; i++) {
		unsigned int val;
		if (sscanf(hexStr + (i * 2), "%2x", &val) != 1) {
			free(decodedBuf);
			*decodedLen = 0;
			return nullptr;
		}

		decodedBuf[i] = val;
	}

	return decodedBuf;
}
