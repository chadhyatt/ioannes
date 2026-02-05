#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	const char *serverAddr;
	const char *pingAddr;

	const char *key;
	const char *iv;
	const char *hmacKey;
	const char *sessionId;

	const char *luaAutoexecScript;
} ProxyServerConfig;

typedef struct {
	char *srcAddr;
	char *dstAddr;
	char isSend;

	char *name;
	uint64_t timestamp;

	int payloadLen;
	char *payload;
	// char *payloadDump;	// Litter reflection dump of the specific deserialized packet, OR error message
} ProxyPacket;

// Callbacks for Go bridge
typedef void (*callbackAddLog_t)(const char *);
typedef void (*callbackAddPacket_t)(ProxyPacket *);
static inline void callbackAddLog(callbackAddLog_t fn, const char *s) { return fn(s); }
static inline void callbackAddPacket(callbackAddPacket_t fn, ProxyPacket *pkt) { return fn(pkt); }

#ifdef __cplusplus
}
#endif
