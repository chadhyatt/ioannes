package main

/*
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "libproxy_types.h"
*/
import "C"

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"runtime/debug"
	"slices"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/chadhyatt/ioannes/proxy"
	"gitlab.com/greyxor/slogor"
)

// State

var (
	logWriter   io.Writer
	isCapturing atomic.Bool
	servers     []*proxy.Server
)

var (
	callbackAddLog    C.callbackAddLog_t
	callbackAddPacket C.callbackAddPacket_t
)

// Utils

type cLogWriter struct{ files []*C.FILE }

func (w cLogWriter) Write(b []byte) (int, error) {
	bLen := len(b)

	if callbackAddLog != nil {
		scanner := bufio.NewScanner(bytes.NewReader(b))
		for scanner.Scan() {
			line := scanner.Text()

			cstr := C.CString(line)
			C.callbackAddLog(callbackAddLog, cstr)
			C.free(unsafe.Pointer(cstr))
		}
	}

	for _, f := range w.files {
		pfx := []byte("[PROXY] ")
		C.fwrite(unsafe.Pointer(&pfx[0]), 1, C.size_t(len(pfx)), f)
		C.fwrite(unsafe.Pointer(&b[0]), 1, C.size_t(bLen), f)
	}
	return bLen, nil
}

func callbackAddPacketFromProxyPacket(server *proxy.Server, pkt *proxy.Packet) {
	cPktPtr := C.malloc(C.sizeof_ProxyPacket)
	cPkt := (*C.ProxyPacket)(cPktPtr)

	cPkt.srcAddr = C.CString(pkt.SrcAddr.String())
	cPkt.dstAddr = C.CString(pkt.DstAddr.String())

	if pkt.IsSend {
		cPkt.isSend = C.char(1)
	} else {
		cPkt.isSend = C.char(0)
	}

	cPkt.name = C.CString("Unknown")
	cPkt.timestamp = C.uint64_t(pkt.Time.Unix())

	uPkt, _ := server.DeserializeUNetPacket(pkt.Data)

	cPkt.payloadLen = C.int(len(uPkt.Payload))
	cPkt.payload = (*C.char)(C.CBytes(uPkt.Payload)) //(*C.char)(unsafe.Pointer(&pkt.Payload[0]))

	C.callbackAddPacket(callbackAddPacket, cPkt)
}

// C header exports

//export proxy_global_init
func proxy_global_init(
	logStream *C.FILE,
	logFileStream *C.FILE,
	addLog C.callbackAddLog_t,
	addPacket C.callbackAddPacket_t,
) {
	defer proxy.PanicCheck()
	proxy.PanicCheckFunc = func() {
		if r := recover(); r != nil {
			slog.Error(fmt.Sprintf("PSYCRITICAL EXCEPTION: %s\n\n%s", fmt.Sprint(r), string(debug.Stack())))
			os.Exit(2)
		}
	}

	writers := []*C.FILE{}
	if logStream != nil {
		writers = append(writers, logStream)
	}
	if logFileStream != nil {
		writers = append(writers, logFileStream)
	}

	logWriter := cLogWriter{writers}
	slog.SetDefault(slog.New(
		slogor.NewHandler(
			logWriter,
			slogor.SetLevel(slog.LevelDebug),
			slogor.SetTimeFormat(time.TimeOnly),
			slogor.DisableColor(),
		),
	))

	callbackAddLog = addLog
	callbackAddPacket = addPacket

	initPlatSpecific()
	slog.Debug("proxy_global_init")
}

//export proxy_new_server
func proxy_new_server(cConfig C.ProxyServerConfig) (cMitmConfig C.ProxyServerConfig) {
	defer proxy.PanicCheck()

	// Yeah, we're being evil
	config := &proxy.ServerConfig{}
	config.ServerAddr = netip.MustParseAddrPort(C.GoString(cConfig.serverAddr))
	config.PingAddr = netip.MustParseAddrPort(C.GoString(cConfig.pingAddr))
	config.Key, _ = base64.StdEncoding.DecodeString(C.GoString(cConfig.key))
	config.Iv, _ = base64.StdEncoding.DecodeString(C.GoString(cConfig.iv))
	config.HmacKey, _ = base64.StdEncoding.DecodeString(C.GoString(cConfig.hmacKey))
	config.SessionId, _ = base64.StdEncoding.DecodeString(C.GoString(cConfig.sessionId))

	if cConfig.luaAutoexecScript != nil {
		config.LuaAutoExecScript = []byte(C.GoString(cConfig.luaAutoexecScript))
	}

	slog.Info("Setting up proxy server..", "ServerAddr", config.ServerAddr, "PingAddr", config.PingAddr)

	server := proxy.NewServer(config)
	servers = append(servers, server)

	// Proxy callbacks
	config.OnConnect = func(addr netip.AddrPort) {
		slog.Info("Client connected", "addr", addr.String())
	}

	config.OnDisconnect = func() {
		slog.Info("Client connection closed")

		for i, v := range servers {
			if v == server {
				servers = slices.Delete(servers, i, i+1)
			}
		}

		server = nil
	}

	config.OnSend = func(pkt *proxy.Packet) []byte {
		if isCapturing.Load() {
			callbackAddPacketFromProxyPacket(server, pkt)
		}

		return pkt.Data
	}

	config.OnRecv = func(pkt *proxy.Packet) []byte {
		if isCapturing.Load() {
			callbackAddPacketFromProxyPacket(server, pkt)
		}

		return pkt.Data
	}

	mitmConfig, err := server.Start()
	if err != nil {
		slog.Error("Failed to start proxy server", "err", err)
		mitmConfig = config
	}

	return C.ProxyServerConfig{
		serverAddr: C.CString(mitmConfig.ServerAddr.String()),
		pingAddr:   C.CString(mitmConfig.PingAddr.String()),
		key:        C.CString(base64.StdEncoding.EncodeToString(mitmConfig.Key)),
		iv:         C.CString(base64.StdEncoding.EncodeToString(mitmConfig.Iv)),
		hmacKey:    C.CString(base64.StdEncoding.EncodeToString(mitmConfig.HmacKey)),
		sessionId:  C.CString(base64.StdEncoding.EncodeToString(mitmConfig.SessionId)),
	}
}

//export proxy_set_is_capturing
func proxy_set_is_capturing(val C.char) {
	isCapturing.Store(byte(val) != 0)
}

//export proxy_packet_free
func proxy_packet_free(cPkt *C.ProxyPacket) {
	C.free(unsafe.Pointer(cPkt.srcAddr))
	C.free(unsafe.Pointer(cPkt.dstAddr))
	C.free(unsafe.Pointer(cPkt.name))
	C.free(unsafe.Pointer(cPkt.payload))
	//C.free(unsafe.Pointer(cPkt.payloadDump))
	C.free(unsafe.Pointer(cPkt))
}

//export proxy_execute_script
func proxy_execute_script(cSrc *C.char) {
	src := []byte(C.GoString(cSrc))
	for _, server := range servers {
		if server == nil || !server.IsConnected() {
			continue
		}

		server.ExecuteScript(src)
	}
}

func main() {}
