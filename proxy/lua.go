package proxy

import (
	"bytes"
	"context"
	"embed"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/PeerDB-io/gluajson"
	"github.com/chadhyatt/ioannes/proxy/gluabit32"
	"github.com/cjoudrey/gluahttp"
	"github.com/tengattack/gluacrypto"
	crypto "github.com/tengattack/gluacrypto/crypto"
	lua "github.com/yuin/gopher-lua"
	lfs "layeh.com/gopher-lfs"
)

const (
	luaTaskTimeout = 12 * time.Second
)

//go:embed lua_mod
var luaModEmbed embed.FS

func luaErr(err error) {
	slog.Error(fmt.Sprintf("[Lua] %s", err))
}

func luaFieldErr(ls *lua.LState, fieldName string, expected lua.LValueType, got lua.LValueType) {
	ls.RaiseError("invalid type for field %q (%s expected, got %s)", fieldName, expected.String(), got.String())
}

type luaTask struct {
	Thread *lua.LState
	Fn     *lua.LFunction
}

// Create new task (and its *LFunction) from an LGFunction
func (server *Server) luaNewTask(fn lua.LGFunction) luaTask {
	t, _ := server.ls.NewThread()
	return luaTask{Thread: t, Fn: server.ls.NewFunction(fn)}
}

// Run an LGFunction as an asynchronous task
func (server *Server) luaRunTaskAsync(fn lua.LGFunction) {
	var wg sync.WaitGroup
	wg.Add(1)
	server.luaTaskChan <- server.luaNewTask(func(ls *lua.LState) int {
		defer wg.Done()
		return fn(ls)
	})
	wg.Wait()
}

func (server *Server) ExecuteScript(src []byte) {
	server.mutex.Lock()
	defer server.mutex.Unlock()

	if server.ls == nil || server.ls.Dead {
		luaErr(fmt.Errorf("LState not initialized or already closed"))
		return
	}

	fn, err := server.ls.Load(bytes.NewReader(src), "Script")
	if err != nil {
		luaErr(err)
		return
	}

	server.luaTaskChan <- luaTask{Fn: fn}
}

// Only call within LState thread
func (server *Server) executeScriptInternal(src []byte) {
	if server.ls == nil || server.ls.Dead {
		luaErr(fmt.Errorf("LState not initialized or already closed"))
		return
	}

	//server.ls.DoString(src)
	fn, err := server.ls.Load(bytes.NewReader(src), "Script")
	if err != nil {
		luaErr(err)
		return
	}

	server.ls.Push(fn)
	if err = server.ls.PCall(0, lua.MultRet, nil); err != nil {
		luaErr(err)
		return
	}
}

func (server *Server) luaInit() {
	slog.Debug("Init LState")

	ls := lua.NewState(lua.Options{
		CallStackSize:       lua.CallStackSize,
		RegistrySize:        lua.RegistrySize,
		IncludeGoStackTrace: true,
		MinimizeStackMemory: true,
	})

	server.ls = ls
	server.luaTaskChan = make(chan luaTask)

	ls.SetContext(server.runCtx)

	// `ioannes` global table and stuff

	globalIoannes := ls.SetFuncs(ls.NewTable(), map[string]lua.LGFunction{
		"send":   server.luaApiSend,
		"recv":   server.luaApiRecv,
		"decode": server.luaApiDecode,
		"encode": server.luaApiEncode,
	})
	ls.SetMetatable(globalIoannes, ls.SetFuncs(ls.NewTable(), map[string]lua.LGFunction{
		"__newindex": server.luaApiNewindex,
	}))

	ioannesSession := ls.NewTable()
	globalIoannes.RawSetString("session", ioannesSession)
	ls.SetMetatable(ioannesSession, ls.SetFuncs(ls.NewTable(), map[string]lua.LGFunction{
		"__index": server.luaApiSessionIndex,
	}))

	ls.SetGlobal("ioannes", globalIoannes)

	// Extras

	ls.SetGlobal("print", ls.NewFunction(server.luaApiGlobalPrint))
	ls.SetGlobal("warn", ls.NewFunction(server.luaApiGlobalWarn))
	// Screw it random util globals all over the namespace :muscle:
	ls.SetGlobal("hex", ls.NewFunction(server.luaApiGlobalHex))
	ls.SetGlobal("hexdump", ls.NewFunction(server.luaApiGlobalHexDump))
	ls.SetGlobal("swap", ls.NewFunction(gluabit32.Bit32byteswap))

	ls.PreloadModule("bit32", gluabit32.Loader)
	server.luaImplGlobal("bit32", gluabit32.Loader)

	gluacrypto.Preload(ls)
	server.luaImplGlobal("crypto", crypto.Loader)

	ls.PreloadModule("json", gluajson.Loader)
	server.luaImplGlobal("json", gluajson.Loader)

	httpMod := gluahttp.NewHttpModule(&http.Client{Timeout: 25 * time.Second})
	ls.PreloadModule("http", httpMod.Loader)
	server.luaImplGlobal("http", httpMod.Loader)

	// Layeh's luafilesystem implementation
	lfs.Preload(ls)
	server.luaRequireAsGlobal("lfs", "lfs")

	server.luaLoadEmbedMod("struct.lua", "struct")
	server.luaLoadEmbedMod("BitBuffer.lua", "BitBuffer")
	server.luaLoadEmbedMod("LuaEncode.lua", "LuaEncode")

	// Main LState thread
	server.wg.Go(func() {
		defer PanicCheck()

		for {
			select {
			case task := <-server.luaTaskChan:
				if task.Thread == nil {
					task.Thread, _ = server.ls.NewThread()
				}

				ctx, ctxCancel := context.WithTimeout(server.runCtx, luaTaskTimeout)
				task.Thread.SetContext(ctx)

				state, err, _ := ls.Resume(task.Thread, task.Fn)
				if err != nil {
					if apiErr, ok := err.(*lua.ApiError); ok {
						// Okay, this is probably a crazy dirty stack issue or something but I don't really
						// want to figure it out right now. Hack.
						if apiErr.Object != lua.LNil {
							luaErr(fmt.Errorf("%v: %v", apiErr.Object, apiErr.Cause))
						}
					} else {
						luaErr(err)
					}
				}

				ctxCancel()
				ls.SetContext(server.runCtx)
				if err != nil {
					continue
				}

				if state == lua.ResumeYield {
					go func() { server.luaTaskChan <- task }()
				}
			case <-server.runCtx.Done():
				ls.Close()
				return
			}
		}
	})
}

func (server *Server) luaImplGlobal(name string, fn lua.LGFunction) {
	server.ls.Push(server.ls.NewFunction(fn))
	server.ls.Call(0, 1)
	server.ls.SetGlobal(name, server.ls.Get(-1))
	server.ls.Pop(1)
}

func (server *Server) luaRequireAsGlobal(modName, globalName string) {
	require := server.ls.GetGlobal("require").(*lua.LFunction)

	server.ls.CallByParam(lua.P{Fn: require, NRet: 1, Protect: true}, lua.LString(modName))
	server.ls.SetGlobal(globalName, server.ls.Get(-1))
	server.ls.Pop(1)
}

func (server *Server) luaLoadEmbedMod(modFile, globalName string) {
	src, err := luaModEmbed.ReadFile("lua_mod/" + modFile)
	if err != nil {
		slog.Error("Failed to read embedded Lua module", "err", err)
		return
	}

	if err = server.ls.DoString(string(src)); err != nil {
		luaErr(err)
	}
	server.ls.SetGlobal(globalName, server.ls.Get(-1))
	server.ls.Pop(1)
}

// Ioannes Lua APIs / global overrides and stuff

func (server *Server) luaApiGlobalPrint(ls *lua.LState) int {
	strs := []string{}
	for i := 1; i <= ls.GetTop(); i++ {
		strs = append(strs, ls.ToString(i))
	}

	slog.Info(fmt.Sprintf("[Lua] %s", strings.Join(strs, "\t")))
	return 0
}

func (server *Server) luaApiGlobalWarn(ls *lua.LState) int {
	strs := []string{}
	for i := 1; i <= ls.GetTop(); i++ {
		strs = append(strs, ls.ToString(i))
	}

	slog.Warn(fmt.Sprintf("[Lua] %s", strings.Join(strs, "\t")))
	return 0
}

func (server *Server) luaApiGlobalHex(ls *lua.LState) int {
	ls.Push(lua.LString(hex.EncodeToString([]byte(ls.CheckString(1)))))
	return 1
}
func (server *Server) luaApiGlobalHexDump(ls *lua.LState) int {
	ls.Push(lua.LString(hex.Dump([]byte(ls.CheckString(1)))))
	return 1
}

func (server *Server) luaApiNewindex(ls *lua.LState) int {
	ls.CheckTable(1)
	key := ls.CheckString(2)
	val := ls.OptFunction(3, nil)

	switch key {
	case "onSend":
		server.luaOnSend.Store(val)
	case "onRecv":
		server.luaOnRecv.Store(val)
	default:
		ls.RaiseError("unknown field %q, expected (onSend, onRecv)", key)
	}

	return 0
}

// ioannes.session[idx]
func (server *Server) luaApiSessionIndex(ls *lua.LState) int {
	ls.CheckTable(1)
	key := ls.CheckString(2)

	server.clientSess.mutex.Lock()
	defer server.clientSess.mutex.Unlock()

	switch key {
	case "serverAddr":
		ls.Push(lua.LString(server.Conf.ServerAddr.String()))
	case "pingAddr":
		ls.Push(lua.LString(server.Conf.PingAddr.String()))
	case "key":
		ls.Push(lua.LString(server.Conf.Key))
	case "iv":
		ls.Push(lua.LString(server.Conf.Iv))
	case "hmacKey":
		ls.Push(lua.LString(server.Conf.HmacKey))
	case "sessionId":
		ls.Push(lua.LString(server.Conf.SessionId))
	case "uid":
		if server.clientSess.uid == nil {
			ls.Push(lua.LNil)
		} else {
			ls.Push(lua.LString(server.clientSess.uid))
		}
	default:
		ls.RaiseError("unknown field %q", key)
		return 0
	}

	return 1
}

func (server *Server) luaApiSend(ls *lua.LState) int {
	data := []byte(ls.CheckString(1))
	server.InjectSend(data)
	return 0
}

func (server *Server) luaApiRecv(ls *lua.LState) int {
	data := []byte(ls.CheckString(1))
	server.InjectRecv(data)
	return 0
}

// I guess??

func (server *Server) luaApiDecode(ls *lua.LState) int {
	data := []byte(ls.CheckString(1))
	uPkt, err := server.DeserializeUNetPacket(data)
	if err != nil {
		ls.RaiseError("failed to deserialize packet: %s", err.Error())
		return 0
	}

	obj := ls.NewTable()
	obj.RawSetString("uid", lua.LString(uPkt.Uid))
	obj.RawSetString("payload", lua.LString(uPkt.Payload))

	ls.Push(obj)
	return 1
}

func (server *Server) luaApiEncode(ls *lua.LState) int {
	obj := ls.CheckTable(1)
	uidLV := obj.RawGetString("uid")
	payloadLV := obj.RawGetString("payload")

	uPkt := &UNetPacket{}

	if uidLV == lua.LNil {
		if server.clientSess.uid != nil {
			uPkt.Uid = server.clientSess.uid
		} else if server.clientSess.pendingUid != nil {
			uPkt.Uid = server.clientSess.pendingUid
		} else {
			uPkt.Uid = []byte{0, 0, 0}
		}
	} else if uid, ok := uidLV.(lua.LString); ok {
		uPkt.Uid = []byte(uid)
	} else {
		luaFieldErr(ls, "uid", lua.LTString, uidLV.Type())
		return 0
	}

	if payload, ok := payloadLV.(lua.LString); ok {
		uPkt.Payload = []byte(payload)
	} else {
		luaFieldErr(ls, "payload", lua.LTString, payloadLV.Type())
		return 0
	}

	out, err := server.SerializeUNetPacket(uPkt)
	if err != nil {
		ls.RaiseError("failed to serialize packet: %s", err.Error())
		return 0
	}

	ls.Push(lua.LString(out))
	return 1
}

// For callbacks

func (server *Server) luaOnPktCallback(callbackFn *lua.LFunction, pkt *Packet) (newData []byte) {
	server.luaRunTaskAsync(func(ls *lua.LState) int {
		luaPkt := ls.CreateTable(0, 5)
		luaPkt.RawSetString("data", lua.LString(pkt.Data))
		luaPkt.RawSetString("isSend", lua.LBool(pkt.IsSend))
		luaPkt.RawSetString("time", lua.LNumber(pkt.Time.Unix()))
		luaPkt.RawSetString("srcAddr", lua.LString(pkt.SrcAddr.String()))
		luaPkt.RawSetString("dstAddr", lua.LString(pkt.DstAddr.String()))

		if err := ls.CallByParam(lua.P{Fn: callbackFn, NRet: 1, Protect: true}, luaPkt); err != nil {
			luaErr(err)
			return 0
		}
		newDataLV := ls.Get(-1)
		ls.Pop(1)

		if lua.LVIsFalse(newDataLV) {
			return 0
		}

		newData = []byte(lua.LVAsString(newDataLV))
		return 0
	})

	return newData
}
