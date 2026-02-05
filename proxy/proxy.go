package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	lua "github.com/yuin/gopher-lua"
)

const (
	startMTU         = 1500 - 28
	closeConnTimeout = 15 * time.Second
)

type Server struct {
	Conf *ServerConfig

	mitmConf   *ServerConfig
	clientSess *clientSess
	serverAddr netip.AddrPort // Addr we dial

	mutex      sync.Mutex
	runCtx     context.Context
	cancelFunc context.CancelFunc
	wg         sync.WaitGroup

	// For being able to externally force send/recv arbitrary packets
	injectSendQueue *FifoQueue[[]byte]
	injectRecvQueue *FifoQueue[[]byte]

	ls          *lua.LState
	luaTaskChan chan luaTask
	luaOnSend   atomic.Pointer[lua.LFunction]
	luaOnRecv   atomic.Pointer[lua.LFunction]
}

type ServerConfig struct {
	OnConnect    func(netip.AddrPort) // Fired on client connect
	OnDisconnect func()               // Fired on client dc/server close etc. Deinit and dealloc stuff on this signal
	OnSend       func(*Packet) []byte
	OnRecv       func(*Packet) []byte

	ServerAddr netip.AddrPort
	PingAddr   netip.AddrPort

	Key       []byte
	Iv        []byte
	HmacKey   []byte
	SessionId []byte

	LuaAutoExecScript []byte
}

func NewServer(conf *ServerConfig) *Server {
	server := &Server{
		Conf: conf,

		injectSendQueue: NewFifoQueue[[]byte](),
		injectRecvQueue: NewFifoQueue[[]byte](),
	}

	return server
}

func (server *Server) Start() (mitmConf *ServerConfig, err error) {
	server.mutex.Lock() // Unlocked right after server.luaInit()

	if server.cancelFunc != nil {
		return nil, fmt.Errorf("Server is already running")
	}

	server.serverAddr = server.Conf.ServerAddr

	mitmConf = &ServerConfig{
		PingAddr: server.Conf.PingAddr,
	}
	server.mitmConf = mitmConf

	// Temp
	mitmConf.Key = server.Conf.Key
	mitmConf.Iv = server.Conf.Iv
	mitmConf.HmacKey = server.Conf.HmacKey
	mitmConf.SessionId = server.Conf.SessionId

	listenConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	listenConnAddr := listenConn.LocalAddr().String()
	mitmConf.ServerAddr = netip.MustParseAddrPort(listenConnAddr)

	runCtx, cancel := context.WithCancel(context.Background())
	server.runCtx = runCtx
	server.cancelFunc = cancel

	server.luaInit()

	server.mutex.Unlock()

	if server.Conf.LuaAutoExecScript != nil {
		server.ExecuteScript(server.Conf.LuaAutoExecScript)
	}

	go func() {
		defer PanicCheck()

		server.wg.Add(1)
		defer func() {
			server.mutex.Lock()
			defer server.mutex.Unlock()

			if server.Conf.OnDisconnect != nil {
				server.Conf.OnDisconnect()
			}

			listenConn.Close()
			server.cancelFunc()

			server.wg.Done()
			server.wg.Wait()

			server.cancelFunc = nil
		}()

		for {
			select {
			case <-runCtx.Done():
				slog.Debug("Got close signal")
				return
			default:
				// Doing this manually and instead of in the select block b/c we can't send the incoming
				// data if the server.clientSess isn't initialized
				if server.injectSendQueue.Len() > 0 && server.clientSess != nil {
					data, _ := server.injectSendQueue.Pop()

					var err error
					if data, err = aesCbcEncrypt(data, server.Conf.Key, server.Conf.Iv); err != nil {
						slog.Error("Failed to encrypt packet", "err", err)
						continue
					}
					if _, err := server.clientSess.Socket.Write(data); err != nil {
						slog.Error("Error writing injected SEND packet", "err", err)
						continue
					}

					continue
				}

				listenConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

				bufSize := startMTU
				buf := make([]byte, bufSize)

				l, clientAddr, err := listenConn.ReadFromUDP(buf)
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						continue
					} else if errors.Is(err, os.ErrDeadlineExceeded) {
						if server.clientSess != nil && time.Since(server.clientSess.LastPacketSent).Seconds() > closeConnTimeout.Seconds() {
							slog.Debug("No packets recieved from client in a while, closing conn", "timeout", closeConnTimeout.Seconds())
							return
						}

						continue
					}
					slog.Error("Error reading packet from listener conn", "err", err, "clientAddr", clientAddr.String(), "serverAddr", server.serverAddr.String())
					continue
				} else if server.clientSess != nil && clientAddr.String() != server.clientSess.Addr.String() {
					if server.clientSess.Socket != nil {
						server.clientSess.Socket.Close()
					}
					server.clientSess = nil
				}

				if server.clientSess == nil {
					server.clientSess = &clientSess{
						Addr: clientAddr.AddrPort(),
					}

					if clientSessSocket, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(server.serverAddr)); err != nil {
						slog.Error("Error initializing proxy conn for client",
							"err", err,
							"clientAddr", clientAddr.String(),
							"serverAddr", server.serverAddr.String(),
						)
						continue
					} else {
						server.clientSess.Socket = clientSessSocket
						slog.Debug("Opened clientSessSocket",
							"mitmServerAddr", server.mitmConf.ServerAddr.String(),
							"clientAddr", clientAddr.String(),
							"clientSessAddr", server.clientSess.Socket.LocalAddr().String(),
							"serverAddr", server.serverAddr.String(),
						)
					}

					// Listener goroutine for this client's allocated conn
					go func() {
						defer PanicCheck()

						server.wg.Add(1)
						defer func() {
							server.clientSess.Socket.Close()
							server.wg.Done()
						}()

						for {
							select {
							case <-runCtx.Done():
								return
							default:
								// Same as SEND
								if server.injectRecvQueue.Len() > 0 {
									data, _ := server.injectRecvQueue.Pop()

									var err error
									if data, err = aesCbcEncrypt(data, server.Conf.Key, server.Conf.Iv); err != nil {
										slog.Error("Failed to encrypt packet", "err", err)
										continue
									}
									if _, err := listenConn.WriteToUDP(data, clientAddr); err != nil {
										slog.Error("Error writing packet to client", "err", err)
										continue
									}

									continue
								}

								server.clientSess.Socket.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

								buf := make([]byte, startMTU)
								l, err := server.clientSess.Socket.Read(buf)
								if err != nil {
									if errors.Is(err, net.ErrClosed) {
										slog.Warn("Error reading packet from server (ErrClosed)",
											"clientAddr", clientAddr.String(),
											"serverAddr", server.serverAddr.String(),
										)
										continue
									} else if errors.Is(err, os.ErrDeadlineExceeded) {
										continue
									}

									slog.Error("Error reading packet from server",
										"err", err,
										"clientAddr", clientAddr.String(),
										"serverAddr", server.serverAddr.String(),
									)
									continue
								}

								now := time.Now()
								server.clientSess.LastPacketRecv = now

								pkt := &Packet{
									Name: "Unknown",
									Data: buf[:l],

									IsSend:  false,
									Time:    now,
									SrcAddr: server.serverAddr,
									DstAddr: server.clientSess.Addr,
								}

								if pkt.Data, err = aesCbcDecrypt(pkt.Data, server.Conf.Key, server.Conf.Iv); err != nil {
									slog.Error("Failed to decrypt packet from server",
										"err", err,
										"clientAddr", clientAddr.String(),
										"serverAddr", server.serverAddr.String(),
									)
									continue
								}

								if err := server.processRecvPkt(pkt); err != nil {
									slog.Error("Failed to process RECV packet", "err", err)
									continue
								}

								luaOnRecv := server.luaOnRecv.Load()
								if luaOnRecv != nil {
									pkt.Data = server.luaOnPktCallback(luaOnRecv, pkt)
									if pkt.Data == nil {
										continue
									}
								}

								if server.Conf.OnRecv != nil {
									pkt.Data = server.Conf.OnRecv(pkt)
									if pkt.Data == nil {
										continue
									}
								}

								if pkt.Data, err = aesCbcEncrypt(pkt.Data, server.Conf.Key, server.Conf.Iv); err != nil {
									slog.Error("Failed to re-encrypt packet from server",
										"err", err,
										"clientAddr", clientAddr.String(),
										"serverAddr", server.serverAddr.String(),
									)
									continue
								}

								if _, err := listenConn.WriteToUDP(pkt.Data, clientAddr); err != nil {
									slog.Error("Error writing packet to client",
										"err", err,
										"clientAddr", clientAddr.String(),
										"serverAddr", server.serverAddr.String(),
									)
									continue
								}
							}
						}
					}()

					// Fire OnConnect after we've setup the listener loop and all
					server.Conf.OnConnect(server.clientSess.Addr)
				}

				now := time.Now()
				server.clientSess.LastPacketSent = now

				pkt := &Packet{
					Name: "Unknown",
					Data: buf[:l],

					IsSend:  true,
					Time:    now,
					SrcAddr: server.clientSess.Addr,
					DstAddr: server.serverAddr,
				}

				if pkt.Data, err = aesCbcDecrypt(pkt.Data, server.Conf.Key, server.Conf.Iv); err != nil {
					slog.Error("Failed to decrypt packet from client",
						"err", err,
						"clientAddr", clientAddr.String(),
						"serverAddr", server.serverAddr.String(),
					)
					continue
				}

				if err := server.processSendPkt(pkt); err != nil {
					slog.Error("Failed to process SEND packet", "err", err)
					continue
				}

				luaOnSend := server.luaOnSend.Load()
				if luaOnSend != nil {
					pkt.Data = server.luaOnPktCallback(luaOnSend, pkt)
					if pkt.Data == nil {
						continue
					}
				}

				if server.Conf.OnSend != nil {
					pkt.Data = server.Conf.OnSend(pkt)
					if pkt.Data == nil {
						continue
					}
				}

				if pkt.Data, err = aesCbcEncrypt(pkt.Data, server.Conf.Key, server.Conf.Iv); err != nil {
					slog.Error("Failed to re-encrypt packet from client",
						"err", err,
						"clientAddr", clientAddr.String(),
						"serverAddr", server.serverAddr.String(),
					)
					continue
				}

				if _, err := server.clientSess.Socket.Write(pkt.Data); err != nil {
					slog.Error("Error writing packet to server",
						"err", err,
						"clientAddr", clientAddr.String(),
						"serverAddr", server.serverAddr.String(),
					)
					continue
				}
			}
		}
	}()

	return mitmConf, nil
}

func (server *Server) Stop() {
	server.mutex.Lock()
	defer server.mutex.Unlock()

	if server.cancelFunc != nil {
		server.cancelFunc()
		server.wg.Wait()
	}
}

func (server *Server) IsRunning() bool {
	server.mutex.Lock()
	defer server.mutex.Unlock()

	return server.cancelFunc != nil
}

func (server *Server) IsConnected() bool {
	server.mutex.Lock()
	defer server.mutex.Unlock()

	return server.clientSess != nil
}

func (server *Server) InjectSend(data []byte) {
	if server.cancelFunc != nil {
		server.injectSendQueue.Push(data)
	}
}

func (server *Server) InjectRecv(data []byte) {
	if server.cancelFunc != nil {
		server.injectRecvQueue.Push(data)
	}
}
