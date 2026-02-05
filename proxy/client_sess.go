package proxy

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// server.clientSess
type clientSess struct {
	Socket         *net.UDPConn
	Addr           netip.AddrPort // The downstream client address allocated to and using the proxy conn
	LastPacketSent time.Time
	LastPacketRecv time.Time

	mutex sync.Mutex

	uid        []byte
	pendingUid []byte
}

func (server *Server) processSendPkt(pkt *Packet) error {
	server.clientSess.mutex.Lock()
	defer server.clientSess.mutex.Unlock()

	uPkt, err := server.DeserializeUNetPacket(pkt.Data)
	if err != nil {
		return fmt.Errorf("failed to deserialize packet from client: %w", err)
	}

	if server.clientSess.uid == nil && server.clientSess.pendingUid == nil && !bytes.Equal(uPkt.Uid, []byte{0, 0, 0}) {
		server.clientSess.pendingUid = uPkt.Uid
	}

	return nil
}

func (server *Server) processRecvPkt(pkt *Packet) error {
	server.clientSess.mutex.Lock()
	defer server.clientSess.mutex.Unlock()

	uPkt, err := server.DeserializeUNetPacket(pkt.Data)
	if err != nil {
		return fmt.Errorf("failed to deserialize packet from server: %w", err)
	}

	if server.clientSess.uid == nil && server.clientSess.pendingUid != nil && !bytes.Equal(uPkt.Uid, []byte{0, 0, 0}) {
		if bytes.Equal(uPkt.Uid, server.clientSess.pendingUid) {
			slog.Debug(fmt.Sprintf("Session UID: %s", hex.EncodeToString(uPkt.Uid)))
			server.clientSess.uid = uPkt.Uid
		} else {
			slog.Debug("Server rejected our Session UID (???)", "pendingUid", hex.EncodeToString(server.clientSess.pendingUid), "uPkt.Uid", hex.EncodeToString(uPkt.Uid))
		}
		server.clientSess.pendingUid = nil
	}

	return nil
}
