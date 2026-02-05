package proxy

import (
	"bytes"
	"fmt"
	"net/netip"
	"time"
)

// TODO: Will probably have to completely refactor and rethink this whole thing,
// as well as with the Lua ioannes.deserialize/serialize APIs, ESPECIALLY if
// we plan on doing a whole UNet reliability layer.

type Packet struct {
	IsSend  bool
	Time    time.Time
	SrcAddr netip.AddrPort
	DstAddr netip.AddrPort

	Name string
	Data []byte // The decrypted packet payload from off-the-wire
}

type UNetPacket struct {
	Uid []byte

	Payload []byte
}

func (server *Server) DeserializeUNetPacket(in []byte) (uPkt *UNetPacket, err error) {
	uPkt = &UNetPacket{}

	pktLen := len(in)
	if pktLen < 36 { // uid + seq id + hmac sig
		return nil, fmt.Errorf("packet too small (expected >=%d, is %d", 36, pktLen)
	}

	hmacSum := in[pktLen-32:]
	if err := hmacVerify(in[:pktLen-32], server.Conf.HmacKey, hmacSum); err != nil {
		return nil, err
	}

	uPkt.Uid = in[:3]
	uPkt.Payload = in[3 : pktLen-32]

	return uPkt, nil
}

func (server *Server) SerializeUNetPacket(uPkt *UNetPacket) (out []byte, err error) {
	w := new(bytes.Buffer)

	w.Write(uPkt.Uid)
	w.Write(uPkt.Payload)

	sum, err := hmacSum(w.Bytes(), server.Conf.HmacKey)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate HMAC sum for packet: %w", err)
	}
	w.Write(sum)

	return w.Bytes(), nil
}
