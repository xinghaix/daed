// Package vision implements VLESS flow `xtls-rprx-vision` introduced by Xray-core.
package vision

import (
	"errors"

	"github.com/daeuniverse/outbound/netproxy"
)

var ErrNotTLS13 = errors.New("XTLS Vision based on TLS 1.3 outer connection")

func NewPacketConn(conn netproxy.Conn, userUUID []byte, network string, addr string) (*PacketConn, error) {
	c, err := NewConn(conn, userUUID)
	return &PacketConn{Conn: c, network: network, addr: addr}, err
}

func NewConn(conn netproxy.Conn, userUUID []byte) (*Conn, error) {
	c := &Conn{
		overlayConn:                conn,
		userUUID:                   userUUID,
		packetsToFilter:            6,
		needHandshake:              true,
		readFilterUUID:             true,
		writeFilterApplicationData: true,
	}
	c.writer = &writeWrapper{
		vision: c,
	}
	c.reader = &readWrapper{
		vision: c,
	}
	underlayConn, tlsConn, connType, connPointer, err := visionIntrinsicConn(conn)
	if err != nil {
		// NewConn owns conn from here on; close it on every failure or the
		// vless conn wrapping the dialed underlay leaks.
		_ = conn.Close()
		return nil, err
	}
	readBuffers, err := visionTLSReadBuffersFor(connType, connPointer)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	c.Conn = underlayConn
	c.tlsConn = tlsConn
	c.input = readBuffers.input
	c.rawInput = readBuffers.rawInput
	return c, nil
}
