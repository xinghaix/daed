package vision

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type bufferConn struct {
	*bytes.Buffer
}

func (c *bufferConn) Close() error                     { return nil }
func (c *bufferConn) LocalAddr() net.Addr              { return nil }
func (c *bufferConn) RemoteAddr() net.Addr             { return nil }
func (c *bufferConn) SetDeadline(time.Time) error      { return nil }
func (c *bufferConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufferConn) SetWriteDeadline(time.Time) error { return nil }

var _ netproxy.Conn = (*bufferConn)(nil)

func TestReadFromDrainsOversizedPayload(t *testing.T) {
	payload := []byte("0123456789")
	addr := netip.MustParseAddrPort("203.0.113.10:53")
	packetAddrLen := IPAddrToPacketAddrLength(addr)
	headerLen := 4 + 1 + packetAddrLen
	var framed bytes.Buffer
	var fl [2]byte
	binary.BigEndian.PutUint16(fl[:], uint16(headerLen))
	framed.Write(fl[:])
	framed.Write([]byte{0, 0, 0x02, 0x01})
	framed.WriteByte(2)
	addrBytes := make([]byte, packetAddrLen)
	if err := PutPacketAddr(addrBytes, addr); err != nil {
		t.Fatal(err)
	}
	framed.Write(addrBytes)
	var ll [2]byte
	binary.BigEndian.PutUint16(ll[:], uint16(len(payload)))
	framed.Write(ll[:])
	framed.Write(payload)
	framed.WriteString("NEXT")

	underlay := &bufferConn{Buffer: &framed}
	vc := &Conn{Conn: underlay, toReadDirect: true}
	vc.reader = &readWrapper{directRead: true, vision: vc}
	pc := &PacketConn{Conn: vc}
	n, _, err := pc.ReadFrom(make([]byte, 4))
	if err == nil {
		t.Fatal("expected buffer too small")
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
	rest := make([]byte, 4)
	if _, err := io.ReadFull(underlay, rest); err != nil {
		t.Fatalf("remaining stream: %v", err)
	}
	if string(rest) != "NEXT" {
		t.Fatalf("remaining = %q, want NEXT", rest)
	}
}
