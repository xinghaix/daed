package vision

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

type memConn struct {
	reader *bytes.Reader
}

func (c *memConn) Read(p []byte) (int, error)       { return c.reader.Read(p) }
func (c *memConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *memConn) Close() error                     { return nil }
func (c *memConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *memConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *memConn) SetDeadline(time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

func appendKeepaliveFrame(buf *bytes.Buffer) {
	_ = binary.Write(buf, binary.BigEndian, uint16(4))
	buf.Write([]byte{0, 0, 0x04, 0})
}

func appendDataFrame(buf *bytes.Buffer, addr netip.AddrPort, payload []byte) {
	packetAddrLen := IPAddrToPacketAddrLength(addr)
	frameLen := uint16(5 + packetAddrLen)
	_ = binary.Write(buf, binary.BigEndian, frameLen)
	buf.Write([]byte{0, 0, 0x02, 1})
	buf.WriteByte(2)
	addrBuf := make([]byte, packetAddrLen)
	if err := PutPacketAddr(addrBuf, addr); err != nil {
		panic(err)
	}
	buf.Write(addrBuf)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(payload)))
	buf.Write(payload)
}

func TestPacketConnAddrPortForWriteCachesLastTarget(t *testing.T) {
	oldParse := parseAddrPort
	defer func() { parseAddrPort = oldParse }()

	var calls int
	parseAddrPort = func(addr string) (netip.AddrPort, error) {
		calls++
		return oldParse(addr)
	}

	var pc PacketConn
	for i := 0; i < 2; i++ {
		if _, err := pc.addrPortForWrite("127.0.0.1:53"); err != nil {
			t.Fatalf("addrPortForWrite() error = %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("parseAddrPort() call count = %d, want 1", calls)
	}

	if _, err := pc.addrPortForWrite("127.0.0.2:54"); err != nil {
		t.Fatalf("addrPortForWrite() second target error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("parseAddrPort() call count after target change = %d, want 2", calls)
	}
}

func TestPacketConnReadFromSkipsKeepaliveFrames(t *testing.T) {
	var stream bytes.Buffer
	for i := 0; i < 32; i++ {
		appendKeepaliveFrame(&stream)
	}
	wantAddr := netip.MustParseAddrPort("203.0.113.10:443")
	wantPayload := []byte("payload")
	appendDataFrame(&stream, wantAddr, wantPayload)

	pc := &PacketConn{
		Conn: &Conn{Conn: &memConn{reader: bytes.NewReader(stream.Bytes())}},
	}
	pc.reader = &readWrapper{vision: pc.Conn, directRead: true}
	pc.toReadDirect = true

	buf := make([]byte, 64)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if addr != wantAddr {
		t.Fatalf("ReadFrom() addr = %v, want %v", addr, wantAddr)
	}
	if got := string(buf[:n]); got != string(wantPayload) {
		t.Fatalf("ReadFrom() payload = %q, want %q", got, wantPayload)
	}
}
