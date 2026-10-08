package shadowsocks

import (
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

// markerPacketConn is a netproxy.PacketConn whose only variable behaviour is
// the optional destructive write-deadline declaration.
type markerPacketConn struct {
	marker bool
}

func (c *markerPacketConn) Read(_ []byte) (int, error) { return 0, io.EOF }
func (c *markerPacketConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *markerPacketConn) ReadFrom(_ []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}

func (c *markerPacketConn) WriteTo(p []byte, _ string) (int, error) {
	return len(p), nil
}
func (c *markerPacketConn) Close() error                       { return nil }
func (c *markerPacketConn) SetDeadline(_ time.Time) error      { return nil }
func (c *markerPacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *markerPacketConn) SetWriteDeadline(_ time.Time) error { return nil }
func (c *markerPacketConn) WriteDeadlineClosesSession() bool   { return c.marker }

// UdpConn delegates SetWriteDeadline to the wrapped transport unchanged, so
// its destructive-write-deadline declaration must follow that transport in
// both directions. Built through the real NewUdpConn constructor.
func TestUdpConnForwardsWriteDeadlineBehavior(t *testing.T) {
	destructive, err := NewUdpConn(&markerPacketConn{marker: true}, "proxy.example.com:8388", protocol.Metadata{Cipher: "aes-256-gcm"}, nil, nil)
	if err != nil {
		t.Fatalf("NewUdpConn() error = %v", err)
	}
	if !netproxy.WriteDeadlineClosesSession(destructive) {
		t.Fatal("UdpConn must forward a true WriteDeadlineClosesSession of its wrapped transport")
	}
	normal, err := NewUdpConn(&markerPacketConn{marker: false}, "proxy.example.com:8388", protocol.Metadata{Cipher: "aes-256-gcm"}, nil, nil)
	if err != nil {
		t.Fatalf("NewUdpConn() error = %v", err)
	}
	if netproxy.WriteDeadlineClosesSession(normal) {
		t.Fatal("UdpConn must forward a false WriteDeadlineClosesSession of its wrapped transport")
	}
}
