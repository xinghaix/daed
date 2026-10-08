package socks5

import (
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
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

// plainPacketConn carries no write-deadline declaration at all.
type plainPacketConn struct {
	markerPacketConn
}

// PktConn delegates SetWriteDeadline to the wrapped transport unchanged, so
// its destructive-write-deadline declaration must follow that transport in
// both directions. Built through the real NewPktConn constructor.
func TestPktConnForwardsWriteDeadlineBehavior(t *testing.T) {
	destructive := NewPktConn(&markerPacketConn{marker: true}, "proxy.example.com:1080", "1.2.3.4:53", nil)
	if !netproxy.WriteDeadlineClosesSession(destructive) {
		t.Fatal("PktConn must forward a true WriteDeadlineClosesSession of its wrapped transport")
	}
	normal := NewPktConn(&markerPacketConn{marker: false}, "proxy.example.com:1080", "1.2.3.4:53", nil)
	if netproxy.WriteDeadlineClosesSession(normal) {
		t.Fatal("PktConn must forward a false WriteDeadlineClosesSession of its wrapped transport")
	}
	plain := NewPktConn(&plainPacketConn{}, "proxy.example.com:1080", "1.2.3.4:53", nil)
	if netproxy.WriteDeadlineClosesSession(plain) {
		t.Fatal("PktConn over a transport without the declaration must report false")
	}
}
