package shadowsocks_2022

import (
	"io"
	"net"
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

// markerNetConn is a net.Conn with the optional destructive write-deadline
// declaration.
type markerNetConn struct {
	marker bool
}

func (c *markerNetConn) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (c *markerNetConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *markerNetConn) Close() error                { return nil }
func (c *markerNetConn) LocalAddr() net.Addr         { return nil }
func (c *markerNetConn) RemoteAddr() net.Addr        { return nil }
func (c *markerNetConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *markerNetConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *markerNetConn) SetWriteDeadline(_ time.Time) error {
	return nil
}
func (c *markerNetConn) WriteDeadlineClosesSession() bool { return c.marker }

// FakeNetPacketConn delegates SetWriteDeadline to the wrapped transport
// unchanged (built the way the dialer builds it: the embedded PacketConn
// carries the real transport).
func TestFakeNetPacketConnForwardsWriteDeadlineBehavior(t *testing.T) {
	destructive := &FakeNetPacketConn{PacketConn: &markerPacketConn{marker: true}}
	if !netproxy.WriteDeadlineClosesSession(destructive) {
		t.Fatal("FakeNetPacketConn must forward a true WriteDeadlineClosesSession of its wrapped transport")
	}
	normal := &FakeNetPacketConn{PacketConn: &markerPacketConn{marker: false}}
	if netproxy.WriteDeadlineClosesSession(normal) {
		t.Fatal("FakeNetPacketConn must forward a false WriteDeadlineClosesSession of its wrapped transport")
	}
}

// UdpConn embeds the raw net.Conn and its exported SetWriteDeadline is the
// promoted delegate of that conn; the declaration must follow it too.
func TestUdpConnForwardsWriteDeadlineBehavior(t *testing.T) {
	destructive := &UdpConn{Conn: &markerNetConn{marker: true}}
	if !netproxy.WriteDeadlineClosesSession(destructive) {
		t.Fatal("UdpConn must forward a true WriteDeadlineClosesSession of its wrapped conn")
	}
	normal := &UdpConn{Conn: &markerNetConn{marker: false}}
	if netproxy.WriteDeadlineClosesSession(normal) {
		t.Fatal("UdpConn must forward a false WriteDeadlineClosesSession of its wrapped conn")
	}
}
