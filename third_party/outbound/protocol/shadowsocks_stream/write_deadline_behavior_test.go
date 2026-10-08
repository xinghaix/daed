package shadowsocks_stream

import (
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
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
// both directions. Built through the real NewUdpConn constructor; the
// UdpTransportConn dialer wrapper embeds *UdpConn and inherits the forward.
func TestUdpConnForwardsWriteDeadlineBehavior(t *testing.T) {
	cipher, err := ciphers.NewStreamCipher("aes-128-cfb", "test-password")
	if err != nil {
		t.Fatalf("NewStreamCipher() error = %v", err)
	}
	defaultAddr, err := socks.ParseAddr("1.2.3.4:53")
	if err != nil {
		t.Fatalf("ParseAddr() error = %v", err)
	}
	destructive := NewUdpConn(&markerPacketConn{marker: true}, cipher, defaultAddr, "proxy.example.com:8388")
	if !netproxy.WriteDeadlineClosesSession(destructive) {
		t.Fatal("UdpConn must forward a true WriteDeadlineClosesSession of its wrapped transport")
	}
	normal := NewUdpConn(&markerPacketConn{marker: false}, cipher, defaultAddr, "proxy.example.com:8388")
	if netproxy.WriteDeadlineClosesSession(normal) {
		t.Fatal("UdpConn must forward a false WriteDeadlineClosesSession of its wrapped transport")
	}
}
