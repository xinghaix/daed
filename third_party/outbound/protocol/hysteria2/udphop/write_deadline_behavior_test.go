package udphop

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// markerNetPacketConn is a net.PacketConn whose only variable behaviour is
// the optional destructive write-deadline declaration.
type markerNetPacketConn struct {
	marker bool
}

func (c *markerNetPacketConn) ReadFrom(_ []byte) (int, net.Addr, error) {
	return 0, nil, io.EOF
}
func (c *markerNetPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return len(p), nil
}
func (c *markerNetPacketConn) Close() error                       { return nil }
func (c *markerNetPacketConn) LocalAddr() net.Addr                { return nil }
func (c *markerNetPacketConn) RemoteAddr() net.Addr               { return nil }
func (c *markerNetPacketConn) SetDeadline(_ time.Time) error      { return nil }
func (c *markerNetPacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *markerNetPacketConn) SetWriteDeadline(_ time.Time) error { return nil }
func (c *markerNetPacketConn) WriteDeadlineClosesSession() bool   { return c.marker }

// The hop conn delegates SetWriteDeadline to its current (and previous)
// underlay conns unchanged, so its destructive-write-deadline declaration
// must follow them. Built through the real NewUDPHopPacketConnContext
// constructor with a dial function that supplies the underlay.
func TestUDPHopPacketConnForwardsWriteDeadlineBehavior(t *testing.T) {
	addr, err := ParseUDPHopAddr("127.0.0.1:443")
	if err != nil {
		t.Fatalf("ParseUDPHopAddr() error = %v", err)
	}
	newConn := func(marker bool) net.PacketConn {
		t.Helper()
		conn, err := NewUDPHopPacketConnContext(context.Background(), addr, time.Hour,
			func(ctx context.Context, a net.Addr) (net.PacketConn, error) {
				return &markerNetPacketConn{marker: marker}, nil
			})
		if err != nil {
			t.Fatalf("NewUDPHopPacketConnContext() error = %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}

	if !netproxy.WriteDeadlineClosesSession(newConn(true)) {
		t.Fatal("udpHopPacketConn must forward a true WriteDeadlineClosesSession of its underlay")
	}
	if netproxy.WriteDeadlineClosesSession(newConn(false)) {
		t.Fatal("udpHopPacketConn must forward a false WriteDeadlineClosesSession of its underlay")
	}
}
