package obfs

import (
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

// The obfs wrapper delegates SetWriteDeadline to the wrapped conn unchanged,
// so its destructive-write-deadline declaration must follow that conn in
// both directions. Built through the real WrapPacketConnSalamander
// constructor used by the hysteria2 dialer.
func TestWrapPacketConnSalamanderForwardsWriteDeadlineBehavior(t *testing.T) {
	destructive, err := WrapPacketConnSalamander(&markerNetPacketConn{marker: true}, make([]byte, 16))
	if err != nil {
		t.Fatalf("WrapPacketConnSalamander() error = %v", err)
	}
	if !netproxy.WriteDeadlineClosesSession(destructive) {
		t.Fatal("obfs wrapper must forward a true WriteDeadlineClosesSession of its wrapped conn")
	}
	normal, err := WrapPacketConnSalamander(&markerNetPacketConn{marker: false}, make([]byte, 16))
	if err != nil {
		t.Fatalf("WrapPacketConnSalamander() error = %v", err)
	}
	if netproxy.WriteDeadlineClosesSession(normal) {
		t.Fatal("obfs wrapper must forward a false WriteDeadlineClosesSession of its wrapped conn")
	}
}
