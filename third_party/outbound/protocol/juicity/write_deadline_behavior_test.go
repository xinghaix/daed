package juicity

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/olicesx/quic-go"
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

// TransportPacketConn delegates SetWriteDeadline to the QUIC transport's
// underlay conn (c.Conn), so the destructive-write-deadline declaration must
// follow that underlay. The plain stream PacketConn keeps its own
// write-abort (quic stream) deadline semantics and deliberately does not
// forward anything. Built the way the dialer and existing tests build it.
func TestTransportPacketConnForwardsWriteDeadlineBehavior(t *testing.T) {
	destructive := &TransportPacketConn{Transport: &quic.Transport{Conn: &markerNetPacketConn{marker: true}}}
	if !netproxy.WriteDeadlineClosesSession(destructive) {
		t.Fatal("TransportPacketConn must forward a true WriteDeadlineClosesSession of the transport underlay")
	}
	normal := &TransportPacketConn{Transport: &quic.Transport{Conn: &markerNetPacketConn{marker: false}}}
	if netproxy.WriteDeadlineClosesSession(normal) {
		t.Fatal("TransportPacketConn must forward a false WriteDeadlineClosesSession of the transport underlay")
	}
	noTransport := &TransportPacketConn{}
	if netproxy.WriteDeadlineClosesSession(noTransport) {
		t.Fatal("TransportPacketConn without a transport underlay must report false")
	}
}

// The plain stream PacketConn inherits the quic stream write-abort deadline
// and must NOT declare destructive semantics.
func TestStreamPacketConnDoesNotDeclareDestructiveDeadline(t *testing.T) {
	conn := &PacketConn{Conn: &Conn{}}
	if netproxy.WriteDeadlineClosesSession(conn) {
		t.Fatal("juicity stream PacketConn write deadline is write-abort only, must not declare destructive")
	}
}
