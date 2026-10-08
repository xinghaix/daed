package trojanc

import (
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// markerConn is a netproxy.Conn whose only variable behaviour is the
// optional destructive write-deadline declaration.
type markerConn struct {
	marker bool
}

func (c *markerConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (c *markerConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *markerConn) Close() error                       { return nil }
func (c *markerConn) SetDeadline(_ time.Time) error      { return nil }
func (c *markerConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *markerConn) SetWriteDeadline(_ time.Time) error { return nil }
func (c *markerConn) WriteDeadlineClosesSession() bool   { return c.marker }

// Conn delegates SetWriteDeadline to the wrapped stream conn unchanged, so
// its destructive-write-deadline declaration must follow that conn; the UDP
// PacketConn embeds *Conn and inherits the forward. Built through the real
// NewConn constructor.
func TestConnForwardsWriteDeadlineBehavior(t *testing.T) {
	destructive, err := NewConn(&markerConn{marker: true}, Metadata{}, "test-password")
	if err != nil {
		t.Fatalf("NewConn() error = %v", err)
	}
	if !netproxy.WriteDeadlineClosesSession(destructive) {
		t.Fatal("trojanc Conn must forward a true WriteDeadlineClosesSession of its wrapped conn")
	}
	normal, err := NewConn(&markerConn{marker: false}, Metadata{}, "test-password")
	if err != nil {
		t.Fatalf("NewConn() error = %v", err)
	}
	if netproxy.WriteDeadlineClosesSession(normal) {
		t.Fatal("trojanc Conn must forward a false WriteDeadlineClosesSession of its wrapped conn")
	}
}
