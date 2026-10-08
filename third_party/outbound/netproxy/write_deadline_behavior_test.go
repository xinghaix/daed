package netproxy

import (
	"net/netip"
	"syscall"
	"testing"
	"time"
)

// closesSessionPacketConn is a PacketConn double that declares the optional
// destructive write-deadline behaviour through closesSession.
type closesSessionPacketConn struct {
	closesSession bool
}

func (c *closesSessionPacketConn) Read(_ []byte) (int, error)  { return 0, nil }
func (c *closesSessionPacketConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *closesSessionPacketConn) ReadFrom(_ []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, nil
}
func (c *closesSessionPacketConn) WriteTo(p []byte, _ string) (int, error) { return len(p), nil }
func (c *closesSessionPacketConn) Close() error                            { return nil }
func (c *closesSessionPacketConn) SetDeadline(_ time.Time) error           { return nil }
func (c *closesSessionPacketConn) SetReadDeadline(_ time.Time) error       { return nil }
func (c *closesSessionPacketConn) SetWriteDeadline(_ time.Time) error      { return nil }
func (c *closesSessionPacketConn) WriteDeadlineClosesSession() bool        { return c.closesSession }

// closesSessionRawPacketConn forces the fakeNetPacketConn2 wrapper variant by
// exposing SyscallConn.
type closesSessionRawPacketConn struct {
	closesSessionPacketConn
}

func (c *closesSessionRawPacketConn) SyscallConn() (syscall.RawConn, error) { return nil, nil }

// A conn that does not declare the optional behaviour keeps the standard
// net.Conn semantics: a write deadline aborts only the blocked write.
func TestWriteDeadlineClosesSessionDefaultsFalse(t *testing.T) {
	if WriteDeadlineClosesSession(nil) {
		t.Fatal("nil conn must default to non-destructive")
	}
	if WriteDeadlineClosesSession(&fakePacketConnForLifecycle{}) {
		t.Fatal("conn without WriteDeadlineBehavior must default to non-destructive")
	}
}

// An explicit declaration must be reported verbatim, in both directions.
func TestWriteDeadlineClosesSessionHonorsOptionalBehavior(t *testing.T) {
	if !WriteDeadlineClosesSession(&closesSessionPacketConn{closesSession: true}) {
		t.Fatal("conn declaring a session-closing write deadline must report true")
	}
	if WriteDeadlineClosesSession(&closesSessionPacketConn{closesSession: false}) {
		t.Fatal("conn declaring non-destructive write deadlines must report false")
	}
}

// The fake net.Conn compatibility wrapper must forward the optional
// declaration of the wrapped PacketConn in both wrapper variants, otherwise a
// destructive inner conn (e.g. TUIC) becomes invisible to deadline-arming
// callers.
func TestFakeNetPacketConnForwardsWriteDeadlineBehavior(t *testing.T) {
	destructive := NewFakeNetPacketConn(&closesSessionPacketConn{closesSession: true}, nil, nil)
	if !WriteDeadlineClosesSession(destructive) {
		t.Fatal("fake packet conn wrapper must forward a true WriteDeadlineClosesSession")
	}
	normal := NewFakeNetPacketConn(&closesSessionPacketConn{closesSession: false}, nil, nil)
	if WriteDeadlineClosesSession(normal) {
		t.Fatal("fake packet conn wrapper must forward a false WriteDeadlineClosesSession")
	}
	destructiveRaw := NewFakeNetPacketConn(&closesSessionRawPacketConn{
		closesSessionPacketConn: closesSessionPacketConn{closesSession: true},
	}, nil, nil)
	if !WriteDeadlineClosesSession(destructiveRaw) {
		t.Fatal("fakeNetPacketConn2 wrapper must forward a true WriteDeadlineClosesSession")
	}
}
