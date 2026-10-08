package coalesce

import (
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// capabilityConn records which optional capabilities a wrapper reached on the
// conn it wraps.
type capabilityConn struct {
	intrinsic      netproxy.Conn
	closeWrites    int
	localAddr      net.Addr
	remoteAddr     net.Addr
	deadlineCloses bool
}

func (c *capabilityConn) Read([]byte) (int, error)         { return 0, nil }
func (c *capabilityConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *capabilityConn) Close() error                     { return nil }
func (c *capabilityConn) SetDeadline(time.Time) error      { return nil }
func (c *capabilityConn) SetReadDeadline(time.Time) error  { return nil }
func (c *capabilityConn) SetWriteDeadline(time.Time) error { return nil }

func (c *capabilityConn) IntrinsicConn() netproxy.Conn     { return c.intrinsic }
func (c *capabilityConn) CloseWrite() error                { c.closeWrites++; return nil }
func (c *capabilityConn) LocalAddr() net.Addr              { return c.localAddr }
func (c *capabilityConn) RemoteAddr() net.Addr             { return c.remoteAddr }
func (c *capabilityConn) WriteDeadlineClosesSession() bool { return c.deadlineCloses }

var (
	_ netproxy.Conn                  = (*capabilityConn)(nil)
	_ net.Conn                       = (*capabilityConn)(nil)
	_ netproxy.WriteCloser           = (*capabilityConn)(nil)
	_ netproxy.WriteDeadlineBehavior = (*capabilityConn)(nil)
)

// TestFlushConnForwardsWrappedCapabilities is the regression guard for the
// coalescer layer: transport/tls used to hand the *tls.Conn itself to callers,
// so every duck-typed capability has to survive the extra wrapper.
func TestFlushConnForwardsWrappedCapabilities(t *testing.T) {
	target := &capabilityConn{}
	local := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	inner := &capabilityConn{
		intrinsic:      target,
		localAddr:      local,
		remoteAddr:     remote,
		deadlineCloses: true,
	}
	fc := NewFlushConn(inner, New(inner))

	if got := fc.IntrinsicConn(); got != netproxy.Conn(target) {
		t.Fatalf("IntrinsicConn() = %T, want the wrapped conn's intrinsic target %T", got, target)
	}
	if err := fc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite(): %v", err)
	}
	if inner.closeWrites != 1 {
		t.Fatalf("inner CloseWrite calls = %d, want 1", inner.closeWrites)
	}
	if got := fc.LocalAddr(); got != local {
		t.Fatalf("LocalAddr() = %v, want %v", got, local)
	}
	if got := fc.RemoteAddr(); got != remote {
		t.Fatalf("RemoteAddr() = %v, want %v", got, remote)
	}
	if !fc.WriteDeadlineClosesSession() {
		t.Fatal("WriteDeadlineClosesSession() = false, want the wrapped declaration")
	}
}

// TestFlushConnCloseWriteFlushesCoalescedClose guards the flush half of the
// forwarded half-close contract: CloseWrite's close_notify goes through the
// coalescer like any other record, so the forward is only complete once the
// buffer has been pushed (Write behaves the same way).
func TestFlushConnCloseWriteFlushesCoalescedClose(t *testing.T) {
	inner := &capabilityConn{}
	co := New(inner)
	fc := NewFlushConn(inner, co)

	if _, err := co.Write([]byte("close-notify")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if co.Pending() == 0 {
		t.Fatal("expected the alert buffered before CloseWrite")
	}
	if err := fc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if inner.closeWrites != 1 {
		t.Fatalf("inner CloseWrite calls = %d, want 1", inner.closeWrites)
	}
	if got := co.Pending(); got != 0 {
		t.Fatalf("pending after CloseWrite = %d, want the coalescer flushed", got)
	}
}

// bareConn implements only netproxy.Conn (plus the net.Conn address surface),
// so a wrapper over it must fall back to the wrapped conn itself instead of
// inventing an intrinsic target.
type bareConn struct{ netproxy.Conn }

func (*bareConn) Read([]byte) (int, error)         { return 0, nil }
func (*bareConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*bareConn) Close() error                     { return nil }
func (*bareConn) LocalAddr() net.Addr              { return nil }
func (*bareConn) RemoteAddr() net.Addr             { return nil }
func (*bareConn) SetDeadline(time.Time) error      { return nil }
func (*bareConn) SetReadDeadline(time.Time) error  { return nil }
func (*bareConn) SetWriteDeadline(time.Time) error { return nil }

var (
	_ netproxy.Conn = (*bareConn)(nil)
	_ net.Conn      = (*bareConn)(nil)
)

func TestFlushConnIntrinsicConnFallsBackToWrapped(t *testing.T) {
	inner := &bareConn{}
	fc := NewFlushConn(inner, New(inner))

	if got := fc.IntrinsicConn(); got != netproxy.Conn(inner) {
		t.Fatalf("IntrinsicConn() = %T, want the wrapped bareConn itself", got)
	}
	if got := fc.LocalAddr(); got != nil {
		t.Fatalf("LocalAddr() = %v, want nil for a conn without addresses", got)
	}
	if got := fc.RemoteAddr(); got != nil {
		t.Fatalf("RemoteAddr() = %v, want nil for a conn without addresses", got)
	}
	if got := fc.UnderlyingConn(); got != nil {
		t.Fatalf("UnderlyingConn() = %v, want nil for a conn without a raw-socket accessor", got)
	}
	if got := fc.WriteDeadlineClosesSession(); got {
		t.Fatal("WriteDeadlineClosesSession() = true for a conn without the declaration")
	}
}
