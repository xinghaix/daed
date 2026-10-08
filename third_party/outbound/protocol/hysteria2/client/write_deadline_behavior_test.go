package client

import (
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// Characterization of the existing semantics: arming a write deadline on a
// hy2 UDP session arms a session-wide timer whose expiry closes the whole
// udpConn (and every flow multiplexed on it), not just one blocked write.
// This is the destructive behaviour the WriteDeadlineClosesSession marker
// below declares for deadline-arming callers.
func TestUDPConnWriteDeadlineClosesSession(t *testing.T) {
	closed := make(chan struct{})
	u := &udpConn{CloseFunc: func() { close(closed) }}

	if err := u.SetWriteDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline() error = %v", err)
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("expected the armed write deadline to close the session")
	}
}

// Clearing the deadline must not close the session.
func TestUDPConnClearedWriteDeadlineDoesNotCloseSession(t *testing.T) {
	closed := make(chan struct{})
	u := &udpConn{CloseFunc: func() { close(closed) }}

	if err := u.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("SetWriteDeadline(zero) error = %v", err)
	}
	select {
	case <-closed:
		t.Fatal("clearing the write deadline must not close the session")
	case <-time.After(50 * time.Millisecond):
	}
}

// The hy2 UDP session must declare its destructive write-deadline semantics
// through the shared netproxy contract so deadline-arming callers skip it.
func TestUDPConnDeclaresWriteDeadlineClosesSession(t *testing.T) {
	u := &udpConn{}
	if !u.WriteDeadlineClosesSession() {
		t.Fatal("hy2 udpConn write deadline closes the session, must declare true")
	}
	if !netproxy.WriteDeadlineClosesSession(u) {
		t.Fatal("netproxy helper must see the hy2 udpConn marker")
	}
}
