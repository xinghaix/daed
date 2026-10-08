package vision

import (
	"io"
	"net"
	"testing"
	"time"
)

// closeWriteStub is the direct-mode underlay: it records the half-close it is
// asked for. It is deliberately not a *net.TCPConn, because the underlay is
// always the TLS conn's NetConn() (the record coalescer or a FakeNetConn).
type closeWriteStub struct {
	closeWrites int
}

func (s *closeWriteStub) Read([]byte) (int, error)         { return 0, io.EOF }
func (s *closeWriteStub) Write(p []byte) (int, error)      { return len(p), nil }
func (s *closeWriteStub) Close() error                     { return nil }
func (s *closeWriteStub) LocalAddr() net.Addr              { return nil }
func (s *closeWriteStub) RemoteAddr() net.Addr             { return nil }
func (s *closeWriteStub) SetDeadline(time.Time) error      { return nil }
func (s *closeWriteStub) SetReadDeadline(time.Time) error  { return nil }
func (s *closeWriteStub) SetWriteDeadline(time.Time) error { return nil }
func (s *closeWriteStub) CloseWrite() error                { s.closeWrites++; return nil }

// TestConnCloseWriteDirectModeReachesUnderlay is the regression guard for XTLS
// direct mode: once toWriteDirect is on, payload is written to the underlay
// conn itself (see writeWrapper.Write), so CloseWrite must half-close that same
// conn. The old code asserted *net.TCPConn on it, which never matched, and the
// FIN was silently dropped.
func TestConnCloseWriteDirectModeReachesUnderlay(t *testing.T) {
	stub := &closeWriteStub{}
	vc := &Conn{Conn: stub, toWriteDirect: true}

	if err := vc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if stub.closeWrites != 1 {
		t.Fatalf("underlay CloseWrite calls = %d, want 1", stub.closeWrites)
	}
}
