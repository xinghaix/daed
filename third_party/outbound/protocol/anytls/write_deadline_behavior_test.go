package anytls

import (
	stderrors "errors"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// observedPipeConn adapts one end of a real net.Pipe for the anytls session.
// Deadlines are the pipe conn's own real mechanics (no synthetic timers, no
// sleep-driven socket behaviour); the adapter only makes it observable that
// a stream write truly entered the underlying Write.
type observedPipeConn struct {
	net.Conn
	writeEntered atomic.Bool
	closeCalled  atomic.Bool
}

func newObservedPipeConn() (*observedPipeConn, net.Conn) {
	client, server := net.Pipe()
	return &observedPipeConn{Conn: client}, server
}

func (c *observedPipeConn) Write(p []byte) (int, error) {
	c.writeEntered.Store(true)
	return c.Conn.Write(p)
}

func (c *observedPipeConn) Close() error {
	c.closeCalled.Store(true)
	return c.Conn.Close()
}

// Arming a write deadline on an idle stream must not close the session or
// the underlying conn, even after the deadline expires with nothing in
// flight. This is the claim "setting a deadline alone does not auto-close
// the session" and nothing more.
func TestStreamSetDeadlineDoesNotCloseSession(t *testing.T) {
	conn, server := newObservedPipeConn()
	defer func() { _ = server.Close() }()
	s := newSession(conn, 1)
	defer func() { _ = s.Close() }()
	st := newStream(s, 1)

	deadline := time.Now().Add(30 * time.Millisecond)
	if err := st.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline() error = %v", err)
	}
	// Let the deadline expire with no write in flight.
	for time.Now().Before(deadline.Add(30 * time.Millisecond)) {
		time.Sleep(5 * time.Millisecond)
	}

	if s.Closed() {
		t.Fatal("arming a write deadline must not close the anytls session")
	}
	if conn.closeCalled.Load() {
		t.Fatal("arming a write deadline must not close the underlying session conn")
	}
}

// A stream write that is genuinely blocked inside the underlying conn's
// Write must (a) provably enter that Write before the deadline passes and
// (b) be released by the deadline with os.ErrDeadlineExceeded — the pipe is
// unbuffered and never read, so only the deadline can unblock it.
//
// Claim scope: the deadline releases the blocked write without the runtime
// closing the session or the conn. No claim is made about further writes
// after a transport-level timeout (see tls.Conn: a write timeout can leave
// the TLS layer corrupted); this test uses net.Pipe, which has no TLS layer.
func TestStreamBlockedWriteReleasedByDeadline(t *testing.T) {
	conn, server := newObservedPipeConn()
	defer func() { _ = server.Close() }()
	s := newSession(conn, 1)
	defer func() { _ = s.Close() }()
	st := newStream(s, 1)

	deadline := time.Now().Add(300 * time.Millisecond)
	if err := st.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline() error = %v", err)
	}
	type writeResult struct {
		n   int
		err error
	}
	resultCh := make(chan writeResult, 1)
	go func() {
		n, err := st.Write([]byte("blocked payload"))
		resultCh <- writeResult{n: n, err: err}
	}()

	// The write must truly enter the underlying Write while the deadline is
	// still pending: the unbuffered pipe Write cannot complete on its own.
	for !conn.writeEntered.Load() {
		if !time.Now().Before(deadline) {
			t.Fatal("write never entered the underlying Write before the deadline passed")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !time.Now().Before(deadline) {
		t.Fatal("write entered the underlying Write only after the deadline had passed")
	}

	select {
	case result := <-resultCh:
		if !stderrors.Is(result.err, os.ErrDeadlineExceeded) {
			t.Fatalf("blocked write must be released by the deadline with os.ErrDeadlineExceeded, got: %v", result.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked write was not released by the armed deadline")
	}

	if s.Closed() {
		t.Fatal("the deadline releasing a blocked write must not close the anytls session")
	}
	if conn.closeCalled.Load() {
		t.Fatal("the deadline releasing a blocked write must not close the underlying session conn")
	}
}

// The anytls stream must not declare the destructive write-deadline
// contract: its deadline aborts only the blocked write.
func TestStreamDoesNotDeclareWriteDeadlineClosesSession(t *testing.T) {
	conn, server := newObservedPipeConn()
	defer func() { _ = server.Close() }()
	s := newSession(conn, 1)
	defer func() { _ = s.Close() }()
	st := newStream(s, 1)

	if netproxy.WriteDeadlineClosesSession(st) {
		t.Fatal("anytls stream write deadline is write-abort only, must not declare destructive")
	}
}
