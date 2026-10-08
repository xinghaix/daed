package coalesce

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

type coalesceRecConn struct {
	net.Conn
	writes  [][]byte
	failOn  int
	closed  bool
	wdCount int
}

func (r *coalesceRecConn) Write(p []byte) (int, error) {
	if r.failOn > 0 && len(r.writes)+1 == r.failOn {
		return 0, errors.New("injected")
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	r.writes = append(r.writes, cp)
	return len(p), nil
}

func (r *coalesceRecConn) Close() error { r.closed = true; return nil }

func (r *coalesceRecConn) SetWriteDeadline(t time.Time) error { r.wdCount++; return nil }

func TestCoalesceMergesBurstIntoOneWrite(t *testing.T) {
	rec := &coalesceRecConn{}
	c := New(rec)
	if _, err := c.Write([]byte("record-one--")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("record-two--")); err != nil {
		t.Fatal(err)
	}
	if n := c.Pending(); n != 24 {
		t.Fatalf("pending = %d, want 24", n)
	}
	if len(rec.writes) != 0 {
		t.Fatalf("premature writes: %d", len(rec.writes))
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) != 1 {
		t.Fatalf("writes = %d, want 1 merged write", len(rec.writes))
	}
	if got := string(rec.writes[0]); got != "record-one--record-two--" {
		t.Fatalf("merged = %q", got)
	}
	if c.Pending() != 0 {
		t.Fatalf("pending after flush = %d", c.Pending())
	}
}

func TestCoalesceFlushEmptyIsNoop(t *testing.T) {
	rec := &coalesceRecConn{}
	c := New(rec)
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) != 0 {
		t.Fatalf("unexpected writes: %d", len(rec.writes))
	}
}

func TestCoalesceDeadlineExpiredFailsFlush(t *testing.T) {
	rec := &coalesceRecConn{}
	c := New(rec)
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Second)
	if err := c.SetWriteDeadline(past); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("flush err = %v, want deadline exceeded", err)
	}
	if c.Pending() != 0 {
		t.Fatalf("pending after failed flush = %d", c.Pending())
	}
	if len(rec.writes) != 0 {
		t.Fatalf("should not write past deadline, writes = %d", len(rec.writes))
	}
}

func TestCoalesceFlushPropagatesWriteError(t *testing.T) {
	rec := &coalesceRecConn{failOn: 1}
	c := New(rec)
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err == nil || err.Error() != "injected" {
		t.Fatalf("flush err = %v, want injected", err)
	}
	if c.Pending() != 0 {
		t.Fatalf("buffer must be dropped after error, pending = %d", c.Pending())
	}
}

func TestCoalesceCloseClosesRawWithoutDrain(t *testing.T) {
	rec := &coalesceRecConn{}
	c := New(rec)
	if _, err := c.Write([]byte("close_notify")); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// Close deliberately does NOT drain: a flush blocked mid-write holds
	// mu, and draining first would deadlock the deadline escape hatches
	// that call Close. The contract is raw close, pending bytes dropped.
	if len(rec.writes) != 0 {
		t.Fatalf("pending bytes were flushed on Close: %+v", rec.writes)
	}
	if !rec.closed {
		t.Fatal("underlying conn not closed")
	}
}

func TestCoalesceHardLimitSelfFlushes(t *testing.T) {
	rec := &coalesceRecConn{}
	c := New(rec)
	chunk := make([]byte, 40<<10)
	for i := 0; i < 4; i++ { // 160KB total, crosses the 128KB limit
		if _, err := c.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if len(rec.writes) == 0 {
		t.Fatal("hard limit did not trigger a self-flush")
	}
	if c.Pending() >= bufHardLimit {
		t.Fatalf("pending = %d still above limit", c.Pending())
	}
}

// TestCloseNotDeadlockedByBlockedFlush reproduces the deadlock escape: with
// a synchronous pipe whose peer never reads, a Read-triggered flush blocks
// mid-write holding mu. Close must still return promptly (deadline escape
// hatches wait on it), not queue behind the blocked flush forever.
func TestCloseNotDeadlockedByBlockedFlush(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	c := New(client)
	// Accumulate more than the pipe buffers (net.Pipe is unbuffered, so
	// any record blocks until the peer reads; the peer never does).
	if _, err := c.Write(make([]byte, 4096)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		// Read flushes first and blocks on the pipe write.
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
	}()
	time.Sleep(20 * time.Millisecond) // let the read-side flush block
	go func() {
		done <- c.Close()
	}()
	select {
	case <-done:
		if time.Since(start) > time.Second {
			t.Fatalf("Close() took %v, want deadline-bounded return", time.Since(start))
		}
		// The flush failure may or may not surface from Close (a
		// deadline-class drain loss is deliberately swallowed); what
		// matters is that Close returned within the bound.
	case <-time.After(2 * time.Second):
		t.Fatal("Close() deadlocked behind a blocked flush")
	}
}

// coalesceTCPPair returns a connected TCP pair, which is the only layered conn
// that can observe a real half-close (a *net.TCPConn is what actually sends the
// FIN). The caller owns both ends; they are closed on cleanup.
func coalesceTCPPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("accept timed out")
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

// TestCoalesceCloseWriteFlushesPendingThenHalfCloses is the regression guard for
// XTLS/Vision direct mode: it writes payload through the coalescer and then
// half-closes, so the buffered records have to reach the peer before the FIN.
// CloseWrite on the embedded net.Conn would have been a no-op (net.Conn has no
// CloseWrite) with the records still sitting in c.buf.
func TestCoalesceCloseWriteFlushesPendingThenHalfCloses(t *testing.T) {
	client, server := coalesceTCPPair(t)
	c := New(client)

	if _, err := c.Write([]byte("pending-records")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if c.Pending() == 0 {
		t.Fatal("expected records buffered before CloseWrite")
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if got := c.Pending(); got != 0 {
		t.Fatalf("pending after CloseWrite = %d, want the records flushed", got)
	}

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 64)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if got := string(buf[:n]); got != "pending-records" {
		t.Fatalf("peer read = %q, want the flushed records", got)
	}
	if n, err := server.Read(buf); n != 0 || err != io.EOF {
		t.Fatalf("peer read after half-close = %d, %v, want 0, EOF", n, err)
	}
}
