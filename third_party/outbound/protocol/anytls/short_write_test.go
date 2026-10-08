package anytls

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type shortNilErrorConn struct {
	mu     sync.Mutex
	writes [][]byte
}

func (c *shortNilErrorConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *shortNilErrorConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 1
	if n > len(p) {
		n = len(p)
	}
	buf := make([]byte, n)
	copy(buf, p[:n])
	c.writes = append(c.writes, buf)
	return n, io.ErrClosedPipe
}
func (c *shortNilErrorConn) Close() error                     { return nil }
func (c *shortNilErrorConn) LocalAddr() net.Addr              { return testAddr("local") }
func (c *shortNilErrorConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *shortNilErrorConn) SetDeadline(time.Time) error      { return nil }
func (c *shortNilErrorConn) SetReadDeadline(time.Time) error  { return nil }
func (c *shortNilErrorConn) SetWriteDeadline(time.Time) error { return nil }

func TestWriteFrameDoesNotReportSuccessOnShortWrite(t *testing.T) {
	underlay := &shortNilErrorConn{}
	s := newSession(underlay, 1)
	s.sendPadding = false
	s.padding.Store(NewPaddingFactory([]byte("stop=1\n0=1-1")))
	frame := newFrame(cmdPSH, 1)
	frame.data = []byte("hello")
	n, err := writeFrame(s, frame)
	if n != 0 {
		t.Fatalf("n = %d, want 0 (must not report payload success after a failed underlay write)", n)
	}
	if err == nil {
		t.Fatal("expected underlay write error, got success")
	}
}

func TestWriteConnLockedCompletesPartialWrites(t *testing.T) {
	underlay := &scriptedFullWriter{chunk: 2}
	s := newSession(underlay, 1)
	s.sendPadding = false
	s.padding.Store(NewPaddingFactory([]byte("stop=1\n0=1-1")))
	payload := []byte("abcdef")
	n, err := s.writeConnLocked(payload)
	if err != nil {
		t.Fatalf("writeConnLocked: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("n = %d, want %d", n, len(payload))
	}
	if underlay.calls.Load() < 2 {
		t.Fatalf("expected looping writes, got %d", underlay.calls.Load())
	}
}

type scriptedFullWriter struct {
	chunk int
	calls atomic.Int32
	mu    sync.Mutex
}

func (c *scriptedFullWriter) Read([]byte) (int, error) { return 0, io.EOF }
func (c *scriptedFullWriter) Write(p []byte) (int, error) {
	c.calls.Add(1)
	n := c.chunk
	if n > len(p) {
		n = len(p)
	}
	return n, nil
}
func (c *scriptedFullWriter) Close() error                     { return nil }
func (c *scriptedFullWriter) LocalAddr() net.Addr              { return testAddr("local") }
func (c *scriptedFullWriter) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *scriptedFullWriter) SetDeadline(time.Time) error      { return nil }
func (c *scriptedFullWriter) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedFullWriter) SetWriteDeadline(time.Time) error { return nil }
