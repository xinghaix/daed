package simpleobfs

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// segConn serves its payload one segment per Read, emulating TCP
// segmentation; every other net.Conn method is unused by the path under
// test.
type segConn struct {
	segs [][]byte
	idx  int
}

func (c *segConn) Read(p []byte) (int, error) {
	if c.idx >= len(c.segs) {
		return 0, io.EOF
	}
	n := copy(p, c.segs[c.idx])
	c.idx++
	return n, nil
}
func (c *segConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *segConn) Close() error                     { return nil }
func (c *segConn) LocalAddr() net.Addr              { return nil }
func (c *segConn) RemoteAddr() net.Addr             { return nil }
func (c *segConn) SetDeadline(time.Time) error      { return nil }
func (c *segConn) SetReadDeadline(time.Time) error  { return nil }
func (c *segConn) SetWriteDeadline(time.Time) error { return nil }

// TestHTTPObfsResponseHeaderAcrossSegments pins the header accumulator: a
// response header split across TCP segments must be reassembled, not
// misread as a clean EOF (which silently dropped the tunnel).
func TestHTTPObfsResponseHeaderAcrossSegments(t *testing.T) {
	conn := NewHTTPObfs(&netproxy.FakeNetConn{
		Conn: &segConn{segs: [][]byte{
			// The header terminator CRLFCRLF straddles the boundary: the
			// first segment carries the final header CRLF, the second one
			// opens with the blank-line CRLF.
			[]byte("HTTP/1.1 200 OK\r\nServer: x\r\n"),
			[]byte("\r\nPAYLOAD"),
		}},
	}, "example.com", "80", "/")

	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v, want payload delivery", err)
	}
	if got := string(buf[:n]); got != "PAYLOAD" {
		t.Fatalf("Read() = %q, want %q", got, "PAYLOAD")
	}

	if _, err := conn.Read(buf); err != io.EOF {
		t.Fatalf("second Read() error = %v, want io.EOF", err)
	}
}
