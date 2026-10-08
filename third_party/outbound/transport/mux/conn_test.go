package mux

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// oneByteConn returns at most one byte per Read, simulating extreme TCP
// fragmentation.
type oneByteConn struct {
	data []byte
	pos  int
}

func (c *oneByteConn) Read(p []byte) (int, error) {
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = c.data[c.pos]
	c.pos++
	return 1, nil
}

func (c *oneByteConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *oneByteConn) Close() error                { return nil }
func (c *oneByteConn) LocalAddr() net.Addr         { return nil }
func (c *oneByteConn) RemoteAddr() net.Addr        { return nil }
func (c *oneByteConn) SetDeadline(time.Time) error { return nil }
func (c *oneByteConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *oneByteConn) SetWriteDeadline(time.Time) error {
	return nil
}

// TestConnReadFragmentedStatus is a regression test: when the status field is
// split across TCP segments, both bytes must be read with ReadFull, otherwise
// the frame stream stays desynchronized forever.
func TestConnReadFragmentedStatus(t *testing.T) {
	payload := []byte("hello")
	var frame []byte
	// Frame header: 2B length(=4) + 2B id + 2B status + 2B dataLen + payload
	frame = binary.BigEndian.AppendUint16(frame, 4)
	frame = binary.BigEndian.AppendUint16(frame, 0)                  // id
	frame = binary.BigEndian.AppendUint16(frame, uint16(OptionData)) // status: keep=0, opts=OptionData
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
	frame = append(frame, payload...)

	c := &Conn{Conn: &oneByteConn{data: frame}}
	buf := make([]byte, len(payload))
	// Read may return partial data (the m.remain mechanism), so use io.ReadFull
	// to read the whole payload.
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("got %q, want %q (frame stream desynced?)", buf, payload)
	}
}

// Assert oneByteConn satisfies the minimal interface (a compile-time check that
// it cannot be misused silently).
var _ interface {
	Read([]byte) (int, error)
	io.Writer
	io.Closer
} = (*oneByteConn)(nil)

var _ = errors.New
