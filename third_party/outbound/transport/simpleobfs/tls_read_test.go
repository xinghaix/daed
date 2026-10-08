package simpleobfs

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// scriptConn serves a scripted byte stream: the obfs wire format is a
// sequence of records, each a 5-byte header (3 discarded, uint16 length)
// followed by the payload.
type scriptConn struct {
	data []byte
}

func (c *scriptConn) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.data)
	c.data = c.data[n:]
	return n, nil
}
func (c *scriptConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *scriptConn) Close() error                     { return nil }
func (c *scriptConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *scriptConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *scriptConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptConn) SetWriteDeadline(time.Time) error { return nil }

func obfsRecord(payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint16(out[3:], uint16(len(payload)))
	copy(out[5:], payload)
	return out
}

func TestTLSObfsReadSurvivesFirstHelloDiscard(t *testing.T) {
	// The first server response discards 105 bytes, not 3: a fixed-size
	// scratch buffer panicked here instead of reading the record.
	hello := make([]byte, 105+2) // discard + uint16 size of the payload record
	payload := []byte("body-after-hello")
	hello[105] = byte(len(payload) >> 8)
	hello[106] = byte(len(payload))
	stream := append(hello, payload...)

	to := &TLSObfs{Conn: &scriptConn{data: stream}, server: "example.com", firstRequest: false, firstResponse: true}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(to, got); err != nil {
		t.Fatalf("first Read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("data = %q, want %q", got, payload)
	}
}

func TestTLSObfsReadSkipsZeroLengthRecords(t *testing.T) {
	// The first record carries the hello discard (105 bytes); the zero
	// records follow it on the regular record path, where a plain
	// (0, nil) passthrough made relay loops spin.
	first := make([]byte, 105+2)
	first[105] = 0
	first[106] = 3
	stream := append(first, []byte("abc")...)
	stream = append(stream, obfsRecord(nil)...)
	stream = append(stream, obfsRecord(nil)...)
	stream = append(stream, obfsRecord([]byte("real"))...)

	to := &TLSObfs{Conn: &scriptConn{data: stream}, server: "example.com", firstRequest: false, firstResponse: true}
	got := make([]byte, 3)
	if _, err := io.ReadFull(to, got); err != nil {
		t.Fatalf("first Read: %v", err)
	}
	if string(got) != "abc" {
		t.Fatalf("data = %q, want %q", got, "abc")
	}
	got = make([]byte, 4)
	if _, err := io.ReadFull(to, got); err != nil {
		t.Fatalf("Read through empty records: %v", err)
	}
	if string(got) != "real" {
		t.Fatalf("data = %q, want %q", got, "real")
	}
}
