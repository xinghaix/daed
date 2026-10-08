package trojanc

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

type captureConn struct {
	bytes.Buffer
}

func (c *captureConn) Close() error                       { return nil }
func (c *captureConn) SetDeadline(_ time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(_ time.Time) error { return nil }

var _ netproxy.Conn = (*captureConn)(nil)

type splitCaptureConn struct {
	writes bytes.Buffer
}

func (c *splitCaptureConn) Read([]byte) (int, error)           { return 0, io.EOF }
func (c *splitCaptureConn) Write(p []byte) (int, error)        { return c.writes.Write(p) }
func (c *splitCaptureConn) Close() error                       { return nil }
func (c *splitCaptureConn) SetDeadline(_ time.Time) error      { return nil }
func (c *splitCaptureConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *splitCaptureConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestConnWrite_WritesHeaderOnlyOnce(t *testing.T) {
	raw := &captureConn{}
	baseMetadata, err := protocol.ParseMetadata("example.com:443")
	if err != nil {
		t.Fatalf("parse metadata failed: %v", err)
	}
	baseMetadata.IsClient = true
	conn, err := NewConn(raw, Metadata{Metadata: baseMetadata, Network: "tcp"}, "test-password")
	if err != nil {
		t.Fatalf("new conn failed: %v", err)
	}

	firstPayload := []byte("hello")
	n, err := conn.Write(firstPayload)
	if err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if n != len(firstPayload) {
		t.Fatalf("unexpected first write length: got %d want %d", n, len(firstPayload))
	}

	headerMetadata := Metadata{Metadata: baseMetadata, Network: "tcp"}
	headerLen := 56 + 2 + 1 + headerMetadata.Len() + 2
	if raw.Len() != headerLen+len(firstPayload) {
		t.Fatalf("unexpected buffered length after first write: got %d want %d", raw.Len(), headerLen+len(firstPayload))
	}
	if !bytes.Equal(raw.Bytes()[raw.Len()-len(firstPayload):], firstPayload) {
		t.Fatal("first payload mismatch")
	}

	secondPayload := []byte("world")
	n, err = conn.Write(secondPayload)
	if err != nil {
		t.Fatalf("second write failed: %v", err)
	}
	if n != len(secondPayload) {
		t.Fatalf("unexpected second write length: got %d want %d", n, len(secondPayload))
	}

	if raw.Len() != headerLen+len(firstPayload)+len(secondPayload) {
		t.Fatalf("unexpected buffered length after second write: got %d want %d", raw.Len(), headerLen+len(firstPayload)+len(secondPayload))
	}
	if !bytes.Equal(raw.Bytes()[raw.Len()-len(secondPayload):], secondPayload) {
		t.Fatal("second payload mismatch")
	}
}

func TestConnRead_WritesHeaderBeforeFirstReadForClient(t *testing.T) {
	raw := &splitCaptureConn{}
	baseMetadata, err := protocol.ParseMetadata("example.com:443")
	if err != nil {
		t.Fatalf("parse metadata failed: %v", err)
	}
	baseMetadata.IsClient = true
	conn, err := NewConn(raw, Metadata{Metadata: baseMetadata, Network: "tcp"}, "test-password")
	if err != nil {
		t.Fatalf("new conn failed: %v", err)
	}

	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("Read() error = nil, want EOF from empty underlying conn")
	}

	headerMetadata := Metadata{Metadata: baseMetadata, Network: "tcp"}
	headerLen := 56 + 2 + 1 + headerMetadata.Len() + 2
	if raw.writes.Len() != headerLen {
		t.Fatalf("unexpected buffered length after first read: got %d want %d", raw.writes.Len(), headerLen)
	}
}

func TestConnRead_DoesNotWriteHeaderBeforeFirstReadForUDPClient(t *testing.T) {
	raw := &splitCaptureConn{}
	baseMetadata, err := protocol.ParseMetadata("example.com:443")
	if err != nil {
		t.Fatalf("parse metadata failed: %v", err)
	}
	baseMetadata.IsClient = true
	conn, err := NewConn(raw, Metadata{Metadata: baseMetadata, Network: "udp"}, "test-password")
	if err != nil {
		t.Fatalf("new conn failed: %v", err)
	}

	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("Read() error = nil, want EOF from empty underlying conn")
	}
	if raw.writes.Len() != 0 {
		t.Fatalf("unexpected write before first UDP payload: got %d bytes", raw.writes.Len())
	}
}
