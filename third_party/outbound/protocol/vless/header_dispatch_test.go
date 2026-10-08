package vless

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/vmess"
)

type bufferConn struct {
	*bytes.Buffer
}

func (c *bufferConn) Close() error                     { return nil }
func (c *bufferConn) SetDeadline(time.Time) error      { return nil }
func (c *bufferConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufferConn) SetWriteDeadline(time.Time) error { return nil }

var _ netproxy.Conn = (*bufferConn)(nil)

func testKey(t *testing.T) []byte {
	t.Helper()
	id, err := Password2Key("11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestClientReadConsumesResponseHeader(t *testing.T) {
	// Response header: version 0 + addon length 0, then payload.
	raw := bytes.NewBuffer([]byte{0, 0, 'p', 'a', 'y'})
	c := &Conn{
		Conn: &bufferConn{Buffer: raw},
		metadata: Metadata{Metadata: vmess.Metadata{
			Metadata: protocol.Metadata{IsClient: true},
			Network:  "tcp",
		}},
		cmdKey: testKey(t),
	}
	got := make([]byte, 8)
	n, err := c.Read(got)
	if err != nil && err != io.EOF {
		t.Fatalf("client Read: %v", err)
	}
	if string(got[:n]) != "pay" {
		t.Fatalf("client payload = %q, want pay", got[:n])
	}
}

func TestServerReadConsumesRequestHeader(t *testing.T) {
	key := testKey(t)
	clientUnderlay := &bufferConn{Buffer: &bytes.Buffer{}}
	client := &Conn{
		Conn: clientUnderlay,
		metadata: Metadata{Metadata: vmess.Metadata{
			Metadata: protocol.Metadata{
				Type:     protocol.MetadataTypeIPv4,
				Hostname: "203.0.113.10",
				Port:     443,
				IsClient: true,
			},
			Network: "tcp",
		}},
		cmdKey: key,
	}
	payload := []byte("hello")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("client Write: %v", err)
	}

	server := &Conn{
		Conn: &bufferConn{Buffer: bytes.NewBuffer(clientUnderlay.Bytes())},
		metadata: Metadata{Metadata: vmess.Metadata{
			Metadata: protocol.Metadata{IsClient: false},
			Network:  "tcp",
		}},
		cmdKey: key,
	}
	got := make([]byte, 16)
	n, err := server.Read(got)
	if err != nil && err != io.EOF {
		t.Fatalf("server Read: %v", err)
	}
	if string(got[:n]) != string(payload) {
		t.Fatalf("server payload = %q, want %q", got[:n], payload)
	}
	if server.metadata.Hostname != "203.0.113.10" {
		t.Fatalf("parsed hostname = %q", server.metadata.Hostname)
	}
}

func TestHeaderErrorIsStickyAfterPartialConsume(t *testing.T) {
	raw := bytes.NewBuffer([]byte{0}) // version only, EOF before addon length
	c := &Conn{
		Conn: &bufferConn{Buffer: raw},
		metadata: Metadata{Metadata: vmess.Metadata{
			Metadata: protocol.Metadata{IsClient: true},
			Network:  "tcp",
		}},
		cmdKey: testKey(t),
	}
	_, err := c.Read(make([]byte, 8))
	if err == nil {
		t.Fatal("expected header read error")
	}
	_, err2 := c.Read(make([]byte, 8))
	if err2 != err {
		t.Fatalf("second Read = %v, want sticky %v", err2, err)
	}
}
