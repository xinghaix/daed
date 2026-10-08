package vless

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/vmess"
)

type writeCounter struct {
	bytes.Buffer
	calls int
}

func (c *writeCounter) Write(p []byte) (int, error)      { c.calls++; return c.Buffer.Write(p) }
func (c *writeCounter) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *writeCounter) Close() error                     { return nil }
func (c *writeCounter) SetDeadline(time.Time) error      { return nil }
func (c *writeCounter) SetReadDeadline(time.Time) error  { return nil }
func (c *writeCounter) SetWriteDeadline(time.Time) error { return nil }

// The request header and the first payload (with its UDP length prefix) must
// leave in one write so that WebSocket early data carries the whole first
// request, as Xray's client does.
func TestFirstWriteCarriesHeaderAndPayload(t *testing.T) {
	md, err := protocol.ParseMetadata("1.2.3.4:53")
	if err != nil {
		t.Fatal(err)
	}
	md.IsClient = true
	for _, network := range []string{"tcp", "udp"} {
		raw := &writeCounter{}
		conn, err := NewConn(raw, Metadata{Metadata: vmess.Metadata{Metadata: md, Network: network}}, make([]byte, 16))
		if err != nil {
			t.Fatal(err)
		}
		n, err := conn.Write([]byte("dns-query"))
		if err != nil || n != len("dns-query") {
			t.Fatalf("%s: n=%d err=%v", network, n, err)
		}
		if raw.calls != 1 || !bytes.HasSuffix(raw.Bytes(), []byte("dns-query")) {
			t.Fatalf("%s: %d writes, %q", network, raw.calls, raw.Bytes())
		}
		if network == "udp" && !bytes.HasSuffix(raw.Bytes(), append([]byte{0, 9}, "dns-query"...)) {
			t.Fatalf("udp length prefix missing: %q", raw.Bytes())
		}
		// Later writes go straight through.
		if _, err := conn.Write([]byte("more")); err != nil || raw.calls != 2 {
			t.Fatalf("%s: second write: calls=%d err=%v", network, raw.calls, err)
		}
	}
}
