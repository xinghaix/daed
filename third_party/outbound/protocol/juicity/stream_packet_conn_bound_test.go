package juicity

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/trojanc"
)

// scriptedJuicityStream serves canned bytes to the packet conn's read path.
type scriptedJuicityStream struct {
	juicityTestStream
	wire *bytes.Buffer
}

func (s *scriptedJuicityStream) Read(p []byte) (int, error) { return s.wire.Read(p) }

// juicityUDPFrame seals one UDP datagram the way juicity frames it: metadata,
// then a bare 2-byte length, then the payload (no CRLF).
func juicityUDPFrame(md trojanc.Metadata, payload []byte) []byte {
	wire := make([]byte, md.Len()+2+len(payload))
	md.PackTo(wire)
	binary.BigEndian.PutUint16(wire[md.Len():], uint16(len(payload)))
	copy(wire[md.Len()+2:], payload)
	return wire
}

// TestPacketConnReadFromKeepsFramingWhenResolutionFails is the juicity-side
// counterpart of the trojanc framing guard. It matters more here: this packet
// conn multiplexes over a stream shared with the flow's other traffic, so a
// desync would corrupt everything the stream carries, not just the datagram
// whose source address could not be resolved.
func TestPacketConnReadFromKeepsFramingWhenResolutionFails(t *testing.T) {
	protocol.SetDatapathResolver(func(context.Context, string) (netip.Addr, error) {
		return netip.Addr{}, errors.New("test resolver: no answer")
	})
	t.Cleanup(func() { protocol.SetDatapathResolver(nil) })

	badMD := trojanc.Metadata{
		Metadata: protocol.Metadata{Type: protocol.MetadataTypeDomain, Hostname: "unresolvable.invalid", Port: 53},
		Network:  "udp",
	}
	goodMD := trojanc.Metadata{
		Metadata: protocol.Metadata{
			Type:     protocol.MetadataTypeIPv4,
			Hostname: "192.0.2.8",
			Port:     53,
			IP:       netip.MustParseAddr("192.0.2.8"),
		},
		Network: "udp",
	}
	const dropped, kept = "dropped-payload", "kept-payload"
	wire := &bytes.Buffer{}
	wire.Write(juicityUDPFrame(badMD, []byte(dropped)))
	wire.Write(juicityUDPFrame(goodMD, []byte(kept)))

	pc := &PacketConn{
		Conn: NewConn(
			&scriptedJuicityStream{wire: wire},
			&trojanc.Metadata{Metadata: protocol.Metadata{IsClient: true}, Network: "udp"},
			nil,
			nil,
		),
	}

	buf := make([]byte, 64)
	if _, _, err := pc.ReadFrom(buf); !errors.Is(err, protocol.ErrDomainResolution) {
		t.Fatalf("first ReadFrom err = %v, want it to wrap ErrDomainResolution", err)
	}

	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("second ReadFrom: %v (the failed resolution desynced the shared stream)", err)
	}
	if string(buf[:n]) != kept {
		t.Fatalf("second payload = %q, want %q", buf[:n], kept)
	}
	if addr.String() != "192.0.2.8:53" {
		t.Fatalf("second addr = %s, want 192.0.2.8:53", addr)
	}
}
