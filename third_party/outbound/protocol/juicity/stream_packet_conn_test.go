package juicity

import (
	"bytes"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/trojanc"
)

func TestConnTransportDoneReturnsConfiguredChannel(t *testing.T) {
	done := make(chan struct{})
	conn := NewConn(nil, &trojanc.Metadata{}, nil, done)

	if got := conn.TransportDone(); got != done {
		t.Fatal("expected juicity stream conn to expose configured transport done channel")
	}
}

func TestPacketConnTransportDoneForwardsConnLifecycle(t *testing.T) {
	done := make(chan struct{})
	pc := &PacketConn{
		Conn: NewConn(nil, &trojanc.Metadata{}, nil, done),
	}

	if got := pc.TransportDone(); got != done {
		t.Fatal("expected juicity packet conn to forward underlying transport done channel")
	}
}

type recordingJuicityStream struct {
	juicityTestStream
	wire bytes.Buffer
}

func (s *recordingJuicityStream) Write(p []byte) (int, error) {
	return s.wire.Write(p)
}

func TestPacketConnReusesWriteBufferWithoutChangingWire(t *testing.T) {
	stream := &recordingJuicityStream{}
	conn := NewConn(stream, &trojanc.Metadata{Metadata: protocol.Metadata{}}, nil, nil)
	packetConn := &PacketConn{Conn: conn}
	payload := []byte("payload")
	const target = "203.0.113.10:443"

	if _, err := packetConn.WriteTo(payload, target); err != nil {
		t.Fatal(err)
	}
	firstBacking := &conn.packetWriteBuf[0]
	if _, err := packetConn.WriteTo(payload, target); err != nil {
		t.Fatal(err)
	}
	if firstBacking != &conn.packetWriteBuf[0] {
		t.Fatal("packet write buffer was not reused")
	}

	metadata, err := packetConn.metadataForAddr(target)
	if err != nil {
		t.Fatal(err)
	}
	packetMetadata := trojanc.Metadata{Metadata: metadata, Network: "udp"}
	expectedPacket := make([]byte, packetMetadata.Len()+2+len(payload))
	SealUDP(packetMetadata, expectedPacket, payload)
	expectedWire := append(append([]byte(nil), expectedPacket...), expectedPacket...)
	if !bytes.Equal(stream.wire.Bytes(), expectedWire) {
		t.Fatal("reused packet buffer changed wire bytes")
	}

	if err := packetConn.Close(); err != nil {
		t.Fatal(err)
	}
	if conn.packetWriteBuf != nil {
		t.Fatal("Close retained packet write buffer")
	}
}
