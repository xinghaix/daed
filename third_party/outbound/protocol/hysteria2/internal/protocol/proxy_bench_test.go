package protocol

import (
	"bytes"
	"testing"
)

// BenchmarkReadTCPRequest measures the TCP request parse path: every new
// inbound Hysteria2 TCP stream runs ReadTCPRequest on its first frame.
// We craft the post-frame-type wire bytes directly (HTTP/3 layer consumes
// the frame-type prefix upstream) so the bench exercises the production
// parse path rather than a synthetic round-trip.
func BenchmarkReadTCPRequest(b *testing.B) {
	addr := "127.0.0.1:8080"
	// wire = varint(addrLen) + addr + varint(paddingLen=0)
	var raw bytes.Buffer
	var tmp [8]byte
	n := varintPut(tmp[:], uint64(len(addr)))
	raw.Write(tmp[:n])
	raw.WriteString(addr)
	n = varintPut(tmp[:], 0) // paddingLen = 0
	raw.Write(tmp[:n])
	wire := raw.Bytes()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ReadTCPRequest(bytes.NewReader(wire)); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWriteTCPRequest measures the TCP request serialize path.
func BenchmarkWriteTCPRequest(b *testing.B) {
	addr := "127.0.0.1:8080"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := WriteTCPRequest(&buf, addr); err != nil {
			b.Fatal(err)
		}
		_ = buf.Bytes()
	}
}

// BenchmarkParseUDPMessage measures the UDP message parse path (Hysteria2
// UDP relay): runs once per inbound UDP datagram at line rate.
func BenchmarkParseUDPMessage(b *testing.B) {
	msg := &UDPMessage{
		SessionID: 1,
		PacketID:  1,
		FragID:    0,
		FragCount: 1,
		Addr:      []byte("127.0.0.1:8080"),
		Data:      make([]byte, 100),
	}
	buf := make([]byte, msg.Size())
	n := msg.Serialize(buf)
	if n < 0 {
		b.Fatal("serialize failed")
	}
	serialized := buf[:n]
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseUDPMessage(serialized); err != nil {
			b.Fatal(err)
		}
	}
}
