package tuic

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/daeuniverse/outbound/protocol/tuic/common"
)

// buildPacketMessage serializes a full TUIC Packet command (CommandHead +
// Packet fields + Address + DATA) into the wire format QUIC datagrams carry.
// Used to feed processDatagram without any network I/O.
func buildPacketMessage(b *testing.B, dataSize int) []byte {
	b.Helper()
	addr := NewAddressAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 8080))
	data := make([]byte, dataSize)
	pkt := NewPacket(1, 1, 1, 0, uint16(len(data)), addr, data, Ver5)
	var buf bytes.Buffer
	if err := pkt.WriteTo(&buf); err != nil {
		b.Fatal(err)
	}
	return buf.Bytes()
}

// BenchmarkReadPacketFromMessage is the source of truth for the allocation
// count documented on readPacketFromMessage. It measures the native
// (UdpRelayMode=native) per-datagram parse, which runs once per inbound UDP
// datagram on the shared demux goroutine.
//
// Measured: 6 allocs/op (Packet + CommandHead + Address + ADDR slice +
// packetDataOwner + the pooled DATA slice). The first four are structural; the
// DATA slice is a pool.Get rather than a fresh allocation, so its size does not
// grow with the payload. The comment previously claimed 4 and omitted
// CommandHead and packetDataOwner.
func BenchmarkReadPacketFromMessage(b *testing.B) {
	msg := buildPacketMessage(b, 100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt, err := readPacketFromMessage(msg)
		if err != nil {
			b.Fatal(err)
		}
		pkt.releaseData()
	}
}

// BenchmarkReadPacketFromMessageSmall uses a tiny payload so the fixed
// structural cost dominates: this is the number the alloc comment refers to.
func BenchmarkReadPacketFromMessageSmall(b *testing.B) {
	msg := buildPacketMessage(b, 8)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt, err := readPacketFromMessage(msg)
		if err != nil {
			b.Fatal(err)
		}
		pkt.releaseData()
	}
}

// BenchmarkReadPacketFromStream measures the QUIC uni-stream parser used
// when UdpRelayMode=quic. Native processDatagram is a different path.
func BenchmarkReadPacketFromStream(b *testing.B) {
	msg := buildPacketMessage(b, 100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt, err := readPacketFromStream(bytes.NewReader(msg))
		if err != nil {
			b.Fatal(err)
		}
		pkt.releaseData()
	}
}

// BenchmarkProcessDatagram measures the UDP receive hot path: every QUIC
// datagram carrying a Packet is parsed via processDatagram. No network, no
// QUIC connection — this isolates the protocol parse + dispatch cost that
// runs once per inbound UDP packet at line rate.
func BenchmarkProcessDatagram(b *testing.B) {
	msg := buildPacketMessage(b, 100)
	t := &clientImpl{
		ClientOption: &ClientOption{UdpRelayMode: common.NATIVE},
		udp:          true,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.processDatagram(nil, msg)
	}
}

// BenchmarkProcessDatagramSmall isolates the per-datagram fixed overhead
// (reader + CommandHead + Packet struct), where DATA is tiny so payload
// copy cost is negligible. This is the alloc-reduction target.
func BenchmarkProcessDatagramSmall(b *testing.B) {
	msg := buildPacketMessage(b, 8)
	t := &clientImpl{
		ClientOption: &ClientOption{UdpRelayMode: common.NATIVE},
		udp:          true,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.processDatagram(nil, msg)
	}
}

// BenchmarkPacketWriteTo measures the send-path serialization of a Packet
// into a bytes.Buffer (stands in for the QUIC stream write buffer).
func BenchmarkPacketWriteTo(b *testing.B) {
	addr := NewAddressAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 8080))
	data := make([]byte, 100)
	pkt := NewPacket(1, 1, 1, 0, uint16(len(data)), addr, data, Ver5)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := pkt.WriteTo(&buf); err != nil {
			b.Fatal(err)
		}
		_ = buf.Bytes()
	}
}

// BenchmarkPacketsPushPop measures the per-packet queue round-trip
// (PushBack + PopFrontBlock). With the channel-based queue this is
// allocation-free; the previous container/list design allocated a
// list.Element (~48 B) per PushBack.
func BenchmarkPacketsPushPop(b *testing.B) {
	p := NewPackets()
	pkt := &Packet{DATA: []byte("test")}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.PushBack(pkt)
		if _, closed := p.PopFrontBlock(); closed {
			b.Fatal("PopFrontBlock returned closed on live queue")
		}
	}
}
