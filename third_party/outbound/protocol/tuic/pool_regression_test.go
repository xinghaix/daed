package tuic

import (
	"bytes"
	"net/netip"
	"runtime"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
)

// TestTuicUnfragmentedDataPooled guards the DATA pool optimization: for
// unfragmented packets, B/op must stay flat across payload sizes because DATA
// is recycled via releaseData. If the pool path regresses (make per packet),
// large-payload B/op grows roughly with the payload.
func TestTuicUnfragmentedDataPooled(t *testing.T) {
	bop := func(dataSize int) int {
		addr := NewAddressAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 8080))
		data := make([]byte, dataSize)
		pkt := NewPacket(1, 1, 1, 0, uint16(len(data)), addr, data, Ver5)
		var buf bytes.Buffer
		if err := pkt.WriteTo(&buf); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
		msg := buf.Bytes()

		const runs = 200
		var m1, m2 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m1)
		for i := 0; i < runs; i++ {
			p, err := readPacketFromMessage(msg)
			if err != nil {
				t.Fatalf("readPacketFromMessage: %v", err)
			}
			p.releaseData()
		}
		runtime.ReadMemStats(&m2)
		return int(m2.TotalAlloc-m1.TotalAlloc) / runs
	}

	small := bop(64)
	large := bop(4096)
	// Race instrumentation adds size-dependent bookkeeping, but a pooled 4 KiB
	// payload must still stay well below one fresh payload allocation per parse.
	if large > small+2048 {
		t.Fatalf("tuic unfragmented DATA not pooled: small=%d large=%d B/op "+
			"(large should stay below one payload allocation)", small, large)
	}
}

// TestReadPacketFromStreamRoundTrip locks the incremental uni-stream parser:
// a packet serialized via WriteTo and re-read through readPacketFromStream
// must reproduce every field, including the AtypNone non-first-fragment form.
func TestReadPacketFromStreamRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		pkt  *Packet
	}{
		{
			name: "ipv4 unfragmented",
			pkt: NewPacket(7, 9, 1, 0, 5,
				NewAddressAddrPort(netip.MustParseAddrPort("127.0.0.1:53")), []byte("hello"), Ver5),
		},
		{
			name: "ipv6 unfragmented",
			pkt: NewPacket(8, 10, 1, 0, 4,
				NewAddressAddrPort(netip.MustParseAddrPort("[2001:db8::1]:443")), []byte("data"), Ver5),
		},
		{
			name: "domain unfragmented",
			pkt: NewPacket(9, 11, 1, 0, 3,
				NewAddress(&protocol.Metadata{Type: protocol.MetadataTypeDomain, Hostname: "example.com", Port: 80}),
				[]byte("abc"), Ver5),
		},
		{
			name: "atyp-none non-first fragment",
			pkt:  NewPacket(1, 2, 3, 1, 4, &Address{TYPE: AtypNone}, []byte("frag"), Ver5),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.pkt.WriteTo(&buf); err != nil {
				t.Fatalf("WriteTo: %v", err)
			}
			got, err := readPacketFromStream(bytes.NewReader(buf.Bytes()))
			if err != nil {
				t.Fatalf("readPacketFromStream: %v", err)
			}
			if got.ASSOC_ID != tc.pkt.ASSOC_ID || got.PKT_ID != tc.pkt.PKT_ID ||
				got.FRAG_TOTAL != tc.pkt.FRAG_TOTAL || got.FRAG_ID != tc.pkt.FRAG_ID ||
				got.SIZE != tc.pkt.SIZE || got.VER != tc.pkt.VER {
				t.Fatalf("field mismatch: got %+v", got)
			}
			if string(got.DATA) != string(tc.pkt.DATA) {
				t.Fatalf("DATA = %q, want %q", got.DATA, tc.pkt.DATA)
			}
			if got.ADDR.TYPE != tc.pkt.ADDR.TYPE || got.ADDR.PORT != tc.pkt.ADDR.PORT ||
				string(got.ADDR.ADDR) != string(tc.pkt.ADDR.ADDR) {
				t.Fatalf("ADDR = %+v, want %+v", got.ADDR, tc.pkt.ADDR)
			}
			got.releaseData()
		})
	}
}
