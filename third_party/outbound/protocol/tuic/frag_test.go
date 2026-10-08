package tuic

import (
	"bytes"
	"net/netip"
	"testing"
)

// Regression: fragmenting once must not flip the TYPE of the caller-cached
// shared *Address to AtypNone, which would drop the address bytes from all
// later unfragmented datagrams to the same destination.
func TestFragmentPacketsDoesNotPoisonCachedAddress(t *testing.T) {
	addr := &Address{TYPE: AtypIPv4, ADDR: netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice(), PORT: 443}
	packet := NewPacket(7, 9, 1, 0, uint16(len(bytes.Repeat([]byte{0xAA}, 100))), addr, bytes.Repeat([]byte{0xBB}, 300), Ver5)

	frags, err := fragmentPackets(packet, 128)
	if err != nil {
		t.Fatalf("fragmentPackets: %v", err)
	}
	if len(frags) < 3 {
		t.Fatalf("expected at least 3 fragments, got %d", len(frags))
	}
	for i, frag := range frags {
		if frag == packet {
			t.Fatal("fragments must be value copies, not the original packet pointer")
		}
		if i == 0 {
			if frag.ADDR.TYPE != AtypIPv4 || len(frag.ADDR.ADDR) != 4 {
				t.Fatalf("fragment 0 must keep the address: type=%v", frag.ADDR.TYPE)
			}
			continue
		}
		if frag.ADDR.TYPE != AtypNone {
			t.Fatalf("fragment %d must carry AtypNone, got %v", i, frag.ADDR.TYPE)
		}
		if n := frag.ADDR.WriteToBytes(make([]byte, 64)); n != 1 {
			t.Fatalf("AtypNone address must serialize to a single byte, got %d", n)
		}
	}
	if packet.ADDR.TYPE != AtypIPv4 || len(packet.ADDR.ADDR) != 4 {
		t.Fatalf("shared cached address was mutated: type=%v", packet.ADDR.TYPE)
	}

	// The exact production failure shape: an unfragmented send to the same
	// destination after one fragmented send must still serialize the full
	// address (type + 4B IP + port).
	payload := []byte("small")
	unfrag := NewPacket(7, 10, 1, 0, uint16(len(payload)), packet.ADDR, payload, Ver5)
	buf := &bytes.Buffer{}
	if err := unfrag.WriteTo(buf); err != nil {
		t.Fatalf("unfragmented write failed: %v", err)
	}
	if buf.Len() != unfrag.BytesLen() {
		t.Fatalf("frame length %d does not match BytesLen %d", buf.Len(), unfrag.BytesLen())
	}
	serializedAddr := make([]byte, 64)
	if n := packet.ADDR.WriteToBytes(serializedAddr); n != 3+len(addr.ADDR) {
		t.Fatalf("cached address lost fields after fragmentation: serialized %d bytes", n)
	}
}

func TestFragmentPacketsReassemblesInOrder(t *testing.T) {
	addr := &Address{TYPE: AtypIPv6, ADDR: netip.AddrFrom16([16]byte{0x20}).AsSlice(), PORT: 53}
	payload := bytes.Repeat([]byte{0xC3}, 600)
	packet := NewPacket(11, 12, 1, 0, uint16(len(payload)), addr, append([]byte(nil), payload...), Ver5)

	frags, err := fragmentPackets(packet, 256)
	if err != nil {
		t.Fatalf("fragmentPackets: %v", err)
	}
	if int(packet.FRAG_TOTAL) != len(frags) {
		t.Fatalf("FRAG_TOTAL %d does not match fragment count %d", packet.FRAG_TOTAL, len(frags))
	}
	var reassembled []byte
	for _, frag := range frags {
		reassembled = append(reassembled, frag.DATA...)
	}
	if !bytes.Equal(reassembled, payload) {
		t.Fatal("reassembly in fragment order does not reproduce the payload")
	}
}

func TestFragmentPacketsRejectsProtocolCountOverflow(t *testing.T) {
	packet := NewPacket(1, 2, 1, 0, 256, &Address{TYPE: AtypNone}, make([]byte, 256), Ver5)
	if _, err := fragmentPackets(packet, 1); err == nil {
		t.Fatal("256 fragments must exceed the uint8 wire limit")
	}
	if _, err := fragmentPackets(packet, 0); err == nil {
		t.Fatal("zero fragment size must be rejected")
	}
}
