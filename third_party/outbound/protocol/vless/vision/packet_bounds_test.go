package vision

import (
	"io"
	"net/netip"
	"testing"
)

// TestReadPacketAddrBounds pins the bounds checks on the server-controlled
// address block: every truncated input must return an error instead of
// panicking on the internal slices.
func TestReadPacketAddrBounds(t *testing.T) {
	for n := 0; n < 20; n++ {
		p := make([]byte, n)
		if n >= 3 {
			// Force the IPv6 branch (16-byte IP) so the only variable is
			// the input length; the all-zero IPv4 layout would parse.
			p[2] = 3
		}
		addr, err := ReadPacketAddr(p)
		if err == nil {
			t.Fatalf("ReadPacketAddr(len %d) = %v, want error", n, addr)
		}
		if !ioErr(err) {
			t.Fatalf("ReadPacketAddr(len %d) error = %v, want io.ErrUnexpectedEOF", n, err)
		}
	}
}

func ioErr(err error) bool { return err == io.ErrUnexpectedEOF }

// TestReadPacketAddrRoundTrip pins the valid layouts through PutPacketAddr.
func TestReadPacketAddrRoundTrip(t *testing.T) {
	v4 := netip.MustParseAddrPort("1.2.3.4:443")
	src := make([]byte, IPAddrToPacketAddrLength(v4))
	if err := PutPacketAddr(src, v4); err != nil {
		t.Fatalf("PutPacketAddr(v4) error = %v", err)
	}
	// The wire layout carries one extra leading byte before the block
	// ReadPacketAddr parses.
	wire := append([]byte{0}, src...)
	got, err := ReadPacketAddr(wire)
	if err != nil {
		t.Fatalf("ReadPacketAddr(v4) error = %v", err)
	}
	if got != v4 {
		t.Fatalf("ReadPacketAddr(v4) = %v, want %v", got, v4)
	}

	v6 := netip.MustParseAddrPort("[2001:db8::1]:443")
	src6 := make([]byte, IPAddrToPacketAddrLength(v6))
	if err := PutPacketAddr(src6, v6); err != nil {
		t.Fatalf("PutPacketAddr(v6) error = %v", err)
	}
	wire6 := append([]byte{0}, src6...)
	got6, err := ReadPacketAddr(wire6)
	if err != nil {
		t.Fatalf("ReadPacketAddr(v6) error = %v", err)
	}
	if got6 != v6 {
		t.Fatalf("ReadPacketAddr(v6) = %v, want %v", got6, v6)
	}
}
