package obfs

import (
	"strings"
	"testing"
)

// TestTLS12TicketAuthEncodeLongHost pins the dynamically sized ClientHello
// scratch: an obfs host from link params longer than the old fixed 2 KiB
// array must encode without panicking.
func TestTLS12TicketAuthEncodeLongHost(t *testing.T) {
	tls12 := newTLS12TicketAuth().(*tls12TicketAuth)
	tls12.SetServerInfo(&ServerInfo{Host: strings.Repeat("a", 2000)})
	tls12.SetData(tls12.GetData())

	encoded, err := tls12.Encode(nil)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if len(encoded) == 0 {
		t.Fatal("Encode() returned no data")
	}
}
