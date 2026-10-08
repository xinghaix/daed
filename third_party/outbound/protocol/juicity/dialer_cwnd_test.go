package juicity

import (
	"crypto/tls"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
)

func TestNewDialerWiresCWNDFromFeature2(t *testing.T) {
	d, err := NewDialer(direct.SymmetricDirect, protocol.Header{
		ProxyAddress: "127.0.0.1:443",
		Feature1:     "brutal",
		Feature2:     80000000,
		TlsConfig:    &tls.Config{NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13, ServerName: "example.com"},
		User:         "00000000-0000-0000-0000-000000000000",
		Password:     "pass",
		IsClient:     true,
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	jd, ok := d.(*Dialer)
	if !ok {
		t.Fatalf("got %T, want *Dialer", d)
	}
	cli := jd.clientRing.newClient(func(int64) {})
	if cli.CWND != 80000000 {
		t.Fatalf("CWND = %d, want 80000000", cli.CWND)
	}
	if cli.CongestionController != "brutal" {
		t.Fatalf("CongestionController = %q, want brutal (negotiated brutal with a declared rate)", cli.CongestionController)
	}
}
