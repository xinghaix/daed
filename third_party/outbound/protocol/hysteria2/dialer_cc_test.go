package hysteria2

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/outbound/protocol/hysteria2/client"
)

func newCCOverrideHeader(override string) protocol.Header {
	return protocol.Header{
		ProxyAddress: "127.0.0.1:443",
		TlsConfig: &tls.Config{
			NextProtos:         []string{"h3"},
			MinVersion:         tls.VersionTLS13,
			ServerName:         "example.com",
			InsecureSkipVerify: true,
		},
		Feature1: &Feature1{
			BandwidthConfig: client.BandwidthConfig{MaxRx: 10_000_000, MaxTx: 5_000_000},
		},
		CongestionOverride: override,
		User:               "auth",
		IsClient:           true,
	}
}

// TestNewDialerAcceptsSupportedCCOverride covers the construction path: an
// empty override keeps the server-driven selection (and must never fail), and
// the hysteria2-supported overrides construct a dialer.
func TestNewDialerAcceptsSupportedCCOverride(t *testing.T) {
	for _, override := range []string{"", "bbr", "brutal", "bbr3"} {
		t.Run("override="+override, func(t *testing.T) {
			d, err := NewDialer(direct.SymmetricDirect, newCCOverrideHeader(override))
			if err != nil {
				t.Fatalf("NewDialer(override=%q): %v", override, err)
			}
			hd, ok := d.(*Dialer)
			if !ok {
				t.Fatalf("got %T, want *Dialer", d)
			}
			defer func() { _ = hd.Close() }()
		})
	}
}

// TestNewDialerRejectsUnsupportedCCOverride pins the fail-fast behavior for
// controllers the shared allowlist accepts but hysteria2 cannot install.
func TestNewDialerRejectsUnsupportedCCOverride(t *testing.T) {
	for _, override := range []string{"cubic", "new_reno", "bbr4"} {
		t.Run("override="+override, func(t *testing.T) {
			d, err := NewDialer(direct.SymmetricDirect, newCCOverrideHeader(override))
			if err == nil {
				if hd, ok := d.(*Dialer); ok {
					_ = hd.Close()
				}
				t.Fatalf("NewDialer(override=%q): want error, got nil", override)
			}
			if !strings.Contains(err.Error(), "cc_override") {
				t.Fatalf("error %q does not mention cc_override", err)
			}
		})
	}
}
