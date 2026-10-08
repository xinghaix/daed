package juicity

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
)

func TestNewDialerWiresCongestionOverride(t *testing.T) {
	cases := []struct {
		name     string
		serverCC string
		override string
		want     string
	}{
		{
			name:     "no override selects the default (bbr3), ignoring server value",
			serverCC: "cubic",
			override: "",
			want:     "bbr3",
		},
		{
			name:     "override replaces server value",
			serverCC: "cubic",
			override: "bbr3",
			want:     "bbr3",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := NewDialer(direct.SymmetricDirect, protocol.Header{
				ProxyAddress: "127.0.0.1:443",
				Feature1:     tc.serverCC,
				Feature2:     0,
				TlsConfig: &tls.Config{
					NextProtos: []string{"h3"},
					MinVersion: tls.VersionTLS13,
					ServerName: "example.com",
				},
				CongestionOverride: tc.override,
				User:               "00000000-0000-0000-0000-000000000000",
				Password:           "pass",
				IsClient:           true,
			})
			if err != nil {
				t.Fatalf("NewDialer: %v", err)
			}
			jd, ok := d.(*Dialer)
			if !ok {
				t.Fatalf("got %T, want *Dialer", d)
			}
			defer func() { _ = jd.Close() }()

			cli := jd.clientRing.newClient(func(int64) {})
			if cli.CongestionController != tc.want {
				t.Fatalf("CongestionController = %q, want %q", cli.CongestionController, tc.want)
			}
		})
	}
}

func TestNewDialerRejectsUnknownCongestionOverride(t *testing.T) {
	d, err := NewDialer(direct.SymmetricDirect, protocol.Header{
		ProxyAddress:       "127.0.0.1:443",
		Feature1:           "bbr",
		CongestionOverride: "bbr4",
		User:               "00000000-0000-0000-0000-000000000000",
		Password:           "pass",
		IsClient:           true,
	})
	if err == nil {
		if jd, ok := d.(*Dialer); ok {
			_ = jd.Close()
		}
		t.Fatal("NewDialer with unknown cc_override: want error, got nil")
	}
	if !strings.Contains(err.Error(), "cc_override") {
		t.Fatalf("error %q does not mention cc_override", err)
	}
}

func TestNewDialerNonStringFeature1DoesNotPanic(t *testing.T) {
	d, err := NewDialer(direct.SymmetricDirect, protocol.Header{
		ProxyAddress: "127.0.0.1:443",
		Feature1:     42,
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
	defer func() { _ = jd.Close() }()

	cli := jd.clientRing.newClient(func(int64) {})
	if cli.CongestionController != "bbr3" {
		t.Fatalf("CongestionController = %q, want default %q for non-string Feature1", cli.CongestionController, "bbr3")
	}
}
