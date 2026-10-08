package hysteria2

import (
	"errors"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
)

// TestParseHysteria2URLBandwidth covers bandwidth declarations in the URL:
// hysteria2 official / sing-box style upmbps/downmbps (Mbps, usable
// individually) plus the legacy dae-style maxTx/maxRx (raw bytes per second,
// both required together).
func TestParseHysteria2URLBandwidth(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantTx  uint64
		wantRx  uint64
		wantErr bool
	}{
		{
			name:   "upmbps downmbps",
			url:    "hysteria2://user:pass@example.com:443?upmbps=40&downmbps=300",
			wantTx: 5_000_000, wantRx: 37_500_000, // 40 Mbps / 300 Mbps -> B/s
		},
		{
			name:   "upmbps only",
			url:    "hysteria2://user:pass@example.com:443?upmbps=40",
			wantTx: 5_000_000, wantRx: 0,
		},
		{
			name:   "downmbps only",
			url:    "hysteria2://user:pass@example.com:443?downmbps=300",
			wantTx: 0, wantRx: 37_500_000,
		},
		{
			name:   "legacy maxTx maxRx",
			url:    "hysteria2://user:pass@example.com:443?maxTx=5000000&maxRx=37500000",
			wantTx: 5_000_000, wantRx: 37_500_000,
		},
		{
			name:   "mixed upmbps with legacy maxRx",
			url:    "hysteria2://user:pass@example.com:443?upmbps=40&maxTx=999&maxRx=37500000",
			wantTx: 5_000_000, wantRx: 37_500_000, // upmbps wins over maxTx; maxRx from legacy
		},
		{
			name:    "invalid upmbps",
			url:     "hysteria2://user:pass@example.com:443?upmbps=abc",
			wantErr: true,
		},
		{
			name:    "invalid downmbps",
			url:     "hysteria2://user:pass@example.com:443?downmbps=12x",
			wantErr: true,
		},
		{
			name: "no bandwidth params",
			url:  "hysteria2://user:pass@example.com:443",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := ParseHysteria2URL(tc.url)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseHysteria2URL(%q) = nil error, want InvalidParameterErr", tc.url)
				}
				if !errors.Is(err, dialer.InvalidParameterErr) {
					t.Fatalf("ParseHysteria2URL(%q) error = %v, want InvalidParameterErr", tc.url, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseHysteria2URL(%q) error = %v", tc.url, err)
			}
			if conf.MaxTx != tc.wantTx {
				t.Errorf("MaxTx = %d, want %d", conf.MaxTx, tc.wantTx)
			}
			if conf.MaxRx != tc.wantRx {
				t.Errorf("MaxRx = %d, want %d", conf.MaxRx, tc.wantRx)
			}
		})
	}
}

// TestParseHysteria2URLBandwidthRoundTrip ensures exported URLs stay parseable
// and keep the bandwidth values after a round trip.
func TestParseHysteria2URLBandwidthRoundTrip(t *testing.T) {
	link := "hysteria2://user:pass@example.com:443?upmbps=40&downmbps=300"
	conf, err := ParseHysteria2URL(link)
	if err != nil {
		t.Fatalf("ParseHysteria2URL() error = %v", err)
	}
	roundTrip, err := ParseHysteria2URL(conf.ExportToURL())
	if err != nil {
		t.Fatalf("ParseHysteria2URL() on exported URL error = %v", err)
	}
	if roundTrip.MaxTx != conf.MaxTx || roundTrip.MaxRx != conf.MaxRx {
		t.Fatalf("round-trip bandwidth = (%d,%d), want (%d,%d)",
			roundTrip.MaxTx, roundTrip.MaxRx, conf.MaxTx, conf.MaxRx)
	}
}
