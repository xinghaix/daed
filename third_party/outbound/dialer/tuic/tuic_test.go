package tuic

import (
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
)

func TestTuicURLRoundTripWithCwnd(t *testing.T) {
	cases := []struct {
		name     string
		link     string
		wantCwnd int
	}{
		{
			name:     "brutal with cwnd",
			link:     "tuic://uuid:pass@example.com:443?congestion_control=brutal&cwnd=80000000",
			wantCwnd: 80000000,
		},
		{
			name:     "no cwnd defaults to zero",
			link:     "tuic://uuid:pass@example.com:443?congestion_control=bbr",
			wantCwnd: 0,
		},
		{
			name:     "malformed cwnd degrades to zero",
			link:     "tuic://uuid:pass@example.com:443?congestion_control=brutal&cwnd=abc",
			wantCwnd: 0,
		},
		{
			name:     "negative cwnd degrades to zero",
			link:     "tuic://uuid:pass@example.com:443?congestion_control=brutal&cwnd=-5",
			wantCwnd: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseTuicURL(tc.link)
			if err != nil {
				t.Fatalf("ParseTuicURL: %v", err)
			}
			if parsed.Cwnd != tc.wantCwnd {
				t.Fatalf("Cwnd = %d, want %d", parsed.Cwnd, tc.wantCwnd)
			}

			// Export/parse round trip must preserve the cwnd value.
			reparsed, err := ParseTuicURL(parsed.ExportToURL())
			if err != nil {
				t.Fatalf("re-ParseTuicURL: %v", err)
			}
			if reparsed.Cwnd != tc.wantCwnd {
				t.Fatalf("round-trip Cwnd = %d, want %d", reparsed.Cwnd, tc.wantCwnd)
			}
			if reparsed.CongestionControl != parsed.CongestionControl {
				t.Fatalf("round-trip CongestionControl = %q, want %q",
					reparsed.CongestionControl, parsed.CongestionControl)
			}
		})
	}
}

func TestTuicURLRoundTripWithCCOverride(t *testing.T) {
	cases := []struct {
		name           string
		link           string
		wantCC         string
		wantCCOverride string
	}{
		{
			name:           "cc_override bbr3",
			link:           "tuic://uuid:pass@example.com:443?congestion_control=bbr&cc_override=bbr3",
			wantCC:         "bbr",
			wantCCOverride: "bbr3",
		},
		{
			name:           "cc_override is lowercased and trimmed",
			link:           "tuic://uuid:pass@example.com:443?congestion_control=bbr&cc_override=%20BBR3%20",
			wantCC:         "bbr",
			wantCCOverride: "bbr3",
		},
		{
			name:           "missing cc_override stays empty",
			link:           "tuic://uuid:pass@example.com:443?congestion_control=bbr",
			wantCC:         "bbr",
			wantCCOverride: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseTuicURL(tc.link)
			if err != nil {
				t.Fatalf("ParseTuicURL: %v", err)
			}
			if parsed.CCOverride != tc.wantCCOverride {
				t.Fatalf("CCOverride = %q, want %q", parsed.CCOverride, tc.wantCCOverride)
			}
			// The override must not leak into the server-visible value.
			if parsed.CongestionControl != tc.wantCC {
				t.Fatalf("CongestionControl = %q, want %q", parsed.CongestionControl, tc.wantCC)
			}

			// Export/parse round trip must preserve the override.
			exported := parsed.ExportToURL()
			reparsed, err := ParseTuicURL(exported)
			if err != nil {
				t.Fatalf("re-ParseTuicURL: %v", err)
			}
			if reparsed.CCOverride != tc.wantCCOverride {
				t.Fatalf("round-trip CCOverride = %q, want %q", reparsed.CCOverride, tc.wantCCOverride)
			}
			if reparsed.CongestionControl != tc.wantCC {
				t.Fatalf("round-trip CongestionControl = %q, want %q", reparsed.CongestionControl, tc.wantCC)
			}
			if hasOverride := strings.Contains(exported, "cc_override="); hasOverride != (tc.wantCCOverride != "") {
				t.Fatalf("exported URL %q cc_override presence = %v, want %v",
					exported, hasOverride, tc.wantCCOverride != "")
			}
		})
	}
}

// TestDialerPropagatesCCOverrideToHeader closes the last untested hop of the
// opt-in path: a parsed link must reach the protocol layer as a client-local
// override, while the server-visible Feature1 keeps congestion_control.
func TestDialerPropagatesCCOverrideToHeader(t *testing.T) {
	parsed, err := ParseTuicURL("tuic://uuid:pass@example.com:443?congestion_control=bbr&cc_override=bbr3")
	if err != nil {
		t.Fatalf("ParseTuicURL: %v", err)
	}

	original := newProtocolDialer
	var capturedName string
	var captured protocol.Header
	newProtocolDialer = func(name string, next netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
		capturedName, captured = name, header
		return next, nil
	}
	defer func() { newProtocolDialer = original }()

	if _, _, err := parsed.Dialer(&dialer.ExtraOption{}, direct.SymmetricDirect); err != nil {
		t.Fatalf("Dialer: %v", err)
	}
	if capturedName != "tuic" {
		t.Fatalf("protocol name = %q, want tuic", capturedName)
	}
	if captured.CongestionOverride != "bbr3" {
		t.Fatalf("header CongestionOverride = %q, want bbr3", captured.CongestionOverride)
	}
	if captured.Feature1 != "bbr" {
		t.Fatalf("header Feature1 = %v, want server-visible congestion_control bbr", captured.Feature1)
	}
}
