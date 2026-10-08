package juicity

import (
	"strings"
	"testing"
)

func TestJuicityURLRoundTripWithCwnd(t *testing.T) {
	cases := []struct {
		name     string
		link     string
		wantCwnd int
	}{
		{
			name:     "brutal with cwnd",
			link:     "juicity://uuid:pass@example.com:443?congestion_control=brutal&cwnd=80000000",
			wantCwnd: 80000000,
		},
		{
			name:     "no cwnd defaults to zero",
			link:     "juicity://uuid:pass@example.com:443?congestion_control=bbr",
			wantCwnd: 0,
		},
		{
			name:     "malformed cwnd degrades to zero",
			link:     "juicity://uuid:pass@example.com:443?congestion_control=brutal&cwnd=abc",
			wantCwnd: 0,
		},
		{
			name:     "negative cwnd degrades to zero",
			link:     "juicity://uuid:pass@example.com:443?congestion_control=brutal&cwnd=-5",
			wantCwnd: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseJuicityURL(tc.link)
			if err != nil {
				t.Fatalf("ParseJuicityURL: %v", err)
			}
			if parsed.Cwnd != tc.wantCwnd {
				t.Fatalf("Cwnd = %d, want %d", parsed.Cwnd, tc.wantCwnd)
			}

			reparsed, err := ParseJuicityURL(parsed.ExportToURL())
			if err != nil {
				t.Fatalf("re-ParseJuicityURL: %v", err)
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

func TestJuicityURLRoundTripWithCCOverride(t *testing.T) {
	cases := []struct {
		name           string
		link           string
		wantCC         string
		wantCCOverride string
	}{
		{
			name:           "cc_override bbr3",
			link:           "juicity://uuid:pass@example.com:443?congestion_control=bbr&cc_override=bbr3",
			wantCC:         "bbr",
			wantCCOverride: "bbr3",
		},
		{
			name:           "cc_override is lowercased and trimmed",
			link:           "juicity://uuid:pass@example.com:443?congestion_control=bbr&cc_override=%20BBR3%20",
			wantCC:         "bbr",
			wantCCOverride: "bbr3",
		},
		{
			name:           "missing cc_override stays empty",
			link:           "juicity://uuid:pass@example.com:443?congestion_control=bbr",
			wantCC:         "bbr",
			wantCCOverride: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseJuicityURL(tc.link)
			if err != nil {
				t.Fatalf("ParseJuicityURL: %v", err)
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
			reparsed, err := ParseJuicityURL(exported)
			if err != nil {
				t.Fatalf("re-ParseJuicityURL: %v", err)
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
