package hysteria2

import (
	"strings"
	"testing"
)

// TestParseHysteria2URLCCOverride covers the client-local cc_override
// parameter: normalization, round-trip serialization, and that it never
// disturbs the bandwidth declarations.
func TestParseHysteria2URLCCOverride(t *testing.T) {
	cases := []struct {
		name      string
		url       string
		want      string
		wantMaxTx uint64
		wantMaxRx uint64
	}{
		{
			name: "cc_override bbr3",
			url:  "hysteria2://user:pass@example.com:443?cc_override=bbr3",
			want: "bbr3",
		},
		{
			name: "cc_override is lowercased and trimmed",
			url:  "hysteria2://user:pass@example.com:443?cc_override=%20BBR3%20",
			want: "bbr3",
		},
		{
			name: "missing cc_override stays empty",
			url:  "hysteria2://user:pass@example.com:443",
			want: "",
		},
		{
			name:      "cc_override keeps bandwidth params intact",
			url:       "hysteria2://user:pass@example.com:443?upmbps=40&downmbps=300&cc_override=bbr3",
			want:      "bbr3",
			wantMaxTx: 5_000_000,
			wantMaxRx: 37_500_000,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseHysteria2URL(tc.url)
			if err != nil {
				t.Fatalf("ParseHysteria2URL: %v", err)
			}
			if parsed.CCOverride != tc.want {
				t.Fatalf("CCOverride = %q, want %q", parsed.CCOverride, tc.want)
			}
			if parsed.MaxTx != tc.wantMaxTx || parsed.MaxRx != tc.wantMaxRx {
				t.Fatalf("MaxTx/MaxRx = %d/%d, want %d/%d",
					parsed.MaxTx, parsed.MaxRx, tc.wantMaxTx, tc.wantMaxRx)
			}

			exported := parsed.ExportToURL()
			reparsed, err := ParseHysteria2URL(exported)
			if err != nil {
				t.Fatalf("re-ParseHysteria2URL(%q): %v", exported, err)
			}
			if reparsed.CCOverride != tc.want {
				t.Fatalf("round-trip CCOverride = %q, want %q", reparsed.CCOverride, tc.want)
			}
			if reparsed.MaxTx != tc.wantMaxTx || reparsed.MaxRx != tc.wantMaxRx {
				t.Fatalf("round-trip MaxTx/MaxRx = %d/%d, want %d/%d",
					reparsed.MaxTx, reparsed.MaxRx, tc.wantMaxTx, tc.wantMaxRx)
			}
			if hasOverride := strings.Contains(exported, "cc_override="); hasOverride != (tc.want != "") {
				t.Fatalf("exported URL %q cc_override presence = %v, want %v",
					exported, hasOverride, tc.want != "")
			}
		})
	}
}
