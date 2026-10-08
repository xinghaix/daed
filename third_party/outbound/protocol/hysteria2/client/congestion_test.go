package client

import "testing"

// TestResolveCongestion pins the whole decision table. An empty override now
// splits on whether the link actually declared a rate to send at: a positive
// min(serverRx, clientTx) installs the fixed-rate sender at exactly that rate
// (measured best on both throughput and latency on a bottlenecked path), while
// everything else - including the rxAuto case where the server asked for
// bandwidth detection - installs the probing default.
func TestResolveCongestion(t *testing.T) {
	const (
		mbps5  = uint64(5_000_000)
		mbps10 = uint64(10_000_000)
		mbps20 = uint64(20_000_000)
	)
	cases := []struct {
		name     string
		override string
		rxAuto   bool
		serverRx uint64
		clientTx uint64
		wantName string
		wantTx   uint64
		wantErr  bool
	}{
		{
			// The server asked for detection, so a fixed rate would ignore the
			// request; serverRx is not meaningful here and a declared clientTx
			// only caps the prober.
			// The probing default is bbr (see congestion.go): bbr3's estimator
			// stalls on low-RTT paths. The clientTx cap is carried through
			// but ignored by UseBBR, which probes with its own estimator.
			name:     "empty override with RxAuto probes and caps at clientTx",
			rxAuto:   true,
			serverRx: mbps5,
			clientTx: mbps10,
			wantName: ccBbr3,
			wantTx:   mbps10,
		},
		{
			name:     "empty override with a server limit sends at the fixed rate",
			serverRx: mbps5,
			clientTx: mbps10,
			wantName: ccBrutal,
			wantTx:   mbps5,
		},
		{
			name:     "empty override caps the fixed rate at clientTx",
			serverRx: mbps20,
			clientTx: mbps10,
			wantName: ccBrutal,
			wantTx:   mbps10,
		},
		{
			name:     "empty override with only a client rate sends at the fixed rate",
			serverRx: 0,
			clientTx: mbps10,
			wantName: ccBrutal,
			wantTx:   mbps10,
		},
		{
			// The probing default is bbr: the experimental bbr3 estimator does
			// not grow its bandwidth estimate on low-RTT paths (measured:
			// ~0.3 Gbps cap on a loopback veth lab while bbr reached 4 Gbps
			// over the same path). bbr3 stays reachable via cc_override.
			name:     "empty override without any bandwidth probes purely",
			wantName: ccBbr3,
			wantTx:   0,
		},
		{
			// clientTx is the hard cap on the historical computation, so a server
			// limit alone does not produce a rate to send at.
			name:     "empty override ignores server limit when clientTx is unset",
			serverRx: mbps5,
			clientTx: 0,
			wantName: ccBbr3,
			wantTx:   0,
		},
		{
			name:     "bbr3 hint is clientTx",
			override: ccBbr3,
			serverRx: mbps5,
			clientTx: mbps10,
			wantName: ccBbr3,
			wantTx:   mbps10,
		},
		{
			name:     "bbr3 overrides RxAuto",
			override: ccBbr3,
			rxAuto:   true,
			clientTx: mbps10,
			wantName: ccBbr3,
			wantTx:   mbps10,
		},
		{
			name:     "bbr3 without bandwidth probes with zero hint",
			override: ccBbr3,
			serverRx: mbps5,
			wantName: ccBbr3,
			wantTx:   0,
		},
		{
			name:     "bbr forces BBR and reports no target",
			override: ccBBR,
			serverRx: mbps5,
			clientTx: mbps10,
			wantName: ccBBR,
			wantTx:   0,
		},
		{
			name:     "brutal uses server limit",
			override: ccBrutal,
			serverRx: mbps5,
			clientTx: mbps10,
			wantName: ccBrutal,
			wantTx:   mbps5,
		},
		{
			name:     "brutal overrides RxAuto and falls back to clientTx",
			override: ccBrutal,
			rxAuto:   true,
			clientTx: mbps10,
			wantName: ccBrutal,
			wantTx:   mbps10,
		},
		{
			name:     "brutal without bandwidth falls back to BBR",
			override: ccBrutal,
			wantName: ccBBR,
			wantTx:   0,
		},
		{
			name:     "cubic is rejected",
			override: "cubic",
			serverRx: mbps5,
			clientTx: mbps10,
			wantErr:  true,
		},
		{
			name:     "new_reno is rejected",
			override: "new_reno",
			serverRx: mbps5,
			clientTx: mbps10,
			wantErr:  true,
		},
		{
			name:     "unknown override is rejected",
			override: "bbr4",
			wantErr:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, tx, err := resolveCongestion(tc.override, tc.rxAuto, tc.serverRx, tc.clientTx)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveCongestion(%q, %v, %d, %d) = (%q, %d), want error",
						tc.override, tc.rxAuto, tc.serverRx, tc.clientTx, name, tx)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveCongestion(%q, %v, %d, %d): %v",
					tc.override, tc.rxAuto, tc.serverRx, tc.clientTx, err)
			}
			if name != tc.wantName || tx != tc.wantTx {
				t.Fatalf("resolveCongestion(%q, %v, %d, %d) = (%q, %d), want (%q, %d)",
					tc.override, tc.rxAuto, tc.serverRx, tc.clientTx, name, tx, tc.wantName, tc.wantTx)
			}
		})
	}
}

func TestValidateCongestionOverride(t *testing.T) {
	cases := []struct {
		override string
		wantErr  bool
	}{
		{override: "", wantErr: false},
		{override: ccBBR, wantErr: false},
		{override: ccBrutal, wantErr: false},
		{override: ccBbr3, wantErr: false},
		{override: "cubic", wantErr: true},
		{override: "new_reno", wantErr: true},
		{override: "bbr4", wantErr: true},
		{override: "BBR3", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.override, func(t *testing.T) {
			if err := ValidateCongestionOverride(tc.override); (err != nil) != tc.wantErr {
				t.Fatalf("ValidateCongestionOverride(%q) error = %v, wantErr %v",
					tc.override, err, tc.wantErr)
			}
		})
	}
}
