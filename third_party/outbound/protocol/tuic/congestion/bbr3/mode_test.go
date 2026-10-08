package bbr3

import "testing"

func TestModeString(t *testing.T) {
	want := map[mode]string{
		modeStartup:       "STARTUP",
		modeDrain:         "DRAIN",
		modeProbeBWDown:   "PROBE_BW_DOWN",
		modeProbeBWCruise: "PROBE_BW_CRUISE",
		modeProbeBWRefill: "PROBE_BW_REFILL",
		modeProbeBWUp:     "PROBE_BW_UP",
		modeProbeRTT:      "PROBE_RTT",
	}
	for m, s := range want {
		if got := m.String(); got != s {
			t.Fatalf("mode %d String() = %q, want %q", m, got, s)
		}
	}
	if got := mode(99).String(); got != "UNKNOWN" {
		t.Fatalf("unknown mode String() = %q", got)
	}
}

func TestProbeBWGainCycleOrder(t *testing.T) {
	// UP -> DOWN -> CRUISE -> REFILL -> UP, so a full cycle returns to UP.
	m := modeProbeBWUp
	seen := []mode{m}
	for i := 0; i < 3; i++ {
		m = m.advance()
		seen = append(seen, m)
	}
	want := []mode{modeProbeBWUp, modeProbeBWDown, modeProbeBWCruise, modeProbeBWRefill}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("cycle = %v, want %v", seen, want)
		}
	}
	if got := modeProbeBWRefill.advance(); got != modeProbeBWUp {
		t.Fatalf("REFILL advances to %s, want PROBE_BW_UP", got)
	}
	if got := modeStartup.advance(); got != modeProbeBWDown {
		t.Fatalf("unexpected advance from STARTUP: %s", got)
	}
}
