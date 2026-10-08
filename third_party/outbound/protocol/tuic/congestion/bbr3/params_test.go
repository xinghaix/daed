package bbr3

import "testing"

func TestDefaultParamsAreSane(t *testing.T) {
	p := DefaultParams()
	if p.HighGain <= 1 {
		t.Fatalf("HighGain = %v, want > 1", p.HighGain)
	}
	if p.CwndGain < 1 {
		t.Fatalf("CwndGain = %v, want >= 1", p.CwndGain)
	}
	if p.DrainGain <= 0 || p.DrainGain >= 1 {
		t.Fatalf("DrainGain = %v, want in (0,1)", p.DrainGain)
	}
	if p.UpGain <= 1 || p.DownGain >= 1 {
		t.Fatalf("probe gains out of order: up=%v down=%v", p.UpGain, p.DownGain)
	}
	if p.CruiseGain != 1 {
		t.Fatalf("CruiseGain = %v, want exactly 1: the pacer cruises at the estimate", p.CruiseGain)
	}
	if p.FullBwThreshold <= 1 {
		t.Fatalf("FullBwThreshold = %v, want > 1", p.FullBwThreshold)
	}
	if p.Beta <= 0 || p.Beta >= 1 {
		t.Fatalf("Beta = %v, want in (0,1)", p.Beta)
	}
	if p.ProbeRttFraction <= 0 || p.ProbeRttFraction >= 1 {
		t.Fatalf("ProbeRttFraction = %v, want in (0,1)", p.ProbeRttFraction)
	}
	if p.MinCwndPackets >= p.InitialCwndPackets {
		t.Fatalf("min cwnd %d >= initial cwnd %d", p.MinCwndPackets, p.InitialCwndPackets)
	}
	if p.MaxBwFilterRounds == 0 {
		t.Fatal("MaxBwFilterRounds must be positive")
	}
}

func TestConservativeParamsOnlyDisableLossBaseline(t *testing.T) {
	def, cons := DefaultParams(), ConservativeParams()
	if !def.EnableLossBaseline {
		t.Fatal("DefaultParams must enable the loss baseline")
	}
	if cons.EnableLossBaseline {
		t.Fatal("ConservativeParams must disable the loss baseline")
	}
	def.EnableLossBaseline = cons.EnableLossBaseline
	if def != cons {
		t.Fatalf("presets differ beyond the loss baseline: %+v vs %+v", def, cons)
	}
}

func TestSenderUsesGivenParams(t *testing.T) {
	p := DefaultParams()
	p.CwndGain = 1.5
	s := NewBbr3SenderWithParams(1200, 0, p)
	if s.params.CwndGain != 1.5 {
		t.Fatalf("CwndGain = %v, want 1.5", s.params.CwndGain)
	}
	if s.model.params.CwndGain != 1.5 {
		t.Fatal("model did not receive the parameters")
	}
}
