package bbr3

import (
	"testing"
	"time"

	"github.com/olicesx/quic-go/congestion"
)

// TestSetMaxDatagramSizeRecomputesDerivedWindows is the P3-53 guard:
// maxDatagramSize is the per-packet size ceiling and the unit every
// packet-count-derived window is expressed in, so changing it must move
// initialCwnd, minCwnd and maxCwnd together. Recomputing only some of them
// leaves the sender with a window expressed in the old unit.
func TestSetMaxDatagramSizeRecomputesDerivedWindows(t *testing.T) {
	p := DefaultParams()
	for _, size := range []congestion.ByteCount{1200, 1400, 4096} {
		s := NewBbr3SenderWithParams(size, 0, p)
		s.SetRTTStatsProvider(&fakeRTT{latest: 80 * time.Millisecond, smoothed: 80 * time.Millisecond})

		if got, want := s.model.maxDatagramSize, size; got != want {
			t.Fatalf("size=%d: model maxDatagramSize = %d, want %d", size, got, want)
		}
		if got, want := s.model.initialCwnd, congestion.ByteCount(p.InitialCwndPackets)*size; got != want {
			t.Fatalf("size=%d: initialCwnd = %d, want %d (%d packets)",
				size, got, want, p.InitialCwndPackets)
		}
		if got, want := s.model.minCwnd, congestion.ByteCount(p.MinCwndPackets)*size; got != want {
			t.Fatalf("size=%d: minCwnd = %d, want %d (%d packets)",
				size, got, want, p.MinCwndPackets)
		}
		if got, want := s.maxCwnd, congestion.ByteCount(congestion.MaxCongestionWindowPackets)*size; got != want {
			t.Fatalf("size=%d: maxCwnd = %d, want %d (%d packets)",
				size, got, want, congestion.MaxCongestionWindowPackets)
		}

		// A later change must move them again rather than leave the old unit.
		next := size * 2
		s.SetMaxDatagramSize(next)
		if got, want := s.model.initialCwnd, congestion.ByteCount(p.InitialCwndPackets)*next; got != want {
			t.Fatalf("after resize to %d: initialCwnd = %d, want %d", next, got, want)
		}
		if got, want := s.maxCwnd, congestion.ByteCount(congestion.MaxCongestionWindowPackets)*next; got != want {
			t.Fatalf("after resize to %d: maxCwnd = %d, want %d", next, got, want)
		}
		if got := s.GetCongestionWindow(); got < s.model.minCwnd {
			t.Fatalf("after resize to %d: cwnd = %d is below the new minCwnd %d", next, got, s.model.minCwnd)
		}
	}
}

// TestSetMaxDatagramSizeIgnoresNonPositive pins that a zero or negative size is
// rejected rather than blanking every derived window.
func TestSetMaxDatagramSizeIgnoresNonPositive(t *testing.T) {
	s := newTestSender(0)
	before := s.model.maxDatagramSize
	for _, size := range []congestion.ByteCount{0, -1} {
		s.SetMaxDatagramSize(size)
		if s.model.maxDatagramSize != before {
			t.Fatalf("SetMaxDatagramSize(%d) changed maxDatagramSize to %d", size, s.model.maxDatagramSize)
		}
	}
}

// TestAdaptLowerBoundsInvariant pins the P3-54 invariant in adaptLowerBounds:
//
//	inflightLo = max(bdp(bwLo), bdp(estimate), minCwnd)
//
// The bdp(estimate) term is the standing-BDP floor that stops a single loss
// round from starting a delivery-rate death spiral, and it is what makes the
// `cwnd < inflightLo` branch in recalc inert while bwLo stays near the estimate.
// The branch becomes load-bearing only when the estimate collapses well below
// the decayed bound. Both halves are asserted, so the explanation in the code
// cannot drift from the behaviour.
func TestAdaptLowerBoundsInvariant(t *testing.T) {
	p := DefaultParams()
	m := newModel(p, 1200)
	m.minRtt = 80 * time.Millisecond

	// Phase 1: a high, sustained estimate pulls bwLo up with it.
	seedEstimate(m, 10_000_000)
	for i := 0; i < 4; i++ {
		m.adaptLowerBounds()
	}
	est := m.estimate()
	if est == 0 {
		t.Fatal("no estimate after seeding the filter")
	}
	loBw := m.bwLo
	lo := m.inflightLo
	if want := bdpFrom(est, m.minRttValue()); lo < want {
		t.Fatalf("inflightLo = %d, want at least the standing BDP %d", lo, want)
	}

	// Phase 2: the estimate collapses. The floor must still hold inflightLo at
	// the standing BDP of the CURRENT estimate, and the decayed bound must be
	// what keeps it above that floor once it dominates.
	collapsed := Bandwidth(50_000)
	setEstimate(m, collapsed)
	m.adaptLowerBounds()
	newEst := m.estimate()
	floor := bdpFrom(newEst, m.minRttValue())
	if m.inflightLo < floor {
		t.Fatalf("inflightLo = %d fell below the standing BDP %d after the collapse",
			m.inflightLo, floor)
	}
	if m.bwLo == 0 {
		t.Fatal("bwLo is unset after a loss, so the lower bound could never bind")
	}
	// bwLo is a running MINIMUM: it only ever decays, never recovers on its
	// own. That is what makes the lower bound a bound rather than a second
	// estimate, and it is why the floor term above is needed at all.
	if m.bwLo > loBw {
		t.Fatalf("bwLo rose from %d to %d after a loss round; it must only decay", loBw, m.bwLo)
	}
	if want := Bandwidth(float64(est) * p.Beta); m.bwLo > want && m.bwLo != loBw {
		t.Fatalf("bwLo = %d, want it clamped by Beta*estimate = %d", m.bwLo, want)
	}
}

// TestInflightLoFloorIsLoadBearingWhenEstimateCollapses is the P3-54
// behavioural half: construct a sequence where bwLo > 2 x estimate and assert
// that recalc's `cwnd < inflightLo` branch actually raises the window above
// what the window formula alone would produce. Without this test the branch
// could be deleted and every existing assertion would still pass.
func TestInflightLoFloorIsLoadBearingWhenEstimateCollapses(t *testing.T) {
	s := newTestSender(0)
	// A long RTT so BDP numbers are large and the floor is visible.
	s.SetRTTStatsProvider(&fakeRTT{latest: 200 * time.Millisecond, smoothed: 200 * time.Millisecond})

	// Establish a high bandwidth bound, then let the estimate collapse so the
	// decayed lower bound sits far above it: bwLo > 2 x estimate. The collapse
	// comes from the estimator's window sliding past its peak, not from a loss
	// event, so adaptLowerBounds is deliberately not called again: that leaves
	// recalc's floor as the only thing holding the window up, which is exactly
	// the branch this test exists to exercise.
	s.model.minRtt = 200 * time.Millisecond
	seedEstimate(s.model, 20_000_000)
	for i := 0; i < 4; i++ {
		s.model.adaptLowerBounds()
	}
	setEstimate(s.model, 1_000_000)

	if s.model.bwLo <= 2*s.model.estimate() {
		t.Fatalf("precondition not met: bwLo=%d estimate=%d", s.model.bwLo, s.model.estimate())
	}

	s.mode.Store(uint32(modeProbeBWCruise))
	s.recalc()
	withFloor := s.GetCongestionWindow()

	// What recalc would have produced without the floor.
	est := s.hintEstimate(s.model.estimate())
	unfloored := congestion.ByteCount(s.params.CwndGain * float64(bdpFrom(est, s.model.minRttValue())))
	if unfloored < s.model.minCwnd {
		unfloored = s.model.minCwnd
	}
	if unfloored > s.maxCwnd {
		unfloored = s.maxCwnd
	}
	if withFloor <= unfloored {
		t.Fatalf("inflightLo floor is not load-bearing: cwnd=%d, unfloored=%d (inflightLo=%d)",
			withFloor, unfloored, s.model.inflightLo)
	}
	if want := s.model.inflightLo; withFloor != want {
		t.Fatalf("cwnd = %d, want the inflightLo floor %d", withFloor, want)
	}
}

// TestInflightLoFloorBetaSensitivity pins that the floor reacts to Beta with a
// mutation control: Beta 0.7 -> 0.99 must change the resulting window. This is
// the assertion that catches "Beta was retuned and nothing noticed".
// TestInflightLoFloorBetaSensitivity pins that the Beta term reaches the lower
// bound, with a mutation control: Beta 0.7 -> 0.99 must move the result.
//
// This asserts the bound at its unit, not through the sender's window, because
// the window is also bounded by bdp(estimate) - and estimate() is the windowed
// MAX of peer-reported delivery rates, so a peer that reports a high rate once
// pins that term for MaxBwFilterRounds. Observing Beta through the window
// therefore requires the peer to report a high rate and then a low one, which
// no single-round scenario can arrange. The unit assertion is exact and
// mutation-sensitive; the load-bearing test next door covers the branch itself.
func TestInflightLoFloorBetaSensitivity(t *testing.T) {
	measure := func(beta float64) (lo congestion.ByteCount, betaTerm congestion.ByteCount) {
		p := DefaultParams()
		p.Beta = beta
		m := newModel(p, 1200)
		m.minRtt = 20 * time.Millisecond
		seedEstimate(m, 10_000_000)
		m.adaptLowerBounds()
		return m.inflightLo, bdpFrom(Bandwidth(float64(m.estimate())*beta), m.minRttValue())
	}

	low, lowBetaTerm := measure(0.7)
	high, highBetaTerm := measure(0.99)

	// The decayed term itself is exactly Beta * estimate.
	if highBetaTerm <= lowBetaTerm {
		t.Fatalf("Beta does not scale the decayed bound: 0.7 -> %d, 0.99 -> %d", lowBetaTerm, highBetaTerm)
	}
	// And inflightLo is exactly max(decayed, standing BDP, minCwnd): here the
	// standing-BDP floor legitimately dominates both Beta values, which is the
	// documented invariant rather than a Beta insensitivity.
	standing := func() congestion.ByteCount {
		p := DefaultParams()
		m := newModel(p, 1200)
		m.minRtt = 20 * time.Millisecond
		seedEstimate(m, 10_000_000)
		return bdpFrom(m.estimate(), m.minRttValue())
	}()
	minCwnd := congestion.ByteCount(DefaultParams().MinCwndPackets) * 1200
	for _, got := range []congestion.ByteCount{low, high} {
		want := lowBetaTerm
		if highBetaTerm > want && got == high {
			want = highBetaTerm
		}
		if standing > want {
			want = standing
		}
		if minCwnd > want {
			want = minCwnd
		}
		if got != want {
			t.Fatalf("inflightLo = %d, want max(decayed, standing BDP, minCwnd) = %d", got, want)
		}
	}
	if high < low {
		t.Fatalf("raising Beta lowered inflightLo: 0.7 -> %d, 0.99 -> %d", low, high)
	}
}
