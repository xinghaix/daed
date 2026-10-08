package bbr3

import (
	"github.com/olicesx/quic-go/congestion"
)

// bounds.go holds the inflight_hi / inflight_lo bound pair, the loss baseline and
// the PROBE_UP / PROBE_RTT window policy.
func (m *model) updateLossBaseline() {
	if !m.params.EnableLossBaseline {
		return
	}
	minSent := congestion.ByteCount(m.params.MinLossSentPackets) * m.maxDatagramSize
	if m.lastRoundSent < minSent {
		return
	}
	rate := float64(m.lastRoundLost) / float64(m.lastRoundSent)
	if !m.lossBaselineSet {
		m.lossBaseline = rate
		m.lossBaselineSet = true
		return
	}
	w := m.params.LossBaselineWeight
	m.lossBaseline = (1-w)*m.lossBaseline + w*rate
}

// lossThresholdNow is the loss rate that counts as overshoot: the fixed floor,
// or a multiple of the recent baseline when the path is inherently lossy.
func (m *model) lossThresholdNow() float64 {
	threshold := m.params.LossThreshold
	if m.params.EnableLossBaseline && m.lossBaselineSet {
		if scaled := m.lossBaseline * m.params.LossBaselineFactor; scaled > threshold {
			threshold = scaled
		}
	}
	return threshold
}

// lossRateExceeded reports whether loss exceeds the overshoot threshold, either
// within the round in flight (fast reaction) or over the round that just
// completed (the round-boundary decision).
func (m *model) lossRateExceeded() bool {
	minSent := congestion.ByteCount(m.params.MinLossSentPackets) * m.maxDatagramSize
	threshold := m.lossThresholdNow()
	if m.roundLostPackets >= m.params.MinLossPackets && m.roundBytesSent >= minSent &&
		float64(m.roundBytesLost) > threshold*float64(m.roundBytesSent) {
		return true
	}
	if m.lastRoundLostPkts >= m.params.MinLossPackets && m.lastRoundSent >= minSent {
		if m.lastRoundLossThreshold > 0 {
			threshold = m.lastRoundLossThreshold
		}
		return float64(m.lastRoundLost) > threshold*float64(m.lastRoundSent)
	}
	return false
}

// capInflightHi pins the upper bound at the volume the sender put on the path in
// the round where the overshoot happened, floored at one BDP so it never falls
// below the pipe already measured. It can grow again on later PROBE_UP rounds,
// as part of this experimental recovery policy.
func (m *model) capInflightHi() {
	target := m.lastRoundSent
	if target == 0 {
		target = m.roundBytesSent
	}
	floor := m.bdp()
	if floor < m.initialCwnd {
		floor = m.initialCwnd
	}
	if floor > target {
		target = floor
	}
	if m.inflightHi == 0 || target < m.inflightHi {
		m.inflightHi = target
	}
}

// adaptLowerBounds is the loss response: bandwidth_lo decays toward Beta of the
// current estimate and inflight_lo follows it, floored at the standing BDP so a
// single loss round cannot start a delivery-rate death spiral.
func (m *model) adaptLowerBounds() {
	est := m.estimate()
	if est == 0 {
		return
	}
	decayed := Bandwidth(float64(est) * m.params.Beta)
	if m.bwLo == 0 || decayed < m.bwLo {
		m.bwLo = decayed
	}
	lo := bdpFrom(m.bwLo, m.minRttValue())
	if floor := bdpFrom(est, m.minRttValue()); floor > lo {
		lo = floor
	}
	if lo < m.minCwnd {
		lo = m.minCwnd
	}
	m.inflightLo = lo
}

// probeUpRound grows inflight_hi while the probe is not overshooting, and caps
// it when it is. cwnd is the sender's current window, used as the growth floor.
func (m *model) probeUpRound(roundStart bool, lostBytes congestion.ByteCount, cwnd congestion.ByteCount) (turnedDown bool) {
	if lostBytes > 0 && m.lossRateExceeded() {
		m.capInflightHi()
		m.probeUpRounds = 0
		return true
	}
	if !roundStart {
		return false
	}
	target := m.inflightHi + congestion.ByteCount(float64(m.inflightHi)*m.params.ProbeUpGrowth)
	if minGrowth := cwnd + 2*m.maxDatagramSize; target < minGrowth {
		target = minGrowth
	}
	if target > m.inflightHi {
		m.inflightHi = target
	}
	// Bound the experimental probe to ProbeUpRounds even without loss.
	m.probeUpRounds++
	if m.probeUpRounds >= m.params.ProbeUpRounds {
		m.probeUpRounds = 0
		return true
	}
	return false
}

// resetProbeUp starts a fresh PROBE_UP budget.
func (m *model) resetProbeUp() { m.probeUpRounds = 0 }

// probeRttTarget is a local policy: a fraction of the upper bound, floored at
// the minimum window. This formula alone does not establish spec conformance.
func (m *model) probeRttTarget() congestion.ByteCount {
	upper := m.inflightHi
	if upper == 0 {
		upper = congestion.ByteCount(m.params.CwndGain * float64(m.bdp()))
	}
	target := congestion.ByteCount(m.params.ProbeRttFraction * float64(upper))
	if target < m.minCwnd {
		target = m.minCwnd
	}
	return target
}
