package bbr3

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/olicesx/quic-go/congestion"
)

type hintState uint32

const (
	hintUnvalidated hintState = iota
	hintProbing
	hintValidated
	hintRevoked
)

// Revoke reasons. rejections counts every withdraw attempt in any state;
// withdrawals counts only exits from probing/validated. The strings are a
// frozen diagnostic vocabulary: rename nothing, reorder nothing.
//
// There is deliberately no "pto" reason. PTO is not observable through
// congestion.CongestionControl in this quic-go fork: the only reference to
// OnRetransmissionTimeout is the pure forwarder at
// internal/ackhandler/cc_adapter.go:52-53, and the PTO path in
// sent_packet_handler.go (OnLossDetectionTimeout, ~lines 713-780) never
// notifies the controller. A reason bucket that can never be filled would make
// the telemetry claim a coverage the controller does not have (P3-50).
const (
	reasonLoss       = "loss"
	reasonEcnOrTimer = "ecn_or_timer"
	reasonRtt        = "rtt"
	reasonZeroRtt    = "zero_rtt"
	reasonBackwards  = "backwards"
	reasonExpiry     = "expiry"
	reasonDelivery   = "delivery"
	reasonProbeFail  = "probe_fail"
)

const nRevokeReasons = 8

var revokeReasons = [nRevokeReasons]string{
	reasonLoss, reasonEcnOrTimer, reasonRtt, reasonZeroRtt,
	reasonBackwards, reasonExpiry, reasonDelivery, reasonProbeFail,
}

var revokeReasonIndex = func() map[string]int {
	m := make(map[string]int, nRevokeReasons)
	for i, r := range revokeReasons {
		m[r] = i
	}
	return m
}()

// windowRateRingCap bounds the per-window rate ring so a long run cannot grow
// telemetry without bound; the oldest windows are dropped first.
const windowRateRingCap = 256

// WindowRate is one completed evaluation window: when it ended (milliseconds
// since sender creation), the delivery rate it measured, and its band.
type WindowRate struct {
	TMS     uint64 `json:"t_ms"`
	RateBps uint64 `json:"rate_Bps"`
	Class   string `json:"class"`
}

// HintStatus reports experimental gate transitions, independently of model mode.
// Counts are safe to read while QUIC owns and updates the sender. All fields
// after Revocations are diagnostic telemetry: they never feed back into control
// decisions, and a disabled gate reports them all zero or empty.
type HintStatus struct {
	State       string `json:"state"`
	Probes      uint64 `json:"probes"`
	Validations uint64 `json:"validations"`
	Revocations uint64 `json:"revocations"`

	RejectionsTotal map[string]uint64 `json:"rejections_total"`
	Withdrawals     map[string]uint64 `json:"withdrawals"`

	WindowsTotal     uint64 `json:"windows_total"`
	WindowsClean     uint64 `json:"windows_clean"`
	WindowsProbeBand uint64 `json:"windows_probe_band"`
	WindowsLow       uint64 `json:"windows_low"`
	MaxCleanStreak   uint64 `json:"max_clean_streak"`

	FirstProbeMS     uint64 `json:"first_probe_ms"`
	FirstValidatedMS uint64 `json:"first_validated_ms"`
	LastValidatedMS  uint64 `json:"last_validated_ms"`
	MsProbing        uint64 `json:"ms_probing"`
	MsValidated      uint64 `json:"ms_validated"`

	WindowRates []WindowRate `json:"window_rates"`

	LiftEvents     uint64 `json:"lift_events"`
	LiftMaxBps     uint64 `json:"lift_max_bps"`
	RttChecks      uint64 `json:"rtt_checks"`
	RttOverBound   uint64 `json:"rtt_over_bound"`
	RttZeroSamples uint64 `json:"rtt_zero_samples"`
}
type hintGate struct {
	state       hintState
	stateSince  time.Time
	since       time.Time
	bytes       congestion.ByteCount
	clean       int
	recent      Bandwidth
	until       time.Time
	cooldown    time.Time
	publicState atomic.Uint32
	probes      atomic.Uint64
	validations atomic.Uint64
	revocations atomic.Uint64

	// Diagnostic telemetry below. None of it is consulted by control decisions.
	rejections  [nRevokeReasons]atomic.Uint64
	withdrawals [nRevokeReasons]atomic.Uint64

	windowsTotal     atomic.Uint64
	windowsClean     atomic.Uint64
	windowsProbeBand atomic.Uint64
	windowsLow       atomic.Uint64
	cleanStreak      int // sender goroutine only; see recordWindow
	maxCleanStreak   atomic.Uint64

	firstProbeMS     atomic.Uint64
	firstValidatedMS atomic.Uint64
	lastValidatedMS  atomic.Uint64
	msProbing        atomic.Uint64
	msValidated      atomic.Uint64

	liftEvents atomic.Uint64
	liftMaxBps atomic.Uint64

	rttChecks      atomic.Uint64
	rttOverBound   atomic.Uint64
	rttZeroSamples atomic.Uint64

	ringMu   sync.Mutex
	ring     [windowRateRingCap]WindowRate
	ringNext int
	ringLen  int
}

func (g *hintGate) pushWindowRate(w WindowRate) {
	g.ringMu.Lock()
	defer g.ringMu.Unlock()
	g.ring[g.ringNext] = w
	g.ringNext = (g.ringNext + 1) % windowRateRingCap
	if g.ringLen < windowRateRingCap {
		g.ringLen++
	}
}

func (g *hintGate) snapshotWindowRates() []WindowRate {
	g.ringMu.Lock()
	defer g.ringMu.Unlock()
	out := make([]WindowRate, 0, g.ringLen)
	for i := 0; i < g.ringLen; i++ {
		idx := (g.ringNext - g.ringLen + i + windowRateRingCap) % windowRateRingCap
		out = append(out, g.ring[idx])
	}
	return out
}

func (b *Bbr3Sender) setHintState(state hintState, now time.Time) {
	g := &b.gate
	if state != g.state {
		// Accumulate state residence on actual transitions; renewals while
		// staying validated or repeated revocations do not reset the clock.
		if !g.stateSince.IsZero() && now.After(g.stateSince) {
			switch g.state {
			case hintProbing:
				g.msProbing.Add(uint64(now.Sub(g.stateSince).Milliseconds()))
			case hintValidated:
				g.msValidated.Add(uint64(now.Sub(g.stateSince).Milliseconds()))
			}
		}
		g.stateSince = now
	}
	g.state = state
	g.publicState.Store(uint32(state))
}

// sinceStartMS converts an event time to milliseconds since sender creation;
// zero is reserved for "never" and clamps clock skew below creation.
func (b *Bbr3Sender) sinceStartMS(now time.Time) uint64 {
	if b.createdAt.IsZero() || now.Before(b.createdAt) {
		return 0
	}
	return uint64(now.Sub(b.createdAt).Milliseconds())
}

// HintStatus returns only atomic or lock-protected telemetry, never mutable
// congestion state.
func (b *Bbr3Sender) HintStatus() HintStatus {
	if !b.params.EnableValidatedHint || b.hint == 0 {
		// Disabled gate: zero counts, empty (not null) maps and ring.
		return HintStatus{
			State:           "disabled",
			RejectionsTotal: map[string]uint64{},
			Withdrawals:     map[string]uint64{},
			WindowRates:     []WindowRate{},
		}
	}
	g := &b.gate
	return HintStatus{
		State:       []string{"unvalidated", "probing", "validated", "revoked"}[g.publicState.Load()],
		Probes:      g.probes.Load(),
		Validations: g.validations.Load(),
		Revocations: g.revocations.Load(),

		RejectionsTotal: g.counts(&g.rejections),
		Withdrawals:     g.counts(&g.withdrawals),

		WindowsTotal:     g.windowsTotal.Load(),
		WindowsClean:     g.windowsClean.Load(),
		WindowsProbeBand: g.windowsProbeBand.Load(),
		WindowsLow:       g.windowsLow.Load(),
		MaxCleanStreak:   g.maxCleanStreak.Load(),

		FirstProbeMS:     g.firstProbeMS.Load(),
		FirstValidatedMS: g.firstValidatedMS.Load(),
		LastValidatedMS:  g.lastValidatedMS.Load(),
		MsProbing:        g.msProbing.Load(),
		MsValidated:      g.msValidated.Load(),

		WindowRates: g.snapshotWindowRates(),

		LiftEvents:     g.liftEvents.Load(),
		LiftMaxBps:     g.liftMaxBps.Load(),
		RttChecks:      g.rttChecks.Load(),
		RttOverBound:   g.rttOverBound.Load(),
		RttZeroSamples: g.rttZeroSamples.Load(),
	}
}

func (g *hintGate) counts(arr *[nRevokeReasons]atomic.Uint64) map[string]uint64 {
	out := make(map[string]uint64, nRevokeReasons)
	for i, name := range revokeReasons {
		out[name] = arr[i].Load()
	}
	return out
}

func (b *Bbr3Sender) revokeHint(now time.Time, reason string) {
	if !b.params.EnableValidatedHint || b.hint == 0 {
		return
	}
	g := &b.gate
	idx, ok := revokeReasonIndex[reason]
	if !ok {
		idx = revokeReasonIndex[reasonEcnOrTimer]
	}
	g.rejections[idx].Add(1)
	if g.state == hintProbing || g.state == hintValidated {
		g.revocations.Add(1)
		g.withdrawals[idx].Add(1)
	}
	b.setHintState(hintRevoked, now)
	g.clean = 0
	g.since = now
	g.bytes = 0
	g.until = time.Time{}
	g.cooldown = now.Add(time.Second)
}
func (b *Bbr3Sender) expireHint(now time.Time) {
	if !b.gate.until.IsZero() && !now.Before(b.gate.until) {
		b.revokeHint(now, reasonExpiry)
		b.recalc()
	}
}

// observeHint uses actual uniquely acknowledged bytes over wall-clock windows,
// not the experimental delivery sampler's rate or an inferred loss correction.
// A near-hint delivery rate must survive three >=250ms windows without loss or
// RTT inflation. The target is renewed by continuing evidence, never by a hint.
func (b *Bbr3Sender) observeHint(now time.Time, delivered, lost congestion.ByteCount) {
	if !b.params.EnableValidatedHint || b.hint == 0 {
		return
	}
	g := &b.gate
	g.rttChecks.Add(1)
	rtt := b.rttSample()
	base := b.model.minRttValue()
	allowance := base / 8
	if allowance < 2*time.Millisecond {
		allowance = 2 * time.Millisecond
	}
	// RTT bound telemetry counts the condition itself, independent of which
	// reason a simultaneous loss event would claim for the rejection.
	if rtt <= 0 {
		g.rttZeroSamples.Add(1)
	} else if rtt > base+allowance {
		g.rttOverBound.Add(1)
	}
	if lost > 0 {
		b.revokeHint(now, reasonLoss)
		return
	}
	if rtt <= 0 {
		b.revokeHint(now, reasonZeroRtt)
		return
	}
	if rtt > base+allowance {
		b.revokeHint(now, reasonRtt)
		return
	}
	if now.Before(g.cooldown) {
		return
	}
	if g.since.IsZero() {
		g.since = now
		return
	}
	if now.Before(g.since) {
		b.revokeHint(now, reasonBackwards)
		return
	}
	g.bytes += delivered
	window := 3 * base
	if window < 250*time.Millisecond {
		window = 250 * time.Millisecond
	}
	if window > time.Second {
		window = time.Second
	}
	elapsed := now.Sub(g.since)
	if elapsed < window {
		return
	}
	rate := bandwidthFromDelta(g.bytes, elapsed)
	g.bytes = 0
	g.since = now
	g.recent = rate
	b.recordWindow(now, rate)
	if float64(rate) >= 0.9*float64(b.hint) && elapsed <= 2*window {
		g.clean++
		if g.clean >= 3 {
			if g.state != hintValidated {
				g.validations.Add(1)
				ms := b.sinceStartMS(now)
				g.lastValidatedMS.Store(ms)
				g.firstValidatedMS.CompareAndSwap(0, ms)
			}
			b.setHintState(hintValidated, now)
			g.until = now.Add(2 * window)
			return
		}
	} else {
		g.clean = 0
	}
	if g.state == hintValidated {
		// Inadequate delivery revokes even without an observable queue.
		b.revokeHint(now, reasonDelivery)
		return
	}
	if g.state == hintProbing {
		b.revokeHint(now, reasonProbeFail)
		return
	}
	if g.clean > 0 {
		return
	}
	// One short probe, at most 10% above observed delivery and never above the
	// hint. A failed probe enters a cooldown before more evidence is collected.
	if float64(rate) >= 0.75*float64(b.hint) {
		b.setHintState(hintProbing, now)
		g.probes.Add(1)
		g.firstProbeMS.CompareAndSwap(0, b.sinceStartMS(now))
		g.until = now.Add(window)
	} else {
		b.setHintState(hintUnvalidated, now)
	}
}

// recordWindow files one completed evaluation window into the band counters,
// the clean-streak tracker, and the bounded rate ring. The streak counts
// consecutive completed clean windows only: a revoke between windows resets the
// gate's own clean count but not this telemetry, which is exactly the
// distinction needed to separate "window never completed" from "window
// completed but rate insufficient".
func (b *Bbr3Sender) recordWindow(now time.Time, rate Bandwidth) {
	g := &b.gate
	class := "low"
	if float64(rate) >= 0.75*float64(b.hint) {
		class = "probe_band"
	}
	if float64(rate) >= 0.9*float64(b.hint) {
		class = "clean"
	}
	g.windowsTotal.Add(1)
	switch class {
	case "clean":
		g.windowsClean.Add(1)
	case "probe_band":
		g.windowsProbeBand.Add(1)
	default:
		g.windowsLow.Add(1)
	}
	if class == "clean" {
		g.cleanStreak++
		if uint64(g.cleanStreak) > g.maxCleanStreak.Load() {
			g.maxCleanStreak.Store(uint64(g.cleanStreak))
		}
	} else {
		g.cleanStreak = 0
	}
	g.pushWindowRate(WindowRate{TMS: b.sinceStartMS(now), RateBps: uint64(rate), Class: class})
}

func (b *Bbr3Sender) hintEstimate(est Bandwidth) Bandwidth {
	if !b.params.EnableValidatedHint || b.hint == 0 {
		return est
	}
	target := Bandwidth(0)
	switch b.gate.state {
	case hintValidated:
		target = b.hint
	case hintProbing:
		target = Bandwidth(float64(b.gate.recent) * 1.1)
		if target > b.hint {
			target = b.hint
		}
	}
	// Draining, RTT measurement, and congestion bounds always take priority.
	cur := mode(b.mode.Load())
	if cur == modeDrain || cur == modeProbeBWDown || cur == modeProbeRTT {
		return est
	}
	if target > est {
		lift := target - est
		b.gate.liftEvents.Add(1)
		for {
			old := Bandwidth(b.gate.liftMaxBps.Load())
			if lift <= old || b.gate.liftMaxBps.CompareAndSwap(uint64(old), uint64(lift)) {
				break
			}
		}
		return target
	}
	return est
}
