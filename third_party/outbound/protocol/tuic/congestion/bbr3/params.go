package bbr3

import (
	"fmt"
	"math"
	"time"
)

// Params holds the tunable parameters of the sender. Zero values are not valid;
// always start from a preset and adjust.
type Params struct {
	// Window sizing, in packets.
	InitialCwndPackets int
	MinCwndPackets     int

	// Pacing and congestion-window gains. The pacer runs at the mode's pacing
	// gain times the estimate, so Cruise is the steady-state multiplier and must
	// stay at 1: on a bottlenecked path (4 MB/s shaper, 256 KB queue, 40 ms
	// one-way) cruising at 1x held ~90% utilisation with a 60.9 ms p95 and ~70
	// drops, while pacing at CwndGain (the reference's bandwidthForPacer
	// convention) over-drove the same bottleneck to ~1130 drops and 63.8 ms at
	// LOWER goodput. Pacing above the estimate buys nothing on a real bottleneck;
	// it only fills the queue.
	HighGain     float64
	DrainGain    float64
	CwndGain     float64
	UpGain       float64
	DownGain     float64
	CruiseGain   float64
	ProbeRttGain float64

	// STARTUP exit: bandwidth must grow by FullBwThreshold for FullBwRounds
	// consecutive rounds.
	FullBwThreshold float64
	FullBwRounds    int

	// Loss response.
	LossThreshold      float64
	MinLossPackets     int
	MinLossSentPackets int
	Beta               float64
	ProbeUpGrowth      float64
	ProbeUpRounds      int
	EnableLossBaseline bool
	LossBaselineWeight float64
	LossBaselineFactor float64
	// CorrectSampleForLoss is retained for source compatibility but rejected.
	// ACK/loss event ratios do not identify loss location or carried capacity.
	CorrectSampleForLoss bool
	MaxLossCorrection    float64

	// PROBE_RTT.
	ProbeRttFraction float64
	ProbeRttDuration time.Duration

	// HintProbeOvershoot bounds how far a PROBE_UP may exceed the access hint.
	// The hint is the steady-state ceiling; a probe that could never exceed it
	// would pin the estimate below the hint when the hint equals path capacity.
	HintProbeOvershoot float64
	// EnableValidatedHint opts into the experimental delivery/queue-gated target.
	EnableValidatedHint bool
	// StrictHintCap forbids pacing above the hint, including probes.
	StrictHintCap bool

	// Estimator windows.
	MinRttFilterLen time.Duration
	DefaultMinRtt   time.Duration
	MinPacingRate   Bandwidth
	// MaxBwFilterRounds is the delivery-rate estimate's window, in packet-timed
	// rounds, handed to the shared reference estimator (bbr.RefSampler). The
	// reference sender sizes it as one gain cycle plus two rounds
	// (bbr_sender.go: bandwidthWindowSize = gainCycleLength + 2). The window must
	// span at least a full PROBE_BW probe cycle because the estimate is the
	// windowed MAXIMUM: a shorter window forgets the probe's peak before the next
	// probe refreshes it, and every dip then ratchets the estimate down for good.
	MaxBwFilterRounds uint64
}

// DefaultParams returns the experimental preset. It does not enable hint
// targeting and is not evidence of BBRv3 conformance or performance.
func DefaultParams() Params {
	return Params{
		InitialCwndPackets: 10,
		MinCwndPackets:     4,

		HighGain:     2.77,
		DrainGain:    1.0 / 2.77,
		CwndGain:     2.0,
		UpGain:       1.25,
		DownGain:     0.75,
		CruiseGain:   1.0,
		ProbeRttGain: 1.0,

		FullBwThreshold: 1.25,
		FullBwRounds:    3,

		LossThreshold:        0.02,
		MinLossPackets:       8,
		MinLossSentPackets:   10,
		Beta:                 0.7,
		ProbeUpGrowth:        0.25,
		ProbeUpRounds:        1,
		EnableLossBaseline:   true,
		LossBaselineWeight:   0.25,
		LossBaselineFactor:   4.0,
		CorrectSampleForLoss: false,
		MaxLossCorrection:    0.25,

		ProbeRttFraction:   0.5,
		ProbeRttDuration:   200 * time.Millisecond,
		HintProbeOvershoot: 1.25,

		MinRttFilterLen:   10 * time.Second,
		DefaultMinRtt:     100 * time.Millisecond,
		MinPacingRate:     Bandwidth(65536),
		MaxBwFilterRounds: 10,
	}
}

// Validate rejects unsafe or undefined tuning values before constructing a sender.
func (p Params) Validate() error {
	for name, v := range map[string]float64{"HighGain": p.HighGain, "DrainGain": p.DrainGain, "CwndGain": p.CwndGain, "UpGain": p.UpGain, "DownGain": p.DownGain, "CruiseGain": p.CruiseGain, "ProbeRttGain": p.ProbeRttGain, "FullBwThreshold": p.FullBwThreshold, "LossThreshold": p.LossThreshold, "Beta": p.Beta, "ProbeUpGrowth": p.ProbeUpGrowth, "LossBaselineWeight": p.LossBaselineWeight, "LossBaselineFactor": p.LossBaselineFactor, "MaxLossCorrection": p.MaxLossCorrection, "ProbeRttFraction": p.ProbeRttFraction, "HintProbeOvershoot": p.HintProbeOvershoot} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 || v > 100 {
			return fmt.Errorf("bbr3: invalid %s", name)
		}
	}
	if p.MinCwndPackets < 2 || p.InitialCwndPackets < p.MinCwndPackets || p.InitialCwndPackets > 10000 || p.FullBwRounds < 1 || p.FullBwRounds > 10000 || p.MinLossPackets < 1 || p.MinLossPackets > 1<<20 || p.MinLossSentPackets < 1 || p.MinLossSentPackets > 1<<20 || p.ProbeUpRounds < 1 || p.ProbeUpRounds > 16 || p.MaxBwFilterRounds == 0 || p.MaxBwFilterRounds > 10000 {
		return fmt.Errorf("bbr3: invalid packet or round limits")
	}
	if p.HighGain <= 1 || p.DrainGain >= 1 || p.CwndGain < 1 || p.UpGain <= 1 || p.DownGain >= 1 || p.CruiseGain <= 0 || p.FullBwThreshold <= 1 || p.LossThreshold >= 1 || p.Beta >= 1 || p.LossBaselineWeight > 1 || p.LossBaselineFactor < 1 || p.MaxLossCorrection >= 1 || p.ProbeRttFraction >= 1 || p.HintProbeOvershoot < 1 || p.HintProbeOvershoot > 1.25 || p.ProbeUpGrowth > 1 {
		return fmt.Errorf("bbr3: invalid gains or fractions")
	}
	if p.MinRttFilterLen <= 0 || p.DefaultMinRtt <= 0 || p.ProbeRttDuration <= 0 || p.DefaultMinRtt > time.Minute || p.MinRttFilterLen > time.Hour || p.ProbeRttDuration > time.Minute || p.MinPacingRate == 0 || p.MinPacingRate > 1<<40 {
		return fmt.Errorf("bbr3: invalid timing or pacing limits")
	}
	if p.CorrectSampleForLoss {
		return fmt.Errorf("bbr3: loss correction is unsupported: loss location cannot be inferred from ACK events")
	}
	return nil
}

// ConservativeParams disables the experimental adaptive loss threshold.
// It does not imply conformance to a reference congestion controller.
func ConservativeParams() Params {
	p := DefaultParams()
	p.EnableLossBaseline = false
	return p
}
