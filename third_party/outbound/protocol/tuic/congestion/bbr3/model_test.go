package bbr3

import (
	"testing"
	"time"

	"github.com/olicesx/quic-go/congestion"
)

func TestUpdateRoundAdvancesOnlyOnNewerPacket(t *testing.T) {
	m := newModel(DefaultParams(), 1200)
	m.lastSent = 10
	if !m.updateRound(1) {
		t.Fatal("first ack must start a round")
	}
	m.lastSent = 20
	if m.updateRound(5) {
		t.Fatal("ack for an older packet must not start a round")
	}
	if !m.updateRound(11) {
		t.Fatal("ack past the round boundary must start a round")
	}
	if m.round != 2 {
		t.Fatalf("round = %d, want 2", m.round)
	}
}

func TestAccountEventSnapshotsThenResets(t *testing.T) {
	m := newModel(DefaultParams(), 1200)
	m.lastSent = 5
	m.roundBytesSent = 100_000
	m.accountEvent(90_000, 10_000, 9, 6) // triggers a round start

	if m.lastRoundSent != 100_000 || m.lastRoundLost != 10_000 || m.lastRoundAcked != 90_000 {
		t.Fatalf("snapshot = sent %d lost %d acked %d", m.lastRoundSent, m.lastRoundLost, m.lastRoundAcked)
	}
	if m.roundBytesSent != 0 || m.roundBytesLost != 0 || m.roundBytesAcked != 0 || m.roundLostPackets != 0 {
		t.Fatalf("round counters not reset: %d %d %d %d",
			m.roundBytesSent, m.roundBytesLost, m.roundBytesAcked, m.roundLostPackets)
	}
}

func TestLossBaselineRaisesThresholdOnLossyPath(t *testing.T) {
	m := newModel(DefaultParams(), 1200)
	m.minRtt = 80 * time.Millisecond
	m.minRttStamp = time.Now()

	// Five rounds of 5% independent loss.
	for i := 0; i < 5; i++ {
		m.lastSent += 100
		m.roundBytesSent = 100_000
		m.accountEvent(95_000, 5_000, 42, m.lastSent)
		// The sender classifies the completed round before updating its baseline.
		m.updateLossBaseline()
	}
	if !m.lossBaselineSet {
		t.Fatal("baseline never set")
	}
	if m.lossBaseline < 0.04 || m.lossBaseline > 0.06 {
		t.Fatalf("baseline = %v, want near 0.05", m.lossBaseline)
	}
	// 5% is the baseline, so it must not count as overshoot.
	m.roundBytesSent = 100_000
	m.roundBytesLost = 5_000
	m.roundLostPackets = 42
	if m.lossRateExceeded() {
		t.Fatalf("baseline loss counted as overshoot (threshold %v)", m.lossThresholdNow())
	}
}

func TestLossBaselineDisabledByConservativePreset(t *testing.T) {
	m := newModel(ConservativeParams(), 1200)
	m.lastRoundSent = 100_000
	m.lastRoundLost = 50_000
	m.updateLossBaseline()
	if m.lossBaselineSet {
		t.Fatal("conservative preset must not track a baseline")
	}
	if got := m.lossThresholdNow(); got != ConservativeParams().LossThreshold {
		t.Fatalf("threshold = %v, want the fixed %v", got, ConservativeParams().LossThreshold)
	}
}

func TestLossRateNeedsVolumeAndPacketFloor(t *testing.T) {
	m := newModel(DefaultParams(), 1200)

	// High loss rate but a tiny round: below the volume floor.
	m.roundBytesSent = 1200
	m.roundBytesLost = 1200
	m.roundLostPackets = 100
	if m.lossRateExceeded() {
		t.Fatal("tiny round must not count as overshoot")
	}

	// Enough volume but too few lost packets: a handshake hiccup.
	m.roundBytesSent = 100_000
	m.roundBytesLost = 10_000
	m.roundLostPackets = 1
	if m.lossRateExceeded() {
		t.Fatal("single lost packet must not count as overshoot")
	}

	m.roundLostPackets = 100
	if !m.lossRateExceeded() {
		t.Fatal("10% loss over a full round must count as overshoot")
	}
}

func TestCapInflightHiUsesSentVolumeWithBdpFloor(t *testing.T) {
	m := newModel(DefaultParams(), 1200)
	m.minRtt = 80 * time.Millisecond
	seedEstimate(m, 1_000_000) // 1 MB/s
	m.lastRoundSent = 500_000
	m.inflightHi = 10_000_000
	m.capInflightHi()
	if m.inflightHi != 500_000 {
		t.Fatalf("inflightHi = %d, want the sent volume 500000", m.inflightHi)
	}

	// A round that sent less than one BDP must not drop the bound below the
	// pipe the estimate already demonstrated.
	m.lastRoundSent = 1000
	m.inflightHi = 10_000_000
	m.capInflightHi()
	if m.inflightHi != m.bdp() {
		t.Fatalf("inflightHi = %d, want bdp %d", m.inflightHi, m.bdp())
	}
}

func TestAdaptLowerBoundsNeverFallsBelowStandingBdp(t *testing.T) {
	m := newModel(DefaultParams(), 1200)
	m.minRtt = 80 * time.Millisecond
	seedEstimate(m, 1_000_000)
	m.adaptLowerBounds()
	if m.inflightLo != m.bdp() {
		t.Fatalf("inflightLo = %d, want bdp %d", m.inflightLo, m.bdp())
	}
	// Repeated loss events must not spiral the bound down.
	for i := 0; i < 20; i++ {
		m.adaptLowerBounds()
	}
	if m.inflightLo != m.bdp() {
		t.Fatalf("inflightLo spiralled to %d, want bdp %d", m.inflightLo, m.bdp())
	}
}

func TestCheckFullBwReached(t *testing.T) {
	m := newModel(DefaultParams(), 1200)
	seedEstimate(m, 1_000_000)
	m.checkFullBwReached() // establishes the baseline
	if m.fullBwReached {
		t.Fatal("full bandwidth reached on the first sample")
	}
	for i := 0; i < DefaultParams().FullBwRounds; i++ {
		m.checkFullBwReached()
	}
	if !m.fullBwReached {
		t.Fatal("full bandwidth not reached after the flat rounds")
	}
}

func TestProbeUpGrowsInflightHiAndCapsOnOvershoot(t *testing.T) {
	m := newModel(DefaultParams(), 1200)
	m.minRtt = 80 * time.Millisecond
	seedEstimate(m, 1_000_000)
	m.inflightHi = 100_000

	m.probeUpRound(true, 0, 100_000)
	if m.inflightHi <= 100_000 {
		t.Fatalf("inflightHi = %d, want growth", m.inflightHi)
	}
	grown := m.inflightHi

	// An overshooting round turns the cycle down and caps the bound at what was
	// actually put on the path that round.
	m.roundBytesSent = 90_000
	m.roundBytesLost = 45_000
	m.roundLostPackets = 100
	if !m.probeUpRound(false, 45_000, 100_000) {
		t.Fatal("overshoot must report a turn down")
	}
	if m.inflightHi >= grown {
		t.Fatalf("inflightHi = %d, want it capped below %d", m.inflightHi, grown)
	}
}

func TestProbeRttTargetUsesHalfInflightHi(t *testing.T) {
	m := newModel(DefaultParams(), 1200)
	m.inflightHi = 1_000_000
	if got, want := m.probeRttTarget(), congestion.ByteCount(500_000); got != want {
		t.Fatalf("probeRttTarget = %d, want %d", got, want)
	}
	m.inflightHi = 1200
	if got := m.probeRttTarget(); got != m.minCwnd {
		t.Fatalf("probeRttTarget = %d, want minCwnd %d", got, m.minCwnd)
	}
}

func TestProbeRttWindowIsNotFourPackets(t *testing.T) {
	// The v1 regression this fixes: a connection with a large probed upper bound
	// must keep a probe window far above four packets.
	m := newModel(DefaultParams(), 1200)
	m.inflightHi = 4_000_000
	if got := m.probeRttTarget(); got <= 4*1200 {
		t.Fatalf("probeRttTarget = %d, want well above four packets", got)
	}
}

func TestUpdateMinRttExpires(t *testing.T) {
	m := newModel(DefaultParams(), 1200)
	now := time.Now()
	if m.updateMinRtt(now, 80*time.Millisecond) {
		t.Fatal("first sample must not report expiry")
	}
	if m.minRtt != 80*time.Millisecond {
		t.Fatalf("minRtt = %v", m.minRtt)
	}
	later := now.Add(DefaultParams().MinRttFilterLen + time.Second)
	if !m.updateMinRtt(later, 90*time.Millisecond) {
		t.Fatal("filter expiry must be reported")
	}
	if m.minRtt != 90*time.Millisecond {
		t.Fatalf("minRtt after expiry = %v, want 90ms", m.minRtt)
	}
	if m.updateMinRtt(later, 0) {
		t.Fatal("a missing sample must not report expiry")
	}
}
