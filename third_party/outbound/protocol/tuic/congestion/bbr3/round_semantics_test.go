package bbr3

import (
	"testing"
	"time"

	"github.com/olicesx/quic-go/congestion"
)

// The round counter is a *packet-timed* round: it advances when an ack carries a
// packet number greater than the send head recorded at the previous round start,
// which is exactly an ack for a packet sent after that sentinel. Every round
// consumer - the STARTUP full-bandwidth test, the PROBE_BW cycle, the PROBE_RTT
// exit and the bandwidth filter's window - inherits its meaning from this rule,
// so the rule is pinned here rather than inferred from throughput.
//
// Semantics source: draft-cardwell-iccrg-bbr-congestion-control-02, section
// 4.5.1 ("BBR counts packet-timed round trips by recording state about a
// sentinel packet, and waiting for an ACK of any data packet that was sent after
// that sentinel packet"; BBRUpdateRound/BBRStartRound), and the equivalent
// packet-number form in this tree at
// protocol/tuic/congestion/bbr/bbr_sender.go:605-613, which stores the send head
// as the round boundary and advances on an ack above it.
//
// The three consequences these tests pin:
//   - acks of one window advance the round at most once, so a burst of acks is
//     not a burst of rounds;
//   - a round cannot advance until the sender has put a new packet on the wire
//     after the boundary, so a round can never be shorter than that packet's
//     RTT: rounds are timed by packet exchange, not by ack events;
//   - a loss-only event carries no ack, and quic-go only declares lost the
//     packets at or below the largest acked packet number, so the loss path
//     cannot cross a boundary either.

// roundDriver drives the sender through the congestion-control interface the way
// quic-go's sentPacketHandler does (bytesInFlight includes the packet being sent
// and is read before the acked bytes are removed - see the convention comment on
// Bbr3Sender.OnPacketSent), with explicit packet numbers so a test can name the
// exact ack that is expected to start a round.
type roundDriver struct {
	s     *Bbr3Sender
	now   time.Time
	next  congestion.PacketNumber
	inFly congestion.ByteCount
	step  time.Duration
}

func newRoundDriver() *roundDriver {
	return &roundDriver{
		s:    newTestSender(0),
		now:  time.Unix(1_700_000_000, 0),
		step: 80 * time.Millisecond,
	}
}

// send queues n fresh packets, advancing the send head.
func (d *roundDriver) send(n int) {
	for i := 0; i < n; i++ {
		d.next++
		d.inFly += 1200
		d.s.OnPacketSent(d.now, d.inFly, d.next, 1200, true)
	}
}

// head is the highest packet number sent so far.
func (d *roundDriver) head() congestion.PacketNumber { return d.next }

// ack acknowledges the given packet numbers, then advances the clock by one RTT
// step so the sampler sees a positive packet age.
func (d *roundDriver) ack(pns ...congestion.PacketNumber) {
	acked := make([]congestion.AckedPacketInfo, 0, len(pns))
	for _, pn := range pns {
		acked = append(acked, congestion.AckedPacketInfo{PacketNumber: pn, BytesAcked: 1200})
	}
	prior := d.inFly
	d.inFly -= congestion.ByteCount(1200 * len(pns))
	d.s.OnCongestionEventEx(prior, d.now, acked, nil)
	d.now = d.now.Add(d.step)
}

// lose declares the given packet numbers lost in a loss-only event.
func (d *roundDriver) lose(pns ...congestion.PacketNumber) {
	lost := make([]congestion.LostPacketInfo, 0, len(pns))
	for _, pn := range pns {
		lost = append(lost, congestion.LostPacketInfo{PacketNumber: pn, BytesLost: 1200})
	}
	prior := d.inFly
	d.inFly -= congestion.ByteCount(1200 * len(pns))
	d.s.OnCongestionEventEx(prior, d.now, nil, lost)
	d.now = d.now.Add(d.step)
}

func (d *roundDriver) rounds() uint64 { return d.s.model.round }

// TestRoundBoundaryIsTheSendHeadAtRoundStart pins the sentinel itself: the first
// ack starts a round whose boundary is the current send head, an ack at or below
// that boundary is not a new round, and only a packet sent after it can start
// the next one.
func TestRoundBoundaryIsTheSendHeadAtRoundStart(t *testing.T) {
	d := newRoundDriver()
	d.send(40)

	d.ack(1) // first ack ever: starts round 1
	if d.rounds() != 1 {
		t.Fatalf("round = %d after the first ack, want 1", d.rounds())
	}
	if got := d.s.model.roundEnd; got != 40 {
		t.Fatalf("round boundary = %d, want the send head 40", got)
	}

	// An ack for the boundary packet itself, and any older ack, are inside the
	// round: the sentinel has to be *passed*, not reached.
	d.ack(40)
	d.ack(25)
	if d.rounds() != 1 {
		t.Fatalf("round = %d after acks at or below the boundary, want 1", d.rounds())
	}

	// The next round needs a packet the sender had not yet put on the wire when
	// the boundary was recorded.
	d.send(1)
	d.ack(d.head())
	if d.rounds() != 2 {
		t.Fatalf("round = %d after acknowledging a post-boundary send, want 2", d.rounds())
	}
	if got := d.s.model.roundEnd; got != d.head() {
		t.Fatalf("round boundary = %d, want the new send head %d", got, d.head())
	}
}

// TestAckBurstAdvancesOneRoundNotOnePerAck is the direct regression test for
// event-timed rounds: a whole window acknowledged packet by packet, after the
// window has already been sent, is one round.
func TestAckBurstAdvancesOneRoundNotOnePerAck(t *testing.T) {
	d := newRoundDriver()
	d.send(100)
	for pn := congestion.PacketNumber(1); pn <= 100; pn++ {
		d.ack(pn)
	}
	if d.rounds() != 1 {
		t.Fatalf("round = %d after 100 acks of one sent window, want 1", d.rounds())
	}
}

// TestPipelinedWindowsAdvanceOneRoundEach checks the rule on a pipeline: one
// round start per window that is sent after the previous boundary.
func TestPipelinedWindowsAdvanceOneRoundEach(t *testing.T) {
	const windows = 10
	d := newRoundDriver()
	for w := 0; w < windows; w++ {
		first := d.head() + 1
		d.send(10)
		for pn := first; pn <= d.head(); pn++ {
			d.ack(pn)
		}
	}
	if d.rounds() != windows {
		t.Fatalf("round = %d after %d sent-and-acked windows, want %d", d.rounds(), windows, windows)
	}
}

// TestLossOnlyEventCannotAdvanceARound pins the loss path. quic-go reports a
// loss-only event (no acked packets) when its loss timer fires, and it only
// declares lost the packets at or below the largest acked packet number, which
// the previous test's invariant keeps at or below the round boundary. The loss
// path therefore carries no packet number that can cross the boundary.
func TestLossOnlyEventCannotAdvanceARound(t *testing.T) {
	d := newRoundDriver()
	d.send(50)
	d.ack(50) // round 1, boundary = 50
	if d.rounds() != 1 {
		t.Fatalf("round = %d, want 1", d.rounds())
	}
	d.lose(25, 26, 27)
	if d.rounds() != 1 {
		t.Fatalf("round = %d after a loss-only event inside the round, want 1", d.rounds())
	}
	if got := d.s.model.roundEnd; got != 50 {
		t.Fatalf("round boundary = %d after a loss-only event, want 50", got)
	}
}

// TestRoundBoundaryNeverLagsTheLargestAck pins the invariant the loss argument
// rests on: after every ack event the boundary is at or above the largest entity
// acknowledged so far, so a later loss declaration - which quic-go bounds by
// that largest acked packet number - can never pass the boundary.
func TestRoundBoundaryNeverLagsTheLargestAck(t *testing.T) {
	d := newRoundDriver()
	var largest congestion.PacketNumber
	for w := 0; w < 8; w++ {
		first := d.head() + 1
		d.send(7)
		for pn := first; pn <= first+2; pn++ {
			d.ack(pn)
			largest = pn
			if d.s.model.roundEnd < largest {
				t.Fatalf("round boundary = %d lags the largest ack %d in window %d",
					d.s.model.roundEnd, largest, w)
			}
		}
	}
}

// TestFullBandwidthTestCountsRoundsNotAckEvents pins the STARTUP exit at the
// sender level: earning a full-bandwidth round requires a round start, so
// acknowledging one window packet by packet (many events, one round) cannot
// satisfy any part of FullBwRounds.
func TestFullBandwidthTestCountsRoundsNotAckEvents(t *testing.T) {
	d := newRoundDriver()
	d.send(100)
	for pn := congestion.PacketNumber(1); pn <= 100; pn++ {
		d.ack(pn)
	}
	if d.rounds() != 1 {
		t.Fatalf("round = %d, want 1", d.rounds())
	}
	if got := d.s.model.fullBwRounds; got != 0 {
		t.Fatalf("fullBwRounds = %d after one packet-timed round, want 0: the STARTUP exit test is per round, not per ack event", got)
	}
	if !d.s.model.fullBwReached == false {
		t.Fatal("STARTUP latched full bandwidth inside a single round")
	}
}
