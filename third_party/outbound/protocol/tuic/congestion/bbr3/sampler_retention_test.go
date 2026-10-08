package bbr3

import (
	"testing"
	"time"
)

// packetSize matches the payload drive() sends.
const packetSize = 1200

// TestSenderDoesNotRetainSendRecords is the end-to-end guard for the send-record
// leak, driven through the production sender rather than the sampler directly.
//
// bbr3 replaced its local sampler with the shared reference estimator
// (bbr.RefSampler) but never called RemoveObsoletePackets, so the estimator's
// connection-state map retained one 136-byte record per retransmittable send for
// the life of the connection. In the field that was 524,288 records (71.3 MiB,
// 85.7% of the live heap) on a single hysteria2 connection, growing for as long
// as the connection kept sending.
//
// The retained set must be bounded by the in-flight window — at most the two
// rounds drive() keeps outstanding — not by the number of packets ever sent. The
// bound is derived from the sender's own congestion window so it cannot go stale
// if that window changes.
func TestSenderDoesNotRetainSendRecords(t *testing.T) {
	const rounds = 200
	s := newTestSender(0)
	now := time.Now()
	_ = drive(s, now, rounds, 80*time.Millisecond)

	pending := int(s.GetCongestionWindow()/packetSize) + 2 // one drive() round
	bound := 4 * pending                                   // two rounds outstanding, plus margin
	retained := s.model.ref.EntrySlotsUsed()
	t.Logf("retained=%d capacity=%d cwnd=%d oneRound=%d truncated=%d",
		retained, s.model.ref.EntrySlotsCapacity(), s.GetCongestionWindow(), pending,
		s.model.ref.TruncatedRecords())

	if retained > bound {
		t.Fatalf("send records retained = %d after %d rounds; want the in-flight window only (<= %d)",
			retained, rounds, bound)
	}
	if got := s.model.ref.TruncatedRecords(); got != 0 {
		t.Fatalf("the map's budget backstop fired %d times with the trim in place", got)
	}
	if got := s.model.ref.EntrySlotsCapacity(); got > bound {
		t.Fatalf("send-record capacity = %d, want <= %d", got, bound)
	}

	// The telemetry accessor must report what the map actually holds.
	capacity := s.model.ref.EntrySlotsCapacity()
	statRetained, statCapacity, statTruncated := s.SendRecordStats()
	if statRetained != retained || statCapacity != capacity || statTruncated != 0 {
		t.Fatalf("SendRecordStats() = (%d, %d, %d), want (%d, %d, 0)",
			statRetained, statCapacity, statTruncated, retained, capacity)
	}
}
