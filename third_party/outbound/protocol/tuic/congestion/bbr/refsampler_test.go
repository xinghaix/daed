package bbr

import (
	"testing"
	"time"

	"github.com/olicesx/quic-go/congestion"
)

// TestRefSamplerReclaimsSendRecords is the regression guard for the leak this
// change fixes. Before it, a consumer of the adapter (bbr3) never called
// RemoveObsoletePackets, so the connection-state map retained one 136-byte
// record per retransmittable send for the life of the connection: 128,000
// records here, and 524,288 (71.3 MiB, 85.7% of the live heap) in the field on
// a single hysteria2 connection.
func TestRefSamplerReclaimsSendRecords(t *testing.T) {
	const (
		window = 64
		rounds = 2000
	)
	s := NewRefSampler(10)
	now := time.Now()
	var pn congestion.PacketNumber
	for round := 0; round < rounds; round++ {
		acked := make([]congestion.AckedPacketInfo, 0, window)
		for i := 0; i < window; i++ {
			pn++
			s.OnPacketSent(now, pn, 1200, window*1200, true)
			acked = append(acked, congestion.AckedPacketInfo{PacketNumber: pn, BytesAcked: 1200})
			now = now.Add(time.Millisecond)
		}
		s.OnCongestionEvent(now, acked, nil, uint64(round))
	}
	if got := s.EntrySlotsUsed(); got > window {
		t.Fatalf("send records retained = %d after %d sends; want the in-flight window only (<= %d)", got, pn, window)
	}
	if got := s.TruncatedRecords(); got != 0 {
		t.Fatalf("the budget backstop fired %d times with the trim in place", got)
	}
}

// TestRefSamplerTrimKeepsDeliveredAccounting is the correctness half of the
// trim. onPacketAcknowledged skips the delivered-byte accounting when a send
// record is missing, so a trim that reaches past the reorder margin would
// silently under-count delivery and depress the bandwidth estimate.
func TestRefSamplerTrimKeepsDeliveredAccounting(t *testing.T) {
	const packets = 100
	s := NewRefSampler(10)
	now := time.Now()
	for pn := congestion.PacketNumber(1); pn <= packets; pn++ {
		s.OnPacketSent(now, pn, 1200, packets*1200, true)
	}

	// Ack everything except packet 98. The largest ack is 100, so the trim
	// point is 98: packet 98's record is inside the two-packet margin and must
	// survive, while everything below it must be gone.
	first := make([]congestion.AckedPacketInfo, 0, packets-1)
	for pn := congestion.PacketNumber(1); pn <= packets; pn++ {
		if pn != 98 {
			first = append(first, congestion.AckedPacketInfo{PacketNumber: pn, BytesAcked: 1200})
		}
	}
	s.OnCongestionEvent(now, first, nil, 1)

	if got := s.sampler.connectionStateMap.GetEntry(98); got == nil {
		t.Fatal("packet inside the reorder margin was trimmed: its ack can no longer be accounted")
	}
	if got := s.sampler.connectionStateMap.GetEntry(97); got != nil {
		t.Fatal("packet below the trim point was retained")
	}

	// The late ack of 98 must still count its bytes.
	s.OnCongestionEvent(now, []congestion.AckedPacketInfo{{PacketNumber: 98, BytesAcked: 1200}}, nil, 1)
	if got, want := s.TotalBytesAcked(), congestion.ByteCount(packets*1200); got != want {
		t.Fatalf("TotalBytesAcked() = %d, want %d (an over-aggressive trim under-counts delivery)", got, want)
	}
}

// TestRefSamplerReclaimsOnlyConsumedRecords pins both halves of the reclamation
// rule: a record whose packet has been acked or lost gives its slot back, and a
// record whose packet is still outstanding is never passed over even when the
// records ahead of it are gone.
func TestRefSamplerReclaimsOnlyConsumedRecords(t *testing.T) {
	const packets = 10
	s := NewRefSampler(10)
	now := time.Now()
	for pn := congestion.PacketNumber(1); pn <= packets; pn++ {
		s.OnPacketSent(now, pn, 1200, packets*1200, true)
	}
	acked := make([]congestion.AckedPacketInfo, 0, 8)
	for pn := congestion.PacketNumber(1); pn <= 8; pn++ {
		acked = append(acked, congestion.AckedPacketInfo{PacketNumber: pn, BytesAcked: 1200})
	}
	s.OnCongestionEvent(now, acked, nil, 1)

	if got := s.sampler.connectionStateMap.GetEntry(8); got != nil {
		t.Fatal("a consumed record was retained")
	}
	for _, pn := range []congestion.PacketNumber{9, 10} {
		if got := s.sampler.connectionStateMap.GetEntry(pn); got == nil {
			t.Fatalf("record for outstanding packet %d was dropped", pn)
		}
	}

	// The outstanding records must still be usable, or their acks go unaccounted.
	s.OnCongestionEvent(now, []congestion.AckedPacketInfo{
		{PacketNumber: 9, BytesAcked: 1200},
		{PacketNumber: 10, BytesAcked: 1200},
	}, nil, 1)
	if got, want := s.TotalBytesAcked(), congestion.ByteCount(packets*1200); got != want {
		t.Fatalf("TotalBytesAcked() = %d, want %d", got, want)
	}
}

// TestRefSamplerKeepsRecordsBehindALiveFront pins the prefix semantics: a
// consumed record behind a still-live front record is not passed over, because
// the map can only give back a prefix. That is why the budget below exists as
// the backstop for a connection whose oldest record never gets consumed.
func TestRefSamplerKeepsRecordsBehindALiveFront(t *testing.T) {
	s := NewRefSampler(10)
	now := time.Now()
	for pn := congestion.PacketNumber(1); pn <= 50; pn++ {
		s.OnPacketSent(now, pn, 1200, 50*1200, true)
	}
	// Only packet 20 is declared lost; 1..19 are still unconsumed.
	s.OnCongestionEvent(now, nil, []congestion.LostPacketInfo{{PacketNumber: 20, BytesLost: 1200}}, 1)

	if got := s.sampler.connectionStateMap.GetEntry(1); got == nil {
		t.Fatal("the live front record was dropped")
	}
	if got := s.sampler.connectionStateMap.GetEntry(20); got == nil {
		t.Fatal("a consumed record behind a live front was dropped; only a prefix may be reclaimed")
	}
	if got := s.EntrySlotsUsed(); got == 0 {
		t.Fatal("the map reclaimed records it could not prove were consumed")
	}
}

// TestRefSamplerReleasesCapacityWhenTheWindowDrains pins the "no longer needed
// is not occupied" half: a 20,000-record burst leaves a multi-megabyte backing
// array that must collapse once the window drains, instead of being pinned at
// its peak for the connection's lifetime.
func TestRefSamplerReleasesCapacityWhenTheWindowDrains(t *testing.T) {
	const burst = 20_000
	s := NewRefSampler(10)
	now := time.Now()
	acked := make([]congestion.AckedPacketInfo, 0, burst)
	for pn := 1; pn <= burst; pn++ {
		s.OnPacketSent(now, congestion.PacketNumber(pn), 1200, burst*1200, true)
		acked = append(acked, congestion.AckedPacketInfo{PacketNumber: congestion.PacketNumber(pn), BytesAcked: 1200})
	}
	peak := s.EntrySlotsCapacity()
	if peak < burst {
		t.Fatalf("capacity %d did not grow to hold a %d-record burst", peak, burst)
	}

	s.OnCongestionEvent(now, acked, nil, 1)
	if got := s.EntrySlotsUsed(); got > 4 {
		t.Fatalf("send records retained = %d after the window drained, want <= 4", got)
	}
	if got := s.EntrySlotsCapacity(); got != initialConnectionStateMapSlots {
		t.Fatalf("capacity = %d after the window drained, want %d (peak was %d)",
			got, initialConnectionStateMapSlots, peak)
	}
}

// TestRefSamplerSurvivesAPacketNumberJump covers the discontinuity guard at the
// adapter level: a span no ackhandler can be tracking must not be materialised.
func TestRefSamplerSurvivesAPacketNumberJump(t *testing.T) {
	s := NewRefSampler(10)
	now := time.Now()
	s.OnPacketSent(now, 1, 1200, 1200, true)
	s.OnPacketSent(now, congestion.PacketNumber(maxConnectionStateMapSlots)*10, 1200, 1200, true)
	if got := s.EntrySlotsCapacity(); got > maxConnectionStateMapSlots {
		t.Fatalf("capacity = %d, want <= the protocol budget %d", got, maxConnectionStateMapSlots)
	}
	if got := s.EntrySlotsUsed(); got > 4 {
		t.Fatalf("send records retained = %d after a discontinuity, want <= 4", got)
	}
}

// TestCandidateRingIsAllocatedOnDemand: the A0-candidate ring only participates
// while overestimate avoidance is enabled, so it must not reserve 8 KiB in
// every sampler that never turns it on.
func TestCandidateRingIsAllocatedOnDemand(t *testing.T) {
	s := NewRefSampler(10)
	if got := s.sampler.a0Candidates.Cap(); got != 0 {
		t.Fatalf("a0Candidates capacity = %d before overestimate avoidance is enabled, want 0", got)
	}
	s.sampler.EnableOverestimateAvoidance()
	if got := s.sampler.a0Candidates.Cap(); got != defaultCandidatesBufferSize {
		t.Fatalf("a0Candidates capacity = %d after enabling, want %d", got, defaultCandidatesBufferSize)
	}
}
