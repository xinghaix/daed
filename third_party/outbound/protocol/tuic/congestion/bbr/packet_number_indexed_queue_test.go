package bbr

import (
	"testing"

	"github.com/olicesx/quic-go/congestion"
)

func intEntry(n int) *int { return &n }

// TestQueueRestartsOnAnUntrackablePacketNumberJump covers the hazard the queue
// documents about itself ("an addition of just two entries will cause it to
// consume all of the memory available"): a packet-number span wider than the
// budget is a discontinuity, not a hole, and must not be materialised.
func TestQueueRestartsOnAnUntrackablePacketNumberJump(t *testing.T) {
	const maxSlots = 1024
	q := newPacketNumberIndexedQueue[int](64, maxSlots)
	if !q.Emplace(1, intEntry(1)) {
		t.Fatal("first Emplace rejected")
	}
	if !q.Emplace(1_000_000, intEntry(7)) {
		t.Fatal("Emplace after the jump rejected")
	}
	if got := q.EntrySlotsUsed(); got > maxSlots {
		t.Fatalf("slots used = %d, want <= %d", got, maxSlots)
	}
	if got := q.TruncatedSlots(); got == 0 {
		t.Fatal("discarded records were not counted")
	}
	if got := q.GetEntry(1_000_000); got == nil || *got != 7 {
		t.Fatalf("GetEntry(1_000_000) = %v, want 7", got)
	}
	if q.GetEntry(1) != nil {
		t.Fatal("records below the discontinuity survived the restart")
	}
}

// TestQueueBudgetBoundsRunawayGrowth is the backstop: a caller that never trims
// must degrade the estimator's history, not the process.
func TestQueueBudgetBoundsRunawayGrowth(t *testing.T) {
	const maxSlots = 1024
	q := newPacketNumberIndexedQueue[int](64, maxSlots)
	for pn := congestion.PacketNumber(1); pn <= 100_000; pn++ {
		q.Emplace(pn, intEntry(int(pn)))
		if got := q.EntrySlotsUsed(); got > maxSlots {
			t.Fatalf("slots grew past the budget: %d > %d at packet %d", got, maxSlots, pn)
		}
	}
	if q.TruncatedSlots() == 0 {
		t.Fatal("expected the budget to discard records once it was reached")
	}
	if got := q.GetEntry(100_000); got == nil || *got != 100_000 {
		t.Fatalf("GetEntry(100_000) = %v, want 100_000", got)
	}
}

// TestQueueReclaimsCapacityWhenTheWindowDrains pins the memory half: capacity
// follows the live window down, and a drained queue hands everything back.
func TestQueueReclaimsCapacityWhenTheWindowDrains(t *testing.T) {
	const burst = 200_000
	q := newPacketNumberIndexedQueue[int](64, 1<<20)
	for pn := congestion.PacketNumber(1); pn <= burst; pn++ {
		q.Emplace(pn, intEntry(int(pn)))
	}
	peak := q.EntrySlotsCapacity()
	if peak < burst {
		t.Fatalf("capacity %d did not grow to hold a %d-record burst", peak, burst)
	}

	// Leave the newest 100 records in place.
	q.RemoveUpTo(burst - 99)
	if got := q.EntrySlotsUsed(); got > 200 {
		t.Fatalf("live slots = %d after the drain, want <= 200", got)
	}
	drained := q.EntrySlotsCapacity()
	if drained >= peak {
		t.Fatalf("capacity stayed at %d after draining to %d live records", peak, q.EntrySlotsUsed())
	}
	// The shrink copies the live records, so they must survive intact and in
	// order.
	for pn := congestion.PacketNumber(burst - 99); pn <= burst; pn++ {
		got := q.GetEntry(pn)
		if got == nil || *got != int(pn) {
			t.Fatalf("GetEntry(%d) = %v after shrink, want %d", pn, got, pn)
		}
	}
	if got := q.FirstPacket(); got != burst-99 {
		t.Fatalf("firstPacket = %d, want %d", got, burst-99)
	}

	q.RemoveUpTo(burst + 1)
	if got := q.EntrySlotsUsed(); got != 0 {
		t.Fatalf("live slots = %d after a full drain, want 0", got)
	}
	if got := q.EntrySlotsCapacity(); got != 64 {
		t.Fatalf("capacity = %d after a full drain, want the initial 64", got)
	}
}

func TestRingBufferShrinkToPreservesOrder(t *testing.T) {
	var r RingBuffer[int]
	r.Init(32)
	for i := 1; i <= 30; i++ {
		r.PushBack(i)
	}
	for i := 0; i < 27; i++ {
		r.PopFront()
	}
	// Wrap the tail: live records are now 28..33 with headPos+n past the end.
	for i := 31; i <= 33; i++ {
		r.PushBack(i)
	}
	if got := r.Len(); got != 6 {
		t.Fatalf("Len() = %d, want 6", got)
	}

	r.ShrinkTo(8)
	if got := r.Cap(); got != 8 {
		t.Fatalf("Cap() = %d after ShrinkTo(8), want 8", got)
	}
	for i := 0; i < 6; i++ {
		if got := *r.Offset(i); got != 28+i {
			t.Fatalf("Offset(%d) = %d, want %d", i, got, 28+i)
		}
	}

	// Refill to exactly full, then one more to force a grow: order must hold
	// across the wrap the shrink left behind.
	for i := 34; i <= 35; i++ {
		r.PushBack(i)
	}
	if got := r.Len(); got != 8 {
		t.Fatalf("Len() = %d after refilling, want 8", got)
	}
	r.PushBack(36)
	if got := r.Len(); got != 9 {
		t.Fatalf("Len() = %d after the grow, want 9", got)
	}
	for i := 0; i < 9; i++ {
		if got := *r.Offset(i); got != 28+i {
			t.Fatalf("Offset(%d) = %d after grow, want %d", i, got, 28+i)
		}
	}
}
