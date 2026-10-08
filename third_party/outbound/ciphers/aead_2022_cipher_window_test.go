package ciphers

import (
	"math/rand/v2"
	"testing"
)

// referenceWindow is a deliberately naive model of the sliding-window replay
// filter: one bool per distance from the latest accepted packet ID. It is slow
// and allocation-heavy on purpose so the optimized in-place implementation can
// be differentially compared against it.
type referenceWindow struct {
	seen        []bool
	latest      uint64
	initialized bool
}

func newReferenceWindow(windowSize int) *referenceWindow {
	return &referenceWindow{seen: make([]bool, windowSize)}
}

func (r *referenceWindow) CheckAndUpdate(packetID uint64) bool {
	if !r.initialized {
		r.initialized = true
		r.latest = packetID
		r.seen[0] = true
		return true
	}
	if packetID > r.latest {
		shift := packetID - r.latest
		if shift >= uint64(len(r.seen)) {
			for i := range r.seen {
				r.seen[i] = false
			}
		} else {
			for i := len(r.seen) - 1; int(shift) <= i; i-- {
				r.seen[i] = r.seen[i-int(shift)]
			}
			for i := uint64(0); i < shift; i++ {
				r.seen[i] = false
			}
		}
		r.latest = packetID
		r.seen[0] = true
		return true
	}
	distance := r.latest - packetID
	if distance >= uint64(len(r.seen)) {
		return false
	}
	if r.seen[distance] {
		return false
	}
	r.seen[distance] = true
	return true
}

// TestSlidingWindowFilter_ShiftIsTowardHigherDistances pins the single-word
// (bitShift > 0, wordShift == 0) direction of shiftWindow: after the newest
// packet ID advances, a recorded bit for distance d must move to distance
// d+shift. The pre-fix code shifted the opposite way, which both re-admitted
// already-seen IDs (replay leak) and rejected never-seen IDs (false reject).
func TestSlidingWindowFilter_ShiftIsTowardHigherDistances(t *testing.T) {
	f := NewSlidingWindowFilter(64)

	// 0 and 1 are only 1 apart, so the shift is a pure bit shift (wordShift=0).
	if !f.CheckAndUpdate(1000) {
		t.Fatalf("first packet must pass")
	}
	if !f.CheckAndUpdate(1001) {
		t.Fatalf("1014-forward packet must pass")
	}
	// Distance 1 held packet 1000. After the shift it must be distance 2.
	if f.CheckAndUpdate(1001) {
		t.Fatalf("replay of packet 1001 must be rejected")
	}
	if f.CheckAndUpdate(1000) {
		t.Fatalf("replay of packet 1000 must be rejected")
	}
	// 999 was never seen and is still inside the window.
	if !f.CheckAndUpdate(999) {
		t.Fatalf("never-seen packet 999 must pass")
	}
	if f.CheckAndUpdate(999) {
		t.Fatalf("replay of packet 999 must be rejected")
	}
}

// TestSlidingWindowFilter_CrossWordShiftIsTowardHigherDistances is the
// cross-word variant (wordShift > 0 and bitShift > 0) of the same contract.
func TestSlidingWindowFilter_CrossWordShiftIsTowardHigherDistances(t *testing.T) {
	f := NewSlidingWindowFilter(128)

	if !f.CheckAndUpdate(100) {
		t.Fatalf("first packet must pass")
	}
	// shift = 70: wordShift=1, bitShift=6. Bit 0 must land at distance 70,
	// i.e. bit 6 of word 1 - the pre-fix code moved it to bit 58 of word 0.
	if !f.CheckAndUpdate(170) {
		t.Fatalf("packet 170 must pass")
	}
	if f.CheckAndUpdate(100) {
		t.Fatalf("replay of packet 100 must be rejected after a cross-word shift")
	}
	// 106 sits at distance 64 - the word boundary the pre-fix code corrupted.
	if !f.CheckAndUpdate(106) {
		t.Fatalf("never-seen packet 106 must pass")
	}
	if f.CheckAndUpdate(106) {
		t.Fatalf("replay of packet 106 must be rejected")
	}
}

// TestSlidingWindowFilter_MinimalRepro is the smallest deterministic
// reproduction of the reported defect: after a purely ordered stream, replaying
// latest-1 must be rejected. latest-1 is exactly the distance that the pre-fix
// shift direction pushed out of the recorded region.
func TestSlidingWindowFilter_MinimalRepro(t *testing.T) {
	for _, windowSize := range []int{64, 128, 1024} {
		f := NewSlidingWindowFilter(windowSize)
		if !f.CheckAndUpdate(100) {
			t.Fatalf("window=%d: packet 100 must pass", windowSize)
		}
		seq := uint64(101)
		if !f.CheckAndUpdate(seq) {
			t.Fatalf("window=%d: packet %d must pass", windowSize, seq)
		}
		if f.CheckAndUpdate(seq - 1) {
			t.Fatalf("window=%d: replay of latest-1 (%d) must be rejected", windowSize, seq-1)
		}
	}
}

// TestSlidingWindowFilter_OrderedStreamRejectsEveryReplay replays every packet
// of an ordered stream immediately after that stream was accepted.
func TestSlidingWindowFilter_OrderedStreamRejectsEveryReplay(t *testing.T) {
	const windowSize = 128
	f := NewSlidingWindowFilter(windowSize)
	start := uint64(1) << 40 // exercise multi-word shifts
	for i := uint64(0); i < windowSize; i++ {
		if !f.CheckAndUpdate(start + i) {
			t.Fatalf("ordered packet %d must pass", start+i)
		}
	}
	for i := uint64(0); i < windowSize; i++ {
		if f.CheckAndUpdate(start + i) {
			t.Fatalf("replay of packet %d must be rejected", start+i)
		}
	}
}

// TestSlidingWindowFilter_MatchesReferenceModel differentially fuzzes the
// in-place implementation against referenceWindow. The bug is only visible in
// the middle of the window (the pre-existing tests only covered "just inserted"
// and "shift >= windowSize clears everything"), so the operation mix
// deliberately stays near the window edge instead of jumping far ahead.
func TestSlidingWindowFilter_MatchesReferenceModel(t *testing.T) {
	for _, windowSize := range []int{64, 1024} {
		for _, seed := range []uint64{1, 2, 3, 4} {
			rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
			f := NewSlidingWindowFilter(windowSize)
			ref := newReferenceWindow(windowSize)

			latest := uint64(1 << 40)
			id := latest
			for op := 0; op < 200_000; op++ {
				switch rng.IntN(4) {
				case 0:
					id = latest + uint64(rng.IntN(3))
				case 1:
					id = latest - uint64(rng.IntN(windowSize))
				case 2:
					id = latest + uint64(rng.IntN(windowSize))
				default:
					id += uint64(rng.IntN(2))
				}
				if id > latest {
					latest = id
				}

				got := f.CheckAndUpdate(id)
				want := ref.CheckAndUpdate(id)
				if got != want {
					t.Fatalf("window=%d seed=%d op=%d id=%d: got %v want %v (latest=%d)",
						windowSize, seed, op, id, got, want, latest)
				}
			}
		}
	}
}

// TestSlidingWindowFilter_MatchesReferenceOnExactReplayStream checks that a
// strictly ordered stream followed by the same stream in reverse (every packet
// already seen) is rejected in full.
func TestSlidingWindowFilter_MatchesReferenceOnExactReplayStream(t *testing.T) {
	const windowSize = 512
	f := NewSlidingWindowFilter(windowSize)
	ref := newReferenceWindow(windowSize)
	start := uint64(7_000_000)
	for i := 0; i < windowSize; i++ {
		id := start + uint64(i)
		if f.CheckAndUpdate(id) != ref.CheckAndUpdate(id) {
			t.Fatalf("forward pass diverged at %d", id)
		}
	}
	for i := windowSize - 1; i >= 0; i-- {
		id := start + uint64(i)
		got, want := f.CheckAndUpdate(id), ref.CheckAndUpdate(id)
		if got != want {
			t.Fatalf("reverse pass diverged at %d: got %v want %v", id, got, want)
		}
		if got {
			t.Fatalf("replayed packet %d was accepted", id)
		}
	}
}
