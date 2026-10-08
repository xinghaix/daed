package bbr

import (
	"github.com/olicesx/quic-go/congestion"
)

// packetNumberIndexedQueue is a queue of mostly continuous numbered entries
// which supports the following operations:
// - adding elements to the end of the queue, or at some point past the end
// - removing elements in any order
// - retrieving elements
// If all elements are inserted in order, all of the operations above are
// amortized O(1) time.
//
// Internally, the data structure is a deque where each element is marked as
// present or not.  The deque starts at the lowest present index.  Whenever an
// element is removed, it's marked as not present, and the front of the deque is
// cleared of elements that are not present.
//
// The tail of the queue is not cleared due to the assumption of entries being
// inserted in order, though removing all elements of the queue will return it
// to its initial state.
//
// Note that this data structure is inherently hazardous, since an addition of
// just two entries will cause it to consume all of the memory available.
// Because of that, it is not a general-purpose container and should not be used
// as one.
//
// The hazard above is contained by maxSlots: a packet-number span wider than
// the budget is treated as a discontinuity and the queue restarts at the new
// packet number instead of materialising the hole. The budget is the caller's
// own bound on how many records can still be needed; see
// newPacketNumberIndexedQueue.

type entryWrapper[T any] struct {
	present bool
	entry   T
}

// shrinkDenominator is the occupancy divisor at which the backing array is
// halved. Together with doubling on growth it leaves a 4x hysteresis band, so
// the array can neither ratchet to the all-time high-water mark nor thrash
// between grow and shrink; the amortised cost stays O(1) per operation.
const shrinkDenominator = 4

type packetNumberIndexedQueue[T any] struct {
	entries                RingBuffer[entryWrapper[T]]
	numberOfPresentEntries int
	firstPacket            congestion.PacketNumber

	// maxSlots is the hard slot budget. It is a backstop for a caller that
	// stops trimming, not a policy: with the trim in place the live set never
	// approaches it.
	maxSlots int
	// initialSlots is the capacity the queue returns to when it drains. A
	// drained queue needs no slots at all, and an idle connection is the common
	// case for a relay.
	initialSlots int

	// truncatedSlots counts records discarded because the budget was reached.
	// Non-zero means the caller is not trimming and the estimator is running on
	// a truncated send history; it is exported for telemetry.
	truncatedSlots uint64
}

// newPacketNumberIndexedQueue builds a queue that starts at initialSize slots
// and refuses to hold more than maxSize.
func newPacketNumberIndexedQueue[T any](initialSize, maxSize int) *packetNumberIndexedQueue[T] {
	if initialSize < 1 {
		initialSize = 1
	}
	if maxSize < initialSize {
		maxSize = initialSize
	}
	q := &packetNumberIndexedQueue[T]{
		firstPacket:  invalidPacketNumber,
		maxSlots:     maxSize,
		initialSlots: initialSize,
	}

	q.entries.Init(initialSize)

	return q
}

// Emplace inserts data associated |packet_number| into (or past) the end of the
// queue, filling up the missing intermediate entries as necessary.  Returns
// true if the element has been inserted successfully, false if it was already
// in the queue or inserted out of order.
func (p *packetNumberIndexedQueue[T]) Emplace(packetNumber congestion.PacketNumber, entry *T) bool {
	if packetNumber == invalidPacketNumber || entry == nil {
		return false
	}

	if p.IsEmpty() {
		p.entries.PushBack(entryWrapper[T]{
			present: true,
			entry:   *entry,
		})
		p.numberOfPresentEntries = 1
		p.firstPacket = packetNumber
		return true
	}

	// Do not allow insertion out-of-order.
	if packetNumber <= p.LastPacket() {
		return false
	}

	// Handle potentially missing elements.
	offset := int(packetNumber - p.FirstPacket())
	gap := offset - p.entries.Len()
	if gap < 0 {
		gap = 0
	}

	if gap >= p.maxSlots {
		// A span wider than the whole budget is a discontinuity, not a hole: the
		// packet numbers it covers were either never sent or can no longer be
		// acked or lost, and materialising them is the "two entries consume all
		// the memory available" hazard this type documents. Restart at this
		// packet number instead of allocating the hole.
		p.restart(packetNumber)
		p.entries.PushBack(entryWrapper[T]{
			present: true,
			entry:   *entry,
		})
		p.numberOfPresentEntries = 1
		return true
	}

	if excess := p.entries.Len() + gap + 1 - p.maxSlots; excess > 0 {
		// The budget is reached, which means the caller has stopped trimming.
		// Keep the newest records — those are the ones an ack can still arrive
		// for — by dropping the oldest, exactly as a working trim would have.
		// Dropping from the front leaves the hole width unchanged, so gap stays
		// valid below.
		p.dropFront(excess)
	}

	for i := 0; i < gap; i++ {
		p.entries.PushBack(entryWrapper[T]{})
	}

	p.entries.PushBack(entryWrapper[T]{
		present: true,
		entry:   *entry,
	})
	p.numberOfPresentEntries++
	return true
}

// dropFront removes the n oldest slots, present or not, advancing firstPacket.
func (p *packetNumberIndexedQueue[T]) dropFront(n int) {
	for i := 0; i < n && !p.entries.Empty(); i++ {
		if p.entries.Front().present {
			p.numberOfPresentEntries--
		}
		p.entries.PopFront()
		p.firstPacket++
		p.truncatedSlots++
	}
}

// DropConsumedFront pops the front of the queue while it holds nothing that is
// still needed: absent slots hold no record at all, and a present slot is
// dropped only when isConsumed reports it. It stops at the first record that is
// still live, so a record for an outstanding packet always survives and its
// later ack or loss still finds it.
//
// This is not the budget backstop: what it drops has already been consumed, so
// it does not count as truncation. It is what lets the queue's size follow the
// outstanding window instead of its high-water mark.
func (p *packetNumberIndexedQueue[T]) DropConsumedFront(isConsumed func(*T) bool) (n int) {
	for !p.entries.Empty() {
		ew := p.entries.Front()
		if ew == nil {
			break
		}
		if ew.present {
			if !isConsumed(&ew.entry) {
				break
			}
			p.numberOfPresentEntries--
		}
		p.entries.PopFront()
		p.firstPacket++
		n++
	}
	if p.entries.Empty() {
		p.firstPacket = invalidPacketNumber
	}
	p.reclaim()
	return n
}

// restart drops every record and re-anchors the queue at packetNumber. The
// discarded records are counted so a missing trim shows up as telemetry instead
// of as an out-of-memory kill. The caller pushes the new entry and owns
// numberOfPresentEntries afterwards.
func (p *packetNumberIndexedQueue[T]) restart(packetNumber congestion.PacketNumber) {
	p.truncatedSlots += uint64(p.entries.Len())
	// Init, not Clear: a queue that reached the budget should hand the memory
	// back, and it will regrow only as far as the live window requires.
	p.entries.Init(p.initialSlots)
	p.numberOfPresentEntries = 0
	p.firstPacket = packetNumber
}

// GetEntry Retrieve the entry associated with the packet number.  Returns the pointer
// to the entry in case of success, or nullptr if the entry does not exist.
func (p *packetNumberIndexedQueue[T]) GetEntry(packetNumber congestion.PacketNumber) *T {
	ew := p.getEntryWraper(packetNumber)
	if ew == nil {
		return nil
	}

	return &ew.entry
}

// Remove, Same as above, but if an entry is present in the queue, also call f(entry)
// before removing it.
func (p *packetNumberIndexedQueue[T]) Remove(packetNumber congestion.PacketNumber, f func(T)) bool {
	ew := p.getEntryWraper(packetNumber)
	if ew == nil {
		return false
	}
	if f != nil {
		f(ew.entry)
	}
	ew.present = false
	p.numberOfPresentEntries--

	if packetNumber == p.FirstPacket() {
		p.clearup()
	}

	return true
}

// RemoveUpTo, but not including |packet_number|.
// Unused slots in the front are also removed, which means when the function
// returns, |first_packet()| can be larger than |packet_number|.
func (p *packetNumberIndexedQueue[T]) RemoveUpTo(packetNumber congestion.PacketNumber) {
	for !p.entries.Empty() &&
		p.firstPacket != invalidPacketNumber &&
		p.firstPacket < packetNumber {
		if p.entries.Front().present {
			p.numberOfPresentEntries--
		}
		p.entries.PopFront()
		p.firstPacket++
	}
	p.clearup()
}

// IsEmpty return if queue is empty.
func (p *packetNumberIndexedQueue[T]) IsEmpty() bool {
	return p.numberOfPresentEntries == 0
}

// NumberOfPresentEntries returns the number of entries in the queue.
func (p *packetNumberIndexedQueue[T]) NumberOfPresentEntries() int {
	return p.numberOfPresentEntries
}

// EntrySlotsUsed returns the number of entries allocated in the underlying deque.  This is
// proportional to the memory usage of the queue.
func (p *packetNumberIndexedQueue[T]) EntrySlotsUsed() int {
	return p.entries.Len()
}

// EntrySlotsCapacity returns the slot capacity of the underlying deque. This,
// not EntrySlotsUsed, is the queue's memory footprint.
func (p *packetNumberIndexedQueue[T]) EntrySlotsCapacity() int {
	return p.entries.Cap()
}

// Budget returns the hard slot budget, the cap the queue enforces on itself
// when a caller stops reclaiming.
func (p *packetNumberIndexedQueue[T]) Budget() int {
	return p.maxSlots
}

// TruncatedSlots returns how many records the slot budget has discarded over
// the queue's lifetime.
func (p *packetNumberIndexedQueue[T]) TruncatedSlots() uint64 {
	return p.truncatedSlots
}

// LastPacket returns packet number of the first entry in the queue.
func (p *packetNumberIndexedQueue[T]) FirstPacket() (packetNumber congestion.PacketNumber) {
	return p.firstPacket
}

// LastPacket returns packet number of the last entry ever inserted in the queue.  Note that the
// entry in question may have already been removed.  Zero if the queue is
// empty.
func (p *packetNumberIndexedQueue[T]) LastPacket() (packetNumber congestion.PacketNumber) {
	if p.IsEmpty() {
		return invalidPacketNumber
	}

	return p.firstPacket + congestion.PacketNumber(p.entries.Len()-1)
}

func (p *packetNumberIndexedQueue[T]) clearup() {
	for !p.entries.Empty() && !p.entries.Front().present {
		p.entries.PopFront()
		p.firstPacket++
	}
	if p.entries.Empty() {
		p.firstPacket = invalidPacketNumber
	}
	p.reclaim()
}

// reclaim returns capacity that the live set no longer needs. It runs at the
// end of every trim, so the common case must be a couple of comparisons: it
// reallocates only when occupancy falls below a quarter of the capacity, and a
// drained queue collapses all the way back to initialSlots. Without it a single
// burst pins the backing array at its peak for the connection's lifetime, which
// is how a transient 68 MiB ring became permanent.
func (p *packetNumberIndexedQueue[T]) reclaim() {
	live := p.entries.Len()
	capacity := p.entries.Cap()
	if capacity <= p.initialSlots {
		return
	}
	target := p.initialSlots
	if live > 0 {
		target = capacity
		for target > p.initialSlots && live*shrinkDenominator <= target {
			target /= 2
		}
		if target >= capacity {
			return
		}
	}
	p.entries.ShrinkTo(target)
}

func (p *packetNumberIndexedQueue[T]) getEntryWraper(packetNumber congestion.PacketNumber) *entryWrapper[T] {
	if packetNumber == invalidPacketNumber ||
		p.IsEmpty() ||
		packetNumber < p.firstPacket {
		return nil
	}

	offset := int(packetNumber - p.firstPacket)
	if offset >= p.entries.Len() {
		return nil
	}

	ew := p.entries.Offset(offset)
	if ew == nil || !ew.present {
		return nil
	}

	return ew
}
