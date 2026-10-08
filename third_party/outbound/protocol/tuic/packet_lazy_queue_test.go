package tuic

import (
	"runtime"
	"testing"
	"time"
)

// TestPacketsQueueIsLazilyAllocated is the P2-10 quantification: a UDP
// association that never queues a packet must not pay for the 2048-slot
// packet channel. Before the fix NewPackets allocated the channel eagerly,
// which is ~18.5 KB per association (≈36 MB at 2000 concurrent UDP flows).
func TestPacketsQueueIsLazilyAllocated(t *testing.T) {
	const n = 512

	// Warm up so the measurement does not include the first-call runtime
	// bookkeeping.
	for i := 0; i < 16; i++ {
		_ = NewPackets()
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	all := make([]*Packets, 0, n)
	for i := 0; i < n; i++ {
		all = append(all, NewPackets())
	}
	runtime.ReadMemStats(&after)
	if len(all) != n {
		t.Fatalf("kept %d Packets, want %d", len(all), n)
	}

	perPackets := int64(after.TotalAlloc-before.TotalAlloc) / n
	// The eager channel is ~18.5 KB; the lazily-allocated struct is a few
	// dozen bytes. Anything above 256 B/op means the queue came back.
	const budget = 256
	if perPackets > budget {
		t.Fatalf("NewPackets allocates %d B/op, want <= %d: the 2048-slot queue is no longer lazy",
			perPackets, budget)
	}

	// The queue must still exist once it is actually used: the lazy path may
	// not trade memory for a dropped packet.
	p := all[0]
	for i := 0; i < packetChanCap; i++ {
		p.PushBack(NewPacket(0, 0, 0, 0, 0, nil, nil, 0))
	}
	full, noReceiver := p.DroppedPackets()
	if full != 0 || noReceiver != 0 {
		t.Fatalf("dropped=%d/%d before the queue was full, want 0/0", full, noReceiver)
	}
	for i := 0; i < packetChanCap; i++ {
		pkt, closed := p.PopFrontBlock()
		if closed || pkt == nil {
			t.Fatalf("PopFrontBlock #%d: closed=%v pkt=%v", i, closed, pkt)
		}
	}
}

// TestPacketsDroppedCountsQueueFull pins the P2-10 loss counter: dropping on
// a full queue is silent by design (it must not block the shared demux
// goroutine), so the counter is the only way a caller can observe it.
func TestPacketsDroppedCountsQueueFull(t *testing.T) {
	p := NewPackets()
	for i := 0; i < packetChanCap; i++ {
		p.PushBack(NewPacket(0, 0, 0, 0, 0, nil, nil, 0))
	}
	if full, noReceiver := p.DroppedPackets(); full != 0 || noReceiver != 0 {
		t.Fatalf("dropped=%d/%d while filling the queue, want 0/0", full, noReceiver)
	}

	const overflow = 7
	for i := 0; i < overflow; i++ {
		p.PushBack(NewPacket(0, 0, 0, 0, 0, nil, nil, 0))
	}
	full, noReceiver := p.DroppedPackets()
	if full != overflow {
		t.Fatalf("DroppedPackets() full=%d, want %d", full, overflow)
	}
	if noReceiver != 0 {
		t.Fatalf("DroppedPackets() noReceiver=%d, want 0", noReceiver)
	}

	// Draining frees capacity; the counter must not double-count.
	for i := 0; i < packetChanCap; i++ {
		if _, closed := p.PopFrontBlock(); closed {
			t.Fatalf("queue closed early at %d", i)
		}
	}
	if full, _ := p.DroppedPackets(); full != overflow {
		t.Fatalf("DroppedPackets() full=%d after draining, want %d", full, overflow)
	}
}

// TestPacketsDroppedCountsNoReceiver pins the second loss path: a push that
// finds a deactivated receiver is discarded, and that is counted too.
func TestPacketsDroppedCountsNoReceiver(t *testing.T) {
	p := NewPackets()
	unregister, ok := p.registerPacketHandler(func(*Packet) bool { return true })
	if !ok {
		t.Fatal("registerPacketHandler refused the first registration")
	}
	unregister()
	// The receiver slot is cleared by unregister, so this push queues instead.
	// Deactivate without retiring the slot to exercise the drop branch.
	p.mu.Lock()
	p.receiver = &packetHandlerRegistration{handler: func(*Packet) bool { return true }}
	p.receiver.active.Store(false)
	p.mu.Unlock()

	p.PushBack(NewPacket(0, 0, 0, 0, 0, nil, nil, 0))
	full, noReceiver := p.DroppedPackets()
	if full != 0 || noReceiver != 1 {
		t.Fatalf("DroppedPackets() = %d/%d, want 0/1", full, noReceiver)
	}
}

// TestPacketsCloseWithoutQueueIsSafe pins the lazy-allocation edge case: a
// Packets whose queue was never allocated must still accept Close and keep
// refusing pushes. The closed flag, not the channel, carries the state — a nil
// channel would otherwise block PopFrontBlock forever.
func TestPacketsCloseWithoutQueueIsSafe(t *testing.T) {
	p := NewPackets()
	if err := p.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	p.PushBack(NewPacket(0, 0, 0, 0, 0, nil, nil, 0))

	done := make(chan struct{})
	go func() {
		if _, closed := p.PopFrontBlock(); !closed {
			t.Error("PopFrontBlock() on a closed, never-allocated queue must report closed")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PopFrontBlock blocked on a closed, never-allocated queue")
	}

	// A second Close is a no-op, and a later push is still refused.
	if err := p.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if full, _ := p.DroppedPackets(); full != 0 {
		t.Fatalf("DroppedPackets() full=%d, want 0: a closed queue is not a full queue", full)
	}
}
