package tuic

import (
	"testing"
	"time"
)

// TestPushBackFullDoesNotBlock is a regression test: PushBack must drop rather
// than block when the queue is full, otherwise the single demultiplexing
// goroutine stalls (head-of-line blocking).
func TestPushBackFullDoesNotBlock(t *testing.T) {
	p := NewPackets()
	for i := 0; i < packetChanCap; i++ {
		p.PushBack(NewPacket(0, 0, 0, 0, 0, nil, nil, 0))
	}
	done := make(chan struct{})
	go func() {
		p.PushBack(NewPacket(0, 0, 0, 0, 0, nil, nil, 0))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PushBack blocked on full queue (head-of-line blocking)")
	}

	// The queue is still consumable (the drop did not disturb the entries
	// already in it).
	for i := 0; i < packetChanCap; i++ {
		pkt, closed := p.PopFrontBlock()
		if closed || pkt == nil {
			t.Fatalf("PopFrontBlock #%d: closed=%v pkt=%v", i, closed, pkt)
		}
	}
}
