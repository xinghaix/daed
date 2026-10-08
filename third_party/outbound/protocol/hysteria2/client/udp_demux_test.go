package client

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

// chanUDPIO feeds datagrams from a channel and reports a fatal transport
// error when closed, mirroring the real udpIOImpl contract.
type chanUDPIO struct {
	msgs chan *protocol.UDPMessage
	dead chan struct{}
}

func (io *chanUDPIO) ReceiveMessage() (*protocol.UDPMessage, error) {
	select {
	case msg := <-io.msgs:
		return msg, nil
	case <-io.dead:
		return nil, errors.New("transport closed")
	}
}

func (io *chanUDPIO) SendMessage([]byte, *protocol.UDPMessage) error { return nil }

// TestUDPSessionManagerDemuxPreservesPerSessionOrder is the ordering
// counterpart of the parallel-demux test above: datagrams of one session
// must be delivered to the receiver in arrival order. Reordered delivery
// makes the inner protocol (QUIC/H3, games) see spurious loss: cwnd
// collapse and periodic throughput dips. The per-message payload carries a
// per-session sequence number; the receiver records the delivery order and
// the test asserts it is strictly increasing for every session.
func TestUDPSessionManagerDemuxPreservesPerSessionOrder(t *testing.T) {
	const numSessions = 4
	const msgsPerSession = 2000

	io := &chanUDPIO{
		msgs: make(chan *protocol.UDPMessage, 256),
		dead: make(chan struct{}),
	}
	m := newUDPSessionManager(io)

	conns := make([]*udpConn, numSessions)
	var mu sync.Mutex
	delivered := make([][]int, numSessions)
	for i := range numSessions {
		c, err := m.NewUDP("192.0.2.1:443")
		if err != nil {
			t.Fatalf("NewUDP #%d: %v", i, err)
		}
		uc := c.(*udpConn)
		conns[i] = uc
		idx := i
		_, ok := uc.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
			j := int(packet.Data[1]) | int(packet.Data[2])<<8
			mu.Lock()
			delivered[idx] = append(delivered[idx], j)
			mu.Unlock()
			packet.Release()
			return true
		})
		if !ok {
			t.Fatalf("RegisterPacketReceiver #%d failed", i)
		}
	}

	// Concurrent senders interleaving sessions, mirroring a saturated
	// multi-session tunnel where demux goroutines race.
	var wg sync.WaitGroup
	wg.Add(numSessions)
	for i := range numSessions {
		go func(idx int) {
			defer wg.Done()
			for j := range msgsPerSession {
				io.msgs <- &protocol.UDPMessage{
					SessionID: conns[idx].ID,
					PacketID:  0,
					FragID:    0,
					FragCount: 1,
					Addr:      []byte("192.0.2.1:443"),
					Data:      []byte{byte(idx), byte(j), byte(j >> 8)},
				}
			}
		}(i)
	}
	wg.Wait()

	deadline := time.Now().Add(20 * time.Second)
	for {
		mu.Lock()
		done := true
		for i := range numSessions {
			if len(delivered[i]) != msgsPerSession {
				done = false
				break
			}
		}
		mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			for i := range numSessions {
				t.Logf("session %d received %d/%d", i, len(delivered[i]), msgsPerSession)
			}
			t.Fatal("messages were not fully delivered")
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	for i, seq := range delivered {
		if len(seq) != msgsPerSession {
			t.Fatalf("session %d: delivered %d, want %d", i, len(seq), msgsPerSession)
		}
		for pos, j := range seq {
			if j != pos {
				t.Fatalf("session %d: delivery %d carries sequence %d (out of order); first inversion in the first %d deliveries", i, pos, j, pos)
			}
		}
	}

	close(io.dead)
	select {
	case <-m.done:
	case <-time.After(5 * time.Second):
		t.Fatal("manager done channel was not closed")
	}
}

// TestUDPSessionManagerParallelDemux is a regression test: when several run()
// goroutines consume datagrams concurrently, every session still receives all
// of its messages, and only its own.
func TestUDPSessionManagerParallelDemux(t *testing.T) {
	const numSessions = 4
	const msgsPerSession = 500

	io := &chanUDPIO{
		msgs: make(chan *protocol.UDPMessage, 64),
		dead: make(chan struct{}),
	}
	m := newUDPSessionManager(io)

	conns := make([]*udpConn, numSessions)
	var counts [numSessions]atomic.Int32
	for i := range numSessions {
		c, err := m.NewUDP("192.0.2.1:443")
		if err != nil {
			t.Fatalf("NewUDP #%d: %v", i, err)
		}
		uc := c.(*udpConn)
		conns[i] = uc
		idx := i
		_, ok := uc.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
			counts[idx].Add(1)
			packet.Release()
			return true
		})
		if !ok {
			t.Fatalf("RegisterPacketReceiver #%d failed", i)
		}
	}

	// Interleave messages from all sessions so concurrent run() goroutines
	// must demux them in parallel.
	var wg sync.WaitGroup
	wg.Add(numSessions)
	for i := range numSessions {
		go func(idx int) {
			defer wg.Done()
			for j := range msgsPerSession {
				io.msgs <- &protocol.UDPMessage{
					SessionID: conns[idx].ID,
					PacketID:  0,
					FragID:    0,
					FragCount: 1,
					Addr:      []byte("192.0.2.1:443"),
					Data:      []byte{byte(idx), byte(j)},
				}
			}
		}(i)
	}
	wg.Wait()

	deadline := time.Now().Add(10 * time.Second)
	for {
		done := true
		for i := range numSessions {
			if counts[i].Load() != msgsPerSession {
				done = false
				break
			}
		}
		if done {
			break
		}
		if time.Now().After(deadline) {
			for i := range numSessions {
				t.Logf("session %d received %d/%d", i, counts[i].Load(), msgsPerSession)
			}
			t.Fatal("messages were not fully delivered")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Fatal transport error: every run() goroutine exits; closeCleanup must
	// run exactly once (sync.Once) without panicking on close(m.done).
	close(io.dead)
	select {
	case <-m.done:
	case <-time.After(5 * time.Second):
		t.Fatal("manager done channel was not closed")
	}
	m.mutex.RLock()
	closed := m.closed
	m.mutex.RUnlock()
	if !closed {
		t.Fatal("manager not marked closed after transport death")
	}
	for i, c := range conns {
		if _, ok := <-c.ReceiveCh; ok {
			t.Fatalf("session %d ReceiveCh still open after cleanup", i)
		}
	}
}

func TestUDPSessionManagerCloseUnblocksFullWorkerQueue(t *testing.T) {
	io := &chanUDPIO{
		// Unbuffered: a send returns only after routeDemux has taken the
		// datagram, so the extra message below is the one blocked on a
		// full worker queue rather than sitting in the IO channel.
		msgs: make(chan *protocol.UDPMessage),
		dead: make(chan struct{}),
	}
	m := newUDPSessionManager(io)
	connRaw, err := m.NewUDP("192.0.2.8:443")
	if err != nil {
		t.Fatalf("NewUDP: %v", err)
	}
	u := connRaw.(*udpConn)

	hold := make(chan struct{})
	entered := make(chan struct{})
	_, ok := u.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-hold
		packet.Release()
		return true
	})
	if !ok {
		t.Fatal("expected packet receiver registration")
	}

	io.msgs <- &protocol.UDPMessage{SessionID: u.ID, FragCount: 1, Addr: []byte("192.0.2.8:443"), Data: []byte{0}}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not take the first datagram")
	}
	for i := 0; i < demuxWorkerQueueLen; i++ {
		select {
		case io.msgs <- &protocol.UDPMessage{SessionID: u.ID, FragCount: 1, Addr: []byte("192.0.2.8:443"), Data: []byte{byte(i + 1)}}:
		case <-time.After(2 * time.Second):
			t.Fatal("could not fill the worker queue")
		}
	}

	var released atomic.Int32
	parked := &protocol.UDPMessage{
		SessionID: u.ID,
		FragCount: 1,
		Addr:      []byte("192.0.2.8:443"),
		Data:      []byte{255},
		Release:   func() { released.Add(1) },
	}
	parkedSent := make(chan struct{})
	go func() {
		io.msgs <- parked
		close(parkedSent)
	}()
	time.Sleep(20 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		m.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked on a full worker queue")
	}
	select {
	case <-parkedSent:
	case <-time.After(2 * time.Second):
		t.Fatal("router stayed blocked on the parked datagram")
	}
	close(hold)

	deadline := time.Now().Add(2 * time.Second)
	for released.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("parked datagram Release calls = %d, want 1", released.Load())
		}
		time.Sleep(time.Millisecond)
	}
}
