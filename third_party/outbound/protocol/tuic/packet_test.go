package tuic

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

func countDeFraggers(q *quicStreamPacketConn) int {
	count := 0
	q.deFraggers.Range(func(_, value any) bool {
		count += value.(*deFraggerBucket).len()
		return true
	})
	return count
}

func TestReadFromNoDeadlock(t *testing.T) {
	packets := NewPackets()
	q := &quicStreamPacketConn{
		incomingPackets: packets,
	}

	var wg sync.WaitGroup
	wg.Add(2)

	readDone := make(chan struct{})
	go func() {
		defer wg.Done()
		defer close(readDone)
		_, _, _ = q.ReadFrom(make([]byte, 1024))
	}()

	time.Sleep(100 * time.Millisecond)

	go func() {
		defer wg.Done()
		_ = packets.Close()
	}()

	select {
	case <-readDone:
		t.Log("ReadFrom unblocked successfully - no deadlock")
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom deadlocked - Close() could not unblock it")
	}

	wg.Wait()
}

func TestReadFromReturnsNilAfterClose(t *testing.T) {
	packets := NewPackets()
	q := &quicStreamPacketConn{
		incomingPackets: packets,
	}

	_ = packets.Close()

	_, _, err := q.ReadFrom(make([]byte, 1024))
	if err == nil {
		t.Error("expected error after close, got nil")
	}
}

func TestPacketsCloseUnblocksPopFrontBlock(t *testing.T) {
	p := NewPackets()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = p.PopFrontBlock()
	}()

	time.Sleep(50 * time.Millisecond)
	_ = p.Close()

	select {
	case <-done:
		t.Log("PopFrontBlock unblocked after Close")
	case <-time.After(1 * time.Second):
		t.Fatal("PopFrontBlock did not unblock after Close")
	}
}

func TestPacketsPushPop(t *testing.T) {
	p := NewPackets()

	go func() {
		time.Sleep(50 * time.Millisecond)
		p.PushBack(&Packet{
			PKT_ID:     1,
			FRAG_ID:    0,
			FRAG_TOTAL: 1,
			DATA:       []byte("test data"),
			ADDR:       &Address{TYPE: AtypIPv4, ADDR: []byte{127, 0, 0, 1}, PORT: 8080},
		})
	}()

	packet, closed := p.PopFrontBlock()
	if closed {
		t.Fatal("expected packet, got closed")
	}
	if packet == nil {
		t.Fatal("expected non-nil packet")
	}
	if string(packet.DATA) != "test data" {
		t.Errorf("expected 'test data', got '%s'", packet.DATA)
	}
	_ = p.Close()
}

func TestQuicStreamPacketConnPacketReceiverDeliversQueuedDatagram(t *testing.T) {
	packets := NewPackets()
	packets.PushBack(&Packet{
		FRAG_TOTAL: 1,
		DATA:       []byte("queued payload"),
		ADDR:       &Address{TYPE: AtypIPv4, ADDR: []byte{192, 0, 2, 7}, PORT: 5353},
	})
	q := &quicStreamPacketConn{incomingPackets: packets}
	delivered := make(chan *netproxy.ReceivedPacket, 1)
	unregister, ok := q.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
		delivered <- packet
		return true
	})
	if !ok || unregister == nil {
		t.Fatal("expected packet receiver registration")
	}
	defer unregister()

	select {
	case packet := <-delivered:
		if string(packet.Data) != "queued payload" {
			t.Fatalf("packet data = %q, want queued payload", packet.Data)
		}
		if packet.From != netip.MustParseAddrPort("192.0.2.7:5353") {
			t.Fatalf("packet address = %v", packet.From)
		}
		packet.Release()
	case <-time.After(time.Second):
		t.Fatal("packet receiver did not drain queued datagram")
	}
	_ = q.Close()
}

func TestQuicStreamPacketConnPacketReceiverAssemblesFragments(t *testing.T) {
	packets := NewPackets()
	q := &quicStreamPacketConn{incomingPackets: packets}
	delivered := make(chan *netproxy.ReceivedPacket, 1)
	unregister, ok := q.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
		delivered <- packet
		return true
	})
	if !ok {
		t.Fatal("expected packet receiver registration")
	}
	defer unregister()

	addr := &Address{TYPE: AtypIPv4, ADDR: []byte{198, 51, 100, 9}, PORT: 443}
	packets.PushBack(&Packet{PKT_ID: 42, FRAG_TOTAL: 2, FRAG_ID: 0, ADDR: addr, DATA: []byte("frag-")})
	packets.PushBack(&Packet{PKT_ID: 42, FRAG_TOTAL: 2, FRAG_ID: 1, ADDR: &Address{TYPE: AtypNone}, DATA: []byte("mented")})

	select {
	case packet := <-delivered:
		if string(packet.Data) != "frag-mented" {
			t.Fatalf("assembled data = %q, want frag-mented", packet.Data)
		}
		if packet.From != netip.MustParseAddrPort("198.51.100.9:443") {
			t.Fatalf("assembled address = %v", packet.From)
		}
		packet.Release()
	case <-time.After(time.Second):
		t.Fatal("packet receiver did not assemble fragments")
	}
	_ = q.Close()
}

func TestDefraggerAllocatesFromActualFragmentSum(t *testing.T) {
	addr := &Address{TYPE: AtypIPv4, ADDR: []byte{198, 51, 100, 9}, PORT: 443}
	payloadA := bytes.Repeat([]byte{'a'}, 1400)
	payloadB := bytes.Repeat([]byte{'b'}, 53)
	bucket := &deFraggerBucket{}

	_, _, assembled, size := bucket.feed(&Packet{PKT_ID: 1, FRAG_TOTAL: 2, FRAG_ID: 0, ADDR: addr, SIZE: uint16(len(payloadA)), DATA: payloadA}, nil, time.Now().UnixNano())
	if assembled || size != 0 {
		t.Fatalf("first fragment assembled=%v size=%d", assembled, size)
	}
	_, _, assembled, size = bucket.feed(&Packet{PKT_ID: 1, FRAG_TOTAL: 2, FRAG_ID: 1, ADDR: &Address{TYPE: AtypNone}, SIZE: uint16(len(payloadB)), DATA: payloadB}, nil, time.Now().UnixNano())
	if assembled || size != len(payloadA)+len(payloadB) {
		t.Fatalf("complete set assembled=%v size=%d, want %d", assembled, size, len(payloadA)+len(payloadB))
	}
	buffer := pool.GetFullCap(size)
	defer buffer.Put()
	n, _, assembled, _ := bucket.feed(nil, buffer, time.Now().UnixNano())
	if !assembled || n != size {
		t.Fatalf("assembled=%v n=%d, want %d", assembled, n, size)
	}
	if !bytes.Equal(buffer[:n], append(payloadA, payloadB...)) {
		t.Fatal("assembled payload mismatch")
	}
}

func TestPacketHandlerCanUnregisterItself(t *testing.T) {
	packets := NewPackets()
	var unregister func()
	called := make(chan struct{})
	var ok bool
	unregister, ok = packets.registerPacketHandler(func(*Packet) bool {
		unregister()
		close(called)
		return true
	})
	if !ok {
		t.Fatal("registerPacketHandler failed")
	}

	done := make(chan struct{})
	go func() {
		packets.PushBack(NewPacket(0, 0, 1, 0, 0, nil, nil, Ver5))
		close(done)
	}()
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("handler deadlocked while unregistering itself")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("PushBack did not return after self-unregister")
	}
	_ = packets.Close()
}

func TestPacketHandlerCanClosePackets(t *testing.T) {
	packets := NewPackets()
	called := make(chan struct{})
	_, ok := packets.registerPacketHandler(func(*Packet) bool {
		if err := packets.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		close(called)
		return true
	})
	if !ok {
		t.Fatal("registerPacketHandler failed")
	}

	done := make(chan struct{})
	go func() {
		packets.PushBack(NewPacket(0, 0, 1, 0, 0, nil, nil, Ver5))
		close(done)
	}()
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("handler deadlocked while closing packets")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("PushBack did not return after handler Close")
	}
}

func TestConcurrentPushClose(t *testing.T) {
	p := NewPackets()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.PushBack(&Packet{DATA: []byte("test")})
		}()
	}

	time.Sleep(10 * time.Millisecond)
	_ = p.Close()

	wg.Wait()
	_, closed := p.PopFrontBlock()
	if !closed {
		t.Error("expected closed after Close")
	}
}

func TestQuicStreamPacketConnWriteToAfterClose(t *testing.T) {
	q := &quicStreamPacketConn{}

	if err := q.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	if _, err := q.WriteTo([]byte("test"), "127.0.0.1:53"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed after Close, got %v", err)
	}
}

func TestQuicStreamPacketConnCloseUnblocksReadFrom(t *testing.T) {
	packets := NewPackets()
	closeDone := make(chan struct{})
	q := &quicStreamPacketConn{
		incomingPackets: packets,
		closeDeferFn: func() {
			close(closeDone)
		},
	}

	readErr := make(chan error, 1)
	go func() {
		_, _, err := q.ReadFrom(make([]byte, 1024))
		readErr <- err
	}()

	time.Sleep(50 * time.Millisecond)

	if err := q.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	select {
	case err := <-readErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected net.ErrClosed from ReadFrom after Close, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom did not unblock after quicStreamPacketConn.Close")
	}

	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("closeDeferFn was not called")
	}
}

func TestPacketsPushBackAfterCloseIsIgnored(t *testing.T) {
	p := NewPackets()
	if err := p.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	p.PushBack(&Packet{DATA: []byte("test")})

	if got := len(p.ch); got != 0 {
		t.Fatalf("closed packet queue length = %d, want 0", got)
	}
}

func TestQuicStreamPacketConnPrunesExpiredDeFraggers(t *testing.T) {
	oldIdleTimeout := deFraggerIdleTimeout
	oldCleanupInterval := deFraggerCleanupInterval
	deFraggerIdleTimeout = 10 * time.Millisecond
	deFraggerCleanupInterval = 0
	t.Cleanup(func() {
		deFraggerIdleTimeout = oldIdleTimeout
		deFraggerCleanupInterval = oldCleanupInterval
	})

	q := &quicStreamPacketConn{}
	nowNano := time.Now().UnixNano()
	q.deFraggers.Store(uint16(1), &deFraggerBucket{
		deFraggers: []*deFragger{newDeFragger(nowNano - int64(2*deFraggerIdleTimeout))},
	})
	q.deFraggers.Store(uint16(2), &deFraggerBucket{
		deFraggers: []*deFragger{newDeFragger(nowNano)},
	})

	q.maybeCleanupDeFraggers(nowNano)

	if got := countDeFraggers(q); got != 1 {
		t.Fatalf("deFragger count after cleanup = %d, want 1", got)
	}
	if _, ok := q.deFraggers.Load(uint16(1)); ok {
		t.Fatal("expected stale deFragger to be removed")
	}
	if _, ok := q.deFraggers.Load(uint16(2)); !ok {
		t.Fatal("expected fresh deFragger to remain")
	}
}

func TestQuicStreamPacketConnCloseClearsIncompleteDeFraggers(t *testing.T) {
	packets := NewPackets()
	q := &quicStreamPacketConn{
		incomingPackets: packets,
	}

	readErr := make(chan error, 1)
	go func() {
		_, _, err := q.ReadFrom(make([]byte, 1024))
		readErr <- err
	}()

	packets.PushBack(&Packet{
		PKT_ID:     1,
		FRAG_ID:    0,
		FRAG_TOTAL: 2,
		DATA:       []byte("fragment"),
		ADDR:       &Address{TYPE: AtypIPv4, ADDR: []byte{127, 0, 0, 1}, PORT: 53},
	})

	deadline := time.Now().Add(2 * time.Second)
	for countDeFraggers(q) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for incomplete deFragger to be created")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := q.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	select {
	case err := <-readErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ReadFrom error = %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom did not unblock after Close")
	}

	if got := countDeFraggers(q); got != 0 {
		t.Fatalf("deFragger count after Close = %d, want 0", got)
	}
}

func TestQuicStreamPacketConnReadFromAssemblesCompleteFragments(t *testing.T) {
	packets := NewPackets()
	q := &quicStreamPacketConn{
		incomingPackets: packets,
	}

	packets.PushBack(&Packet{
		PKT_ID:     1,
		FRAG_ID:    0,
		FRAG_TOTAL: 2,
		DATA:       []byte("hello "),
		ADDR:       &Address{TYPE: AtypIPv4, ADDR: []byte{127, 0, 0, 1}, PORT: 53},
	})
	packets.PushBack(&Packet{
		PKT_ID:     1,
		FRAG_ID:    1,
		FRAG_TOTAL: 2,
		DATA:       []byte("world"),
		ADDR:       &Address{TYPE: AtypNone},
	})

	buf := make([]byte, 64)
	n, addr, err := q.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom returned error: %v", err)
	}
	if got := string(buf[:n]); got != "hello world" {
		t.Fatalf("assembled payload = %q, want %q", got, "hello world")
	}
	if addr != netip.MustParseAddrPort("127.0.0.1:53") {
		t.Fatalf("assembled addr = %v, want 127.0.0.1:53", addr)
	}
	if got := countDeFraggers(q); got != 0 {
		t.Fatalf("deFragger count after successful assembly = %d, want 0", got)
	}
}

func TestQuicStreamPacketConnReadFromSeparatesSamePktIDDifferentFragmentSets(t *testing.T) {
	packets := NewPackets()
	q := &quicStreamPacketConn{
		incomingPackets: packets,
	}

	packets.PushBack(&Packet{
		PKT_ID:     7,
		FRAG_ID:    0,
		FRAG_TOTAL: 2,
		DATA:       []byte("hello "),
		ADDR:       &Address{TYPE: AtypIPv4, ADDR: []byte{127, 0, 0, 1}, PORT: 53},
	})
	packets.PushBack(&Packet{
		PKT_ID:     7,
		FRAG_ID:    0,
		FRAG_TOTAL: 3,
		DATA:       []byte("golang "),
		ADDR:       &Address{TYPE: AtypIPv4, ADDR: []byte{127, 0, 0, 2}, PORT: 54},
	})
	packets.PushBack(&Packet{
		PKT_ID:     7,
		FRAG_ID:    1,
		FRAG_TOTAL: 3,
		DATA:       []byte("still "),
		ADDR:       &Address{TYPE: AtypNone},
	})
	packets.PushBack(&Packet{
		PKT_ID:     7,
		FRAG_ID:    1,
		FRAG_TOTAL: 2,
		DATA:       []byte("world"),
		ADDR:       &Address{TYPE: AtypNone},
	})
	packets.PushBack(&Packet{
		PKT_ID:     7,
		FRAG_ID:    2,
		FRAG_TOTAL: 3,
		DATA:       []byte("rocks"),
		ADDR:       &Address{TYPE: AtypNone},
	})

	buf := make([]byte, 64)
	n, addr, err := q.ReadFrom(buf)
	if err != nil {
		t.Fatalf("first ReadFrom returned error: %v", err)
	}
	if got := string(buf[:n]); got != "hello world" {
		t.Fatalf("first assembled payload = %q, want %q", got, "hello world")
	}
	if addr != netip.MustParseAddrPort("127.0.0.1:53") {
		t.Fatalf("first assembled addr = %v, want 127.0.0.1:53", addr)
	}

	n, addr, err = q.ReadFrom(buf)
	if err != nil {
		t.Fatalf("second ReadFrom returned error: %v", err)
	}
	if got := string(buf[:n]); got != "golang still rocks" {
		t.Fatalf("second assembled payload = %q, want %q", got, "golang still rocks")
	}
	if addr != netip.MustParseAddrPort("127.0.0.2:54") {
		t.Fatalf("second assembled addr = %v, want 127.0.0.2:54", addr)
	}

	if got := countDeFraggers(q); got != 0 {
		t.Fatalf("deFragger count after both assemblies = %d, want 0", got)
	}
}

func TestQuicStreamPacketConnMetadataForAddrCachesLastTarget(t *testing.T) {
	oldParse := parseMetadata
	defer func() { parseMetadata = oldParse }()

	var calls int
	parseMetadata = func(addr string) (protocol.Metadata, error) {
		calls++
		return protocol.Metadata{
			Type:     protocol.MetadataTypeIPv4,
			Hostname: "127.0.0.1",
			Port:     53,
		}, nil
	}

	var q quicStreamPacketConn
	var first *Address
	for i := 0; i < 2; i++ {
		address, err := q.addressForAddr("127.0.0.1:53")
		if err != nil {
			t.Fatalf("addressForAddr() error = %v", err)
		}
		if i == 0 {
			first = address
		} else if address != first {
			t.Fatalf("addressForAddr() did not reuse the cached address")
		}
		if address.TYPE != AtypIPv4 || address.PORT != 53 {
			t.Fatalf("addressForAddr() produced %+v", address)
		}
	}
	if calls != 1 {
		t.Fatalf("parseMetadata() call count = %d, want 1", calls)
	}

	if _, err := q.addressForAddr("127.0.0.2:54"); err != nil {
		t.Fatalf("addressForAddr() second target error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("parseMetadata() call count after target change = %d, want 2", calls)
	}
}

// TestPacketWriteToAtypNoneFrameLayout locks the serialization of non-first
// TUIC fragments: the AtypNone address byte must survive on the wire and the
// payload must not be shifted over it (a previous WriteToBytes bug returned 0
// for the address section and let DATA cover the type byte).
func TestPacketWriteToAtypNoneFrameLayout(t *testing.T) {
	packet := NewPacket(7, 9, 2, 1, 4, &Address{TYPE: AtypNone}, []byte("DATA"), Ver5)

	buf := make([]byte, packet.BytesLen())
	n := packet.WriteToBytes(buf)
	if n != packet.BytesLen() {
		t.Fatalf("WriteToBytes() = %d, want %d (BytesLen must be exact)", n, packet.BytesLen())
	}
	// Layout: head(2) + ASSOC(2) + PKT(2) + FRAG_TOTAL(1) + FRAG_ID(1) + SIZE(2)
	// + AtypNone(1) + DATA(4).
	want := []byte{Ver5, byte(PacketType), 0, 7, 0, 9, 2, 1, 0, 4, AtypNone, 'D', 'A', 'T', 'A'}
	if string(buf[:n]) != string(want) {
		t.Fatalf("serialized frame = %v, want %v", buf[:n], want)
	}
}

// TestPacketWriteToPooledBufferMatchesScratch verifies the Extend fast path
// of Packet.WriteTo into a pooled buffer produces byte-identical output to
// the scratch-buffer path.
func TestPacketWriteToPooledBufferMatchesScratch(t *testing.T) {
	address := NewAddress(&protocol.Metadata{
		Type:     protocol.MetadataTypeDomain,
		Hostname: "example.com",
		Port:     53,
	})
	packet := NewPacket(1, 2, 1, 0, 5, address, []byte("hello"), Ver5)

	scratch := make([]byte, packet.BytesLen())
	n := packet.WriteToBytes(scratch)

	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	if err := packet.WriteTo(buf); err != nil {
		t.Fatalf("WriteTo(pooled) error = %v", err)
	}
	if buf.Len() != n {
		t.Fatalf("pooled buffer length = %d, want %d", buf.Len(), n)
	}
	if string(buf.Bytes()) != string(scratch[:n]) {
		t.Fatalf("pooled bytes = %v, want %v", buf.Bytes(), scratch[:n])
	}
}
