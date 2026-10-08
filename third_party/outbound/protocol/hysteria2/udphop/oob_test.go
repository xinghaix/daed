package udphop

import (
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/olicesx/quic-go"
	"golang.org/x/net/ipv4"
)

// errNoSyscall is returned by the stub's SyscallConn so the interface is
// satisfied without needing a real kernel file descriptor.
var errNoSyscall = syscall.ENOSYS

// oobStubConn is a net.PacketConn that also advertises the OOB socket
// surface quic-go probes for (SyscallConn + ReadMsgUDP + WriteMsgUDP). It is
// used to drive the GSO/batch code paths without a real kernel socket.
type oobStubConn struct {
	stubPacketConn
	remote  net.Addr
	writeMu sync.Mutex

	writeMsgCalls  int
	writeMsgOOB    []byte
	writeMsgTarget *net.UDPAddr
}

func (c *oobStubConn) RemoteAddr() net.Addr { return c.remote }

func (c *oobStubConn) SyscallConn() (syscall.RawConn, error) { return nil, errNoSyscall }

func (c *oobStubConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	return 0, 0, 0, &net.UDPAddr{}, nil
}

func (c *oobStubConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.writeMsgCalls++
	c.writeMsgOOB = append(c.writeMsgOOB[:0], oob...)
	c.writeMsgTarget = addr
	return len(b), len(oob), nil
}

// TestSatisfiesOOBCapablePacketConn is a runtime mirror of the compile-time
// assertion. If this ever fails, quic-go silently downgrades udpHop to a
// basicConn (per-packet recvfrom, no GSO), which is exactly the regression
// this optimisation exists to prevent.
func TestSatisfiesOOBCapablePacketConn(t *testing.T) {
	conn := &udpHopPacketConn{closeChan: make(chan struct{}), bufPool: newHopBufPool()}
	if _, ok := interface{}(conn).(quic.OOBCapablePacketConn); !ok {
		t.Fatal("udpHopPacketConn no longer satisfies quic.OOBCapablePacketConn")
	}
}

// TestSatisfiesBatchConn confirms quic-go will route reads through our
// ReadBatch (queue-backed) instead of binding a recvmmsg reader to a single
// hop's file descriptor.
func TestSatisfiesBatchConn(t *testing.T) {
	conn := &udpHopPacketConn{closeChan: make(chan struct{}), bufPool: newHopBufPool()}
	type batchConn interface {
		ReadBatch([]ipv4.Message, int) (int, error)
	}
	if _, ok := interface{}(conn).(batchConn); !ok {
		t.Fatal("udpHopPacketConn no longer satisfies quic-go's batchConn interface")
	}
}

// TestReadBatchDrainsQueueInOneCall verifies that a burst of queued packets is
// handed to quic-go in a single ReadBatch, which is what lets the receive loop
// amortise goroutine wake-ups.
func TestReadBatchDrainsQueueInOneCall(t *testing.T) {
	conn := &udpHopPacketConn{
		currentAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443},
		recvQueue:   make(chan *udpPacket, 8),
		closeChan:   make(chan struct{}),
		bufPool:     testBufPool(),
	}
	for i := 0; i < 3; i++ {
		conn.recvQueue <- &udpPacket{
			Buf:  []byte{byte('a' + i), 0, 0, 0, 0, 0, 0, 0},
			N:    1,
			Addr: &net.UDPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 8443},
		}
	}

	msgs := make([]ipv4.Message, 8)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, 16)}
	}

	n, err := conn.ReadBatch(msgs, 0)
	if err != nil {
		t.Fatalf("ReadBatch() error = %v", err)
	}
	if n != 3 {
		t.Fatalf("ReadBatch() returned %d packets, want 3", n)
	}
	for i := 0; i < n; i++ {
		if got, want := msgs[i].N, 1; got != want {
			t.Fatalf("msgs[%d].N = %d, want %d", i, got, want)
		}
	}
}

// TestReadBatchBlocksUntilFirstPacket ensures ReadBatch does not busy-loop
// when the queue is empty (it must block like ReadFrom).
func TestReadBatchBlocksUntilFirstPacket(t *testing.T) {
	conn := &udpHopPacketConn{
		currentAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443},
		recvQueue:   make(chan *udpPacket, 1),
		closeChan:   make(chan struct{}),
		bufPool:     testBufPool(),
	}

	done := make(chan struct{})
	go func() {
		msgs := make([]ipv4.Message, 4)
		for i := range msgs {
			msgs[i].Buffers = [][]byte{make([]byte, 16)}
		}
		n, _ := conn.ReadBatch(msgs, 0)
		if n != 1 {
			t.Errorf("ReadBatch() returned %d, want 1", n)
		}
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("ReadBatch returned before a packet was queued")
	case <-time.After(20 * time.Millisecond):
	}

	conn.recvQueue <- &udpPacket{Buf: []byte("x"), N: 1, Addr: conn.currentAddr}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ReadBatch did not unblock after a packet was queued")
	}
}

// TestReadBatchReturnsOnClose ensures a closed conn unblocks a pending
// ReadBatch instead of leaking the goroutine.
func TestReadBatchReturnsOnClose(t *testing.T) {
	conn := &udpHopPacketConn{
		currentAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443},
		recvQueue:   make(chan *udpPacket, 1),
		closeChan:   make(chan struct{}),
		bufPool:     testBufPool(),
	}

	done := make(chan struct{})
	go func() {
		msgs := make([]ipv4.Message, 1)
		msgs[0].Buffers = [][]byte{make([]byte, 16)}
		_, err := conn.ReadBatch(msgs, 0)
		if err == nil {
			t.Error("ReadBatch() expected error on closed conn, got nil")
		}
		close(done)
	}()

	close(conn.closeChan)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ReadBatch did not unblock on close")
	}
}

// TestWriteMsgUDPForwardsOOBToCurrentConn verifies that the GSO ancillary data
// quic-go attaches reaches the underlying socket, and that the destination is
// always the active hop address (not a stale handshake-time peer).
func TestWriteMsgUDPForwardsOOBToCurrentConn(t *testing.T) {
	hopAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 8443}
	stub := &oobStubConn{remote: hopAddr}
	conn := &udpHopPacketConn{
		currentAddr: hopAddr,
		currentConn: stub,
		closeChan:   make(chan struct{}),
	}

	oob := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	stalePeer := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 9999}
	if _, _, err := conn.WriteMsgUDP([]byte("payload"), oob, stalePeer); err != nil {
		t.Fatalf("WriteMsgUDP() error = %v", err)
	}

	if stub.writeMsgCalls != 1 {
		t.Fatalf("writeMsgCalls = %d, want 1", stub.writeMsgCalls)
	}
	if got, want := stub.writeMsgOOB, oob; !bytesEqual(got, want) {
		t.Fatalf("forwarded OOB = %v, want %v", got, want)
	}
	if stub.writeMsgTarget == nil || stub.writeMsgTarget.String() != hopAddr.String() {
		t.Fatalf("write target = %v, want the active hop addr %v", stub.writeMsgTarget, hopAddr)
	}
}

// TestWriteMsgUDPFallsBackToWriteToWhenOOBUnsupported checks that a proxied
// transport (no WriteMsgUDP) still delivers the packet via WriteTo.
func TestWriteMsgUDPFallsBackToWriteToWhenOOBUnsupported(t *testing.T) {
	stub := &stubPacketConn{}
	hopAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 443}
	conn := &udpHopPacketConn{
		currentAddr: hopAddr,
		currentConn: stub,
		closeChan:   make(chan struct{}),
	}

	n, _, err := conn.WriteMsgUDP([]byte("fallback"), nil, nil)
	if err != nil {
		t.Fatalf("WriteMsgUDP() fallback error = %v", err)
	}
	if n != len("fallback") {
		t.Fatalf("WriteMsgUDP() fallback n = %d, want %d", n, len("fallback"))
	}
	if got, want := stub.lastWriteAddr, hopAddr.String(); got != want {
		t.Fatalf("fallback WriteTo target = %q, want %q", got, want)
	}
}

// TestReadMsgUDPReturnsQueuedPacket confirms ReadMsgUDP (required by
// OOBCapablePacketConn but not used by quic-go's read path) stays consistent
// with ReadFrom by draining the same recvQueue.
func TestReadMsgUDPReturnsQueuedPacket(t *testing.T) {
	src := &net.UDPAddr{IP: net.IPv4(7, 7, 7, 7), Port: 53}
	conn := &udpHopPacketConn{
		currentAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443},
		recvQueue:   make(chan *udpPacket, 1),
		closeChan:   make(chan struct{}),
		bufPool:     newHopBufPool(),
	}
	conn.recvQueue <- &udpPacket{Buf: []byte("quic"), N: 4, Addr: src}

	b := make([]byte, 16)
	n, oobn, flags, addr, err := conn.ReadMsgUDP(b, nil)
	if err != nil {
		t.Fatalf("ReadMsgUDP() error = %v", err)
	}
	if n != 4 || string(b[:n]) != "quic" {
		t.Fatalf("ReadMsgUDP() payload n=%d %q, want 4 \"quic\"", n, b[:n])
	}
	if oobn != 0 || flags != 0 {
		t.Fatalf("ReadMsgUDP() oobn=%d flags=%d, want 0/0", oobn, flags)
	}
	if addr == nil || addr.String() != src.String() {
		t.Fatalf("ReadMsgUDP() addr = %v, want %v", addr, src)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// testBufPool mirrors the production bufPool so ReadBatch can recycle buffers
// when draining queued packets.
func testBufPool() *hopBufPool {
	return newHopBufPool()
}

// TestReadBatchRecyclesBuffersExactlyOnce guards the buffer ownership
// invariant on the batch receive path: every packet queued by recvLoop is
// owned by exactly one consumer, which must recycle it exactly once. A lost
// Put leaks the buffer (the pool keeps allocating), so refilling the queue
// after a full drain must hit the pool with zero new allocations.
func TestReadBatchRecyclesBuffersExactlyOnce(t *testing.T) {
	conn := &udpHopPacketConn{
		currentAddr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443},
		recvQueue:   make(chan *udpPacket, 16),
		closeChan:   make(chan struct{}),
		bufPool:     newHopBufPool(),
	}
	initialNewCalls := conn.bufPool.newCount.Load()

	// Batch 1: recvLoop transfers ownership of 16 fresh pool buffers to the
	// queue. The pool is pre-warmed with recvBatchSize buffers, so only the
	// remaining n-recvBatchSize Get calls allocate.
	const n = 16
	for i := 0; i < n; i++ {
		conn.recvQueue <- &udpPacket{Buf: conn.bufPool.Get(), N: 8, Addr: conn.currentAddr}
	}
	if got, want := conn.bufPool.newCount.Load()-initialNewCalls, int64(n-recvBatchSize); got != want {
		t.Fatalf("seed allocations = %d, want %d", got, want)
	}

	// Drain batch 1 through ReadBatch; every buffer must be recycled.
	msgs := make([]ipv4.Message, 8)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, 16)}
	}
	for drained := 0; drained < n; {
		got, err := conn.ReadBatch(msgs, 0)
		if err != nil {
			t.Fatalf("ReadBatch: %v", err)
		}
		if got == 0 {
			t.Fatal("ReadBatch returned 0 with packets queued")
		}
		drained += got
	}

	// Batch 2: if every buffer was recycled exactly once, refilling the queue
	// hits the pool and allocates nothing.
	for i := 0; i < n; i++ {
		conn.recvQueue <- &udpPacket{Buf: conn.bufPool.Get(), N: 8, Addr: conn.currentAddr}
	}
	if got, want := conn.bufPool.newCount.Load()-initialNewCalls, int64(n-recvBatchSize); got != want {
		t.Fatalf("pool reallocated %d buffers after a full recycle (want 0); "+
			"a Put path was lost (%d total allocations)", got-(n-recvBatchSize), got)
	}
}
