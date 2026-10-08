package tuic

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/olicesx/quic-go"
)

// cancelTestConn is a fake quic.Connection for the cancellation/force-close
// tests: every method the production path may call is either tracked or a
// no-op, so a late force-close timer cannot panic on a missing method.
type cancelTestConn struct {
	quic.Connection

	ctx    context.Context
	cancel context.CancelFunc

	sendMu        sync.Mutex
	sentDatagrams [][]byte

	closeWithCalls atomic.Int32
	closeCalled    chan struct{}
}

func newCancelTestConn() *cancelTestConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &cancelTestConn{ctx: ctx, cancel: cancel, closeCalled: make(chan struct{})}
}

func (c *cancelTestConn) Context() context.Context { return c.ctx }

func (c *cancelTestConn) SendDatagram(b []byte) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	c.sentDatagrams = append(c.sentDatagrams, append([]byte(nil), b...))
	return nil
}

func (c *cancelTestConn) sentDatagramCount() int {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return len(c.sentDatagrams)
}

func (c *cancelTestConn) OpenUniStream() (quic.SendStream, error) {
	return nil, net.ErrClosed
}

func (c *cancelTestConn) CloseWithError(quic.ApplicationErrorCode, string) error {
	if c.closeWithCalls.Add(1) == 1 {
		c.cancel()
		close(c.closeCalled)
	}
	return nil
}

// cancelTestUnderConn is a minimal net.PacketConn tracking Close.
type cancelTestUnderConn struct {
	closeCalls atomic.Int32
	closedAt   chan time.Time
}

func (c *cancelTestUnderConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (c *cancelTestUnderConn) WriteTo(_ []byte, _ net.Addr) (int, error) {
	return 0, net.ErrClosed
}

func (c *cancelTestUnderConn) Close() error {
	if c.closeCalls.Add(1) == 1 && c.closedAt != nil {
		c.closedAt <- time.Now()
	}
	return nil
}

func (c *cancelTestUnderConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}
func (c *cancelTestUnderConn) SetDeadline(time.Time) error      { return nil }
func (c *cancelTestUnderConn) SetReadDeadline(time.Time) error  { return nil }
func (c *cancelTestUnderConn) SetWriteDeadline(time.Time) error { return nil }

func newCancelTestClient(t *testing.T, conn *cancelTestConn) *clientImpl {
	t.Helper()
	c := newClientImpl(&ClientOption{
		UdpRelayMode:          common.NATIVE,
		MaxUdpRelayPacketSize: 1452,
	}, true, 8)
	if conn != nil {
		c.quicConn = conn
	}
	return c
}

func cancelTestNoDial(ctx context.Context, dialer netproxy.Dialer) (*quic.Transport, net.Addr, error) {
	return nil, nil, errors.New("cancel test: dialFn must not be reached on the cached-conn branch")
}

func udpTestAddr() string { return "1.2.3.4:53" }

// A canceled context on the cached-connection branch must fail the UDP dial
// and must not publish any association (inverts the QA cached-ctx finding).
func TestListenPacketCanceledCtxCachedConnFailsWithoutAssociation(t *testing.T) {
	c := newCancelTestClient(t, newCancelTestConn())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already dead before the call

	pc, err := c.ListenPacketWithDialer(ctx, &protocol.Metadata{}, nil, cancelTestNoDial)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ListenPacketWithDialer(canceled ctx) = %v, want context.Canceled", err)
	}
	if pc != nil {
		t.Fatalf("ListenPacketWithDialer(canceled ctx) returned conn %v", pc)
	}
	var registered int
	c.udpIncomingPacketsMap.Range(func(any, any) bool {
		registered++
		return true
	})
	if registered != 0 {
		t.Fatalf("canceled dial leaked %d association(s) in udpIncomingPacketsMap", registered)
	}
}

// The ring-level UDP and TCP entries must pass the caller context down so a
// canceled dial neither walks the ring nor constructs clients.
func TestClientRingCanceledCtxFailsWithoutNewClient(t *testing.T) {
	var constructed atomic.Int32
	r := newClientRing(func(func(int64)) *clientImpl {
		constructed.Add(1)
		return newClientImpl(&ClientOption{}, true, 8)
	}, 0)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := r.ListenPacketWithDialer(ctx, &protocol.Metadata{}, nil, cancelTestNoDial); !errors.Is(err, context.Canceled) {
		t.Fatalf("ListenPacketWithDialer(canceled) = %v, want context.Canceled", err)
	}
	if _, err := r.DialContextWithDialer(ctx, &protocol.Metadata{}, nil, cancelTestNoDial); !errors.Is(err, context.Canceled) {
		t.Fatalf("DialContextWithDialer(canceled) = %v, want context.Canceled", err)
	}
	if constructed.Load() != 0 {
		t.Fatalf("canceled dials constructed %d clients", constructed.Load())
	}
	if got := r.ring.Len(); got != 0 {
		t.Fatalf("canceled dials mutated the ring: len = %d", got)
	}
}

// A local bad-destination-address error on ONE association's WriteTo must
// stay local: the shared client survives, the peer association keeps
// working, and the ring close hook is not fired (inverts the QA bad-addr
// force-close finding).
func TestWriteToBadAddrDoesNotForceCloseSharedClient(t *testing.T) {
	conn := newCancelTestConn()
	c := newCancelTestClient(t, conn)

	onCloseFired := make(chan struct{}, 1)
	c.setOnClose(func() { onCloseFired <- struct{}{} })

	secondPackets := NewPackets() // another user's association sharing this client
	c.udpIncomingPacketsMap.Store(uint16(0x2222), secondPackets)
	victimPackets := NewPackets()
	victimId := uint16(0x1111)
	pc := &quicStreamPacketConn{
		connId:          victimId,
		quicConn:        conn,
		incomingPackets: victimPackets,
		udpRelayMode:    common.NATIVE,
		deferQuicConnFn: c.deferQuicConn,
		closeDeferFn: func() {
			c.udpIncomingPacketsMap.CompareAndDelete(victimId, victimPackets)
		},
	}
	c.udpIncomingPacketsMap.Store(victimId, victimPackets)

	if _, werr := pc.WriteTo([]byte("x"), "bad-addr-without-port"); werr == nil {
		t.Fatal("expected addressForAddr parse error, got nil")
	}

	if c.closed.Load() {
		t.Fatal("local bad-address WriteTo must not force-close the shared client")
	}
	select {
	case <-onCloseFired:
		t.Fatal("onClose (ring removal hook) fired for a local parse error")
	case <-time.After(200 * time.Millisecond):
	}
	if _, stillThere := c.udpIncomingPacketsMap.Load(pc.connId); !stillThere {
		t.Fatal("victim association was dropped from udpIncomingPacketsMap by a local parse error")
	}
	if secondPackets.closed.Load() {
		t.Fatal("unrelated second association was closed by the victim's local error")
	}
	if got := conn.closeWithCalls.Load(); got != 0 {
		t.Fatalf("QUIC connection closed %d time(s) by a local parse error", got)
	}

	// The shared tunnel must still carry traffic for both associations.
	if _, werr := pc.WriteTo([]byte("x"), udpTestAddr()); werr != nil {
		t.Fatalf("valid WriteTo after a local parse error = %v, want nil", werr)
	}
	secondPc := &quicStreamPacketConn{
		connId:          0x2222,
		quicConn:        conn,
		incomingPackets: secondPackets,
		udpRelayMode:    common.NATIVE,
		deferQuicConnFn: c.deferQuicConn,
	}
	if _, werr := secondPc.WriteTo([]byte("y"), udpTestAddr()); werr != nil {
		t.Fatalf("peer association WriteTo after the victim's local error = %v, want nil", werr)
	}
	if got := conn.sentDatagramCount(); got != 2 {
		t.Fatalf("sent datagrams = %d, want 2 (both associations still sending)", got)
	}

	_ = pc.Close()
	_ = secondPc.Close()
}

// forceClose must publish retirement immediately (done closed, writes and
// new registrations blocked, readers released) while the actual QUIC close
// still waits out its grace period.
func TestForceCloseSignalsDoneImmediatelyWhileQuicStillOpen(t *testing.T) {
	conn := newCancelTestConn()
	c := newCancelTestClient(t, conn)

	pc, err := c.ListenPacketWithDialer(context.Background(), &protocol.Metadata{}, nil, cancelTestNoDial)
	if err != nil {
		t.Fatalf("ListenPacketWithDialer() = %v", err)
	}
	done := pc.TransportDone()
	if done == nil {
		t.Fatal("TransportDone() = nil, want the client-owned lifecycle channel")
	}
	select {
	case <-done:
		t.Fatal("done closed before forceClose")
	default:
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}

	// Logical retirement is immediate...
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("client done not closed right after forceClose")
	}
	if _, werr := pc.WriteTo([]byte("x"), udpTestAddr()); !errors.Is(werr, net.ErrClosed) {
		t.Fatalf("WriteTo on retired association = %v, want net.ErrClosed", werr)
	}
	if _, err := c.ListenPacketWithDialer(context.Background(), &protocol.Metadata{}, nil, cancelTestNoDial); !errors.Is(err, common.ErrClientClosed) {
		t.Fatalf("ListenPacketWithDialer after forceClose = %v, want ErrClientClosed", err)
	}
	readErr := make(chan error, 1)
	go func() {
		_, _, rerr := pc.ReadFrom(make([]byte, 1))
		readErr <- rerr
	}()
	select {
	case rerr := <-readErr:
		if !errors.Is(rerr, net.ErrClosed) {
			t.Fatalf("ReadFrom on retired association = %v, want net.ErrClosed", rerr)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadFrom still blocked after forceClose")
	}

	// ...while the actual QUIC close honors the grace period.
	if got := conn.closeWithCalls.Load(); got != 0 {
		t.Fatalf("CloseWithError ran %d time(s) during the grace period, want 0", got)
	}
	select {
	case <-conn.ctx.Done():
		t.Fatal("QUIC connection context canceled during the grace period")
	default:
	}
}

// After the grace period the captured resources must actually be closed.
func TestForceCloseTimerClosesCapturedResourcesAfterGrace(t *testing.T) {
	origGrace := forceCloseGracePeriod
	forceCloseGracePeriod = 50 * time.Millisecond
	t.Cleanup(func() { forceCloseGracePeriod = origGrace })

	conn := newCancelTestConn()
	c := newCancelTestClient(t, conn)
	underConn := &cancelTestUnderConn{closedAt: make(chan time.Time, 1)}
	c.underConn = underConn

	started := time.Now()
	if err := c.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	select {
	case closedAt := <-underConn.closedAt:
		if elapsed := closedAt.Sub(started); elapsed < forceCloseGracePeriod {
			t.Fatalf("underlay closed after %s, before grace %s", elapsed, forceCloseGracePeriod)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("grace-period close did not reach the underlay")
	}
	c.connMutex.Lock()
	qcAttached, ucAttached := c.quicConn != nil, c.underConn != nil
	c.connMutex.Unlock()
	if qcAttached || ucAttached {
		t.Fatalf("resources not detached by the grace timer: quicConn=%v underConn=%v", qcAttached, ucAttached)
	}
	if got := conn.closeWithCalls.Load(); got != 1 {
		t.Fatalf("CloseWithError calls = %d, want 1", got)
	}
	if got := underConn.closeCalls.Load(); got != 1 {
		t.Fatalf("underlay Close calls = %d, want 1", got)
	}
}

// Concurrent Close/WriteTo/registration racing forceClose: retirement must
// happen exactly once and late arrivals must observe the closed client.
func TestForceCloseExactlyOnceUnderConcurrentClose(t *testing.T) {
	origGrace := forceCloseGracePeriod
	forceCloseGracePeriod = 50 * time.Millisecond
	t.Cleanup(func() { forceCloseGracePeriod = origGrace })

	conn := newCancelTestConn()
	c := newCancelTestClient(t, conn)

	var onCloseCount atomic.Int32
	onCloseCalled := make(chan struct{})
	c.setOnClose(func() {
		if onCloseCount.Add(1) == 1 {
			close(onCloseCalled)
		}
	})

	pc, err := c.ListenPacketWithDialer(context.Background(), &protocol.Metadata{}, nil, cancelTestNoDial)
	if err != nil {
		t.Fatalf("ListenPacketWithDialer() = %v", err)
	}

	const workers = 8
	var wg sync.WaitGroup
	var registrationSuccesses atomic.Int32
	start := make(chan struct{})
	wg.Add(workers + 1)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			<-start
			_, _ = pc.WriteTo([]byte("x"), udpTestAddr())
			// A registration that lands after forceClose would leave an
			// orphaned entry in udpIncomingPacketsMap; the final map check
			// below fails if that ever happens.
			if _, rerr := c.ListenPacketWithDialer(context.Background(), &protocol.Metadata{}, nil, cancelTestNoDial); rerr == nil {
				registrationSuccesses.Add(1)
			}
			_ = c.Close()
		}()
	}
	go func() {
		defer wg.Done()
		<-start
		_, _, _ = pc.ReadFrom(make([]byte, 1))
	}()
	close(start)
	wg.Wait()

	select {
	case <-onCloseCalled:
	case <-time.After(time.Second):
		t.Fatal("asynchronous onClose did not run")
	}
	if got := onCloseCount.Load(); got != 1 {
		t.Fatalf("onClose fired %d time(s), want exactly 1", got)
	}
	var remaining int
	c.udpIncomingPacketsMap.Range(func(any, any) bool {
		remaining++
		return true
	})
	if remaining != 0 {
		t.Fatalf("%d association(s) orphaned in udpIncomingPacketsMap after forceClose (post-close registration)", remaining)
	}
	_ = registrationSuccesses.Load() // success count is racy by design; only the map invariant above matters
	select {
	case <-pc.TransportDone():
	case <-time.After(time.Second):
		t.Fatal("client done not closed after concurrent forceClose")
	}
	select {
	case <-conn.closeCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("grace-period QUIC close did not run")
	}
	if got := conn.closeWithCalls.Load(); got != 1 {
		t.Fatalf("CloseWithError calls = %d, want exactly 1", got)
	}
}

// WriteDeadlineClosesSession documents that a write deadline (which tears
// the association down via SetDeadline) also ends the UDP session.
func TestQuicStreamPacketConnWriteDeadlineClosesSessionReportsTrue(t *testing.T) {
	pc := &quicStreamPacketConn{}
	if !pc.WriteDeadlineClosesSession() {
		t.Fatal("WriteDeadlineClosesSession() = false, want true")
	}
}
