package tuic

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/congestion"
)

func TestDeferQuicConnKeepsAliveOnDatagramQueueTimeout(t *testing.T) {
	t.Parallel()

	client := &clientImpl{}
	var closed atomic.Bool
	client.onClose = func() { closed.Store(true) }

	client.deferQuicConn(nil, quic.ErrDatagramQueueFullTimeout)
	if client.closed.Load() {
		t.Fatal("datagram send-queue timeout must not mark the shared TUIC client closed")
	}
	if closed.Load() {
		t.Fatal("datagram send-queue timeout must not invoke the client close callback")
	}

	client.deferQuicConn(nil, errors.Join(errors.New("association write"), quic.ErrDatagramQueueFullTimeout))
	if client.closed.Load() {
		t.Fatal("wrapped datagram send-queue timeout must not close the shared TUIC client")
	}
	if closed.Load() {
		t.Fatal("wrapped datagram send-queue timeout must not invoke the client close callback")
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	live := &lifecycleQuicConn{ctx: ctx, cancel: cancel}
	client.quicConn = live
	client.deferQuicConn(live, quic.ErrDatagramQueueFullTimeout)
	if client.closed.Load() {
		t.Fatal("live-connection datagram send-queue timeout must not close the shared TUIC client")
	}
	if closed.Load() {
		t.Fatal("live-connection datagram send-queue timeout must not invoke the client close callback")
	}
}

func TestDeferQuicConnStillClosesOnPermanentError(t *testing.T) {
	t.Parallel()

	client := &clientImpl{}
	done := make(chan struct{})
	client.onClose = func() { close(done) }

	client.deferQuicConn(nil, errors.New("connection lost"))
	if !client.closed.Load() {
		t.Fatal("permanent errors must still close the shared TUIC client")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("permanent errors must invoke the client close callback")
	}
}

type lifecycleQuicConn struct {
	ctx      context.Context
	cancel   context.CancelFunc
	receive  func(context.Context) ([]byte, error)
	receives atomic.Int32
	closes   atomic.Int32
}

func (c *lifecycleQuicConn) AcceptStream(context.Context) (quic.Stream, error) {
	return nil, net.ErrClosed
}
func (c *lifecycleQuicConn) AcceptUniStream(context.Context) (quic.ReceiveStream, error) {
	return nil, net.ErrClosed
}
func (c *lifecycleQuicConn) OpenStream() (quic.Stream, error) { return nil, net.ErrClosed }
func (c *lifecycleQuicConn) OpenStreamSync(context.Context) (quic.Stream, error) {
	return nil, net.ErrClosed
}
func (c *lifecycleQuicConn) OpenUniStream() (quic.SendStream, error) { return nil, net.ErrClosed }
func (c *lifecycleQuicConn) OpenUniStreamSync(context.Context) (quic.SendStream, error) {
	return nil, net.ErrClosed
}
func (c *lifecycleQuicConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}
func (c *lifecycleQuicConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}
}
func (c *lifecycleQuicConn) CloseWithError(quic.ApplicationErrorCode, string) error {
	c.closes.Add(1)
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}
func (c *lifecycleQuicConn) Context() context.Context { return c.ctx }
func (c *lifecycleQuicConn) ConnectionState() quic.ConnectionState {
	return quic.ConnectionState{}
}
func (c *lifecycleQuicConn) SendDatagram([]byte) error { return net.ErrClosed }
func (c *lifecycleQuicConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	c.receives.Add(1)
	if c.receive != nil {
		return c.receive(ctx)
	}
	return nil, io.EOF
}
func (c *lifecycleQuicConn) ReleaseDatagram([]byte)                            {}
func (c *lifecycleQuicConn) SetCongestionControl(congestion.CongestionControl) {}

func TestHandleMessageExitsOnStatelessResetInsteadOfBusyLoop(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn := &lifecycleQuicConn{
		ctx:    ctx,
		cancel: cancel,
		receive: func(context.Context) ([]byte, error) {
			return nil, &quic.StatelessResetError{}
		},
	}
	client := &clientImpl{quicConn: conn}
	done := make(chan struct{})
	client.onClose = func() { close(done) }

	finished := make(chan error, 1)
	go func() { finished <- client.handleMessage(conn) }()

	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("handleMessage() = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("handleMessage spun instead of exiting after stateless reset")
	}
	if n := conn.receives.Load(); n > 8 {
		t.Fatalf("ReceiveDatagram called %d times; busy-loop was not broken", n)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stateless reset must retire the shared TUIC client")
	}
}

func TestDeferQuicConnRetiresClosedConnectionOnTemporaryError(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn := &lifecycleQuicConn{ctx: ctx, cancel: cancel}
	client := &clientImpl{quicConn: conn}
	done := make(chan struct{})
	client.onClose = func() { close(done) }

	client.deferQuicConn(conn, &quic.StatelessResetError{})
	if !client.closed.Load() {
		t.Fatal("closed-connection temporary errors must still retire the shared TUIC client")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("closed-connection temporary errors must invoke the client close callback")
	}
}
