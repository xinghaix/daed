package client

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/congestion"

	coreErrs "github.com/daeuniverse/outbound/protocol/hysteria2/errors"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

type packetConnWithRemoteAddr struct {
	remote net.Addr
}

func (c *packetConnWithRemoteAddr) ReadFrom(_ []byte) (n int, addr net.Addr, err error) {
	return 0, nil, net.ErrClosed
}

func (c *packetConnWithRemoteAddr) WriteTo(b []byte, _ net.Addr) (n int, err error) {
	return len(b), nil
}

func (c *packetConnWithRemoteAddr) Close() error {
	return nil
}

func (c *packetConnWithRemoteAddr) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *packetConnWithRemoteAddr) SetDeadline(_ time.Time) error {
	return nil
}

func (c *packetConnWithRemoteAddr) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *packetConnWithRemoteAddr) SetWriteDeadline(_ time.Time) error {
	return nil
}

func (c *packetConnWithRemoteAddr) RemoteAddr() net.Addr {
	return c.remote
}

func TestQuicRemoteAddrPrefersPacketConnRemoteAddr(t *testing.T) {
	fallback := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 443}
	remote := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 2), Port: 8443}
	conn := &packetConnWithRemoteAddr{remote: remote}

	if got := quicRemoteAddr(conn, fallback); got.String() != remote.String() {
		t.Fatalf("quicRemoteAddr() = %q, want %q", got.String(), remote.String())
	}
}

func TestQuicRemoteAddrFallsBackWhenPacketConnHasNoRemoteAddr(t *testing.T) {
	fallback := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 443}
	conn := &packetConnWithRemoteAddr{}

	if got := quicRemoteAddr(conn, fallback); got.String() != fallback.String() {
		t.Fatalf("quicRemoteAddr() = %q, want %q", got.String(), fallback.String())
	}
}

func TestUDPIOImplSendMessageReturnsDatagramTooLargeOnSerializeOverflow(t *testing.T) {
	io := &udpIOImpl{}
	msg := &protocol.UDPMessage{
		SessionID: 1,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      []byte("203.0.113.10:40000"),
		Data:      bytes.Repeat([]byte("x"), 64),
	}

	err := io.SendMessage(make([]byte, 16), msg)
	var errTooLarge *quic.DatagramTooLargeError
	if !errors.As(err, &errTooLarge) {
		t.Fatalf("SendMessage() error = %T %v, want DatagramTooLargeError", err, err)
	}
	if errTooLarge.MaxDataLen != 16 {
		t.Fatalf("DatagramTooLargeError.MaxDataLen = %d, want 16", errTooLarge.MaxDataLen)
	}
}

type closeTrackingPacketConn struct {
	packetConnWithRemoteAddr
	closes atomic.Int32
}

func (c *closeTrackingPacketConn) Close() error {
	c.closes.Add(1)
	return nil
}

type closeTrackingQuicConn struct {
	ctx    context.Context
	cancel context.CancelFunc
	closes atomic.Int32
}

func (c *closeTrackingQuicConn) AcceptStream(context.Context) (quic.Stream, error) {
	return nil, net.ErrClosed
}

func (c *closeTrackingQuicConn) AcceptUniStream(context.Context) (quic.ReceiveStream, error) {
	return nil, net.ErrClosed
}

func (c *closeTrackingQuicConn) OpenStream() (quic.Stream, error) {
	return nil, net.ErrClosed
}

func (c *closeTrackingQuicConn) OpenStreamSync(context.Context) (quic.Stream, error) {
	return nil, net.ErrClosed
}

func (c *closeTrackingQuicConn) OpenUniStream() (quic.SendStream, error) {
	return nil, net.ErrClosed
}

func (c *closeTrackingQuicConn) OpenUniStreamSync(context.Context) (quic.SendStream, error) {
	return nil, net.ErrClosed
}

func (c *closeTrackingQuicConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (c *closeTrackingQuicConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}

func (c *closeTrackingQuicConn) CloseWithError(quic.ApplicationErrorCode, string) error {
	c.closes.Add(1)
	c.cancel()
	return nil
}

func (c *closeTrackingQuicConn) Context() context.Context {
	return c.ctx
}

func (c *closeTrackingQuicConn) ConnectionState() quic.ConnectionState {
	return quic.ConnectionState{}
}

func (c *closeTrackingQuicConn) SendDatagram([]byte) error {
	return net.ErrClosed
}

func (c *closeTrackingQuicConn) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, net.ErrClosed
}

func (c *closeTrackingQuicConn) ReleaseDatagram([]byte) {}

func (c *closeTrackingQuicConn) SetCongestionControl(congestion.CongestionControl) {}

func TestClientCloseReleasesActiveResourcesAndRejectsFutureDials(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	conn := &closeTrackingQuicConn{ctx: ctx, cancel: cancel}
	pktConn := &closeTrackingPacketConn{}
	c := &clientImpl{
		conn:    conn,
		pktConn: pktConn,
		udpSM: &udpSessionManager{
			m:    make(map[uint32]*udpConn),
			done: make(chan struct{}),
		},
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("QUIC CloseWithError calls = %d, want 1", got)
	}
	if got := pktConn.closes.Load(); got != 1 {
		t.Fatalf("packet conn Close calls = %d, want 1", got)
	}
	if c.conn != nil || c.pktConn != nil || c.udpSM != nil {
		t.Fatalf("client resources not cleared: conn=%v pktConn=%v udpSM=%v", c.conn, c.pktConn, c.udpSM)
	}

	_, err := c.UDP("127.0.0.1:53", context.Background())
	var closedErr coreErrs.ClosedError
	if !errors.As(err, &closedErr) {
		t.Fatalf("UDP after Close() error = %T %v, want ClosedError", err, err)
	}
}

func TestClientCloseDefersTransportCloseUntilActiveUDPSessionsDrain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	conn := &closeTrackingQuicConn{ctx: ctx, cancel: cancel}
	pktConn := &closeTrackingPacketConn{}
	manager := &udpSessionManager{
		io:     noopUDPTestIO{},
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		done:   make(chan struct{}),
	}
	udpRaw, err := manager.NewUDP("127.0.0.1:53")
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}
	udpSession := udpRaw.(*udpConn)
	c := &clientImpl{
		conn:    conn,
		pktConn: pktConn,
		udpSM:   manager,
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := conn.closes.Load(); got != 0 {
		t.Fatalf("QUIC closed while UDP session active = %d, want 0", got)
	}
	if got := pktConn.closes.Load(); got != 0 {
		t.Fatalf("packet conn closed while UDP session active = %d, want 0", got)
	}
	if _, err := manager.NewUDP("127.0.0.1:54"); !errors.As(err, new(coreErrs.ClosedError)) {
		t.Fatalf("NewUDP while draining error = %T %v, want ClosedError", err, err)
	}

	if err := udpSession.Close(); err != nil {
		t.Fatalf("udp session Close() error = %v", err)
	}
	// The drain callback is deliberately decoupled (it must never run
	// synchronously on a call stack that holds c.m, or it self-deadlocks),
	// so wait for the deferred teardown instead of asserting immediately.
	// Field reads go through c.m to stay ordered against closeExisting.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.m.Lock()
		cleared := c.conn == nil && c.pktConn == nil && c.udpSM == nil
		c.m.Unlock()
		if cleared {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("QUIC CloseWithError calls after UDP drain = %d, want 1", got)
	}
	if got := pktConn.closes.Load(); got != 1 {
		t.Fatalf("packet conn Close calls after UDP drain = %d, want 1", got)
	}
	c.m.Lock()
	defer c.m.Unlock()
	if c.conn != nil || c.pktConn != nil || c.udpSM != nil {
		t.Fatalf("client resources not cleared after UDP drain: conn=%v pktConn=%v udpSM=%v", c.conn, c.pktConn, c.udpSM)
	}
}
