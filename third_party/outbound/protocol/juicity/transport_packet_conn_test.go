package juicity

import (
	"errors"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/olicesx/quic-go"
)

type countingPacketConn struct {
	net.PacketConn
	closes         atomic.Int32
	readDeadlines  atomic.Int32
	writeDeadlines atomic.Int32
}

func (c *countingPacketConn) Close() error {
	c.closes.Add(1)
	if c.PacketConn != nil {
		return c.PacketConn.Close()
	}
	return nil
}

func (c *countingPacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadlines.Add(1)
	return c.PacketConn.SetReadDeadline(t)
}

func (c *countingPacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadlines.Add(1)
	return c.PacketConn.SetWriteDeadline(t)
}

func newTestTransportPacketConn(t *testing.T) (*TransportPacketConn, *countingPacketConn) {
	t.Helper()
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	counted := &countingPacketConn{PacketConn: raw}
	masterKey := make([]byte, CipherConf.KeyLen)
	_, _ = fastrand.Read(masterKey)
	conn := &TransportPacketConn{
		Transport: &quic.Transport{Conn: counted},
		proxyAddr: raw.LocalAddr().(*net.UDPAddr),
		key: &shadowsocks.Key{
			CipherConf: CipherConf,
			MasterKey:  masterKey,
		},
	}
	return conn, counted
}

func waitForActiveTransportRead(t *testing.T, conn *TransportPacketConn) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		conn.deadlineMu.Lock()
		active := conn.activeReadCancel != nil
		conn.deadlineMu.Unlock()
		if active {
			return
		}
		runtime.Gosched()
	}
	t.Fatal("ReadFrom did not become active")
}

func TestTransportPacketConnExposesTransportDone(t *testing.T) {
	conn, _ := newTestTransportPacketConn(t)
	lifecycle, ok := any(conn).(netproxy.TransportLifecycle)
	if !ok {
		t.Fatalf("expected TransportPacketConn to expose TransportDone, got %T", conn)
	}
	done := lifecycle.TransportDone()
	if done == nil {
		t.Fatal("expected non-nil TransportDone channel")
	}
	select {
	case <-done:
		t.Fatal("TransportDone closed before Close")
	default:
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TransportDone did not close after Close")
	}
}

func TestTransportPacketConnCloseReleasesPacketConnOnce(t *testing.T) {
	conn, counted := newTestTransportPacketConn(t)
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got := counted.closes.Load(); got != 1 {
		t.Fatalf("PacketConn Close count = %d, want 1", got)
	}
}

func TestTransportPacketConnCloseInterruptsRead(t *testing.T) {
	conn, _ := newTestTransportPacketConn(t)
	errCh := make(chan error, 1)
	go func() {
		_, _, err := conn.ReadFrom(make([]byte, 1500))
		errCh <- err
	}()
	waitForActiveTransportRead(t, conn)
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ReadFrom error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadFrom was not interrupted by Close")
	}
}

func TestTransportPacketConnReadDeadlineInterruptsRead(t *testing.T) {
	conn, counted := newTestTransportPacketConn(t)
	defer func() { _ = conn.Close() }()
	if err := conn.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, _, err := conn.ReadFrom(make([]byte, 1500))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadFrom error = %v, want os.ErrDeadlineExceeded", err)
	}
	if got := counted.readDeadlines.Load(); got != 0 {
		t.Fatalf("underlying SetReadDeadline calls = %d, want 0", got)
	}
}

func TestTransportPacketConnFutureDeadlineDoesNotInterruptImmediately(t *testing.T) {
	conn, _ := newTestTransportPacketConn(t)
	defer func() { _ = conn.Close() }()
	errCh := make(chan error, 1)
	go func() {
		_, _, err := conn.ReadFrom(make([]byte, 1500))
		errCh <- err
	}()
	waitForActiveTransportRead(t, conn)
	if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	select {
	case err := <-errCh:
		t.Fatalf("future deadline interrupted ReadFrom early: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("ReadFrom error = %v, want os.ErrDeadlineExceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("future deadline did not interrupt ReadFrom")
	}
}

func TestTransportPacketConnClearingDeadlineKeepsReadBlocked(t *testing.T) {
	conn, _ := newTestTransportPacketConn(t)
	errCh := make(chan error, 1)
	go func() {
		_, _, err := conn.ReadFrom(make([]byte, 1500))
		errCh <- err
	}()
	waitForActiveTransportRead(t, conn)
	if err := conn.SetReadDeadline(time.Now().Add(60 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear SetReadDeadline: %v", err)
	}
	select {
	case err := <-errCh:
		t.Fatalf("cleared deadline interrupted ReadFrom: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ReadFrom error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt ReadFrom")
	}
}

func TestTransportPacketConnPastDeadlineInterruptsQueuedReaders(t *testing.T) {
	conn, _ := newTestTransportPacketConn(t)
	defer func() { _ = conn.Close() }()
	errCh := make(chan error, 2)
	for range 2 {
		go func() {
			_, _, err := conn.ReadFrom(make([]byte, 1500))
			errCh <- err
		}()
	}
	waitForActiveTransportRead(t, conn)
	if err := conn.SetReadDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	for range 2 {
		select {
		case err := <-errCh:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("ReadFrom error = %v, want os.ErrDeadlineExceeded", err)
			}
		case <-time.After(time.Second):
			t.Fatal("past deadline did not interrupt all queued readers")
		}
	}
}

func TestTransportPacketConnSetDeadlineOnlyForwardsWriteDeadline(t *testing.T) {
	conn, counted := newTestTransportPacketConn(t)
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if got := counted.readDeadlines.Load(); got != 0 {
		t.Fatalf("underlying SetReadDeadline calls = %d, want 0", got)
	}
	if got := counted.writeDeadlines.Load(); got != 1 {
		t.Fatalf("underlying SetWriteDeadline calls = %d, want 1", got)
	}
}
