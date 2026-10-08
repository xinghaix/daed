package socks5

import (
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type receiverPacketConn struct {
	mu      sync.Mutex
	writes  [][]byte
	handler netproxy.PacketReceiveHandler
}

func (c *receiverPacketConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *receiverPacketConn) Write(p []byte) (int, error) { return c.WriteTo(p, "") }
func (c *receiverPacketConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (c *receiverPacketConn) WriteTo(p []byte, _ string) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.mu.Unlock()
	return len(p), nil
}
func (c *receiverPacketConn) Close() error                     { return nil }
func (c *receiverPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *receiverPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *receiverPacketConn) SetWriteDeadline(time.Time) error { return nil }
func (c *receiverPacketConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	c.mu.Lock()
	c.handler = handler
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		c.handler = nil
		c.mu.Unlock()
	}, true
}

func (c *receiverPacketConn) emit(packet *netproxy.ReceivedPacket) bool {
	c.mu.Lock()
	handler := c.handler
	c.mu.Unlock()
	if handler == nil {
		return false
	}
	return handler(packet)
}

func TestPktConnPacketReceiverDecodesTargetAndPayload(t *testing.T) {
	receiver := &receiverPacketConn{}
	conn := NewPktConn(receiver, "127.0.0.1:1080", "1.1.1.1:53", nil)
	if _, err := conn.WriteTo([]byte("payload"), "8.8.8.8:53"); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}

	var got *netproxy.ReceivedPacket
	stop, ok := conn.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
		got = packet
		return true
	})
	if !ok || stop == nil {
		t.Fatal("RegisterPacketReceiver() did not register")
	}
	receiver.mu.Lock()
	raw := append([]byte(nil), receiver.writes[0]...)
	receiver.mu.Unlock()
	var rawReleased atomic.Int32
	if !receiver.emit(netproxy.NewReceivedPacket(raw, netip.AddrPort{}, nil, func() {
		rawReleased.Add(1)
	})) {
		t.Fatal("receiver did not consume packet")
	}
	if got == nil || string(got.Data) != "payload" || got.From.Addr().Unmap() != netip.MustParseAddr("8.8.8.8") || got.From.Port() != 53 {
		t.Fatalf("decoded packet = %+v, want payload and target source", got)
	}
	got.Release()
	if rawReleased.Load() != 1 {
		t.Fatalf("raw release count = %d, want 1", rawReleased.Load())
	}
	stop()
}

func TestPktConnPacketReceiverForwardsMalformedPacketAsError(t *testing.T) {
	receiver := &receiverPacketConn{}
	conn := NewPktConn(receiver, "127.0.0.1:1080", "1.1.1.1:53", nil)
	var got *netproxy.ReceivedPacket
	stop, ok := conn.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
		got = packet
		return true
	})
	if !ok || stop == nil {
		t.Fatal("RegisterPacketReceiver() did not register")
	}
	if !receiver.emit(netproxy.NewReceivedPacket([]byte{0, 0}, netip.AddrPort{}, nil, nil)) {
		t.Fatal("receiver did not consume malformed packet")
	}
	if got == nil || got.Err == nil || len(got.Data) != 0 {
		t.Fatalf("malformed packet = %+v, want error without payload", got)
	}
	got.Release()
	stop()
}
