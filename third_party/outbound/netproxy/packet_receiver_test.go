package netproxy

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type mappedPacketReceiverTestConn struct {
	handler PacketReceiveHandler
}

func (c *mappedPacketReceiverTestConn) Read([]byte) (int, error)    { return 0, nil }
func (c *mappedPacketReceiverTestConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *mappedPacketReceiverTestConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, nil
}
func (c *mappedPacketReceiverTestConn) WriteTo(p []byte, _ string) (int, error) {
	return len(p), nil
}
func (c *mappedPacketReceiverTestConn) Close() error                     { return nil }
func (c *mappedPacketReceiverTestConn) SetDeadline(time.Time) error      { return nil }
func (c *mappedPacketReceiverTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *mappedPacketReceiverTestConn) SetWriteDeadline(time.Time) error { return nil }
func (c *mappedPacketReceiverTestConn) RegisterPacketReceiver(handler PacketReceiveHandler) (func(), bool) {
	c.handler = handler
	return func() { c.handler = nil }, true
}

func (c *mappedPacketReceiverTestConn) emit(packet *ReceivedPacket) bool {
	if c.handler == nil {
		return false
	}
	return c.handler(packet)
}

func TestRegisterMappedPacketReceiverReleasesRejectedMappedPacket(t *testing.T) {
	underlying := &mappedPacketReceiverTestConn{}
	var rawReleases atomic.Int32
	var mappedReleases atomic.Int32
	var gotData string

	_, ok := RegisterMappedPacketReceiver(
		underlying,
		func(packet *ReceivedPacket) bool {
			gotData = string(packet.Data)
			return false
		},
		func(packet *ReceivedPacket) (*ReceivedPacket, bool) {
			return NewReceivedPacket(
				append([]byte(nil), packet.Data...),
				packet.From,
				packet.Err,
				func() { mappedReleases.Add(1) },
			), true
		},
	)
	if !ok {
		t.Fatal("RegisterMappedPacketReceiver() returned false")
	}
	raw := NewReceivedPacket([]byte("raw"), netip.MustParseAddrPort("192.0.2.1:53"), nil, func() {
		rawReleases.Add(1)
	})
	if !underlying.emit(raw) {
		t.Fatal("mapped receiver callback rejected the consumed raw packet")
	}
	if gotData != "raw" {
		t.Fatalf("mapped packet data = %q, want copied raw payload", gotData)
	}
	if rawReleases.Load() != 1 || mappedReleases.Load() != 1 {
		t.Fatalf("release counts = raw:%d mapped:%d, want 1:1", rawReleases.Load(), mappedReleases.Load())
	}
}

func TestRegisterMappedPacketReceiverReleasesRawOnMappingFailure(t *testing.T) {
	underlying := &mappedPacketReceiverTestConn{}
	var releases atomic.Int32
	var handled atomic.Int32

	_, ok := RegisterMappedPacketReceiver(
		underlying,
		func(*ReceivedPacket) bool {
			handled.Add(1)
			return true
		},
		func(*ReceivedPacket) (*ReceivedPacket, bool) { return nil, false },
	)
	if !ok {
		t.Fatal("RegisterMappedPacketReceiver() returned false")
	}
	raw := NewReceivedPacket([]byte("malformed"), netip.AddrPort{}, nil, func() {
		releases.Add(1)
	})
	if !underlying.emit(raw) {
		t.Fatal("mapped receiver callback rejected the consumed malformed packet")
	}
	if releases.Load() != 1 || handled.Load() != 0 {
		t.Fatalf("release/handler counts = %d/%d, want 1/0", releases.Load(), handled.Load())
	}
}
