package shadowsocks_stream

import (
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

type recordingPacketConn struct {
	mu     sync.Mutex
	writes []recordedPacketWrite
}

type recordedPacketWrite struct {
	addr string
	data []byte
}

type receivingPacketConn struct {
	*recordingPacketConn
	handler netproxy.PacketReceiveHandler
}

func (c *receivingPacketConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	c.handler = handler
	return func() { c.handler = nil }, true
}

func (c *receivingPacketConn) emit(packet *netproxy.ReceivedPacket) bool {
	if c.handler == nil {
		return false
	}
	return c.handler(packet)
}

func (c *recordingPacketConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *recordingPacketConn) Write(p []byte) (int, error) {
	return c.WriteTo(p, "")
}

func (c *recordingPacketConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}

func (c *recordingPacketConn) WriteTo(p []byte, addr string) (int, error) {
	clone := append([]byte(nil), p...)
	c.mu.Lock()
	c.writes = append(c.writes, recordedPacketWrite{addr: addr, data: clone})
	c.mu.Unlock()
	return len(p), nil
}

func (c *recordingPacketConn) Close() error                     { return nil }
func (c *recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestUdpConnConcurrentWriteTo(t *testing.T) {
	t.Helper()

	recorder := &recordingPacketConn{}
	cipher, err := ciphers.NewStreamCipher("none", "password")
	if err != nil {
		t.Fatalf("NewStreamCipher failed: %v", err)
	}
	defaultAddr, err := socks.ParseAddr("1.1.1.1:53")
	if err != nil {
		t.Fatalf("ParseAddr default target failed: %v", err)
	}

	conn := NewUdpConn(recorder, cipher, defaultAddr, "127.0.0.1:8388")
	targets := []string{
		"1.1.1.1:53",
		"8.8.8.8:53",
		"9.9.9.9:53",
		"208.67.222.222:53",
	}

	var wg sync.WaitGroup
	for _, target := range targets {
		target := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := conn.WriteTo([]byte("payload-"+target), target); err != nil {
				t.Errorf("WriteTo(%s) failed: %v", target, err)
			}
		}()
	}
	wg.Wait()

	if len(recorder.writes) != len(targets) {
		t.Fatalf("unexpected write count: got %d want %d", len(recorder.writes), len(targets))
	}

	seen := make(map[string]bool, len(targets))
	for _, write := range recorder.writes {
		if write.addr != "127.0.0.1:8388" {
			t.Fatalf("unexpected proxy addr: got %q", write.addr)
		}
		addr := socks.SplitAddr(write.data)
		if addr == nil {
			t.Fatal("failed to parse encoded target addr")
		}
		target := addr.String()
		payload := string(write.data[len(addr):])
		if payload != "payload-"+target {
			t.Fatalf("payload mismatch for %s: got %q", target, payload)
		}
		seen[target] = true
	}

	for _, target := range targets {
		if !seen[target] {
			t.Fatalf("missing target write for %s", target)
		}
	}
}

func TestUdpConnWriteToCachesLastTarget(t *testing.T) {
	recorder := &recordingPacketConn{}
	cipher, err := ciphers.NewStreamCipher("none", "password")
	if err != nil {
		t.Fatalf("NewStreamCipher failed: %v", err)
	}
	defaultAddr, err := socks.ParseAddr("1.1.1.1:53")
	if err != nil {
		t.Fatalf("ParseAddr default target failed: %v", err)
	}

	conn := NewUdpConn(recorder, cipher, defaultAddr, "127.0.0.1:8388")

	oldParse := parseSocksAddr
	defer func() { parseSocksAddr = oldParse }()

	var calls atomic.Int32
	parseSocksAddr = func(addr string) (socks.Addr, error) {
		calls.Add(1)
		return oldParse(addr)
	}

	for i := 0; i < 2; i++ {
		if _, err := conn.WriteTo([]byte("payload"), "8.8.8.8:53"); err != nil {
			t.Fatalf("WriteTo() error = %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("ParseAddr() call count = %d, want 1", got)
	}
}

func TestUdpConnPacketReceiverDecodesPayloadAndSource(t *testing.T) {
	receiver := &receivingPacketConn{recordingPacketConn: &recordingPacketConn{}}
	cipher, err := ciphers.NewStreamCipher("none", "password")
	if err != nil {
		t.Fatalf("NewStreamCipher failed: %v", err)
	}
	defaultAddr, err := socks.ParseAddr("1.1.1.1:53")
	if err != nil {
		t.Fatalf("ParseAddr default target failed: %v", err)
	}
	conn := NewUdpConn(receiver, cipher, defaultAddr, "127.0.0.1:8388")
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
	write := receiver.writes[0]
	var rawReleased atomic.Int32
	if !receiver.emit(netproxy.NewReceivedPacket(append([]byte(nil), write.data...), netip.AddrPort{}, nil, func() {
		rawReleased.Add(1)
	})) {
		t.Fatal("receiver did not consume packet")
	}
	if got == nil {
		t.Fatal("handler did not receive packet")
	}
	if string(got.Data) != "payload" || got.From != netip.MustParseAddrPort("8.8.8.8:53") {
		t.Fatalf("decoded packet = data:%q from:%s", got.Data, got.From)
	}
	got.Release()
	if rawReleased.Load() != 1 {
		t.Fatalf("raw release count = %d, want 1", rawReleased.Load())
	}
	stop()
}

func TestUdpTransportConnPacketReceiverDecryptsWithoutSource(t *testing.T) {
	receiver := &receivingPacketConn{recordingPacketConn: &recordingPacketConn{}}
	cipher, err := ciphers.NewStreamCipher("none", "password")
	if err != nil {
		t.Fatalf("NewStreamCipher failed: %v", err)
	}
	conn := &UdpTransportConn{UdpConn: NewUdpConn(receiver, cipher, nil, "127.0.0.1:8388")}
	if _, err := conn.Write([]byte("transport-payload")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var got *netproxy.ReceivedPacket
	stop, ok := conn.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
		got = packet
		return true
	})
	if !ok || stop == nil {
		t.Fatal("RegisterPacketReceiver() did not register")
	}
	if !receiver.emit(netproxy.NewReceivedPacket(append([]byte(nil), receiver.writes[0].data...), netip.MustParseAddrPort("192.0.2.1:443"), nil, nil)) {
		t.Fatal("receiver did not consume transport packet")
	}
	if got == nil || string(got.Data) != "transport-payload" || got.From.IsValid() {
		t.Fatalf("transport packet = %+v, want payload with invalid source", got)
	}
	got.Release()
	stop()
}
