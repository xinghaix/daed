package shadowsocks

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

type mockShadowsocksPacketConn struct {
	writes int64
}

func (m *mockShadowsocksPacketConn) Read(b []byte) (n int, err error) {
	return 0, nil
}

func (m *mockShadowsocksPacketConn) Write(b []byte) (n int, err error) {
	atomic.AddInt64(&m.writes, 1)
	time.Sleep(10 * time.Microsecond) // simulate latency
	return len(b), nil
}

func (m *mockShadowsocksPacketConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	return 0, netip.AddrPort{}, nil
}

func (m *mockShadowsocksPacketConn) WriteTo(p []byte, addr string) (n int, err error) {
	atomic.AddInt64(&m.writes, 1)
	time.Sleep(10 * time.Microsecond) // simulate latency
	return len(p), nil
}

func (m *mockShadowsocksPacketConn) Close() error {
	return nil
}

func (m *mockShadowsocksPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockShadowsocksPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockShadowsocksPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func newRaceTestUDPConn(tb testing.TB, conn *mockShadowsocksPacketConn) *UdpConn {
	tb.Helper()

	metadata := protocol.Metadata{
		Type:     protocol.MetadataTypeIPv4,
		Hostname: "127.0.0.1",
		Port:     8080,
		Cipher:   "aes-128-gcm",
	}

	udpConn, err := NewUdpConn(conn, "127.0.0.1:8388", metadata, make([]byte, 16), nil)
	if err != nil {
		tb.Fatalf("NewUdpConn() error = %v", err)
	}
	return udpConn
}

func TestShadowsocksUdpConnWriteToRace(t *testing.T) {
	mockConn := &mockShadowsocksPacketConn{}
	udpConn := newRaceTestUDPConn(t, mockConn)

	const goroutines = 10
	const writesPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < writesPerGoroutine; j++ {
				data := []byte("test data from goroutine")
				_, err := udpConn.WriteTo(data, "127.0.0.1:9090")
				if err != nil {
					t.Errorf("WriteTo(%d, %d) returned unexpected error: %v", id, j, err)
				}
			}
		}(i)
	}

	wg.Wait()

	writes := atomic.LoadInt64(&mockConn.writes)
	t.Logf("Total WriteTo calls: %d", writes)
}

func TestShadowsocksUdpConnWriteRace(t *testing.T) {
	mockConn := &mockShadowsocksPacketConn{}
	udpConn := newRaceTestUDPConn(t, mockConn)

	const goroutines = 10
	const writesPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < writesPerGoroutine; j++ {
				data := []byte("test data")
				_, err := udpConn.Write(data)
				if err != nil {
					t.Errorf("Write(%d, %d) returned unexpected error: %v", id, j, err)
				}
			}
		}(i)
	}

	wg.Wait()

	t.Logf("Completed concurrent Write test")
}

func TestShadowsocksUdpConnBufferPoolRace(t *testing.T) {
	const goroutines = 20
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()

			for j := 0; j < opsPerGoroutine; j++ {
				buf := pool.Get(1500)
				copy(buf, []byte("test data"))
				pool.Put(buf)
			}
		}()
	}

	wg.Wait()

	t.Log("Buffer pool concurrent access test completed")
}

// TestShadowsocksUdpConnRealConnection tests with a real UDP connection
func TestShadowsocksUdpConnRealConnection(t *testing.T) {
	// Create the UDP server
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve server address: %v", err)
	}

	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer func() { _ = serverConn.Close() }()

	// Server side that receives
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			t.Logf("Server received %d bytes from %v", n, addr)
		}
	}()

	// Create the client connection
	clientConn, err := net.Dial("udp", serverConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	// Wrapping this as a netproxy.PacketConn is required but not implemented
	t.Skip("Requires netproxy.PacketConn implementation")
}

// BenchmarkShadowsocksUdpConnWrite is the sequential write benchmark
func BenchmarkShadowsocksUdpConnWrite(b *testing.B) {
	mockConn := &mockShadowsocksPacketConn{}
	udpConn := newRaceTestUDPConn(b, mockConn)

	data := []byte("benchmark test data")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = udpConn.Write(data)
	}
}

// BenchmarkShadowsocksUdpConnWriteParallel is the parallel write benchmark
func BenchmarkShadowsocksUdpConnWriteParallel(b *testing.B) {
	mockConn := &mockShadowsocksPacketConn{}
	udpConn := newRaceTestUDPConn(b, mockConn)

	data := []byte("benchmark test data")

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = udpConn.Write(data)
		}
	})
}

// TestShadowsocksUdpConnMetadataParseRace tests the concurrency safety of
// metadata parsing
func TestShadowsocksUdpConnMetadataParseRace(t *testing.T) {
	const goroutines = 20
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < opsPerGoroutine; j++ {
				addr := "127.0.0.1:8080"
				_, err := protocol.ParseMetadata(addr)
				if err != nil {
					t.Errorf("Goroutine %d parse %d failed: %v", id, j, err)
				}
			}
		}(i)
	}

	wg.Wait()
}
