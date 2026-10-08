package direct

import (
	"net"
	"net/netip"
	"sync"
	"testing"
)

// TestDirectPacketConnConcurrentWriteWithRealUDP exercises the production
// FullCone Write path under concurrent target-cache access.
func TestDirectPacketConnConcurrentWriteWithRealUDP(t *testing.T) {
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve server address: %v", err)
	}

	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer func() { _ = serverConn.Close() }()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	targetAddr := serverConn.LocalAddr().(*net.UDPAddr).AddrPort()
	target := netip.AddrPortFrom(targetAddr.Addr().Unmap(), targetAddr.Port())
	conn := &directPacketConn{
		UDPConn:  clientConn,
		FullCone: true,
		dialTgt:  target.String(),
	}

	const goroutines = 10
	const writesPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < writesPerGoroutine; j++ {
				data := []byte("test data from goroutine")
				if _, err := conn.Write(data); err != nil {
					t.Errorf("Write() error = %v", err)
					return
				}
			}
		}(i)
	}

	wg.Wait()

	cached, ok := conn.cachedDialTgt.Load().(netip.AddrPort)
	if !ok {
		t.Fatal("concurrent writes did not initialize the target cache")
	}
	if cached != target {
		t.Fatalf("cached target = %v, want %v", cached, target)
	}
}

// BenchmarkDirectPacketConnWrite measures direct UDP write throughput.
func BenchmarkDirectPacketConnWrite(b *testing.B) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Skip("Failed to create server")
	}
	defer func() { _ = serverConn.Close() }()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Skip("Failed to create client")
	}
	defer func() { _ = clientConn.Close() }()

	target := serverConn.LocalAddr().(*net.UDPAddr).AddrPort()
	data := []byte("benchmark test data")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = clientConn.WriteToUDPAddrPort(data, target)
	}
}

// BenchmarkDirectPacketConnWriteParallel measures concurrent UDP writes.
func BenchmarkDirectPacketConnWriteParallel(b *testing.B) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Skip("Failed to create server")
	}
	defer func() { _ = serverConn.Close() }()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Skip("Failed to create client")
	}
	defer func() { _ = clientConn.Close() }()

	target := serverConn.LocalAddr().(*net.UDPAddr).AddrPort()
	data := []byte("benchmark test data")

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = clientConn.WriteToUDPAddrPort(data, target)
		}
	})
}
