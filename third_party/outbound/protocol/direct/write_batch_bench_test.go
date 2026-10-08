package direct

import (
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// Micro-benchmarks quantifying the per-datagram syscall cost of single write
// vs sendmmsg batching on a connected UDP socket (the socks5 relay shape).

func benchWithDrainServer(b *testing.B, fn func(conn *directPacketConn)) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		b.Fatalf("ListenUDP(server): %v", err)
	}
	defer func() { _ = server.Close() }()
	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		b.Fatalf("DialUDP(client): %v", err)
	}
	defer func() { _ = client.Close() }()
	// Drain the server socket so the client send buffer never fills.
	done := make(chan struct{})
	defer close(done)
	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = server.SetReadDeadline(time.Now().Add(time.Second))
			if _, _, err := server.ReadFromUDP(buf); err != nil {
				return
			}
		}
	}()
	conn := &directPacketConn{UDPConn: client, FullCone: false}
	fn(conn)
}

func BenchmarkDirectWriteSingle(b *testing.B) {
	benchWithDrainServer(b, func(conn *directPacketConn) {
		buf := make([]byte, 1200)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := conn.Write(buf); err != nil {
				b.Fatalf("Write: %v", err)
			}
		}
	})
}

func BenchmarkDirectWriteBatch32(b *testing.B) {
	benchWithDrainServer(b, func(conn *directPacketConn) {
		items := make([]netproxy.BatchItem, 32)
		for i := range items {
			items[i] = netproxy.BatchItem{Data: make([]byte, 1200)}
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := conn.WriteBatch(items); err != nil {
				b.Fatalf("WriteBatch: %v", err)
			}
		}
	})
}

func BenchmarkDirectWriteBatch8(b *testing.B) {
	benchWithDrainServer(b, func(conn *directPacketConn) {
		items := make([]netproxy.BatchItem, 8)
		for i := range items {
			items[i] = netproxy.BatchItem{Data: make([]byte, 1200)}
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := conn.WriteBatch(items); err != nil {
				b.Fatalf("WriteBatch: %v", err)
			}
		}
	})
}
