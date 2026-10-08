package direct

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestDirectPacketConnWriteToUsesDialTargetCache(t *testing.T) {
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	defer func() { _ = serverConn.Close() }()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	target := serverConn.LocalAddr().String()
	conn := &directPacketConn{
		UDPConn:  clientConn,
		FullCone: true,
		dialTgt:  target,
		resolver: net.DefaultResolver,
	}

	oldResolve := resolveUDPAddr
	defer func() { resolveUDPAddr = oldResolve }()

	var calls atomic.Int32
	resolveUDPAddr = func(resolver *net.Resolver, hostport string) (*net.UDPAddr, error) {
		calls.Add(1)
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			uint16(serverConn.LocalAddr().(*net.UDPAddr).Port),
		)), nil
	}

	for i := 0; i < 2; i++ {
		if _, err := conn.WriteTo([]byte("ping"), target); err != nil {
			t.Fatalf("WriteTo() error = %v", err)
		}
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("resolveUDPAddr() call count = %d, want 1", got)
	}
}

func TestDirectPacketConnWriteToCachesAlternateTarget(t *testing.T) {
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	defer func() { _ = serverConn.Close() }()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	target := serverConn.LocalAddr().String()
	conn := &directPacketConn{
		UDPConn:  clientConn,
		FullCone: true,
		dialTgt:  "127.0.0.1:1",
		resolver: net.DefaultResolver,
	}

	oldResolve := resolveUDPAddr
	defer func() { resolveUDPAddr = oldResolve }()

	var calls atomic.Int32
	resolveUDPAddr = func(resolver *net.Resolver, hostport string) (*net.UDPAddr, error) {
		calls.Add(1)
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			uint16(serverConn.LocalAddr().(*net.UDPAddr).Port),
		)), nil
	}

	for i := 0; i < 2; i++ {
		if _, err := conn.WriteTo([]byte("ping"), target); err != nil {
			t.Fatalf("WriteTo() error = %v", err)
		}
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("resolveUDPAddr() call count = %d, want 1", got)
	}
}
