//go:build linux

package direct

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"
)

func TestDirectPacketReceiverMultiplexesSockets(t *testing.T) {
	server1 := mustListenDirectReceiverUDP(t)
	server2 := mustListenDirectReceiverUDP(t)
	client1 := mustListenDirectReceiverUDP(t)
	client2 := mustListenDirectReceiverUDP(t)
	defer server1.Close()
	defer server2.Close()
	defer client1.Close()
	defer client2.Close()

	conn1 := &directPacketConn{UDPConn: client1, FullCone: true, receiver: defaultPacketReceiverRegistry}
	conn2 := &directPacketConn{UDPConn: client2, FullCone: true, receiver: defaultPacketReceiverRegistry}
	defer conn1.Close()
	defer conn2.Close()

	packets1 := make(chan *netproxy.ReceivedPacket, 1)
	packets2 := make(chan *netproxy.ReceivedPacket, 1)
	stop1, ok := conn1.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
		packets1 <- packet
		return true
	})
	if !ok {
		t.Fatal("conn1 RegisterPacketReceiver() = false")
	}
	stop2, ok := conn2.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
		packets2 <- packet
		return true
	})
	if !ok {
		t.Fatal("conn2 RegisterPacketReceiver() = false")
	}

	defaultPacketReceiverRegistry.mu.RLock()
	registered := len(defaultPacketReceiverRegistry.entries)
	epollFD := defaultPacketReceiverRegistry.epollFD
	defaultPacketReceiverRegistry.mu.RUnlock()
	if registered < 2 || epollFD < 0 {
		t.Fatalf("registry state = entries:%d epollFD:%d, want two entries and one epoll fd", registered, epollFD)
	}

	writeDirectReceiverPacket(t, server1, client1, []byte("one"))
	writeDirectReceiverPacket(t, server2, client2, []byte("two"))

	assertDirectReceiverPacket(t, packets1, "one", server1.LocalAddr().(*net.UDPAddr).AddrPort())
	assertDirectReceiverPacket(t, packets2, "two", server2.LocalAddr().(*net.UDPAddr).AddrPort())

	stop1()
	stop1()
	stop2()
	stop2()

	defaultPacketReceiverRegistry.mu.RLock()
	remaining := len(defaultPacketReceiverRegistry.entries)
	defaultPacketReceiverRegistry.mu.RUnlock()
	if remaining != 0 {
		t.Fatalf("registry entries after unregister = %d, want 0", remaining)
	}
}

func TestDirectPacketReceiverRejectsSecondRegistrationAndCloseUnregisters(t *testing.T) {
	server := mustListenDirectReceiverUDP(t)
	client := mustListenDirectReceiverUDP(t)
	defer server.Close()
	defer client.Close()
	conn := &directPacketConn{UDPConn: client, FullCone: true, receiver: defaultPacketReceiverRegistry}

	stop, ok := conn.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
		packet.Release()
		return true
	})
	if !ok {
		t.Fatal("RegisterPacketReceiver() = false")
	}
	if _, ok := conn.RegisterPacketReceiver(func(*netproxy.ReceivedPacket) bool { return true }); ok {
		t.Fatal("second RegisterPacketReceiver() = true, want false")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	stop()

	defaultPacketReceiverRegistry.mu.RLock()
	remaining := len(defaultPacketReceiverRegistry.entries)
	defaultPacketReceiverRegistry.mu.RUnlock()
	if remaining != 0 {
		t.Fatalf("registry entries after Close = %d, want 0", remaining)
	}
}

func newUnixDatagramReceiverEntry(t *testing.T) (*directPacketReceiverEntry, int, func()) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	entry := &directPacketReceiverEntry{fd: fds[0]}
	entry.active.Store(true)
	// Delivery is decoupled from the epoll thread, so a hand-built entry needs
	// the same delivery goroutine register() starts: the handler now runs
	// there, not on the caller of drain().
	entry.startDelivery()
	return entry, fds[1], func() {
		entry.stopDelivery()
		entry.active.Store(false)
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	}
}

func mustUnixSend(t *testing.T, fd int, payload []byte) {
	t.Helper()
	if err := unix.Send(fd, payload, 0); err != nil {
		n, sendErr := unix.Write(fd, payload)
		if sendErr != nil || n != len(payload) {
			t.Fatalf("send datagram: send=%v write=%v n=%d", err, sendErr, n)
		}
	}
}

func mustListenDirectReceiverUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	return conn
}

func writeDirectReceiverPacket(t *testing.T, server, client *net.UDPConn, payload []byte) {
	t.Helper()
	if _, err := server.WriteToUDP(payload, client.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("WriteToUDP() error = %v", err)
	}
}

func assertDirectReceiverPacket(t *testing.T, packets <-chan *netproxy.ReceivedPacket, wantData string, wantFrom netip.AddrPort) {
	t.Helper()
	select {
	case packet := <-packets:
		if packet == nil {
			t.Fatal("received nil packet")
		}
		if packet.Err != nil {
			t.Fatalf("received packet error = %v", packet.Err)
		}
		if string(packet.Data) != wantData {
			t.Fatalf("received packet data = %q, want %q", packet.Data, wantData)
		}
		if !wantFrom.IsValid() {
			// Unix-datagram injection has no IP peer.
		} else if packet.From != wantFrom {
			t.Fatalf("received packet from = %s, want %s", packet.From, wantFrom)
		}
		packet.Release()
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %q", wantData)
	}
}

func TestDirectPacketReceiverDeliversBelow8KiBOnSmallTier(t *testing.T) {
	if directPacketReceiverSmallBufferSize < 8192 {
		t.Fatalf("small tier = %d, want >= 8192", directPacketReceiverSmallBufferSize)
	}
	entry, peer, cleanup := newUnixDatagramReceiverEntry(t)
	defer cleanup()

	packets := make(chan *netproxy.ReceivedPacket, 2)
	entry.handler = func(packet *netproxy.ReceivedPacket) bool {
		packets <- packet
		return true
	}

	small := bytes.Repeat([]byte("a"), 1200)
	mid := bytes.Repeat([]byte("b"), 3000)
	mustUnixSend(t, peer, small)
	defaultPacketReceiverRegistry.drain(entry)
	assertDirectReceiverPacket(t, packets, string(small), netip.AddrPort{})
	mustUnixSend(t, peer, mid)
	defaultPacketReceiverRegistry.drain(entry)
	assertDirectReceiverPacket(t, packets, string(mid), netip.AddrPort{})
}

func TestDirectPacketReceiverDeliversFirstJumboDatagram(t *testing.T) {
	entry, peer, cleanup := newUnixDatagramReceiverEntry(t)
	defer cleanup()

	packets := make(chan *netproxy.ReceivedPacket, 2)
	entry.handler = func(packet *netproxy.ReceivedPacket) bool {
		packets <- packet
		return true
	}

	jumbo := bytes.Repeat([]byte("z"), 20000)
	mustUnixSend(t, peer, jumbo)
	defaultPacketReceiverRegistry.drain(entry)
	assertDirectReceiverPacket(t, packets, string(jumbo), netip.AddrPort{})

	small := bytes.Repeat([]byte("s"), 512)
	mustUnixSend(t, peer, small)
	defaultPacketReceiverRegistry.drain(entry)
	assertDirectReceiverPacket(t, packets, string(small), netip.AddrPort{})
}
