//go:build linux

package direct

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"
)

// slowHandlerEntry builds a hand-driven entry whose handler blocks on the
// returned channel, so a test can hold the delivery goroutine inside the
// handler.
func slowHandlerEntry(t *testing.T) (*directPacketReceiverEntry, int, chan *netproxy.ReceivedPacket, func()) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	entry := &directPacketReceiverEntry{fd: fds[0]}
	entry.active.Store(true)
	delivered := make(chan *netproxy.ReceivedPacket, 4)
	entry.handler = func(packet *netproxy.ReceivedPacket) bool {
		delivered <- packet
		return true
	}
	entry.startDelivery()
	return entry, fds[1], delivered, func() {
		entry.stopDelivery()
		entry.active.Store(false)
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	}
}

// TestDirectPacketReceiverDrainDoesNotRunHandler is the P3-38 regression:
// drain() used to call the handler inline on the shared epoll thread, so one
// slow handler stalled packet reception for every other registered socket. It
// must return as soon as the datagrams are queued.
func TestDirectPacketReceiverDrainDoesNotRunHandler(t *testing.T) {
	entry, peer, delivered, cleanup := slowHandlerEntry(t)
	defer cleanup()

	// Block the delivery goroutine inside the handler.
	release := make(chan struct{})
	var handlerOnce sync.Once
	blocked := make(chan struct{})
	entry.deliverMu.Lock()
	entry.handler = func(packet *netproxy.ReceivedPacket) bool {
		handlerOnce.Do(func() { close(blocked) })
		<-release
		packet.Release()
		return true
	}
	entry.deliverMu.Unlock()

	mustUnixSend(t, peer, []byte("first"))
	defaultPacketReceiverRegistry.drain(entry)
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("handler never ran")
	}

	// The handler is now wedged. drain() must still return promptly for a
	// second datagram instead of waiting for it.
	mustUnixSend(t, peer, []byte("second"))
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		defaultPacketReceiverRegistry.drain(entry)
	}()
	select {
	case <-drained:
	case <-time.After(2 * time.Second):
		t.Fatal("drain blocked on a slow handler: the shared epoll thread would stall every socket")
	}
	close(release)
	_ = delivered
}

// TestDirectPacketReceiverHandlerPanicIsContained is the P3-38 recover: the
// handler belongs to the caller (dae's udp_endpoint_watcher) and runs on a
// goroutine this package owns, so a panic in it would otherwise take down the
// process.
func TestDirectPacketReceiverHandlerPanicIsContained(t *testing.T) {
	entry, peer, _, cleanup := slowHandlerEntry(t)
	defer cleanup()

	delivered := make(chan string, 4)
	entry.deliverMu.Lock()
	entry.handler = func(packet *netproxy.ReceivedPacket) bool {
		data := string(packet.Data)
		packet.Release()
		if data == "boom" {
			panic("synthetic handler panic")
		}
		delivered <- data
		return true
	}
	entry.deliverMu.Unlock()

	mustUnixSend(t, peer, []byte("boom"))
	defaultPacketReceiverRegistry.drain(entry)
	mustUnixSend(t, peer, []byte("after"))
	defaultPacketReceiverRegistry.drain(entry)

	select {
	case got := <-delivered:
		if got != "after" {
			t.Fatalf("delivered %q, want %q", got, "after")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("delivery stopped after a handler panic; the registry must keep serving")
	}
}

// TestDirectPacketReceiverDeliverToHandlerReportsPanic pins the recover
// contract used by the registry-failure path: a panicking handler is reported
// as not-delivered rather than propagating.
func TestDirectPacketReceiverDeliverToHandlerReportsPanic(t *testing.T) {
	packet := netproxy.NewReceivedPacket(nil, netip.AddrPort{}, nil, nil)
	delivered, err := deliverToHandler(func(*netproxy.ReceivedPacket) bool {
		panic("synthetic")
	}, 7, packet)
	if delivered {
		t.Fatal("deliverToHandler reported delivery for a panicking handler")
	}
	if err == nil {
		t.Fatal("deliverToHandler swallowed the panic without reporting it")
	}
	packet.Release()
}

// TestDirectPacketReceiverStopReleasesQueuedPackets pins that retiring an entry
// releases datagrams the handler never saw, instead of leaking their pooled
// buffers.
func TestDirectPacketReceiverStopReleasesQueuedPackets(t *testing.T) {
	entry, _, _, _ := slowHandlerEntry(t)
	released := make(chan struct{}, 1)
	entry.deliverMu.Lock()
	entry.queued = append(entry.queued, netproxy.NewReceivedPacket([]byte("x"), netip.AddrPort{}, nil, func() {
		select {
		case released <- struct{}{}:
		default:
		}
	}))
	entry.deliverMu.Unlock()

	entry.stopDelivery()
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("queued packet buffer was not released by stopDelivery")
	}
}
