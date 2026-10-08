//go:build linux

package direct

import (
	"fmt"
	"net/netip"
	"runtime/debug"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/logger"
	"github.com/daeuniverse/outbound/pool"
	"golang.org/x/sys/unix"
)

const (
	directPacketReceiverBufferSize = 65535
	// Small tier covers EDNS/DNSSEC and almost all QUIC initial/handshake
	// datagrams. The receiver peeks only the datagram length, then consumes it
	// into the smallest fitting tier so a queue never permanently pins 64 KiB
	// buffers and the first jumbo datagram is preserved.
	directPacketReceiverSmallBufferSize = 8192
	directPacketReceiverBatchSize       = 64
)

// packetReceiverRegistry multiplexes direct UDP sockets through one Linux
// epoll reader. The socket itself remains owned by its logical PacketConn;
// only packet readiness and delivery are shared.
type packetReceiverRegistry struct {
	mu      sync.RWMutex
	started bool
	epollFD int
	entries map[int]*directPacketReceiverEntry
}

type directPacketReceiverEntry struct {
	fd      int
	handler netproxy.PacketReceiveHandler
	active  atomic.Bool
	// pending queues datagrams fetched from the socket by the epoll thread.
	// Only the epoll thread touches it, so the slice is reused.
	pending []*netproxy.ReceivedPacket

	// deliverMu guards queued/signal, the handoff between the epoll thread
	// (producer) and this entry's delivery goroutine (consumer). Delivery is
	// decoupled from the epoll thread so one slow or wedged handler cannot
	// stall packet reception on every other socket registered in the shared
	// registry.
	deliverMu sync.Mutex
	queued    []*netproxy.ReceivedPacket
	signal    chan struct{}
	stopped   bool
}

var defaultPacketReceiverRegistry = &packetReceiverRegistry{}

func newPacketReceiverRegistry() *packetReceiverRegistry {
	return defaultPacketReceiverRegistry
}

// RegisterPacketReceiver delivers direct UDP datagrams through the shared
// Linux epoll reader instead of starting one blocking reader per socket.
func (c *directPacketConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	if c == nil || c.receiver == nil || handler == nil || c.UDPConn == nil {
		return nil, false
	}

	c.receiverMu.Lock()
	if c.receiverStop != nil {
		c.receiverMu.Unlock()
		return nil, false
	}
	c.receiverGeneration++
	generation := c.receiverGeneration
	entry := &directPacketReceiverEntry{handler: handler}
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			entry.active.Store(false)
			c.receiver.unregister(entry)
			c.receiverMu.Lock()
			if c.receiverGeneration == generation {
				c.receiverStop = nil
			}
			c.receiverMu.Unlock()
		})
	}
	c.receiverStop = stop
	if !c.receiver.register(c, entry) {
		c.receiverStop = nil
		c.receiverMu.Unlock()
		return nil, false
	}
	c.receiverMu.Unlock()
	return stop, true
}

func (r *packetReceiverRegistry) register(conn *directPacketConn, entry *directPacketReceiverEntry) bool {
	if conn == nil || entry == nil || entry.handler == nil {
		return false
	}
	fd, err := directPacketReceiverFD(conn)
	if err != nil {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ensureStartedLocked() {
		return false
	}
	if _, exists := r.entries[fd]; exists {
		return false
	}
	entry.fd = fd
	entry.active.Store(true)
	entry.startDelivery()
	r.entries[fd] = entry
	event := &unix.EpollEvent{
		Events: unix.EPOLLIN | unix.EPOLLERR | unix.EPOLLHUP,
		Fd:     int32(fd),
	}
	if err := unix.EpollCtl(r.epollFD, unix.EPOLL_CTL_ADD, fd, event); err != nil {
		delete(r.entries, fd)
		entry.active.Store(false)
		return false
	}
	return true
}

func (r *packetReceiverRegistry) unregister(entry *directPacketReceiverEntry) {
	if r == nil || entry == nil {
		return
	}
	entry.active.Store(false)
	entry.stopDelivery()
	r.mu.Lock()
	if current, ok := r.entries[entry.fd]; ok && current == entry {
		delete(r.entries, entry.fd)
		if r.started {
			_ = unix.EpollCtl(r.epollFD, unix.EPOLL_CTL_DEL, entry.fd, nil)
		}
	}
	r.mu.Unlock()
}

func (r *packetReceiverRegistry) ensureStartedLocked() bool {
	if r.started {
		return r.epollFD >= 0
	}
	epollFD, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return false
	}
	r.started = true
	r.epollFD = epollFD
	r.entries = make(map[int]*directPacketReceiverEntry)
	go r.loop(epollFD)
	return true
}

func (r *packetReceiverRegistry) loop(epollFD int) {
	events := make([]unix.EpollEvent, 64)
	for {
		n, err := unix.EpollWait(epollFD, events, -1)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			// Non-EINTR failures on a valid epoll fd are unrecoverable
			// kernel conditions. A dead wait loop would silently
			// blackhole every socket registered after it: tear the
			// registry down so the next registration starts a fresh
			// loop, and surface the failure to registered endpoints.
			r.fail(epollFD, err)
			return
		}
		for i := 0; i < n; i++ {
			fd := int(events[i].Fd)
			r.mu.RLock()
			entry := r.entries[fd]
			r.mu.RUnlock()
			if entry != nil {
				r.drain(entry)
			}
		}
	}
}

// fail retires a registry whose wait loop hit an unrecoverable error:
// registered endpoints are told the receiver is gone, and the next
// registration starts a fresh loop instead of feeding a dead epoll set.
func (r *packetReceiverRegistry) fail(epollFD int, cause error) {
	r.mu.Lock()
	if !r.started || r.epollFD != epollFD {
		// Already replaced or torn down by another path.
		r.mu.Unlock()
		return
	}
	_ = unix.Close(epollFD)
	r.started = false
	r.epollFD = -1
	failed := r.entries
	r.entries = make(map[int]*directPacketReceiverEntry)
	r.mu.Unlock()

	errPacket := fmt.Errorf("direct packet receiver: %w", cause)
	for _, entry := range failed {
		if entry.active.Swap(false) {
			entry.stopDelivery()
			packet := netproxy.NewReceivedPacket(nil, netip.AddrPort{}, errPacket, nil)
			if _, err := deliverToHandler(entry.handler, entry.fd, packet); err != nil {
				packet.Release()
			}
		}
	}
}

// drain fetches queued datagrams from the socket and queues them for this
// entry's delivery goroutine. It runs on the shared epoll thread and must stay
// cheap: the handler is never invoked here.
func (r *packetReceiverRegistry) drain(entry *directPacketReceiverEntry) {
	r.fetch(entry)
	entry.enqueuePending()
}

// fetch drains up to directPacketReceiverBatchSize datagrams into the
// entry's pending queue. The read lock is held across the recvfrom
// syscalls: unregister takes the write lock before the socket is closed
// downstream, so an in-flight recvfrom can never race fd close and
// number reuse. The socket is non-blocking, so the lock never covers a
// blocking syscall.
func (r *packetReceiverRegistry) fetch(entry *directPacketReceiverEntry) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry.pending = entry.pending[:0]
	for range directPacketReceiverBatchSize {
		if !entry.active.Load() {
			return
		}
		var peek [1]byte
		packetLen, _, err := unix.Recvfrom(entry.fd, peek[:], unix.MSG_DONTWAIT|unix.MSG_PEEK|unix.MSG_TRUNC)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				if err == unix.EINTR {
					continue
				}
				return
			}
			entry.pending = append(entry.pending, netproxy.NewReceivedPacket(nil, netip.AddrPort{}, err, nil))
			return
		}
		bufSize := directPacketReceiverSmallBufferSize
		if packetLen > bufSize {
			bufSize = packetLen
			if bufSize > directPacketReceiverBufferSize {
				bufSize = directPacketReceiverBufferSize
			}
		}
		buf := pool.GetFullCap(bufSize)
		n, sockaddr, err := unix.Recvfrom(entry.fd, buf, unix.MSG_DONTWAIT)
		if err != nil {
			pool.Put(buf)
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				if err == unix.EINTR {
					continue
				}
				return
			}
			entry.pending = append(entry.pending, netproxy.NewReceivedPacket(nil, netip.AddrPort{}, err, nil))
			return
		}

		from, ok := directPacketReceiverAddrPort(sockaddr)
		if !ok {
			pool.Put(buf)
			entry.pending = append(entry.pending, netproxy.NewReceivedPacket(nil, netip.AddrPort{}, fmt.Errorf("unsupported direct UDP peer address %T", sockaddr), nil))
			return
		}
		packet := netproxy.NewReceivedPacket(buf[:n], from, nil, func() {
			pool.Put(buf)
		})
		entry.pending = append(entry.pending, packet)
	}
}

// enqueuePending moves the freshly fetched datagrams onto the delivery queue
// and wakes the delivery goroutine. Runs on the epoll thread.
func (e *directPacketReceiverEntry) enqueuePending() {
	if len(e.pending) == 0 {
		return
	}
	e.deliverMu.Lock()
	if e.stopped {
		// The entry was stopped between the fetch and the handoff: release
		// the datagrams here so their pool buffers are not leaked.
		for _, packet := range e.pending {
			packet.Release()
		}
		e.pending = e.pending[:0]
		e.deliverMu.Unlock()
		return
	}
	e.queued = append(e.queued, e.pending...)
	e.pending = e.pending[:0]
	signal := e.signal
	e.deliverMu.Unlock()

	if signal == nil {
		return
	}
	select {
	case signal <- struct{}{}:
	default:
		// A wakeup is already pending; the consumer drains the whole queue on
		// every pass, so this one is redundant rather than lost.
	}
}

// startDelivery launches this entry's delivery goroutine. The channel is
// created here and never re-created, so the producer can always send on it
// without racing a nil channel; the consumer may exit into a select that still
// has a valid channel operand.
func (e *directPacketReceiverEntry) startDelivery() {
	e.deliverMu.Lock()
	if e.signal != nil {
		e.deliverMu.Unlock()
		return
	}
	signal := make(chan struct{}, 1)
	e.signal = signal
	e.deliverMu.Unlock()
	go e.deliverLoop(signal)
}

// deliverLoop hands queued datagrams to the handler off the epoll thread.
func (e *directPacketReceiverEntry) deliverLoop(signal chan struct{}) {
	for {
		e.deliverMu.Lock()
		batch := e.queued
		e.queued = nil
		stopped := e.stopped
		e.deliverMu.Unlock()

		if len(batch) > 0 {
			e.deliverBatch(batch)
			continue
		}
		if stopped {
			// The batch above was the whole queue, so the entry is drained and
			// the consumer can exit. stopDelivery's wakeup may already be
			// buffered; nothing waits on this goroutine, so it is dropped.
			return
		}
		select {
		case <-signal:
		}
	}
}

// deliverBatch invokes the handler for each packet, then releases whatever the
// handler did not take ownership of.
func (e *directPacketReceiverEntry) deliverBatch(batch []*netproxy.ReceivedPacket) {
	for _, packet := range batch {
		if !e.active.Load() || !e.deliverToHandler(packet) {
			packet.Release()
		}
	}
}

func (e *directPacketReceiverEntry) deliverToHandler(packet *netproxy.ReceivedPacket) bool {
	delivered, _ := deliverToHandler(e.handler, e.fd, packet)
	return delivered
}

// deliverToHandler runs one user handler call under a recover. The handler
// belongs to the caller (dae's udp_endpoint_watcher), and a panic in it would
// otherwise take down the process: this goroutine is not the caller's, so
// nothing else would contain it. The panic is logged with its stack and the
// packet is reported as not delivered; the registry keeps serving every other
// socket.
func deliverToHandler(handler netproxy.PacketReceiveHandler, fd int, packet *netproxy.ReceivedPacket) (delivered bool, panicked error) {
	defer func() {
		if r := recover(); r != nil {
			logger.Logger.WithFields(map[string]any{
				"fd":    fd,
				"from":  packet.From.String(),
				"panic": fmt.Sprint(r),
				"stack": string(debug.Stack()),
			}).Error("direct: panic in packet receive handler")
			delivered = false
			panicked = fmt.Errorf("panic in packet receive handler: %v", r)
		}
	}()
	return handler(packet), nil
}

// stopDelivery retires the delivery goroutine and releases anything it had not
// handed over yet.
func (e *directPacketReceiverEntry) stopDelivery() {
	e.deliverMu.Lock()
	e.stopped = true
	pending := e.queued
	e.queued = nil
	signal := e.signal
	e.deliverMu.Unlock()
	for _, packet := range pending {
		packet.Release()
	}
	if signal != nil {
		select {
		case signal <- struct{}{}:
		default:
		}
	}
}

func directPacketReceiverFD(conn *directPacketConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	fd := -1
	if err := raw.Control(func(rawFD uintptr) {
		fd = int(rawFD)
	}); err != nil {
		return -1, err
	}
	if fd < 0 {
		return -1, fmt.Errorf("invalid direct UDP socket descriptor")
	}
	return fd, nil
}

func directPacketReceiverAddrPort(sockaddr unix.Sockaddr) (netip.AddrPort, bool) {
	switch addr := sockaddr.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(addr.Addr), uint16(addr.Port)), true
	case *unix.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(addr.Addr), uint16(addr.Port)), true
	case *unix.SockaddrUnix:
		// Production sockets are UDP; unnamed unix datagrams are used by
		// tests to inject oversize payloads past this environment's
		// loopback UDP ~1472-byte ceiling.
		return netip.AddrPort{}, true
	case nil:
		// Recvfrom on a connected socket (including SOCK_DGRAM socketpair)
		// reports no peer address.
		return netip.AddrPort{}, true
	default:
		return netip.AddrPort{}, false
	}
}
