// Package clientring provides the failover client ring shared by the QUIC
// based protocols (tuic, juicity): a circular list of live clients where a
// dial attempt walks to the next client on failover-class errors and spins
// up a new client when the ring is exhausted.
package clientring

import (
	"container/list"
	"context"
	"errors"
	"sync/atomic"

	outbounderrors "github.com/daeuniverse/outbound/common/errors"
	"golang.org/x/sync/semaphore"
)

// IsFailoverError reports whether err is one of the conditions the ring
// treats as "try the next client": stream exhaustion, a closed client, or
// the capability hold gate. Stream exhaustion additionally matches the
// quic-go native *quic.StreamLimitReachedError via its message, so a raw
// transport error fails over instead of aborting the attempt.
func IsFailoverError(err error) bool {
	return outbounderrors.IsStreamExhausted(err) ||
		errors.Is(err, outbounderrors.ErrClientClosed) ||
		errors.Is(err, outbounderrors.ErrOperationHold)
}

// Node is one ring entry: the protocol client plus its last reported
// capability. capability is written by quic-go's stream-table goroutine and
// read from dial attempts holding the ring lock; the atomic keeps that
// cross-goroutine pair race-free without coupling the two locks.
type Node[T any] struct {
	Client     T
	capability atomic.Int64
}

// Capability returns the node's last reported capability (-1 = unknown).
func (n *Node[T]) Capability() int64 {
	if n == nil {
		return -1
	}
	return n.capability.Load()
}

// Ring is the shared failover ring. The protocol-specific dial bodies are
// supplied as attempt callbacks, so only client construction, close, and
// close-registration differ per protocol.
//
// Every state operation (attempts, Len, passiveRemove, Close) holds the
// same single semaphore permit, so attempts serialize exactly as they did
// under the former mutex. A context-aware waiter blocked on the permit,
// however, returns as soon as its context is done instead of waiting for
// the holder to finish.
type Ring[T any] struct {
	sem        *semaphore.Weighted
	closed     bool
	ring       *list.List
	current    *list.Element
	newClient  func(capabilityCallback func(n int64)) T
	setOnClose func(T, func())
	close      func(T) error
	reserved   int64
}

// New constructs a ring. newClient builds a client and wires its capability
// feedback to the given callback; setOnClose registers a ring-removal hook
// on a client; close tears one down.
func New[T any](
	newClient func(capabilityCallback func(n int64)) T,
	setOnClose func(T, func()),
	close func(T) error,
	reserved int64,
) *Ring[T] {
	return &Ring[T]{
		sem:        semaphore.NewWeighted(1),
		ring:       list.New().Init(),
		newClient:  newClient,
		setOnClose: setOnClose,
		close:      close,
		reserved:   reserved,
	}
}

// TryNext runs one dial attempt against the current client, walking the ring
// on failover-class errors and inserting a fresh client when every existing
// one failed. The ring permit is held across attempts, matching the original
// per-protocol rings (dials on one ring serialize).
func (r *Ring[T]) TryNext(f func(node *Node[T]) error) error {
	return r.TryNextContext(context.Background(), f)
}

// TryNextContext cancels the permit wait and stops further attempts when ctx
// ends. The callback is responsible for observing ctx during an active dial;
// a successful callback result is returned unchanged.
func (r *Ring[T]) TryNextContext(ctx context.Context, f func(node *Node[T]) error) error {
	if err := r.sem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer r.sem.Release(1)
	if r.closed {
		return outbounderrors.ErrClientClosed
	}
	newCurrent := r.current
	err := r.tryNext(ctx, &newCurrent, f)
	r.current = newCurrent
	return err
}

func (r *Ring[T]) tryNext(ctx context.Context, current **list.Element, f func(*Node[T]) error) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	var node *Node[T]
	if *current == nil {
		goto getNew
	}
	node = (*current).Value.(*Node[T])
	err = f(node)
	if err == nil {
		// OK.
		return nil
	}
	if ctx.Err() != nil {
		// The caller gave up during this attempt: not a failover
		// condition, stop the walk here.
		return err
	}

	// Expected error: fail over to the next client.
	*current = (*current).Next()
	// NOTICE: Add the below code to reuse previous clients.
	{
		if *current == nil {
			*current = r.ring.Front()
		}
	}
	if *current == r.current {
		if IsFailoverError(err) {
			goto getNew
		}
		// Not the expected error.
		return err
	}

	return r.tryNext(ctx, current, f)

getNew:
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.closed {
		return outbounderrors.ErrClientClosed
	}
	newNode := &Node[T]{
		Client: *new(T),
	}
	// -1 = unknown until the first capability report arrives.
	newNode.capability.Store(-1)
	newCli := r.newClient(func(n int64) { newNode.capability.Store(n) })
	newNode.Client = newCli
	r.current = r.insertAfterCurrent(newNode)
	*current = r.current
	return f(newNode)
}

func (r *Ring[T]) insertAfterCurrent(node *Node[T]) (elem *list.Element) {
	if r.current == nil {
		elem = r.ring.PushBack(node)
		r.current = elem
	} else {
		elem = r.ring.InsertAfter(node, r.current)
	}
	r.setOnClose(node.Client, func() {
		r.passiveRemove(elem)
	})
	return elem
}

func (r *Ring[T]) passiveRemove(elem *list.Element) {
	if err := r.sem.Acquire(context.Background(), 1); err != nil {
		return
	}
	defer r.sem.Release(1)
	if elem.Value == nil {
		// Removed.
		return
	}
	elem.Value = nil
	if r.current == elem {
		r.current = elem.Next()
	}
	r.ring.Remove(elem)
}

// Len returns the number of clients currently held in the ring.
func (r *Ring[T]) Len() int {
	if err := r.sem.Acquire(context.Background(), 1); err != nil {
		return 0
	}
	defer r.sem.Release(1)
	return r.ring.Len()
}

// Close tears down every client in the ring.
func (r *Ring[T]) Close() error {
	if err := r.sem.Acquire(context.Background(), 1); err != nil {
		return err
	}
	r.closed = true
	clients := make([]T, 0, r.ring.Len())
	for elem := r.ring.Front(); elem != nil; {
		next := elem.Next()
		if node, ok := elem.Value.(*Node[T]); ok && node != nil {
			clients = append(clients, node.Client)
		}
		elem.Value = nil
		r.ring.Remove(elem)
		elem = next
	}
	r.current = nil
	r.sem.Release(1)

	for _, cli := range clients {
		_ = r.close(cli)
	}
	return nil
}
