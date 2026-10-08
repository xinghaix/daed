package clientring

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	outbounderrors "github.com/daeuniverse/outbound/common/errors"
)

func newCountingRing() (*Ring[*fakeClient], *atomic.Int32, *atomic.Int32) {
	var constructed, closed atomic.Int32
	r := New(func(func(int64)) *fakeClient {
		constructed.Add(1)
		return &fakeClient{id: int(constructed.Load())}
	}, func(*fakeClient, func()) {}, func(*fakeClient) error {
		closed.Add(1)
		return nil
	}, 0)
	return r, &constructed, &closed
}

// primeTwoClientRing inserts two clients without walking: each priming
// attempt fails on its freshly created node and returns directly.
func primeTwoClientRing(t *testing.T) (*Ring[*fakeClient], *atomic.Int32) {
	t.Helper()
	r, constructed, _ := newCountingRing()
	for i := 0; i < 2; i++ {
		if err := r.TryNext(func(*Node[*fakeClient]) error {
			return outbounderrors.ErrOperationHold
		}); !errors.Is(err, outbounderrors.ErrOperationHold) {
			t.Fatalf("priming TryNext() = %v, want hold on", err)
		}
	}
	if got := r.Len(); got != 2 {
		t.Fatalf("ring length after priming = %d, want 2", got)
	}
	return r, constructed
}

// A canceled context must fail the attempt before the callback runs and
// before any client is constructed: no association, no dial, no leak.
func TestTryNextContextCanceledFailsWithoutCallbackOrConstruction(t *testing.T) {
	r, constructed, _ := newCountingRing()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := r.TryNextContext(ctx, func(*Node[*fakeClient]) error {
		t.Error("callback invoked despite canceled context")
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("TryNextContext(canceled) = %v, want context.Canceled", err)
	}
	if constructed.Load() != 0 {
		t.Fatalf("canceled walk constructed %d clients", constructed.Load())
	}
	if r.Len() != 0 {
		t.Fatalf("canceled walk mutated the ring: len = %d", r.Len())
	}
}

// A waiter canceled while the permit is held by a long attempt must return
// promptly with its context error; the holder's attempt must be untouched.
func TestTryNextContextCanceledWaiterReturnsBeforeHolderRelease(t *testing.T) {
	r, _, _ := newCountingRing()

	holderStarted := make(chan struct{})
	releaseHolder := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- r.TryNext(func(*Node[*fakeClient]) error {
			close(holderStarted)
			<-releaseHolder
			return nil
		})
	}()
	<-holderStarted

	ctx, cancel := context.WithCancel(context.Background())
	waiterDone := make(chan error, 1)
	go func() {
		waiterDone <- r.TryNextContext(ctx, func(*Node[*fakeClient]) error {
			t.Error("canceled waiter ran its callback")
			return nil
		})
	}()

	// Give the waiter time to block on the held permit, then cancel it.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-waiterDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled waiter error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled waiter still blocked on the held ring permit")
	}

	select {
	case <-holderDone:
		t.Fatal("holder attempt finished before its release gate was closed")
	default:
	}
	close(releaseHolder)
	if err := <-holderDone; err != nil {
		t.Fatalf("holder attempt error = %v", err)
	}
}

// A callback whose caller canceled mid-attempt is not a failover condition:
// the walk must stop instead of trying the next client or spawning one.
func TestTryNextContextCanceledCallbackStopsFailover(t *testing.T) {
	r, constructed := primeTwoClientRing(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attempts := 0
	err := r.TryNextContext(ctx, func(*Node[*fakeClient]) error {
		attempts++
		cancel() // caller gives up during the first attempt
		return outbounderrors.ErrOperationHold
	})
	if !errors.Is(err, outbounderrors.ErrOperationHold) {
		t.Fatalf("TryNextContext() = %v, want the attempt error", err)
	}
	if attempts != 1 {
		t.Fatalf("walk continued after cancellation: attempts = %d", attempts)
	}
	if r.Len() != 2 {
		t.Fatalf("canceled walk changed ring length: %d, want 2", r.Len())
	}
	if constructed.Load() != 2 {
		t.Fatalf("canceled walk constructed clients: %d, want 2", constructed.Load())
	}
}

// Cancellation checked between attempts stops the walk even when the
// previous attempt reported success: a completed attempt stays a success,
// but no further client is attempted.
func TestTryNextContextCancelBetweenAttemptsStopsWalk(t *testing.T) {
	r, constructed := primeTwoClientRing(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attempts := 0
	err := r.TryNextContext(ctx, func(*Node[*fakeClient]) error {
		attempts++
		cancel()
		return nil
	})
	if err != nil {
		t.Fatalf("TryNextContext() = %v, want nil (the attempt completed)", err)
	}
	if attempts != 1 {
		t.Fatalf("walk continued after cancellation: attempts = %d", attempts)
	}
	if constructed.Load() != 2 {
		t.Fatalf("canceled walk constructed clients: %d, want 2", constructed.Load())
	}
}

// A live context must preserve the ordinary failover walk.
func TestTryNextContextLiveContextPreservesFailover(t *testing.T) {
	r, constructed := primeTwoClientRing(t)

	attempts := 0
	err := r.TryNextContext(context.Background(), func(*Node[*fakeClient]) error {
		attempts++
		if attempts == 1 {
			return outbounderrors.ErrOperationHold
		}
		return nil
	})
	if err != nil {
		t.Fatalf("TryNextContext() error = %v, want nil", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2 (fail over to the second client)", attempts)
	}
	if constructed.Load() != 2 {
		t.Fatalf("constructed = %d, want 2 (no new client on failover)", constructed.Load())
	}
}

// Exhausting a live-context walk still spins up a fresh client.
func TestTryNextContextExhaustedRingConstructsNewClient(t *testing.T) {
	r, constructed := primeTwoClientRing(t)

	err := r.TryNextContext(context.Background(), func(*Node[*fakeClient]) error {
		return outbounderrors.ErrOperationHold
	})
	if !errors.Is(err, outbounderrors.ErrOperationHold) {
		t.Fatalf("TryNextContext() = %v, want hold on", err)
	}
	if constructed.Load() != 3 {
		t.Fatalf("constructed = %d, want 3 (fresh client after full walk)", constructed.Load())
	}
	if r.Len() != 3 {
		t.Fatalf("ring length = %d, want 3", r.Len())
	}
}

// TryNextContext after Close is terminal, like TryNext.
func TestTryNextContextAfterCloseIsTerminal(t *testing.T) {
	r, constructed, closedCount := newCountingRing()
	if err := r.TryNextContext(context.Background(), func(*Node[*fakeClient]) error {
		return nil
	}); err != nil {
		t.Fatalf("TryNextContext() before Close = %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	err := r.TryNextContext(context.Background(), func(*Node[*fakeClient]) error {
		t.Error("callback invoked on a closed ring")
		return nil
	})
	if !errors.Is(err, outbounderrors.ErrClientClosed) {
		t.Fatalf("TryNextContext() after Close = %v, want ErrClientClosed", err)
	}
	if constructed.Load() != closedCount.Load() {
		t.Fatalf("constructed = %d, closed = %d; every constructed client must be closed", constructed.Load(), closedCount.Load())
	}
}

// Concurrent attempts (canceled and not) racing a Close must stay
// consistent: no panic, no deadlock, and every constructed client closed.
func TestTryNextContextConcurrentCloseRace(t *testing.T) {
	r, constructed, closedCount := newCountingRing()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				_ = r.TryNextContext(ctx, func(*Node[*fakeClient]) error { return nil })
				cancel()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(20 * time.Millisecond)
		_ = r.Close()
	}()
	time.Sleep(60 * time.Millisecond)
	close(stop)
	wg.Wait()

	if r.Len() != 0 {
		t.Fatalf("ring length after Close = %d, want 0", r.Len())
	}
	if constructed.Load() != closedCount.Load() {
		t.Fatalf("constructed = %d, closed = %d; Close must tear down every client", constructed.Load(), closedCount.Load())
	}
	err := r.TryNextContext(context.Background(), func(*Node[*fakeClient]) error { return nil })
	if !errors.Is(err, outbounderrors.ErrClientClosed) {
		t.Fatalf("TryNextContext() after race Close = %v, want ErrClientClosed", err)
	}
}
