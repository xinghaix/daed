package tuic

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol/infra/clientring"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
)

func TestAcquireUniStreamSlotWaitsForCapacity(t *testing.T) {
	client := &clientImpl{streamSem: make(chan struct{}, 1)}
	if err := client.acquireUniStreamSlot(context.Background()); err != nil {
		t.Fatalf("acquireUniStreamSlot() initial error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.acquireUniStreamSlot(ctx)
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("acquireUniStreamSlot() error = %v, want context deadline exceeded", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("acquireUniStreamSlot() did not unblock on context cancellation")
	}
}

func TestAcquireUniStreamSlotSucceedsAfterRelease(t *testing.T) {
	client := &clientImpl{streamSem: make(chan struct{}, 1)}
	if err := client.acquireUniStreamSlot(context.Background()); err != nil {
		t.Fatalf("acquireUniStreamSlot() initial error = %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		errCh <- client.acquireUniStreamSlot(ctx)
	}()

	time.Sleep(20 * time.Millisecond)
	client.releaseUniStreamSlot()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("acquireUniStreamSlot() error = %v", err)
		}
		client.releaseUniStreamSlot()
	case <-time.After(200 * time.Millisecond):
		t.Fatal("acquireUniStreamSlot() did not acquire released capacity")
	}
}

func TestClientRingCloseClosesClientsAndClearsRing(t *testing.T) {
	r := newClientRing(func(func(int64)) *clientImpl { return &clientImpl{} }, 0)
	// Prime the ring with one client (a failure on a freshly created node
	// returns directly without walking), then fail on it so a second
	// client is inserted and the attempt succeeds there.
	if err := r.ring.TryNext(func(*clientring.Node[*clientImpl]) error { return common.ErrHoldOn }); err == nil {
		t.Fatal("priming TryNext() = nil, want hold-on")
	}
	attempts := 0
	err := r.ring.TryNext(func(*clientring.Node[*clientImpl]) error {
		attempts++
		if attempts == 1 {
			return common.ErrHoldOn
		}
		return nil
	})
	if err != nil {
		t.Fatalf("second TryNext() error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	if got := r.ring.Len(); got != 2 {
		t.Fatalf("ring length = %d, want 2", got)
	}

	if err := r.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := r.ring.Len(); got != 0 {
		t.Fatalf("ring not cleared: len=%d", got)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}
