package clientring

import (
	"container/list"
	"context"
	"errors"
	"sync/atomic"
	"testing"

	outbounderrors "github.com/daeuniverse/outbound/common/errors"
)

type fakeClient struct {
	id int
}

func TestCloseIsTerminal(t *testing.T) {
	var constructed atomic.Int32
	r := New(func(func(int64)) *fakeClient {
		constructed.Add(1)
		return &fakeClient{id: int(constructed.Load())}
	}, func(*fakeClient, func()) {}, func(*fakeClient) error { return nil }, 0)

	if err := r.TryNext(func(node *Node[*fakeClient]) error {
		if node.Client == nil {
			t.Fatal("nil client")
		}
		return nil
	}); err != nil {
		t.Fatalf("first TryNext: %v", err)
	}
	if constructed.Load() != 1 {
		t.Fatalf("constructed = %d, want 1", constructed.Load())
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err := r.TryNext(func(*Node[*fakeClient]) error { return nil })
	if !errors.Is(err, outbounderrors.ErrClientClosed) {
		t.Fatalf("TryNext after Close: %v, want ErrClientClosed", err)
	}
	if constructed.Load() != 1 {
		t.Fatalf("Close resurrected clients: constructed = %d", constructed.Load())
	}
	if r.Len() != 0 {
		t.Fatalf("Len after Close = %d, want 0", r.Len())
	}
}

func TestCloseEmptyRingDoesNotResurrectViaGetNew(t *testing.T) {
	var constructed atomic.Int32
	r := New(func(func(int64)) *fakeClient {
		constructed.Add(1)
		return &fakeClient{id: int(constructed.Load())}
	}, func(*fakeClient, func()) {}, func(*fakeClient) error { return nil }, 0)

	if err := r.Close(); err != nil {
		t.Fatalf("Close empty ring: %v", err)
	}
	err := r.TryNext(func(*Node[*fakeClient]) error { return nil })
	if !errors.Is(err, outbounderrors.ErrClientClosed) {
		t.Fatalf("TryNext after empty Close: %v, want ErrClientClosed", err)
	}
	if constructed.Load() != 0 {
		t.Fatalf("empty-ring Close resurrected via getNew: constructed = %d", constructed.Load())
	}
}

func TestGetNewRefusesWhenClosed(t *testing.T) {
	var constructed atomic.Int32
	r := New(func(func(int64)) *fakeClient {
		constructed.Add(1)
		return &fakeClient{id: int(constructed.Load())}
	}, func(*fakeClient, func()) {}, func(*fakeClient) error { return nil }, 0)
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Acquire cannot fail with a Background context; release must run.
	_ = r.sem.Acquire(context.Background(), 1)
	defer r.sem.Release(1)
	var current *list.Element
	err := r.tryNext(context.Background(), &current, func(*Node[*fakeClient]) error { return nil })
	if !errors.Is(err, outbounderrors.ErrClientClosed) {
		t.Fatalf("tryNext/getNew after Close: %v, want ErrClientClosed", err)
	}
	if constructed.Load() != 0 {
		t.Fatalf("getNew constructed after Close: %d", constructed.Load())
	}
}
