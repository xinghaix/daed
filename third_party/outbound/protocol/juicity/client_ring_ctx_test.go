package juicity

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/outbound/protocol/trojanc"
)

// Ring callers must pass the caller context down: a canceled dial fails
// before the walk touches any client or constructs a new one.
func TestClientRingCanceledCtxFailsWithoutNewClient(t *testing.T) {
	var constructed atomic.Int32
	r := newClientRing(func(func(int64)) *clientImpl {
		constructed.Add(1)
		return &clientImpl{}
	}, 0)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := r.DialContext(ctx, &trojanc.Metadata{}, nil, nil); err == nil {
		t.Fatal("DialContext(canceled ctx) = nil error, want context error")
	}
	if _, _, err := r.DialAuth(ctx, &trojanc.Metadata{}, nil, nil); err == nil {
		t.Fatal("DialAuth(canceled ctx) = nil error, want context error")
	}
	if constructed.Load() != 0 {
		t.Fatalf("canceled dials constructed %d clients", constructed.Load())
	}
	if got := r.ring.Len(); got != 0 {
		t.Fatalf("canceled dials mutated the ring: len = %d", got)
	}
}
