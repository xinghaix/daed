package vless

import (
	"runtime"
	"testing"

	"github.com/daeuniverse/outbound/protocol/infra/bench"
)

// TestVlessWriteNoAllocCliff guards against the 64KB first-write allocation
// cliff: pre-fix the header+payload were merged into one pool.Get sized with
// the payload, overflowing the pool at ~64KB and forcing a ~74KB heap alloc per
// first write. Post-fix the header uses a small pooled buffer and the payload
// is written via net.Buffers. TotalAlloc is deterministic/machine-independent.
func TestVlessWriteNoAllocCliff(t *testing.T) {
	h := vlessHarness{}
	payload := make([]byte, 65536)
	conn, err := h.NewConn(bench.NewDiscardConn())
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("warmup write: %v", err)
	}

	const runs = 50
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	for i := 0; i < runs; i++ {
		c, err := h.NewConn(bench.NewDiscardConn())
		if err != nil {
			t.Fatalf("NewConn: %v", err)
		}
		if _, err := c.Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	runtime.ReadMemStats(&m2)

	bytesPerOp := int(m2.TotalAlloc-m1.TotalAlloc) / runs
	const budget = 4096
	if bytesPerOp > budget {
		t.Fatalf("vless 64KB first-write alloc cliff regressed: %d B/op (budget %d); "+
			"check reqHeader stays small and payload is written via net.Buffers", bytesPerOp, budget)
	}
}
