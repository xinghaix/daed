package bbr3

import (
	"testing"
	"time"
)

func TestBandwidthFromDelta(t *testing.T) {
	if got := bandwidthFromDelta(1200, 100*time.Millisecond); got != 12000 {
		t.Fatalf("rate = %d, want 12000", got)
	}
	if got := bandwidthFromDelta(0, time.Second); got != 0 {
		t.Fatalf("zero bytes must give zero rate, got %d", got)
	}
	if got := bandwidthFromDelta(1200, 0); got != 0 {
		t.Fatalf("zero delta must give zero rate, got %d", got)
	}
}

func TestBdpFrom(t *testing.T) {
	if got := bdpFrom(1_000_000, 100*time.Millisecond); got != 100_000 {
		t.Fatalf("bdp = %d, want 100000", got)
	}
	if got := bdpFrom(0, time.Second); got != 0 {
		t.Fatalf("zero bandwidth must give zero bdp, got %d", got)
	}
	if got := bdpFrom(1_000_000, 0); got != 0 {
		t.Fatalf("zero rtt must give zero bdp, got %d", got)
	}
}
