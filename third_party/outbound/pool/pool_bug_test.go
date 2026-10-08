package pool

import (
	"fmt"
	"testing"
)

// TestPool_Get_Bug tests pool.Get for power-of-two sizes
func TestPool_Get_Bug(t *testing.T) {
	fmt.Println("=== Testing pool.Get for powers of 2 ===")
	fmt.Println()

	testCases := []struct {
		size           int
		minExpectedCap int
		description    string
	}{
		{1024, 1024, "1024 bytes (power of 2)"},
		{2048, 2048, "2048 bytes (power of 2) - LIKELY BUG"},
		{4096, 4096, "4096 bytes (power of 2)"},
		{1025, 2048, "1025 bytes (not power of 2)"},
		{2049, 4096, "2049 bytes (not power of 2)"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			buf := Get(tc.size)
			defer buf.Put()

			actualCap := cap(buf)
			actualLen := len(buf)

			fmt.Printf("Test: %s\n", tc.description)
			fmt.Printf("  Requested: %d bytes\n", tc.size)
			fmt.Printf("  Got: len=%d, cap=%d\n", actualLen, actualCap)
			fmt.Printf("  Min expected cap: %d\n", tc.minExpectedCap)

			if actualCap < tc.size {
				t.Errorf("❌ CRITICAL: cap=%d < requested size=%d (WILL PANIC!)\n", actualCap, tc.size)
			} else if actualCap < tc.minExpectedCap {
				t.Errorf("⚠️  WARNING: cap=%d < min expected=%d\n", actualCap, tc.minExpectedCap)
			} else {
				fmt.Printf("✅ PASS\n\n")
			}
		})
	}
}

// TestPutNonPowerOf2Cap verifies that a buffer whose cap was grown by
// append (non-power-of-2) can be Put back safely: a later Get requesting
// more than its cap must fall back to a fresh allocation instead of
// panicking, and a Get that fits must not panic either.
func TestPutNonPowerOf2Cap(t *testing.T) {
	grown := Get(1000)                          // bucket cap 1024
	grown = append(grown, make([]byte, 536)...) // cap 1536, non-power-of-2
	Put(grown)

	// A Get larger than the grown cap must allocate fresh (no panic).
	big := Get(2048)
	if cap(big) < 2048 {
		t.Fatalf("Get(2048) returned cap %d, want >= 2048", cap(big))
	}
	Put(big)

	// A Get that fits the grown cap must not panic either.
	small := Get(1500)
	if len(small) != 1500 {
		t.Fatalf("Get(1500) returned len %d", len(small))
	}
	Put(small)
}

func TestGetBucketCapacityBug(t *testing.T) {
	testCases := []struct {
		size        int
		expectedCap int
		description string
	}{
		{2080, 4096, "2080 bytes - should get bucket 12 (4096)"},
		{2048, 2048, "2048 bytes - should get bucket 11 (2048)"},
		{2049, 4096, "2049 bytes - should get bucket 12 (4096)"},
		{1536, 2048, "1536 bytes - should get bucket 11 (2048)"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			buf := Get(tc.size)
			defer buf.Put()

			actualCap := cap(buf)
			actualLen := len(buf)

			fmt.Printf("Test: %s\n", tc.description)
			fmt.Printf("  Requested: %d bytes\n", tc.size)
			fmt.Printf("  Got: len=%d, cap=%d\n", actualLen, actualCap)
			fmt.Printf("  Expected cap: %d\n", tc.expectedCap)

			if actualCap < tc.size {
				t.Errorf("❌ FAIL: cap=%d < requested size=%d (PANIC!)\n", actualCap, tc.size)
			} else if actualCap < tc.expectedCap {
				t.Errorf("⚠️  WARNING: cap=%d < expected=%d\n", actualCap, tc.expectedCap)
			} else {
				fmt.Printf("✅ PASS\n\n")
			}
		})
	}
}

// TestPoolInitialization tests whether pool initialization is correct
func TestPoolInitialization(t *testing.T) {
	fmt.Println("\n=== Pool Initialization Test ===")

	// Test every bucket
	for i := minsizePower; i < num; i++ {
		buf := pools[i].Get().([]byte)
		actualCap := cap(buf)
		expectedCap := 1 << i

		fmt.Printf("Bucket %d: expected cap=%d, actual cap=%d", i, expectedCap, actualCap)

		if actualCap != expectedCap {
			fmt.Printf(" ❌ MISMATCH!\n")
			t.Errorf("Bucket %d: expected cap=%d, got %d", i, expectedCap, actualCap)
		} else {
			fmt.Printf(" ✅\n")
		}
	}
	fmt.Println()
}

// TestPool_PutNonPowerOfTwoCapDoesNotPolluteBucket is a regression test: a
// buffer whose cap is not a power of two must be discarded instead of being
// stored in the next bucket up, otherwise a later Get(2^n) reslices the short
// pooled buffer to the bucket size and panics with slice bounds out of range.
func TestPool_PutNonPowerOfTwoCapDoesNotPolluteBucket(t *testing.T) {
	// Simulate the non-power-of-two cap that append growth produces (e.g. the
	// socks5 authentication branch pushing past 512 → ~832).
	polluter := make([]byte, 512)
	polluter = append(polluter, make([]byte, 300)...)
	if cap(polluter)&(cap(polluter)-1) == 0 {
		t.Fatalf("test setup: expected non-power-of-2 cap, got %d", cap(polluter))
	}
	Put(polluter)

	// If the next bucket up were polluted, a Get(1024/2048) here would panic or
	// return a buffer with insufficient capacity.
	for i := 0; i < 200; i++ {
		b := Get(2048)
		if cap(b) < 2048 {
			t.Fatalf("iteration %d: Get(2048) returned cap=%d (bucket polluted)", i, cap(b))
		}
		b.Put()
	}
}
