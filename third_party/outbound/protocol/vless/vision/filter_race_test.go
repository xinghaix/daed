package vision

import (
	"sync"
	"testing"
)

// TestFilterTLSConcurrentAccess exercises the TLS-sniffing state machine
// under concurrent access that mirrors the real relay data path: the write
// direction calls FilterTLS then reads a snapshot, while the read direction
// calls FilterTLS on the same Conn concurrently.
//
// Run with -race. Before the filterMu fix this reports data races on
// isTLS / packetsToFilter / remainingServerHello; after the fix it is clean.
func TestFilterTLSConcurrentAccess(t *testing.T) {
	// Craft a synthetic ServerHello-style buffer so FilterTLS takes the
	// isTLS / remainingServerHello branches rather than the early return.
	serverHello := make([]byte, 128)
	serverHello[0] = 0x16 // TLS handshake record
	serverHello[1] = 0x03
	serverHello[2] = 0x03
	serverHello[3] = 0
	serverHello[4] = 0x40
	serverHello[5] = tlsHandshakeTypeServerHello

	const pairs = 16
	const iters = 100

	for range pairs {
		vc := &Conn{packetsToFilter: 6}

		var wg sync.WaitGroup
		wg.Add(2)

		// Write path: FilterTLS then read a snapshot (mirrors conn.write).
		go func() {
			defer wg.Done()
			for range iters {
				vc.FilterTLS(serverHello)
				_ = vc.filterSnapshot()
			}
		}()

		// Read path: FilterTLS concurrently (mirrors conn.read calling FilterTLS).
		go func() {
			defer wg.Done()
			for range iters {
				vc.FilterTLS(serverHello)
			}
		}()

		wg.Wait()
	}
}
