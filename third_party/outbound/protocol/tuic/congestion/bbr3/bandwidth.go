package bbr3

import (
	"time"

	"github.com/olicesx/quic-go/congestion"
)

// Bandwidth in bytes per second.
type Bandwidth uint64

// bandwidthFromDelta converts a delivered volume over an interval to a rate.
func bandwidthFromDelta(bytes congestion.ByteCount, delta time.Duration) Bandwidth {
	if bytes <= 0 || delta <= 0 {
		return 0
	}
	return Bandwidth(float64(bytes) / delta.Seconds())
}

// bdpFrom is the bandwidth-delay product in bytes.
func bdpFrom(bw Bandwidth, rtt time.Duration) congestion.ByteCount {
	if bw == 0 || rtt <= 0 {
		return 0
	}
	return congestion.ByteCount(float64(bw) * rtt.Seconds())
}
