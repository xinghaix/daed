package bbr

import (
	"strconv"
	"testing"
	"time"

	"github.com/olicesx/quic-go/congestion"
)

// BenchmarkSamplerSteadyState measures the path bbr3 drives on every packet:
// one OnPacketSent plus one OnCongestionEvent per acknowledged packet, with a
// fixed in-flight window. It exists to keep the send-record map's memory
// reclamation from costing throughput: the steady state must stay allocation
// free per packet, and the per-packet bookkeeping added alongside the trim
// (RemoveUpTo plus the occupancy check) must stay inside the same O(1) path.
func BenchmarkSamplerSteadyState(b *testing.B) {
	const packetSize = 1200
	for _, windowPackets := range []int{32, 1000, 8192} {
		b.Run("window="+strconv.Itoa(windowPackets), func(b *testing.B) {
			s := NewRefSampler(10)
			now := time.Now()
			var pn congestion.PacketNumber
			acked := make([]congestion.AckedPacketInfo, 1)
			bytesInFlight := congestion.ByteCount(windowPackets * packetSize)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				pn++
				s.OnPacketSent(now, pn, packetSize, bytesInFlight, true)
				if pn > congestion.PacketNumber(windowPackets) {
					acked[0] = congestion.AckedPacketInfo{
						PacketNumber: pn - congestion.PacketNumber(windowPackets),
						BytesAcked:   packetSize,
					}
					s.OnCongestionEvent(now, acked, nil, uint64(pn)/10)
				}
				now = now.Add(time.Microsecond)
			}
		})
	}
}

// BenchmarkTrimSteadyState isolates the bookkeeping the reclamation adds to the
// packet path: one Emplace, one RemoveUpTo and one occupancy check on a queue
// holding a fixed window. This is the cost side of the trade the steady-state
// benchmark above measures the benefit of.
func BenchmarkTrimSteadyState(b *testing.B) {
	const window = 1000
	entry := 1
	q := newPacketNumberIndexedQueue[int](initialConnectionStateMapSlots, maxConnectionStateMapSlots)
	var pn congestion.PacketNumber
	for i := 0; i < window; i++ {
		pn++
		q.Emplace(pn, &entry)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pn++
		q.Emplace(pn, &entry)
		q.RemoveUpTo(pn - window)
	}
}
