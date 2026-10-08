package tuic

import (
	"strconv"
	"testing"

	"github.com/daeuniverse/outbound/protocol/infra/bench"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
)

// tuicDatagramHarness adapts the TUIC UDP receive hot path to the unified bench
// framework. It reuses the existing buildPacketMessage helper and processDatagram
// entry point; no protocol API is changed.
type tuicDatagramHarness struct {
	client *clientImpl
}

func newTuicDatagramHarness() *tuicDatagramHarness {
	return &tuicDatagramHarness{client: &clientImpl{
		ClientOption: &ClientOption{UdpRelayMode: common.NATIVE},
		udp:          true,
	}}
}

func (tuicDatagramHarness) Name() string { return "tuic" }

func (h *tuicDatagramHarness) BuildDatagram(b *testing.B, payloadSize int) []byte {
	return buildPacketMessage(b, payloadSize)
}

func (h *tuicDatagramHarness) ProcessDatagram(msg []byte) {
	h.client.processDatagram(nil, msg)
}

var _ bench.UDPDatagramHarness = (*tuicDatagramHarness)(nil)

// datagramSizes covers a tiny fixed-overhead packet and realistic payload sizes.
var datagramSizes = []int{8, 100, 512, 1024}

// BenchmarkTuicDatagramUnified measures the TUIC UDP receive hot path (parse +
// dispatch per inbound datagram) through the unified framework.
func BenchmarkTuicDatagramUnified(b *testing.B) {
	h := newTuicDatagramHarness()
	for _, size := range datagramSizes {
		b.Run("payload/"+strconv.Itoa(size), func(b *testing.B) {
			bench.RunUDPDatagramBench(b, h, size)
		})
	}
}

// BenchmarkTuicParseRelease measures parse + immediate release, exercising the
// pool reuse path that BenchmarkTuicDatagramUnified cannot (it only parses and
// drops). With DATA pool-backed and recycled, allocs/op and B/op should stay
// flat across payload sizes instead of scaling with the payload.
func BenchmarkTuicParseRelease(b *testing.B) {
	for _, size := range datagramSizes {
		msg := buildPacketMessage(b, size)
		b.Run("payload/"+strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				pkt, err := readPacketFromMessage(msg)
				if err != nil {
					b.Fatal(err)
				}
				pkt.releaseData()
			}
		})
	}
}
