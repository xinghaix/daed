package protocol

import (
	"strconv"
	"testing"

	"github.com/daeuniverse/outbound/protocol/infra/bench"
)

// hy2UDPHarness adapts the Hysteria2 UDP relay parse path to the unified bench
// framework. It exercises the production ParseUDPMessage path that runs once
// per inbound UDP message at line rate; no protocol API is changed.
type hy2UDPHarness struct{}

func (hy2UDPHarness) Name() string { return "hysteria2" }

func (hy2UDPHarness) BuildDatagram(b *testing.B, payloadSize int) []byte {
	b.Helper()
	msg := &UDPMessage{
		SessionID: 1,
		PacketID:  1,
		FragID:    0,
		FragCount: 1,
		Addr:      []byte("127.0.0.1:8080"),
		Data:      make([]byte, payloadSize),
	}
	buf := make([]byte, msg.Size())
	n := msg.Serialize(buf)
	if n < 0 {
		b.Fatal("serialize failed")
	}
	return buf[:n]
}

func (hy2UDPHarness) ProcessDatagram(msg []byte) {
	if _, err := ParseUDPMessage(msg); err != nil {
		panic(err)
	}
}

var _ bench.UDPDatagramHarness = hy2UDPHarness{}

// hy2DatagramSizes covers a tiny fixed-overhead packet and realistic sizes.
var hy2DatagramSizes = []int{8, 100, 512, 1024}

// BenchmarkHy2DatagramUnified measures the Hysteria2 UDP parse hot path through
// the unified framework.
func BenchmarkHy2DatagramUnified(b *testing.B) {
	h := hy2UDPHarness{}
	for _, size := range hy2DatagramSizes {
		b.Run("payload/"+strconv.Itoa(size), func(b *testing.B) {
			bench.RunUDPDatagramBench(b, h, size)
		})
	}
}
