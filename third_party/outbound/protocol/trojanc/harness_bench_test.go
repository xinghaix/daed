package trojanc

import (
	"strconv"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/infra/bench"
)

// trojanHarness adapts the trojan protocol to the unified bench framework. It
// calls the existing public NewConn constructor; no protocol API is changed.
type trojanHarness struct{}

func (trojanHarness) Name() string { return "trojan" }

func (trojanHarness) NewConn(underlying netproxy.Conn) (netproxy.Conn, error) {
	md, err := protocol.ParseMetadata("example.com:443")
	if err != nil {
		return nil, err
	}
	md.IsClient = true
	return NewConn(underlying, Metadata{Metadata: md, Network: "tcp"}, "bench-password")
}

var _ bench.TCPHarness = trojanHarness{}

// writeSizes spans small interactive frames to bulk transfer chunks.
var writeSizes = []int{64, 1024, 4096, 16384, 65536}

// BenchmarkTrojanSteadyWrite measures per-byte encrypt+frame cost on the write
// hot path with the connection reused across iterations (dial cost excluded).
func BenchmarkTrojanSteadyWrite(b *testing.B) {
	h := trojanHarness{}
	for _, size := range writeSizes {
		b.Run("payload/"+strconv.Itoa(size), func(b *testing.B) {
			bench.RunTCPWriteBench(b, h, size)
		})
	}
}

// BenchmarkTrojanDialWrite measures first-write cost including handshake, key
// derivation and header serialization (connection rebuilt every iteration).
func BenchmarkTrojanDialWrite(b *testing.B) {
	h := trojanHarness{}
	for _, size := range writeSizes {
		b.Run("payload/"+strconv.Itoa(size), func(b *testing.B) {
			bench.RunTCPDialWriteBench(b, h, size)
		})
	}
}
