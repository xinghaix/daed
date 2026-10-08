package vless

import (
	"strconv"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/infra/bench"
	"github.com/daeuniverse/outbound/protocol/vmess"
)

// vlessHarness adapts vless to the unified bench framework via the existing
// public NewConn constructor. cmdKey uses a test key (NewConn only copies it).
type vlessHarness struct{}

func (vlessHarness) Name() string { return "vless" }

func (vlessHarness) NewConn(underlying netproxy.Conn) (netproxy.Conn, error) {
	md, err := protocol.ParseMetadata("example.com:443")
	if err != nil {
		return nil, err
	}
	md.IsClient = true
	cmdKey := make([]byte, 16)
	return NewConn(underlying, Metadata{
		Metadata: vmess.Metadata{Metadata: md, Network: "tcp"},
	}, cmdKey)
}

var _ bench.TCPHarness = vlessHarness{}

var vlessWriteSizes = []int{64, 1024, 4096, 16384, 65536}

func BenchmarkVlessSteadyWrite(b *testing.B) {
	h := vlessHarness{}
	for _, size := range vlessWriteSizes {
		b.Run("payload/"+strconv.Itoa(size), func(b *testing.B) {
			bench.RunTCPWriteBench(b, h, size)
		})
	}
}

func BenchmarkVlessDialWrite(b *testing.B) {
	h := vlessHarness{}
	for _, size := range vlessWriteSizes {
		b.Run("payload/"+strconv.Itoa(size), func(b *testing.B) {
			bench.RunTCPDialWriteBench(b, h, size)
		})
	}
}
