package anytls

import (
	"strconv"
	"testing"

	"github.com/daeuniverse/outbound/protocol/infra/bench"
)

var anytlsWriteSizes = []int{64, 1024, 4096, 16384, 65536}

// BenchmarkAnytlsStreamWrite measures the anytls stream write path: frame
// splitting + multiplexing overhead, with the session backed by a discarding
// net.Conn. The read path depends on the session receive loop and is out of
// scope here. anytls uses net.Conn (not netproxy.Conn) for its session, hence
// it does not fit the TCPHarness contract.
func BenchmarkAnytlsStreamWrite(b *testing.B) {
	sess := newSession(bench.NewNetDiscardConn(), 0)
	stream, err := sess.newStream("127.0.0.1:8080")
	if err != nil {
		b.Fatalf("newStream: %v", err)
	}
	for _, size := range anytlsWriteSizes {
		payload := make([]byte, size)
		b.Run("payload/"+strconv.Itoa(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := stream.Write(payload); err != nil {
					b.Fatalf("Write: %v", err)
				}
			}
		})
	}
}
