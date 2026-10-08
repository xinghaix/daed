package anytls

import (
	"testing"
)

// BenchmarkGenerateRecordPayloadSizes measures the write-hot-path cost of
// resolving the padding rule for each outgoing frame. This is called once per
// session.Write while pkt < paddingFactory.Stop, so per-call overhead is
// amplified by connection count.
func BenchmarkGenerateRecordPayloadSizes(b *testing.B) {
	p := DefaultPaddingFactory.Load()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// pkt=2 exercises the largest rule (400-500,c,500-1000,...) and the
		// random-range path; pkt=0 is the fixed-size auth path.
		_ = p.GenerateRecordPayloadSizes(2)
		_ = p.GenerateRecordPayloadSizes(0)
	}
}
