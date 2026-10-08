package anytls

import "testing"

// TestRelayBufferAlignment locks the downstream buffer contract documented on
// maxFramePayloadSize: common relay read-buffer sizes must be integer
// multiples of the frame payload size. A 64 KiB buffer over a 65535-byte
// frame budget famously degrades into a full frame plus a one-byte tail frame
// per read; keeping these sizes aligned avoids that class of regression for
// dae (32 KiB relay buffer) and any other consumer using power-of-two reads.
func TestRelayBufferAlignment(t *testing.T) {
	if maxFramePayloadSize&(maxFramePayloadSize-1) != 0 {
		t.Fatalf("maxFramePayloadSize=%d is not a power of two; alignment reasoning below no longer holds", maxFramePayloadSize)
	}
	for _, bufSize := range []int{16 << 10, 32 << 10, 64 << 10} {
		if bufSize%maxFramePayloadSize != 0 && maxFramePayloadSize%bufSize != 0 {
			t.Fatalf("relay buffer %d and maxFramePayloadSize=%d are not integer multiples of each other; a full read buffer would split into a full frame plus a tail frame", bufSize, maxFramePayloadSize)
		}
	}
}
