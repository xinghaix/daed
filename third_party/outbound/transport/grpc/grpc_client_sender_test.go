package grpc

import (
	"bytes"
	"io"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	proto "github.com/daeuniverse/outbound/pkg/gun_proto"
)

// recordingSendTun records the payload of every Send. Send must copy it
// immediately: the sender goroutine recycles the hunk as soon as Send
// returns, exactly like grpc-go marshals the message before SendMsg returns.
type recordingSendTun struct {
	*stubTun
	mu       sync.Mutex
	payloads [][]byte
}

func (s *recordingSendTun) Send(h *proto.Hunk) error {
	payload := append([]byte(nil), h.Data...)
	s.mu.Lock()
	s.payloads = append(s.payloads, payload)
	s.mu.Unlock()
	return nil
}

func TestSequentialWritesDeliverPayloadsInOrder(t *testing.T) {
	tun := &recordingSendTun{stubTun: newStubTun(make(chan *proto.Hunk, 1))}
	c := NewClientConn(tun, func() { _ = tun.CloseSend() })
	defer c.Close()

	const writes = 1000
	want := make([][]byte, writes)
	for i := range want {
		want[i] = bytes.Repeat([]byte{byte('a' + i%26)}, 1+(i*37)%4096)
	}
	before := runtime.NumGoroutine()
	for i := range want {
		n, err := c.Write(want[i])
		if err != nil || n != len(want[i]) {
			t.Fatalf("Write #%d = (%d, %v), want (%d, nil)", i, n, err, len(want[i]))
		}
	}
	// Leak guard in the style of protocol/shadowsocks_2022/udp_conn_race_test.go:
	// the persistent sender must not grow goroutines with the write count.
	time.Sleep(50 * time.Millisecond)
	if after := runtime.NumGoroutine(); after-before > 5 {
		t.Errorf("potential goroutine leak across %d writes: before=%d, after=%d", writes, before, after)
	}

	tun.mu.Lock()
	defer tun.mu.Unlock()
	if len(tun.payloads) != writes {
		t.Fatalf("Send called %d times, want %d", len(tun.payloads), writes)
	}
	for i, got := range tun.payloads {
		if !bytes.Equal(got, want[i]) {
			t.Fatalf("Send payload #%d corrupted: got %d bytes, want %d", i, len(got), len(want[i]))
		}
	}
}

// gatedSendTun wedges the first Send until the stream is closed (the conn
// closer's effect); later Sends succeed immediately. Only the sender
// goroutine calls Send, so calls needs no lock.
type gatedSendTun struct {
	*stubTun
	entered chan struct{}
	exited  chan struct{}
	calls   int
}

func (s *gatedSendTun) Send(*proto.Hunk) error {
	s.calls++
	if s.calls == 1 {
		close(s.entered)
		defer close(s.exited)
		<-s.done
		return io.EOF
	}
	return nil
}

// TestWriteAfterAbandonedDeadlineRecyclesRequest covers the request-recycling
// corner: a Write abandoned at its (terminal) write deadline leaves its
// aborted Send's result queued in the pooled request's done channel, and a
// retrying caller that re-arms the deadline must get a clean next Write.
func TestWriteAfterAbandonedDeadlineRecyclesRequest(t *testing.T) {
	tun := &gatedSendTun{
		stubTun: newStubTun(make(chan *proto.Hunk)),
		entered: make(chan struct{}),
		exited:  make(chan struct{}),
	}
	c := NewClientConn(tun, func() { _ = tun.CloseSend() })
	defer c.Close()

	if err := c.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline() error = %v", err)
	}
	result := make(chan error, 1)
	go func() { _, err := c.Write([]byte("wedged")); result <- err }()
	select {
	case <-tun.entered:
	case <-time.After(time.Second):
		t.Fatal("first Send did not start")
	}
	select {
	case err := <-result:
		if !os.IsTimeout(err) {
			t.Fatalf("wedged Write = %v, want timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("wedged Write did not return at its deadline")
	}
	select {
	case <-tun.exited:
	case <-time.After(time.Second):
		t.Fatal("abandoned Send never returned after stream cancel")
	}
	// Give the sender a moment to recycle the abandoned request, then
	// re-arm the terminal write deadline the way a retrying caller does.
	time.Sleep(20 * time.Millisecond)
	if err := c.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline() re-arm error = %v", err)
	}
	n, err := c.Write([]byte("second"))
	if err != nil || n != len("second") {
		t.Fatalf("Write after abandoned deadline = (%d, %v), want (%d, nil)", n, err, len("second"))
	}
}

// BenchmarkClientConnWrite measures the Write-path overhead per chunk with
// the persistent sender: steady-state allocations per Write are zero (the
// request and its done channel are pooled, the hunk is reused). grpc's own
// per-message marshal buffer is not exercised by this no-op stub stream.
func BenchmarkClientConnWrite(b *testing.B) {
	tun := newStubTun(make(chan *proto.Hunk, 1))
	c := NewClientConn(tun, func() { _ = tun.CloseSend() })
	defer c.Close()
	payload := make([]byte, 1400)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}
