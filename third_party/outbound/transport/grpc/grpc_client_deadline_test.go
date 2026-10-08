package grpc

import (
	"io"
	"os"
	"sync"
	"testing"
	"time"

	proto "github.com/daeuniverse/outbound/pkg/gun_proto"
	"google.golang.org/grpc"
)

// stubTun implements just enough of GunService_TunClient for the deadline
// semantics test; Recv blocks on a channel the test controls.
type stubTun struct {
	grpc.ClientStream
	recvCh   chan *proto.Hunk
	done     chan struct{}
	closeOne sync.Once
}

func (s *stubTun) Recv() (*proto.Hunk, error) {
	select {
	case hunk := <-s.recvCh:
		return hunk, nil
	case <-s.done:
		return nil, io.EOF
	}
}
func (s *stubTun) Send(*proto.Hunk) error { return nil }
func (s *stubTun) CloseSend() error {
	s.closeOne.Do(func() { close(s.done) })
	return nil
}

func newStubTun(recvCh chan *proto.Hunk) *stubTun {
	return &stubTun{recvCh: recvCh, done: make(chan struct{})}
}

func TestReadMemoizesRecvError(t *testing.T) {
	tun := &errOnceTun{err: io.ErrUnexpectedEOF}
	c := NewClientConn(tun, func() {})
	defer func() { _ = c.Close() }()

	buf := make([]byte, 8)
	_, err := c.Read(buf)
	if err == nil {
		t.Fatal("first Read expected error")
	}
	start := time.Now()
	_, err2 := c.Read(buf)
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("second Read blocked after terminal recv error")
	}
	if err2 == nil {
		t.Fatal("second Read expected memoized error")
	}
}

type errOnceTun struct {
	grpc.ClientStream
	err error
}

func (s *errOnceTun) Recv() (*proto.Hunk, error) { return nil, s.err }
func (s *errOnceTun) Send(*proto.Hunk) error     { return nil }
func (s *errOnceTun) CloseSend() error           { return nil }

func TestPendingReadUsesExtendedDeadline(t *testing.T) {
	tun := newStubTun(make(chan *proto.Hunk, 1))
	c := NewClientConn(tun, func() { _ = tun.CloseSend() })
	defer func() { _ = c.Close() }()

	if err := c.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	c.muReading.Lock()
	resultCh := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		buf := make([]byte, 128)
		n, err := c.Read(buf)
		resultCh <- struct {
			n   int
			err error
		}{n: n, err: err}
	}()
	time.Sleep(50 * time.Millisecond)
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() extension error = %v", err)
	}
	c.muReading.Unlock()
	tun.recvCh <- &proto.Hunk{Data: []byte("pending read")}

	select {
	case result := <-resultCh:
		if result.err != nil || result.n != len("pending read") {
			t.Fatalf("pending Read() = (%d, %v), want payload after deadline extension", result.n, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending Read() did not complete")
	}
}

func TestPendingWriteUsesExtendedDeadline(t *testing.T) {
	tun := newStubTun(make(chan *proto.Hunk))
	c := NewClientConn(tun, func() { _ = tun.CloseSend() })
	defer func() { _ = c.Close() }()

	if err := c.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline() error = %v", err)
	}
	c.muWriting.Lock()
	resultCh := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := c.Write([]byte("pending write"))
		resultCh <- struct {
			n   int
			err error
		}{n: n, err: err}
	}()
	time.Sleep(50 * time.Millisecond)
	if err := c.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline() extension error = %v", err)
	}
	c.muWriting.Unlock()

	select {
	case result := <-resultCh:
		if result.err != nil || result.n != len("pending write") {
			t.Fatalf("pending Write() = (%d, %v), want success after deadline extension", result.n, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending Write() did not complete")
	}
}

// TestReadDeadlineIsNotTerminal pins the net.Conn deadline contract: an
// expired read deadline must surface os.ErrDeadlineExceeded WITHOUT killing
// the stream, and a later Read (after the deadline is extended) must still
// deliver the hunk the pump received meanwhile.
func TestReadDeadlineIsNotTerminal(t *testing.T) {
	tun := newStubTun(make(chan *proto.Hunk))
	c := NewClientConn(tun, func() { _ = tun.CloseSend() })
	defer func() { _ = c.Close() }()

	if err := c.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	if _, err := c.Read(make([]byte, 128)); !os.IsTimeout(err) {
		t.Fatalf("Read() error = %v, want os.ErrDeadlineExceeded", err)
	}

	// The conn must remain usable: deliver a hunk and read it after the
	// deadline was cleared.
	tun.recvCh <- &proto.Hunk{Data: []byte("still alive")}
	if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	buf := make([]byte, 128)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("Read() after deadline expiry error = %v, want success", err)
	}
	if string(buf[:n]) != "still alive" {
		t.Fatalf("Read() = %q, want %q", buf[:n], "still alive")
	}
}
