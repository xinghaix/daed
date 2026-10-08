package grpc

import (
	"io"
	"os"
	"sync"
	"testing"
	"time"

	proto "github.com/daeuniverse/outbound/pkg/gun_proto"
)

func TestReviewGRPCZeroDeadlineClears(t *testing.T) {
	for _, which := range []string{"both", "read", "write"} {
		t.Run(which, func(t *testing.T) {
			tun := newStubTun(make(chan *proto.Hunk, 1))
			c := NewClientConn(tun, func() { _ = tun.CloseSend() })
			defer c.Close()
			set := c.SetDeadline
			if which == "read" {
				set = c.SetReadDeadline
			} else if which == "write" {
				set = c.SetWriteDeadline
			}
			if err := set(time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if err := set(time.Time{}); err != nil {
				t.Fatal(err)
			}
			if which != "write" {
				tun.recvCh <- &proto.Hunk{Data: []byte("response")}
				buf := make([]byte, 16)
				n, err := c.Read(buf)
				if n != 8 || err != nil {
					t.Errorf("Read after clearing deadline = (%d, %v), want (8, nil)", n, err)
				}
			}
			if which != "read" {
				n, err := c.Write([]byte("query"))
				if n != 5 || err != nil {
					t.Errorf("Write after clearing deadline = (%d, %v), want (5, nil)", n, err)
				}
			}
		})
	}
}

func TestClearExpiredReadDeadlinePreservesHunk(t *testing.T) {
	for _, both := range []bool{false, true} {
		tun := newStubTun(make(chan *proto.Hunk, 1))
		c := NewClientConn(tun, func() { _ = tun.CloseSend() })
		defer c.Close()
		set := c.SetReadDeadline
		if both {
			set = c.SetDeadline
		}
		if err := set(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Read(make([]byte, 8)); !os.IsTimeout(err) {
			t.Fatalf("Read = %v, want timeout", err)
		}
		tun.recvCh <- &proto.Hunk{Data: []byte("response")}
		if err := set(time.Time{}); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 8)
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "response" {
			t.Fatalf("recovered Read = %q, %v", buf, err)
		}
	}
}

func waitForReadLock(t *testing.T, mu *sync.Mutex) {
	t.Helper()
	limit := time.Now().Add(time.Second)
	for mu.TryLock() {
		mu.Unlock()
		if time.Now().After(limit) {
			t.Fatal("Read did not acquire its lock")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPendingReadDeadlineClearAndWake(t *testing.T) {
	for _, both := range []bool{false, true} {
		tun := newStubTun(make(chan *proto.Hunk, 1))
		c := NewClientConn(tun, func() { _ = tun.CloseSend() })
		defer c.Close()
		set := c.SetReadDeadline
		if both {
			set = c.SetDeadline
		}
		if err := set(time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { _, err := c.Read(make([]byte, 8)); result <- err }()
		waitForReadLock(t, &c.muReading)
		if err := set(time.Time{}); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-result:
			t.Fatalf("clearing deadline ended pending Read: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
		// A new deadline must still wake the original pending Read.
		if err := set(time.Now().Add(10 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-result:
			if !os.IsTimeout(err) {
				t.Fatalf("pending Read = %v, want timeout", err)
			}
		case <-time.After(time.Second):
			t.Fatal("new deadline did not wake pending Read")
		}
		if err := set(time.Time{}); err != nil {
			t.Fatal(err)
		}
		tun.recvCh <- &proto.Hunk{Data: []byte("response")}
		buf := make([]byte, 8)
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "response" {
			t.Fatalf("Read after wake = %q, %v", buf, err)
		}
	}
}

type blockedSendTun struct {
	*stubTun
	started chan struct{}
	release chan struct{}
	exited  chan struct{}
}

func (s *blockedSendTun) Send(*proto.Hunk) error {
	close(s.started)
	defer close(s.exited)
	select {
	case <-s.done:
		return io.EOF
	case <-s.release:
		return nil
	}
}

func TestPendingWriteDeadlineClearAndTerminate(t *testing.T) {
	for _, expire := range []bool{false, true} {
		tun := &blockedSendTun{stubTun: newStubTun(make(chan *proto.Hunk)), started: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
		c := NewClientConn(tun, func() { _ = tun.CloseSend() })
		defer c.Close()
		if err := c.SetWriteDeadline(time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { _, err := c.Write([]byte("query")); result <- err }()
		select {
		case <-tun.started:
		case <-time.After(time.Second):
			t.Fatal("Send did not start")
		}
		if err := c.SetWriteDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-result:
			t.Fatalf("clearing deadline ended pending Write: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
		if expire {
			if err := c.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
		} else {
			close(tun.release)
		}
		select {
		case err := <-result:
			if expire && !os.IsTimeout(err) || !expire && err != nil {
				t.Fatalf("Write = %v, expire=%v", err, expire)
			}
		case <-time.After(time.Second):
			t.Fatal("pending Write did not return")
		}
		select {
		case <-tun.exited:
		case <-time.After(time.Second):
			t.Fatal("Send remained blocked")
		}
		if expire {
			select {
			case <-tun.done:
			default:
				t.Fatal("write expiry did not terminate stream")
			}
			if err := c.SetWriteDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Read(make([]byte, 8)); err != io.EOF {
				t.Fatalf("terminated stream Read = %v", err)
			}
		}
	}
}

func TestReplacedDeadlineIgnoresStartedTimer(t *testing.T) {
	for _, write := range []bool{false, true} {
		for _, clear := range []bool{false, true} {
			tun := newStubTun(make(chan *proto.Hunk, 1))
			c := NewClientConn(tun, func() { _ = tun.CloseSend() })
			defer c.Close()
			c.deadlineMu.Lock()
			slot, ctx, cancel := &c.readDeadline, &c.ctxRead, &c.cancelRead
			if write {
				slot, ctx, cancel = &c.writeDeadline, &c.ctxWrite, &c.cancelWrite
			}
			c.setDeadlineLocked(slot, ctx, cancel, time.Now().Add(time.Millisecond))
			// Keep the callback blocked on deadlineMu until its epoch is replaced.
			time.Sleep(20 * time.Millisecond)
			if (*slot).Stop() {
				c.deadlineMu.Unlock()
				t.Fatal("old timer had not started")
			}
			next := time.Now().Add(time.Hour)
			if clear {
				next = time.Time{}
			}
			c.setDeadlineLocked(slot, ctx, cancel, next)
			current := *ctx
			c.deadlineMu.Unlock()
			select {
			case <-current.Done():
				t.Fatal("old timer cancelled replacement deadline")
			case <-time.After(20 * time.Millisecond):
			}
			tun.recvCh <- &proto.Hunk{Data: []byte("response")}
			if _, err := c.Read(make([]byte, 8)); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Write([]byte("query")); err != nil {
				t.Fatal(err)
			}
		}
	}
}
