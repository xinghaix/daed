package meek

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type staticTripper struct {
	started chan struct{}
	data    []byte
}

func (t *staticTripper) RoundTrip(context.Context, Request) (Response, error) {
	select {
	case <-t.started:
	default:
		close(t.started)
	}
	return Response{Data: t.data}, nil
}

func TestRunOnceReturnsAfterCloseWhileReaderChanIsFull(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tripper := &staticTripper{
		started: make(chan struct{}),
		data:    []byte("payload"),
	}
	session := &assemblerClientSession{
		assembler: &assemblerClient{
			tripper: tripper,
			config: &config{
				MaxWriteSize:          1024,
				FailedRetryIntervalMs: 1,
			},
		},
		tripper:          tripper,
		writerChan:       make(chan []byte),
		readerChan:       make(chan []byte, 1),
		ctx:              ctx,
		finish:           cancel,
		currentWriteWait: 0,
		sessionID:        []byte("session"),
	}
	session.readerChan <- []byte("blocked")

	done := make(chan struct{})
	go func() {
		defer close(done)
		session.runOnce()
	}()

	select {
	case <-tripper.started:
	case <-time.After(time.Second):
		t.Fatal("RoundTrip() was not reached")
	}

	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runOnce() did not return after Close/cancel")
	}
}

type failingTripper struct {
	n atomic.Int32
}

func (t *failingTripper) RoundTrip(context.Context, Request) (Response, error) {
	t.n.Add(1)
	return Response{}, errors.New("poll failed")
}

func TestRunOnceFinishesAfterMaxFailedPolls(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tripper := &failingTripper{}
	var finishOnce sync.Once
	session := &assemblerClientSession{
		assembler: &assemblerClient{
			tripper: tripper,
			config: &config{
				MaxWriteSize:          1024,
				FailedRetryIntervalMs: 1,
			},
		},
		tripper:          tripper,
		writerChan:       make(chan []byte),
		readerChan:       make(chan []byte, 1),
		ctx:              ctx,
		finish:           func() { finishOnce.Do(cancel) },
		currentWriteWait: 0,
		sessionID:        []byte("session"),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		session.runOnce()
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runOnce() did not finish after failed-poll cap")
	}
	if got := tripper.n.Load(); got < int32(maxFailedPolls) {
		t.Fatalf("RoundTrip calls = %d, want >= %d", got, maxFailedPolls)
	}
}

func TestReadReturnsEOFAfterSessionFinish(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	session := &assemblerClientSession{
		ctx:        ctx,
		finish:     cancel,
		readBuffer: bytes.NewBuffer(nil),
	}
	cancel()
	n, err := session.Read(make([]byte, 8))
	if n != 0 || err != io.EOF {
		t.Fatalf("Read() = %d, %v, want EOF", n, err)
	}
}
