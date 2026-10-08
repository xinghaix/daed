package bufferred_conn

import (
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

type stagedReadConn struct {
	readStarted  chan *byte
	closeStarted chan struct{}
	releaseClose chan struct{}
	closed       chan struct{}
	closeOnce    sync.Once
}

func newStagedReadConn() *stagedReadConn {
	return &stagedReadConn{
		readStarted:  make(chan *byte, 1),
		closeStarted: make(chan struct{}),
		releaseClose: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (c *stagedReadConn) Read(p []byte) (int, error) {
	c.readStarted <- &p[0]
	<-c.closed
	return 0, net.ErrClosed
}

func (c *stagedReadConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *stagedReadConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeStarted)
		<-c.releaseClose
		close(c.closed)
	})
	return nil
}
func (c *stagedReadConn) LocalAddr() net.Addr              { return nil }
func (c *stagedReadConn) RemoteAddr() net.Addr             { return nil }
func (c *stagedReadConn) SetDeadline(time.Time) error      { return nil }
func (c *stagedReadConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stagedReadConn) SetWriteDeadline(time.Time) error { return nil }

func TestBufferedConnCloseKeepsActiveReaderBufferOwned(t *testing.T) {
	oldProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(oldProcs)

	firstRaw := newStagedReadConn()
	first := NewBufferedConnSize(firstRaw, 64)
	firstReadDone := make(chan struct{})
	go func() {
		_, _ = first.Read(make([]byte, 1))
		close(firstReadDone)
	}()
	firstBuffer := <-firstRaw.readStarted

	firstCloseDone := make(chan struct{})
	go func() {
		_ = first.Close()
		close(firstCloseDone)
	}()
	<-firstRaw.closeStarted

	secondRaw := newStagedReadConn()
	second := NewBufferedConnSize(secondRaw, 64)
	secondReadDone := make(chan struct{})
	go func() {
		_, _ = second.Read(make([]byte, 1))
		close(secondReadDone)
	}()
	secondBuffer := <-secondRaw.readStarted

	if firstBuffer == secondBuffer {
		t.Fatal("Close recycled a buffer still owned by an active reader")
	}

	close(firstRaw.releaseClose)
	close(secondRaw.releaseClose)
	_ = second.Close()
	<-firstCloseDone
	<-firstReadDone
	<-secondReadDone
	first.ReleaseReader()
	second.ReleaseReader()
}
