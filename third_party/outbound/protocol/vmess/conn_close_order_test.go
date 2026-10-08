package vmess

import (
	"net"
	"sync"
	"testing"
	"time"
)

type closeOrderConn struct {
	closed chan struct{}
	once   sync.Once
}

func newCloseOrderConn() *closeOrderConn {
	return &closeOrderConn{closed: make(chan struct{})}
}

func (c *closeOrderConn) Read([]byte) (int, error)         { <-c.closed; return 0, net.ErrClosed }
func (c *closeOrderConn) Write([]byte) (int, error)        { <-c.closed; return 0, net.ErrClosed }
func (c *closeOrderConn) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *closeOrderConn) SetDeadline(time.Time) error      { return nil }
func (c *closeOrderConn) SetReadDeadline(time.Time) error  { return nil }
func (c *closeOrderConn) SetWriteDeadline(time.Time) error { return nil }

func TestConnCloseClosesUnderlayBeforeCleanupLocks(t *testing.T) {
	for _, tc := range []struct {
		name string
		lock func(*Conn) *sync.Mutex
	}{
		{name: "read", lock: func(c *Conn) *sync.Mutex { return &c.readMutex }},
		{name: "write", lock: func(c *Conn) *sync.Mutex { return &c.writeMutex }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			underlay := newCloseOrderConn()
			conn := &Conn{Conn: underlay}
			mu := tc.lock(conn)
			mu.Lock()

			closeDone := make(chan error, 1)
			go func() { closeDone <- conn.Close() }()

			select {
			case <-underlay.closed:
			case <-time.After(time.Second):
				mu.Unlock()
				<-closeDone
				t.Fatal("Close waited for cleanup lock before closing underlay")
			}
			select {
			case err := <-closeDone:
				mu.Unlock()
				t.Fatalf("Close returned before cleanup lock was released: %v", err)
			default:
			}

			mu.Unlock()
			select {
			case err := <-closeDone:
				if err != nil {
					t.Fatalf("Close: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Close did not finish after cleanup lock was released")
			}
		})
	}
}
