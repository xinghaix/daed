package bufferred_conn

import (
	"net"
	"sync"

	"github.com/daeuniverse/outbound/pkg/zeroalloc/bufio"
)

type BufferedConn struct {
	r         *bufio.Reader
	net.Conn  // So that most methods are embedded
	closeOnce sync.Once
	closeErr  error
	putOnce   sync.Once
}

func NewBufferedConn(c net.Conn) *BufferedConn {
	return &BufferedConn{r: bufio.NewReader(c), Conn: c}
}

func NewBufferedConnSize(c net.Conn, n int) *BufferedConn {
	return &BufferedConn{r: bufio.NewReaderSize(c, n), Conn: c}
}

func (b *BufferedConn) Peek(n int) ([]byte, error) {
	if b == nil || b.r == nil {
		return nil, net.ErrClosed
	}
	return b.r.Peek(n)
}

func (b *BufferedConn) UnderlyingConn() net.Conn {
	return b.Conn
}

// TakeRelayPrefix returns currently buffered bytes and marks them consumed so
// relay can flush the prefix directly before continuing normal reads.
//
// The returned slice is only safe for immediate synchronous use before the
// next BufferedConn read.
func (b *BufferedConn) TakeRelayPrefix() []byte {
	if b == nil || b.r == nil {
		return nil
	}
	n := b.r.Buffered()
	if n == 0 {
		return nil
	}
	prefix, err := b.r.Peek(n)
	if err != nil || len(prefix) == 0 {
		return nil
	}
	if _, err := b.r.Discard(len(prefix)); err != nil {
		return nil
	}
	return prefix
}

func (b *BufferedConn) Close() error {
	if b == nil {
		return nil
	}
	b.closeOnce.Do(func() {
		if b.Conn != nil {
			b.closeErr = b.Conn.Close()
		}
	})
	return b.closeErr
}

// ReleaseReader returns the pooled read buffer after the sole reader exits.
// It must not run concurrently with any read-side method.
func (b *BufferedConn) ReleaseReader() {
	if b == nil {
		return
	}
	b.putOnce.Do(func() {
		if b.r != nil {
			b.r.Put()
			b.r = nil
		}
	})
}

func (b *BufferedConn) Read(p []byte) (int, error) {
	if b == nil || b.r == nil {
		return 0, net.ErrClosed
	}
	return b.r.Read(p)
}

func (c *BufferedConn) ReadByte() (byte, error) {
	if c == nil || c.r == nil {
		return 0, net.ErrClosed
	}
	return c.r.ReadByte()
}

func (c *BufferedConn) UnreadByte() error {
	if c == nil || c.r == nil {
		return net.ErrClosed
	}
	return c.r.UnreadByte()
}
