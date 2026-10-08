package shadowsocks_stream

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
)

type pipeConn struct {
	net.Conn
}

func (c *pipeConn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(t) }
func (c *pipeConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *pipeConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }

var _ netproxy.Conn = (*pipeConn)(nil)

func TestTcpConnConcurrentReadWrite(t *testing.T) {
	left, right := net.Pipe()
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})

	clientCipher, err := ciphers.NewStreamCipher("aes-256-cfb", "p@ssw0rd")
	if err != nil {
		t.Fatal(err)
	}
	serverCipher, err := ciphers.NewStreamCipher("aes-256-cfb", "p@ssw0rd")
	if err != nil {
		t.Fatal(err)
	}
	client := NewTcpConn(&pipeConn{Conn: left}, clientCipher)
	peer := NewTcpConn(&pipeConn{Conn: right}, serverCipher)

	up := []byte("hello-stream")
	down := []byte("world-reply")
	var wg sync.WaitGroup
	wg.Add(2)
	errCh := make(chan error, 2)
	go func() {
		defer wg.Done()
		if _, err := client.Write(up); err != nil {
			errCh <- err
			return
		}
		got := make([]byte, len(down))
		if _, err := io.ReadFull(client, got); err != nil {
			errCh <- err
			return
		}
		if string(got) != string(down) {
			errCh <- io.ErrUnexpectedEOF
		}
	}()
	go func() {
		defer wg.Done()
		got := make([]byte, len(up))
		if _, err := io.ReadFull(peer, got); err != nil {
			errCh <- err
			return
		}
		if string(got) != string(up) {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		if _, err := peer.Write(down); err != nil {
			errCh <- err
		}
	}()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent Read/Write timed out")
	}
	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
}
