package shadowsocks_stream

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
)

type shortThenFailWriter struct {
	mu     sync.Mutex
	writes int
}

func (w *shortThenFailWriter) Read([]byte) (int, error) { return 0, io.EOF }
func (w *shortThenFailWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes++
	if w.writes == 1 {
		n := 1
		if n > len(p) {
			n = len(p)
		}
		return n, nil
	}
	return 0, io.ErrClosedPipe
}
func (w *shortThenFailWriter) Close() error                     { return nil }
func (w *shortThenFailWriter) SetDeadline(time.Time) error      { return nil }
func (w *shortThenFailWriter) SetReadDeadline(time.Time) error  { return nil }
func (w *shortThenFailWriter) SetWriteDeadline(time.Time) error { return nil }

var _ netproxy.Conn = (*shortThenFailWriter)(nil)

func TestTcpConnFirstWriteDoesNotCommitOnShortWrite(t *testing.T) {
	cipher, err := ciphers.NewStreamCipher("aes-256-cfb", "p@ssw0rd")
	if err != nil {
		t.Fatal(err)
	}
	underlay := &shortThenFailWriter{}
	conn := NewTcpConn(underlay, cipher)
	_, err = conn.Write([]byte("hello"))
	if err == nil {
		t.Fatal("expected first write to fail after incomplete underlay write")
	}
	if conn.init {
		t.Fatal("init committed despite failed first write")
	}
	if !conn.writeBroken {
		t.Fatal("expected writeBroken after incomplete encrypted write")
	}
	_, err = conn.Write([]byte("world"))
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("retry after partial first write: %v, want net.ErrClosed", err)
	}
}
