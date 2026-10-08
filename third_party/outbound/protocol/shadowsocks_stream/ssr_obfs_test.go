package shadowsocks_stream_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/shadowsocks_stream"
	"github.com/daeuniverse/outbound/transport/shadowsocksr/obfs"
)

// drainConn is a netproxy.Conn that accepts writes and reads EOF. It stands in
// for the raw transport underneath the protocol stack built below.
type drainConn struct{}

func (drainConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (drainConn) Write(p []byte) (int, error)      { return len(p), nil }
func (drainConn) Close() error                     { return nil }
func (drainConn) SetDeadline(time.Time) error      { return nil }
func (drainConn) SetReadDeadline(time.Time) error  { return nil }
func (drainConn) SetWriteDeadline(time.Time) error { return nil }

var _ netproxy.Conn = drainConn{}

// staticDialer hands out the same conn regardless of the requested address; the
// tests below never reach the network.
type staticDialer struct{ c netproxy.Conn }

func (s staticDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return s.c, nil
}

var _ netproxy.Dialer = staticDialer{}

// tcpTransportOf builds a shadowsocks_stream dialer over next and returns its
// TCP transport entry point.
func tcpTransportOf(t *testing.T, next netproxy.Dialer) func(context.Context, string) (netproxy.Conn, error) {
	t.Helper()
	d, err := shadowsocks_stream.NewDialer(next, protocol.Header{
		ProxyAddress: "example.com:8388",
		Cipher:       "aes-256-cfb",
		Password:     "p@ssw0rd",
		IsClient:     true,
	})
	if err != nil {
		t.Fatalf("shadowsocks_stream.NewDialer: %v", err)
	}
	transport, ok := d.(interface {
		DialTcpTransport(context.Context, string) (netproxy.Conn, error)
	})
	if !ok {
		t.Fatalf("dialer %T does not expose DialTcpTransport", d)
	}
	return transport.DialTcpTransport
}

// TestTcpConnFirstWriteReachesSSRObfsCipher builds the real SSR transport stack
// (raw conn -> obfs -> shadowsocks_stream) and asserts that the first write on
// the resulting conn succeeds.
//
// shadowsocks_stream hands its cipher to the SSR obfs layer through the
// duck-typed SetCipher/SetAddrLen hooks on the conn it wraps, and it wraps that
// underlay in a read-buffering wrapper. A one-level type assertion misses the
// hooks, leaves the obfs cipher nil, and the first write then fails with
// "outer conn did not init cipher of Obfs" - which takes down every TCP flow on
// the node.
func TestTcpConnFirstWriteReachesSSRObfsCipher(t *testing.T) {
	obfsDialer, err := obfs.NewDialer(staticDialer{c: drainConn{}}, &obfs.ObfsParam{
		ObfsHost: "example.com",
		ObfsPort: 80,
		Obfs:     "http_simple",
	})
	if err != nil {
		t.Fatalf("obfs.NewDialer: %v", err)
	}

	conn, err := tcpTransportOf(t, obfsDialer)(context.Background(), "tcp")
	if err != nil {
		t.Fatalf("DialTcpTransport: %v", err)
	}

	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatalf("first write through SSR transport failed: %v", err)
	}
}

// TestTcpConnFirstWriteWithoutSSRObfs is the control: with no obfs layer the
// buffered underlay carries no SSR hooks, and the first write must still
// succeed (the hook lookup is a no-op, not a failure).
func TestTcpConnFirstWriteWithoutSSRObfs(t *testing.T) {
	conn, err := tcpTransportOf(t, staticDialer{c: drainConn{}})(context.Background(), "tcp")
	if err != nil {
		t.Fatalf("DialTcpTransport: %v", err)
	}

	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatalf("first write through plain shadowsocks transport failed: %v", err)
	}
}
