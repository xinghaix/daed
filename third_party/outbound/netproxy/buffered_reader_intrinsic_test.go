package netproxy

import (
	gotls "crypto/tls"
	"net"
	"testing"
)

// TestBufferedReaderConnIntrinsicConnUnwrapsToTLSConn verifies that XTLS/Vision
// can reach the underlying *tls.Conn through a BufferedReaderConn wrapper.
// Without this method, visionIntrinsicConn's type assertion fails with
// "XTLS only supports TLS and REALITY directly for now: *BufferedReaderConn".
func TestBufferedReaderConnIntrinsicConnUnwrapsToTLSConn(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	tlsConn := gotls.Client(client, &gotls.Config{InsecureSkipVerify: true})
	// The TLS handshake won't complete over net.Pipe without a peer, but
	// *tls.Client's identity as a netproxy.Conn is what matters here.
	// Force the wrap: NewBufferedReaderConn now skips TLS-like underlays.
	wrapped := ForceBufferedReaderConn(tlsConn, 0)

	got := wrapped.IntrinsicConn()
	if got != tlsConn {
		t.Fatalf("IntrinsicConn() = %T, want the wrapped *tls.Conn", got)
	}
}

func TestDefaultReadBufferSizeStaysBounded(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	wrapped := ForceBufferedReaderConn(netPipeConn{client}, 0)
	if got := wrapped.reader.Size(); got != 32<<10 {
		t.Fatalf("default read buffer size = %d, want %d", got, 32<<10)
	}
}

// TestBufferedReaderConnIntrinsicConnForwardsThroughNestedWrapper ensures that
// when BufferedReaderConn wraps another IntrinsicConn-bearing wrapper, the
// call recurses so callers always reach the innermost TLS/REALITY connection.
func TestBufferedReaderConnIntrinsicConnForwardsThroughNestedWrapper(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	tlsConn := gotls.Client(client, &gotls.Config{InsecureSkipVerify: true})
	inner := &intrinsicForwarder{Conn: tlsConn, inner: tlsConn}
	outer := ForceBufferedReaderConn(inner, 0)

	got := outer.IntrinsicConn()
	if got != tlsConn {
		t.Fatalf("IntrinsicConn() = %T, want the innermost *tls.Conn", got)
	}
}

// TestBufferedReaderConnIsAnIntrinsicConn is a regression guard: if the
// IntrinsicConn method is ever removed, this test stops passing, which
// surfaces the breakage before a user hits the Vision type-assertion error.
func TestBufferedReaderConnIsAnIntrinsicConn(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	wrapped := NewBufferedReaderConn(netPipeConn{client}, 0)
	br, ok := wrapped.(*BufferedReaderConn)
	if !ok {
		t.Fatalf("plain underlay: got %T, want *BufferedReaderConn", wrapped)
	}
	type intrinsicConn interface {
		IntrinsicConn() Conn
	}
	if _, ok := interface{}(br).(intrinsicConn); !ok {
		t.Fatal("BufferedReaderConn no longer satisfies the intrinsicConn interface")
	}
}

// TestNewBufferedReaderConnSkipsTLSLikeUnderlay is the live-RSS cut: a TLS
// record layer already coalesces small ReadFull calls, so wrapping it again
// would hold an extra read buffer for the connection lifetime.
func TestNewBufferedReaderConnSkipsTLSLikeUnderlay(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	tlsConn := gotls.Client(client, &gotls.Config{InsecureSkipVerify: true})
	got := NewBufferedReaderConn(tlsConn, 0)
	if got != tlsConn {
		t.Fatalf("TLS underlay: got %T, want the original *tls.Conn", got)
	}
	if _, ok := got.(net.Conn); !ok {
		t.Fatal("skipped TLS conn must still satisfy net.Conn (ss2022 asserts this)")
	}
}

func TestNewBufferedReaderConnWrapsPlainUnderlay(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	got := NewBufferedReaderConn(netPipeConn{client}, 0)
	if _, ok := got.(*BufferedReaderConn); !ok {
		t.Fatalf("plain underlay: got %T, want *BufferedReaderConn", got)
	}
}

func TestNewBufferedReaderConnHonorsAlreadyReadBuffered(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	marked := alreadyBufferedConn{Conn: netPipeConn{client}}
	got := NewBufferedReaderConn(marked, 0)
	if got != marked {
		t.Fatalf("AlreadyReadBuffered underlay: got %T, want the original conn", got)
	}
}

func TestNewBufferedReaderConnIsIdempotent(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	first := NewBufferedReaderConn(netPipeConn{client}, 0)
	second := NewBufferedReaderConn(first, 0)
	if first != second {
		t.Fatal("wrapping an already-buffered conn allocated a second bufio")
	}
}

// TestBufferedReaderConnUnderlyingConnDoesNotUnwrapPlainTCP is the splice
// gate: protocol Conns embed BufferedReaderConn, and dae's unwrap path
// follows UnderlyingConn. Returning the inner *net.TCPConn would let splice
// ship AEAD ciphertext to the LAN client.
func TestBufferedReaderConnUnderlyingConnDoesNotUnwrapPlainTCP(t *testing.T) {
	client, _ := tcpPair(t)
	wrapped := ForceBufferedReaderConn(client, 0)
	if got := wrapped.UnderlyingConn(); got != nil {
		t.Fatalf("UnderlyingConn() = %T, want nil so splice cannot skip AEAD", got)
	}
	if _, ok := UnwrapTCPConn(wrapped); ok {
		t.Fatal("UnwrapTCPConn succeeded on BufferedReaderConn over *net.TCPConn")
	}
}

// netPipeConn adapts net.Pipe's endpoint to netproxy.Conn.
type netPipeConn struct {
	net.Conn
}

type intrinsicForwarder struct {
	Conn
	inner Conn
}

func (w *intrinsicForwarder) IntrinsicConn() Conn { return w.inner }

type alreadyBufferedConn struct{ Conn }

func (alreadyBufferedConn) AlreadyReadBuffered() {}
