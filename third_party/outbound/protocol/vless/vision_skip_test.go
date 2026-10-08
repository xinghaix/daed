package vless

import (
	gotls "crypto/tls"
	"net"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/vless/vision"
	outboundtls "github.com/daeuniverse/outbound/transport/tls"
	utls "github.com/refraction-networking/utls"
)

// TestVisionNewConnAcceptsSkippedTLSUnderlay is the production XTLS path
// after NewBufferedReaderConn started skipping TLS-like underlays: vless.Conn
// still exposes IntrinsicConn, so vision can peel to *tls.Conn without a
// bufio wrapper.
func TestVisionNewConnAcceptsSkippedTLSUnderlay(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	tlsConn := gotls.Client(client, &gotls.Config{InsecureSkipVerify: true})
	got := netproxy.NewBufferedReaderConn(tlsConn, 0)
	if got != tlsConn {
		t.Fatalf("expected TLS skip: got %T", got)
	}
	overlay, err := NewConn(got, Metadata{}, make([]byte, 16))
	if err != nil {
		t.Fatalf("vless.NewConn returned error: %v", err)
	}
	conn, err := vision.NewConn(overlay, make([]byte, 16))
	if err != nil {
		t.Fatalf("vision.NewConn returned error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected vision conn on the skip path")
	}
}

func TestVisionNewConnAcceptsSkippedRealityUnderlay(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	uConn := utls.UClient(client, &utls.Config{InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	realityConn := &outboundtls.RealityUConn{UConn: uConn}
	got := netproxy.NewBufferedReaderConn(realityConn, 0)
	if got != realityConn {
		t.Fatalf("expected REALITY skip: got %T", got)
	}
	overlay, err := NewConn(got, Metadata{}, make([]byte, 16))
	if err != nil {
		t.Fatalf("vless.NewConn returned error: %v", err)
	}
	conn, err := vision.NewConn(overlay, make([]byte, 16))
	if err != nil {
		t.Fatalf("vision.NewConn returned error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected vision conn on the skip path")
	}
}
