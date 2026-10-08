package tls

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type blockingHandshakeDialer struct {
	server net.Conn
}

func (d *blockingHandshakeDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	client, server := net.Pipe()
	d.server = server
	return client, nil
}

func TestDialContextHandshakeRespectsCallerDeadline(t *testing.T) {
	parent := &blockingHandshakeDialer{}
	tlsDialer, _, err := NewTls(
		&dialer.ExtraOption{},
		parent,
		"tls://proxy.example:443?sni=proxy.example&allowInsecure=1",
	)
	if err != nil {
		t.Fatalf("NewTls() error = %v", err)
	}
	t.Cleanup(func() {
		if parent.server != nil {
			_ = parent.server.Close()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	conn, err := tlsDialer.DialContext(ctx, "tcp", "example.com:443")
	if err == nil {
		_ = conn.Close()
		t.Fatal("DialContext() error = nil, want deadline error")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("DialContext() took %v, want deadline-bound return", elapsed)
	}
}
