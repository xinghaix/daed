package vmess

import (
	"context"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

type testScopedDialer struct {
	namespace string
}

func (d *testScopedDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, nil
}

func (d *testScopedDialer) TransportCacheNamespace() string {
	return d.namespace
}

func TestDialerTransportCacheNamespaceFollowsUnderlyingDialer(t *testing.T) {
	dialer, err := NewDialer(&testScopedDialer{namespace: "reload-scope"}, protocol.Header{
		ProxyAddress: "127.0.0.1:443",
		Password:     "6b1b36c1-bf0d-4b5e-b411-589efc1029e8",
		Cipher:       "auto",
		Feature1:     "GunService",
		IsClient:     true,
	})
	if err != nil {
		t.Fatalf("NewDialer() error = %v", err)
	}
	if got := netproxy.TransportCacheNamespace(dialer); got != "reload-scope" {
		t.Fatalf("TransportCacheNamespace() = %q, want %q", got, "reload-scope")
	}
}
