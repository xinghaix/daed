package v2ray_test

import (
	"context"
	"errors"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/dialer/v2ray"
	"github.com/daeuniverse/outbound/netproxy"
)

var errGenerationDialerUsed = errors.New("generation dialer used")

type generationDialer struct{}

func (generationDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, errGenerationDialerUsed
}

func TestHTTPTransportUsesProvidedGenerationDialer(t *testing.T) {
	parsed := &v2ray.V2Ray{
		Add:      "192.0.2.1",
		Port:     "443",
		ID:       "00000000-0000-0000-0000-000000000001",
		Net:      "h2",
		Protocol: "vmess",
	}
	got, _, err := parsed.Dialer(&dialer.ExtraOption{}, generationDialer{})
	if err != nil {
		t.Fatalf("Dialer() error = %v", err)
	}

	_, err = got.DialContext(context.Background(), "tcp", "example.com:80")
	if !errors.Is(err, errGenerationDialerUsed) {
		t.Fatalf("DialContext() error = %v, want generation dialer sentinel", err)
	}
}
