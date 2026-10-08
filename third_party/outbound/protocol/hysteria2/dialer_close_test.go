package hysteria2

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	hyclient "github.com/daeuniverse/outbound/protocol/hysteria2/client"
)

type closeTrackingHyClient struct {
	closes atomic.Int32
}

func (c *closeTrackingHyClient) TCP(string, context.Context) (netproxy.Conn, error) {
	return nil, nil
}

func (c *closeTrackingHyClient) UDP(string, context.Context) (netproxy.Conn, error) {
	return nil, nil
}

func (c *closeTrackingHyClient) Close() error {
	c.closes.Add(1)
	return nil
}

var _ hyclient.Client = (*closeTrackingHyClient)(nil)

func TestDialerCloseDelegatesToClient(t *testing.T) {
	client := &closeTrackingHyClient{}
	d := &Dialer{client: client}

	if err := d.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := client.closes.Load(); got != 1 {
		t.Fatalf("client Close calls = %d, want 1", got)
	}
}
