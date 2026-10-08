package tuic

import (
	"context"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/infra/clientring"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
)

// clientRing wraps the shared failover ring (protocol/infra/clientring)
// with the tuic dial bodies.
type clientRing struct {
	ring      *clientring.Ring[*clientImpl]
	newClient func(capabilityCallback func(n int64)) *clientImpl
	reserved  int64
}

func newClientRing(newClient func(capabilityCallback func(n int64)) *clientImpl, reserved int64) *clientRing {
	return &clientRing{
		ring: clientring.New(
			newClient,
			func(cli *clientImpl, onClose func()) { cli.setOnClose(onClose) },
			func(cli *clientImpl) error { return cli.Close() },
			reserved,
		),
		newClient: newClient,
		reserved:  reserved,
	}
}

func (r *clientRing) DialContextWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (conn netproxy.Conn, err error) {
	err = r.ring.TryNextContext(ctx, func(node *clientring.Node[*clientImpl]) error {
		if capability := node.Capability(); capability != -1 && capability <= r.reserved {
			return common.ErrHoldOn
		}
		conn, err = node.Client.DialContextWithDialer(ctx, metadata, dialer, dialFn)
		return err
	})
	return conn, err
}

func (r *clientRing) ListenPacketWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (conn netproxy.PacketConn, err error) {
	err = r.ring.TryNextContext(ctx, func(node *clientring.Node[*clientImpl]) error {
		if capability := node.Capability(); capability != -1 && capability <= r.reserved {
			return common.ErrHoldOn
		}
		conn, err = node.Client.ListenPacketWithDialer(ctx, metadata, dialer, dialFn)
		return err
	})
	return conn, err
}

func (r *clientRing) Close() error {
	return r.ring.Close()
}
