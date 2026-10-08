//go:build !linux

package direct

import "github.com/daeuniverse/outbound/netproxy"

type packetReceiverRegistry struct{}

func newPacketReceiverRegistry() *packetReceiverRegistry {
	return nil
}

// RegisterPacketReceiver is unavailable on platforms without the Linux epoll
// implementation; callers retain the PacketConn ReadFrom fallback.
func (c *directPacketConn) RegisterPacketReceiver(netproxy.PacketReceiveHandler) (func(), bool) {
	return nil, false
}
