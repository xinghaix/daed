package vmess

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/pool"
)

func (c *Conn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	if !c.metadata.IsPacketAddr() {
		// Fixed target: read the datagram straight into the caller's
		// buffer instead of bouncing through a pooled MaxUDPSize copy.
		n, err = c.read(p)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		tgt, err := c.dialTargetAddrPort()
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		return n, tgt, nil
	}
	buf := pool.Get(MaxUDPSize)
	defer pool.Put(buf)
	n, err = c.read(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	addrTyp, address, err := ExtractPacketAddr(buf)
	addrLen := PacketAddrLength(addrTyp)
	if n < addrLen {
		return 0, netip.AddrPort{}, fmt.Errorf("not enough data to read for PacketAddr")
	}
	payload := n - addrLen
	copied := copy(p, buf[addrLen:n])
	if copied < payload {
		return copied, address, fmt.Errorf("buf size is not enough")
	}
	return copied, address, err
}

func (c *Conn) WriteTo(p []byte, addr string) (n int, err error) {
	if c.metadata.IsPacketAddr() {
		// VMess packet addr does not support domain.
		address, err := c.writeTargetAddrPort(addr)
		if err != nil {
			return 0, err
		}
		packetAddrLen := UDPAddrToPacketAddrLength(address)
		buf := pool.Get(packetAddrLen + len(p))
		defer pool.Put(buf)

		err = PutPacketAddr(buf, address)
		if err != nil {
			return 0, err
		}
		copy(buf[packetAddrLen:], p)
		return c.write(buf)
	}

	return c.write(p)
}

func (c *Conn) writeTargetAddrPort(addr string) (*net.UDPAddr, error) {
	if addr == c.dialTgt {
		target, err := c.dialTargetAddrPort()
		if err != nil {
			return nil, err
		}
		return net.UDPAddrFromAddrPort(target), nil
	}
	if cached, ok := c.writeCache.Load(addr); ok {
		return net.UDPAddrFromAddrPort(cached), nil
	}
	target, err := resolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	addrPort := unmapAddrPort(target.AddrPort())
	c.writeCache.Store(addr, addrPort)
	return target, nil
}
