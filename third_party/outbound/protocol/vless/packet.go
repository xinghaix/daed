package vless

import (
	"encoding/binary"
	"io"
	"net/netip"

	"github.com/daeuniverse/outbound/netproxy"
)

func (c *Conn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	// FIXME: a compromise on Symmetric NAT
	addr = c.cachedProxyAddrIpIP

	var bLen [2]byte
	if _, err = io.ReadFull(&netproxy.ReadWrapper{ReadFunc: c.read}, bLen[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	length := int(binary.BigEndian.Uint16(bLen[:]))
	if len(p) < length {
		if _, discardErr := io.CopyN(io.Discard, &netproxy.ReadWrapper{ReadFunc: c.read}, int64(length)); discardErr != nil {
			return 0, netip.AddrPort{}, discardErr
		}
		return 0, netip.AddrPort{}, io.ErrShortBuffer
	}
	n, err = io.ReadFull(&netproxy.ReadWrapper{ReadFunc: c.read}, p[:length])
	return n, addr, err
}

func (c *Conn) WriteTo(p []byte, addr string) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	var bLen [2]byte
	binary.BigEndian.PutUint16(bLen[:], uint16(len(p)))
	if _, err = c.write(bLen[:]); err != nil {
		return 0, err
	}
	return c.write(p)
}
