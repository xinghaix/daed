package juicity

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/trojanc"
)

type PacketConn struct {
	*Conn
	domainIpMapping sync.Map
	writeTarget     common.LastStringValue[protocol.Metadata]
}

var parseMetadata = protocol.ParseMetadata

func (c *PacketConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, net.JoinHostPort(c.Metadata.Hostname, strconv.Itoa(int(c.Metadata.Port))))
}

func (c *PacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return n, err
}

func (c *PacketConn) ReadFrom(p []byte) (n int, addrPort netip.AddrPort, err error) {
	m := trojanc.Metadata{}
	if _, err = m.Unpack(c.Conn); err != nil {
		return 0, netip.AddrPort{}, err
	}

	// Consume the whole frame before resolving the reported address: see the
	// same note in trojanc.PacketConn.ReadFrom. Any failure then leaves the
	// stream at a frame boundary, so a caller can drop this datagram and keep
	// the session.
	var lengthBuf [2]byte
	if _, err = io.ReadFull(c.Conn, lengthBuf[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	length := int(binary.BigEndian.Uint16(lengthBuf[:]))
	if length > len(p) {
		if n, err = io.ReadFull(c.Conn, p); err != nil {
			return 0, netip.AddrPort{}, err
		}
		_, _ = io.CopyN(io.Discard, c.Conn, int64(length-len(p)))
	} else if n, err = io.ReadFull(c.Conn, p[:length]); err != nil {
		return 0, netip.AddrPort{}, err
	}

	if addrPort, err = m.DomainIpMapping(&c.domainIpMapping); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("ReadFrom AddrPort: %w", err)
	}
	return n, addrPort, nil
}

func (c *PacketConn) WriteTo(p []byte, addr string) (n int, err error) {
	_metadata, err := c.metadataForAddr(addr)
	if err != nil {
		return 0, err
	}
	metadata := trojanc.Metadata{
		Metadata: _metadata,
		Network:  "udp",
	}
	c.Conn.writeMutex.Lock()
	defer c.Conn.writeMutex.Unlock()
	buf := c.Conn.borrowPacketWriteBuffer(metadata.Len() + 2 + len(p))
	SealUDP(metadata, buf, p)
	_, err = c.Conn.writeLocked(buf)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *PacketConn) metadataForAddr(addr string) (protocol.Metadata, error) {
	if cached, ok := c.writeTarget.Load(addr); ok {
		return cached, nil
	}
	mdata, err := parseMetadata(addr)
	if err != nil {
		return protocol.Metadata{}, err
	}
	c.writeTarget.Store(addr, mdata)
	return mdata, nil
}

func (c *PacketConn) Close() error {
	return c.Conn.Close()
}

func (c *PacketConn) TransportDone() <-chan struct{} {
	if c.Conn == nil {
		return nil
	}
	return c.Conn.TransportDone()
}

var _ netproxy.TransportLifecycle = (*PacketConn)(nil)

func SealUDP(metadata trojanc.Metadata, dst []byte, data []byte) []byte {
	n := metadata.Len()
	// copy first to allow overlap
	copy(dst[n+2:], data)
	metadata.PackTo(dst)
	binary.BigEndian.PutUint16(dst[n:], uint16(len(data)))
	return dst[:n+2+len(data)]
}
