package trojanc

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/protocol"
)

type PacketConn struct {
	*Conn
	domainIpMapping sync.Map
	writeTarget     common.LastStringValue[protocol.Metadata]
}

var parseMetadata = protocol.ParseMetadata

func (c *PacketConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, net.JoinHostPort(c.metadata.Hostname, strconv.Itoa(int(c.metadata.Port))))
}

func (c *PacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return n, err
}

func (c *PacketConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	m := Metadata{}
	if _, err = m.Unpack(c.Conn); err != nil {
		return 0, netip.AddrPort{}, err
	}

	// Consume the whole frame before resolving the reported address. Resolving
	// can fail (a peer-supplied domain that does not resolve in time), and
	// returning with the body still unread would leave the next Unpack parsing
	// payload bytes as metadata. Reading first keeps every error at a frame
	// boundary, which is what lets the caller drop one datagram and keep the
	// session instead of tearing it down.
	var lengthAndCRLF [4]byte
	if _, err = io.ReadFull(c.Conn, lengthAndCRLF[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	if lengthAndCRLF[2] != '\r' || lengthAndCRLF[3] != '\n' {
		return 0, netip.AddrPort{}, fmt.Errorf("invalid trojan UDP CRLF")
	}
	length := int(binary.BigEndian.Uint16(lengthAndCRLF[:2]))
	if length > len(p) {
		// Caller buffer too small: fill it and discard the remainder of the
		// datagram so the stream stays framed.
		if n, err = io.ReadFull(c.Conn, p); err != nil {
			return 0, netip.AddrPort{}, err
		}
		_, _ = io.CopyN(io.Discard, c.Conn, int64(length-len(p)))
	} else if n, err = io.ReadFull(c.Conn, p[:length]); err != nil {
		return 0, netip.AddrPort{}, err
	}

	if addr, err = m.DomainIpMapping(&c.domainIpMapping); err != nil {
		return 0, netip.AddrPort{}, err
	}
	return n, addr, nil
}

func (c *PacketConn) WriteTo(p []byte, addr string) (n int, err error) {
	_metadata, err := c.metadataForAddr(addr)
	if err != nil {
		return 0, err
	}
	metadata := Metadata{
		Metadata: _metadata,
		Network:  "udp",
	}
	c.Conn.writeMutex.Lock()
	defer c.Conn.writeMutex.Unlock()
	buf := c.Conn.borrowPacketWriteBuffer(metadata.Len() + 4 + len(p))
	SealUDP(metadata, buf, p)
	if _, err = c.Conn.writeLocked(buf); err != nil {
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

func SealUDP(metadata Metadata, dst []byte, data []byte) []byte {
	n := metadata.Len()
	// copy first to allow overlap
	copy(dst[n+4:], data)
	metadata.PackTo(dst)
	binary.BigEndian.PutUint16(dst[n:], uint16(len(data)))
	copy(dst[n+2:], CRLF)
	return dst[:n+4+len(data)]
}
