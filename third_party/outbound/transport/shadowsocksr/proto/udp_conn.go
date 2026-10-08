package proto

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/pool/bytes"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
	"github.com/daeuniverse/outbound/protocol/shadowsocks_stream"
)

type PacketConn struct {
	netproxy.PacketConn
	Protocol  IProtocol
	tgt       string
	writeMu   sync.Mutex
	addrCache common.LastStringValue[socks.Addr]
}

var parseSocksAddr = socks.ParseAddr

func NewPacketConn(c netproxy.PacketConn, proto IProtocol, tgt string) (*PacketConn, error) {
	return &PacketConn{
		PacketConn: c,
		Protocol:   proto,
		tgt:        tgt,
	}, nil
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the wrapped transport: SetWriteDeadline is
// delegated to the underlying PacketConn unchanged, so the semantics — and
// the declaration — belong to that transport, not to this wrapper.
// Production wraps shadowsocks_stream.DialUdpTransport here, whose own
// forward would otherwise be erased by this outer layer.
func (c *PacketConn) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(c.PacketConn)
}

func (c *PacketConn) InnerCipher() *ciphers.StreamCipher {
	switch innerConn := c.PacketConn.(type) {
	case *shadowsocks_stream.UdpConn:
		return innerConn.Cipher()
	default:
		return nil
	}
}

func (c *PacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return n, err
}

func (c *PacketConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.tgt)
}

func (c *PacketConn) ReadFrom(b []byte) (n int, from netip.AddrPort, err error) {
	n, err = c.PacketConn.Read(b)
	if err != nil {
		return n, netip.AddrPort{}, err
	}
	decoded, err := c.Protocol.DecodePkt(b[:n])
	if err != nil {
		return n, netip.AddrPort{}, err
	}
	defer decoded.Put()

	addr := socks.SplitAddr(decoded.Bytes())
	if addr == nil {
		return 0, netip.AddrPort{}, fmt.Errorf("no addr present")
	}

	from, ok := addr.AddrPort()
	if !ok {
		var err error
		from, err = netip.ParseAddrPort(addr.String())
		if err != nil {
			return 0, netip.AddrPort{}, fmt.Errorf("bad addr: %w", err)
		}
	}

	//if len(b) < len(decoded.Bytes())-len(addr) {
	//	return 0, netip.AddrPort{}, fmt.Errorf("buffer is not enough to read")
	//}
	n = copy(b, decoded.Bytes()[len(addr):])
	return n, from, nil
}

func (c *PacketConn) WriteTo(b []byte, to string) (n int, err error) {
	addr, err := c.targetAddr(to)
	if err != nil {
		return 0, err
	}

	// Lock to protect concurrent writes.
	// Critical section is minimized to only protect the shared buffer and write operation.
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	pb := pool.Get(len(addr) + len(b))
	defer pool.Put(pb)

	copy(pb, addr)
	copy(pb[len(addr):], b)
	buf := bytes.NewBuffer(pb)
	if err = c.Protocol.EncodePkt(buf); err != nil {
		return 0, err
	}
	if _, err = c.PacketConn.Write(buf.Bytes()); err != nil {
		return 0, err
	}

	return len(b), nil
}

func (c *PacketConn) targetAddr(addr string) (socks.Addr, error) {
	if cached, ok := c.addrCache.Load(addr); ok {
		return cached, nil
	}
	target, err := parseSocksAddr(addr)
	if err != nil {
		return nil, err
	}
	target = append(socks.Addr(nil), target...)
	c.addrCache.Store(addr, target)
	return target, nil
}
