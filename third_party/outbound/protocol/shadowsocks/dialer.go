package shadowsocks

import (
	"context"
	"fmt"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

func init() {
	protocol.Register("shadowsocks", NewDialer)
}

type Dialer struct {
	proxyAddress string
	nextDialer   netproxy.Dialer
	metadata     protocol.Metadata
	key          []byte
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	//log.Trace("shadowsocks.NewDialer: metadata: %v, password: %v", metadata, password)
	return &Dialer{
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
		metadata: protocol.Metadata{
			Cipher:   header.Cipher,
			IsClient: header.IsClient,
		},
		key: common.EVPBytesToKey(header.Password, ciphers.AeadCiphersConf[header.Cipher].KeyLen),
	}, nil
}

func (d *Dialer) UnwrapDialer() netproxy.Dialer {
	return d.nextDialer
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.Cipher = d.metadata.Cipher
		mdata.IsClient = d.metadata.IsClient

		// Shadowsocks transfer TCP traffic via TCP tunnel.
		conn, err := d.nextDialer.DialContext(ctx, network, d.proxyAddress)
		if err != nil {
			return nil, err
		}
		// Wrap with a buffered reader so io.ReadFull on chunk headers and
		// payloads does not each hit the kernel. See BufferedReaderConn docs.
		conn = netproxy.NewBufferedReaderConn(conn, 0)
		c, err := NewTCPConn(conn, mdata, d.key, nil)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return c, nil
	case "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.Cipher = d.metadata.Cipher
		mdata.IsClient = d.metadata.IsClient

		// Shadowsocks transfer UDP traffic via UDP tunnel.
		magicNetwork.Network = "udp"
		conn, err := d.nextDialer.DialContext(ctx, magicNetwork.Encode(), d.proxyAddress)
		if err != nil {
			return nil, err
		}
		pktConn, ok := conn.(netproxy.PacketConn)
		if !ok {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: %T does not implement PacketConn", netproxy.UnsupportedTunnelTypeError, conn)
		}
		c, err := NewUdpConn(pktConn, d.proxyAddress, mdata, d.key, nil)
		if err != nil {
			// The cipher was rejected after the dial succeeded: the
			// underlay belongs to this call until the wrapper takes over.
			_ = conn.Close()
			return nil, err
		}
		return c, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
