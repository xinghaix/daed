package proto

import (
	"context"
	"errors"
	"fmt"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
	"github.com/daeuniverse/outbound/protocol/shadowsocks_stream"
)

type Dialer struct {
	NextDialer    netproxy.Dialer
	Protocol      string
	ProtocolParam string
	ObfsOverhead  int
}

func (d *Dialer) protocolFromInnerConn(conn netproxy.Conn, addr socks.Addr) (proto IProtocol, err error) {
	proto = NewProtocol(d.Protocol)
	if proto == nil {
		return nil, errors.New("unsupported protocol type: " + d.Protocol)
	}
	proto.SetData(proto.GetData())
	switch c := conn.(type) {
	case interface{ Cipher() *ciphers.StreamCipher }:
		iv, err := c.Cipher().InitEncrypt()
		if err != nil {
			return nil, err
		}
		key := c.Cipher().Key()
		if key == nil {
			return nil, fmt.Errorf("ss conn did not init Key")
		}
		proto.InitWithServerInfo(&ServerInfo{
			Param:    d.ProtocolParam,
			TcpMss:   1460,
			IV:       iv,
			Key:      key,
			AddrLen:  len(addr),
			Overhead: proto.GetOverhead() + d.ObfsOverhead,
		})
		return proto, nil
	default:
		return nil, fmt.Errorf("unsupported conn: %T", conn)
	}
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		addr, err := socks.ParseAddr(address)
		if err != nil {
			return nil, err
		}

		switch nextDialer := d.NextDialer.(type) {
		case *shadowsocks_stream.Dialer:
			transportConn, err := nextDialer.DialTcpTransport(ctx, network)
			if err != nil {
				return nil, err
			}
			// From here on transportConn is owned by this function; every
			// failure path must close it or the fd leaks.
			proto, err := d.protocolFromInnerConn(transportConn, addr)
			if err != nil {
				_ = transportConn.Close()
				return nil, err
			}
			conn, err := NewConn(transportConn, proto)
			if err != nil {
				_ = transportConn.Close()
				return nil, err
			}
			if _, err = conn.Write(addr); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("failed to write target: %w", err)
			}
			return conn, nil
		default:
			return nil, fmt.Errorf("unsupported next dialer: %T", d.NextDialer)
		}
	case "udp":
		addr, err := socks.ParseAddr(address)
		if err != nil {
			return nil, err
		}

		switch nextDialer := d.NextDialer.(type) {
		case *shadowsocks_stream.Dialer:
			c, err := nextDialer.DialUdpTransport(ctx, network)
			if err != nil {
				return nil, err
			}

			proto, err := d.protocolFromInnerConn(c, addr)
			if err != nil {
				_ = c.Close()
				return nil, err
			}

			packetConn, err := NewPacketConn(c, proto, address)
			if err != nil {
				_ = c.Close()
				return nil, err
			}
			return packetConn, nil
		default:
			return nil, fmt.Errorf("unsupported inner dialer: %T", d.NextDialer)
		}
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
