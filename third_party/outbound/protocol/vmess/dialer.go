package vmess

import (
	"context"
	"fmt"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/transport/grpc"
	"github.com/google/uuid"
)

func init() {
	protocol.Register("vmess", NewDialerFactory(protocol.ProtocolVMessTCP))
	protocol.Register("vmess+tls+grpc", NewDialerFactory(protocol.ProtocolVMessTlsGrpc))
}

type Dialer struct {
	protocol          protocol.Protocol
	proxyAddress      string
	proxySNI          string
	grpcServiceName   string
	nextDialer        netproxy.Dialer
	metadata          protocol.Metadata
	key               []byte
	featurePacketAddr bool
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}
	cipher, _ := ParseCipherFromSecurity(Cipher(header.Cipher).ToSecurity())
	metadata.Cipher = string(cipher)

	// UUID mapping
	if l := len([]byte(header.Password)); l < 32 || l > 36 {
		header.Password = common.StringToUUID5(header.Password)
	}

	id, err := uuid.Parse(header.Password)
	if err != nil {
		return nil, err
	}
	//log.Trace("vmess.NewDialer: metadata: %v, password: %v", metadata, password)
	// protocol.Header is an exported API: a caller passing a non-string
	// Feature1 must get an error, not a panic inside NewDialer.
	grpcServiceName, ok := header.Feature1.(string)
	if !ok {
		return nil, fmt.Errorf("vmess: unexpected Feature1 type %T, want string", header.Feature1)
	}
	return &Dialer{
		proxyAddress:      header.ProxyAddress,
		proxySNI:          header.SNI,
		grpcServiceName:   grpcServiceName,
		nextDialer:        nextDialer,
		metadata:          metadata,
		key:               NewID(id).CmdKey(),
		featurePacketAddr: header.Flags&protocol.Flags_VMess_UsePacketAddr > 0,
	}, nil
}

func (d *Dialer) UnwrapDialer() netproxy.Dialer {
	return d.nextDialer
}

func NewDialerFactory(proto protocol.Protocol) func(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	return func(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
		d, err := NewDialer(nextDialer, header)
		if err != nil {
			return nil, err
		}
		dd := d.(*Dialer)
		dd.protocol = proto
		return dd, nil
	}
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp", "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.Cipher = d.metadata.Cipher
		mdata.IsClient = d.metadata.IsClient
		if d.featurePacketAddr && magicNetwork.Network == "udp" {
			mdata.Hostname = SeqPacketMagicAddress
			mdata.Type = protocol.MetadataTypeDomain
		}

		underlayDialer := d.nextDialer
		if d.protocol == protocol.ProtocolVMessTlsGrpc {
			underlayDialer = &grpc.Dialer{
				NextDialer:  d.nextDialer,
				ServiceName: d.grpcServiceName,
				ServerName:  d.proxySNI,
			}
		}
		tcpNetwork := netproxy.MagicNetwork{
			Network: "tcp",
			Mark:    magicNetwork.Mark,
			Mptcp:   magicNetwork.Mptcp,
		}.Encode()
		conn, err := underlayDialer.DialContext(ctx, tcpNetwork, d.proxyAddress)
		if err != nil {
			return nil, err
		}
		// Buffer reads: vmess issues many small io.ReadFull calls per chunk
		// (size header, nonce, payload). Without buffering each costs a syscall.
		conn = netproxy.NewBufferedReaderConn(conn, 0)

		return NewConn(conn, Metadata{
			Metadata: mdata,
			Network:  magicNetwork.Network,
		}, addr, d.key)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
}
