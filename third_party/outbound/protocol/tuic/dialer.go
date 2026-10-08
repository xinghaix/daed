package tuic

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/google/uuid"
	"github.com/olicesx/quic-go"
)

func init() {
	protocol.Register("tuic", NewDialer)
}

type Dialer struct {
	clientRing *clientRing

	proxyAddress string
	proxyUDPAddr *net.UDPAddr
	nextDialer   netproxy.Dialer
	metadata     protocol.Metadata
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}

	id, err := uuid.Parse(header.User)
	if err != nil {
		return nil, fmt.Errorf("parse UUID: %w", err)
	}
	// ensure server's incoming stream can handle correctly, increase to 1.1x
	maxDatagramFrameSize := 1452 // = quic-go MaxPacketBufferSize (Ethernet PMTU)
	// UdpRelayMode is intentionally pinned to NATIVE: the QUIC unistream
	// relay mode has known throughput problems and is not selectable from
	// configuration. The ClientOption field and the packet.go QUIC branch
	// stay for API compatibility.
	udpRelayMode := common.NATIVE
	// cwnd doubles as the brutal congestion controller's target bandwidth
	// (bytes per second) when congestion_control=brutal, and is what selects it
	// when the server negotiated brutal and the link declared a rate; 0 means no
	// rate is known, so the probing default is installed.
	cwnd := common.CWNDFromFeature(header.Feature2)
	// Feature1 is the congestion controller echoed by the server. A non-string
	// value (a caller mistake) must degrade instead of panicking; the override,
	// when present, takes precedence over whatever the server echoed.
	serverCC, _ := header.Feature1.(string)
	cc, err := common.SelectCongestionController(serverCC, header.CongestionOverride, cwnd)
	if err != nil {
		return nil, err
	}
	proxyUDPAddr, err := net.ResolveUDPAddr("udp", header.ProxyAddress)
	if err != nil {
		return nil, err
	}
	return &Dialer{
		clientRing: newClientRing(func(capabilityCallback func(n int64)) *clientImpl {
			return newClientImpl(&ClientOption{
				TlsConfig: header.TlsConfig,
				QuicConfig: &quic.Config{
					InitialStreamReceiveWindow:     common.InitialStreamReceiveWindow,
					MaxStreamReceiveWindow:         common.MaxStreamReceiveWindow,
					InitialConnectionReceiveWindow: common.InitialConnectionReceiveWindow,
					MaxConnectionReceiveWindow:     common.MaxConnectionReceiveWindow,
					KeepAlivePeriod:                3 * time.Second,
					DisablePathMTUDiscovery:        false,
					EnableDatagrams:                true,
					HandshakeIdleTimeout:           8 * time.Second,
					CapabilityCallback:             capabilityCallback,
				},
				Uuid:                  id,
				Password:              header.Password,
				UdpRelayMode:          udpRelayMode,
				CongestionController:  cc,
				ReduceRtt:             true, // 0-RTT cuts cold-start RTT
				CWND:                  cwnd,
				MaxUdpRelayPacketSize: maxDatagramFrameSize,
			}, true, 64)
		}, 10),
		proxyAddress: header.ProxyAddress,
		proxyUDPAddr: proxyUDPAddr,
		nextDialer:   nextDialer,
		metadata:     metadata,
	}, nil
}

func (d *Dialer) dialFuncFactory(udpNetwork string, rAddr net.Addr) common.DialFunc {
	return func(ctx context.Context, dialer netproxy.Dialer) (transport *quic.Transport, addr net.Addr, err error) {
		conn, err := dialer.DialContext(ctx, udpNetwork, d.proxyAddress)
		if err != nil {
			return nil, nil, err
		}
		pc := netproxy.NewFakeNetPacketConn(
			conn.(netproxy.PacketConn),
			net.UDPAddrFromAddrPort(common.GetUniqueFakeAddrPort()),
			rAddr,
		)
		transport = &quic.Transport{
			Conn:               pc,
			DisableAddrParsing: true,
		}
		return transport, rAddr, nil
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
		mdata.IsClient = d.metadata.IsClient
		udpNetwork := network
		if magicNetwork.Network == "tcp" {
			udpNetwork = netproxy.MagicNetwork{
				Network: "udp",
				Mark:    magicNetwork.Mark,
			}.Encode()
			tcpConn, err := d.clientRing.DialContextWithDialer(ctx, &mdata, d.nextDialer,
				d.dialFuncFactory(udpNetwork, d.proxyUDPAddr),
			)
			if err != nil {
				return nil, err
			}
			return tcpConn, nil
		} else {
			udpConn, err := d.clientRing.ListenPacketWithDialer(ctx, &mdata, d.nextDialer,
				d.dialFuncFactory(udpNetwork, d.proxyUDPAddr),
			)
			if err != nil {
				return nil, err
			}
			udpConn.(*quicStreamPacketConn).target = addr
			return udpConn, nil
		}

	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
}

func (d *Dialer) Close() error {
	if d == nil || d.clientRing == nil {
		return nil
	}
	return d.clientRing.Close()
}
