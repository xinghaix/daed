package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/daeuniverse/outbound/pkg/coalesce"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	utls "github.com/refraction-networking/utls"
)

// Tls is a base Tls struct
type Tls struct {
	dialer              netproxy.Dialer
	addr                string
	serverName          string
	skipVerify          bool
	tlsImplentation     string
	utlsImitate         string
	passthroughUdp      bool
	fragmentation       bool
	fragmentMinLength   int64
	fragmentMaxLength   int64
	fragmentMinInterval int64
	fragmentMaxInterval int64

	tlsConfig *tls.Config
}

func (s *Tls) UnwrapDialer() netproxy.Dialer {
	return s.dialer
}

// NewTls returns a Tls infra.
func NewTls(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, nil, fmt.Errorf("NewTls: %w", err)
	}

	query := u.Query()

	tlsImplentation := u.Scheme
	utlsImitate := query.Get("utlsImitate")
	if (tlsImplentation == "tls" || tlsImplentation == "") && option.TlsImplementation != "" {
		tlsImplentation = option.TlsImplementation
		utlsImitate = option.UtlsImitate
	}
	t := &Tls{
		dialer:          nextDialer,
		addr:            u.Host,
		tlsImplentation: tlsImplentation,
		utlsImitate:     utlsImitate,
		serverName:      query.Get("sni"),
	}
	if t.tlsImplentation == "utls" {
		// Fail an unknown fingerprint at construction time instead of on
		// every dial, after the underlay connection was already established.
		if _, err := nameToUtlsClientHelloID(utlsImitate); err != nil {
			return nil, nil, fmt.Errorf("NewTls: %w", err)
		}
	}
	if t.serverName == "" {
		t.serverName = u.Hostname()
	}
	t.passthroughUdp, _ = strconv.ParseBool(u.Query().Get("passthroughUdp"))

	// skipVerify
	allowInsecure, _ := strconv.ParseBool(u.Query().Get("allowInsecure"))
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(u.Query().Get("allow_insecure"))
	}
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(u.Query().Get("allowinsecure"))
	}
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(u.Query().Get("skipVerify"))
	}
	t.skipVerify = allowInsecure || option.AllowInsecure
	t.tlsConfig = &tls.Config{
		ServerName:         t.serverName,
		InsecureSkipVerify: t.skipVerify,
	}
	if len(query.Get("alpn")) > 0 {
		t.tlsConfig.NextProtos = strings.Split(query.Get("alpn"), ",")
	}

	if option.TlsFragment {
		t.fragmentation = true
		minLen, maxLen, err := parseRange(option.TlsFragmentLength)
		if err != nil {
			return nil, nil, err
		}
		t.fragmentMinLength = minLen
		t.fragmentMaxLength = maxLen
		minInterval, maxInterval, err := parseRange(option.TlsFragmentInterval)
		if err != nil {
			return nil, nil, err
		}
		t.fragmentMinInterval = minInterval
		t.fragmentMaxInterval = maxInterval
	}

	return t, &dialer.Property{
		Name:     u.Fragment,
		Address:  t.addr,
		Protocol: tlsImplentation,
		Link:     link,
	}, nil
}

func (s *Tls) DialContext(ctx context.Context, network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		rc, err := s.dialer.DialContext(ctx, network, s.addr)
		if err != nil {
			return nil, fmt.Errorf("[Tls]: dial to %s: %w", s.addr, err)
		}

		if s.fragmentation {
			rc = NewFragmentConn(rc, s.fragmentMinLength, s.fragmentMaxLength, s.fragmentMinInterval, s.fragmentMaxInterval)
		}

		var tlsConn interface {
			netproxy.Conn
			Handshake() error
		}

		// Coalesce the TLS records of one write burst into one socket
		// write. Both crypto/tls and utls issue one underlying Write per
		// record; on bulk relay paths that is ~3 write syscalls per 32KB.
		co := coalesce.New(&netproxy.FakeNetConn{
			Conn:  rc,
			LAddr: nil,
			RAddr: nil,
		})

		switch s.tlsImplentation {
		case "tls":
			tlsConn = tls.Client(co, s.tlsConfig)

		case "utls":
			clientHelloID, err := nameToUtlsClientHelloID(s.utlsImitate)
			if err != nil {
				// rc was dialed above and is owned by this call.
				_ = rc.Close()
				return nil, err
			}

			tlsConn = utls.UClient(co, uTLSConfigFromTLSConfig(s.tlsConfig), *clientHelloID)

		default:
			_ = rc.Close()
			return nil, fmt.Errorf("unknown tls implementation: %v", s.tlsImplentation)
		}

		if err := netproxy.HandshakeWithContext(ctx, tlsConn); err != nil {
			_ = tlsConn.Close()
			return nil, err
		}
		// The handshake writes through the coalescer; a read that blocks on
		// the peer flushes it, but push it out now so the first application
		// write ordering is deterministic.
		if err := co.Flush(); err != nil {
			_ = tlsConn.Close()
			return nil, err
		}
		// Flush after every protocol Write so unmanaged Write/Read users
		// never observe stalled records.
		return coalesce.NewFlushConn(tlsConn, co), nil
	case "udp":
		if s.passthroughUdp {
			return s.dialer.DialContext(ctx, network, addr)
		}
		return nil, fmt.Errorf("%w: tls+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
