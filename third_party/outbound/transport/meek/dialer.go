package meek

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"

	"github.com/daeuniverse/outbound/netproxy"
)

type Dialer struct {
	nextDialer netproxy.Dialer
	tlsConfig  *tls.Config
	addr       string
	url        string
	serverName string
	skipVerify bool
	alpn       []string
}

func (m *Dialer) UnwrapDialer() netproxy.Dialer {
	return m.nextDialer
}

func NewDialer(s string, d netproxy.Dialer) (*Dialer, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("NewMeek: %w", err)
	}

	m := &Dialer{
		nextDialer: d,
		addr:       u.Host,
	}

	query := u.Query()
	m.url = query.Get("url")
	if m.url == "" {
		return nil, fmt.Errorf("NewMeek: url is empty")
	}

	meekUrl, err := url.Parse(m.url)
	if err != nil {
		return nil, fmt.Errorf("NewMeek: %w", err)
	}
	if meekUrl.Scheme != "https" {
		return nil, fmt.Errorf("NewMeek: unimplemented backdrop")
	}

	// skipVerify
	if query.Get("allowInsecure") == "true" || query.Get("allowInsecure") == "1" ||
		query.Get("skipVerify") == "true" || query.Get("skipVerify") == "1" {
		m.skipVerify = true
	}
	// alpn
	if query.Get("alpn") != "" {
		// Set it not nil.
		m.alpn = strings.Split(query.Get("alpn"), ",")
	} else {
		m.alpn = []string{"h2", "http/1.1"}
	}
	if m.serverName == "" {
		// The sni/serverName query parameters were historically parsed
		// nowhere, so every link silently used the host as SNI.
		for _, key := range []string{"sni", "serverName"} {
			if v := query.Get(key); v != "" {
				m.serverName = v
				break
			}
		}
	}
	if m.serverName == "" {
		m.serverName = u.Hostname()
	}
	m.tlsConfig = &tls.Config{
		ServerName:         m.serverName,
		InsecureSkipVerify: m.skipVerify,
		NextProtos:         m.alpn,
	}

	return m, nil
}

func (m *Dialer) DialContext(ctx context.Context, network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		tripper := &httpTripperClient{
			nextDialer: m.nextDialer,
			addr:       addr,
			url:        m.url,
			// The TLS block above (sni/serverName/skipVerify/alpn) must
			// actually reach the round tripper, and it is part of the
			// transport cache key, so dialers differing only in TLS
			// options no longer share one cached transport.
			tlsConfig: m.tlsConfig,
		}

		clientConfig := &config{
			MaxWriteSize:             65536,
			WaitSubsequentWriteMs:    10,
			InitialPollingIntervalMs: 100,
			MaxPollingIntervalMs:     1000,
			MinPollingIntervalMs:     10,
			BackoffFactor:            1.5,
			FailedRetryIntervalMs:    1000,
		}

		assembler := newAssemblerClient(tripper, clientConfig)
		// The session outlives this dial: its lifetime is governed by
		// Conn.Close, not by the dial context (which may be request-scoped
		// and cancelled right after the handshake). WithoutCancel keeps the
		// caller's context values (loggers, trace metadata) while decoupling
		// cancellation, instead of discarding the context entirely.
		session, err := assembler.NewSession(context.WithoutCancel(ctx))
		if err != nil {
			return nil, err
		}

		return session.(netproxy.Conn), nil
	case "udp":
		return nil, fmt.Errorf("%w: meek+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
