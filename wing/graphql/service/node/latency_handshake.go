/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, daeuniverse Organization <team@v2raya.org>
 */

package node

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/dialer/v2ray"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/olicesx/quic-go"
)

const (
	handshakeTLS  = "TLS"
	handshakeTCP  = "TCP"
	handshakeQUIC = "QUIC"
)

// handshakeTarget is what the direct handshake probe does for a node.
type handshakeTarget struct {
	// Kind is TLS, TCP or QUIC; empty means the probe does not apply.
	Kind string
	SNI  string
	ALPN []string
	// Note explains why the probe does not apply (Kind is empty).
	Note string
}

// handshakeTargetForLink derives the handshake from the node's share link.
//
// Reality nodes get a TCP connect only: a Reality server forwards any
// handshake it cannot authenticate to its camouflage destination, so a TLS
// handshake would time the server-to-destination leg as well and show up in
// the server's logs as a probe. A TCP connect still measures the path to the
// node with the least noise. The UI labels such results "TCP".
func handshakeTargetForLink(link string) handshakeTarget {
	scheme, _, ok := strings.Cut(link, "://")
	if !ok {
		return handshakeTarget{Kind: handshakeTCP}
	}
	scheme = strings.ToLower(scheme)
	switch scheme {
	case "vmess", "vless":
		var v *v2ray.V2Ray
		var err error
		if scheme == "vmess" {
			v, err = v2ray.ParseVmessURL(link)
		} else {
			v, err = v2ray.ParseVlessURL(link)
		}
		if err != nil {
			return handshakeTarget{Kind: handshakeTCP}
		}
		switch strings.ToLower(v.TLS) {
		case "tls", "xtls":
			return handshakeTarget{Kind: handshakeTLS, SNI: firstNonEmpty(v.SNI, firstHost(v.Host), v.Add), ALPN: splitList(v.Alpn)}
		case "reality":
			return handshakeTarget{Kind: handshakeTCP}
		default:
			return handshakeTarget{Kind: handshakeTCP}
		}
	}

	u, err := url.Parse(link)
	if err != nil {
		return handshakeTarget{Kind: handshakeTCP}
	}
	q := u.Query()
	sni := firstNonEmpty(q.Get("sni"), q.Get("peer"), q.Get("servername"), u.Hostname())
	alpn := splitList(q.Get("alpn"))
	switch scheme {
	case "trojan", "trojan-go", "anytls", "https", "naive+https", "http2":
		if strings.EqualFold(q.Get("security"), "reality") {
			return handshakeTarget{Kind: handshakeTCP}
		}
		if scheme != "trojan" && scheme != "trojan-go" && scheme != "anytls" {
			sni = firstNonEmpty(q.Get("sni"), u.Hostname())
		}
		return handshakeTarget{Kind: handshakeTLS, SNI: sni, ALPN: alpn}
	case "hysteria2", "hy2", "hysteria", "tuic", "juicity":
		if q.Get("obfs") != "" && !strings.EqualFold(q.Get("obfs"), "none") {
			return handshakeTarget{Note: "not applicable: obfuscated QUIC"}
		}
		if len(alpn) == 0 {
			switch scheme {
			case "hysteria":
				alpn = []string{"hysteria"}
			default:
				alpn = []string{"h3"}
			}
		}
		return handshakeTarget{Kind: handshakeQUIC, SNI: sni, ALPN: alpn}
	default:
		return handshakeTarget{Kind: handshakeTCP}
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

func firstHost(hosts string) string {
	host, _, _ := strings.Cut(hosts, ",")
	return host
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// resolveServer splits address and resolves its host; IPv4 comes first.
func resolveServer(ctx context.Context, lookup hostLookup, address string) (port string, ips []netip.Addr, err error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", nil, fmt.Errorf("bad server address %q: %w", address, err)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return port, []netip.Addr{ip.Unmap()}, nil
	}
	dnsCtx, cancel := context.WithTimeout(ctx, latencyDNSTimeout)
	ips, err = lookup(dnsCtx, host)
	cancel()
	if err != nil {
		return "", nil, fmt.Errorf("DNS: %w", err)
	}
	if len(ips) == 0 {
		return "", nil, fmt.Errorf("DNS: no address for %s", host)
	}
	return port, orderIPv4First(ips), nil
}

// probeHandshake connects directly (not through the node) to the node's
// server and times connect plus handshake. Name resolution is not timed.
// Every connection is closed cleanly (TLS close_notify, QUIC
// CONNECTION_CLOSE) before returning.
func probeHandshake(ctx context.Context, dial contextDialer, lookup hostLookup, address string, target handshakeTarget, soMark uint32, mptcp bool) probeOutcome {
	if target.Kind == "" {
		return probeOutcome{Method: handshakeTLS, Unsupported: true, Message: target.Note, TestedAt: time.Now()}
	}
	port, ips, err := resolveServer(ctx, lookup, address)
	if err != nil {
		return withMethod(failedOutcome(err), target.Kind)
	}
	var lastErr error = errors.New("no address")
	for _, ip := range ips {
		if ctx.Err() != nil {
			return withMethod(failedOutcome(ctx.Err()), target.Kind)
		}
		addr := net.JoinHostPort(ip.String(), port)
		var latency time.Duration
		switch target.Kind {
		case handshakeQUIC:
			latency, err = quicHandshake(ctx, addr, target, soMark)
		default:
			latency, err = tcpHandshake(ctx, dial, addr, target, soMark, mptcp)
		}
		if err != nil {
			lastErr = err
			continue
		}
		return probeOutcome{Method: target.Kind, Ok: true, Latency: latency, TestedAt: time.Now(), Message: sanityNote(ip, latency)}
	}
	return withMethod(failedOutcome(lastErr), target.Kind)
}

func tlsClientConfig(target handshakeTarget) *tls.Config {
	return &tls.Config{
		ServerName: target.SNI,
		NextProtos: target.ALPN,
		// Only the handshake time matters; certificate problems show up in
		// the HTTP probe, which goes through the node's real TLS settings.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
}

func tcpHandshake(ctx context.Context, dial contextDialer, addr string, target handshakeTarget, soMark uint32, mptcp bool) (time.Duration, error) {
	hsCtx, cancel := context.WithTimeout(ctx, latencyHandshakeTimeout)
	defer cancel()
	start := time.Now()
	conn, err := dial(hsCtx, common.MagicNetwork("tcp", soMark, mptcp), addr)
	if err != nil {
		return 0, err
	}
	if target.Kind != handshakeTLS {
		latency := time.Since(start)
		_ = conn.Close()
		return latency, nil
	}
	tlsConn := tls.Client(&netproxy.FakeNetConn{Conn: conn}, tlsClientConfig(target))
	err = tlsConn.HandshakeContext(hsCtx)
	latency := time.Since(start)
	if err != nil {
		_ = conn.Close()
		return 0, err
	}
	// Close sends close_notify so the server sees an orderly shutdown.
	_ = tlsConn.SetDeadline(time.Now().Add(time.Second))
	_ = tlsConn.Close()
	return latency, nil
}

func quicHandshake(ctx context.Context, addr string, target handshakeTarget, soMark uint32) (time.Duration, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, err
	}
	lc := net.ListenConfig{}
	if soMark != 0 {
		lc.Control = func(_, _ string, c syscall.RawConn) error {
			return netproxy.SoMarkControl(c, int(soMark))
		}
	}
	laddr := ":0"
	if udpAddr.IP.To4() != nil {
		laddr = "0.0.0.0:0"
	}
	pconn, err := lc.ListenPacket(ctx, "udp", laddr)
	if err != nil {
		return 0, err
	}
	defer pconn.Close()
	hsCtx, cancel := context.WithTimeout(ctx, latencyHandshakeTimeout)
	defer cancel()
	start := time.Now()
	conn, err := quic.Dial(hsCtx, pconn, udpAddr, tlsClientConfig(target), &quic.Config{
		HandshakeIdleTimeout: latencyHandshakeTimeout,
		MaxIdleTimeout:       latencyHandshakeTimeout,
	})
	if err != nil {
		return 0, err
	}
	latency := time.Since(start)
	_ = conn.CloseWithError(0, "")
	return latency, nil
}
