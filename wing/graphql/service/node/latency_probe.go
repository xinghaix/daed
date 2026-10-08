/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, daeuniverse Organization <team@v2raya.org>
 */

package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/outbound/netproxy"
)

// Manual latency probes measure every node with two methods:
//
//   - PING: a direct (not proxied) TCP connect to the node's server
//     address, i.e. "tcping". It needs no CAP_NET_RAW, works in containers
//     and is what proxy clients usually call "ping". UDP-only protocols
//     (hysteria2, tuic, juicity) have nothing listening on TCP, so PING is
//     reported as not applicable for them.
//   - HTTP: a real request through the node to the selected config's
//     tcp_check_url/tcp_check_http_method, timed from dialing to the
//     response headers, over a fresh connection (keep-alive disabled).
//
// The timeouts are package variables (not flags) so tests can shorten them.
var (
	// latencyPingTimeout bounds one TCP connect (DNS resolution excluded).
	latencyPingTimeout = 3 * time.Second
	// latencyDNSTimeout bounds resolving the node's server name for PING.
	latencyDNSTimeout = 3 * time.Second
	// latencyHTTPTimeout bounds one proxied HTTP request, dial included.
	// dae's own health check uses 1.5s, too tight for TLS+WS over a CDN.
	latencyHTTPTimeout = 5 * time.Second
)

// latencyMessageMaxLen caps error messages returned to the UI.
const latencyMessageMaxLen = 300

// udpOnlyProtocols have no TCP listener on the server port.
var udpOnlyProtocols = map[string]struct{}{
	"hysteria2": {},
	"hysteria":  {},
	"hy2":       {},
	"tuic":      {},
	"juicity":   {},
}

func pingSupported(protocol string) bool {
	_, udpOnly := udpOnlyProtocols[strings.ToLower(protocol)]
	return !udpOnly
}

// probeOutcome is the result of one probe method.
type probeOutcome struct {
	Ok       bool
	Latency  time.Duration
	Message  string
	TestedAt time.Time
	// Unsupported marks a method that does not apply to the node.
	Unsupported bool
}

func failedOutcome(err error) probeOutcome {
	return probeOutcome{Message: describeProbeError(err), TestedAt: time.Now()}
}

type contextDialer func(ctx context.Context, network, addr string) (netproxy.Conn, error)

// probePing measures a direct TCP connect to address (host:port). Names are
// resolved first (not timed); IPv4 is tried before IPv6.
func probePing(ctx context.Context, dial contextDialer, resolver *net.Resolver, address string, soMark uint32, mptcp bool) probeOutcome {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return failedOutcome(fmt.Errorf("bad server address %q: %w", address, err))
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip.Unmap()}
	} else {
		dnsCtx, cancel := context.WithTimeout(ctx, latencyDNSTimeout)
		ips, err = resolver.LookupNetIP(dnsCtx, "ip", host)
		cancel()
		if err != nil {
			return failedOutcome(fmt.Errorf("DNS: %w", err))
		}
	}
	network := common.MagicNetwork("tcp", soMark, mptcp)
	var lastErr error = errors.New("no address")
	for _, ip := range orderIPv4First(ips) {
		if ctx.Err() != nil {
			return failedOutcome(ctx.Err())
		}
		pingCtx, cancel := context.WithTimeout(ctx, latencyPingTimeout)
		start := time.Now()
		conn, err := dial(pingCtx, network, net.JoinHostPort(ip.String(), port))
		latency := time.Since(start)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		_ = conn.Close()
		return probeOutcome{Ok: true, Latency: latency, TestedAt: time.Now()}
	}
	return failedOutcome(lastErr)
}

func orderIPv4First(ips []netip.Addr) []netip.Addr {
	ordered := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.Unmap().Is4() {
			ordered = append(ordered, ip.Unmap())
		}
	}
	for _, ip := range ips {
		if !ip.Unmap().Is4() {
			ordered = append(ordered, ip)
		}
	}
	return ordered
}

// probeHTTP sends one request to checkURL through dial, connecting to ip
// instead of resolving the URL host (like dae's own health check). The
// transport is private to this probe and never reuses connections.
func probeHTTP(ctx context.Context, dial contextDialer, checkURL *url.URL, method string, ip netip.Addr, soMark uint32, mptcp bool) probeOutcome {
	if method == "" {
		method = http.MethodGet
	}
	network := common.MagicNetwork("tcp", soMark, mptcp)
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			c, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
			if err != nil {
				return nil, err
			}
			return &netproxy.FakeNetConn{Conn: c}, nil
		},
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxIdleConns:           -1,
		TLSHandshakeTimeout:    latencyHTTPTimeout,
		ResponseHeaderTimeout:  latencyHTTPTimeout,
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	reqCtx, cancel := context.WithTimeout(ctx, latencyHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, checkURL.String(), nil)
	if err != nil {
		return failedOutcome(err)
	}
	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)
	if err != nil {
		return failedOutcome(err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if err := judgeCheckStatus(checkURL, resp.StatusCode); err != nil {
		return failedOutcome(err)
	}
	return probeOutcome{Ok: true, Latency: latency, TestedAt: time.Now()}
}

type httpStatusError int

func (e httpStatusError) Error() string { return "HTTP " + strconv.Itoa(int(e)) }

// judgeCheckStatus mirrors dae's health check: ".../generate_204" demands
// that exact status, anything else accepts 2xx-4xx.
func judgeCheckStatus(u *url.URL, status int) error {
	if page := path.Base(u.Path); strings.HasPrefix(page, "generate_") {
		if strconv.Itoa(status) != strings.TrimPrefix(page, "generate_") {
			return httpStatusError(status)
		}
		return nil
	}
	if status < 200 || status >= 500 {
		return httpStatusError(status)
	}
	return nil
}

// probeHTTPFamilies runs probeHTTP over IPv4 first and falls back to IPv6
// only when IPv4 is unavailable or failed, so every node is measured the
// same way.
func probeHTTPFamilies(ctx context.Context, dial contextDialer, opt *netutils.URL, ips *netutils.Ip46, method string, soMark uint32, mptcp bool) probeOutcome {
	if opt == nil || ips == nil {
		return failedOutcome(errors.New("tcp_check_url is not configured"))
	}
	var outcome probeOutcome
	tried := false
	for _, ip := range []netip.Addr{ips.Ip4, ips.Ip6} {
		if !ip.IsValid() {
			continue
		}
		if ctx.Err() != nil {
			return failedOutcome(ctx.Err())
		}
		tried = true
		outcome = probeHTTP(ctx, dial, opt.URL, method, ip, soMark, mptcp)
		if outcome.Ok {
			return outcome
		}
	}
	if !tried {
		return failedOutcome(errors.New("tcp_check_url has no usable IP"))
	}
	return outcome
}

// describeProbeError turns probe errors into short messages for the UI.
func describeProbeError(err error) string {
	if err == nil {
		return ""
	}
	var statusErr httpStatusError
	if errors.As(err, &statusErr) {
		return statusErr.Error()
	}
	if isTimeout(err) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		// Drop Go's `Head "http://...":` prefix.
		err = urlErr.Err
		if isTimeout(err) {
			return "timeout"
		}
	}
	msg := err.Error()
	var certErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var alertErr tls.AlertError
	var recordErr tls.RecordHeaderError
	switch {
	case errors.As(err, &certErr), errors.As(err, &unknownAuthority), errors.As(err, &hostnameErr):
		msg = "TLS certificate error: " + msg
	case errors.As(err, &alertErr), errors.As(err, &recordErr),
		strings.Contains(msg, "tls: "), strings.Contains(msg, "handshake failure"):
		msg = "TLS handshake failed: " + msg
	case strings.Contains(msg, "websocket: bad handshake"):
		msg = "WebSocket handshake failed: " + msg
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		msg = "connection closed by server (EOF): " + msg
	}
	if len(msg) > latencyMessageMaxLen {
		msg = msg[:latencyMessageMaxLen] + "…"
	}
	return msg
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return err.Error() == "timeout"
}
