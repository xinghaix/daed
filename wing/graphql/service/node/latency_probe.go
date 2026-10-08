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
//   - Handshake (shown as TLS): a direct, unproxied connection to the
//     node's server, timed from connect to a completed handshake. TLS nodes
//     get a TCP+TLS handshake with the node's SNI and ALPN; QUIC nodes
//     (hysteria2, tuic, juicity) a QUIC handshake; plain-TCP nodes
//     (shadowsocks, socks, ...) and Reality nodes a TCP connect. Sockets
//     carry so_mark_from_dae and server names are resolved like dae's own
//     node dialers, so dae does not capture the probe. See latency_handshake.go.
//   - HTTP: a real request through the node to the selected config's
//     tcp_check_url/tcp_check_http_method, timed from dialing to the
//     response headers, over a fresh connection (keep-alive disabled).
//
// The timeouts are package variables (not flags) so tests can shorten them.
var (
	// latencyHandshakeTimeout bounds one direct handshake (DNS excluded).
	latencyHandshakeTimeout = 4 * time.Second
	// latencyDNSTimeout bounds resolving the node's server name.
	latencyDNSTimeout = 3 * time.Second
	// latencyHTTPTimeout bounds one proxied HTTP request, dial included.
	// The first request over a fresh connection pays for TCP, TLS, the
	// WebSocket upgrade and the proxy handshake before the check URL is even
	// reached; through a CDN from a distant network that alone can take
	// 3-5s, so dae's 1.5s health check timeout is far too tight here.
	latencyHTTPTimeout = 8 * time.Second
)

// latencyMessageMaxLen caps error messages returned to the UI.
const latencyMessageMaxLen = 300

// probeOutcome is the result of one probe method.
type probeOutcome struct {
	// Method names what was measured: TLS, TCP, QUIC or HTTP.
	Method   string
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

// hostLookup resolves a server name to its addresses.
type hostLookup func(ctx context.Context, host string) ([]netip.Addr, error)

// fakeIPRange is the benchmark range fake-ip DNS servers (Clash/mihomo,
// sing-box) hand out by default.
var fakeIPRange = netip.MustParsePrefix("198.18.0.0/15")

// sanityNote flags results that cannot be a real round trip to a remote
// server: a fake-ip address, or a near-zero RTT to a public address, which
// means something on this host or LAN answered the SYN (a transparent proxy).
func sanityNote(ip netip.Addr, latency time.Duration) string {
	ip = ip.Unmap()
	if fakeIPRange.Contains(ip) {
		return fmt.Sprintf("resolved to %s (fake-ip range): a fake-ip DNS on the path answers for this server, so the probe does not reach it", ip)
	}
	if latency < 2*time.Millisecond && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !cgnatRange.Contains(ip) {
		return fmt.Sprintf("suspiciously low for public address %s: the connection may be answered by a local or LAN transparent proxy", ip)
	}
	return ""
}

var cgnatRange = netip.MustParsePrefix("100.64.0.0/10")

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
	// A response racing the deadline is reported as the timeout it is,
	// never as a latency equal to the cap.
	if latency >= latencyHTTPTimeout {
		return failedOutcome(context.DeadlineExceeded)
	}
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

func withMethod(o probeOutcome, method string) probeOutcome {
	o.Method = method
	return o
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
