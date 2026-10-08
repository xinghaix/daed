package httpupgrade

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/daeuniverse/outbound/netproxy"
)

type Dialer struct {
	nextDialer netproxy.Dialer
	tlsConfig  *tls.Config
	addr       string
	host       string
	path       string
	serverName string
	skipVerify bool
}

type bufferedConn struct {
	netproxy.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *bufferedConn) CloseWrite() error {
	return netproxy.ForwardCloseWrite(c.Conn)
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the wrapped conn: embedding netproxy.Conn
// promotes SetWriteDeadline but not this optional method, so the inner
// conn's destructive-deadline declaration would otherwise be erased here.
func (c *bufferedConn) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(c.Conn)
}

func (t *Dialer) UnwrapDialer() netproxy.Dialer {
	return t.nextDialer
}

func NewDialer(s string, d netproxy.Dialer) (*Dialer, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("NewHTTPUpgrade: %w", err)
	}
	query := u.Query()

	path := query.Get("path")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	t := &Dialer{
		nextDialer: d,
		addr:       u.Host,
		path:       path,
	}

	if query.Get("allowInsecure") == "true" || query.Get("allowInsecure") == "1" ||
		query.Get("skipVerify") == "true" || query.Get("skipVerify") == "1" {
		t.skipVerify = true
	}

	t.host = query.Get("host")
	if t.host == "" {
		t.host = u.Hostname()
	}

	if u.Scheme == "https" {
		t.serverName = query.Get("serverName")
		if t.serverName == "" {
			t.serverName = u.Hostname()
		}
		t.tlsConfig = &tls.Config{
			ServerName:         t.serverName,
			InsecureSkipVerify: t.skipVerify,
			NextProtos:         []string{"http/1.1"},
		}
	}

	return t, nil
}

func (t *Dialer) DialContext(ctx context.Context, network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		conn, err := t.nextDialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		if t.tlsConfig != nil {
			tlsConn := tls.Client(&netproxy.FakeNetConn{Conn: conn}, t.tlsConfig)
			if err := netproxy.HandshakeWithContext(ctx, tlsConn); err != nil {
				_ = tlsConn.Close()
				return nil, fmt.Errorf("httpupgrade: %w", err)
			}
			conn = tlsConn
		}

		restoreDeadline, err := netproxy.ApplyConnDeadlineFromContext(ctx, conn)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("httpupgrade: %w", err)
		}
		defer restoreDeadline()

		req, err := http.NewRequest("GET", t.path, nil)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("httpupgrade: %w", err)
		}
		req.Header.Set("Connection", "upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Host = t.host

		err = req.Write(conn)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("httpupgrade: %w", err)
		}

		reader := bufio.NewReaderSize(conn, 32<<10)
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("httpupgrade: %w", err)
		}

		if resp.Status == "101 Switching Protocols" &&
			strings.ToLower(resp.Header.Get("Upgrade")) == "websocket" &&
			strings.ToLower(resp.Header.Get("Connection")) == "upgrade" {
			if reader.Buffered() == 0 {
				return conn, nil
			}
			return &bufferedConn{Conn: conn, reader: reader}, nil
		}
		_ = conn.Close()
		return nil, errors.New("httpupgrade: unrecognized reply")

	case "udp":
		return nil, fmt.Errorf("%w: httpupgrade+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
