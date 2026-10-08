package hysteria2

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
	"golang.org/x/net/context"
)

func requireHysteria2Integration(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping hysteria2 integration test in short mode")
	}
	if os.Getenv("OUTBOUND_INTEGRATION") == "" {
		t.Skip("skipping hysteria2 integration test; set OUTBOUND_INTEGRATION=1 to enable")
	}
	if _, err := net.DialTimeout("tcp", "127.0.0.1:8443", 100*time.Millisecond); err != nil {
		t.Skip("skipping hysteria2 integration test: local server on 127.0.0.1:8443 not available")
	}
}

func TestTCP(t *testing.T) {
	requireHysteria2Integration(t)
	d, err := NewDialer(direct.SymmetricDirect, protocol.Header{
		ProxyAddress: "localhost:8443",
		SNI:          "",
		TlsConfig:    &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13, ServerName: "example.com"},
		User:         "auth",
		IsClient:     true,
		Flags:        0,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := http.Client{
		Transport: &http.Transport{Dial: func(network string, addr string) (net.Conn, error) {
			t.Log("target", addr)
			c, err := d.DialContext(context.Background(), "tcp", addr)
			if err != nil {
				return nil, err
			}
			return &netproxy.FakeNetConn{
				Conn:  c,
				LAddr: nil,
				RAddr: nil,
			}, nil
		}},
	}
	resp, err := c.Get("https://ipinfo.io")
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	defer func() { _ = resp.Body.Close() }()
	t.Log(buf.String())
}

func TestUDP(t *testing.T) {
	requireHysteria2Integration(t)
	d, err := NewDialer(direct.SymmetricDirect, protocol.Header{
		ProxyAddress: "localhost:8443",
		SNI:          "",
		TlsConfig:    &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13, ServerName: "example.com"},
		User:         "auth",
		IsClient:     true,
		Flags:        0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	resolver := net.Resolver{
		PreferGo:     true,
		StrictErrors: false,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			t.Log("target", address)
			if !strings.HasPrefix(network, "udp") {
				return nil, fmt.Errorf("unsupported network")
			}
			c, err := d.DialContext(context.Background(), "udp", address)
			if err != nil {
				return nil, err
			}
			return netproxy.NewFakeNetPacketConn(
				c.(netproxy.PacketConn),
				nil,
				nil,
			), nil
		},
	}
	ips, err := resolver.LookupNetIP(context.TODO(), "ip", "www.baidu.com")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(ips)
}
