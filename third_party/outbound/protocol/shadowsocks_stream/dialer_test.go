package shadowsocks_stream

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
)

type Params struct {
	Method, Passwd, Address, Port string
}

func requireShadowsocksStreamIntegration(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping shadowsocks_stream integration test in short mode")
	}
	if os.Getenv("OUTBOUND_INTEGRATION") == "" {
		t.Skip("skipping shadowsocks_stream integration test; set OUTBOUND_INTEGRATION=1 to enable")
	}
}

func TestNewSSStream(t *testing.T) {
	requireShadowsocksStreamIntegration(t)
	// https://github.com/winterssy/SSR-Docker

	params := Params{
		Method:  "aes-256-cfb",
		Passwd:  "p@ssw0rd",
		Address: "localhost",
		Port:    "8989",
	}
	dialer, err := NewDialer(direct.SymmetricDirect, protocol.Header{
		Cipher:       params.Method,
		Password:     params.Passwd,
		ProxyAddress: net.JoinHostPort(params.Address, params.Port),
	})
	if err != nil {
		t.Fatal(err)
	}
	c := http.Client{
		Transport: &http.Transport{Dial: func(network string, addr string) (net.Conn, error) {
			c, err := dialer.DialContext(context.Background(), "tcp", addr)
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
	resp, err := c.Get("https://www.baidu.com")
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	defer func() { _ = resp.Body.Close() }()
	t.Log(buf.String())
}
