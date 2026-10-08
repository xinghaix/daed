package v2ray_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/dialer/v2ray"
	"github.com/daeuniverse/outbound/protocol/direct"
	_ "github.com/daeuniverse/outbound/protocol/vless"
	"github.com/gorilla/websocket"
)

type wsHandshake struct {
	requestURI string
	earlyData  []byte
}

func wsRecorder(t *testing.T) (*httptest.Server, <-chan wsHandshake) {
	t.Helper()
	ch := make(chan wsHandshake, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		early, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Protocol"))
		ch <- wsHandshake{requestURI: r.RequestURI, earlyData: early}
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_, _, _ = c.ReadMessage()
	}))
	t.Cleanup(srv.Close)
	return srv, ch
}

// A VLESS ws node from an Xray share link with "?ed=2048" in its path must
// request the bare path and carry the VLESS request header as early data.
func TestVlessWsEarlyDataFromShareLink(t *testing.T) {
	const id = "8d4a4f5e-6b1c-4f67-9a3e-0f5b2b9c1d2e"
	srv, handshakes := wsRecorder(t)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	link := "vless://" + id + "@" + net.JoinHostPort(host, port) + "?" + url.Values{
		"type":       []string{"ws"},
		"security":   []string{"none"},
		"encryption": []string{"none"},
		"host":       []string{"example.com"},
		"path":       []string{"/abcd1234?ed=2048"},
	}.Encode() + "#vless-ws-ed"

	d, _, err := v2ray.NewV2Ray(&dialer.ExtraOption{}, direct.SymmetricDirect, link)
	if err != nil {
		t.Fatalf("NewV2Ray() error = %v", err)
	}
	c, err := d.DialContext(context.Background(), "tcp", "example.org:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var h wsHandshake
	select {
	case h = <-handshakes:
	case <-time.After(5 * time.Second):
		t.Fatal("no websocket handshake")
	}
	if h.requestURI != "/abcd1234" {
		t.Fatalf("request URI = %q, want /abcd1234 (ed must be stripped, '?' must not be escaped)", h.requestURI)
	}
	uuid, _ := hexUUID(id)
	if len(h.earlyData) < 17 || h.earlyData[0] != 0 || !bytes.Equal(h.earlyData[1:17], uuid) {
		t.Fatalf("early data does not start with the VLESS request header: %x", h.earlyData)
	}
	if !bytes.Contains(h.earlyData, []byte("example.org")) {
		t.Fatalf("early data does not carry the VLESS target address: %q", h.earlyData)
	}
}

func hexUUID(s string) ([]byte, error) {
	b := make([]byte, 0, 16)
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			continue
		}
		var v byte
		for j := 0; j < 2; j++ {
			ch := s[i+j]
			switch {
			case ch >= '0' && ch <= '9':
				v = v<<4 | (ch - '0')
			case ch >= 'a' && ch <= 'f':
				v = v<<4 | (ch - 'a' + 10)
			}
		}
		b = append(b, v)
		i++
	}
	return b, nil
}

func TestParseVlessURLAllowInsecure(t *testing.T) {
	for link, want := range map[string]bool{
		"vless://id@h:443?security=tls&allowInsecure=1#a":    true,
		"vless://id@h:443?security=tls&allowInsecure=true#a": true,
		"vless://id@h:443?security=tls&insecure=1#a":         true,
		"vless://id@h:443?security=tls&allowInsecure=0#a":    false,
		"vless://id@h:443?security=tls#a":                    false,
	} {
		s, err := v2ray.ParseVlessURL(link)
		if err != nil {
			t.Fatal(err)
		}
		if s.AllowInsecure != want {
			t.Errorf("%s: AllowInsecure=%v want %v", link, s.AllowInsecure, want)
		}
	}
}
