package trojan_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/dialer/trojan"
	"github.com/daeuniverse/outbound/protocol/direct"
	_ "github.com/daeuniverse/outbound/protocol/trojanc"
	"github.com/gorilla/websocket"
)

func trojanWsServer(t *testing.T) (*httptest.Server, <-chan [2]string) {
	t.Helper()
	ch := make(chan [2]string, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		early, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Protocol"))
		ch <- [2]string{r.RequestURI, string(early)}
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

func dialTrojanWs(t *testing.T, srv *httptest.Server, path string) {
	t.Helper()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	link := "trojan://secret-password@" + net.JoinHostPort(host, port) + "?" + url.Values{
		"type":          []string{"ws"},
		"security":      []string{"tls"},
		"sni":           []string{"example.com"},
		"host":          []string{"example.com"},
		"path":          []string{path},
		"allowInsecure": []string{"1"},
	}.Encode() + "#trojan-ws"
	d, _, err := trojan.NewTrojan(&dialer.ExtraOption{TlsImplementation: "tls"}, direct.SymmetricDirect, link)
	if err != nil {
		t.Fatalf("NewTrojan() error = %v", err)
	}
	c, err := d.DialContext(context.Background(), "tcp", "example.org:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
}

func next(t *testing.T, ch <-chan [2]string) (string, string) {
	t.Helper()
	select {
	case h := <-ch:
		return h[0], h[1]
	case <-time.After(5 * time.Second):
		t.Fatal("no websocket handshake")
		return "", ""
	}
}

func TestTrojanWsEarlyData(t *testing.T) {
	srv, ch := trojanWsServer(t)
	dialTrojanWs(t, srv, "/abcd1234?ed=2048")
	uri, early := next(t, ch)
	if uri != "/abcd1234" {
		t.Fatalf("request URI = %q, want /abcd1234", uri)
	}
	sum := sha256.Sum224([]byte("secret-password"))
	if !bytes.HasPrefix([]byte(early), []byte(hex.EncodeToString(sum[:])+"\r\n")) {
		t.Fatalf("early data does not start with the trojan password hash: %q", early)
	}
	// The trojan client writes its request header on its own, so the header
	// (with the target address) is what rides in the handshake.
	if !bytes.Contains([]byte(early), []byte("example.org")) {
		t.Fatalf("early data does not carry the trojan request header: %q", early)
	}
}

func TestTrojanWsPathQueryWithoutEarlyData(t *testing.T) {
	srv, ch := trojanWsServer(t)
	dialTrojanWs(t, srv, "/abcd1234?token=a%2Fb")
	uri, early := next(t, ch)
	if uri != "/abcd1234?token=a%2Fb" {
		t.Fatalf("request URI = %q, want /abcd1234?token=a%%2Fb", uri)
	}
	if early != "" {
		t.Fatalf("unexpected early data %q", early)
	}
}
