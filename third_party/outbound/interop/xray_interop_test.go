// Package interop checks the VMess/VLESS/Trojan WebSocket dialers (with and
// without TLS and ?ed= early data, std TLS and uTLS, TCP and UDP) and VLESS
// Reality+Vision (TCP and UDP over XUDP; the test serves the Reality dest on
// 127.0.0.1:18443) against a real Xray.
// It is skipped unless XRAY_INTEROP=1. Xray >= 26.5 blocks private targets
// in freedom by default; testdata/xray-server.json allows 127.0.0.1 with
// finalRules. Verified against Xray 26.3.27, 26.7.28 and 26.9.9. To run it:
//
//	cd testdata && xray tls cert --domain=example.com --file=cert && xray run -c xray-server.json &
//	XRAY_INTEROP=1 go test ./interop/
package interop

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	_ "github.com/daeuniverse/outbound/dialer/trojan"
	_ "github.com/daeuniverse/outbound/dialer/v2ray"
	"github.com/daeuniverse/outbound/protocol/direct"
	_ "github.com/daeuniverse/outbound/protocol/trojanc"
	_ "github.com/daeuniverse/outbound/protocol/vless"
	_ "github.com/daeuniverse/outbound/protocol/vmess"
)

const id = "8d4a4f5e-6b1c-4f67-9a3e-0f5b2b9c1d2e"

func vmessLink(port int, path, scy string) string {
	tls := ""
	if port > 10010 {
		tls = "tls"
	}
	j, _ := json.Marshal(map[string]any{"v": "2", "ps": "vm", "add": "127.0.0.1", "port": fmt.Sprint(port), "id": id, "aid": "0", "scy": scy, "net": "ws", "path": path, "host": "example.com", "sni": "example.com", "tls": tls, "allowInsecure": true})
	return "vmess://" + base64.StdEncoding.EncodeToString(j)
}

func vlessLink(port int, path string) string {
	return fmt.Sprintf("vless://%s@127.0.0.1:%d?", id, port) + url.Values{"type": {"ws"}, "security": {"none"}, "encryption": {"none"}, "host": {"example.com"}, "path": {path}}.Encode() + "#vl"
}

func trojanLink(port int, path string) string {
	return fmt.Sprintf("trojan://dummy-pass@127.0.0.1:%d?", port) + url.Values{"type": {"ws"}, "security": {"none"}, "host": {"example.com"}, "path": {path}}.Encode() + "#tr"
}

func TestXrayInterop(t *testing.T) {
	if os.Getenv("XRAY_INTEROP") == "" {
		t.Skip("set XRAY_INTEROP=1 with the local xray server running")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer target.Close()
	cases := map[string]string{}
	for _, scy := range []string{"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"} {
		cases["vmess-"+scy] = vmessLink(10001, "/vm", scy)
		cases["vmess-"+scy+"-ed"] = vmessLink(10001, "/vm?ed=2048", scy)
	}
	cases["vless"] = vlessLink(10002, "/vl")
	cases["vless-ed"] = vlessLink(10002, "/vl?ed=2048")
	for _, ed := range []string{"", "?ed=2048"} {
		cases["tls-vmess-aes"+ed] = vmessLink(10011, "/vm"+ed, "aes-128-gcm")
		cases["tls-vless"+ed] = fmt.Sprintf("vless://%s@127.0.0.1:10012?", id) + url.Values{"type": {"ws"}, "security": {"tls"}, "encryption": {"none"}, "host": {"example.com"}, "sni": {"example.com"}, "allowInsecure": {"1"}, "path": {"/vl" + ed}}.Encode() + "#v"
		cases["tls-trojan"+ed] = "trojan://dummy-pass@127.0.0.1:10013?" + url.Values{"type": {"ws"}, "security": {"tls"}, "host": {"example.com"}, "sni": {"example.com"}, "allowInsecure": {"1"}, "path": {"/tr" + ed}}.Encode() + "#t"
	}
	for name, link := range cases {
		for _, impl := range []string{"tls", "utls"} {
			t.Run(name+"/"+impl, func(t *testing.T) {
				d, _, err := dialer.NewNetproxyDialerFromLink(direct.SymmetricDirect, &dialer.ExtraOption{TlsImplementation: impl, UtlsImitate: "chrome_auto"}, link)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				c, err := d.DialContext(ctx, "tcp", target.Listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := c.Write([]byte("HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")); err != nil {
					t.Fatal(err)
				}
				resp, err := http.ReadResponse(bufio.NewReader(&connReader{c}), nil)
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != 204 {
					t.Fatalf("status %d", resp.StatusCode)
				}
			})
		}
	}
}

const (
	realityPublicKey = "MeNjgMx96CumzpNzbwFDmlJiMMVi31nitb-LizNh6xk"
	realityShortID   = "6ba85179e30d4fc2"
)

func realityLink() string {
	return fmt.Sprintf("vless://%s@127.0.0.1:10020?", id) + url.Values{"type": {"tcp"}, "security": {"reality"}, "encryption": {"none"},
		"flow": {"xtls-rprx-vision"}, "sni": {"example.com"}, "fp": {"chrome"}, "pbk": {realityPublicKey}, "sid": {realityShortID}}.Encode() + "#r"
}

// startRealityDest serves the TLS 1.3 site the Reality inbound borrows its
// handshake from (testdata/xray-server.json: dest 127.0.0.1:18443).
func startRealityDest(t *testing.T) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ln, err := net.Listen("tcp", "127.0.0.1:18443")
	if err != nil {
		t.Fatal(err)
	}
	srv.Listener = ln
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
}

func startUDPEcho(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte("echo:"), buf[:n]...), addr)
		}
	}()
	return pc.LocalAddr().String()
}

// TestXrayInteropUDPAndReality covers what DNS over the proxy needs: one
// UDP datagram out and its answer back, over ws (with and without early
// data) and over VLESS Reality+Vision, plus TCP over Reality+Vision.
func TestXrayInteropUDPAndReality(t *testing.T) {
	if os.Getenv("XRAY_INTEROP") == "" {
		t.Skip("set XRAY_INTEROP=1 with the local xray server running")
	}
	startRealityDest(t)
	echo := startUDPEcho(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer target.Close()

	links := map[string]string{"reality-vision": realityLink()}
	for _, ed := range []string{"", "?ed=2048"} {
		links["vmess"+ed] = vmessLink(10011, "/vm"+ed, "aes-128-gcm")
		links["vless"+ed] = fmt.Sprintf("vless://%s@127.0.0.1:10012?", id) + url.Values{"type": {"ws"}, "security": {"tls"}, "encryption": {"none"}, "host": {"example.com"}, "sni": {"example.com"}, "allowInsecure": {"1"}, "path": {"/vl" + ed}}.Encode() + "#v"
		links["trojan"+ed] = "trojan://dummy-pass@127.0.0.1:10013?" + url.Values{"type": {"ws"}, "security": {"tls"}, "host": {"example.com"}, "sni": {"example.com"}, "allowInsecure": {"1"}, "path": {"/tr" + ed}}.Encode() + "#t"
	}
	for name, link := range links {
		d, _, err := dialer.NewNetproxyDialerFromLink(direct.SymmetricDirect, &dialer.ExtraOption{TlsImplementation: "utls", UtlsImitate: "chrome_auto"}, link)
		if err != nil {
			t.Fatal(name, err)
		}
		t.Run(name+"/udp", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := d.DialContext(ctx, "udp", echo)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			query := []byte("dns-query-0123456789")
			if _, err := c.Write(query); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 2048)
			n, err := c.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf[:n], append([]byte("echo:"), query...)) {
				t.Fatalf("got %q", buf[:n])
			}
		})
		t.Run(name+"/tcp-split-writes", func(t *testing.T) {
			// DNS over TCP style: the length prefix and the query arrive in
			// separate writes, so the server needs a frame after the first.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := d.DialContext(ctx, "tcp", target.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			for _, part := range []string{"HEAD / HTTP/1.1\r\n", "Host: x\r\nConnection: close\r\n\r\n"} {
				if _, err := c.Write([]byte(part)); err != nil {
					t.Fatal(err)
				}
			}
			resp, err := http.ReadResponse(bufio.NewReader(&connReader{c}), nil)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 204 {
				t.Fatalf("status %d", resp.StatusCode)
			}
		})
	}
}

type connReader struct {
	c interface{ Read([]byte) (int, error) }
}

func (r *connReader) Read(b []byte) (int, error) { return r.c.Read(b) }
