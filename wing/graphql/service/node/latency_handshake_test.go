package node

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/olicesx/quic-go"
	"go.uber.org/goleak"
)

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "self-signed.invalid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"self-signed.invalid"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestHandshakeTargetForLink(t *testing.T) {
	vmess := func(fields map[string]any) string {
		j, _ := json.Marshal(fields)
		return "vmess://" + base64.StdEncoding.EncodeToString(j)
	}
	for name, c := range map[string]struct {
		link string
		want handshakeTarget
	}{
		"vless-ws-tls-host-as-sni": {"vless://id@1.2.3.4:443?type=ws&security=tls&host=cdn.example&path=%2Fx%3Fed%3D2048#a",
			handshakeTarget{Kind: handshakeTLS, SNI: "cdn.example"}},
		"vless-sni-alpn": {"vless://id@h.example:443?security=tls&sni=s.example&alpn=h2,http/1.1#a",
			handshakeTarget{Kind: handshakeTLS, SNI: "s.example", ALPN: []string{"h2", "http/1.1"}}},
		"vless-reality": {"vless://id@h.example:443?security=reality&sni=www.apple.com&pbk=x#a",
			handshakeTarget{Kind: handshakeTCP}},
		"vless-plain": {"vless://id@h.example:80?type=ws#a", handshakeTarget{Kind: handshakeTCP}},
		"vmess-tls": {vmess(map[string]any{"v": "2", "add": "1.2.3.4", "port": "443", "id": "x", "net": "ws", "host": "cdn.example", "tls": "tls"}),
			handshakeTarget{Kind: handshakeTLS, SNI: "cdn.example"}},
		"vmess-plain":        {vmess(map[string]any{"v": "2", "add": "1.2.3.4", "port": "80", "id": "x", "net": "tcp"}), handshakeTarget{Kind: handshakeTCP}},
		"trojan-default-sni": {"trojan://p@t.example:443?type=ws#a", handshakeTarget{Kind: handshakeTLS, SNI: "t.example"}},
		"trojan-peer":        {"trojan://p@1.2.3.4:443?peer=p.example#a", handshakeTarget{Kind: handshakeTLS, SNI: "p.example"}},
		"hysteria2": {"hysteria2://pw@1.2.3.4:51859?sni=r.example&insecure=1&alpn=h3&pinSHA256=ab#a",
			handshakeTarget{Kind: handshakeQUIC, SNI: "r.example", ALPN: []string{"h3"}}},
		"hy2-obfs": {"hy2://pw@1.2.3.4:443?obfs=salamander&obfs-password=x#a", handshakeTarget{Note: "not applicable: obfuscated QUIC"}},
		"tuic":     {"tuic://u:p@q.example:443?alpn=h3#a", handshakeTarget{Kind: handshakeQUIC, SNI: "q.example", ALPN: []string{"h3"}}},
		"juicity":  {"juicity://u:p@q.example:443#a", handshakeTarget{Kind: handshakeQUIC, SNI: "q.example", ALPN: []string{"h3"}}},
		"ss":       {"ss://YWVzLTEyOC1nY206cA@1.2.3.4:8388#a", handshakeTarget{Kind: handshakeTCP}},
		"socks5":   {"socks5://1.2.3.4:1080", handshakeTarget{Kind: handshakeTCP}},
		"garbage":  {"not a link", handshakeTarget{Kind: handshakeTCP}},
	} {
		if got := handshakeTargetForLink(c.link); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %+v want %+v", name, got, c.want)
		}
	}
}

func TestProbeHandshakeTCP(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	setLatencyTimeouts(t, time.Second, time.Second)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	addr := ln.Addr().String()
	_, port, _ := net.SplitHostPort(addr)
	tcp := handshakeTarget{Kind: handshakeTCP}

	outcome := probeHandshake(context.Background(), plainDial, systemLookup, addr, tcp, 0, false)
	if !outcome.Ok || outcome.Latency <= 0 || outcome.Message != "" || outcome.Method != handshakeTCP {
		t.Fatalf("listening port: %+v", outcome)
	}
	outcome = probeHandshake(context.Background(), plainDial, systemLookup, net.JoinHostPort("localhost", port), tcp, 0, false)
	if !outcome.Ok {
		t.Fatalf("hostname: %+v", outcome)
	}
	_ = ln.Close()
	<-accepted

	outcome = probeHandshake(context.Background(), plainDial, systemLookup, addr, tcp, 0, false)
	if outcome.Ok || outcome.Message == "" || outcome.Method != handshakeTCP {
		t.Fatalf("closed port: %+v", outcome)
	}
	outcome = probeHandshake(context.Background(), plainDial, systemLookup, "no-port", tcp, 0, false)
	if outcome.Ok || !strings.Contains(outcome.Message, "bad server address") {
		t.Fatalf("bad address: %+v", outcome)
	}
	outcome = probeHandshake(context.Background(), plainDial, systemLookup, addr, handshakeTarget{Note: "not applicable: obfuscated QUIC"}, 0, false)
	if !outcome.Unsupported || outcome.Ok {
		t.Fatalf("unsupported: %+v", outcome)
	}
}

func TestProbeHandshakeUsesInjectedLookup(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var asked string
	lookup := func(_ context.Context, host string) ([]netip.Addr, error) {
		asked = host
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	tcp := handshakeTarget{Kind: handshakeTCP}
	outcome := probeHandshake(context.Background(), plainDial, lookup, net.JoinHostPort("node.example", port), tcp, 0, false)
	if !outcome.Ok || asked != "node.example" {
		t.Fatalf("outcome=%+v asked=%q", outcome, asked)
	}
	empty := func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
	outcome = probeHandshake(context.Background(), plainDial, empty, net.JoinHostPort("node.example", port), tcp, 0, false)
	if outcome.Ok || !strings.HasPrefix(outcome.Message, "DNS: no address") {
		t.Fatalf("empty lookup: %+v", outcome)
	}
}

// The TLS probe must send the node's SNI and ALPN, accept a self-signed
// certificate and end with close_notify (the server reads a clean EOF).
func TestProbeHandshakeTLS(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	setLatencyTimeouts(t, 2*time.Second, time.Second)
	type seen struct {
		sni, alpn string
		cleanEOF  bool
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan seen, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tc := c.(*tls.Conn)
		_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
		if err := tc.Handshake(); err != nil {
			got <- seen{}
			return
		}
		st := tc.ConnectionState()
		_, err = tc.Read(make([]byte, 1))
		got <- seen{sni: st.ServerName, alpn: st.NegotiatedProtocol, cleanEOF: errors.Is(err, io.EOF)}
	}()
	defer ln.Close()

	target := handshakeTarget{Kind: handshakeTLS, SNI: "cdn.example", ALPN: []string{"http/1.1"}}
	outcome := probeHandshake(context.Background(), plainDial, systemLookup, ln.Addr().String(), target, 0, false)
	if !outcome.Ok || outcome.Method != handshakeTLS || outcome.Latency <= 0 {
		t.Fatalf("tls: %+v", outcome)
	}
	s := <-got
	if s.sni != "cdn.example" || s.alpn != "http/1.1" || !s.cleanEOF {
		t.Fatalf("server saw %+v", s)
	}
}

// A TCP listener that never speaks TLS must fail the TLS probe in time.
func TestProbeHandshakeTLSTimeout(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	setLatencyTimeouts(t, 200*time.Millisecond, time.Second)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
	}()
	start := time.Now()
	outcome := probeHandshake(context.Background(), plainDial, systemLookup, ln.Addr().String(), handshakeTarget{Kind: handshakeTLS, SNI: "x"}, 0, false)
	if outcome.Ok || outcome.Message != "timeout" || time.Since(start) > 2*time.Second {
		t.Fatalf("outcome %+v after %v", outcome, time.Since(start))
	}
	_ = ln.Close()
	<-done
}

func TestProbeHandshakeQUIC(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	setLatencyTimeouts(t, 2*time.Second, time.Second)
	// The client closes right after its side of the handshake, possibly
	// before the server would hand the connection to Accept, so the SNI is
	// read from the ClientHello instead.
	sni := make(chan string, 1)
	cert := selfSignedCert(t)
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		NextProtos: []string{"h3"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case sni <- hello.ServerName:
			default:
			}
			return nil, nil
		},
		Certificates: []tls.Certificate{cert},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	target := handshakeTarget{Kind: handshakeQUIC, SNI: "random.example", ALPN: []string{"h3"}}
	outcome := probeHandshake(context.Background(), plainDial, systemLookup, ln.Addr().String(), target, 0, false)
	if !outcome.Ok || outcome.Method != handshakeQUIC {
		t.Fatalf("quic: %+v", outcome)
	}
	select {
	case got := <-sni:
		if got != "random.example" {
			t.Fatalf("sni %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server saw no ClientHello")
	}
	_ = ln.Close()

	// Wrong ALPN: the server refuses the handshake.
	ln2, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}, NextProtos: []string{"h3"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	outcome = probeHandshake(context.Background(), plainDial, systemLookup, ln2.Addr().String(), handshakeTarget{Kind: handshakeQUIC, SNI: "x", ALPN: []string{"nope"}}, 0, false)
	if outcome.Ok {
		t.Fatalf("wrong alpn accepted: %+v", outcome)
	}
	_ = ln2.Close()
	// Allow quic-go's transport goroutines to exit after the listeners close.
	time.Sleep(100 * time.Millisecond)
}
