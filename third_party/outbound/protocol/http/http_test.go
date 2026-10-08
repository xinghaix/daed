package http

import (
	"bytes"
	"context"
	stderrors "errors"
	"net"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type noopDialer struct{}

func (noopDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	return nil, nil
}

type deadlineRecordingDialer struct {
	deadline time.Time
}

func (d *deadlineRecordingDialer) DialContext(ctx context.Context, _, _ string) (netproxy.Conn, error) {
	d.deadline, _ = ctx.Deadline()
	return nil, stderrors.New("stop after recording deadline")
}

type stallingConnectDialer struct {
	server net.Conn
}

func (d *stallingConnectDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	client, server := net.Pipe()
	d.server = server
	go func() {
		var req bytes.Buffer
		buf := make([]byte, 256)
		for !bytes.Contains(req.Bytes(), []byte("\r\n\r\n")) {
			n, err := server.Read(buf)
			if n > 0 {
				_, _ = req.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
		_, _ = server.Read(make([]byte, 1))
	}()
	return client, nil
}

func TestNewHTTPProxyPreservesTLSOptionsFromOriginalURL(t *testing.T) {
	u, err := url.Parse("https://proxy.example:443?allowInsecure=1&tlsImplementation=utls&utlsImitate=chrome&sni=edge.example&alpn=h2,http/1.1")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	dialer, err := NewHTTPProxy(u, noopDialer{})
	if err != nil {
		t.Fatalf("NewHTTPProxy returned error: %v", err)
	}

	proxy, ok := dialer.(*HttpProxy)
	if !ok {
		t.Fatalf("expected *HttpProxy, got %T", dialer)
	}

	tlsDialerValue := reflect.ValueOf(proxy.dialer).Elem()
	if got := tlsDialerValue.FieldByName("tlsImplentation").String(); got != "utls" {
		t.Fatalf("unexpected tlsImplentation: got %q want %q", got, "utls")
	}
	if got := tlsDialerValue.FieldByName("utlsImitate").String(); got != "chrome" {
		t.Fatalf("unexpected utlsImitate: got %q want %q", got, "chrome")
	}
	if !tlsDialerValue.FieldByName("skipVerify").Bool() {
		t.Fatal("expected allowInsecure to propagate to skipVerify")
	}
	if got := tlsDialerValue.FieldByName("serverName").String(); got != "edge.example" {
		t.Fatalf("unexpected serverName: got %q want %q", got, "edge.example")
	}

	nextProtos := tlsDialerValue.FieldByName("tlsConfig").Elem().FieldByName("NextProtos")
	if nextProtos.Len() != 2 || nextProtos.Index(0).String() != "h2" || nextProtos.Index(1).String() != "http/1.1" {
		t.Fatalf("unexpected NextProtos: %#v", nextProtos)
	}
}

func TestHTTPProxyLazyHandshakePreservesOriginalDeadline(t *testing.T) {
	parent := &deadlineRecordingDialer{}
	deadline := time.Now().Add(200 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	conn := NewConn(ctx, parent, &HttpProxy{
		Addr:   "proxy.example:8080",
		dialer: parent,
	}, "example.com:80", "tcp")

	time.Sleep(30 * time.Millisecond)
	_, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err == nil {
		t.Fatal("Write() error = nil, want recording error")
	}
	if parent.deadline.IsZero() {
		t.Fatal("DialContext() did not receive a deadline")
	}
	if delta := parent.deadline.Sub(deadline); delta > 20*time.Millisecond || delta < -20*time.Millisecond {
		t.Fatalf("DialContext() deadline = %v, want close to %v", parent.deadline, deadline)
	}
}

func TestHTTPProxyLazyHandshakeGetsFreshTimeoutWithoutCallerDeadline(t *testing.T) {
	oldTimeout := netproxy.DialTimeout
	netproxy.DialTimeout = 80 * time.Millisecond
	defer func() { netproxy.DialTimeout = oldTimeout }()

	parent := &deadlineRecordingDialer{}
	conn := NewConn(context.Background(), parent, &HttpProxy{
		Addr:   "proxy.example:8080",
		dialer: parent,
	}, "example.com:80", "tcp")

	time.Sleep(40 * time.Millisecond)
	beforeWrite := time.Now()
	_, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err == nil {
		t.Fatal("Write() error = nil, want recording error")
	}
	if parent.deadline.IsZero() {
		t.Fatal("DialContext() did not receive a deadline")
	}

	remaining := parent.deadline.Sub(beforeWrite)
	if remaining < 40*time.Millisecond || remaining > 120*time.Millisecond {
		t.Fatalf("DialContext() remaining timeout = %v, want a fresh timeout close to %v", remaining, netproxy.DialTimeout)
	}
}

func TestHTTPProxyConnectResponseRespectsHandshakeDeadline(t *testing.T) {
	parent := &stallingConnectDialer{}
	t.Cleanup(func() {
		if parent.server != nil {
			_ = parent.server.Close()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	conn := NewConn(ctx, parent, &HttpProxy{
		Addr:   "proxy.example:8080",
		dialer: parent,
	}, "example.com:443", "tcp")

	start := time.Now()
	_, err := conn.Write([]byte("client hello"))
	if err == nil {
		t.Fatal("Write() error = nil, want timeout")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Write() took %v, want deadline-bound failure", elapsed)
	}
}
