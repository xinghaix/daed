package ws

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/gorilla/websocket"
)

func TestParseEarlyDataPath(t *testing.T) {
	tests := []struct {
		in     string
		path   string
		query  string
		ed     int
		header string
	}{
		{in: "/abcd1234", path: "/abcd1234"},
		{in: "/", path: "/"},
		{in: "", path: ""},
		{in: "/abcd1234?ed=2048", path: "/abcd1234", ed: 2048, header: DefaultEarlyDataHeaderName},
		{in: "/p?a=1&ed=2048&b=x%20y", path: "/p", query: "a=1&b=x%20y", ed: 2048, header: DefaultEarlyDataHeaderName},
		{in: "/p?ed=1024&eh=Sec-WebSocket-Protocol", path: "/p", ed: 1024, header: "Sec-WebSocket-Protocol"},
		{in: "/p?eh=X-Early-Data&ed=64&k=v", path: "/p", query: "k=v", ed: 64, header: "X-Early-Data"},
		// A query without early data is preserved verbatim.
		{in: "/p?a=1&b=x%20y", path: "/p", query: "a=1&b=x%20y"},
		{in: "/p?ed=0", path: "/p", query: "ed=0"},
		{in: "/p?ed=abc", path: "/p", query: "ed=abc"},
		{in: "/p?eh=X-Early-Data", path: "/p", query: "eh=X-Early-Data"},
	}
	for _, tt := range tests {
		path, query, ed, header := parseEarlyDataPath(tt.in)
		if path != tt.path || query != tt.query || ed != tt.ed || header != tt.header {
			t.Errorf("parseEarlyDataPath(%q) = (%q, %q, %d, %q), want (%q, %q, %d, %q)",
				tt.in, path, query, ed, header, tt.path, tt.query, tt.ed, tt.header)
		}
	}
}

type tcpDialer struct{}

func (tcpDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

type handshake struct {
	requestURI string
	earlyData  []byte
	rawHeader  string
}

// echoServer emulates an Xray websocket inbound: it decodes early data from
// headerName, echoes the header back like Xray does, treats the early data as
// the first bytes of the stream and echoes every byte it receives. When
// greeting is set the server speaks first.
func echoServer(t *testing.T, headerName string, greeting []byte) (*httptest.Server, <-chan handshake, *atomic.Int32) {
	t.Helper()
	handshakes := make(chan handshake, 4)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		raw := r.Header.Get(headerName)
		var early []byte
		var respHeader http.Header
		if raw != "" {
			var err error
			early, err = base64.RawURLEncoding.DecodeString(raw)
			if err != nil {
				http.Error(w, "bad early data", http.StatusBadRequest)
				return
			}
			if strings.EqualFold(headerName, "Sec-WebSocket-Protocol") {
				respHeader = http.Header{"Sec-Websocket-Protocol": []string{raw}}
			}
		}
		handshakes <- handshake{requestURI: r.RequestURI, earlyData: early, rawHeader: raw}
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, respHeader)
		if err != nil {
			return
		}
		defer c.Close()
		if len(greeting) > 0 {
			if err := c.WriteMessage(websocket.BinaryMessage, greeting); err != nil {
				return
			}
		}
		if len(early) > 0 {
			if err := c.WriteMessage(websocket.BinaryMessage, early); err != nil {
				return
			}
		}
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			if err := c.WriteMessage(mt, msg); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv, handshakes, &hits
}

// newTestWs builds the ws dialer the same way the trojan/vmess/vless dialers do:
// the share-link path goes into url.URL.Path, query included.
func newTestWs(t *testing.T, srv *httptest.Server, path string) netproxy.Dialer {
	t.Helper()
	u := url.URL{
		Scheme:   "ws",
		Host:     strings.TrimPrefix(srv.URL, "http://"),
		Path:     path,
		RawQuery: url.Values{"host": []string{"example.com"}}.Encode(),
	}
	d, _, err := NewWs(&dialer.ExtraOption{}, tcpDialer{}, u.String())
	if err != nil {
		t.Fatalf("NewWs() error = %v", err)
	}
	return d
}

func readN(t *testing.T, c netproxy.Conn, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return buf
}

func nextHandshake(t *testing.T, ch <-chan handshake) handshake {
	t.Helper()
	select {
	case h := <-ch:
		return h
	case <-time.After(5 * time.Second):
		t.Fatal("no websocket handshake reached the server")
		return handshake{}
	}
}

func TestWsPathQueryIsNotEscaped(t *testing.T) {
	srv, handshakes, _ := echoServer(t, DefaultEarlyDataHeaderName, nil)
	d := newTestWs(t, srv, "/abcd1234?x=1&y=2")
	c, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer c.Close()
	h := nextHandshake(t, handshakes)
	if h.requestURI != "/abcd1234?x=1&y=2" {
		t.Fatalf("request URI = %q, want %q", h.requestURI, "/abcd1234?x=1&y=2")
	}
	if h.rawHeader != "" {
		t.Fatalf("unexpected early data header %q", h.rawHeader)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if got := readN(t, c, 4); string(got) != "ping" {
		t.Fatalf("echo = %q", got)
	}
}

func TestWsEarlyDataHandshake(t *testing.T) {
	srv, handshakes, hits := echoServer(t, DefaultEarlyDataHeaderName, nil)
	d := newTestWs(t, srv, "/abcd1234?ed=2048&x=1")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	c, err := d.DialContext(ctx, "tcp", "example.com:80")
	// The handshake must not depend on the dial context staying alive.
	cancel()
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer c.Close()
	time.Sleep(50 * time.Millisecond)
	if n := hits.Load(); n != 0 {
		t.Fatalf("handshake happened before the first write (%d requests)", n)
	}

	first := bytes.Repeat([]byte("early-data-"), 20)
	n, err := c.Write(first)
	if err != nil || n != len(first) {
		t.Fatalf("Write() = %d, %v; want %d, nil", n, err, len(first))
	}
	h := nextHandshake(t, handshakes)
	if h.requestURI != "/abcd1234?x=1" {
		t.Fatalf("request URI = %q, want %q", h.requestURI, "/abcd1234?x=1")
	}
	if !bytes.Equal(h.earlyData, first) {
		t.Fatalf("early data = %q, want %q", h.earlyData, first)
	}
	if got := readN(t, c, len(first)); !bytes.Equal(got, first) {
		t.Fatalf("echo of early data = %q", got)
	}

	second := []byte("after handshake")
	if _, err := c.Write(second); err != nil {
		t.Fatalf("second Write() error = %v", err)
	}
	if got := readN(t, c, len(second)); !bytes.Equal(got, second) {
		t.Fatalf("echo = %q", got)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("server saw %d handshakes, want 1", n)
	}
}

func TestWsEarlyDataSplitsLargeFirstWrite(t *testing.T) {
	srv, handshakes, _ := echoServer(t, DefaultEarlyDataHeaderName, nil)
	d := newTestWs(t, srv, "/p?ed=16")
	c, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer c.Close()

	first := []byte("0123456789abcdefREMAINDER-SENT-AS-A-MESSAGE")
	n, err := c.Write(first)
	if err != nil || n != len(first) {
		t.Fatalf("Write() = %d, %v; want %d, nil", n, err, len(first))
	}
	h := nextHandshake(t, handshakes)
	if h.requestURI != "/p" {
		t.Fatalf("request URI = %q, want /p", h.requestURI)
	}
	if string(h.earlyData) != "0123456789abcdef" {
		t.Fatalf("early data = %q, want the first 16 bytes", h.earlyData)
	}
	if got := readN(t, c, len(first)); !bytes.Equal(got, first) {
		t.Fatalf("echo = %q, want %q", got, first)
	}
}

func TestWsEarlyDataCustomHeader(t *testing.T) {
	srv, handshakes, _ := echoServer(t, "X-Early-Data", nil)
	d := newTestWs(t, srv, "/p?ed=2048&eh=X-Early-Data")
	c, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	h := nextHandshake(t, handshakes)
	if string(h.earlyData) != "hello" || h.requestURI != "/p" {
		t.Fatalf("handshake = %+v", h)
	}
	if got := readN(t, c, 5); string(got) != "hello" {
		t.Fatalf("echo = %q", got)
	}
}

func TestWsEarlyDataReadFirstHandshakesWithoutEarlyData(t *testing.T) {
	greeting := []byte("server speaks first")
	srv, handshakes, _ := echoServer(t, DefaultEarlyDataHeaderName, greeting)
	d := newTestWs(t, srv, "/p?ed=2048")
	c, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer c.Close()
	if got := readN(t, c, len(greeting)); !bytes.Equal(got, greeting) {
		t.Fatalf("greeting = %q", got)
	}
	h := nextHandshake(t, handshakes)
	if h.rawHeader != "" {
		t.Fatalf("read-first handshake carried early data %q", h.rawHeader)
	}
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if got := readN(t, c, 1); string(got) != "x" {
		t.Fatalf("echo = %q", got)
	}
}

func TestWsEarlyDataReadWaitsForFirstWrite(t *testing.T) {
	srv, handshakes, _ := echoServer(t, DefaultEarlyDataHeaderName, nil)
	d := newTestWs(t, srv, "/p?ed=2048")
	c, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer c.Close()

	// A relay usually starts reading before the client has sent anything.
	readDone := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 5)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.ReadFull(c, buf)
		readDone <- buf
	}()
	time.Sleep(20 * time.Millisecond)
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	h := nextHandshake(t, handshakes)
	if string(h.earlyData) != "hello" {
		t.Fatalf("early data = %q, want hello", h.earlyData)
	}
	if got := <-readDone; string(got) != "hello" {
		t.Fatalf("echo = %q", got)
	}
}

func TestWsEarlyDataClosedBeforeWrite(t *testing.T) {
	srv, _, hits := echoServer(t, DefaultEarlyDataHeaderName, nil)
	d := newTestWs(t, srv, "/p?ed=2048")
	c, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("Write() after Close() succeeded")
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read() after Close() succeeded")
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("closed conn still handshook (%d requests)", n)
	}
}

func TestWsEarlyDataDialError(t *testing.T) {
	srv, _, _ := echoServer(t, DefaultEarlyDataHeaderName, nil)
	d := newTestWs(t, srv, "/p?ed=2048")
	srv.Close()
	c, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("Write() to a dead server succeeded")
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read() after a failed handshake succeeded")
	}
}
