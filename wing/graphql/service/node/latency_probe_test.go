package node

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"go.uber.org/goleak"
)

func plainDial(ctx context.Context, _ string, addr string) (netproxy.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

func systemLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func setLatencyTimeouts(t *testing.T, handshake, http time.Duration) {
	t.Helper()
	oldHandshake, oldHTTP := latencyHandshakeTimeout, latencyHTTPTimeout
	latencyHandshakeTimeout, latencyHTTPTimeout = handshake, http
	t.Cleanup(func() { latencyHandshakeTimeout, latencyHTTPTimeout = oldHandshake, oldHTTP })
}

func loopbackIP(t *testing.T, rawURL string) netip.Addr {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return netip.MustParseAddr(u.Hostname())
}

func TestProbeHTTP(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	setLatencyTimeouts(t, time.Second, 300*time.Millisecond)

	var mu sync.Mutex
	newConns := 0
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/slow"):
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
		case r.URL.Query().Get("code") == "404":
			w.WriteHeader(http.StatusNotFound)
		case r.URL.Query().Get("code") == "500":
			w.WriteHeader(http.StatusInternalServerError)
		case strings.HasSuffix(r.URL.Path, "/generate_204"):
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			mu.Lock()
			newConns++
			mu.Unlock()
		}
	}
	srv.Start()
	defer srv.Close()
	ip := loopbackIP(t, srv.URL)

	cases := []struct {
		path    string
		ok      bool
		message string
	}{
		{"/generate_204", true, ""},
		{"/generate_204?code=404", false, "HTTP 404"},
		{"/other", true, ""}, // dae accepts 2xx-4xx for non generate_NNN URLs
		{"/other?code=500", false, "HTTP 500"},
		{"/slow", false, "timeout"},
	}
	for _, c := range cases {
		u, _ := url.Parse(srv.URL + c.path)
		outcome := probeHTTP(context.Background(), plainDial, u, http.MethodHead, ip, 0, false)
		if outcome.Ok != c.ok || outcome.Message != c.message {
			t.Errorf("%s: got ok=%v message=%q, want ok=%v message=%q", c.path, outcome.Ok, outcome.Message, c.ok, c.message)
		}
		if outcome.Ok && outcome.Latency <= 0 {
			t.Errorf("%s: no latency", c.path)
		}
		if outcome.TestedAt.IsZero() {
			t.Errorf("%s: TestedAt not set", c.path)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if newConns != len(cases) {
		t.Fatalf("every probe must use a fresh connection: %d connections for %d probes", newConns, len(cases))
	}
}

func TestProbeHTTPTLSFailure(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	setLatencyTimeouts(t, time.Second, 2*time.Second)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Config.ErrorLog = nil
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/generate_204")
	outcome := probeHTTP(context.Background(), plainDial, u, http.MethodGet, loopbackIP(t, srv.URL), 0, false)
	if outcome.Ok || !strings.HasPrefix(outcome.Message, "TLS certificate error: ") {
		t.Fatalf("got %+v", outcome)
	}
}

func TestProbeHTTPCanceled(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	u, _ := url.Parse(srv.URL + "/generate_204")
	start := time.Now()
	outcome := probeHTTP(ctx, plainDial, u, http.MethodGet, loopbackIP(t, srv.URL), 0, false)
	if outcome.Ok || outcome.Message != "canceled" || time.Since(start) > 2*time.Second {
		t.Fatalf("got %+v after %v", outcome, time.Since(start))
	}
}

func TestDescribeProbeError(t *testing.T) {
	long := strings.Repeat("x", 1000)
	for _, c := range []struct {
		err  error
		want string
	}{
		{httpStatusError(404), "HTTP 404"},
		{context.DeadlineExceeded, "timeout"},
		{context.Canceled, "canceled"},
		{&url.Error{Op: "Head", URL: "http://x", Err: httpStatusError(502)}, "HTTP 502"},
		{&url.Error{Op: "Head", URL: "http://x", Err: errString("websocket: bad handshake (HTTP 403)")}, "WebSocket handshake failed: websocket: bad handshake (HTTP 403)"},
		{errString("remote error: tls: handshake failure"), "TLS handshake failed: remote error: tls: handshake failure"},
	} {
		if got := describeProbeError(c.err); got != c.want {
			t.Errorf("%v: got %q want %q", c.err, got, c.want)
		}
	}
	if got := describeProbeError(errString(long)); len(got) > latencyMessageMaxLen+len("…") {
		t.Errorf("message not truncated: %d", len(got))
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestSanityNote(t *testing.T) {
	for _, c := range []struct {
		ip      string
		latency time.Duration
		warn    string
	}{
		{"203.0.113.10", time.Millisecond, "suspiciously low"},
		{"203.0.113.10", 30 * time.Millisecond, ""},
		{"198.18.0.7", 40 * time.Millisecond, "fake-ip"},
		{"192.168.1.2", time.Millisecond, ""},
		{"127.0.0.1", 0, ""},
		{"100.101.102.103", time.Millisecond, ""}, // CGNAT / Tailscale
		{"2001:db8::1", time.Millisecond, "suspiciously low"},
	} {
		got := sanityNote(netip.MustParseAddr(c.ip), c.latency)
		if (c.warn == "") != (got == "") || !strings.Contains(got, c.warn) {
			t.Errorf("%s %v: got %q, want %q", c.ip, c.latency, got, c.warn)
		}
	}
}
