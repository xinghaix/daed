package meek

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
)

type closeIdleSpyRoundTripper struct {
	closeCalls atomic.Int32
}

func (s *closeIdleSpyRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected RoundTrip call")
}

func (s *closeIdleSpyRoundTripper) CloseIdleConnections() {
	s.closeCalls.Add(1)
}

func TestMeekRoundTripperCacheKeyIncludesALPN(t *testing.T) {
	base := &tls.Config{ServerName: "edge.example"}
	h2 := base.Clone()
	h2.NextProtos = []string{"h2"}
	http1 := base.Clone()
	http1.NextProtos = []string{"http/1.1"}

	keyH2 := meekRoundTripperCacheKey("scope", "proxy:443", "https://edge.example", h2)
	keyHTTP1 := meekRoundTripperCacheKey("scope", "proxy:443", "https://edge.example", http1)
	if keyH2 == keyHTTP1 {
		t.Fatal("cache key shared transports with different ALPN")
	}
}

type contextSpyRoundTripper struct {
	ctx context.Context
}

func (s *contextSpyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	s.ctx = req.Context()
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(http.NoBody),
	}, nil
}

type bodySpyRoundTripper struct {
	body []byte
}

func (s *bodySpyRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(s.body)),
	}, nil
}

func TestRoundTripPropagatesRequestContext(t *testing.T) {
	globalRoundTripperCacheAccess.Lock()
	original := globalRoundTripperCacheMap
	globalRoundTripperCacheMap = nil
	globalRoundTripperCacheAccess.Unlock()
	t.Cleanup(func() {
		globalRoundTripperCacheAccess.Lock()
		globalRoundTripperCacheMap = original
		globalRoundTripperCacheAccess.Unlock()
	})

	spy := &contextSpyRoundTripper{}
	client := &httpTripperClient{
		addr: "test",
		url:  "https://example.com",
	}

	globalRoundTripperCacheAccess.Lock()
	globalRoundTripperCacheMap = map[string]http.RoundTripper{
		meekRoundTripperCacheKey("", client.addr, client.url, client.tlsConfig): spy,
	}
	globalRoundTripperCacheAccess.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err := client.RoundTrip(ctx, Request{Data: []byte("ping")})
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	if spy.ctx != ctx {
		t.Fatal("request context was not propagated to the round tripper")
	}
}

func TestCleanScopedRoundTripperCacheOnlyClosesMatchingScope(t *testing.T) {
	globalRoundTripperCacheAccess.Lock()
	original := globalRoundTripperCacheMap
	globalRoundTripperCacheMap = nil
	globalRoundTripperCacheAccess.Unlock()
	t.Cleanup(func() {
		globalRoundTripperCacheAccess.Lock()
		globalRoundTripperCacheMap = original
		globalRoundTripperCacheAccess.Unlock()
	})

	spyA := &closeIdleSpyRoundTripper{}
	spyB := &closeIdleSpyRoundTripper{}
	globalRoundTripperCacheAccess.Lock()
	globalRoundTripperCacheMap = map[string]http.RoundTripper{
		meekRoundTripperCacheKey("scope-a", "test-a", "https://a.example", &tls.Config{}): spyA,
		meekRoundTripperCacheKey("scope-b", "test-b", "https://b.example", &tls.Config{}): spyB,
	}
	globalRoundTripperCacheAccess.Unlock()

	CleanScopedRoundTripperCache("scope-a")

	if got := spyA.closeCalls.Load(); got != 1 {
		t.Fatalf("scope-a CloseIdleConnections called %d times, want 1", got)
	}
	if got := spyB.closeCalls.Load(); got != 0 {
		t.Fatalf("scope-b CloseIdleConnections called %d times, want 0", got)
	}

	globalRoundTripperCacheAccess.Lock()
	defer globalRoundTripperCacheAccess.Unlock()
	if len(globalRoundTripperCacheMap) != 1 {
		t.Fatalf("global round tripper cache size = %d, want 1", len(globalRoundTripperCacheMap))
	}
}

func TestRoundTripRejectsOversizedResponse(t *testing.T) {
	globalRoundTripperCacheAccess.Lock()
	original := globalRoundTripperCacheMap
	globalRoundTripperCacheMap = nil
	globalRoundTripperCacheAccess.Unlock()
	t.Cleanup(func() {
		globalRoundTripperCacheAccess.Lock()
		globalRoundTripperCacheMap = original
		globalRoundTripperCacheAccess.Unlock()
	})

	spy := &bodySpyRoundTripper{body: make([]byte, maxMeekResponseBodySize+1)}
	client := &httpTripperClient{
		addr: "test",
		url:  "https://example.com",
	}

	globalRoundTripperCacheAccess.Lock()
	globalRoundTripperCacheMap = map[string]http.RoundTripper{
		meekRoundTripperCacheKey("", client.addr, client.url, client.tlsConfig): spy,
	}
	globalRoundTripperCacheAccess.Unlock()

	_, err := client.RoundTrip(context.Background(), Request{Data: []byte("ping")})
	if err == nil {
		t.Fatal("RoundTrip() error = nil, want oversized response error")
	}
}
