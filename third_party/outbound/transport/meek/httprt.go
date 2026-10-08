package meek

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

var (
	globalRoundTripperCacheMap    map[string]http.RoundTripper
	globalRoundTripperCacheAccess sync.Mutex
)

const maxMeekResponseBodySize = 1 << 20

func meekRoundTripperCacheKey(scope, addr, url string, tlsConfig *tls.Config) string {
	serverName := ""
	insecure := false
	nextProtos := ""
	if tlsConfig != nil {
		serverName = tlsConfig.ServerName
		insecure = tlsConfig.InsecureSkipVerify
		nextProtos = strings.Join(tlsConfig.NextProtos, "\x01")
	}
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%t\x00%s", scope, addr, url, serverName, insecure, nextProtos)
}

type httpTripperClient struct {
	addr       string
	nextDialer netproxy.Dialer
	tlsConfig  *tls.Config
	url        string
}

func CleanScopedRoundTripperCache(scope string) {
	if scope == "" {
		return
	}
	prefix := scope + "\x00"
	globalRoundTripperCacheAccess.Lock()
	cached := make([]http.RoundTripper, 0)
	for key, rt := range globalRoundTripperCacheMap {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		cached = append(cached, rt)
		delete(globalRoundTripperCacheMap, key)
	}
	globalRoundTripperCacheAccess.Unlock()

	for _, rt := range cached {
		if closeIdler, ok := rt.(interface{ CloseIdleConnections() }); ok {
			closeIdler.CloseIdleConnections()
		}
	}
}

func (c *httpTripperClient) RoundTrip(ctx context.Context, req Request) (resp Response, err error) {
	roundTripper := c.getRoundTripper()

	connectionTagStr := base64.RawURLEncoding.EncodeToString(req.ConnectionTag)

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(req.Data))
	if err != nil {
		return
	}
	httpRequest.Header.Set("X-Session-ID", connectionTagStr)

	httpResp, err := roundTripper.RoundTrip(httpRequest)
	if err != nil {
		return
	}
	defer func() { _ = httpResp.Body.Close() }()

	result, err := readMeekResponseBody(httpResp.Body)
	if err != nil {
		return
	}
	return Response{Data: result}, err
}

func readMeekResponseBody(body io.Reader) ([]byte, error) {
	result, err := io.ReadAll(io.LimitReader(body, maxMeekResponseBodySize+1))
	if err != nil {
		return nil, err
	}
	if len(result) > maxMeekResponseBodySize {
		return nil, fmt.Errorf("meek: response body exceeds %d bytes", maxMeekResponseBodySize)
	}
	return result, nil
}

func (c *httpTripperClient) getRoundTripper() http.RoundTripper {
	cacheKey := meekRoundTripperCacheKey(netproxy.TransportCacheNamespace(c.nextDialer), c.addr, c.url, c.tlsConfig)
	globalRoundTripperCacheAccess.Lock()
	defer globalRoundTripperCacheAccess.Unlock()
	if globalRoundTripperCacheMap == nil {
		globalRoundTripperCacheMap = make(map[string]http.RoundTripper)
	}
	if _, ok := globalRoundTripperCacheMap[cacheKey]; !ok {
		globalRoundTripperCacheMap[cacheKey] = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				rc, err := c.nextDialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, fmt.Errorf("[Meek]: dial to %s: %w", c.addr, err)
				}
				return &netproxy.FakeNetConn{
					Conn:  rc,
					LAddr: nil,
					RAddr: nil,
				}, nil
			},
			TLSClientConfig: c.tlsConfig,
			// The cache is keyed per destination and nothing in this repo
			// reaps transports, so without an idle timeout every transport
			// would pin its TLS connections (and their read/write
			// goroutines) for the process lifetime.
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		}
	}
	return globalRoundTripperCacheMap[cacheKey]
}
