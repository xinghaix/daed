// from https://github.com/Dreamacro/clash/blob/master/component/simple-obfs/http.go

package simpleobfs

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
)

// HTTPObfs is shadowsocks http simple-obfs implementation
type HTTPObfs struct {
	netproxy.Conn
	host          string
	port          string
	path          string
	buf           []byte
	offset        int
	firstRequest  bool
	firstResponse bool
	// headerBuf accumulates response-header bytes that arrived without the
	// "\r\n\r\n" terminator yet (the header may straddle TCP segments).
	// Guarded by rMu.
	headerBuf []byte
	wMu       sync.Mutex
	rMu       sync.Mutex
}

// maxResponseHeaderSize bounds headerBuf: the peer controls how many bytes
// it can send without a terminator.
const maxResponseHeaderSize = 8 * 1024

func (ho *HTTPObfs) Read(b []byte) (int, error) {
	ho.rMu.Lock()
	defer ho.rMu.Unlock()
	if ho.buf != nil {
		n := copy(b, ho.buf[ho.offset:])
		ho.offset += n
		if ho.offset == len(ho.buf) {
			pool.Put(ho.buf)
			ho.buf = nil
		}
		return n, nil
	}

	if ho.firstResponse {
		n, err := ho.readFirstResponse(b)
		if err != nil || n > 0 {
			return n, err
		}
		// The header was consumed but carried no body bytes; fall through
		// to the raw read instead of returning (0, nil).
	}
	return ho.Conn.Read(b)
}

// readFirstResponse reads until the response header terminator is seen and
// delivers whatever body bytes followed it. A single Read that does not yet
// contain "\r\n\r\n" is NOT end of stream — the header may straddle TCP
// segments — so bytes are accumulated and the JOINED buffer is searched.
// The terminator search runs BEFORE the size bound: a single read can carry
// the complete header plus kilobytes of body (the normal fast-relay case),
// and that is success, not an oversized header. Only a terminator-less
// accumulation beyond the bound is an error.
func (ho *HTTPObfs) readFirstResponse(b []byte) (int, error) {
	for {
		buf := pool.Get(1 << 15)
		n, err := ho.Conn.Read(buf)
		if err != nil {
			pool.Put(buf)
			ho.headerBuf = nil
			return 0, err
		}
		ho.headerBuf = append(ho.headerBuf, buf[:n]...)
		pool.Put(buf)
		idx := bytes.Index(ho.headerBuf, []byte("\r\n\r\n"))
		if idx == -1 {
			if len(ho.headerBuf) > maxResponseHeaderSize {
				ho.headerBuf = nil
				return 0, fmt.Errorf("simple-obfs http: response header exceeds %d bytes", maxResponseHeaderSize)
			}
			continue
		}
		ho.firstResponse = false
		body := ho.headerBuf[idx+4:]
		m := copy(b, body)
		if len(body) > m {
			rest := pool.Get(len(body) - m)
			copy(rest, body[m:])
			ho.buf = rest
			ho.offset = 0
		}
		ho.headerBuf = nil
		return m, nil
	}
}

func (ho *HTTPObfs) Write(b []byte) (int, error) {
	ho.wMu.Lock()
	defer ho.wMu.Unlock()
	if ho.firstRequest {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://%s%s", ho.authorityHost(), ho.path), bytes.NewBuffer(b[:]))
		if err != nil {
			// Do not swallow this: without a request there is no obfs
			// handshake, and the caller must see the failure rather than
			// have raw payload sent as if it were the first request.
			return 0, fmt.Errorf("simple-obfs http: build first request: %w", err)
		}
		req.Header.Set("User-Agent", fmt.Sprintf("curl/7.%d.%d", fastrand.Int()%87, fastrand.Int()%2))
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		if ho.port != "80" {
			req.Host = net.JoinHostPort(ho.host, ho.port)
		}
		randBytes := make([]byte, 16)
		_, _ = fastrand.Read(randBytes)
		req.Header.Set("Sec-WebSocket-Key", base64.URLEncoding.EncodeToString(randBytes))
		req.ContentLength = int64(len(b))
		if err := req.Write(ho.Conn); err != nil {
			// Leave firstRequest set: the request was not delivered, so a
			// retry must still emit the obfs handshake instead of writing
			// the payload bare.
			return 0, err
		}
		ho.firstRequest = false
		return len(b), nil
	}

	return ho.Conn.Write(b)
}

// authorityHost renders the request URL authority. A bare IPv6 literal must be
// bracketed or url.Parse rejects it, and a zone identifier must have its "%"
// escaped (RFC 6874's "%25") or url.Parse fails on the escape sequence. The Go
// toolchain this repo builds with (1.26) no longer panics on an unescaped
// colon in the authority, but the request still has to be well formed.
func (ho *HTTPObfs) authorityHost() string {
	host := ho.host
	if !strings.Contains(host, ":") {
		return host
	}
	if strings.Contains(host, "%") {
		host = strings.Replace(host, "%", "%25", 1)
	}
	return "[" + host + "]"
}

func (ho *HTTPObfs) CloseWrite() error {
	return netproxy.ForwardCloseWrite(ho.Conn)
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the wrapped conn; see TLSObfs for why the
// forward is required rather than inherited.
func (ho *HTTPObfs) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(ho.Conn)
}

func NewHTTPObfs(conn netproxy.Conn, host string, port string, path string) netproxy.Conn {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	// The Host header carries the bare address; brackets are added when the
	// authority is rendered. Accepting a bracketed literal here keeps the
	// constructor's contract with its callers (simpleobfs.NewSimpleObfs passes
	// the ?host= override verbatim, dialer/shadowsocks passes u.Hostname()).
	if len(host) > 1 && strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	return &HTTPObfs{
		Conn:          conn,
		firstRequest:  true,
		firstResponse: true,
		host:          host,
		port:          port,
		path:          path,
	}
}
