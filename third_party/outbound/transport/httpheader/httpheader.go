package httpheader

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
)

const (
	defaultHost       = "www.baidu.com"
	defaultUserAgent  = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36"
	maxResponseHeader = 8192

	// bufioBufferSize is the read buffer size for the wrapped connection.
	// It is decoupled from maxResponseHeader (which only bounds the HTTP
	// response header parsing) because downstream protocols (e.g. vmess)
	// issue io.ReadFull calls of up to ~16KB per chunk. A small bufio buffer
	// splits those reads into multiple syscalls, inflating write count in the
	// relay loop by ~1.5x and wasting CPU on syscall overhead.
	bufioBufferSize = 32 << 10
)

var errResponseHeaderTooLarge = errors.New("HTTP response header is too large")

// Dialer implements the legacy V2Ray TCP HTTP header transport.
type Dialer struct {
	nextDialer netproxy.Dialer
	host       string
	path       string
}

func NewDialer(nextDialer netproxy.Dialer, host, path string) (*Dialer, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		host = defaultHost
	}

	path = strings.TrimSpace(path)
	if path == "" {
		path = "/"
	} else if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if _, err := http.NewRequest(http.MethodGet, path, nil); err != nil {
		return nil, fmt.Errorf("httpheader: invalid path: %w", err)
	}

	return &Dialer{
		nextDialer: nextDialer,
		host:       host,
		path:       path,
	}, nil
}

func (d *Dialer) UnwrapDialer() netproxy.Dialer {
	return d.nextDialer
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	if magicNetwork.Network != "tcp" {
		return nil, fmt.Errorf("%w: httpheader+%s", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}

	conn, err := d.nextDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return newConn(conn, d.host, d.path), nil
}

type conn struct {
	netproxy.Conn
	reader *bufio.Reader
	host   string
	path   string

	readMu     sync.Mutex
	writeMu    sync.Mutex
	headerRead bool
	headerSent bool
	readErr    error
	writeErr   error
}

func newConn(raw netproxy.Conn, host, path string) *conn {
	return &conn{
		Conn:   raw,
		reader: bufio.NewReaderSize(raw, bufioBufferSize),
		host:   host,
		path:   path,
	}
}

func (c *conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if !c.headerRead {
		if err := discardResponseHeader(c.reader); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return 0, err
			}
			var to interface{ Timeout() bool }
			if errors.As(err, &to) && to.Timeout() {
				return 0, err
			}
			c.headerRead = true
			c.readErr = err
			return 0, err
		}
		c.headerRead = true
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.reader.Read(p)
}

func (c *conn) CloseWrite() error {
	return netproxy.ForwardCloseWrite(c.Conn)
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the wrapped conn. This type embeds
// netproxy.Conn, which promotes SetWriteDeadline but not this optional method,
// so without the forward a session-closing inner conn (TUIC, hysteria2) would
// be invisible to deadline-arming callers.
func (c *conn) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(c.Conn)
}

func (c *conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if !c.headerSent {
		c.headerSent = true
		c.writeErr = c.writeRequestHeader()
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.Conn.Write(p)
}

func (c *conn) writeRequestHeader() error {
	req, err := http.NewRequest(http.MethodGet, c.path, nil)
	if err != nil {
		return err
	}
	req.Host = c.host
	// Do not advertise gzip/deflate: the server's compressed response would
	// make every connection allocate a flate decoder (compress/flate + gzip
	// Reader per handshake), which shows up as ~4k allocs/10s under
	// connection-storm workloads (speedtests) and feeds the GC loop. The
	// handshake response header is tiny; compression saves nothing here.
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("User-Agent", defaultUserAgent)
	return req.Write(c.Conn)
}

func discardResponseHeader(reader *bufio.Reader) error {
	total := 0
	for {
		line, err := reader.ReadSlice('\n')
		total += len(line)
		if total > maxResponseHeader || errors.Is(err, bufio.ErrBufferFull) {
			return errResponseHeaderTooLarge
		}
		if err != nil {
			return fmt.Errorf("httpheader: read response header: %w", err)
		}
		if string(line) == "\r\n" || string(line) == "\n" {
			return nil
		}
	}
}
