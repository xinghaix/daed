package ws

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Xray-compatible WebSocket early data ("0-RTT").
//
// Share links written for Xray put the early-data budget into the ws path as a
// query parameter, e.g. "/abcd1234?ed=2048". Xray strips "ed" from the request
// path, delays the WebSocket handshake until the first write, and carries up to
// "ed" bytes of that first payload base64url-encoded (no padding) in the
// Sec-WebSocket-Protocol request header. Xray/V2Fly servers prepend the decoded
// header to the stream, saving one round trip. Some clients additionally accept
// "eh" to name a different header (V2Fly's early_data_header_name); it is
// honoured here as well.

const (
	// DefaultEarlyDataHeaderName is the header Xray uses to carry early data.
	DefaultEarlyDataHeaderName = "Sec-WebSocket-Protocol"

	// earlyDataReadGrace is how long a Read that happens before the first
	// Write waits for that Write before handshaking without early data, so
	// protocols where the server speaks first still work.
	earlyDataReadGrace = 200 * time.Millisecond

	// defaultEarlyDataDialTimeout bounds the deferred handshake when the
	// caller's context carried no deadline.
	defaultEarlyDataDialTimeout = 10 * time.Second
)

// parseEarlyDataPath splits a ws path such as "/abcd1234?ed=2048&x=1" into the
// request path, the raw query to send, the early-data budget in bytes and the
// header that carries the early data.
//
// When the path has no positive "ed" parameter the query is returned verbatim
// and maxEarlyData is 0. Otherwise "ed" and "eh" are removed and the remaining
// query parameters are kept in their original form and order.
func parseEarlyDataPath(p string) (path, rawQuery string, maxEarlyData int, header string) {
	path, rawQuery, ok := strings.Cut(p, "?")
	if !ok {
		return p, "", 0, ""
	}
	values, _ := url.ParseQuery(rawQuery)
	ed, err := strconv.Atoi(strings.TrimSpace(values.Get("ed")))
	if err != nil || ed <= 0 {
		return path, rawQuery, 0, ""
	}
	header = DefaultEarlyDataHeaderName
	if eh := strings.TrimSpace(values.Get("eh")); eh != "" {
		header = eh
	}
	kept := make([]string, 0, 4)
	for _, kv := range strings.Split(rawQuery, "&") {
		key, _, _ := strings.Cut(kv, "=")
		if k, err := url.QueryUnescape(key); err == nil {
			key = k
		}
		if key == "ed" || key == "eh" || kv == "" {
			continue
		}
		kept = append(kept, kv)
	}
	return path, strings.Join(kept, "&"), ed, header
}

// earlyDataConn defers the WebSocket handshake until the first Write so the
// beginning of that payload can travel in the handshake request.
type earlyDataConn struct {
	dial         func(ctx context.Context, earlyData []byte) (*conn, error)
	maxEarlyData int
	dialTimeout  time.Duration

	// ctx outlives the caller's dial context (only its values are kept) and is
	// cancelled by Close to abort an in-flight handshake.
	ctx    context.Context
	cancel context.CancelFunc

	dialMu sync.Mutex    // serialises the single handshake
	ready  chan struct{} // closed once the handshake finished
	conn   *conn         // valid after ready is closed and err == nil
	err    error         // valid after ready is closed

	stateMu       sync.Mutex
	closed        bool
	readDeadline  time.Time
	writeDeadline time.Time
}

func newEarlyDataConn(parent context.Context, maxEarlyData int, dial func(ctx context.Context, earlyData []byte) (*conn, error)) (*earlyDataConn, error) {
	if err := parent.Err(); err != nil {
		return nil, err
	}
	timeout := defaultEarlyDataDialTimeout
	if deadline, ok := parent.Deadline(); ok {
		timeout = max(time.Until(deadline), time.Second)
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	return &earlyDataConn{
		dial:         dial,
		maxEarlyData: maxEarlyData,
		dialTimeout:  timeout,
		ctx:          ctx,
		cancel:       cancel,
		ready:        make(chan struct{}),
	}, nil
}

// handshake performs the deferred WebSocket handshake once. It reports whether
// this call performed it (and therefore consumed earlyData).
func (c *earlyDataConn) handshake(earlyData []byte) (bool, error) {
	c.dialMu.Lock()
	defer c.dialMu.Unlock()
	select {
	case <-c.ready:
		return false, c.err
	default:
	}

	ctx, cancel := context.WithTimeout(c.ctx, c.dialTimeout)
	wc, err := c.dial(ctx, earlyData)
	cancel()

	c.stateMu.Lock()
	if err == nil && c.closed {
		_ = wc.Close()
		wc, err = nil, net.ErrClosed
	}
	if err == nil {
		if !c.readDeadline.IsZero() {
			_ = wc.SetReadDeadline(c.readDeadline)
		}
		if !c.writeDeadline.IsZero() {
			_ = wc.SetWriteDeadline(c.writeDeadline)
		}
	}
	c.conn, c.err = wc, err
	c.stateMu.Unlock()
	close(c.ready)
	return true, err
}

func (c *earlyDataConn) Write(b []byte) (int, error) {
	select {
	case <-c.ready:
		if c.err != nil {
			return 0, c.err
		}
		return c.conn.Write(b)
	default:
	}
	if c.ctx.Err() != nil {
		return 0, net.ErrClosed
	}

	earlyData := b
	if len(earlyData) > c.maxEarlyData {
		earlyData = earlyData[:c.maxEarlyData]
	}
	performed, err := c.handshake(earlyData)
	if err != nil {
		return 0, err
	}
	if !performed {
		// A concurrent Read handshook without early data first.
		return c.conn.Write(b)
	}
	if len(earlyData) == len(b) {
		return len(b), nil
	}
	n, err := c.conn.Write(b[len(earlyData):])
	return len(earlyData) + n, err
}

func (c *earlyDataConn) Read(b []byte) (int, error) {
	select {
	case <-c.ready:
	default:
		timer := time.NewTimer(earlyDataReadGrace)
		select {
		case <-c.ready:
		case <-c.ctx.Done():
			timer.Stop()
			return 0, net.ErrClosed
		case <-timer.C:
		}
		timer.Stop()
		if _, err := c.handshake(nil); err != nil {
			return 0, err
		}
	}
	if c.err != nil {
		return 0, c.err
	}
	return c.conn.Read(b)
}

func (c *earlyDataConn) Close() error {
	c.stateMu.Lock()
	if c.closed {
		c.stateMu.Unlock()
		return nil
	}
	c.closed = true
	wc := c.conn
	c.stateMu.Unlock()
	c.cancel()
	if wc != nil {
		return wc.Close()
	}
	return nil
}

func (c *earlyDataConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *earlyDataConn) SetReadDeadline(t time.Time) error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.readDeadline = t
	if c.conn != nil {
		return c.conn.SetReadDeadline(t)
	}
	return nil
}

func (c *earlyDataConn) SetWriteDeadline(t time.Time) error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.writeDeadline = t
	if c.conn != nil {
		return c.conn.SetWriteDeadline(t)
	}
	return nil
}
