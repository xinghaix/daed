package coalesce

import (
	"net"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// FlushConn is the netproxy.Conn wrapper a transport returns to its
// protocol layer: every Write returns only after the coalesced records of
// that write burst have been pushed to the socket, so plain Write/Read
// users need no flush discipline of their own.
//
// Before the coalescer, transport/tls returned the *tls.Conn / *utls.UConn
// itself, so every capability that callers discover by duck typing on that
// conn (XTLS/Vision's IntrinsicConn peel, half-close, the destructive
// write-deadline declaration, raw-socket access, the net.Conn address
// accessors) reached them directly. FlushConn is an extra layer, and embedding
// netproxy.Conn promotes only the base interface, so each capability needs an
// explicit forward below or it silently disappears. A missing forward is not a
// compile error: the callers use the ok-form and quietly take their fallback
// path (XTLS refuses a wrapped underlay, half-close becomes a no-op, ...).
type FlushConn struct {
	netproxy.Conn // the TLS-layer conn (tls.Conn or utls.UConn)
	co            *Conn
}

// NewFlushConn wraps an established TLS-layer conn and binds it to the
// coalescer sitting underneath that TLS layer.
func NewFlushConn(tlsConn netproxy.Conn, co *Conn) *FlushConn {
	return &FlushConn{Conn: tlsConn, co: co}
}

func (f *FlushConn) Write(b []byte) (int, error) {
	n, err := f.Conn.Write(b)
	if ferr := f.co.Flush(); ferr != nil && err == nil {
		err = ferr
	}
	return n, err
}

// IntrinsicConn forwards the wrapper-peeling convention so callers that need
// the TLS/REALITY conn itself (notably XTLS/Vision) reach it through this
// layer. Without the forward, visionIntrinsicConn stops at *FlushConn and
// fails with "XTLS only supports TLS and REALITY directly for now".
func (f *FlushConn) IntrinsicConn() netproxy.Conn {
	if ic, ok := f.Conn.(netproxy.IntrinsicConnProvider); ok {
		return ic.IntrinsicConn()
	}
	return f.Conn
}

// UnderlyingConn forwards the wrapped conn's raw-socket accessor, if any. The
// TLS conns this layer wraps do not expose one themselves, so like
// netproxy.BufferedReaderConn this returns nil rather than guessing at a
// net.Conn buried under the TLS layer.
func (f *FlushConn) UnderlyingConn() net.Conn {
	if u, ok := f.Conn.(netproxy.UnderlyingConnProvider); ok {
		return u.UnderlyingConn()
	}
	return nil
}

// WriteDeadlineClosesSession forwards the optional destructive write-deadline
// declaration, which embedding does not promote.
func (f *FlushConn) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(f.Conn)
}

// CloseWrite forwards half-close and then flushes the coalesced records that
// carried it. crypto/tls.Conn implements CloseWrite, but the promoted method
// set of an embedded netproxy.Conn does not include it, so without this forward
// every TLS-based transport silently lost half-close.
//
// The flush needs its own deadline window: crypto/tls closeNotify bounds the
// alert write with a 5s write deadline and then re-arms the deadline to
// time.Now() so that any subsequent write fails. That assumes c.conn.Write
// delivered the bytes to the socket; the coalescer deferred them, so the
// re-armed deadline would make the flush below drop the close_notify and
// surface i/o timeout on every half-close. Re-arm a fresh 5s window for the
// alert, flush it, then restore the writes-after-CloseWrite-fail contract.
func (f *FlushConn) CloseWrite() error {
	err := netproxy.ForwardCloseWrite(f.Conn)
	ferr := f.co.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if ferr == nil {
		ferr = f.co.Flush()
	}
	// tls.Conn.CloseWrite leaves the write deadline in the past on purpose:
	// any write after the half-close must fail. Keep that contract.
	_ = f.co.SetWriteDeadline(time.Now())
	if err == nil {
		err = ferr
	}
	return err
}

// LocalAddr exposes the wrapped TLS conn's local address so FlushConn keeps the
// net.Conn surface the TLS conn had before the coalescer layer existed.
func (f *FlushConn) LocalAddr() net.Addr {
	if a, ok := f.Conn.(interface{ LocalAddr() net.Addr }); ok {
		return a.LocalAddr()
	}
	return nil
}

// RemoteAddr exposes the wrapped TLS conn's remote address. See LocalAddr.
func (f *FlushConn) RemoteAddr() net.Addr {
	if a, ok := f.Conn.(interface{ RemoteAddr() net.Addr }); ok {
		return a.RemoteAddr()
	}
	return nil
}

// compile-time interface checks.
var (
	_ netproxy.Conn                   = (*FlushConn)(nil)
	_ netproxy.UnderlyingConnProvider = (*FlushConn)(nil)
	_ netproxy.WriteCloser            = (*FlushConn)(nil)
	_ netproxy.WriteDeadlineBehavior  = (*FlushConn)(nil)
	_ net.Conn                        = (*FlushConn)(nil)
)
