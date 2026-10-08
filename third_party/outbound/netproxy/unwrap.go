package netproxy

import "net"

// UnderlyingConnProvider exposes the wrapped inner net.Conn.
// Wrappers that want to participate in transport capability checks
// (for example TCP fast-path / offload) should implement this interface.
type UnderlyingConnProvider interface {
	UnderlyingConn() net.Conn
}

// WriteCloser is the optional half-close surface. dae's relay type-asserts
// the same method; TLS-wrapped conns typically do not implement it.
type WriteCloser interface {
	CloseWrite() error
}

// IntrinsicConnProvider is the wrapper-peeling convention. A wrapper placed
// between a protocol layer and the conn that layer actually needs (a read
// buffer, a write coalescer, another protocol conn) exposes that inner conn so
// capability checks reach the real transport instead of stopping at the
// wrapper. Embedding netproxy.Conn promotes only the base interface, so any
// other capability has to be forwarded explicitly or declared here.
type IntrinsicConnProvider interface {
	IntrinsicConn() Conn
}

// ForwardCloseWrite half-closes c. Protocol wrappers that implement
// WriteCloser are preferred; otherwise a *net.TCPConn is unwrapped via
// UnderlyingConnProvider. crypto/tls.Conn is not a WriteCloser and is not
// peeled to TCP, so TLS-wrapped chains no-op.
func ForwardCloseWrite(c Conn) error {
	if c == nil {
		return nil
	}
	if wc, ok := c.(WriteCloser); ok {
		return wc.CloseWrite()
	}
	if tcp, ok := UnwrapTCPConn(c); ok {
		return tcp.CloseWrite()
	}
	return nil
}

const unwrapTCPConnMaxDepth = 8

// UnwrapTCPConn resolves a concrete *net.TCPConn from a possibly wrapped
// connection by following UnderlyingConnProvider.
func UnwrapTCPConn(conn any) (*net.TCPConn, bool) {
	return unwrapTCPConnDepth(conn, 0)
}

func unwrapTCPConnDepth(conn any, depth int) (*net.TCPConn, bool) {
	if conn == nil || depth >= unwrapTCPConnMaxDepth {
		return nil, false
	}

	switch c := conn.(type) {
	case *net.TCPConn:
		return c, true
	case UnderlyingConnProvider:
		return unwrapTCPConnDepth(c.UnderlyingConn(), depth+1)
	default:
		return nil, false
	}
}

const unwrapIntrinsicConnMaxDepth = 8

// UnwrapIntrinsicConn resolves the conn at the end of a chain of
// IntrinsicConnProvider wrappers. Callers use it to reach a conn whose
// concrete type or optional methods a wrapper would otherwise hide.
//
// It returns c itself when c is not such a wrapper (or the chain ends), so
// callers can assert on the result without a wrapper-specific pre-check. The
// walk is bounded: a wrapper that reports itself or cycles terminates here
// instead of spinning forever during connection setup.
func UnwrapIntrinsicConn(c Conn) Conn {
	for depth := 0; c != nil && depth < unwrapIntrinsicConnMaxDepth; depth++ {
		wrapper, ok := c.(IntrinsicConnProvider)
		if !ok {
			return c
		}
		next := wrapper.IntrinsicConn()
		if next == nil || next == c {
			return c
		}
		c = next
	}
	return c
}
