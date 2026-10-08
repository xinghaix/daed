package netproxy

import (
	"context"
	"time"
)

var (
	DialTimeout = 10 * time.Second
)

func NewDialTimeoutContextFrom(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, DialTimeout)
}

func NewDialTimeoutContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), DialTimeout)
}

// CaptureDeadline returns the caller's existing deadline. A zero value means
// the caller did not provide one.
func CaptureDeadline(ctx context.Context) time.Time {
	if ctx != nil {
		if deadline, ok := ctx.Deadline(); ok {
			return deadline
		}
	}
	return time.Time{}
}

// NewContextWithCapturedDeadline creates a background-rooted context using a
// previously captured deadline. It intentionally preserves the deadline without
// inheriting cancellation from the original short-lived dial context.
func NewContextWithCapturedDeadline(deadline time.Time, fallback time.Duration) (context.Context, context.CancelFunc) {
	if deadline.IsZero() {
		return context.WithTimeout(context.Background(), fallback)
	}
	return context.WithDeadline(context.Background(), deadline)
}

// NewDialTimeoutContextWithCapturedDeadline is a convenience wrapper around
// NewContextWithCapturedDeadline using DialTimeout as the fallback.
func NewDialTimeoutContextWithCapturedDeadline(deadline time.Time) (context.Context, context.CancelFunc) {
	return NewContextWithCapturedDeadline(deadline, DialTimeout)
}

// ApplyConnDeadlineFromContext applies ctx's deadline to conn and returns a
// restore function that clears it again. If ctx has no deadline, restore is a
// no-op.
func ApplyConnDeadlineFromContext(ctx context.Context, conn Conn) (restore func(), err error) {
	if ctx == nil {
		return func() {}, nil
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return func() {}, nil
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	return func() { _ = conn.SetDeadline(time.Time{}) }, nil
}

// HandshakeWithContext runs a TLS-style handshake under ctx. When the concrete
// connection lacks HandshakeContext, it falls back to applying ctx's deadline to
// the connection before calling Handshake.
func HandshakeWithContext(
	ctx context.Context,
	conn interface {
		Conn
		Handshake() error
	},
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if handshaker, ok := any(conn).(interface {
		HandshakeContext(context.Context) error
	}); ok {
		return handshaker.HandshakeContext(ctx)
	}

	restoreDeadline, err := ApplyConnDeadlineFromContext(ctx, conn)
	if err != nil {
		return err
	}
	defer restoreDeadline()
	return conn.Handshake()
}

// A Dialer is a means to establish a connection.
// Custom dialers should also implement ContextDialer.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (c Conn, err error)
}
