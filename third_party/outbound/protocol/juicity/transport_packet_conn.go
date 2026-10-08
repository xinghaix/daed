package juicity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/olicesx/quic-go"
)

type TransportPacketConn struct {
	*quic.Transport
	proxyAddr   *net.UDPAddr
	tgt         netip.AddrPort
	key         *shadowsocks.Key
	firstIv     []byte
	writeMu     sync.Mutex
	writeBuf    []byte
	writeSubKey [32]byte
	readMu      sync.Mutex
	readBuf     []byte
	readSubKey  [32]byte

	lifeOnce   sync.Once
	lifeCtx    context.Context
	lifeCancel context.CancelFunc

	deadlineMu       sync.Mutex
	readDeadline     time.Time
	deadlineVersion  uint64
	activeReadCancel context.CancelCauseFunc
	activeReadTimer  *time.Timer
	activeReadGen    uint64

	closeOnce sync.Once
	closeErr  error
}

func (c *TransportPacketConn) ensureLifetime() {
	c.lifeOnce.Do(func() {
		c.lifeCtx, c.lifeCancel = context.WithCancel(context.Background())
	})
}

func (c *TransportPacketConn) expireActiveRead(gen, version uint64) {
	c.deadlineMu.Lock()
	if c.activeReadGen != gen || c.deadlineVersion != version || c.activeReadCancel == nil {
		c.deadlineMu.Unlock()
		return
	}
	cancel := c.activeReadCancel
	c.activeReadTimer = nil
	c.deadlineMu.Unlock()
	cancel(os.ErrDeadlineExceeded)
}

func (c *TransportPacketConn) armActiveReadTimerLocked(gen, version uint64) context.CancelCauseFunc {
	if c.activeReadTimer != nil {
		c.activeReadTimer.Stop()
		c.activeReadTimer = nil
	}
	if c.activeReadCancel == nil || c.readDeadline.IsZero() {
		return nil
	}
	delay := time.Until(c.readDeadline)
	if delay <= 0 {
		return c.activeReadCancel
	}
	c.activeReadTimer = time.AfterFunc(delay, func() {
		c.expireActiveRead(gen, version)
	})
	return nil
}

func (c *TransportPacketConn) setStoredReadDeadline(t time.Time) error {
	c.ensureLifetime()
	c.deadlineMu.Lock()
	if c.lifeCtx.Err() != nil {
		c.deadlineMu.Unlock()
		return net.ErrClosed
	}
	c.readDeadline = t
	c.deadlineVersion++
	cancel := c.armActiveReadTimerLocked(c.activeReadGen, c.deadlineVersion)
	c.deadlineMu.Unlock()
	if cancel != nil {
		cancel(os.ErrDeadlineExceeded)
	}
	return nil
}

func (c *TransportPacketConn) startReadContext() (context.Context, context.CancelCauseFunc, uint64) {
	c.ensureLifetime()
	c.deadlineMu.Lock()
	c.activeReadGen++
	gen := c.activeReadGen
	ctx, cancel := context.WithCancelCause(c.lifeCtx)
	c.activeReadCancel = cancel
	version := c.deadlineVersion
	expire := c.armActiveReadTimerLocked(gen, version)
	c.deadlineMu.Unlock()
	if expire != nil {
		expire(os.ErrDeadlineExceeded)
	}
	return ctx, cancel, gen
}

func (c *TransportPacketConn) finishReadContext(ctx context.Context, cancel context.CancelCauseFunc, gen uint64) error {
	c.deadlineMu.Lock()
	if c.activeReadGen == gen {
		if c.activeReadTimer != nil {
			c.activeReadTimer.Stop()
			c.activeReadTimer = nil
		}
		c.activeReadCancel = nil
	}
	c.deadlineMu.Unlock()
	cause := context.Cause(ctx)
	cancel(nil)
	return cause
}

// SetDeadline implements netproxy.Conn.
func (c *TransportPacketConn) SetDeadline(t time.Time) error {
	if err := c.setStoredReadDeadline(t); err != nil {
		return err
	}
	if c.Transport == nil || c.Conn == nil {
		return nil
	}
	return c.Conn.SetWriteDeadline(t)
}

// SetReadDeadline implements netproxy.Conn.
func (c *TransportPacketConn) SetReadDeadline(t time.Time) error {
	return c.setStoredReadDeadline(t)
}

// SetWriteDeadline implements netproxy.Conn.
func (c *TransportPacketConn) SetWriteDeadline(t time.Time) error {
	if c.Transport == nil || c.Conn == nil {
		return nil
	}
	return c.Conn.SetWriteDeadline(t)
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the QUIC transport's underlay conn, which is
// exactly where SetWriteDeadline lands. The plain stream PacketConn keeps
// its own write-abort quic-stream deadline semantics and deliberately does
// not forward anything.
func (c *TransportPacketConn) WriteDeadlineClosesSession() bool {
	if c.Transport == nil || c.Conn == nil {
		return false
	}
	return netproxy.WriteDeadlineClosesSession(c.Conn)
}

func (c *TransportPacketConn) borrowWriteBuffer(size int) []byte {
	if size <= maxReusablePacketWriteBufferSize {
		if cap(c.writeBuf) < size {
			c.writeBuf = make([]byte, size)
		}
		return c.writeBuf[:size]
	}
	return make([]byte, size)
}

func (c *TransportPacketConn) borrowReadBuffer(size int) []byte {
	if size <= maxReusablePacketWriteBufferSize {
		if cap(c.readBuf) < size {
			c.readBuf = make([]byte, size)
		}
		return c.readBuf[:size]
	}
	return make([]byte, size)
}

func (c *TransportPacketConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	saltLen := c.key.CipherConf.SaltLen
	var saltStorage [32]byte
	if saltLen > len(saltStorage) {
		return 0, fmt.Errorf("unsupported salt length: %d", saltLen)
	}
	salt := saltStorage[:saltLen]
	if c.firstIv != nil {
		if len(c.firstIv) < saltLen {
			return 0, fmt.Errorf("first IV is too short: got %d, need %d", len(c.firstIv), saltLen)
		}
		copy(salt, c.firstIv[:saltLen])
		c.firstIv = nil
	} else {
		salt[0] = 0
		salt[1] = 0
		_, _ = fastrand.Read(salt[2:])
	}
	toWrite := c.borrowWriteBuffer(saltLen + len(b) + c.key.CipherConf.TagLen)
	n, err := shadowsocks.EncryptUDPToWithScratch(
		toWrite,
		c.key,
		b,
		salt,
		ciphers.JuicityReusedInfo,
		c.writeSubKey[:],
	)
	if err != nil {
		return 0, err
	}
	toWrite = toWrite[:n]
	n, err = c.Transport.WriteTo(toWrite, c.proxyAddr)
	if err != nil {
		return 0, err
	}
	if n != len(toWrite) {
		return 0, io.ErrShortWrite
	}
	return len(b), nil
}

func (c *TransportPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return n, err
}

func (c *TransportPacketConn) ReadFrom(p []byte) (n int, addrPort netip.AddrPort, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	buf := c.borrowReadBuffer(len(p) + CipherConf.SaltLen + CipherConf.TagLen)
	ctx, cancel, gen := c.startReadContext()
	n, _, err = c.ReadNonQUICPacket(ctx, buf)
	cause := c.finishReadContext(ctx, cancel, gen)
	if err != nil {
		if c.lifeCtx.Err() != nil || errors.Is(cause, context.Canceled) {
			return 0, netip.AddrPort{}, net.ErrClosed
		}
		if errors.Is(cause, os.ErrDeadlineExceeded) {
			return 0, netip.AddrPort{}, os.ErrDeadlineExceeded
		}
		return 0, netip.AddrPort{}, err
	}
	n, err = shadowsocks.DecryptUDPWithScratch(
		p,
		c.key,
		buf[:n],
		ciphers.JuicityReusedInfo,
		c.readSubKey[:],
	)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return n, c.tgt, nil
}

func (c *TransportPacketConn) WriteTo(p []byte, addr string) (n int, err error) {
	return c.Write(p)
}

func (c *TransportPacketConn) Close() error {
	c.ensureLifetime()
	c.closeOnce.Do(func() {
		if c.lifeCancel != nil {
			c.lifeCancel()
		}
		var err error
		if c.Transport != nil {
			err = c.Transport.Close()
			if c.Transport.Conn != nil {
				if closeErr := c.Transport.Conn.Close(); err == nil {
					err = closeErr
				}
			}
		}
		c.writeMu.Lock()
		c.firstIv = nil
		c.writeBuf = nil
		clear(c.writeSubKey[:])
		c.writeMu.Unlock()
		c.readMu.Lock()
		c.readBuf = nil
		clear(c.readSubKey[:])
		c.readMu.Unlock()
		c.closeErr = err
	})
	return c.closeErr
}

// TransportDone implements netproxy.TransportLifecycle so dae can skip
// write-deadline arming on this QUIC underlay. Closing the conn cancels
// lifeCtx; the returned channel is that context's Done.
func (c *TransportPacketConn) TransportDone() <-chan struct{} {
	if c == nil {
		return nil
	}
	c.ensureLifetime()
	if c.lifeCtx == nil {
		return nil
	}
	return c.lifeCtx.Done()
}

var _ netproxy.TransportLifecycle = (*TransportPacketConn)(nil)
