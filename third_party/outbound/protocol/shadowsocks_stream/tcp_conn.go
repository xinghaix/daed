package shadowsocks_stream

import (
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common/iout"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
)

// TcpConn the struct that override the netproxy.Conn methods
type TcpConn struct {
	netproxy.Conn
	cipher *ciphers.StreamCipher

	init        bool
	writeBroken bool
	readMutex   sync.Mutex
	writeMutex  sync.Mutex
}

func (c *TcpConn) CloseWrite() error {
	return netproxy.ForwardCloseWrite(c.Conn)
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the wrapped conn. Embedding the conn interface
// promotes SetWriteDeadline but not this optional method, so without the
// forward a session-closing inner conn (TUIC, hysteria2) would be invisible to
// deadline-arming callers and they would arm a destructive timer believing it
// was an ordinary write deadline.
func (c *TcpConn) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(c.Conn)
}

func NewTcpConn(c netproxy.Conn, cipher *ciphers.StreamCipher) *TcpConn {
	return &TcpConn{
		Conn:   c,
		cipher: cipher,
	}
}

func (c *TcpConn) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	if !c.cipher.DecryptInited() {
		ivLen := c.cipher.InfoIVLen()
		buf := b
		if len(buf) <= ivLen {
			buf = pool.Get(ivLen + len(b))
			defer pool.Put(buf)
		}
		n, err = io.ReadAtLeast(c.Conn, buf, ivLen)
		if err != nil {
			return 0, fmt.Errorf("invalid ivLen:%v, actual length:%v: %w", ivLen, n, err)
		}
		//log.Println("n1", n)
		iv := buf[:ivLen]
		if err = c.cipher.InitDecrypt(iv); err != nil {
			return 0, err
		}

		if c.cipher.IV() == nil {
			c.cipher.SetIV(append([]byte(nil), iv...))
		}
		if n == ivLen {
			// The first read may stop exactly at the IV boundary. Returning
			// (0, nil) here violates the io.Reader contract for non-empty
			// buffers (many callers treat it as EOF), so keep reading until
			// at least one payload byte arrives.
			m, rerr := io.ReadAtLeast(c.Conn, buf[n:], 1)
			n += m
			if rerr != nil {
				return 0, rerr
			}
		}
		n = copy(b, buf[ivLen:n])
		c.cipher.Decrypt(b[:n], b[:n])
		//log.Println("n2", n)
	} else {
		n, err = c.Conn.Read(b)
		if err != nil {
			return n, err
		}
		c.cipher.Decrypt(b[:n], b[:n])
	}
	return n, nil
}

func (c *TcpConn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.writeBroken {
		return 0, net.ErrClosed
	}
	lenToWrite := len(b)
	ivLen := 0
	firstWrite := !c.init
	if !c.cipher.EncryptInited() {
		_, err = c.cipher.InitEncrypt()
		if err != nil {
			return 0, err
		}
	}
	if firstWrite {
		iv := c.cipher.IV()
		buf := pool.Get(len(b) + len(iv))
		defer pool.Put(buf)
		ivLen = len(iv)
		copy(buf, iv)
		copy(buf[ivLen:], b)
		b = buf

		// For SSR obfs. The obfs conn is not necessarily c.Conn:
		// shadowsocks_stream installs a netproxy.BufferedReaderConn between this
		// TcpConn and the dialed underlay, and any wrapper hides the obfs hooks
		// from a single-level type assertion. The ok-form assertion then failed
		// silently, the obfs cipher stayed nil, and the first write returned
		// "outer conn did not init cipher of Obfs" - killing every TCP flow of
		// that node while UDP (which never takes this wrapper) stayed up.
		if hook := netproxy.UnwrapIntrinsicConn(c.Conn); hook != nil {
			if innerConn, ok := hook.(interface {
				SetCipher(cipher *ciphers.StreamCipher)
			}); ok {
				innerConn.SetCipher(c.cipher)
			}
			if innerConn, ok := hook.(interface {
				SetAddrLen(addrLen int)
			}); ok {
				innerConn.SetAddrLen(lenToWrite)
			}
		}
	} else {
		buf := pool.Get(len(b))
		defer pool.Put(buf)
		copy(buf, b)
		b = buf
	}
	c.cipher.Encrypt(b[ivLen:], b[ivLen:])
	if _, err = iout.WriteFull(c.Conn, b); err != nil {
		c.writeBroken = true
		return 0, err
	}
	if firstWrite {
		c.init = true
	}
	return lenToWrite, nil
}

func (c *TcpConn) Cipher() *ciphers.StreamCipher {
	return c.cipher
}
