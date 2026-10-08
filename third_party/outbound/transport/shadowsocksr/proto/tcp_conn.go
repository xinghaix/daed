package proto

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/outbound/common/iout"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/shadowsocks_stream"
)

type Conn struct {
	netproxy.Conn
	Protocol            IProtocol
	underPostdecryptBuf *bytes.Buffer
	readLater           io.Reader

	writeBroken bool
	writeMu     sync.Mutex
	readMu      sync.Mutex
}

func NewConn(c netproxy.Conn, proto IProtocol) (*Conn, error) {
	switch c.(type) {
	case *shadowsocks_stream.TcpConn:
	default:
		return nil, fmt.Errorf("unsupported inner Conn")
	}
	return &Conn{
		Conn:                c,
		Protocol:            proto,
		underPostdecryptBuf: new(bytes.Buffer),
	}, nil
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	// Conn Read: obfs->ss->proto
	if c.readLater != nil {
		n, _ = c.readLater.Read(b)
		if n != 0 {
			return n, nil
		}
		c.readLater = nil
	}
	buf := pool.Get(2048)
	defer pool.Put(buf)
readAgain:
	n, err = c.Conn.Read(buf)
	if err != nil {
		return 0, err
	}
	if n == 0 && err == nil {
		goto readAgain
	}

	// append buf to c.underPostdecryptBuf
	c.underPostdecryptBuf.Write(buf[:n])
	postDecryptedData, length, err := c.Protocol.Decode(c.underPostdecryptBuf.Bytes())
	if err != nil {
		c.underPostdecryptBuf.Reset()
		return 0, err
	}
	if length == 0 {
		// Not enough to postDecrypt yet. Keep reading so callers never see
		// (0, nil), which many treat as EOF; the next iteration appends fresh
		// wire bytes to the accumulator before re-decoding.
		goto readAgain
	} else {
		c.underPostdecryptBuf.Next(length)
	}
	if len(postDecryptedData) == 0 {
		goto readAgain
	}

	n = copy(b, postDecryptedData)
	if n < len(postDecryptedData) {
		c.readLater = bytes.NewReader(postDecryptedData[n:])
	}
	return n, nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeBroken {
		return 0, net.ErrClosed
	}
	// Conn Write: obfs<-ss<-proto
	data, err := c.Protocol.Encode(b)
	if err != nil {
		c.writeBroken = true
		return 0, err
	}
	if _, err = iout.WriteFull(c.Conn, data); err != nil {
		c.writeBroken = true
		return 0, err
	}
	return len(b), nil
}

func (c *Conn) CloseWrite() error {
	return netproxy.ForwardCloseWrite(c.Conn)
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the wrapped conn. Embedding the conn interface
// promotes SetWriteDeadline but not this optional method, so without the
// forward a session-closing inner conn (TUIC, hysteria2) would be invisible to
// deadline-arming callers and they would arm a destructive timer believing it
// was an ordinary write deadline.
func (c *Conn) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(c.Conn)
}
