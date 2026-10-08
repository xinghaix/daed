// Thanks to Dreamacro/clash.

package mux

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
)

type SessionStatus = byte

const (
	SessionStatusNew       SessionStatus = 0x01
	SessionStatusKeep      SessionStatus = 0x02
	SessionStatusEnd       SessionStatus = 0x03
	SessionStatusKeepAlive SessionStatus = 0x04
)

const (
	OptionNone  = byte(0x00)
	OptionData  = byte(0x01)
	OptionError = byte(0x02)
)

type MuxOption struct {
	ID   [2]byte
	Port uint16
	Host string
	Type string
}

// Conn is an mux-compatible client for v2ray-plugin, not a complete implementation
type Conn struct {
	net.Conn
	buf    bytes.Buffer
	id     [2]byte
	length [2]byte
	status [2]byte
	otb    []byte
	remain int

	closeOnce sync.Once
	closeErr  error
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the wrapped conn. This type embeds net.Conn,
// so SetWriteDeadline is promoted while the optional declaration is not.
func (m *Conn) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(m.Conn)
}

func (m *Conn) Read(b []byte) (int, error) {
	if m.remain != 0 {
		length := m.remain
		if len(b) < m.remain {
			length = len(b)
		}

		n, err := m.Conn.Read(b[:length])
		if err != nil {
			return n, err
		}
		m.remain -= n
		return n, nil
	}

	for {
		_, err := io.ReadFull(m.Conn, m.length[:])
		if err != nil {
			return 0, err
		}
		length := binary.BigEndian.Uint16(m.length[:])
		if length > 512 {
			return 0, errors.New("invalid metalen")
		}

		_, err = io.ReadFull(m.Conn, m.id[:])
		if err != nil {
			return 0, err
		}

		_, err = io.ReadFull(m.Conn, m.status[:])
		if err != nil {
			return 0, err
		}

		opcode := m.status[0]
		if opcode == SessionStatusKeepAlive {
			continue
		}

		opts := m.status[1]

		if opts != OptionData {
			continue
		}

		_, err = io.ReadFull(m.Conn, m.length[:])
		if err != nil {
			return 0, err
		}
		dataLen := int(binary.BigEndian.Uint16(m.length[:]))
		m.remain = dataLen
		if dataLen > len(b) {
			dataLen = len(b)
		}

		n, err := m.Conn.Read(b[:dataLen])
		m.remain -= n
		return n, err
	}
}

func (m *Conn) Write(b []byte) (int, error) {
	if m.otb != nil {
		// create a sub connection
		if _, err := m.Conn.Write(m.otb); err != nil {
			return 0, err
		}
		m.otb = nil
	}
	m.buf.Reset()
	if len(b) > 0xFFFF {
		// The frame length field is uint16: silently truncating would
		// desync the peer's framing mid-stream.
		return 0, errors.New("mux: frame payload exceeds 65535 bytes")
	}
	_ = binary.Write(&m.buf, binary.BigEndian, uint16(4))
	m.buf.Write(m.id[:])
	m.buf.WriteByte(SessionStatusKeep)
	m.buf.WriteByte(OptionData)
	_ = binary.Write(&m.buf, binary.BigEndian, uint16(len(b)))
	m.buf.Write(b)

	return m.Conn.Write(m.buf.Bytes())
}

func (m *Conn) Close() error {
	// Defensive closes must be idempotent: a second Close would otherwise
	// write an END frame into a dead conn and surface net.ErrClosed.
	m.closeOnce.Do(func() {
		_, err := m.Conn.Write([]byte{0x0, 0x4, m.id[0], m.id[1], SessionStatusEnd, OptionNone})
		// The underlay must close even when the END frame could not be
		// delivered; returning early here leaked the raw connection.
		closeErr := m.Conn.Close()
		if err != nil {
			m.closeErr = err
		} else {
			m.closeErr = closeErr
		}
	})
	return m.closeErr
}

func NewConn(conn net.Conn, option MuxOption) *Conn {
	buf := &bytes.Buffer{}

	// fill empty length
	buf.Write([]byte{0x0, 0x0})
	buf.Write(option.ID[:])
	buf.WriteByte(SessionStatusNew)
	buf.WriteByte(OptionNone)

	// tcp
	netType := byte(0x1)
	if option.Type == "udp" {
		netType = byte(0x2)
	}
	buf.WriteByte(netType)

	// port
	_ = binary.Write(buf, binary.BigEndian, option.Port)

	// address
	ip := net.ParseIP(option.Host)
	if ip == nil {
		buf.WriteByte(0x2)
		buf.WriteString(option.Host)
	} else if ipv4 := ip.To4(); ipv4 != nil {
		buf.WriteByte(0x1)
		buf.Write(ipv4)
	} else {
		buf.WriteByte(0x3)
		buf.Write(ip.To16())
	}

	metadata := buf.Bytes()
	binary.BigEndian.PutUint16(metadata[:2], uint16(len(metadata)-2))

	return &Conn{
		Conn: conn,
		id:   option.ID,
		otb:  metadata,
	}
}
