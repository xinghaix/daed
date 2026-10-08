// from https://github.com/Dreamacro/clash/blob/master/component/simple-obfs/tls.go

package simpleobfs

import (
	"bytes"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/common/iout"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
)

const (
	chunkSize = 1 << 14 // 2 ** 14 == 16 * 1024
)

// TLSObfs is shadowsocks tls simple-obfs implementation
type TLSObfs struct {
	netproxy.Conn
	server        string
	remain        int
	firstRequest  bool
	firstResponse bool
	// writeFrame is a per-connection scratch holding the 5-byte record
	// header plus one chunk payload; allocating it per chunk (a fresh
	// bytes.Buffer growing to ~16.4KB) put a ~1:1 allocation rate on bulk
	// relay paths, which measurably doubles engine CPU per GB.
	writeFrame []byte
	// readDiscard/readSizeBuf are per-connection scratch for the record
	// framing on the receive side; the discard length varies (3 regular,
	// 105 first hello) but never exceeds 105.
	readDiscard [105]byte
	readSizeBuf [2]byte
	rMu         sync.Mutex
	wMu         sync.Mutex
}

func (to *TLSObfs) read(b []byte, discardN int) (int, error) {
	// discardN is 3 for regular records but 105 for the first server
	// hello, so the scratch is sized for the 105 maximum.
	discard := to.readDiscard[:discardN]
	if _, err := io.ReadFull(to.Conn, discard); err != nil {
		return 0, err
	}
	// A truncated size header must surface as an error: returning
	// (0, nil) here made relay loops spin forever on success-with-no-data.
	sizeBuf := to.readSizeBuf[:]
	if _, err := io.ReadFull(to.Conn, sizeBuf); err != nil {
		return 0, err
	}

	length := int(binary.BigEndian.Uint16(sizeBuf))
	if length == 0 {
		// A zero-length record makes no progress; returning (0, nil)
		// here would spin relay loops until the peer sends real data.
		// Skip it and read the next record instead: the hello discard
		// only applies to the very first record.
		return to.readNext(b)
	}
	if length > len(b) {
		// A single raw Read can return fewer bytes than the record holds, and
		// the leftover must be recorded even when that Read fails partway:
		// returning before setting remain desynchronizes the frame stream, so
		// every later Read would start mid-record.
		n, err := to.Conn.Read(b)
		to.remain = length - n
		if err != nil {
			return n, err
		}
		return n, nil
	}

	return io.ReadFull(to.Conn, b[:length])
}

// readNext reads a regular record after the first hello was consumed.
func (to *TLSObfs) readNext(b []byte) (int, error) {
	var hdr [5]byte // type + ver (discard) + uint16 size
	for {
		if _, err := io.ReadFull(to.Conn, hdr[:]); err != nil {
			return 0, err
		}
		length := int(binary.BigEndian.Uint16(hdr[3:]))
		if length == 0 {
			// Zero-length records make no progress; skipping them keeps
			// relay loops from spinning on a (0, nil) return.
			continue
		}
		if length > len(b) {
			n, err := to.Conn.Read(b)
			to.remain = length - n
			if err != nil {
				return n, err
			}
			return n, nil
		}
		return io.ReadFull(to.Conn, b[:length])
	}
}

func (to *TLSObfs) Read(b []byte) (int, error) {
	to.rMu.Lock()
	defer to.rMu.Unlock()
	if to.remain > 0 {
		length := to.remain
		if length > len(b) {
			length = len(b)
		}

		n, err := io.ReadFull(to.Conn, b[:length])
		to.remain -= n
		return n, err
	}

	if to.firstResponse {
		// type + ver + lensize + 91 = 96
		// type + ver + lensize + 1 = 6
		// type + ver = 3
		to.firstResponse = false
		return to.read(b, 105)
	}

	// type + ver = 3
	return to.read(b, 3)
}
func (to *TLSObfs) Write(b []byte) (int, error) {
	to.wMu.Lock()
	defer to.wMu.Unlock()
	// The return value is the count of bytes the caller may consider
	// delivered, so it must count whole chunks that already went out. The
	// previous version returned n from the *failing* chunk (often 0), which
	// discards the accounting for every chunk already written - a retry then
	// re-sends up to 16 KB that the peer has already accepted.
	written := 0
	length := len(b)
	for i := 0; i < length; i += chunkSize {
		end := i + chunkSize
		if end > length {
			end = length
		}

		n, err := to.write(b[i:end])
		written += n
		if err != nil {
			return written, err
		}
		if n != end-i {
			// A chunk that reports success must have consumed all of its
			// bytes; anything else is a short write and the remaining bytes
			// are not safe to account for.
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func (to *TLSObfs) write(b []byte) (int, error) {
	if to.firstRequest {
		helloMsg := makeClientHelloMsg(b, to.server)
		if _, err := iout.WriteFull(to.Conn, helloMsg); err != nil {
			return 0, err
		}
		to.firstRequest = false
		return len(b), nil
	}

	// Frame into the reusable scratch: 5-byte header + payload in one
	// WriteFull, replacing the per-chunk bytes.Buffer (which allocated a
	// fresh ~16.4KB buffer per 16KB chunk plus several small escapes).
	if cap(to.writeFrame) < 5+len(b) {
		to.writeFrame = make([]byte, 5+chunkSize)
	}
	frame := to.writeFrame[:5+len(b)]
	frame[0], frame[1], frame[2] = 0x17, 0x03, 0x03
	frame[3] = byte(uint16(len(b)) >> 8)
	frame[4] = byte(len(b))
	copy(frame[5:], b)
	if _, err := iout.WriteFull(to.Conn, frame); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (to *TLSObfs) CloseWrite() error {
	return netproxy.ForwardCloseWrite(to.Conn)
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the wrapped conn. Embedding netproxy.Conn
// promotes SetWriteDeadline but not this optional method, so without the
// forward a session-closing inner conn (TUIC, hysteria2) behind this wrapper
// would be invisible to deadline-arming callers and they would arm a
// destructive timer believing it was an ordinary deadline.
func (to *TLSObfs) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(to.Conn)
}

func NewTLSObfs(conn netproxy.Conn, server string) netproxy.Conn {
	return &TLSObfs{
		Conn:          conn,
		server:        server,
		firstRequest:  true,
		firstResponse: true,
	}
}

func makeClientHelloMsg(data []byte, server string) []byte {
	random := make([]byte, 28)
	sessionID := make([]byte, 32)
	_, _ = fastrand.Read(random)
	_, _ = fastrand.Read(sessionID)

	buf := &bytes.Buffer{}

	// handshake, TLS 1.0 version, length
	buf.WriteByte(22)
	buf.Write([]byte{0x03, 0x01})
	length := uint16(212 + len(data) + len(server))
	buf.WriteByte(byte(length >> 8))
	buf.WriteByte(byte(length & 0xff))

	// clientHello, length, TLS 1.2 version
	buf.WriteByte(1)
	buf.WriteByte(0)
	_ = binary.Write(buf, binary.BigEndian, uint16(208+len(data)+len(server)))
	buf.Write([]byte{0x03, 0x03})

	// random with timestamp, sid len, sid
	_ = binary.Write(buf, binary.BigEndian, uint32(time.Now().Unix()))
	buf.Write(random)
	buf.WriteByte(32)
	buf.Write(sessionID)

	// cipher suites
	buf.Write([]byte{0x00, 0x38})
	buf.Write([]byte{
		0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
		0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
		0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
		0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
	})

	// compression
	buf.Write([]byte{0x01, 0x00})

	// extension length
	_ = binary.Write(buf, binary.BigEndian, uint16(79+len(data)+len(server)))

	// session ticket
	buf.Write([]byte{0x00, 0x23})
	_ = binary.Write(buf, binary.BigEndian, uint16(len(data)))
	buf.Write(data)

	// server name
	buf.Write([]byte{0x00, 0x00})
	_ = binary.Write(buf, binary.BigEndian, uint16(len(server)+5))
	_ = binary.Write(buf, binary.BigEndian, uint16(len(server)+3))
	buf.WriteByte(0)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(server)))
	buf.Write([]byte(server))

	// ec_point
	buf.Write([]byte{0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02})

	// groups
	buf.Write([]byte{0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18})

	// signature
	buf.Write([]byte{
		0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05,
		0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01,
		0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
	})

	// encrypt then mac
	buf.Write([]byte{0x00, 0x16, 0x00, 0x00})

	// extended master secret
	buf.Write([]byte{0x00, 0x17, 0x00, 0x00})

	return buf.Bytes()
}
