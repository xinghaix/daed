package shadowsocks_stream_test

// True end-to-end coverage for the shadowsocks stream-cipher client stack
// (protocol/shadowsocks_stream): an in-test shadowsocks server that is an
// independent implementation of the wire format, fronting real loopback echo
// targets, reached through the same dialer chains dae builds.
//
// Wire format implemented here (own framing; only key/stream construction is
// taken from the repo's ciphers package):
//
//	TCP client -> server: [IV][stream-cipher keystream over SOCKS addr + payload...]
//	TCP server -> client: [IV][stream-cipher keystream over payload...]
//	UDP datagram:         [IV][keystream over SOCKS addr + payload] per packet
//	                      (fresh IV per datagram, no chunking)
//
// The SOCKS address is ATYP(1=ipv4,3=domain,4=ipv6) + addr + u16 BE port; the
// parser below is written from the wire spec, not shared with the client.
//
// Cipher split note: dialer/shadowsocks routes the legacy stream methods
// (aes-256-cfb and friends) to protocol "shadowsocks_stream", while the AEAD
// methods go to protocol "shadowsocks" (covered by the classic e2e suite in
// protocol/shadowsocks/e2e_test.go). The simple-obfs and shadowsocksr obfs
// transports compose on top of this stack exactly as dialer/shadowsocks
// (plugin=simple-obfs) and dialer/shadowsocksr build them.

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
	ssrobfs "github.com/daeuniverse/outbound/transport/shadowsocksr/obfs"
	"github.com/daeuniverse/outbound/transport/simpleobfs"
)

// ---- shared helpers (the per-protocol e2e convention) ----

// loopbackEchoTarget starts a TCP echo server; everything received is sent
// back, and a peer half-close (FIN) is propagated back as EOF after the
// remaining output is flushed.
func loopbackEchoTarget(t *testing.T) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr()
}

// startUDPEchoTarget echoes datagrams back to their sender.
func startUDPEchoTarget(t *testing.T) net.Addr {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr()
}

// deadlineCtx bounds every dial in the e2e so a hung protocol layer fails the
// test instead of hanging it.
func deadlineCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// readFullOrDead wraps io.ReadFull with the test deadline.
func readFullOrDead(t *testing.T, c net.Conn, buf []byte) error {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	_, err := io.ReadFull(c, buf)
	return err
}

// verifyRelayRoundTrip writes a large deterministic payload through c while
// concurrently reading it back and verifying every byte. Large enough to
// cross cipher/buffer/record boundaries.
func verifyRelayRoundTrip(t *testing.T, c netproxy.Conn, total int) {
	t.Helper()
	payload := make([]byte, 64<<10)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	sent := 0
	go func() {
		for sent < total {
			n := len(payload)
			if total-sent < n {
				n = total - sent
			}
			if _, err := c.Write(payload[:n]); err != nil {
				return
			}
			sent += n
		}
	}()
	got := 0
	buf := make([]byte, 32<<10)
	if err := c.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	for got < total {
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read back at %d/%d: %v", got, total, err)
		}
		for i := 0; i < n; i++ {
			if want := byte(((got + i) % len(payload)) * 7); buf[i] != want {
				t.Fatalf("payload mismatch at %d: got %#x want %#x", got+i, buf[i], want)
			}
		}
		got += n
	}
}

// assertHalfCloseToEOF checks the CloseWrite capability is present on the
// protocol conn and that the FIN propagates through the obfs/protocol stack
// and the in-test server to the echo target and back as EOF. Losing
// CloseWrite to a wrapper must fail here, not skip the check: the same
// wrapper-peeling path is what hands the SSR obfs conn its cipher hooks.
func assertHalfCloseToEOF(t *testing.T, c netproxy.Conn) {
	t.Helper()
	closeWrite, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("shadowsocks_stream conn %T lost the CloseWrite capability", c)
	}
	if err := closeWrite.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1024)
	if n, err := c.Read(buf); n != 0 || err == nil {
		t.Fatalf("read after half-close = %d, %v, want 0, EOF", n, err)
	}
}

// ---- in-test shadowsocks stream server (independent wire-format implementation) ----

// streamDecryptReader pulls raw ciphertext from conn and pushes it through
// the stateful stream cipher, yielding the plaintext stream. Successive
// decrypt calls on one cipher state are logically one call, so this is
// byte-exact with a single-shot decryption.
type streamDecryptReader struct {
	t    *testing.T
	conn net.Conn
	dec  func(dst, src []byte)
}

func (r *streamDecryptReader) Read(b []byte) (int, error) {
	n, err := r.conn.Read(b)
	if n > 0 {
		r.dec(b[:n], b[:n])
	}
	return n, err
}

// streamEncryptWriter encrypts plaintext with a fresh IV on the first write
// (the IV is sent ahead of the first ciphertext) and continues the same
// keystream for every later write.
type streamEncryptWriter struct {
	t       *testing.T
	conn    net.Conn
	cipher  *ciphers.StreamCipher
	enc     interface{ XORKeyStream(dst, src []byte) }
	started bool
}

func (w *streamEncryptWriter) Write(b []byte) (int, error) {
	if !w.started {
		iv := make([]byte, w.cipher.InfoIVLen())
		enc, err := w.cipher.NewEncryptorInto(iv)
		if err != nil {
			return 0, err
		}
		w.enc = enc
		buf := make([]byte, len(iv)+len(b))
		copy(buf, iv)
		copy(buf[len(iv):], b)
		enc.XORKeyStream(buf[len(iv):], buf[len(iv):])
		if err := w.conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return 0, err
		}
		if _, err := w.conn.Write(buf); err != nil {
			return 0, err
		}
		w.started = true
		return len(b), nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	w.enc.XORKeyStream(out, out)
	if err := w.conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return 0, err
	}
	_, err := w.conn.Write(out)
	return len(b), err
}

// parseSocksStreamAddress decodes ATYP+ADDR+PORT from the start of b (the
// shadowsocks stream wire address). Returns host:port and bytes consumed.
func parseSocksStreamAddress(b []byte) (string, int, error) {
	if len(b) < 1 {
		return "", 0, io.ErrUnexpectedEOF
	}
	switch b[0] {
	case socks.ATypIP4:
		if len(b) < 1+net.IPv4len+2 {
			return "", 0, io.ErrUnexpectedEOF
		}
		return net.IP(b[1:1+net.IPv4len]).String() + ":" +
			strconv.Itoa(int(binary.BigEndian.Uint16(b[1+net.IPv4len:]))), 1 + net.IPv4len + 2, nil
	case socks.ATypIP6:
		if len(b) < 1+net.IPv6len+2 {
			return "", 0, io.ErrUnexpectedEOF
		}
		return net.IP(b[1:1+net.IPv6len]).String() + ":" +
			strconv.Itoa(int(binary.BigEndian.Uint16(b[1+net.IPv6len:]))), 1 + net.IPv6len + 2, nil
	case socks.ATypDomain:
		if len(b) < 2 {
			return "", 0, io.ErrUnexpectedEOF
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return "", 0, io.ErrUnexpectedEOF
		}
		return string(b[2:2+l]) + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(b[2+l:]))), 2 + l + 2, nil
	default:
		return "", 0, io.ErrUnexpectedEOF
	}
}

// serveSSStreamConn handles one accepted connection of the in-test server:
// it reads the IV, decrypts the target address from the head of the
// plaintext, relays to the real target with half-close propagation, and
// answers with its own fresh IV. downstream may be a disguise-wrapped conn
// (obfs tests); this handler only speaks the shadowsocks stream format.
func serveSSStreamConn(t *testing.T, downstream net.Conn, method, password string) {
	t.Helper()
	defer downstream.Close()
	sc, err := ciphers.NewStreamCipher(method, password)
	if err != nil {
		t.Errorf("in-test server: %v", err)
		return
	}
	iv := make([]byte, sc.InfoIVLen())
	if err := readFullOrDead(t, downstream, iv); err != nil {
		return
	}
	if err := sc.InitDecrypt(iv); err != nil {
		return
	}
	reader := &streamDecryptReader{t: t, conn: downstream, dec: sc.Decrypt}

	// The plaintext stream starts with the target address.
	addrHead := make([]byte, 1+1+255+2)
	n, err := io.ReadFull(reader, addrHead[:1])
	if err != nil {
		return
	}
	switch addrHead[0] {
	case socks.ATypIP4:
		n, err = io.ReadFull(reader, addrHead[1:1+net.IPv4len+2])
	case socks.ATypIP6:
		n, err = io.ReadFull(reader, addrHead[1:1+net.IPv6len+2])
	case socks.ATypDomain:
		n, err = io.ReadFull(reader, addrHead[1:2])
		if err == nil {
			n, err = io.ReadFull(reader, addrHead[2:2+int(addrHead[1])+2])
		}
	default:
		return
	}
	if err != nil {
		return
	}
	addr, _, err := parseSocksStreamAddress(addrHead[:1+n])
	if err != nil {
		return
	}

	target, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return
	}
	defer target.Close()
	go func() {
		_, _ = io.Copy(target, reader)
		if tcp, ok := target.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	writer := &streamEncryptWriter{t: t, conn: downstream, cipher: sc}
	_, _ = io.Copy(writer, target)
}

// startSSStreamServer runs the in-test shadowsocks stream server on a plain
// loopback TCP listener.
func startSSStreamServer(t *testing.T, method, password string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("shadowsocks stream listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSSStreamConn(t, c, method, password)
		}
	}()
	return ln.Addr().String()
}

// ---- in-test obfs servers (disguise formats, own implementations) ----

// disguiseHeadFunc renders the disguise bytes that must precede the first
// server->client payload (an HTTP response header, a fake TLS hello, ...).
type disguiseHeadFunc func() []byte

// disguiseConn sits between the disguise layer and the inner shadowsocks
// stream handler. Read yields the unwrapped client stream: the disguise
// payload recovered from the handshake (head) followed by the raw stream
// (or, for TLS record disguise, the client's records decoded into a plain
// stream). Write emits the disguise head once and then the raw stream (or,
// for TLS record disguise, the stream re-framed into records).
type disguiseConn struct {
	net.Conn
	head       []byte                              // recovered handshake payload (client -> server)
	respHead   disguiseHeadFunc                    // disguise bytes before the first response write
	writeFrame func([]byte) []byte                 // optional response re-framing per write
	readDecode func(net.Conn, []byte) (int, error) // optional receive de-framing
	readRemain []byte                              // leftover of a decoded record larger than b
	headSent   bool
}

func (c *disguiseConn) Read(b []byte) (int, error) {
	if len(c.head) > 0 {
		n := copy(b, c.head)
		c.head = c.head[n:]
		return n, nil
	}
	if len(c.readRemain) > 0 {
		n := copy(b, c.readRemain)
		c.readRemain = c.readRemain[n:]
		return n, nil
	}
	if c.readDecode != nil {
		return c.readDecode(c.Conn, b)
	}
	return c.Conn.Read(b)
}

// decodeObfsTLSRecord turns one client TLS-obfs record
// ([0x17][ver 2][len 2][payload]) into plain stream bytes.
func (c *disguiseConn) decodeObfsTLSRecord(conn net.Conn, b []byte) (int, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, err
	}
	length := int(binary.BigEndian.Uint16(hdr[3:5]))
	if length == 0 {
		// Zero-length records make no progress; skip them.
		return c.decodeObfsTLSRecord(conn, b)
	}
	if length <= len(b) {
		return io.ReadFull(conn, b[:length])
	}
	// Record larger than the caller's buffer: stage the remainder so the
	// stream stays byte-exact for the next Read.
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, err
	}
	n := copy(b, buf)
	c.readRemain = buf[n:]
	return n, nil
}

func (c *disguiseConn) Write(b []byte) (int, error) {
	if !c.headSent {
		c.headSent = true
		out := b
		if c.writeFrame != nil {
			out = c.writeFrame(b)
		}
		buf := append(append([]byte(nil), c.respHead()...), out...)
		if err := c.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return 0, err
		}
		if _, err := c.Conn.Write(buf); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	if c.writeFrame != nil {
		b = c.writeFrame(b)
	}
	return c.Conn.Write(b)
}

// readUntilDoubleCRLF accumulates from r until the header terminator is seen
// (the header may straddle TCP segments) and returns head plus the leftover.
func readUntilDoubleCRLF(t *testing.T, r io.Reader, limit int) ([]byte, []byte, error) {
	t.Helper()
	var acc []byte
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			acc = append(acc, buf[:n]...)
			if idx := bytes.Index(acc, []byte("\r\n\r\n")); idx >= 0 {
				return acc[:idx+4], append([]byte(nil), acc[idx+4:]...), nil
			}
			if len(acc) > limit {
				return nil, nil, fmt.Errorf("disguise header exceeds %d bytes", limit)
			}
		}
		if err != nil {
			return nil, nil, err
		}
	}
}

// startSimpleObfsHTTPServer runs an in-test simple-obfs http server: the
// client's first write is a full HTTP GET whose body carries the start of the
// shadowsocks stream; the server answers with a fixed 200 header and then
// relays raw. inner is the shadowsocks stream handler.
func startSimpleObfsHTTPServer(t *testing.T, method, password string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("simpleobfs http listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				head, rest, err := readUntilDoubleCRLF(t, c, 64<<10)
				if err != nil {
					return
				}
				// The request body carries the first shadowsocks write.
				cl := 0
				for _, line := range strings.Split(string(head), "\r\n") {
					if v, ok := strings.CutPrefix(strings.ToLower(line), "content-length:"); ok {
						cl, _ = strconv.Atoi(strings.TrimSpace(v))
					}
				}
				body := make([]byte, cl)
				if len(rest) >= cl {
					copy(body, rest[:cl])
					rest = rest[cl:]
				} else {
					copy(body, rest)
					if _, err := io.ReadFull(c, body[len(rest):]); err != nil {
						return
					}
					rest = nil
				}
				inner := &disguiseConn{
					Conn: c,
					head: append(append([]byte(nil), body...), rest...),
					respHead: func() []byte {
						return []byte("HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n")
					},
				}
				serveSSStreamConn(t, inner, method, password)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// obfsTLSClientHelloTicket extracts the session-ticket extension payload
// from the simple-obfs fake ClientHello. The record layout it walks:
//
//	[22][ver 2][recLen 2] handshake: [1][0][bodyLen 2][ver 2]
//	[time 4][random 28][sidLen 1][sid][suiteLen 2][suites]
//	[compCount 1][comp 1][extLen 2] then extensions: [type 2][len 2][data]
//
// The first shadowsocks write is carried in the session-ticket (0x0023)
// extension data.
func obfsTLSClientHelloTicket(t *testing.T, c net.Conn) ([]byte, error) {
	t.Helper()
	var hdr [5]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 22 {
		return nil, fmt.Errorf("not a handshake record: %#x", hdr[0])
	}
	hello := make([]byte, int(binary.BigEndian.Uint16(hdr[3:5])))
	if _, err := io.ReadFull(c, hello); err != nil {
		return nil, err
	}
	p := 0
	p += 4 // handshake type + length (fake 2-byte form)
	p += 2 // client version
	p += 4 + 28
	if len(hello) < p+1 {
		return nil, io.ErrUnexpectedEOF
	}
	p += 1 + int(hello[p]) // session id
	if len(hello) < p+2 {
		return nil, io.ErrUnexpectedEOF
	}
	p += 2 + int(binary.BigEndian.Uint16(hello[p:])) // cipher suites
	if len(hello) < p+2 {
		return nil, io.ErrUnexpectedEOF
	}
	p += 2 // compression methods
	if len(hello) < p+2 {
		return nil, io.ErrUnexpectedEOF
	}
	extEnd := p + 2 + int(binary.BigEndian.Uint16(hello[p:]))
	p += 2
	for p+4 <= extEnd && p+4 <= len(hello) {
		typ := binary.BigEndian.Uint16(hello[p:])
		l := int(binary.BigEndian.Uint16(hello[p+2:]))
		if p+4+l > len(hello) {
			return nil, io.ErrUnexpectedEOF
		}
		if typ == 0x0023 {
			return append([]byte(nil), hello[p+4:p+4+l]...), nil
		}
		p += 4 + l
	}
	return nil, fmt.Errorf("session ticket extension not found")
}

// obfsTLSRecord frames one server->client application-data record.
func obfsTLSRecord(payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0], out[1], out[2] = 0x17, 0x03, 0x03
	binary.BigEndian.PutUint16(out[3:], uint16(len(payload)))
	copy(out[5:], payload)
	return out
}

// startSimpleObfsTLSServer runs an in-test simple-obfs tls server: the
// client's first write is a fake TLS ClientHello carrying the start of the
// shadowsocks stream in its session-ticket extension; the server answers
// with a fixed 105-byte hello (as the client's first-response path expects)
// and then re-frames every response write into TLS-shaped records.
func startSimpleObfsTLSServer(t *testing.T, method, password string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("simpleobfs tls listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				ticket, err := obfsTLSClientHelloTicket(t, c)
				if err != nil {
					return
				}
				// The fixed hello the client discards on its first read. The
				// client's first-response path swallows exactly 105 bytes:
				// a ServerHello record (5-byte header + 91-byte payload),
				// a ChangeCipherSpec record (6 bytes), and the 3 type/ver
				// bytes of the first application-data record that follows.
				hello := make([]byte, 102)
				hello[0], hello[1], hello[2] = 0x16, 0x03, 0x03
				binary.BigEndian.PutUint16(hello[3:], 91)
				hello[5] = 2 // server hello handshake type
				hello[96], hello[97], hello[98] = 0x14, 0x03, 0x03
				hello[99], hello[100] = 0x00, 0x01 // CCS length = 1
				hello[101] = 0x01                  // CCS payload
				inner := &disguiseConn{
					Conn:     c,
					head:     ticket,
					respHead: func() []byte { return hello },
					writeFrame: func(b []byte) []byte {
						// Frame responses into <=16KiB records like the real
						// obfs endpoint.
						var out []byte
						for len(b) > 0 {
							n := len(b)
							if n > 1<<14 {
								n = 1 << 14
							}
							out = append(out, obfsTLSRecord(b[:n])...)
							b = b[n:]
						}
						return out
					},
				}
				inner.readDecode = inner.decodeObfsTLSRecord
				serveSSStreamConn(t, inner, method, password)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startSSRObfsHTTPSimpleServer runs an in-test shadowsocksr http_simple obfs
// server: the client's first write is an HTTP GET whose path percent-encodes
// the start of the shadowsocks stream; the server answers with a 200 header
// and then relays raw.
func startSSRObfsHTTPSimpleServer(t *testing.T, method, password string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ssr obfs listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				head, rest, err := readUntilDoubleCRLF(t, c, 64<<10)
				if err != nil {
					return
				}
				// Recover the percent-encoded stream head from the request
				// line: "GET /<maybe a plain path>%XX%XX... HTTP/1.1".
				// The SSR request-path fragments contain no '%', so every
				// %XX triplet decodes in order.
				line := strings.SplitN(string(head), "\r\n", 2)[0]
				path := strings.TrimSuffix(strings.TrimPrefix(line, "GET /"), " HTTP/1.1")
				var prefix []byte
				for i := 0; i < len(path); {
					if path[i] == '%' && i+2 < len(path) {
						v, err := strconv.ParseUint(path[i+1:i+3], 16, 8)
						if err != nil {
							return
						}
						prefix = append(prefix, byte(v))
						i += 3
					} else {
						i++
					}
				}
				inner := &disguiseConn{
					Conn: c,
					head: append(append([]byte(nil), prefix...), rest...),
					respHead: func() []byte {
						return []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n")
					},
				}
				serveSSStreamConn(t, inner, method, password)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// ---- client dialer chains (exactly the way dae builds them) ----

// newSSStreamClientDialer builds direct -> shadowsocks_stream, the chain
// dialer/shadowsocks uses for the legacy stream ciphers without a plugin.
func newSSStreamClientDialer(t *testing.T, proxyAddr, method, password string) netproxy.Dialer {
	t.Helper()
	direct, _ := dialer.NewDirectDialer(&dialer.ExtraOption{}, false)
	d, err := protocol.NewDialer("shadowsocks_stream", direct, protocol.Header{
		IsClient:     true,
		ProxyAddress: proxyAddr,
		Cipher:       method,
		Password:     password,
	})
	if err != nil {
		t.Fatalf("shadowsocks_stream dialer: %v", err)
	}
	return d
}

// newSSStreamSimpleObfsDialer builds direct -> simpleobfs -> shadowsocks_stream,
// the chain dialer/shadowsocks uses for plugin=simple-obfs with a stream
// cipher (obfs "http" or "tls").
func newSSStreamSimpleObfsDialer(t *testing.T, proxyAddr, method, password, obfsMode string) netproxy.Dialer {
	t.Helper()
	direct, _ := dialer.NewDirectDialer(&dialer.ExtraOption{}, false)
	link := fmt.Sprintf("simple-obfs://%s?obfs=%s&host=127.0.0.1&uri=/", proxyAddr, obfsMode)
	obfsDialer, _, err := simpleobfs.NewSimpleObfs(&dialer.ExtraOption{}, direct, link)
	if err != nil {
		t.Fatalf("simpleobfs dialer: %v", err)
	}
	d, err := protocol.NewDialer("shadowsocks_stream", obfsDialer, protocol.Header{
		IsClient:     true,
		ProxyAddress: proxyAddr,
		Cipher:       method,
		Password:     password,
	})
	if err != nil {
		t.Fatalf("shadowsocks_stream over simpleobfs: %v", err)
	}
	return d
}

// newSSStreamSSRObfsDialer builds direct -> ssr obfs -> shadowsocks_stream,
// the chain dialer/shadowsocksr builds for obfs=http_simple.
func newSSStreamSSRObfsDialer(t *testing.T, proxyAddr, method, password string) netproxy.Dialer {
	t.Helper()
	direct, _ := dialer.NewDirectDialer(&dialer.ExtraOption{}, false)
	host, portStr, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		t.Fatalf("proxy addr: %v", err)
	}
	port, _ := strconv.Atoi(portStr)
	obfsDialer, err := ssrobfs.NewDialer(direct, &ssrobfs.ObfsParam{
		ObfsHost:  host,
		ObfsPort:  uint16(port),
		Obfs:      "http_simple",
		ObfsParam: "",
	})
	if err != nil {
		t.Fatalf("ssr obfs dialer: %v", err)
	}
	d, err := protocol.NewDialer("shadowsocks_stream", obfsDialer, protocol.Header{
		IsClient:     true,
		ProxyAddress: proxyAddr,
		Cipher:       method,
		Password:     password,
	})
	if err != nil {
		t.Fatalf("shadowsocks_stream over ssr obfs: %v", err)
	}
	return d
}

// ---- the e2e tests ----

// TestE2ESSStreamTCPRelay pushes 4MiB through client -> shadowsocks stream
// server -> echo target -> back on a real loopback socket with the classic
// stream cipher path (aes-256-cfb), then half-closes and expects EOF.
func TestE2ESSStreamTCPRelay(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startSSStreamServer(t, "aes-256-cfb", "ss-password")
	d := newSSStreamClientDialer(t, proxyAddr, "aes-256-cfb", "ss-password")

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	verifyRelayRoundTrip(t, c, 4<<20)
	assertHalfCloseToEOF(t, c)
}

// TestE2ESSStreamUDPRelay exercises the stream-cipher UDP relay: several
// datagrams to two different echo targets, with integrity and source address
// checks on every reply. Wire: [IV][SOCKS addr][payload] per datagram.
func TestE2ESSStreamUDPRelay(t *testing.T) {
	targetA := startUDPEchoTarget(t)
	targetB := startUDPEchoTarget(t)
	udpLn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp server listen: %v", err)
	}
	t.Cleanup(func() { _ = udpLn.Close() })
	go serveSSStreamUDP(t, udpLn, "aes-256-cfb", "ss-password")
	proxyAddr := udpLn.LocalAddr().String()

	d := newSSStreamClientDialer(t, proxyAddr, "aes-256-cfb", "ss-password")
	ctx := deadlineCtx(t)
	pc, err := d.DialContext(ctx, "udp", targetA.String())
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer pc.Close()
	packetConn, ok := pc.(netproxy.PacketConn)
	if !ok {
		t.Fatalf("DialContext(udp) returned %T, want a PacketConn", pc)
	}

	targets := []net.Addr{targetA, targetB}
	for i := 0; i < 16; i++ {
		target := targets[i%2]
		payload := make([]byte, 200+i*31)
		for j := range payload {
			payload[j] = byte(i + j)
		}
		if _, err := packetConn.WriteTo(payload, target.String()); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
		buf := make([]byte, 65535)
		if err := pc.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		n, from, err := packetConn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom: %v", err)
		}
		if n != len(payload) || !bytes.Equal(buf[:n], payload) {
			t.Fatalf("datagram %d mismatch: n=%d", i, n)
		}
		if from.String() != target.String() {
			t.Fatalf("datagram %d source = %v, want %v", i, from, target.String())
		}
	}
}

// socksAddressBytes renders host:port as the SOCKS wire address (own encoder
// used only to build the in-test server's reply addresses).
func socksAddressBytes(host string, port int) []byte {
	ip := net.ParseIP(host)
	var out []byte
	if ip4 := ip.To4(); ip4 != nil {
		out = append([]byte{socks.ATypIP4}, ip4...)
	} else {
		out = append([]byte{socks.ATypIP6}, ip.To16()...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	return append(out, portBytes[:]...)
}

// serveSSStreamUDP is the UDP half of the in-test stream server: it decodes
// [IV][SOCKS addr][payload] per datagram (own framing), forwards the payload
// to the addressed target and answers with [fresh IV][src addr][payload].
func serveSSStreamUDP(t *testing.T, pc net.PacketConn, method, password string) {
	t.Helper()
	sc, err := ciphers.NewStreamCipher(method, password)
	if err != nil {
		t.Errorf("in-test udp server: %v", err)
		return
	}
	buf := make([]byte, 65535)
	for {
		n, cli, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < sc.InfoIVLen() {
			continue
		}
		dec, err := sc.NewDecryptor(buf[:sc.InfoIVLen()])
		if err != nil {
			return
		}
		body := buf[sc.InfoIVLen():n]
		dec.XORKeyStream(body, body)
		addr, _, err := parseSocksStreamAddress(body)
		if err != nil {
			continue
		}
		addrLen := socksAddrWireLen(body)
		payload := body[addrLen:]
		target, err := net.Dial("udp", addr)
		if err != nil {
			continue
		}
		if _, err := target.Write(payload); err != nil {
			target.Close()
			continue
		}
		_ = target.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp := make([]byte, 65535)
		m, err := target.Read(resp)
		if err != nil {
			target.Close()
			continue
		}
		src := target.RemoteAddr().(*net.UDPAddr)
		target.Close()
		plain := append(socksAddressBytes(src.IP.String(), src.Port), resp[:m]...)

		out := make([]byte, sc.InfoIVLen()+len(plain))
		enc, err := sc.NewEncryptorInto(out)
		if err != nil {
			return
		}
		copy(out[sc.InfoIVLen():], plain)
		enc.XORKeyStream(out[sc.InfoIVLen():], out[sc.InfoIVLen():])
		if _, err := pc.WriteTo(out, cli); err != nil {
			return
		}
	}
}

// socksAddrWireLen returns the wire length of the SOCKS address at the start
// of b (0 if the address type is unknown).
func socksAddrWireLen(b []byte) int {
	if len(b) < 1 {
		return 0
	}
	switch b[0] {
	case socks.ATypIP4:
		return 1 + net.IPv4len + 2
	case socks.ATypIP6:
		return 1 + net.IPv6len + 2
	case socks.ATypDomain:
		if len(b) < 2 {
			return 0
		}
		return 2 + int(b[1]) + 2
	default:
		return 0
	}
}

// TestE2ESSStreamWrongPasswordIsAnErrorNotAPanic checks the auth-failure
// path: the server cannot decrypt the address head, drops the session, and
// the client must surface an error without panicking or hanging.
func TestE2ESSStreamWrongPasswordIsAnErrorNotAPanic(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startSSStreamServer(t, "aes-256-cfb", "correct-horse")
	d := newSSStreamClientDialer(t, proxyAddr, "aes-256-cfb", "wrong-horse")

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 128)
	_, _ = c.Write([]byte("hello"))
	for i := 0; i < 10; i++ {
		if _, err := c.Read(buf); err != nil {
			return // an error surfaced: pass
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("server closed the session but the client never surfaced an error")
}

// TestE2ESSStreamOverSimpleObfs runs the full 4MiB relay and half-close with
// the client wrapped in transport/simpleobfs (http and tls modes), talking to
// an in-test obfs server that implements the disguise format. This is the
// composition dialer/shadowsocks builds for plugin=simple-obfs.
func TestE2ESSStreamOverSimpleObfs(t *testing.T) {
	for _, mode := range []string{"http", "tls"} {
		t.Run(mode, func(t *testing.T) {
			echoAddr := loopbackEchoTarget(t)
			var proxyAddr string
			switch mode {
			case "http":
				proxyAddr = startSimpleObfsHTTPServer(t, "aes-256-cfb", "ss-password")
			case "tls":
				proxyAddr = startSimpleObfsTLSServer(t, "aes-256-cfb", "ss-password")
			}
			d := newSSStreamSimpleObfsDialer(t, proxyAddr, "aes-256-cfb", "ss-password", mode)

			ctx := deadlineCtx(t)
			c, err := d.DialContext(ctx, "tcp", echoAddr.String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer c.Close()

			verifyRelayRoundTrip(t, c, 4<<20)
			assertHalfCloseToEOF(t, c)
		})
	}
}

// TestE2ESSStreamOverSSRObfsHTTPSimple is the end-to-end guard for the obfs
// hook-resolution regression: shadowsocks_stream hands its stream cipher to
// the SSR obfs conn through duck-typed SetCipher/SetAddrLen hooks, and the
// read-buffering wrapper between them hides those hooks from a single-level
// type assertion. When the hooks fail to resolve, the obfs layer's first
// encode fails ("outer conn did not init cipher of Obfs") and this dial
// never relays a byte. The chain is the one dialer/shadowsocksr builds.
func TestE2ESSStreamOverSSRObfsHTTPSimple(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startSSRObfsHTTPSimpleServer(t, "aes-256-cfb", "ss-password")
	d := newSSStreamSSRObfsDialer(t, proxyAddr, "aes-256-cfb", "ss-password")

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	verifyRelayRoundTrip(t, c, 4<<20)
	assertHalfCloseToEOF(t, c)
}
