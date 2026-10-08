package shadowsocksr_test

// True end-to-end coverage for the ShadowsocksR client stack: stream cipher
// (rc4-md5 / aes-256-cfb) + SSR protocol plugin (origin / auth_sha1_v4) + SSR
// obfs plugin (http_simple / tls1.2_ticket_auth), exercised over real loopback
// sockets.
//
// The in-test server below is an INDEPENDENT implementation of the SSR wire
// format: it does not import transport/shadowsocksr and does not call any of
// the client's pack/encode helpers. Its framing code was written from the wire
// contract (obfs framing outside, IV-prefixed stream cipher in the middle, SSR
// protocol frames inside), so a framing bug shared by both sides of the client
// stack cannot pass these tests. The client side is built exactly the way
// dialer/shadowsocksr builds it for dae: direct -> obfs -> shadowsocks_stream
// -> proto, including the netproxy.BufferedReaderConn insertion whose duck
// typed SetCipher/SetAddrLen hop to the obfs conn caused the recent
// "outer conn did not init cipher of Obfs" outage class.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	cryptoRand "crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/adler32"
	"hash/crc32"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	ssrdialer "github.com/daeuniverse/outbound/dialer/shadowsocksr"
	"github.com/daeuniverse/outbound/netproxy"
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

// ---- in-test SSR server: independent wire-format implementation ----

// ssrE2EServerConfig is one matrix cell of the e2e server.
type ssrE2EServerConfig struct {
	Password string
	Cipher   string // "rc4-md5" or "aes-256-cfb"
	Proto    string // "origin" or "auth_sha1_v4"
	Obfs     string // "http_simple" or "tls1.2_ticket_auth"
}

// ssrCipherSpec describes one stream cipher of the SS family: key length, IV
// length, and a stream constructor. encrypt selects the CFB direction for
// block-cipher modes (RC4 ignores it).
type ssrCipherSpec struct {
	keyLen    int
	ivLen     int
	newStream func(key, iv []byte, encrypt bool) (cipher.Stream, error)
}

func ssrCipherSpecFor(name string) (ssrCipherSpec, error) {
	switch name {
	case "rc4-md5":
		// rc4-md5 mixes the IV into the RC4 key with MD5(key || IV).
		return ssrCipherSpec{
			keyLen: 16,
			ivLen:  16,
			newStream: func(key, iv []byte, _ bool) (cipher.Stream, error) {
				sum := md5.Sum(append(append([]byte(nil), key...), iv...))
				return rc4.NewCipher(sum[:])
			},
		}, nil
	case "aes-256-cfb":
		return ssrCipherSpec{
			keyLen: 32,
			ivLen:  16,
			newStream: func(key, iv []byte, encrypt bool) (cipher.Stream, error) {
				block, err := aes.NewCipher(key)
				if err != nil {
					return nil, err
				}
				if encrypt {
					return cipher.NewCFBEncrypter(block, iv), nil
				}
				return cipher.NewCFBDecrypter(block, iv), nil
			},
		}, nil
	default:
		return ssrCipherSpec{}, fmt.Errorf("ssr e2e server: unsupported cipher %q", name)
	}
}

// evpBytesToKey derives the cipher key from the password with the MD5 chain
// scheme the SS family uses (reimplemented from the published scheme, not
// copied from the client's helper).
func evpBytesToKey(password string, keyLen int) []byte {
	const digestLen = 16
	out := make([]byte, 0, keyLen+digestLen)
	prev := md5.Sum([]byte(password))
	out = append(out, prev[:]...)
	for len(out) < keyLen {
		h := md5.New()
		h.Write(prev[:])
		h.Write([]byte(password))
		var next [digestLen]byte
		copy(next[:], h.Sum(nil))
		prev = next
		out = append(out, prev[:]...)
	}
	return out[:keyLen]
}

func hmacSHA1(key, data []byte) []byte {
	m := hmac.New(sha1.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// ---- obfs server: http_simple ----

// httpSimplePathPairs mirrors the request-path table the http_simple obfs
// format is defined over: the client picks one (prefix, suffix) pair and
// percent-encodes the first cipher-stream bytes into the URL between them.
// The server needs the same table to locate the encoded bytes.
var httpSimplePathPairs = [][2]string{
	{"", ""},
	{"login.php?redir=", ""},
	{"register.php?code=", ""},
	{"?keyword=", ""},
	{"search?src=typd&q=", "&lang=en"},
	{"s?ie=utf-8&f=8&rsv_bp=1&rsv_idx=1&ch=&bar=&wd=", "&rn="},
	{"post.php?id=", "&goto=view.php"},
}

var crlfcrlf = []byte("\r\n\r\n")

var httpSimpleRespHead = []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 16777216\r\nConnection: close\r\n\r\n")

// httpSimpleSrv decodes the client's one-shot HTTP disguise and then passes
// the raw cipher stream through in both directions. The fake response header
// is emitted lazily before the first server payload write.
type httpSimpleSrv struct {
	conn         net.Conn
	reqHeadDone  bool
	pending      []byte // decoded head bytes not yet handed to the cipher layer
	respHeadSent bool
}

func (h *httpSimpleSrv) Read(p []byte) (int, error) {
	if !h.reqHeadDone {
		var acc []byte
		tmp := make([]byte, 4096)
		for {
			if idx := bytes.Index(acc, crlfcrlf); idx >= 0 {
				head, err := decodeHTTPSimpleHead(acc[:idx])
				if err != nil {
					return 0, err
				}
				// Bytes after the header terminator are already raw
				// cipher stream and must be delivered in order.
				h.pending = append(head, acc[idx+4:]...)
				h.reqHeadDone = true
				break
			}
			if len(acc) > 64*1024 {
				return 0, errors.New("ssr e2e server: http_simple request head too large")
			}
			n, err := h.conn.Read(tmp)
			acc = append(acc, tmp[:n]...)
			if err != nil {
				return 0, err
			}
		}
	}
	if len(h.pending) > 0 {
		n := copy(p, h.pending)
		h.pending = h.pending[n:]
		return n, nil
	}
	return h.conn.Read(p)
}

func (h *httpSimpleSrv) Write(p []byte) (int, error) {
	if !h.respHeadSent {
		if _, err := h.conn.Write(httpSimpleRespHead); err != nil {
			return 0, err
		}
		h.respHeadSent = true
	}
	return h.conn.Write(p)
}

// decodeHTTPSimpleHead extracts the percent-encoded head bytes from the
// request line "METHOD /<prefix><%HH data><suffix> HTTP/1.1 ...". The
// (prefix, suffix) pair is recovered by longest-prefix match against the
// shared path table; only one non-empty prefix can match, so the choice is
// deterministic.
func decodeHTTPSimpleHead(head []byte) ([]byte, error) {
	line := head
	if idx := bytes.Index(head, crlfcrlf[:2]); idx >= 0 {
		line = head[:idx]
	}
	sp := bytes.IndexByte(line, ' ')
	if sp < 0 {
		return nil, errors.New("ssr e2e server: http_simple request without method separator")
	}
	rest := line[sp+1:]
	e := bytes.LastIndex(rest, []byte(" HTTP/"))
	if e < 0 {
		return nil, errors.New("ssr e2e server: http_simple request without HTTP version")
	}
	url := bytes.TrimPrefix(rest[:e], []byte("/"))
	best, bestLen := -1, -1
	for i, pair := range httpSimplePathPairs {
		if len(url) < len(pair[0])+len(pair[1]) {
			continue
		}
		if bytes.HasPrefix(url, []byte(pair[0])) && bytes.HasSuffix(url, []byte(pair[1])) {
			if len(pair[0]) > bestLen {
				best, bestLen = i, len(pair[0])
			}
		}
	}
	if best < 0 {
		return nil, fmt.Errorf("ssr e2e server: http_simple path table miss for %q", url)
	}
	pair := httpSimplePathPairs[best]
	mid := url[len(pair[0]) : len(url)-len(pair[1])]
	return pctDecode(string(mid))
}

func pctDecode(s string) ([]byte, error) {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			out = append(out, s[i])
			continue
		}
		if i+2 >= len(s) {
			return nil, fmt.Errorf("ssr e2e server: truncated %% escape in %q", s)
		}
		hi, err1 := hexNibble(s[i+1])
		lo, err2 := hexNibble(s[i+2])
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("ssr e2e server: bad %% escape in %q", s)
		}
		out = append(out, hi<<4|lo)
		i += 2
	}
	return out, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("bad hex digit %q", c)
	}
}

// ---- obfs server: tls1.2_ticket_auth ----

// tlsTicketSrv implements the fake-TLS framing: ClientHello (with an
// HMAC-SHA1 auth tag keyed by the derived cipher key and the client's random
// ID) -> ServerHello -> ChangeCipherSpec + Finished, then 0x17 records in both
// directions.
type tlsTicketSrv struct {
	conn  net.Conn
	key   []byte
	br    *bufio.Reader // record reader, built once the handshake completes
	dataQ bytes.Buffer  // reassembled 0x17 payloads awaiting the cipher layer
}

// handshake consumes the ClientHello, verifies its auth tag (a wrong cipher
// password fails here), and answers with ServerHello.
func (t *tlsTicketSrv) handshake() error {
	var acc []byte
	tmp := make([]byte, 4096)
	for {
		for i := 0; i < len(acc) && i < 16; i++ {
			if acc[i] != 0x16 {
				continue
			}
			if i+5 > len(acc) {
				break // record header not complete yet
			}
			recLen := int(binary.BigEndian.Uint16(acc[i+3 : i+5]))
			if recLen < 71 {
				return fmt.Errorf("ssr e2e server: tls1.2_ticket_auth record too short at offset %d", i)
			}
			total := i + 5 + recLen
			if total > len(acc) {
				break // record body not complete yet
			}
			hello := acc[i:total]
			if hello[1] != 0x03 || hello[2] != 0x01 || hello[5] != 0x01 {
				return fmt.Errorf("ssr e2e server: tls1.2_ticket_auth: not a ClientHello at offset %d", i)
			}
			if len(hello) < 11+32+1+32 {
				return errors.New("ssr e2e server: tls1.2_ticket_auth ClientHello truncated")
			}
			clientID, err := t.verifyHello(hello)
			if err != nil {
				// Auth failure: reject like a real server by closing.
				return err
			}
			if err := t.sendServerHello(clientID); err != nil {
				return err
			}
			// The length-framed record is the handshake unit; this client's
			// encoder trails two zero bytes after it, and real SSR servers
			// tolerate any post-Hello residue, so residue is dropped rather
			// than parsed as the next record.
			t.br = bufio.NewReader(t.conn)
			return nil
		}
		if len(acc) > 16*1024 {
			return errors.New("ssr e2e server: tls1.2_ticket_auth ClientHello not found")
		}
		n, err := t.conn.Read(tmp)
		acc = append(acc, tmp[:n]...)
		if err != nil {
			return err
		}
	}
}

// verifyHello checks the 32-byte auth block at hello[11:43] (unix time,
// 18 random bytes, 10-byte HMAC) and returns the 32-byte client ID that
// follows the 0x20 session-id length marker.
func (t *tlsTicketSrv) verifyHello(hello []byte) ([]byte, error) {
	auth := hello[11 : 11+32]
	clientID := hello[44 : 44+32]
	want := t.hmacSHA1(auth[:22], clientID)
	if !hmac.Equal(want[:10], auth[22:32]) {
		return nil, errors.New("ssr e2e server: tls1.2_ticket_auth ClientHello HMAC mismatch (wrong password?)")
	}
	return clientID, nil
}

// sendServerHello answers with the 76-byte ServerHello the client decodes:
// bytes [11:33) are the 22 HMAC-input bytes and [33:43) the tag slot.
func (t *tlsTicketSrv) sendServerHello(clientID []byte) error {
	random := make([]byte, 22)
	if _, err := cryptoRand.Read(random); err != nil {
		return err
	}
	sid := make([]byte, 32)
	if _, err := cryptoRand.Read(sid); err != nil {
		return err
	}
	msg := make([]byte, 0, 76)
	msg = append(msg, 0x16, 0x03, 0x03, 0x00, 0x47)         // handshake record, 71-byte body
	msg = append(msg, 0x02, 0x00, 0x00, 0x43)               // server hello, 67-byte body
	msg = append(msg, 0x03, 0x03)                           // TLS 1.2
	msg = append(msg, random...)                            // [11:33)
	msg = append(msg, t.hmacSHA1(random, clientID)[:10]...) // [33:43)
	msg = append(msg, 0x20)                                 // session id length
	msg = append(msg, sid...)                               // session id
	_, err := t.conn.Write(msg)
	return err
}

func (t *tlsTicketSrv) hmacSHA1(data, clientID []byte) []byte {
	k := make([]byte, 0, len(t.key)+len(clientID))
	k = append(k, t.key...)
	k = append(k, clientID...)
	return hmacSHA1(k, data)
}

func (t *tlsTicketSrv) readRecord() (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(t.br, hdr[:]); err != nil {
		return 0, nil, err
	}
	if hdr[1] != 0x03 || hdr[2] != 0x03 {
		return 0, nil, fmt.Errorf("ssr e2e server: tls1.2_ticket_auth bad record version %#x %#x", hdr[1], hdr[2])
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n > 16384 {
		return 0, nil, fmt.Errorf("ssr e2e server: tls1.2_ticket_auth record too large: %d", n)
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(t.br, p); err != nil {
		return 0, nil, err
	}
	return hdr[0], p, nil
}

func (t *tlsTicketSrv) Read(p []byte) (int, error) {
	for t.dataQ.Len() == 0 {
		ct, payload, err := t.readRecord()
		if err != nil {
			return 0, err
		}
		switch ct {
		case 0x17:
			t.dataQ.Write(payload)
		case 0x14, 0x16:
			// Post-ServerHello handshake flights (ChangeCipherSpec and the
			// client Finished). The session was already authenticated by the
			// ClientHello HMAC, so the payload is consumed and dropped.
		default:
			return 0, fmt.Errorf("ssr e2e server: tls1.2_ticket_auth unexpected record type %#x", ct)
		}
	}
	return t.dataQ.Read(p)
}

func (t *tlsTicketSrv) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > 16384 {
			n = 16384
		}
		hdr := []byte{0x17, 0x03, 0x03, byte(n >> 8), byte(n)}
		if _, err := t.conn.Write(hdr); err != nil {
			return written, err
		}
		if _, err := t.conn.Write(p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// ---- stream-cipher server plumbing ----

// cipherReader decrypts the client->server stream: the first ivLen bytes of
// the obfs-decoded stream are the client IV, everything after is ciphertext.
type cipherReader struct {
	r      io.Reader
	spec   ssrCipherSpec
	key    []byte
	iv     []byte
	dec    cipher.Stream
	inited bool
}

func (c *cipherReader) Read(p []byte) (int, error) {
	if !c.inited {
		iv := make([]byte, c.spec.ivLen)
		if _, err := io.ReadFull(c.r, iv); err != nil {
			return 0, fmt.Errorf("ssr e2e server: reading client IV: %w", err)
		}
		dec, err := c.spec.newStream(c.key, iv, false)
		if err != nil {
			return 0, err
		}
		c.iv, c.dec, c.inited = iv, dec, true
	}
	n, err := c.r.Read(p)
	if n > 0 {
		c.dec.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

// cipherWriter encrypts the server->client stream behind a fresh server IV
// sent once before the first payload.
type cipherWriter struct {
	w      io.Writer
	spec   ssrCipherSpec
	key    []byte
	enc    cipher.Stream
	inited bool
}

func (c *cipherWriter) Write(p []byte) (int, error) {
	if !c.inited {
		iv := make([]byte, c.spec.ivLen)
		if _, err := cryptoRand.Read(iv); err != nil {
			return 0, err
		}
		enc, err := c.spec.newStream(c.key, iv, true)
		if err != nil {
			return 0, err
		}
		if _, err := c.w.Write(iv); err != nil {
			return 0, err
		}
		c.enc, c.inited = enc, true
	}
	buf := make([]byte, len(p))
	c.enc.XORKeyStream(buf, p)
	if _, err := c.w.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

// ---- SSR protocol server: origin + auth_sha1_v4 ----

// readSocksAddr decodes the ATYP-prefixed target address from the decrypted
// stream (origin protocol carries it as-is).
func readSocksAddr(br *bufio.Reader) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(br, atyp[:]); err != nil {
		return "", err
	}
	switch atyp[0] {
	case 1:
		var b [6]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return "", err
		}
		return net.JoinHostPort(net.IP(b[0:4]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(b[4:])))), nil
	case 4:
		var b [18]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return "", err
		}
		return net.JoinHostPort(net.IP(b[0:16]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(b[16:])))), nil
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(br, l[:]); err != nil {
			return "", err
		}
		rest := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(br, rest); err != nil {
			return "", err
		}
		return net.JoinHostPort(string(rest[:l[0]]), strconv.Itoa(int(binary.BigEndian.Uint16(rest[l[0]:])))), nil
	default:
		return "", fmt.Errorf("ssr e2e server: bad ATYP %#x (wrong password?)", atyp[0])
	}
}

func parseSocksAddrBytes(b []byte) (string, error) {
	if len(b) < 2 {
		return "", errors.New("ssr e2e server: address truncated")
	}
	var host string
	switch b[0] {
	case 1:
		if len(b) < 7 {
			return "", errors.New("ssr e2e server: ipv4 address truncated")
		}
		host = net.IP(b[1:5]).String()
	case 4:
		if len(b) < 19 {
			return "", errors.New("ssr e2e server: ipv6 address truncated")
		}
		host = net.IP(b[1:17]).String()
	case 3:
		if len(b) < int(b[1])+4 {
			return "", errors.New("ssr e2e server: domain address truncated")
		}
		host = string(b[2 : 2+b[1]])
	default:
		return "", fmt.Errorf("ssr e2e server: bad ATYP %#x (wrong password?)", b[0])
	}
	port := int(binary.BigEndian.Uint16(b[len(b)-2:]))
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// readAuthFrame reads one auth_sha1_v4 header frame (the client sends the
// target address inside it): 2-byte BE total length, then the body.
func readAuthFrame(br *bufio.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, err
	}
	total := int(binary.BigEndian.Uint16(hdr[:]))
	if total < 29 { // randLen(1) + 6 header + 12 fixed fields + 10 HMAC at minimum
		return nil, fmt.Errorf("ssr e2e server: auth frame too short: %d", total)
	}
	frame := make([]byte, total)
	frame[0], frame[1] = hdr[0], hdr[1]
	if _, err := io.ReadFull(br, frame[2:]); err != nil {
		return nil, err
	}
	return frame, nil
}

// authFrameAddr validates one auth_sha1_v4 auth frame and extracts the socks
// address carried in it. A wrong cipher password breaks the CRC32 (which
// covers the key) and the HMAC (which covers IV || key); both reject.
func authFrameAddr(frame []byte, key, iv []byte) (string, error) {
	crcData := make([]byte, 0, 2+12+len(key))
	crcData = append(crcData, frame[0:2]...)
	crcData = append(crcData, "auth_sha1_v4"...)
	crcData = append(crcData, key...)
	if binary.LittleEndian.Uint32(frame[2:6]) != crc32.ChecksumIEEE(crcData) {
		return "", errors.New("ssr e2e server: auth_sha1_v4 CRC32 mismatch (wrong password?)")
	}
	randLen := int(frame[6])
	if randLen == 0xFF {
		if len(frame) < 9 {
			return "", errors.New("ssr e2e server: auth frame truncated in rand length")
		}
		randLen = int(binary.BigEndian.Uint16(frame[7:9]))
	}
	dataOff := randLen + 6
	if len(frame) < dataOff+12+10+2 {
		return "", errors.New("ssr e2e server: auth frame truncated")
	}
	macKey := make([]byte, 0, len(iv)+len(key))
	macKey = append(macKey, iv...)
	macKey = append(macKey, key...)
	want := hmacSHA1(macKey, frame[:len(frame)-10])[:10]
	if !hmac.Equal(want, frame[len(frame)-10:]) {
		return "", errors.New("ssr e2e server: auth_sha1_v4 HMAC mismatch (wrong password?)")
	}
	addrLen := len(frame) - dataOff - 12 - 10
	return parseSocksAddrBytes(frame[dataOff+12 : dataOff+12+addrLen])
}

// frameReader peels auth_sha1_v4 data frames (2-byte BE length, 2-byte CRC32
// of the length, padding marker + padding, payload, 4-byte LE Adler32) from
// the decrypted stream and exposes the payload as an io.Reader. io.EOF is
// returned only at a clean frame boundary, so a client FIN half-closes the
// relay instead of looking like corruption.
type frameReader struct {
	br  *bufio.Reader
	buf []byte
}

func (f *frameReader) Read(p []byte) (int, error) {
	for len(f.buf) == 0 {
		var hdr [2]byte
		if _, err := io.ReadFull(f.br, hdr[:]); err != nil {
			return 0, err
		}
		total := int(binary.BigEndian.Uint16(hdr[:]))
		if total < 8 || total >= 8192 {
			return 0, fmt.Errorf("ssr e2e server: bad auth_sha1_v4 frame length %d", total)
		}
		frame := make([]byte, total)
		frame[0], frame[1] = hdr[0], hdr[1]
		if _, err := io.ReadFull(f.br, frame[2:]); err != nil {
			return 0, err
		}
		if binary.LittleEndian.Uint16(frame[2:4]) != uint16(crc32.ChecksumIEEE(frame[0:2])&0xFFFF) {
			return 0, errors.New("ssr e2e server: auth_sha1_v4 data frame CRC mismatch")
		}
		if binary.LittleEndian.Uint32(frame[total-4:]) != adler32.Checksum(frame[:total-4]) {
			return 0, errors.New("ssr e2e server: auth_sha1_v4 data frame Adler32 mismatch")
		}
		pos := int(frame[4])
		if pos == 0xFF {
			pos = int(binary.BigEndian.Uint16(frame[5:7])) + 4
		} else {
			pos += 4
		}
		if pos > total-4 {
			return 0, errors.New("ssr e2e server: auth_sha1_v4 padding offset out of range")
		}
		f.buf = frame[pos : total-4]
	}
	n := copy(p, f.buf)
	f.buf = f.buf[n:]
	return n, nil
}

// writeDataFrame emits one server->client auth_sha1_v4 data frame with
// variable padding (the offset the client must skip is data-driven, so the
// e2e keeps that decode path honest).
func writeDataFrame(w io.Writer, seq int, data []byte) error {
	randLen := 1 + seq%31
	total := randLen + len(data) + 8
	if total >= 8192 {
		return fmt.Errorf("ssr e2e server: data frame too large: %d", total)
	}
	frame := make([]byte, total)
	binary.BigEndian.PutUint16(frame[0:2], uint16(total))
	binary.LittleEndian.PutUint16(frame[2:4], uint16(crc32.ChecksumIEEE(frame[0:2])&0xFFFF))
	frame[4] = byte(randLen)
	copy(frame[randLen+4:], data)
	binary.LittleEndian.PutUint32(frame[total-4:], adler32.Checksum(frame[:total-4]))
	_, err := w.Write(frame)
	return err
}

// copySSRFramed pumps the target response into auth_sha1_v4 data frames.
func copySSRFramed(w io.Writer, r io.Reader) {
	buf := make([]byte, 4096)
	seq := 0
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if werr := writeDataFrame(w, seq, buf[:n]); werr != nil {
				return
			}
			seq++
		}
		if err != nil {
			return
		}
	}
}

// ---- the server listener and per-connection serving ----

// startSSRE2EServer runs the in-test SSR server and returns its address.
func startSSRE2EServer(t *testing.T, cfg ssrE2EServerConfig) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ssr e2e listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSSRE2EConn(cfg, c)
		}
	}()
	return ln.Addr().String()
}

// serveSSRE2EConn runs one SSR session: obfs decode -> stream-cipher decode
// -> protocol decode -> real TCP relay to the target with half-close
// propagation. Every failure path just closes the session, like a real
// server; the deadlines bound the whole lifetime.
func serveSSRE2EConn(cfg ssrE2EServerConfig, raw net.Conn) {
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(60 * time.Second))

	spec, err := ssrCipherSpecFor(cfg.Cipher)
	if err != nil {
		return
	}
	key := evpBytesToKey(cfg.Password, spec.keyLen)

	var obfsIn io.Reader
	var obfsOut io.Writer
	switch cfg.Obfs {
	case "http_simple":
		hs := &httpSimpleSrv{conn: raw}
		obfsIn, obfsOut = hs, hs
	case "tls1.2_ticket_auth":
		tt := &tlsTicketSrv{conn: raw, key: key}
		if err := tt.handshake(); err != nil {
			return // includes the wrong-password HMAC rejection
		}
		obfsIn, obfsOut = tt, tt
	default:
		return
	}

	req := &cipherReader{r: obfsIn, spec: spec, key: key}
	br := bufio.NewReaderSize(req, 16<<10)
	resp := &cipherWriter{w: obfsOut, spec: spec, key: key}

	var targetAddr string
	var up io.Reader // decoded client payload stream
	switch cfg.Proto {
	case "origin":
		targetAddr, err = readSocksAddr(br)
		if err != nil {
			return
		}
		up = br
	case "auth_sha1_v4":
		var frame []byte
		frame, err = readAuthFrame(br)
		if err != nil {
			return
		}
		// req.iv is populated by the reads above (the IV precedes the frame).
		targetAddr, err = authFrameAddr(frame, key, req.iv)
		if err != nil {
			return
		}
		up = &frameReader{br: br}
	default:
		return
	}

	target, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		return
	}
	defer target.Close()

	// Target -> client pump. It outlives the client->target copy so the
	// echoed data drains before the session closes.
	done := make(chan struct{})
	go func() {
		defer close(done)
		if cfg.Proto == "auth_sha1_v4" {
			copySSRFramed(resp, target)
		} else {
			_, _ = io.Copy(resp, target)
		}
	}()

	// Client -> target: io.Copy ends on the client FIN, which is forwarded
	// to the target as a half-close so the target can finish its output.
	_, _ = io.Copy(target, up)
	if tcp, ok := target.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	<-done
}

// ---- the client (production dialer/shadowsocksr construction path) ----

// newSSRE2EClientDialer builds the dae-side dialer chain exactly the way
// dialer/shadowsocksr.ShadowsocksR.Dialer does: direct -> obfs ->
// shadowsocks_stream -> proto. The obfs dialer is what carries the duck-typed
// SetCipher/SetAddrLen hooks the buffered underlay must not hide.
func newSSRE2EClientDialer(t *testing.T, proxyAddr string, cfg ssrE2EServerConfig) netproxy.Dialer {
	t.Helper()
	direct, _ := dialer.NewDirectDialer(&dialer.ExtraOption{}, false)
	host, portStr, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		t.Fatalf("split proxy addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("proxy port: %v", err)
	}
	s := &ssrdialer.ShadowsocksR{
		Name:     "e2e",
		Server:   host,
		Port:     port,
		Password: cfg.Password,
		Cipher:   cfg.Cipher,
		Proto:    cfg.Proto,
		Obfs:     cfg.Obfs,
	}
	d, _, err := s.Dialer(&dialer.ExtraOption{}, direct)
	if err != nil {
		t.Fatalf("ssr dialer: %v", err)
	}
	return d
}

// verifySSRRelayRoundTrip writes total bytes through c while concurrently
// reading them back from the echo target, verifying every byte. 4MiB crosses
// cipher block, protocol frame and obfs record boundaries many times over.
func verifySSRRelayRoundTrip(t *testing.T, c netproxy.Conn, total int) {
	t.Helper()
	payload := make([]byte, 64<<10)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	written := 0
	go func() {
		for written < total {
			n := len(payload)
			if total-written < n {
				n = total - written
			}
			if _, err := c.Write(payload[:n]); err != nil {
				return
			}
			written += n
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

// runSSRRelayAndHalfClose is the shared body of the per-matrix-row relay
// tests: 4MiB byte-exact echo through the real SSR server, then a half-close
// whose EOF must propagate back through obfs + cipher + protocol layers.
func runSSRRelayAndHalfClose(t *testing.T, cfg ssrE2EServerConfig) {
	t.Helper()
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startSSRE2EServer(t, cfg)
	d := newSSRE2EClientDialer(t, proxyAddr, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	verifySSRRelayRoundTrip(t, c, 4<<20)

	// Half-close must survive every wrapper: proto conn -> ss cipher conn ->
	// buffered underlay -> obfs conn -> TCP. CloseWrite is an optional
	// capability, so losing it to a wrapper must fail this e2e instead of
	// silently skipping the check.
	closeWrite, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("ssr conn %T lost the CloseWrite capability", c)
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

// runSSRBadPassword is the shared auth-failure scenario: the server runs a
// different password, rejects the session, and the client must surface an
// error within the deadline (writes may still "succeed" while the handshake
// is being rejected - the read is where the error must appear). No panic, no
// hang.
func runSSRBadPassword(t *testing.T, cfg ssrE2EServerConfig, clientPassword string) {
	t.Helper()
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startSSRE2EServer(t, cfg)
	clientCfg := cfg
	clientCfg.Password = clientPassword
	d := newSSRE2EClientDialer(t, proxyAddr, clientCfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// The rejection happens server-side; the local write may or may not
	// notice the closed socket first. Either way it must not panic.
	_, _ = c.Write([]byte("hello"))
	if err := c.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 128)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("server rejected the session but the client never surfaced an error")
	}
}

// ---- the e2e tests ----

// TestE2ESSRTCPRelayOriginHTTPSimpleRC4MD5 covers matrix row 1: origin
// protocol + http_simple obfs + rc4-md5, 4MiB byte-exact relay and
// half-close EOF propagation over real loopback sockets.
func TestE2ESSRTCPRelayOriginHTTPSimpleRC4MD5(t *testing.T) {
	runSSRRelayAndHalfClose(t, ssrE2EServerConfig{
		Password: "ssr-e2e-password",
		Cipher:   "rc4-md5",
		Proto:    "origin",
		Obfs:     "http_simple",
	})
}

// TestE2ESSRTCPRelayAuthSHA1v4TLSTicketAES256CFB covers matrix row 2:
// auth_sha1_v4 protocol + tls1.2_ticket_auth obfs + aes-256-cfb, including
// the fake-TLS handshake HMACs and the framed data path.
func TestE2ESSRTCPRelayAuthSHA1v4TLSTicketAES256CFB(t *testing.T) {
	runSSRRelayAndHalfClose(t, ssrE2EServerConfig{
		Password: "ssr-e2e-password",
		Cipher:   "aes-256-cfb",
		Proto:    "auth_sha1_v4",
		Obfs:     "tls1.2_ticket_auth",
	})
}

// TestE2ESSRBadPasswordOriginHTTPSimpleRC4MD5: row 1 has no protocol-layer
// auth, so a wrong password shows up as undecryptable garbage; the server
// rejects the bad ATYP and the client must see an error.
func TestE2ESSRBadPasswordOriginHTTPSimpleRC4MD5(t *testing.T) {
	runSSRBadPassword(t, ssrE2EServerConfig{
		Password: "server-side-password",
		Cipher:   "rc4-md5",
		Proto:    "origin",
		Obfs:     "http_simple",
	}, "client-side-password")
}

// TestE2ESSRBadPasswordAuthSHA1v4TLSTicketAES256CFB: row 2 rejects on the
// tls1.2_ticket_auth ClientHello HMAC (keyed by the derived cipher key)
// before any data flows.
func TestE2ESSRBadPasswordAuthSHA1v4TLSTicketAES256CFB(t *testing.T) {
	runSSRBadPassword(t, ssrE2EServerConfig{
		Password: "server-side-password",
		Cipher:   "aes-256-cfb",
		Proto:    "auth_sha1_v4",
		Obfs:     "tls1.2_ticket_auth",
	}, "client-side-password")
}
