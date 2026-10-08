package shadowsocks_test

// True end-to-end coverage for the classic Shadowsocks AEAD client stack
// (protocol/shadowsocks): an in-test shadowsocks server that is an
// independent implementation of the wire format, fronting a real loopback
// echo target, reached through the same dialer chain dae builds
// (direct -> shadowsocks).
//
// Wire format implemented here (own framing, only key/stream construction is
// taken from the repo's ciphers package):
//
//	client -> server: [salt][chunk]* ; the plaintext of the very first chunk
//	                  begins with the target address (ATYP+ADDR+PORT).
//	server -> client: [salt][chunk]* (no address on replies).
//	chunk:            [u16 BE length][AEAD tag] + [length bytes][AEAD tag],
//	                  AEAD nonces start at zero and increment little-endian
//	                  after every AEAD operation.
//	UDP datagram:     [salt][AEAD(ATYP+ADDR+PORT+payload)] with a fixed zero
//	                  nonce; the salt is the only key freshness.
//
// The subkey is HKDF-SHA1(masterKey, salt, "ss-subkey") derived here directly,
// not by calling into the client's helpers. Cipher split note: dialer/
// shadowsocks routes the AEAD methods (aes-256-gcm, aes-128-gcm,
// chacha20-poly1305, chacha20-ietf-poly1305) to protocol "shadowsocks" and the
// legacy stream methods (aes-256-cfb and friends) to protocol
// "shadowsocks_stream"; both halves are covered by e2e suites in this repo.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	_ "github.com/daeuniverse/outbound/protocol/shadowsocks"
	"golang.org/x/crypto/hkdf"
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

// ---- in-test shadowsocks AEAD server (independent wire-format implementation) ----

// aeadNonce is one shadowsocks AEAD nonce: the operation counter encoded
// little-endian. next() returns the nonce for the upcoming AEAD operation
// (starting at zero) and only then advances the counter, matching the client
// side contract of increment-after-use.
type aeadNonce struct {
	counter uint64
	size    int
}

func newAeadNonce(size int) *aeadNonce {
	return &aeadNonce{size: size}
}

func (n *aeadNonce) next() []byte {
	buf := make([]byte, n.size)
	for i := 0; i < 8 && i < n.size; i++ {
		buf[i] = byte(n.counter >> (8 * i))
	}
	n.counter++
	return buf
}

// deriveAeadSubkey computes the per-session subkey the way shadowsocks AEAD
// defines it. Implemented here with the raw HKDF primitive; the client's key
// schedule helpers are deliberately not used.
func deriveAeadSubkey(masterKey, salt []byte, keyLen int) ([]byte, error) {
	kdf := hkdf.New(sha1.New, masterKey, salt, []byte("ss-subkey"))
	subKey := make([]byte, keyLen)
	if _, err := io.ReadFull(kdf, subKey); err != nil {
		return nil, err
	}
	return subKey, nil
}

// aeadChunkReader turns the encrypted chunk stream into a plaintext
// io.Reader. It reassembles and verifies the [len][tag][payload][tag] chunks
// itself; a tag failure aborts the stream with an error.
type aeadChunkReader struct {
	t    *testing.T
	conn net.Conn
	aead interface {
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	}
	tagLen int
	nonce  *aeadNonce
	left   []byte
}

func (r *aeadChunkReader) Read(b []byte) (int, error) {
	if len(r.left) == 0 {
		hdr := make([]byte, 2+r.tagLen)
		if err := readFullOrDead(r.t, r.conn, hdr); err != nil {
			return 0, err
		}
		plainHdr, err := r.aead.Open(hdr[:0], r.nonce.next(), hdr, nil)
		if err != nil {
			return 0, err
		}
		length := int(binary.BigEndian.Uint16(plainHdr))
		frame := make([]byte, length+r.tagLen)
		if err := readFullOrDead(r.t, r.conn, frame); err != nil {
			return 0, err
		}
		payload, err := r.aead.Open(frame[:0], r.nonce.next(), frame, nil)
		if err != nil {
			return 0, err
		}
		r.left = payload
	}
	n := copy(b, r.left)
	r.left = r.left[n:]
	return n, nil
}

// aeadChunkWriter writes plaintext as shadowsocks AEAD chunks. On the first
// write it generates the reply salt, derives its own subkey and emits the
// salt ahead of the chunks.
type aeadChunkWriter struct {
	conn   net.Conn
	conf   *ciphers.CipherConf
	master []byte
	aead   interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
	}
	nonce   *aeadNonce
	started bool
}

func (w *aeadChunkWriter) start() error {
	salt := make([]byte, w.conf.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	subKey, err := deriveAeadSubkey(w.master, salt, w.conf.KeyLen)
	if err != nil {
		return err
	}
	aead, err := w.conf.NewCipher(subKey)
	if err != nil {
		return err
	}
	w.aead = aead
	w.nonce = newAeadNonce(w.conf.NonceLen)
	if _, err := w.conn.Write(salt); err != nil {
		return err
	}
	w.started = true
	return nil
}

func (w *aeadChunkWriter) Write(b []byte) (int, error) {
	if !w.started {
		if err := w.start(); err != nil {
			return 0, err
		}
	}
	written := 0
	for written < len(b) {
		end := written + 16383
		if end > len(b) {
			end = len(b)
		}
		chunk := b[written:end]
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(chunk)))
		frame := make([]byte, 0, 2+w.conf.TagLen+len(chunk)+w.conf.TagLen)
		frame = w.aead.Seal(frame, w.nonce.next(), hdr[:], nil)
		frame = w.aead.Seal(frame, w.nonce.next(), chunk, nil)
		if err := w.conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return written, err
		}
		if _, err := w.conn.Write(frame); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

// parseShadowsocksAddress decodes ATYP + address + port from the start of b
// and returns the dialable host:port plus the number of bytes consumed. This
// parser is written from the wire spec, not shared with the client.
func parseShadowsocksAddress(b []byte) (addr string, n int, err error) {
	if len(b) < 1 {
		return "", 0, io.ErrUnexpectedEOF
	}
	switch b[0] {
	case 1: // ipv4
		if len(b) < 7 {
			return "", 0, io.ErrUnexpectedEOF
		}
		return net.IP(b[1:5]).String() + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(b[5:7]))), 7, nil
	case 4: // ipv6
		if len(b) < 19 {
			return "", 0, io.ErrUnexpectedEOF
		}
		return net.IP(b[1:17]).String() + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(b[17:19]))), 19, nil
	case 3: // domain
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

// parseShadowsocksUDPAddress decodes ATYP+ADDR+PORT from one decrypted UDP
// datagram and returns the address, the port and the payload offset.
func parseShadowsocksUDPAddress(b []byte) (ip net.IP, port int, offset int, err error) {
	addr, n, err := parseShadowsocksAddress(b)
	if err != nil {
		return nil, 0, 0, err
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0, 0, err
	}
	parsed := net.ParseIP(host)
	if parsed == nil {
		return nil, 0, 0, io.ErrUnexpectedEOF
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		return nil, 0, 0, err
	}
	return parsed, port, n, nil
}

// serveShadowsocksAeadConn handles one accepted connection as a classic
// shadowsocks AEAD server: it decrypts the chunk stream (own framing), parses
// the target address from the first chunk, relays to the real target with
// half-close propagation, and encrypts the replies with its own fresh salt.
func serveShadowsocksAeadConn(t *testing.T, downstream net.Conn, method, password string) {
	t.Helper()
	defer downstream.Close()
	conf, ok := ciphers.AeadCiphersConf[method]
	if !ok || conf.NewCipher == nil {
		t.Errorf("in-test server: unknown cipher %q", method)
		return
	}
	masterKey := common.EVPBytesToKey(password, conf.KeyLen)

	salt := make([]byte, conf.SaltLen)
	if err := readFullOrDead(t, downstream, salt); err != nil {
		return
	}
	subKey, err := deriveAeadSubkey(masterKey, salt, conf.KeyLen)
	if err != nil {
		return
	}
	aead, err := conf.NewCipher(subKey)
	if err != nil {
		return
	}
	reader := &aeadChunkReader{
		t:      t,
		conn:   downstream,
		aead:   aead,
		tagLen: conf.TagLen,
		nonce:  newAeadNonce(conf.NonceLen),
	}

	// The first chunk carries the target address in front of the payload.
	first := make([]byte, 4096)
	n, err := reader.Read(first)
	if err != nil {
		// An AEAD open failure here is exactly the wrong-password case: the
		// session is dead and the client must observe an error, not a hang.
		return
	}
	addr, addrLen, err := parseShadowsocksAddress(first[:n])
	if err != nil {
		return
	}
	reader.left = append(append([]byte(nil), first[addrLen:n]...), reader.left...)

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
	writer := &aeadChunkWriter{
		conn:   downstream,
		conf:   conf,
		master: masterKey,
	}
	_, _ = io.Copy(writer, target)
}

// startShadowsocksAeadServer runs the in-test classic shadowsocks server.
func startShadowsocksAeadServer(t *testing.T, method, password string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("shadowsocks listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveShadowsocksAeadConn(t, c, method, password)
		}
	}()
	return ln.Addr().String()
}

// newShadowsocksClientDialer builds the dae-side dialer chain for the classic
// AEAD shadowsocks client exactly the way dialer/shadowsocks does for the
// AEAD cipher methods: direct -> protocol "shadowsocks".
func newShadowsocksClientDialer(t *testing.T, proxyAddr, method, password string) netproxy.Dialer {
	t.Helper()
	direct, _ := dialer.NewDirectDialer(&dialer.ExtraOption{}, false)
	d, err := protocol.NewDialer("shadowsocks", direct, protocol.Header{
		IsClient:     true,
		ProxyAddress: proxyAddr,
		Cipher:       method,
		Password:     password,
	})
	if err != nil {
		t.Fatalf("shadowsocks dialer: %v", err)
	}
	return d
}

// verifyRelayRoundTrip writes a large deterministic payload through c, reads
// it back, and checks integrity. Large enough to cross chunk/tag/buffer
// boundaries; write and read run concurrently.
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
// protocol conn (losing it to a wrapper is a failure, not a skip) and that
// the FIN propagates through the server to the echo target and back as EOF.
func assertHalfCloseToEOF(t *testing.T, c netproxy.Conn) {
	t.Helper()
	closeWrite, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("shadowsocks conn %T lost the CloseWrite capability", c)
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

// ---- the e2e tests ----

// TestE2EShadowsocksTCPRelay pushes 4MiB through client -> shadowsocks server
// -> echo target -> back on a real loopback socket, per AEAD cipher, then
// half-closes and expects EOF.
func TestE2EShadowsocksTCPRelay(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "chacha20-ietf-poly1305"} {
		t.Run(method, func(t *testing.T) {
			echoAddr := loopbackEchoTarget(t)
			proxyAddr := startShadowsocksAeadServer(t, method, "ss-password")
			d := newShadowsocksClientDialer(t, proxyAddr, method, "ss-password")

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

// TestE2EShadowsocksUDPRelay exercises the shadowsocks UDP relay: several
// datagrams to two different echo targets, with integrity and source address
// checks on every reply.
func TestE2EShadowsocksUDPRelay(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "chacha20-ietf-poly1305"} {
		t.Run(method, func(t *testing.T) {
			targetA := startUDPEchoTarget(t)
			targetB := startUDPEchoTarget(t)
			udpLn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("udp server listen: %v", err)
			}
			t.Cleanup(func() { _ = udpLn.Close() })
			go serveShadowsocksAeadUDP(t, udpLn, method, "ss-password")
			proxyAddr := udpLn.LocalAddr().String()

			d := newShadowsocksClientDialer(t, proxyAddr, method, "ss-password")
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
		})
	}
}

// serveShadowsocksAeadUDP is the UDP half of the in-test server: it decodes
// [salt][AEAD(ATYP+ADDR+PORT+payload)] per datagram (own framing), forwards
// the payload to the addressed target and encrypts the reply with a fresh
// salt plus the reply source address.
func serveShadowsocksAeadUDP(t *testing.T, pc net.PacketConn, method, password string) {
	t.Helper()
	conf, ok := ciphers.AeadCiphersConf[method]
	if !ok || conf.NewCipher == nil {
		t.Errorf("in-test udp server: unknown cipher %q", method)
		return
	}
	masterKey := common.EVPBytesToKey(password, conf.KeyLen)
	buf := make([]byte, 65535)
	for {
		n, cli, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < conf.SaltLen+conf.TagLen {
			continue
		}
		salt := make([]byte, conf.SaltLen)
		copy(salt, buf[:conf.SaltLen])
		subKey, err := deriveAeadSubkey(masterKey, salt, conf.KeyLen)
		if err != nil {
			return
		}
		aead, err := conf.NewCipher(subKey)
		if err != nil {
			return
		}
		plain, err := aead.Open(buf[conf.SaltLen:conf.SaltLen],
			make([]byte, conf.NonceLen), buf[conf.SaltLen:n], nil)
		if err != nil {
			continue // undecryptable packet: drop, keep serving
		}
		ip, port, offset, err := parseShadowsocksUDPAddress(plain)
		if err != nil {
			continue
		}
		target, err := net.Dial("udp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err != nil {
			continue
		}
		if _, err := target.Write(plain[offset:]); err != nil {
			target.Close()
			continue
		}
		_ = target.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp := make([]byte, 65535)
		m, err := target.Read(resp)
		target.Close()
		if err != nil {
			continue
		}
		// Reply plaintext: [ATYP ipv4/ipv6][source addr][port][payload].
		src := target.RemoteAddr().(*net.UDPAddr)
		var meta []byte
		if ip4 := src.IP.To4(); ip4 != nil {
			meta = append([]byte{1}, ip4...)
		} else {
			meta = append([]byte{4}, src.IP.To16()...)
		}
		var portBytes [2]byte
		binary.BigEndian.PutUint16(portBytes[:], uint16(src.Port))
		meta = append(meta, portBytes[:]...)
		plain = append(meta, resp[:m]...)

		reply := make([]byte, conf.SaltLen+len(plain)+conf.TagLen)
		replySalt := make([]byte, conf.SaltLen)
		if _, err := rand.Read(replySalt); err != nil {
			return
		}
		copy(reply, replySalt)
		replySubKey, err := deriveAeadSubkey(masterKey, replySalt, conf.KeyLen)
		if err != nil {
			return
		}
		replyAead, err := conf.NewCipher(replySubKey)
		if err != nil {
			return
		}
		sealed := replyAead.Seal(reply[conf.SaltLen:conf.SaltLen],
			make([]byte, conf.NonceLen), plain, nil)
		if _, err := pc.WriteTo(reply[:conf.SaltLen+len(sealed)], cli); err != nil {
			return
		}
	}
}

// TestE2EShadowsocksWrongPasswordIsAnErrorNotAPanic checks the auth-failure
// path: the server cannot open the first chunk, closes the session, and the
// client must surface an error without panicking or hanging.
func TestE2EShadowsocksWrongPasswordIsAnErrorNotAPanic(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startShadowsocksAeadServer(t, "aes-256-gcm", "correct-horse")
	// The client is built with a different password; the server's AEAD open
	// fails on the very first chunk and the server drops the connection.
	d := newShadowsocksClientDialer(t, proxyAddr, "aes-256-gcm", "wrong-horse")

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
