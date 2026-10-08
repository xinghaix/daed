package trojanc_test

// True end-to-end coverage for the trojan client stack: an in-test trojan
// server (own wire-format implementation, not a copy of protocol/trojanc)
// fronting a real loopback echo target, reached through the same dialer chain
// dae builds (direct -> transport/tls -> trojanc).

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	tls2 "github.com/daeuniverse/outbound/transport/tls"
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

// e2eSelfSignedCert mints the server certificate for the in-test TLS listener.
func e2eSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// deadlineCtx bounds every dial/read in the e2e so a hung protocol layer fails
// the test instead of hanging it.
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

// ---- in-test trojan server (independent wire-format implementation) ----

const trojanCmdTCP byte = 1
const trojanCmdUDP byte = 3

// parseTrojanAddress decodes ATYP + address + port from the stream.
func parseTrojanAddress(t *testing.T, c net.Conn) (host string, port uint16, err error) {
	t.Helper()
	var atyp [1]byte
	if err = readFullOrDead(t, c, atyp[:]); err != nil {
		return "", 0, err
	}
	switch atyp[0] {
	case 1: // ipv4
		var raw [6]byte
		if err = readFullOrDead(t, c, raw[:]); err != nil {
			return "", 0, err
		}
		return net.IP(raw[:4]).String(), binary.BigEndian.Uint16(raw[4:]), nil
	case 4: // ipv6
		var raw [18]byte
		if err = readFullOrDead(t, c, raw[:]); err != nil {
			return "", 0, err
		}
		return net.IP(raw[:16]).String(), binary.BigEndian.Uint16(raw[16:]), nil
	case 3: // domain
		var l [1]byte
		if err = readFullOrDead(t, c, l[:]); err != nil {
			return "", 0, err
		}
		raw := make([]byte, int(l[0])+2)
		if err = readFullOrDead(t, c, raw); err != nil {
			return "", 0, err
		}
		return string(raw[:l[0]]), binary.BigEndian.Uint16(raw[l[0]:]), nil
	default:
		return "", 0, io.ErrUnexpectedEOF
	}
}

// serveTrojanConn handles one accepted TLS conn as a trojan server: TCP is
// relayed to the parsed destination with half-close propagation; UDP frames
// (ATYP+ADDR+PORT+LEN+CRLF+payload on the same stream) are relayed through a
// real UDP socket.
func serveTrojanConn(t *testing.T, downstream net.Conn, password string, rejectAuth bool) {
	t.Helper()
	defer downstream.Close()
	sum := sha256.Sum224([]byte(password))
	want := []byte(hex.EncodeToString(sum[:]))

	var hash [56]byte
	if err := readFullOrDead(t, downstream, hash[:]); err != nil {
		return
	}
	if rejectAuth || !bytes.Equal(hash[:], want) {
		// Real servers close on bad auth; do the same.
		return
	}
	var crlf [2]byte
	if err := readFullOrDead(t, downstream, crlf[:]); err != nil {
		return
	}
	if crlf[0] != '\r' || crlf[1] != '\n' {
		return
	}
	var cmd [1]byte
	if err := readFullOrDead(t, downstream, cmd[:]); err != nil {
		return
	}
	host, port, err := parseTrojanAddress(t, downstream)
	if err != nil {
		return
	}
	if err := readFullOrDead(t, downstream, crlf[:]); err != nil {
		return
	}
	if crlf[0] != '\r' || crlf[1] != '\n' {
		return
	}
	destination := net.JoinHostPort(host, strconv.Itoa(int(port)))

	switch cmd[0] {
	case trojanCmdTCP:
		target, err := net.DialTimeout("tcp", destination, 10*time.Second)
		if err != nil {
			return
		}
		defer target.Close()
		go func() {
			_, _ = io.Copy(target, downstream)
			if tcp, ok := target.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
		}()
		_, _ = io.Copy(downstream, target)
	case trojanCmdUDP:
		udp, err := net.Dial("udp", destination)
		if err != nil {
			return
		}
		defer udp.Close()
		// Server -> client pump: frame every datagram from the target.
		go func() {
			buf := make([]byte, 65535)
			for {
				n, err := udp.Read(buf)
				if err != nil {
					return
				}
				ra, ok := udp.RemoteAddr().(*net.UDPAddr)
				if !ok {
					return
				}
				// ATYP: the target is loopback ipv4.
				frame := make([]byte, 0, 7+n)
				frame = append(frame, 1)
				ip := ra.IP.To4()
				if ip == nil {
					ip = ra.IP.To16()
					frame[0] = 4
					frame = append(frame, ip...)
				} else {
					frame = append(frame, ip...)
				}
				var portBytes [2]byte
				binary.BigEndian.PutUint16(portBytes[:], uint16(ra.Port))
				frame = append(frame, portBytes[:]...)
				var lenBytes [2]byte
				binary.BigEndian.PutUint16(lenBytes[:], uint16(n))
				frame = append(frame, lenBytes[:]...)
				frame = append(frame, '\r', '\n')
				frame = append(frame, buf[:n]...)
				if _, err := downstream.Write(frame); err != nil {
					return
				}
			}
		}()
		// Client -> target: read framed datagrams from the TLS stream.
		for {
			if _, _, err := parseTrojanAddress(t, downstream); err != nil {
				return
			}
			var lengthAndCRLF [4]byte
			if err := readFullOrDead(t, downstream, lengthAndCRLF[:]); err != nil {
				return
			}
			if lengthAndCRLF[2] != '\r' || lengthAndCRLF[3] != '\n' {
				return
			}
			length := int(binary.BigEndian.Uint16(lengthAndCRLF[:2]))
			payload := make([]byte, length)
			if err := readFullOrDead(t, downstream, payload); err != nil {
				return
			}
			// The datagram target is the address in the frame, not the
			// session destination.
			if _, err := udp.Write(payload); err != nil {
				return
			}
		}
	}
}

// startTrojanServer runs the in-test trojan-over-TLS server.
func startTrojanServer(t *testing.T, password string, rejectAuth bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("trojan listen: %v", err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{e2eSelfSignedCert(t)},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	t.Cleanup(func() { _ = tlsLn.Close() })
	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go serveTrojanConn(t, c, password, rejectAuth)
		}
	}()
	return ln.Addr().String()
}

// newTrojanClientDialer builds the dae-side dialer chain for trojan:
// direct -> transport/tls -> trojanc.
func newTrojanClientDialer(t *testing.T, proxyAddr, password string) netproxy.Dialer {
	t.Helper()
	direct, _ := dialer.NewDirectDialer(&dialer.ExtraOption{}, false)
	tlsDialer, _, err := tls2.NewTls(&dialer.ExtraOption{
		AllowInsecure:     true,
		TlsImplementation: "tls",
	}, direct, "tls://"+proxyAddr+"?sni=127.0.0.1&allowInsecure=1")
	if err != nil {
		t.Fatalf("tls dialer: %v", err)
	}
	d, err := protocol.NewDialer("trojanc", tlsDialer, protocol.Header{
		IsClient:     true,
		ProxyAddress: proxyAddr,
		Password:     password,
	})
	if err != nil {
		t.Fatalf("trojanc dialer: %v", err)
	}
	return d
}

// verifyRelayRoundTrip writes a large deterministic payload through c, reads it
// back, and checks integrity. Large enough to cross record/buffer boundaries.
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
		// Verify every byte, which also crosses record and buffer boundaries.
		for i := 0; i < n; i++ {
			if want := byte(((got + i) % len(payload)) * 7); buf[i] != want {
				t.Fatalf("payload mismatch at %d: got %#x want %#x", got+i, buf[i], want)
			}
		}
		got += n
	}
}

// ---- the e2e tests ----

// TestE2ETrojanTCPRelay pushes 4MiB through client -> trojan server -> echo
// target -> back over a real TLS session, then half-closes and expects EOF.
func TestE2ETrojanTCPRelay(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startTrojanServer(t, "trojan-password", false)
	d := newTrojanClientDialer(t, proxyAddr, "trojan-password")

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	verifyRelayRoundTrip(t, c, 4<<20)

	// Half-close must propagate: server relays our FIN to the echo target,
	// the target finishes and closes, and we see EOF. CloseWrite is an
	// optional capability, so losing it to a wrapper must fail this e2e
	// instead of silently skipping the check.
	closeWrite, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("trojanc conn %T lost the CloseWrite capability", c)
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

// TestE2ETrojanUDPRelay exercises UDP over the trojan stream: framed
// datagrams to two different echo targets, integrity and source address.
func TestE2ETrojanUDPRelay(t *testing.T) {
	udpEcho := startUDPEchoTarget(t)
	proxyAddr := startTrojanServer(t, "trojan-password", false)
	d := newTrojanClientDialer(t, proxyAddr, "trojan-password")

	ctx := deadlineCtx(t)
	pc, err := d.DialContext(ctx, "udp", udpEcho.String())
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer pc.Close()

	packetConn, ok := pc.(netproxy.PacketConn)
	if !ok {
		t.Fatalf("DialContext(udp) returned %T, want a PacketConn", pc)
	}
	for i := 0; i < 16; i++ {
		payload := make([]byte, 200+i*31)
		for j := range payload {
			payload[j] = byte(i + j)
		}
		if _, err := packetConn.WriteTo(payload, udpEcho.String()); err != nil {
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
		if from.String() != udpEcho.String() {
			t.Fatalf("datagram %d source = %v, want %v", i, from, udpEcho.String())
		}
	}
}

// TestE2ETrojanBadPasswordIsAnErrorNotAPanic checks the auth-failure path.
func TestE2ETrojanBadPasswordIsAnErrorNotAPanic(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startTrojanServer(t, "correct-horse", true)
	d := newTrojanClientDialer(t, proxyAddr, "correct-horse")

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// The server will close on us; some write or read must surface an error.
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
