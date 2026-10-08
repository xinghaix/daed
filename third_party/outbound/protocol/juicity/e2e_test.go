package juicity_test

// True end-to-end coverage for the Juicity client stack: an in-test Juicity
// server (own wire-format implementation, not a copy of protocol/juicity)
// speaking QUIC on a real loopback UDP socket, fronting real loopback echo
// targets, reached through the same dialer chain dae builds (juicity:// link
// parser -> protocol.NewDialer("juicity") -> direct UDP transport).
//
// The server mirrors exactly what this repo's client puts on the wire:
//   - One unidirectional stream carries the tuic-style Authenticate command
//     (VER=0, TYPE=0, UUID[16], TOKEN[32]) where the token is the TLS 1.3
//     exporter value over the raw UUID bytes with the password as context,
//     optionally followed by underlay-authentication records
//     (IV[32] || PSK[32] || trojan-style metadata) used by the full-cone
//     UDP underlay. This e2e drives none of those records, but the server
//     still drains them so the client's auth writer can never block.
//   - Each bidirectional stream opens with a network byte (0x01 tcp,
//     0x03 udp) plus a trojan-style metadata header. TCP sessions then relay
//     raw bytes; UDP sessions carry datagram frames
//     (metadata || uint16 big-endian length || payload) in both directions,
//     with the reply address being the observed datagram source.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	outbounderrors "github.com/daeuniverse/outbound/common/errors"
	"github.com/daeuniverse/outbound/dialer"
	juicitylink "github.com/daeuniverse/outbound/dialer/juicity"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/olicesx/quic-go"
)

// ---- shared helpers (the per-protocol e2e convention) ----

const (
	e2eJuicityUUIDStr  = "5b8f39d0-3c86-4f76-9a52-7de21c4b0aa3"
	e2eJuicityPassword = "juicity-e2e-password"
)

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

// startOneShotTarget serves exactly one connection, writes payload, and
// closes; used to prove a server-initiated FIN reaches the client as EOF.
func startOneShotTarget(t *testing.T, payload []byte) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("one-shot listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write(payload)
		_ = c.Close()
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

// e2eSelfSignedCert mints the server certificate for the in-test QUIC
// listener; the client is configured allowInsecure, so verification is
// skipped and the cert only has to be a valid TLS 1.3 certificate.
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

// deadlineCtx bounds every dial in the e2e so a hung protocol layer fails
// the test instead of hanging it.
func deadlineCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// ---- in-test Juicity server (independent wire-format implementation) ----

// Juicity wire constants, restated from the protocol rather than imported,
// so the server is an independent implementation of the spec. Note the
// address types follow the trojan convention (domain=3), unlike tuic v5.
const (
	juicityVer0               byte = 0x00
	juicityCmdAuthenticate    byte = 0x00
	juicityNetworkTCP         byte = 0x01
	juicityNetworkUDP         byte = 0x03
	juicityAtypIPv4           byte = 1
	juicityAtypMsg            byte = 2
	juicityAtypDomain         byte = 3
	juicityAtypIPv6           byte = 4
	juicityUnderlaySaltAndKey      = 32 + 32 // IV || PSK per underlay-auth record

	juicityAuthFailedCode  = quic.ApplicationErrorCode(0xfffffff1)
	juicityAuthTimeoutCode = quic.ApplicationErrorCode(0xfffffff2)
	juicityBadCommandCode  = quic.ApplicationErrorCode(0xfffffff3)
)

// readJuicityMetadata decodes a trojan-style metadata header:
// TYPE ADDR PORT (ipv4: 4+2, ipv6: 16+2, domain: 1+len+2, msg: 1).
func readJuicityMetadata(r *bufio.Reader) (host string, port uint16, err error) {
	typ, err := r.ReadByte()
	if err != nil {
		return "", 0, err
	}
	switch typ {
	case juicityAtypIPv4:
		var raw [6]byte
		if _, err = io.ReadFull(r, raw[:]); err != nil {
			return "", 0, err
		}
		return net.IP(raw[:4]).String(), binary.BigEndian.Uint16(raw[4:]), nil
	case juicityAtypIPv6:
		var raw [18]byte
		if _, err = io.ReadFull(r, raw[:]); err != nil {
			return "", 0, err
		}
		return net.IP(raw[:16]).String(), binary.BigEndian.Uint16(raw[16:]), nil
	case juicityAtypDomain:
		var l [1]byte
		if _, err = io.ReadFull(r, l[:]); err != nil {
			return "", 0, err
		}
		raw := make([]byte, int(l[0])+2)
		if _, err = io.ReadFull(r, raw); err != nil {
			return "", 0, err
		}
		return string(raw[:l[0]]), binary.BigEndian.Uint16(raw[l[0]:]), nil
	case juicityAtypMsg:
		var cmd [1]byte
		if _, err = io.ReadFull(r, cmd[:]); err != nil {
			return "", 0, err
		}
		return "", 0, nil
	default:
		return "", 0, fmt.Errorf("juicity e2e server: unsupported metadata type %#x", typ)
	}
}

// buildJuicityDatagramFrame frames one datagram from the UDP target back to
// the client: metadata (observed source address) || length || payload. The
// client's ReadFrom validates the address as the datagram's true source.
func buildJuicityDatagramFrame(data []byte, from *net.UDPAddr) []byte {
	frame := make([]byte, 0, 21+len(data))
	if ip := from.IP.To4(); ip != nil {
		frame = append(frame, juicityAtypIPv4)
		frame = append(frame, ip...)
	} else {
		frame = append(frame, juicityAtypIPv6)
		frame = append(frame, from.IP.To16()...)
	}
	frame = binary.BigEndian.AppendUint16(frame, uint16(from.Port))
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(data)))
	return append(frame, data...)
}

// juicityE2EServer is the in-test Juicity server: a real QUIC listener on a
// real loopback UDP socket.
type juicityE2EServer struct {
	listener *quic.Listener
	password string

	// udpDests records every per-frame destination the server relayed a
	// datagram to, so a test can prove ingress addressing at the server,
	// not only at the echo targets.
	udpDests sync.Map

	conns sync.Map
	done  chan struct{}
}

// startJuicityE2EServer runs the in-test Juicity server on a real loopback
// UDP socket.
func startJuicityE2EServer(t *testing.T, password string) *juicityE2EServer {
	t.Helper()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{e2eSelfSignedCert(t)},
		NextProtos:   []string{"h3"},
		MinVersion:   tls.VersionTLS13,
	}, &quic.Config{
		// This client keeps EnableDatagrams off (streams carry everything),
		// so the listener needs no datagram support either.
		EnableDatagrams: false,
		MaxIdleTimeout:  30 * time.Second,
	})
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	s := &juicityE2EServer{
		listener: listener,
		password: password,
		done:     make(chan struct{}),
	}
	t.Cleanup(s.Close)
	go func() {
		defer close(s.done)
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			s.conns.Store(conn, struct{}{})
			go s.serveConn(conn)
		}
	}()
	return s
}

func (s *juicityE2EServer) Addr() string {
	return s.listener.Addr().String()
}

func (s *juicityE2EServer) Close() {
	_ = s.listener.Close()
	s.conns.Range(func(key, _ any) bool {
		_ = key.(quic.Connection).CloseWithError(juicityBadCommandCode, "test shutdown")
		s.conns.Delete(key)
		return true
	})
	<-s.done
}

func (s *juicityE2EServer) serveConn(conn quic.Connection) {
	defer s.conns.Delete(conn)
	authOK := make(chan struct{})
	var authOnce sync.Once
	go s.serveUniStreams(conn, authOK, &authOnce)
	s.serveRelayStreams(conn, authOK)
}

// serveUniStreams handles the authentication stream: the Authenticate
// command followed by (unused here) underlay-authentication records.
func (s *juicityE2EServer) serveUniStreams(conn quic.Connection, authOK chan struct{}, authOnce *sync.Once) {
	for {
		stream, err := conn.AcceptUniStream(conn.Context())
		if err != nil {
			return
		}
		s.handleAuthStream(conn, stream, authOK, authOnce)
	}
}

func (s *juicityE2EServer) handleAuthStream(conn quic.Connection, stream quic.ReceiveStream, authOK chan struct{}, authOnce *sync.Once) {
	defer stream.CancelRead(0)
	reader := bufio.NewReaderSize(stream, 16<<10)
	ver, err := reader.ReadByte()
	if err != nil {
		return
	}
	if ver != juicityVer0 {
		_ = conn.CloseWithError(juicityBadCommandCode, fmt.Sprintf("bad version %#x", ver))
		return
	}
	typ, err := reader.ReadByte()
	if err != nil {
		return
	}
	if typ != juicityCmdAuthenticate {
		_ = conn.CloseWithError(juicityBadCommandCode, fmt.Sprintf("unexpected uni command %#x", typ))
		return
	}
	var uuidBytes [16]byte
	var token [32]byte
	if _, err := io.ReadFull(reader, uuidBytes[:]); err != nil {
		_ = conn.CloseWithError(juicityBadCommandCode, fmt.Sprintf("read uuid: %v", err))
		return
	}
	if _, err := io.ReadFull(reader, token[:]); err != nil {
		_ = conn.CloseWithError(juicityBadCommandCode, fmt.Sprintf("read token: %v", err))
		return
	}
	authOnce.Do(func() {
		// The token is the TLS 1.3 exporter value over the raw UUID bytes
		// with the password as context; both sides derive it from the
		// negotiated keys, so no secret crosses the wire. A wrong client
		// password produces a different token and is rejected here.
		tlsState := conn.ConnectionState().TLS
		expected, err := tlsState.ExportKeyingMaterial(string(uuidBytes[:]), []byte(s.password), 32)
		if err != nil || !bytes.Equal(token[:], expected) {
			_ = conn.CloseWithError(juicityAuthFailedCode, "invalid credentials")
			return
		}
		close(authOK)
	})
	// Drain what follows: the client appends underlay-authentication
	// records (IV[32] || PSK[32] || trojan-style metadata) to this same
	// stream when it opens the full-cone UDP underlay. This e2e exercises
	// none of those records, but they must be consumed so the client's
	// auth writer can never block on flow control.
	for {
		var ivpsk [juicityUnderlaySaltAndKey]byte
		if _, err := io.ReadFull(reader, ivpsk[:]); err != nil {
			return // EOF or reset: normal end of the auth stream
		}
		if _, _, err := readJuicityMetadata(reader); err != nil {
			return
		}
	}
}

// serveRelayStreams handles bidirectional relay streams (tcp connect and
// udp datagram sessions).
func (s *juicityE2EServer) serveRelayStreams(conn quic.Connection, authOK chan struct{}) {
	for {
		stream, err := conn.AcceptStream(conn.Context())
		if err != nil {
			return
		}
		go s.handleRelayStream(conn, stream, authOK)
	}
}

func (s *juicityE2EServer) handleRelayStream(conn quic.Connection, stream quic.Stream, authOK chan struct{}) {
	reader := bufio.NewReaderSize(stream, 16<<10)
	network, err := reader.ReadByte()
	if err != nil {
		stream.CancelRead(0)
		return
	}
	if network != juicityNetworkTCP && network != juicityNetworkUDP {
		_ = conn.CloseWithError(juicityBadCommandCode, fmt.Sprintf("unexpected stream network %#x", network))
		return
	}
	// Gate: relay nothing before the peer authenticated.
	select {
	case <-authOK:
	case <-conn.Context().Done():
		return
	case <-time.After(10 * time.Second):
		_ = conn.CloseWithError(juicityAuthTimeoutCode, "authentication timeout")
		return
	}
	sessionHost, sessionPort, err := readJuicityMetadata(reader)
	if err != nil {
		_ = conn.CloseWithError(juicityBadCommandCode, fmt.Sprintf("read session metadata: %v", err))
		return
	}
	if network == juicityNetworkTCP {
		s.relayTCP(stream, reader, sessionHost, sessionPort)
		return
	}
	s.relayUDP(conn, stream, reader)
}

// relayTCP connects to the session destination and relays both directions.
// Half-close semantics of Juicity over QUIC streams: the client's
// CloseWrite is a QUIC FIN, relayed here as a TCP half-close to the target;
// the target's EOF propagates back as a QUIC FIN (io.EOF on the client).
func (s *juicityE2EServer) relayTCP(stream quic.Stream, reader *bufio.Reader, host string, port uint16) {
	target, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), 10*time.Second)
	if err != nil {
		// Juicity defines no CONNECT status frame: stop both directions and
		// let the stream die, exactly like the reference servers.
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return
	}
	defer target.Close()
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		_, _ = io.Copy(target, reader)
		// Propagate the client's half-close (QUIC FIN) to the real target.
		if tcp, ok := target.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	_, _ = io.Copy(stream, target)
	// Propagate the target's EOF to the client as a QUIC FIN.
	_ = stream.Close()
	<-upstreamDone
	stream.CancelRead(0)
}

// relayUDP runs one datagram session over the bidirectional stream: each
// inbound frame names its own destination; outbound frames carry the
// observed datagram source as the reply address.
func (s *juicityE2EServer) relayUDP(conn quic.Connection, stream quic.Stream, reader *bufio.Reader) {
	localIP := net.IPv4(127, 0, 0, 1)
	if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok && ua.IP != nil {
		localIP = ua.IP
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIP})
	if err != nil {
		return
	}
	defer udp.Close()
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		buf := make([]byte, 65535)
		for {
			n, from, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			frame := buildJuicityDatagramFrame(buf[:n], from)
			if _, err := stream.Write(frame); err != nil {
				return
			}
		}
	}()
	for {
		host, port, err := readJuicityMetadata(reader)
		if err != nil {
			break
		}
		var lenBuf [2]byte
		if _, err = io.ReadFull(reader, lenBuf[:]); err != nil {
			break
		}
		length := int(binary.BigEndian.Uint16(lenBuf[:]))
		payload := make([]byte, length)
		if _, err = io.ReadFull(reader, payload); err != nil {
			break
		}
		ra, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		if err != nil {
			break
		}
		s.udpDests.Store(ra.String(), struct{}{})
		if _, err := udp.WriteToUDP(payload, ra); err != nil {
			break
		}
	}
	// Inbound side is over; stop the reply pump and the stream. The client
	// sees its reads fail once the session is torn down.
	stream.CancelRead(0)
	_ = udp.Close()
	<-pumpDone
	_ = stream.Close()
}

// ---- client construction (exactly the way the consumer builds it) ----

// newJuicityE2EDialerFromLink builds the dae-side dialer from a juicity://
// link: ParseJuicityURL -> Juicity.Dialer -> protocol.NewDialer("juicity")
// over the direct UDP transport. NewJuicity is the exact creator the
// consumer drives through FromLinkRegister("juicity"); calling it directly
// only skips the registry lookup, not any protocol behavior.
func newJuicityE2EDialerFromLink(t *testing.T, proxyAddr, uuidStr, password string) netproxy.Dialer {
	t.Helper()
	link := fmt.Sprintf("juicity://%s:%s@%s?allow_insecure=1&sni=127.0.0.1&congestion_control=bbr",
		uuidStr, url.QueryEscape(password), proxyAddr)
	d, _, err := juicitylink.NewJuicity(&dialer.ExtraOption{AllowInsecure: true}, direct.SymmetricDirect, link)
	if err != nil {
		t.Fatalf("juicity dialer from link: %v", err)
	}
	if closer, ok := d.(interface{ Close() error }); ok {
		t.Cleanup(func() { _ = closer.Close() })
	}
	return d
}

// verifyRelayRoundTrip writes a large deterministic payload through c while
// concurrently reading it back and checking every byte (write+read race on
// the same conn, crossing flow-control, QUIC packet, and relay buffer
// boundaries).
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

// ---- the e2e tests ----

// TestE2EJuicityTCPRelay pushes 4MiB through client -> Juicity CONNECT
// stream -> echo target -> back over a real QUIC connection with concurrent
// write and read, then half-closes and expects the target's EOF.
func TestE2EJuicityTCPRelay(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startJuicityE2EServer(t, e2eJuicityPassword).Addr()
	d := newJuicityE2EDialerFromLink(t, proxyAddr, e2eJuicityUUIDStr, e2eJuicityPassword)

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	verifyRelayRoundTrip(t, c, 4<<20)

	// Half-close must propagate: the server relays our FIN to the echo
	// target, the target finishes and closes, and we see EOF. CloseWrite is
	// an optional capability, so losing it to a wrapper must fail this e2e
	// instead of silently skipping the check.
	closeWrite, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("juicity conn %T lost the CloseWrite capability", c)
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

// TestE2EJuicityTCPMultiplexedStreams opens several relay streams at once
// over the single shared QUIC tunnel the juicity client keeps (clientRing
// dedupes the QUIC connection across dials) and verifies each payload
// byte-exact while writes and reads run concurrently on every stream.
func TestE2EJuicityTCPMultiplexedStreams(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startJuicityE2EServer(t, e2eJuicityPassword).Addr()
	d := newJuicityE2EDialerFromLink(t, proxyAddr, e2eJuicityUUIDStr, e2eJuicityPassword)

	ctx := deadlineCtx(t)
	const streams = 4
	const perStream = 512 << 10
	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func(streamIdx int) {
			defer wg.Done()
			c, err := d.DialContext(ctx, "tcp", echoAddr.String())
			if err != nil {
				t.Errorf("stream %d dial: %v", streamIdx, err)
				return
			}
			defer c.Close()
			if err := c.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
				t.Errorf("stream %d SetDeadline: %v", streamIdx, err)
				return
			}
			chunk := make([]byte, 32<<10)
			for j := range chunk {
				chunk[j] = byte(uint32(j)*7 + uint32(streamIdx)*29)
			}
			sent := 0
			go func() {
				for sent < perStream {
					n := len(chunk)
					if perStream-sent < n {
						n = perStream - sent
					}
					if _, err := c.Write(chunk[:n]); err != nil {
						return
					}
					sent += n
				}
			}()
			got := 0
			buf := make([]byte, 32<<10)
			for got < perStream {
				n, err := c.Read(buf)
				if err != nil {
					t.Errorf("stream %d read at %d/%d: %v", streamIdx, got, perStream, err)
					return
				}
				for k := 0; k < n; k++ {
					if want := byte(uint32(got+k)*7 + uint32(streamIdx)*29); buf[k] != want {
						t.Errorf("stream %d payload mismatch at %d", streamIdx, got+k)
						return
					}
				}
				got += n
			}
		}(i)
	}
	wg.Wait()
}

// TestE2EJuicityUDPRelay pushes datagrams through the Juicity stream-based
// UDP relay (this client keeps QUIC datagrams disabled and frames every
// datagram on a bidirectional stream) to two different loopback echo
// targets, checking integrity, framing of a large datagram, and that each
// reply carries the real source address of its target. The server also
// records the per-frame destinations it relayed to, so ingress addressing
// is proven at the relay itself.
func TestE2EJuicityUDPRelay(t *testing.T) {
	echoA := startUDPEchoTarget(t)
	echoB := startUDPEchoTarget(t)
	targets := []net.Addr{echoA, echoB}
	srv := startJuicityE2EServer(t, e2eJuicityPassword)
	proxyAddr := srv.Addr()
	d := newJuicityE2EDialerFromLink(t, proxyAddr, e2eJuicityUUIDStr, e2eJuicityPassword)

	ctx := deadlineCtx(t)
	pc, err := d.DialContext(ctx, "udp", echoA.String())
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer pc.Close()

	packetConn, ok := pc.(netproxy.PacketConn)
	if !ok {
		t.Fatalf("DialContext(udp) returned %T, want a PacketConn", pc)
	}
	// Datagram sizes stay within 1200 bytes: this sandbox's loopback drops
	// UDP datagrams beyond a single ~1500-byte packet (1472-byte payload
	// passes, 2000 does not), an environment property unrelated to the
	// protocol - the stream framing itself carries uint16 lengths up to
	// 65535 and the AEAD underlay uses the same 64KiB frame cap.
	for i := 0; i < 8; i++ {
		for _, target := range targets {
			size := 200 + i*31
			if i == 0 && target == echoA {
				size = 1200
			}
			payload := make([]byte, size)
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
				t.Fatalf("datagram %d to %v mismatch: n=%d", i, target, n)
			}
			want := netip.MustParseAddrPort(target.String())
			if from != want {
				t.Fatalf("datagram %d source = %v, want %v", i, from, want)
			}
		}
	}
	// Ingress addressing: the relay must have delivered to both targets.
	for _, target := range targets {
		if _, ok := srv.udpDests.Load(target.String()); !ok {
			t.Fatalf("server never relayed a datagram to %v", target)
		}
	}
}

// assertAuthRejectedOrClientClosed proves a surfaced error is the server's
// credential rejection (the AuthenticationFailed application error code)
// or the client's own clean "tunnel torn down by that rejection" state -
// never the caller's deadline, which would mean the client hung.
func assertAuthRejectedOrClientClosed(t *testing.T, err error) {
	t.Helper()
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		if appErr.ErrorCode != juicityAuthFailedCode {
			t.Fatalf("surfaced application error code = %#x (%s), want AuthenticationFailed %#x",
				appErr.ErrorCode, appErr.ErrorMessage, juicityAuthFailedCode)
		}
		return
	}
	if errors.Is(err, outbounderrors.ErrClientClosed) {
		// The server closed the QUIC connection mid-handshake-of-sorts; the
		// client detached the tunnel. Bounded and clean: acceptable.
		return
	}
	t.Fatalf("surfaced error %v (%T) is neither the AuthenticationFailed application error nor ErrClientClosed", err, err)
}

// TestE2EJuicityWrongPasswordIsAnErrorNotAPanic checks the auth-failure
// path: juicity has no PSK on the wire - the password feeds the TLS exporter
// token - so a wrong password yields a token the server rejects by closing
// the QUIC connection with the AuthenticationFailed application error code.
// The client must surface that error - at dial time or on the first
// write/read (the rejection races the first relay stream) - without
// panicking or hanging.
func TestE2EJuicityWrongPasswordIsAnErrorNotAPanic(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startJuicityE2EServer(t, e2eJuicityPassword).Addr()
	d := newJuicityE2EDialerFromLink(t, proxyAddr, e2eJuicityUUIDStr, "not-the-password")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, dialErr := d.DialContext(ctx, "tcp", echoAddr.String())
	if dialErr != nil {
		if errors.Is(dialErr, context.DeadlineExceeded) {
			t.Fatalf("dial hung until the caller deadline instead of surfacing the rejection: %v", dialErr)
		}
		assertAuthRejectedOrClientClosed(t, dialErr)
		return
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	var surfaced error
	if _, err := c.Write([]byte("authenticate me")); err != nil {
		surfaced = err
	} else {
		deadline := time.Now().Add(5 * time.Second)
		buf := make([]byte, 128)
		for time.Now().Before(deadline) {
			if _, err := c.Read(buf); err != nil {
				surfaced = err
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	if surfaced == nil {
		t.Fatal("server rejected the credentials but the client never surfaced an error")
	}
	assertAuthRejectedOrClientClosed(t, surfaced)
}

// TestE2EJuicityCloseSemantics documents and verifies the close semantics of
// the Juicity stream relay:
//
//   - Client half-close IS expressible: Conn.CloseWrite sends a QUIC FIN
//     (the embedded stream's send side only), the server relays it as a TCP
//     half-close to the target, the target's EOF comes back as a QUIC FIN,
//     and the client keeps reading the whole time.
//   - Server half-close IS expressible the same way in reverse: a target
//     close propagates as io.EOF on the client while the client may keep
//     writing.
//   - Full Conn.Close is an abort, not a graceful close: it calls
//     CancelRead(0) and closes the stream, so buffered peer data is
//     discarded; there is no Juicity-level session teardown frame.
func TestE2EJuicityCloseSemantics(t *testing.T) {
	t.Run("server fin reaches client as io.EOF", func(t *testing.T) {
		goodbye := []byte("goodbye from the target")
		target := startOneShotTarget(t, goodbye)
		proxyAddr := startJuicityE2EServer(t, e2eJuicityPassword).Addr()
		d := newJuicityE2EDialerFromLink(t, proxyAddr, e2eJuicityUUIDStr, e2eJuicityPassword)

		ctx := deadlineCtx(t)
		c, err := d.DialContext(ctx, "tcp", target.String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		got := make([]byte, len(goodbye)+1)
		n, err := io.ReadFull(c, got[:len(goodbye)])
		if err != nil {
			t.Fatalf("read payload: %v (n=%d)", err, n)
		}
		if !bytes.Equal(got[:n], goodbye) {
			t.Fatalf("payload mismatch: got %q", got[:n])
		}
		// The target closed: the server's QUIC FIN must surface as io.EOF,
		// not as an abort error, even though the client never half-closed.
		if _, err := c.Read(got); !errors.Is(err, io.EOF) {
			t.Fatalf("read after target close = %v, want io.EOF", err)
		}
	})

	t.Run("client half-close keeps read side alive", func(t *testing.T) {
		echoAddr := loopbackEchoTarget(t)
		proxyAddr := startJuicityE2EServer(t, e2eJuicityPassword).Addr()
		d := newJuicityE2EDialerFromLink(t, proxyAddr, e2eJuicityUUIDStr, e2eJuicityPassword)

		ctx := deadlineCtx(t)
		c, err := d.DialContext(ctx, "tcp", echoAddr.String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()

		request := []byte("half-close-ping")
		if err := c.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatalf("SetDeadline: %v", err)
		}
		if _, err := c.Write(request); err != nil {
			t.Fatalf("write: %v", err)
		}
		closeWrite, ok := c.(interface{ CloseWrite() error })
		if !ok {
			t.Fatalf("juicity conn %T lost the CloseWrite capability", c)
		}
		if err := closeWrite.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
		// Writes after the half-close must fail: the send side is closed.
		if _, err := c.Write([]byte("must fail")); err == nil {
			t.Fatal("write after CloseWrite succeeded, want an error")
		}
		// The read side is still open: the echo comes back and the
		// propagated target close ends it with io.EOF.
		echo := make([]byte, len(request))
		if _, err := io.ReadFull(c, echo); err != nil {
			t.Fatalf("read echo after half-close: %v", err)
		}
		if !bytes.Equal(echo, request) {
			t.Fatalf("echo mismatch: got %q", echo)
		}
		if _, err := c.Read(echo); !errors.Is(err, io.EOF) {
			t.Fatalf("final read = %v, want io.EOF", err)
		}
	})
}
