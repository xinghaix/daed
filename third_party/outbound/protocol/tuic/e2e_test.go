package tuic_test

// True end-to-end coverage for the TUIC v5 client stack: an in-test TUIC v5
// server (own wire-format implementation, not a copy of protocol/tuic)
// speaking QUIC with datagrams on a real loopback UDP socket, fronting real
// loopback echo targets, reached through the same dialer chain dae builds
// (tuic:// link parser -> protocol.NewDialer("tuic") -> direct UDP transport).
//
// The server authenticates the client exactly as TUIC v5 defines it: the
// client sends an Authenticate command (UUID + 32-byte token) on a uni
// stream, where the token is the TLS 1.3 exporter value over the raw UUID
// bytes with the password as context. Only after a valid token does the
// server relay CONNECT bidirectional streams and Packet datagrams.

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	tuiclink "github.com/daeuniverse/outbound/dialer/tuic"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/olicesx/quic-go"
)

// ---- shared helpers (the per-protocol e2e convention) ----

const (
	e2eTUICUUIDStr  = "b0f5a04f-6a33-4bd5-9f31-3fa5c39f2c10"
	e2eTUICPassword = "tuic-e2e-password"
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

// ---- in-test TUIC v5 server (independent wire-format implementation) ----

// TUIC v5 wire constants, restated from the protocol rather than imported,
// so the server is an independent implementation of the spec.
const (
	tuicVer5 byte = 0x05

	tuicCmdAuthenticate byte = 0x00
	tuicCmdConnect      byte = 0x01
	tuicCmdPacket       byte = 0x02
	tuicCmdDissociate   byte = 0x03
	tuicCmdHeartbeat    byte = 0x04

	tuicAtypDomain byte = 0x00
	tuicAtypIPv4   byte = 0x01
	tuicAtypIPv6   byte = 0x02
	tuicAtypNone   byte = 0xff
)

const (
	tuicAuthFailedCode  = quic.ApplicationErrorCode(0xfffffff1)
	tuicAuthTimeoutCode = quic.ApplicationErrorCode(0xfffffff2)
	tuicBadCommandCode  = quic.ApplicationErrorCode(0xfffffff3)
)

// readTUICCommandHead reads the VER + TYPE pair every v5 command starts with.
func readTUICCommandHead(r io.ByteReader) (ver, typ byte, err error) {
	if ver, err = r.ReadByte(); err != nil {
		return 0, 0, err
	}
	if typ, err = r.ReadByte(); err != nil {
		return 0, 0, err
	}
	return ver, typ, nil
}

// readTUICAddress decodes ATYP + address + port.
func readTUICAddress(r io.ByteReader) (host string, port uint16, err error) {
	atyp, err := r.ReadByte()
	if err != nil {
		return "", 0, err
	}
	full, ok := r.(io.Reader)
	if !ok {
		return "", 0, errors.New("tuic e2e server: reader does not implement io.Reader")
	}
	switch atyp {
	case tuicAtypIPv4:
		var raw [6]byte
		if _, err = io.ReadFull(full, raw[:]); err != nil {
			return "", 0, err
		}
		return net.IP(raw[:4]).String(), binary.BigEndian.Uint16(raw[4:]), nil
	case tuicAtypIPv6:
		var raw [18]byte
		if _, err = io.ReadFull(full, raw[:]); err != nil {
			return "", 0, err
		}
		return net.IP(raw[:16]).String(), binary.BigEndian.Uint16(raw[16:]), nil
	case tuicAtypDomain:
		var l [1]byte
		if _, err = io.ReadFull(full, l[:]); err != nil {
			return "", 0, err
		}
		raw := make([]byte, int(l[0])+2)
		if _, err = io.ReadFull(full, raw); err != nil {
			return "", 0, err
		}
		return string(raw[:l[0]]), binary.BigEndian.Uint16(raw[l[0]:]), nil
	default:
		return "", 0, fmt.Errorf("tuic e2e server: unsupported address type %#x", atyp)
	}
}

// tuicE2EPacket is one decoded Packet command.
type tuicE2EPacket struct {
	assocID   uint16
	pktID     uint16
	fragTotal byte
	fragID    byte
	atyp      byte
	host      string
	port      uint16
	data      []byte
}

// parseTUICPacket decodes a Packet command from a QUIC datagram:
// VER TYPE ASSOC_ID(2) PKT_ID(2) FRAG_TOTAL(1) FRAG_ID(1) SIZE(2) ADDR DATA.
func parseTUICPacket(msg []byte) (tuicE2EPacket, error) {
	// VER(1) + TYPE(1) + ASSOC_ID(2) + PKT_ID(2) + FRAG_TOTAL(1) + FRAG_ID(1) + SIZE(2)
	const fixedLen = 10
	var p tuicE2EPacket
	if len(msg) < fixedLen {
		return p, fmt.Errorf("packet too short: %d bytes", len(msg))
	}
	if msg[0] != tuicVer5 {
		return p, fmt.Errorf("bad version %#x", msg[0])
	}
	if msg[1] != tuicCmdPacket {
		return p, fmt.Errorf("not a packet command: %#x", msg[1])
	}
	off := 2
	p.assocID = binary.BigEndian.Uint16(msg[off:])
	off += 2
	p.pktID = binary.BigEndian.Uint16(msg[off:])
	off += 2
	p.fragTotal = msg[off]
	off++
	p.fragID = msg[off]
	off++
	size := int(binary.BigEndian.Uint16(msg[off:]))
	off += 2
	atyp := msg[off]
	off++
	p.atyp = atyp
	switch atyp {
	case tuicAtypIPv4:
		if len(msg) < off+6 {
			return p, io.ErrUnexpectedEOF
		}
		p.host = net.IP(msg[off : off+4]).String()
		p.port = binary.BigEndian.Uint16(msg[off+4:])
		off += 6
	case tuicAtypIPv6:
		if len(msg) < off+18 {
			return p, io.ErrUnexpectedEOF
		}
		p.host = net.IP(msg[off : off+16]).String()
		p.port = binary.BigEndian.Uint16(msg[off+16:])
		off += 18
	case tuicAtypDomain:
		if len(msg) < off+1 {
			return p, io.ErrUnexpectedEOF
		}
		l := int(msg[off])
		off++
		if len(msg) < off+l+2 {
			return p, io.ErrUnexpectedEOF
		}
		p.host = string(msg[off : off+l])
		p.port = binary.BigEndian.Uint16(msg[off+l:])
		off += l + 2
	default:
		return p, fmt.Errorf("unsupported address type %#x", atyp)
	}
	if len(msg) < off+size {
		return p, io.ErrUnexpectedEOF
	}
	p.data = msg[off : off+size]
	return p, nil
}

// buildTUICPacketFrame frames one datagram from the UDP target back to the
// client. The address is the observed datagram source, per the v5 relay
// contract (the client validates it as the reply's source address).
func buildTUICPacketFrame(assocID, pktID uint16, data []byte, from *net.UDPAddr) []byte {
	frame := make([]byte, 0, 12+18+len(data))
	frame = append(frame, tuicVer5, tuicCmdPacket)
	frame = binary.BigEndian.AppendUint16(frame, assocID)
	frame = binary.BigEndian.AppendUint16(frame, pktID)
	frame = append(frame, 1, 0) // FRAG_TOTAL=1, FRAG_ID=0: unfragmented
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(data)))
	if ip := from.IP.To4(); ip != nil {
		frame = append(frame, tuicAtypIPv4)
		frame = append(frame, ip...)
	} else {
		frame = append(frame, tuicAtypIPv6)
		frame = append(frame, from.IP.To16()...)
	}
	frame = binary.BigEndian.AppendUint16(frame, uint16(from.Port))
	return append(frame, data...)
}

// tuicE2EUdpAssoc is one v5 UDP relay association: a real per-association
// UDP socket on loopback plus the datagram pump back to the client.
type tuicE2EUdpAssoc struct {
	conn    quic.Connection
	pc      *net.UDPConn
	assocID uint16
	pktID   atomic.Uint32
}

func (a *tuicE2EUdpAssoc) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, from, err := a.pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		frame := buildTUICPacketFrame(a.assocID, uint16(a.pktID.Add(1)), buf[:n], from)
		if err := a.conn.SendDatagram(frame); err != nil {
			return
		}
	}
}

type tuicE2EServer struct {
	listener   *quic.Listener
	password   string
	rejectAuth bool

	conns sync.Map
	done  chan struct{}
}

// startTUICE2EServer runs the in-test TUIC v5 server on a real loopback UDP
// socket. rejectAuth forces the AuthenticationFailed path regardless of the
// credentials the client presents.
func startTUICE2EServer(t *testing.T, password string, rejectAuth bool) *tuicE2EServer {
	t.Helper()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{e2eSelfSignedCert(t)},
		NextProtos:   []string{"h3"},
		MinVersion:   tls.VersionTLS13,
	}, &quic.Config{
		EnableDatagrams: true,
		Allow0RTT:       true,
		MaxIdleTimeout:  30 * time.Second,
	})
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	s := &tuicE2EServer{
		listener:   listener,
		password:   password,
		rejectAuth: rejectAuth,
		done:       make(chan struct{}),
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

func (s *tuicE2EServer) Addr() string {
	return s.listener.Addr().String()
}

func (s *tuicE2EServer) Close() {
	_ = s.listener.Close()
	s.conns.Range(func(key, _ any) bool {
		_ = key.(quic.Connection).CloseWithError(tuicBadCommandCode, "test shutdown")
		s.conns.Delete(key)
		return true
	})
	<-s.done
}

func (s *tuicE2EServer) serveConn(conn quic.Connection) {
	defer s.conns.Delete(conn)
	authOK := make(chan struct{})
	var authOnce sync.Once
	assocs := &sync.Map{}
	go s.serveUniStreams(conn, authOK, &authOnce, assocs)
	go s.serveConnectStreams(conn, authOK)
	s.serveDatagrams(conn, authOK, assocs)
}

// serveUniStreams handles the uni-stream commands v5 defines: Authenticate
// (credentials), Dissociate (UDP association teardown), plus the datagram
// heartbeat. Anything else is a spec violation.
func (s *tuicE2EServer) serveUniStreams(conn quic.Connection, authOK chan struct{}, authOnce *sync.Once, assocs *sync.Map) {
	for {
		stream, err := conn.AcceptUniStream(conn.Context())
		if err != nil {
			return
		}
		go s.handleUniStream(conn, stream, authOK, authOnce, assocs)
	}
}

func (s *tuicE2EServer) handleUniStream(conn quic.Connection, stream quic.ReceiveStream, authOK chan struct{}, authOnce *sync.Once, assocs *sync.Map) {
	defer stream.CancelRead(0)
	reader := bufio.NewReaderSize(stream, 16<<10)
	ver, typ, err := readTUICCommandHead(reader)
	if err != nil {
		return
	}
	if ver != tuicVer5 {
		_ = conn.CloseWithError(tuicBadCommandCode, fmt.Sprintf("bad version %#x", ver))
		return
	}
	switch typ {
	case tuicCmdAuthenticate:
		var uuidBytes [16]byte
		var token [32]byte
		if _, err := io.ReadFull(reader, uuidBytes[:]); err != nil {
			_ = conn.CloseWithError(tuicBadCommandCode, fmt.Sprintf("read uuid: %v", err))
			return
		}
		if _, err := io.ReadFull(reader, token[:]); err != nil {
			_ = conn.CloseWithError(tuicBadCommandCode, fmt.Sprintf("read token: %v", err))
			return
		}
		authOnce.Do(func() {
			// The v5 token is the TLS 1.3 exporter value over the raw UUID
			// bytes with the password as context; both sides derive it from
			// the negotiated keys, so no secret crosses the wire.
			tlsState := conn.ConnectionState().TLS
			expected, err := tlsState.ExportKeyingMaterial(string(uuidBytes[:]), []byte(s.password), 32)
			if err != nil || s.rejectAuth || !bytes.Equal(token[:], expected) {
				_ = conn.CloseWithError(tuicAuthFailedCode, "invalid credentials")
				return
			}
			close(authOK)
		})
	case tuicCmdDissociate:
		var raw [2]byte
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return
		}
		if val, loaded := assocs.LoadAndDelete(binary.BigEndian.Uint16(raw[:])); loaded {
			_ = val.(*tuicE2EUdpAssoc).pc.Close()
		}
	default:
		_ = conn.CloseWithError(tuicBadCommandCode, fmt.Sprintf("unexpected uni command %#x", typ))
	}
}

// serveConnectStreams handles bidirectional CONNECT streams.
func (s *tuicE2EServer) serveConnectStreams(conn quic.Connection, authOK chan struct{}) {
	for {
		stream, err := conn.AcceptStream(conn.Context())
		if err != nil {
			return
		}
		go s.handleConnect(conn, stream, authOK)
	}
}

func (s *tuicE2EServer) handleConnect(conn quic.Connection, stream quic.Stream, authOK chan struct{}) {
	reader := bufio.NewReaderSize(stream, 16<<10)
	ver, typ, err := readTUICCommandHead(reader)
	if err != nil {
		stream.CancelRead(0)
		return
	}
	if ver != tuicVer5 || typ != tuicCmdConnect {
		_ = conn.CloseWithError(tuicBadCommandCode, fmt.Sprintf("unexpected stream command ver=%#x type=%#x", ver, typ))
		return
	}
	host, port, err := readTUICAddress(reader)
	if err != nil {
		_ = conn.CloseWithError(tuicBadCommandCode, err.Error())
		return
	}
	// v5 gate: relay nothing before the peer authenticated.
	select {
	case <-authOK:
	case <-conn.Context().Done():
		return
	case <-time.After(10 * time.Second):
		_ = conn.CloseWithError(tuicAuthTimeoutCode, "authentication timeout")
		return
	}
	target, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), 10*time.Second)
	if err != nil {
		// v5 defines no CONNECT failure response: stop both directions and
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
	// Propagate the target's EOF to the client as a QUIC FIN. TUIC v5 rides
	// QUIC streams, so this half-close IS expressible end to end.
	_ = stream.Close()
	<-upstreamDone
	stream.CancelRead(0)
}

// serveDatagrams handles the v5 datagram channel: Packet commands relay
// through a real per-association UDP socket; heartbeats are accepted and
// need no answer.
func (s *tuicE2EServer) serveDatagrams(conn quic.Connection, authOK chan struct{}, assocs *sync.Map) {
	for {
		msg, err := conn.ReceiveDatagram(conn.Context())
		if err != nil {
			return
		}
		s.handleDatagram(conn, msg, authOK, assocs)
		// handleDatagram copies everything it keeps before returning, so the
		// pooled datagram buffer can go straight back.
		conn.ReleaseDatagram(msg)
	}
}

func (s *tuicE2EServer) handleDatagram(conn quic.Connection, msg []byte, authOK chan struct{}, assocs *sync.Map) {
	if len(msg) < 2 {
		return
	}
	if msg[0] != tuicVer5 {
		_ = conn.CloseWithError(tuicBadCommandCode, fmt.Sprintf("bad version %#x", msg[0]))
		return
	}
	switch msg[1] {
	case tuicCmdHeartbeat:
		// v5 clients may heartbeat on the datagram channel; nothing to answer.
		return
	case tuicCmdPacket:
	default:
		_ = conn.CloseWithError(tuicBadCommandCode, fmt.Sprintf("unexpected datagram command %#x", msg[1]))
		return
	}
	pkt, err := parseTUICPacket(msg)
	if err != nil {
		_ = conn.CloseWithError(tuicBadCommandCode, err.Error())
		return
	}
	select {
	case <-authOK:
	case <-conn.Context().Done():
		return
	case <-time.After(10 * time.Second):
		_ = conn.CloseWithError(tuicAuthTimeoutCode, "authentication timeout")
		return
	}
	assocVal, loaded := assocs.Load(pkt.assocID)
	if !loaded {
		localIP := net.IPv4(127, 0, 0, 1)
		if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok && ua.IP != nil {
			localIP = ua.IP
		}
		pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIP})
		if err != nil {
			return
		}
		assoc := &tuicE2EUdpAssoc{conn: conn, pc: pc, assocID: pkt.assocID}
		actual, existed := assocs.LoadOrStore(pkt.assocID, assoc)
		if existed {
			_ = pc.Close()
			assocVal = actual
		} else {
			go assoc.readLoop()
			assocVal = assoc
		}
	}
	ra, err := net.ResolveUDPAddr("udp", net.JoinHostPort(pkt.host, strconv.Itoa(int(pkt.port))))
	if err != nil {
		return
	}
	if _, err := assocVal.(*tuicE2EUdpAssoc).pc.WriteToUDP(pkt.data, ra); err != nil {
		return
	}
}

// ---- client construction (exactly the way the consumer builds it) ----

// newTuicE2EDialerFromLink builds the dae-side dialer from a tuic:// link:
// ParseTuicURL -> Tuic.Dialer -> protocol.NewDialer("tuic") over the direct
// UDP transport. NewTuic is the exact creator the consumer drives through
// FromLinkRegister("tuic"); calling it directly only skips the registry
// lookup, not any protocol behavior.
func newTuicE2EDialerFromLink(t *testing.T, proxyAddr, uuidStr, password string) netproxy.Dialer {
	t.Helper()
	link := fmt.Sprintf("tuic://%s:%s@%s?allow_insecure=1&sni=127.0.0.1&alpn=h3&congestion_control=bbr&udp_relay_mode=native",
		uuidStr, url.QueryEscape(password), proxyAddr)
	d, _, err := tuiclink.NewTuic(&dialer.ExtraOption{}, direct.SymmetricDirect, link)
	if err != nil {
		t.Fatalf("tuic dialer from link: %v", err)
	}
	if closer, ok := d.(interface{ Close() error }); ok {
		t.Cleanup(func() { _ = closer.Close() })
	}
	return d
}

// verifyRelayRoundTrip writes a large deterministic payload through c, reads
// it back, and checks every byte. Large enough to cross flow-control, QUIC
// packet, and relay buffer boundaries.
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

// TestE2ETuicTCPRelay pushes 4MiB through client -> TUIC v5 CONNECT stream ->
// echo target -> back over a real QUIC connection, then half-closes and
// expects the target's EOF. Half-close semantics of TUIC v5: because CONNECT
// rides a QUIC bidirectional stream, a client-side half-close IS expressible
// (the client's CloseWrite sends a QUIC FIN, the server relays it as a TCP
// half-close to the target, and the target's EOF propagates back as io.EOF
// on the client). What v5 cannot express: there is no CONNECT response or
// status frame, so a refused target never fails at dial time - it surfaces
// only as a later stream/connection error, and success is proven by the
// relayed bytes themselves.
func TestE2ETuicTCPRelay(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startTUICE2EServer(t, e2eTUICPassword, false).Addr()
	d := newTuicE2EDialerFromLink(t, proxyAddr, e2eTUICUUIDStr, e2eTUICPassword)

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
		t.Fatalf("tuic conn %T lost the CloseWrite capability", c)
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

// TestE2ETuicTCPMultiplexedStreams opens several CONNECT streams at once
// over one shared QUIC tunnel and verifies each payload byte-exact while
// writes and reads run concurrently on every stream.
func TestE2ETuicTCPMultiplexedStreams(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startTUICE2EServer(t, e2eTUICPassword, false).Addr()
	d := newTuicE2EDialerFromLink(t, proxyAddr, e2eTUICUUIDStr, e2eTUICPassword)

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

// TestE2ETuicUDPRelay pushes datagrams through the v5 datagram channel
// (QUIC DATAGRAM frames; the consumer dialer pins udp_relay_mode=native) to
// two different loopback echo targets over one association, checking
// integrity and that each reply carries the real source address of its
// target. Closing the PacketConn must send Dissociate so the server retires
// the relay socket.
func TestE2ETuicUDPRelay(t *testing.T) {
	echoA := startUDPEchoTarget(t)
	echoB := startUDPEchoTarget(t)
	targets := []net.Addr{echoA, echoB}
	proxyAddr := startTUICE2EServer(t, e2eTUICPassword, false).Addr()
	d := newTuicE2EDialerFromLink(t, proxyAddr, e2eTUICUUIDStr, e2eTUICPassword)

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
	for i := 0; i < 8; i++ {
		for _, target := range targets {
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
				t.Fatalf("datagram %d to %v mismatch: n=%d", i, target, n)
			}
			want := netip.MustParseAddrPort(target.String())
			if from != want {
				t.Fatalf("datagram %d source = %v, want %v", i, from, want)
			}
		}
	}
}

// assertAuthFailedError proves a surfaced error is the TUIC v5
// AuthenticationFailed application error (code 0xfffffff1) sent by the
// server, not a local transport hiccup.
func assertAuthFailedError(t *testing.T, err error) {
	t.Helper()
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		if appErr.ErrorCode != tuicAuthFailedCode {
			t.Fatalf("surfaced application error code = %#x (%s), want AuthenticationFailed %#x",
				appErr.ErrorCode, appErr.ErrorMessage, tuicAuthFailedCode)
		}
		return
	}
	t.Fatalf("surfaced error %v (%T) does not carry the TUIC AuthenticationFailed application error", err, err)
}

// TestE2ETuicBadCredentialsIsAnErrorNotAPanic checks the auth-failure path:
// the server rejects the Authenticate command by closing the connection with
// the AuthenticationFailed application error code. The client must surface
// that error - at dial time or on the first write/read (v5 has no CONNECT
// acknowledgement, so the rejection cannot always fail the dial itself) -
// without panicking or hanging.
func TestE2ETuicBadCredentialsIsAnErrorNotAPanic(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startTUICE2EServer(t, e2eTUICPassword, true).Addr()
	d := newTuicE2EDialerFromLink(t, proxyAddr, e2eTUICUUIDStr, e2eTUICPassword)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, dialErr := d.DialContext(ctx, "tcp", echoAddr.String())
	if dialErr != nil {
		// Rejection already surfaced at dial time: fine, as long as it is
		// the server's rejection and not the caller's own deadline (which
		// would mean the client hung).
		if errors.Is(dialErr, context.DeadlineExceeded) {
			t.Fatalf("dial hung until the caller deadline instead of surfacing the rejection: %v", dialErr)
		}
		assertAuthFailedError(t, dialErr)
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
	assertAuthFailedError(t, surfaced)
}
