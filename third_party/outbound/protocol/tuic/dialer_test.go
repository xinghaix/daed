package tuic

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/olicesx/quic-go"
)

const (
	testTUICUUID     = "00000000-0000-0000-0000-000000000000"
	testTUICPassword = "password"
)

func TestTcp(t *testing.T) {
	server := startTestTUICServer(t, testTUICPassword)
	defer server.Close()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "tuic tcp relay ok")
	}))
	defer backend.Close()

	dialer := newTestTUICDialer(t, server.Addr())
	client := http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := dialer.DialContext(ctx, "tcp", addr)
				if err != nil {
					return nil, err
				}
				return &netproxy.FakeNetConn{Conn: conn}, nil
			},
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(body); got != "tuic tcp relay ok" {
		t.Fatalf("response body = %q, want %q", got, "tuic tcp relay ok")
	}
}

func TestTcpReturnsStreamLocalErrorAfterImmediateDialSuccess(t *testing.T) {
	server := startTestTUICServer(t, testTUICPassword, true)
	defer server.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backendAddr := ln.Addr().String()
	_ = ln.Close()

	dialer := newTestTUICDialer(t, server.Addr())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	type dialResult struct {
		conn netproxy.Conn
		err  error
	}
	dialResultCh := make(chan dialResult, 1)
	go func() {
		conn, err := dialer.DialContext(ctx, "tcp", backendAddr)
		dialResultCh <- dialResult{conn: conn, err: err}
	}()

	select {
	case <-server.connectRequest:
	case <-ctx.Done():
		t.Fatal("server did not receive CONNECT command")
	}

	var result dialResult
	select {
	case result = <-dialResultCh:
	case <-ctx.Done():
		t.Fatal("DialContext waited for remote connection confirmation")
	}
	if result.err != nil {
		t.Fatalf("DialContext() error = %v, want immediate stream", result.err)
	}
	defer result.conn.Close()

	close(server.connectGate)
	if _, err := result.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("stream read error = nil, want remote connect failure")
	}
}

func TestUdp(t *testing.T) {
	server := startTestTUICServer(t, testTUICPassword)
	defer server.Close()

	backendAddr, stopBackend := startTestUDPEchoServer(t)
	defer stopBackend()

	dialer := newTestTUICDialer(t, server.Addr())
	conn, err := dialer.DialContext(context.Background(), "udp", backendAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "pong:ping" {
		t.Fatalf("udp response = %q, want %q", got, "pong:ping")
	}
}

func newTestTUICDialer(t *testing.T, proxyAddr string) netproxy.Dialer {
	t.Helper()

	dialer, err := NewDialer(direct.SymmetricDirect, protocol.Header{
		ProxyAddress: proxyAddr,
		Feature1:     "bbr",
		TlsConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
			MinVersion:         tls.VersionTLS13,
			ServerName:         "localhost",
		},
		User:     testTUICUUID,
		Password: testTUICPassword,
		IsClient: true,
		Flags:    0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return dialer
}

type testTUICServer struct {
	listener *quic.Listener
	password string

	conns          sync.Map
	done           chan struct{}
	connectRequest chan struct{}
	connectGate    chan struct{}
}

func startTestTUICServer(t *testing.T, password string, blockConnect ...bool) *testTUICServer {
	t.Helper()

	listener, err := quic.ListenAddr("127.0.0.1:0", newTestServerTLSConfig(t), &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: time.Second,
	})
	if err != nil {
		t.Fatalf("ListenAddr() error = %v", err)
	}

	s := &testTUICServer{
		listener: listener,
		password: password,
		done:     make(chan struct{}),
	}
	if len(blockConnect) > 0 && blockConnect[0] {
		s.connectRequest = make(chan struct{}, 1)
		s.connectGate = make(chan struct{})
	}
	go func() {
		defer close(s.done)
		for {
			conn, err := s.listener.Accept(context.Background())
			if err != nil {
				return
			}
			s.conns.Store(conn, struct{}{})
			go s.serveConn(conn)
		}
	}()
	return s
}

func (s *testTUICServer) Addr() string {
	return s.listener.Addr().String()
}

func (s *testTUICServer) Close() {
	_ = s.listener.Close()
	s.conns.Range(func(key, _ any) bool {
		_ = key.(quic.Connection).CloseWithError(0, "test shutdown")
		s.conns.Delete(key)
		return true
	})
	<-s.done
}

func (s *testTUICServer) serveConn(conn quic.Connection) {
	defer s.conns.Delete(conn)

	go s.serveAuthStreams(conn)
	go s.serveConnectStreams(conn)
	go s.serveDatagrams(conn)

	<-conn.Context().Done()
}

func (s *testTUICServer) serveAuthStreams(conn quic.Connection) {
	for {
		stream, err := conn.AcceptUniStream(conn.Context())
		if err != nil {
			return
		}
		go func(stream quic.ReceiveStream) {
			defer stream.CancelRead(0)

			reader := bufio.NewReader(stream)
			head, err := ReadCommandHead(reader)
			if err != nil {
				return
			}
			if head.TYPE != AuthenticateType {
				_ = conn.CloseWithError(BadCommand, "unexpected unidirectional command")
				return
			}

			auth, err := ReadAuthenticateWithHead(head, reader)
			if err != nil {
				_ = conn.CloseWithError(BadCommand, err.Error())
				return
			}
			token, err := GenToken(conn.ConnectionState(), auth.UUID, s.password)
			if err != nil || !bytes.Equal(auth.TOKEN[:], token[:]) {
				_ = conn.CloseWithError(AuthenticationFailed, "invalid credentials")
			}
		}(stream)
	}
}

func (s *testTUICServer) serveConnectStreams(conn quic.Connection) {
	for {
		stream, err := conn.AcceptStream(conn.Context())
		if err != nil {
			return
		}
		go func(stream quic.Stream) {
			reader := bufio.NewReader(stream)
			head, err := ReadCommandHead(reader)
			if err != nil {
				_ = stream.Close()
				return
			}
			if head.TYPE != ConnectType {
				_ = conn.CloseWithError(BadCommand, "unexpected stream command")
				return
			}
			connect, err := ReadConnectWithHead(head, reader)
			if err != nil {
				_ = conn.CloseWithError(BadCommand, err.Error())
				return
			}
			if s.connectGate != nil {
				s.connectRequest <- struct{}{}
				select {
				case <-s.connectGate:
				case <-conn.Context().Done():
					return
				}
			}

			targetConn, err := net.Dial("tcp", connect.ADDR.String())
			if err != nil {
				_ = conn.CloseWithError(BadCommand, err.Error())
				return
			}

			done := make(chan struct{}, 2)
			go func() {
				_, _ = io.Copy(targetConn, reader)
				if tcpConn, ok := targetConn.(*net.TCPConn); ok {
					_ = tcpConn.CloseWrite()
				}
				done <- struct{}{}
			}()
			go func() {
				_, _ = io.Copy(stream, targetConn)
				_ = stream.Close()
				done <- struct{}{}
			}()

			<-done
			stream.CancelRead(0)
			_ = targetConn.Close()
			<-done
		}(stream)
	}
}

func (s *testTUICServer) serveDatagrams(conn quic.Connection) {
	for {
		message, err := conn.ReceiveDatagram(conn.Context())
		if err != nil {
			return
		}
		go func(message []byte) {
			reader := bytes.NewReader(message)
			head, err := ReadCommandHead(reader)
			if err != nil {
				return
			}
			if head.TYPE != PacketType {
				return
			}
			packet, err := ReadPacketWithHead(head, reader)
			if err != nil {
				return
			}

			response, responseAddr, err := relayTestUDPPacket(packet)
			if err != nil {
				return
			}

			var buf bytes.Buffer
			reply := NewPacket(
				packet.ASSOC_ID,
				packet.PKT_ID,
				1,
				0,
				uint16(len(response)),
				NewAddressAddrPort(responseAddr),
				response,
				Ver5,
			)
			if err := reply.WriteTo(&buf); err != nil {
				return
			}
			_ = conn.SendDatagram(buf.Bytes())
		}(append([]byte(nil), message...))
	}
}

func relayTestUDPPacket(packet *Packet) ([]byte, netip.AddrPort, error) {
	backendAddr, err := net.ResolveUDPAddr("udp", packet.ADDR.String())
	if err != nil {
		return nil, netip.AddrPort{}, err
	}

	backendConn, err := net.DialUDP("udp", nil, backendAddr)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	defer func() { _ = backendConn.Close() }()

	if err := backendConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, netip.AddrPort{}, err
	}
	if _, err := backendConn.Write(packet.DATA); err != nil {
		return nil, netip.AddrPort{}, err
	}

	buf := make([]byte, 2048)
	n, _, err := backendConn.ReadFromUDP(buf)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	return append([]byte(nil), buf[:n]...), backendAddr.AddrPort(), nil
}

func startTestUDPEchoServer(t *testing.T) (string, func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			response := append([]byte("pong:"), buf[:n]...)
			_, _ = pc.WriteTo(response, addr)
		}
	}()
	return pc.LocalAddr().String(), func() {
		_ = pc.Close()
		<-done
	}
}

func newTestServerTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	certPEM, keyPEM := newTestCertificatePEM(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair() error = %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
		MinVersion:   tls.VersionTLS13,
	}
}

func newTestCertificatePEM(t *testing.T) ([]byte, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return certPEM, keyPEM
}
