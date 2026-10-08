package naive_test

// True end-to-end coverage for the naiveproxy client dialer: an in-test
// naiveproxy server (own wire-format implementation, not a copy of
// dialer/naive) speaking HTTP/2 CONNECT over a real TLS listener on a real
// loopback socket, fronting a real echo target, reached through the same
// dialer chain dae builds (direct -> transport/tls -> dialer/naive).
//
// The naive dialer refuses to run unless the TLS handshake negotiates the
// "h2" ALPN protocol, and that check reaches the *tls.Conn only through
// netproxy.UnwrapIntrinsicConn (the transport hands back a coalescer
// wrapper). The ALPN mismatch test below is the regression guard for that
// peel-before-assert fix: without it the check is silently skipped and the
// h2 preface runs into a non-h2 server.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	naive "github.com/daeuniverse/outbound/dialer/naive"
	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/net/http2"
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

// deadlineCtx bounds every dial in the e2e so a hung protocol layer fails the
// test instead of hanging it. Note that naiveConn intentionally no-ops
// SetReadDeadline after the stream is established (per-stream deadlines cannot
// be forwarded to the shared h2 connection), so the relay loops below bound
// themselves with explicit timers instead of conn deadlines.
func deadlineCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// unreachableLoopbackAddr returns a loopback address whose listener is already
// closed, so dialing it fails with connection refused.
func unreachableLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("probe close: %v", err)
	}
	return addr
}

// ---- in-test naive server (independent wire-format implementation) ----

// naivePadFrameLimit and naivePadFrames mirror the naiveproxy payload padding
// protocol: while padding is negotiated, each side frames the first
// naivePadFrames chunked write/read operations with
//
//	uint8 original_data_size_high; uint8 original_data_size_low;
//	uint8 padding_size; original_data[...]; zeros[padding_size]
//
// and chunks writes at naivePadFrameLimit original bytes. Chunk counts are
// symmetric on the wire: the writer emits exactly one frame per chunk for the
// first naivePadFrames chunks, and the reader consumes exactly one frame per
// read that reaches the wire (overflow is stashed and served without counting).
const (
	naivePadFrameLimit = 65535
	naivePadFrames     = 8
)

// naiveTestPaddingValue generates a response padding header value, mirroring
// the naiveproxy convention of 30..62 non-Huffman-coded characters.
func naiveTestPaddingValue() string {
	alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "naive-test-padding"
	}
	// Modulo in the uint64 domain: converting the full uint64 to a signed
	// int first can wrap negative, and Go's % keeps the sign, which once
	// made this len negative.
	n := 30 + int(binary.BigEndian.Uint64(raw[:])%33)
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "naive-test-padding"
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// padServerWriter pads the first naivePadFrames chunks of the response stream.
type padServerWriter struct {
	w       http.ResponseWriter
	rc      *http.ResponseController
	enabled bool
	frames  int
}

func (p *padServerWriter) Write(b []byte) (int, error) {
	written := 0
	for len(b) > 0 {
		if !p.enabled || p.frames >= naivePadFrames {
			n, err := p.w.Write(b)
			written += n
			_ = p.rc.Flush()
			return written, err
		}
		n := len(b)
		if n > naivePadFrameLimit {
			n = naivePadFrameLimit
		}
		pad := int(b[0]) % 256 // deterministic-ish, 0..255 zeros
		frame := make([]byte, 0, 3+n+pad)
		frame = append(frame, byte(n>>8), byte(n&0xff), byte(pad))
		frame = append(frame, b[:n]...)
		frame = append(frame, make([]byte, pad)...)
		if _, err := p.w.Write(frame); err != nil {
			return written, err
		}
		_ = p.rc.Flush()
		p.frames++
		b = b[n:]
		written += n
	}
	_ = p.rc.Flush()
	return written, nil
}

// padServerReader strips the padding framing of the first naivePadFrames
// chunks of the request stream.
type padServerReader struct {
	r       io.Reader
	enabled bool
	frames  int
	pending []byte
}

func (p *padServerReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if len(p.pending) > 0 {
		n := copy(b, p.pending)
		p.pending = p.pending[n:]
		return n, nil
	}
	if !p.enabled || p.frames >= naivePadFrames {
		return p.r.Read(b)
	}
	var hdr [3]byte
	if _, err := io.ReadFull(p.r, hdr[:]); err != nil {
		return 0, err
	}
	orig := int(hdr[0])<<8 | int(hdr[1])
	pad := int(hdr[2])
	payload := b
	overflow := false
	if orig > len(b) {
		payload = make([]byte, orig)
		overflow = true
	} else {
		payload = payload[:orig]
	}
	if _, err := io.ReadFull(p.r, payload); err != nil {
		return 0, err
	}
	if pad > 0 {
		if _, err := io.CopyN(io.Discard, p.r, int64(pad)); err != nil {
			return 0, err
		}
	}
	p.frames++
	if !overflow {
		return orig, nil
	}
	n := copy(b, payload)
	p.pending = payload[n:]
	return n, nil
}

// naiveConnectRecord is one CONNECT request as the server saw it.
type naiveConnectRecord struct {
	Method    string
	Authority string
	Auth      string
	Padding   bool
}

type naiveServerOptions struct {
	// nextProtos is the ALPN list the TLS listener offers. ["h2"] is the
	// realistic naive deployment; anything else lets the tests exercise the
	// client's mandatory-h2 check.
	nextProtos []string
	// padding echoes the request padding header and pads the payload stream
	// both ways, like a real naive server.
	padding bool
	// username/password is the accepted basic credential pair; empty
	// username disables the auth check.
	username string
	password string
	// refuseStatus, when nonzero, is answered to every CONNECT instead of
	// relaying.
	refuseStatus int
}

type naiveH2TestServer struct {
	opts naiveServerOptions
	ln   net.Listener
	h2   *http2.Server

	mu          sync.Mutex
	alpn        []string
	records     []naiveConnectRecord
	requestEnds []string // "clean EOF" or the copy error text
	conns       map[net.Conn]struct{}
}

func (s *naiveH2TestServer) recordALPN(proto string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alpn = append(s.alpn, proto)
}

func (s *naiveH2TestServer) negotiatedProtocols() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.alpn...)
}

// waitForNegotiatedProtocol polls until at least one TLS connection has been
// accepted and handshaken (the record lands in the accept goroutine right
// after the server-side handshake) or the bound expires.
func (s *naiveH2TestServer) waitForNegotiatedProtocol(t *testing.T, bound time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(bound)
	for {
		protos := s.negotiatedProtocols()
		if len(protos) > 0 {
			return protos[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never recorded a negotiated ALPN protocol within %v", bound)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (s *naiveH2TestServer) connectRecords() []naiveConnectRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]naiveConnectRecord(nil), s.records...)
}

func (s *naiveH2TestServer) recordRequestEnd(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.requestEnds = append(s.requestEnds, "clean EOF")
		return
	}
	s.requestEnds = append(s.requestEnds, "error: "+err.Error())
}

func (s *naiveH2TestServer) requestEndsSnapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requestEnds...)
}

// waitForRequestEnd polls until the request stream has ended at least once or
// the bound expires, and returns the last recorded end.
func (s *naiveH2TestServer) waitForRequestEnd(t *testing.T, bound time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(bound)
	for {
		ends := s.requestEndsSnapshot()
		if len(ends) > 0 {
			return ends[len(ends)-1]
		}
		if time.Now().After(deadline) {
			t.Fatalf("request stream never ended within %v", bound)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (s *naiveH2TestServer) track(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns[c] = struct{}{}
}

func (s *naiveH2TestServer) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		_ = c.Close()
	}
}

// handleConnect implements the naive server side of the tunnel: parse the
// CONNECT, optionally check the basic credential, open the encoded target,
// then relay bidirectionally. A clean end of the request stream (END_STREAM)
// half-closes the upstream target; a stream reset tears the target down.
func (s *naiveH2TestServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	rec := naiveConnectRecord{
		Method:    r.Method,
		Authority: r.Host,
		Auth:      r.Header.Get("Proxy-Authorization"),
		Padding:   r.Header.Get("padding") != "",
	}
	s.mu.Lock()
	s.records = append(s.records, rec)
	s.mu.Unlock()

	if r.Method != http.MethodConnect {
		http.Error(w, "naive test server: CONNECT required", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.refuseStatus != 0 {
		http.Error(w, "naive test server: refused", s.opts.refuseStatus)
		return
	}
	if s.opts.username != "" {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(s.opts.username+":"+s.opts.password))
		if rec.Auth != want {
			http.Error(w, "naive test server: bad credentials", http.StatusProxyAuthRequired)
			return
		}
	}
	target := r.Host
	if target == "" {
		http.Error(w, "naive test server: missing :authority", http.StatusBadRequest)
		return
	}
	upstream, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		http.Error(w, fmt.Sprintf("naive test server: dial %s: %v", target, err), http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	if s.opts.padding {
		w.Header().Set("padding", naiveTestPaddingValue())
	}
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	_ = rc.Flush()

	// Client -> target. A clean request end (io.EOF on r.Body) means the
	// client sent a FIN: propagate it upstream with a half-close. Any other
	// end (RST_STREAM, conn death) kills the target so the response pump
	// below cannot block forever.
	go func() {
		dec := &padServerReader{r: r.Body, enabled: s.opts.padding}
		_, copyErr := io.Copy(upstream, dec)
		s.recordRequestEnd(copyErr)
		if copyErr == nil {
			if tc, ok := upstream.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			}
		} else {
			_ = upstream.Close()
		}
	}()

	// Target -> client, padded and flushed per write so the stream is
	// incrementally delivered like a real proxy.
	out := &padServerWriter{w: w, rc: rc, enabled: s.opts.padding}
	buf := make([]byte, 16<<10)
	for {
		n, readErr := upstream.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}

// startNaiveH2Server runs the in-test naive h2-over-TLS server.
func startNaiveH2Server(t *testing.T, opts naiveServerOptions) *naiveH2TestServer {
	t.Helper()
	if len(opts.nextProtos) == 0 {
		opts.nextProtos = []string{"h2"}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("naive listen: %v", err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{e2eSelfSignedCert(t)},
		NextProtos:   opts.nextProtos,
	})
	s := &naiveH2TestServer{
		opts:  opts,
		ln:    tlsLn,
		conns: make(map[net.Conn]struct{}),
	}
	s.h2 = &http2.Server{}
	t.Cleanup(func() {
		_ = ln.Close()
		s.closeAll()
	})
	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			s.track(c)
			tc, ok := c.(*tls.Conn)
			if !ok {
				_ = c.Close()
				continue
			}
			// Terminate the handshake server-side so the negotiated ALPN is
			// observable before the h2 machinery starts.
			if err := tc.HandshakeContext(context.Background()); err != nil {
				_ = c.Close()
				continue
			}
			s.recordALPN(tc.ConnectionState().NegotiatedProtocol)
			go s.h2.ServeConn(tc, &http2.ServeConnOpts{Handler: http.HandlerFunc(s.handleConnect)})
		}
	}()
	return s
}

// newNaiveClientDialer builds the dae-side dialer chain for naive+https the
// way the consumer builds it: direct -> transport/tls (inside the naive
// dialer) -> dialer/naive, from the registered link format.
func newNaiveClientDialer(t *testing.T, proxyAddr, username, password string) netproxy.Dialer {
	t.Helper()
	direct, _ := dialer.NewDirectDialer(&dialer.ExtraOption{}, false)
	link := (&url.URL{
		Scheme:   "naive+https",
		Host:     proxyAddr,
		User:     url.UserPassword(username, password),
		RawQuery: "allowInsecure=1",
		Fragment: "e2e-naive",
	}).String()
	d, _, err := naive.NewNaive(&dialer.ExtraOption{
		AllowInsecure:     true,
		TlsImplementation: "tls",
	}, direct, link)
	if err != nil {
		t.Fatalf("naive dialer: %v", err)
	}
	return d
}

// ---- bounded execution helpers ----

// opErrorBounded runs f and gives it `bound` to return. It fails the test when
// f is still blocked after `bound` (the no-hang guarantee) and returns f's
// error otherwise.
func opErrorBounded(t *testing.T, bound time.Duration, name string, f func() error) error {
	t.Helper()
	errCh := make(chan error, 1)
	go func() { errCh <- f() }()
	select {
	case err := <-errCh:
		return err
	case <-time.After(bound):
		t.Fatalf("%s: still blocked after %v (protocol layer must not hang)", name, bound)
		return nil
	}
}

const relayCycle = 64 << 10

func relayPattern(off int) byte { return byte((off % relayCycle) * 7) }

// driveRelay writes `total` deterministic bytes through c and reads them back,
// verifying every byte. Write and read run concurrently, so the payload must
// survive a full duplex pass through the protocol stack.
func driveRelay(c netproxy.Conn, total int) error {
	chunk := make([]byte, 100<<10)
	for i := range chunk {
		chunk[i] = relayPattern(i)
	}
	werr := make(chan error, 1)
	go func() {
		sent := 0
		for sent < total {
			n := len(chunk)
			if total-sent < n {
				n = total - sent
			}
			if _, err := c.Write(chunk[:n]); err != nil {
				werr <- fmt.Errorf("write at %d/%d: %w", sent, total, err)
				return
			}
			sent += n
		}
		werr <- nil
	}()
	got := 0
	buf := make([]byte, 32<<10)
	for got < total {
		n, err := c.Read(buf)
		if err != nil {
			return fmt.Errorf("read back at %d/%d: %w", got, total, err)
		}
		for i := 0; i < n; i++ {
			if want := relayPattern(got + i); buf[i] != want {
				return fmt.Errorf("payload mismatch at %d: got %#x want %#x", got+i, buf[i], want)
			}
		}
		got += n
	}
	if err := <-werr; err != nil {
		return err
	}
	return nil
}

// relayBounded runs driveRelay and fails the test when it does not finish
// within `bound`. naiveConn cannot take stream deadlines, so the bound closes
// the conn to unblock a stuck read before reporting the hang.
func relayBounded(t *testing.T, c netproxy.Conn, total int, bound time.Duration) {
	t.Helper()
	errCh := make(chan error, 1)
	go func() { errCh <- driveRelay(c, total) }()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("relay %d bytes: %v", total, err)
		}
	case <-time.After(bound):
		_ = c.Close()
		select {
		case err := <-errCh:
			t.Logf("relay goroutine ended with: %v", err)
		case <-time.After(10 * time.Second):
			t.Log("relay goroutine did not unwind after close")
		}
		t.Fatalf("relay of %d bytes did not finish within %v", total, bound)
	}
}

// ---- the e2e tests ----

// TestE2ENaiveH2RelayByteExact pushes 2MiB of deterministic payload through
// client -> naive h2 CONNECT -> echo target -> back over a real TLS session
// with negotiated padding, and asserts the server really negotiated "h2".
func TestE2ENaiveH2RelayByteExact(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	srv := startNaiveH2Server(t, naiveServerOptions{
		padding:  true,
		username: "e2e-user",
		password: "e2e-pass",
	})
	d := newNaiveClientDialer(t, srv.ln.Addr().String(), "e2e-user", "e2e-pass")

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	relayBounded(t, c, 2<<20, 60*time.Second)

	// Scenario (b): the server must have seen the client's TLS stack select
	// "h2" — the whole point of the dialer's mandatory-ALPN contract.
	protos := srv.negotiatedProtocols()
	if len(protos) == 0 {
		t.Fatal("server never recorded a negotiated ALPN protocol")
	}
	for _, p := range protos {
		if p != "h2" {
			t.Fatalf("server negotiated %q, want %q (all: %v)", p, "h2", protos)
		}
	}

	// The CONNECT the server received must carry the target as :authority
	// and the credentials as Proxy-Authorization.
	records := srv.connectRecords()
	if len(records) == 0 {
		t.Fatal("server never saw the CONNECT request")
	}
	rec := records[0]
	if rec.Method != http.MethodConnect {
		t.Fatalf("request method = %q, want CONNECT", rec.Method)
	}
	if rec.Authority != echoAddr.String() {
		t.Fatalf("CONNECT :authority = %q, want target %q", rec.Authority, echoAddr.String())
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("e2e-user:e2e-pass"))
	if rec.Auth != wantAuth {
		t.Fatalf("Proxy-Authorization = %q, want %q", rec.Auth, wantAuth)
	}
	if !rec.Padding {
		t.Fatal("client did not send the padding header; server would never enable payload padding")
	}
}

// TestE2ENaiveH2RelayWithoutPadding relays without the padding header echo,
// exercising the unpadded branch of the negotiated stream in the full chain.
func TestE2ENaiveH2RelayWithoutPadding(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	srv := startNaiveH2Server(t, naiveServerOptions{
		padding:  false,
		username: "e2e-user",
		password: "e2e-pass",
	})
	d := newNaiveClientDialer(t, srv.ln.Addr().String(), "e2e-user", "e2e-pass")

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	relayBounded(t, c, 256<<10, 60*time.Second)

	if protos := srv.negotiatedProtocols(); len(protos) == 0 || protos[0] != "h2" {
		t.Fatalf("server negotiated protocols = %v, want [h2]", protos)
	}
}

// TestE2ENaiveALPNMismatchIsRejected is the regression guard for the
// peel-before-assert fix in dialer/naive.go: the TLS dialer returns a
// coalescer wrapper, so the *tls.Conn (and with it the mandatory h2 check) is
// reachable only through netproxy.UnwrapIntrinsicConn. Against a server that
// offers http/1.1 the client must fail fast with the ALPN error — not skip
// the check and let the h2 preface die inside the transport.
func TestE2ENaiveALPNMismatchIsRejected(t *testing.T) {
	srv := startNaiveH2Server(t, naiveServerOptions{
		nextProtos: []string{"http/1.1"},
	})
	d := newNaiveClientDialer(t, srv.ln.Addr().String(), "e2e-user", "e2e-pass")

	ctx := deadlineCtx(t)
	err := opErrorBounded(t, 30*time.Second, "DialContext", func() error {
		c, derr := d.DialContext(ctx, "tcp", "127.0.0.1:1")
		if derr == nil {
			_ = c.Close()
		}
		return derr
	})
	if err == nil {
		t.Fatal("dial against a non-h2 server succeeded; the mandatory ALPN check did not run")
	}
	if !strings.Contains(err.Error(), "require h2") {
		t.Fatalf("dial error = %v, want the peeled *tls.Conn ALPN check error (must contain %q)", err, "require h2")
	}
	if got := srv.waitForNegotiatedProtocol(t, 10*time.Second); got != "http/1.1" {
		t.Fatalf("server negotiated %q, want %q", got, "http/1.1")
	}
}

// TestE2ENaiveProxyRefusalIsErrorNotHang covers scenario (c): an HTTP error
// status on the CONNECT must surface as a client error on first use — no
// panic, no hang. The CONNECT is sent lazily, so DialContext itself succeeds
// and the refusal arrives on the first Write.
func TestE2ENaiveProxyRefusalIsErrorNotHang(t *testing.T) {
	cases := []struct {
		name       string
		serverOpts func(t *testing.T) naiveServerOptions
		clientPass string
	}{
		{
			name: "forbidden",
			serverOpts: func(t *testing.T) naiveServerOptions {
				return naiveServerOptions{refuseStatus: http.StatusForbidden}
			},
			clientPass: "e2e-pass",
		},
		{
			name: "bad credentials 407",
			serverOpts: func(t *testing.T) naiveServerOptions {
				return naiveServerOptions{username: "e2e-user", password: "right-pass"}
			},
			clientPass: "wrong-pass",
		},
		{
			name: "unreachable target 502",
			serverOpts: func(t *testing.T) naiveServerOptions {
				return naiveServerOptions{username: "e2e-user", password: "e2e-pass"}
			},
			clientPass: "e2e-pass",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startNaiveH2Server(t, tc.serverOpts(t))
			var target string
			if tc.name == "unreachable target 502" {
				target = unreachableLoopbackAddr(t)
			} else {
				target = loopbackEchoTarget(t).String()
			}
			d := newNaiveClientDialer(t, srv.ln.Addr().String(), "e2e-user", tc.clientPass)

			ctx := deadlineCtx(t)
			c, err := d.DialContext(ctx, "tcp", target)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer c.Close()

			// First write triggers the lazy CONNECT; the refusal must come
			// back as an error, not a panic or a hang.
			err = opErrorBounded(t, 30*time.Second, "first Write after refusal", func() error {
				_, werr := c.Write([]byte("probe"))
				return werr
			})
			if err == nil {
				t.Fatal("CONNECT refusal was not surfaced as an error on first Write")
			}
			if !strings.Contains(err.Error(), "naive CONNECT failed") {
				t.Fatalf("write error = %v, want a naive CONNECT failure", err)
			}
			// The stored handshake failure must also poison reads.
			err = opErrorBounded(t, 10*time.Second, "Read after refusal", func() error {
				_, rerr := c.Read(make([]byte, 16))
				return rerr
			})
			if err == nil {
				t.Fatal("read after a refused CONNECT returned no error")
			}
		})
	}
}

// TestE2ENaiveClientHalfCloseIsImpossible documents scenario (d) for the
// client->server direction instead of failing on it:
//
//   - naiveConn exposes no CloseWrite (netproxy.WriteCloser is not
//     implemented anywhere in the naive chain), so a caller cannot even ask
//     for a half-close.
//   - The wire-level mechanism for a client FIN over h2 CONNECT would be
//     END_STREAM on the request stream. The client's request body is an
//     io.Pipe whose Close() errors the pipe; x/net/http2 reacts to a
//     non-EOF request-body error by aborting and sending
//     RST_STREAM(CANCEL) — which tears down BOTH directions — and
//     naiveConn.Close() additionally closes the response body.
//
// The test proves the second point on the wire: after a successful relay and
// Close(), the server's request pump records an error, never a clean EOF.
func TestE2ENaiveClientHalfCloseIsImpossible(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	srv := startNaiveH2Server(t, naiveServerOptions{
		padding:  true,
		username: "e2e-user",
		password: "e2e-pass",
	})
	d := newNaiveClientDialer(t, srv.ln.Addr().String(), "e2e-user", "e2e-pass")

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	relayBounded(t, c, 128<<10, 60*time.Second)

	if _, hasCloseWrite := c.(interface{ CloseWrite() error }); hasCloseWrite {
		t.Fatal("naive conn unexpectedly supports CloseWrite; revisit the half-close documentation")
	}
	t.Log("no half-close surface: netproxy.WriteCloser is not implemented by naiveConn, " +
		"and closing the request pipe triggers RST_STREAM(CANCEL) instead of END_STREAM, " +
		"so a client FIN would kill the tunnel in both directions")

	if err := opErrorBounded(t, 10*time.Second, "Close", c.Close); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// After Close the conn must fail reads immediately, not block.
	err = opErrorBounded(t, 10*time.Second, "Read after Close", func() error {
		_, rerr := c.Read(make([]byte, 16))
		return rerr
	})
	if err == nil {
		t.Fatal("read after Close returned no error")
	}

	// Wire evidence: the server saw the request stream end with an error
	// (RST_STREAM), not a clean client FIN.
	end := srv.waitForRequestEnd(t, 10*time.Second)
	if end == "clean EOF" {
		t.Fatal("server observed a clean END_STREAM on the request body; " +
			"the client can half-close after all and the documentation above is wrong")
	}
	t.Logf("server observed request stream end: %s (RST_STREAM, not a client FIN)", end)
}

// TestE2ENaiveServerHalfClosePropagatesEOF covers the reverse direction of
// scenario (d): when the upstream target closes, the server ends the response
// stream and the client must see a clean EOF after the remaining data.
func TestE2ENaiveServerHalfClosePropagatesEOF(t *testing.T) {
	greeting := "naive e2e: target half-close arrives as EOF\n"
	// A target that writes a greeting and closes immediately.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("greeting listen: %v", err)
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
				_, _ = io.WriteString(c, greeting)
			}(c)
		}
	}()

	srv := startNaiveH2Server(t, naiveServerOptions{
		padding:  true,
		username: "e2e-user",
		password: "e2e-pass",
	})
	d := newNaiveClientDialer(t, srv.ln.Addr().String(), "e2e-user", "e2e-pass")

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// Read is triggered first here (lazy CONNECT), so bound the whole read.
	var got []byte
	err = opErrorBounded(t, 30*time.Second, "read greeting", func() error {
		buf := make([]byte, 512)
		for {
			n, rerr := c.Read(buf)
			got = append(got, buf[:n]...)
			if rerr != nil {
				return rerr
			}
		}
	})
	if err != io.EOF {
		t.Fatalf("read error = %v, want io.EOF", err)
	}
	if string(got) != greeting {
		t.Fatalf("greeting = %q, want %q", got, greeting)
	}
}
