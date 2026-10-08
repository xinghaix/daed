package http

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	stdhttp "net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/daeuniverse/outbound/netproxy"
)

func TestH2ConnsPoolMarkDeadCleansUpEmptyAddressState(t *testing.T) {
	pool := newH2ConnsPool()
	addr := "proxy.example:443"
	key := "|" + "tcp" + "|" + addr
	pool.h2ConnsPool[key] = newLockedList()
	pool.registerAddrToDialerMapping(addr, noopDialer{}, "tcp")

	h2c := &http2.ClientConn{}
	pool.h2ConnsPool[key].mu.Lock()
	ele := pool.h2ConnsPool[key].l.PushFront(&h2Conn{h2Conn: h2c})
	pool.h2ConnsPool[key].mu.Unlock()
	pool.h2Conn2Ident[h2c] = &poolIdent{ele: ele, key: key}

	pool.MarkDead(h2c)

	if _, ok := pool.h2ConnsPool[key]; ok {
		t.Fatal("expected empty connection list to be removed")
	}
	if _, ok := pool.addr2Dialer[addr]; ok {
		t.Fatal("expected dialer mapping to be removed")
	}
}

func TestH2ConnsPoolMarkDeadKeepsAddressStateWhileConnListIsInUse(t *testing.T) {
	pool := newH2ConnsPool()
	addr := "proxy.example:443"
	key := "|" + "tcp" + "|" + addr
	conns := newLockedList()
	pool.h2ConnsPool[key] = conns
	pool.registerAddrToDialerMapping(addr, noopDialer{}, "tcp")

	oldH2 := &http2.ClientConn{}
	conns.mu.Lock()
	oldEle := conns.l.PushFront(&h2Conn{h2Conn: oldH2})
	conns.mu.Unlock()
	pool.h2Conn2Ident[oldH2] = &poolIdent{ele: oldEle, key: key}

	inUseConns, cached := pool.acquireConnList(key)
	if !cached {
		t.Fatal("expected existing connection list to be reused")
	}
	if inUseConns != conns {
		t.Fatal("expected acquireConnList to return the existing list")
	}

	pool.MarkDead(oldH2)

	if got := pool.h2ConnsPool[key]; got != conns {
		t.Fatal("expected MarkDead to keep the address state while GetConn still holds a reference")
	}
	if _, ok := pool.addr2Dialer[addr]; !ok {
		t.Fatal("expected dialer mapping to remain while list is in use")
	}

	newH2 := &http2.ClientConn{}
	conns.mu.Lock()
	newEle := conns.l.PushFront(&h2Conn{h2Conn: newH2})
	conns.mu.Unlock()
	pool.h2Conn2Ident[newH2] = &poolIdent{ele: newEle, key: key}

	pool.releaseConnList(key, inUseConns)

	if got := pool.h2ConnsPool[key]; got != conns {
		t.Fatal("expected address state to remain after a replacement h2 connection is added")
	}
	if _, ok := pool.addr2Dialer[addr]; !ok {
		t.Fatal("expected dialer mapping to remain after replacement h2 connection is added")
	}
}

func TestH2ConnsPoolReleaseConnListCleansUpDeferredEmptyAddressState(t *testing.T) {
	pool := newH2ConnsPool()
	addr := "proxy.example:443"
	key := "|" + "tcp" + "|" + addr
	conns := newLockedList()
	pool.h2ConnsPool[key] = conns
	pool.registerAddrToDialerMapping(addr, noopDialer{}, "tcp")

	inUseConns, cached := pool.acquireConnList(key)
	if !cached {
		t.Fatal("expected existing connection list to be reused")
	}
	if inUseConns != conns {
		t.Fatal("expected acquireConnList to return the existing list")
	}

	pool.releaseConnList(key, inUseConns)

	if _, ok := pool.h2ConnsPool[key]; ok {
		t.Fatal("expected deferred cleanup to remove the empty connection list once the last reference is released")
	}
	if _, ok := pool.addr2Dialer[addr]; ok {
		t.Fatal("expected deferred cleanup to remove the dialer mapping")
	}
}

type scopedDialer struct {
	noopDialer
	ns string
}

func (d scopedDialer) TransportCacheNamespace() string { return d.ns }

func TestH2ConnsPoolMarkDeadUsesScopedKey(t *testing.T) {
	pool := newH2ConnsPool()
	addr := "proxy.example:443"
	keyA := "ns-a|tcp|" + addr
	keyB := "ns-b|tcp|" + addr

	listA := newLockedList()
	listB := newLockedList()
	pool.h2ConnsPool[keyA] = listA
	pool.h2ConnsPool[keyB] = listB
	pool.registerAddrToDialerMapping(addr, scopedDialer{ns: "ns-a"}, "tcp")
	pool.registerAddrToDialerMapping(addr, scopedDialer{ns: "ns-b"}, "tcp")

	h2a := &http2.ClientConn{}
	h2b := &http2.ClientConn{}
	listA.mu.Lock()
	eleA := listA.l.PushFront(&h2Conn{h2Conn: h2a})
	listA.mu.Unlock()
	listB.mu.Lock()
	eleB := listB.l.PushFront(&h2Conn{h2Conn: h2b})
	listB.mu.Unlock()
	pool.h2Conn2Ident[h2a] = &poolIdent{ele: eleA, key: keyA}
	pool.h2Conn2Ident[h2b] = &poolIdent{ele: eleB, key: keyB}

	pool.MarkDead(h2a)

	if _, ok := pool.h2ConnsPool[keyA]; ok {
		t.Fatal("expected ns-a list to be removed after MarkDead")
	}
	if got := pool.h2ConnsPool[keyB]; got != listB {
		t.Fatal("expected ns-b list to survive MarkDead of an ns-a conn")
	}
	if listB.l.Len() != 1 {
		t.Fatalf("ns-b list len = %d, want 1", listB.l.Len())
	}
	bindings := pool.addr2Dialer[addr]
	if len(bindings) != 1 || bindings[0].key != keyB {
		t.Fatalf("bindings after ns-a removal = %+v, want only ns-b", bindings)
	}
}

func TestH2ConnsPoolLatestBindingRemovalFallsBack(t *testing.T) {
	pool := newH2ConnsPool()
	addr := "proxy.example:443"
	dialerA := scopedDialer{ns: "ns-a"}
	dialerB := scopedDialer{ns: "ns-b"}
	keyA := "ns-a|tcp|" + addr
	keyB := "ns-b|tcp|" + addr

	listA, _ := pool.acquireConnListForDialer(keyA, addr, dialerA, "tcp")
	listB, _ := pool.acquireConnListForDialer(keyB, addr, dialerB, "tcp")
	pool.releaseConnList(keyB, listB)

	bindings := pool.addr2Dialer[addr]
	if len(bindings) != 1 || bindings[0].key != keyA {
		t.Fatalf("bindings after latest removal = %+v, want ns-a fallback", bindings)
	}
	pool.releaseConnList(keyA, listA)
}

func TestConnBuffersIncompleteInitialHTTPRequest(t *testing.T) {
	dialer := &recordingDialer{conn: &recordingConn{}}
	proxy := &HttpProxy{Addr: "proxy.example:8080"}
	conn := NewConn(context.Background(), dialer, proxy, "example.com:80", "tcp")

	part1 := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test")
	n, err := conn.Write(part1)
	if err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if n != len(part1) {
		t.Fatalf("first write n = %d, want %d", n, len(part1))
	}
	if dialer.calls != 0 {
		t.Fatalf("dialer called before request was complete: %d", dialer.calls)
	}

	part2 := []byte("\r\n\r\n")
	n, err = conn.Write(part2)
	if err != nil {
		t.Fatalf("second write failed: %v", err)
	}
	if n != len(part2) {
		t.Fatalf("second write n = %d, want %d", n, len(part2))
	}
	if dialer.calls != 1 {
		t.Fatalf("dialer calls = %d, want 1", dialer.calls)
	}

	got := dialer.conn.(*recordingConn).writes.String()
	if !bytes.Contains([]byte(got), []byte("GET http://example.com/ HTTP/1.1\r\n")) {
		t.Fatalf("proxy request missing absolute-form request line: %q", got)
	}
	if !bytes.Contains([]byte(got), []byte("User-Agent: test\r\n")) {
		t.Fatalf("proxy request missing buffered headers: %q", got)
	}
}

func TestConnBuffersSplitHTTPRequestLinePrefix(t *testing.T) {
	dialer := &recordingDialer{conn: &recordingConn{}}
	proxy := &HttpProxy{Addr: "proxy.example:8080"}
	conn := NewConn(context.Background(), dialer, proxy, "example.com:80", "tcp")

	part1 := []byte("GE")
	n, err := conn.Write(part1)
	if err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if n != len(part1) {
		t.Fatalf("first write n = %d, want %d", n, len(part1))
	}
	if dialer.calls != 0 {
		t.Fatalf("dialer called before request line was complete: %d", dialer.calls)
	}

	part2 := []byte("T / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	n, err = conn.Write(part2)
	if err != nil {
		t.Fatalf("second write failed: %v", err)
	}
	if n != len(part2) {
		t.Fatalf("second write n = %d, want %d", n, len(part2))
	}
	if dialer.calls != 1 {
		t.Fatalf("dialer calls = %d, want 1", dialer.calls)
	}

	got := dialer.conn.(*recordingConn).writes.String()
	if !bytes.Contains([]byte(got), []byte("GET http://example.com/ HTTP/1.1\r\n")) {
		t.Fatalf("proxy request missing reconstructed request line: %q", got)
	}
}

func TestConnBufferedPrefixFallbackKeepsPayload(t *testing.T) {
	dialer := &recordingDialer{conn: &recordingConnWithRead{read: bytes.NewBufferString("HTTP/1.1 200 Connection Established\r\n\r\n")}}
	proxy := &HttpProxy{Addr: "proxy.example:8080"}
	conn := NewConn(context.Background(), dialer, proxy, "example.com:443", "tcp")

	part1 := []byte("PO")
	n, err := conn.Write(part1)
	if err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if n != len(part1) {
		t.Fatalf("first write n = %d, want %d", n, len(part1))
	}
	if dialer.calls != 0 {
		t.Fatalf("dialer called before protocol type was known: %d", dialer.calls)
	}

	part2 := []byte("X")
	n, err = conn.Write(part2)
	if err != nil {
		t.Fatalf("second write failed: %v", err)
	}
	if n != len(part2) {
		t.Fatalf("second write n = %d, want %d", n, len(part2))
	}
	if dialer.calls != 1 {
		t.Fatalf("dialer calls = %d, want 1", dialer.calls)
	}

	got := dialer.conn.(*recordingConnWithRead).writes.String()
	if !bytes.Contains([]byte(got), []byte("CONNECT example.com:443 HTTP/1.1\r\n")) {
		t.Fatalf("proxy connect request missing: %q", got)
	}
	if !bytes.HasSuffix([]byte(got), []byte("POX")) {
		t.Fatalf("buffered tcp payload missing after CONNECT handshake: %q", got)
	}
}

func TestConnRejectsOversizedSingleWriteAfterHTTPRequestLine(t *testing.T) {
	dialer := &recordingDialer{conn: &recordingConn{}}
	conn := NewConn(context.Background(), dialer, &HttpProxy{Addr: "proxy.example:8080"}, "example.com:80", "tcp")

	b := append([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n"), bytes.Repeat([]byte("X-Test: value\r\n"), 500000)...)
	n, err := conn.Write(b)
	if err == nil {
		t.Fatal("Write() error = nil, want oversized header error")
	}
	if n != 0 {
		t.Fatalf("Write() wrote %d bytes after rejecting oversized headers", n)
	}
	if got := conn.pendingFirstWrite.Len(); got != 0 {
		t.Fatalf("pendingFirstWrite retained %d bytes after rejection", got)
	}
	if dialer.calls != 0 {
		t.Fatalf("dialer calls = %d, want 0", dialer.calls)
	}
}

func TestConnDeadlineAfterFailedHandshakeReturnsEOF(t *testing.T) {
	parent := &deadlineRecordingDialer{}
	conn := NewConn(context.Background(), parent, &HttpProxy{Addr: "proxy.example:8080"}, "example.com:80", "tcp")

	if _, err := conn.Write([]byte("payload")); err == nil {
		t.Fatal("initial Write() error = nil, want handshake failure")
	}
	if err := conn.SetDeadline(time.Now()); err != io.EOF {
		t.Fatalf("SetDeadline() error = %v, want io.EOF after failed handshake", err)
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for condition")
}

type barrierDialer struct {
	entered chan struct{}
	release chan struct{}
	conn    netproxy.Conn
	ignore  bool
	calls   atomic.Int32
}

func (d *barrierDialer) DialContext(ctx context.Context, _, _ string) (netproxy.Conn, error) {
	d.calls.Add(1)
	select {
	case d.entered <- struct{}{}:
	default:
	}
	if d.ignore {
		<-d.release
		return d.conn, nil
	}
	select {
	case <-d.release:
		return d.conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type countingConn struct {
	net.Conn
	writes atomic.Int32
	closes atomic.Int32
}

func (c *countingConn) Read(p []byte) (int, error) {
	if c.Conn != nil {
		return c.Conn.Read(p)
	}
	return 0, io.EOF
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	if c.Conn != nil {
		return c.Conn.Write(p)
	}
	return len(p), nil
}

func (c *countingConn) Close() error {
	c.closes.Add(1)
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}

func (c *countingConn) SetDeadline(time.Time) error      { return nil }
func (c *countingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *countingConn) SetWriteDeadline(time.Time) error { return nil }
func (c *countingConn) LocalAddr() net.Addr              { return nil }
func (c *countingConn) RemoteAddr() net.Addr             { return nil }

func TestCloseDuringDialCancelsHandshake(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	candidate := &countingConn{}
	dialer := &barrierDialer{entered: entered, release: release, conn: candidate}
	conn := NewConn(context.Background(), dialer, &HttpProxy{Addr: "proxy.example:8080"}, "example.com:443", "tcp")

	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("client hello"))
		errCh <- err
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("DialContext was not entered")
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	close(release)

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Write succeeded after Close during Dial")
		}
	case <-time.After(time.Second):
		t.Fatal("Write remained blocked after Close during Dial")
	}
	if conn.published.Load() != nil {
		t.Fatal("handshake published a conn after Close during Dial")
	}
	if candidate.closes.Load() != 0 {
		t.Fatalf("candidate closed %d times, want 0 because Dial returned ctx error", candidate.closes.Load())
	}
}

func TestCloseDuringIgnoredDialClosesLateCandidate(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	candidate := &countingConn{Conn: client}
	go func() {
		buf := make([]byte, 256)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()
	dialer := &barrierDialer{entered: entered, release: release, conn: candidate, ignore: true}
	conn := NewConn(context.Background(), dialer, &HttpProxy{Addr: "proxy.example:8080"}, "example.com:443", "tcp")

	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("client hello"))
		errCh <- err
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("DialContext was not entered")
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	close(release)

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Write succeeded after ignored Dial returned late")
		}
	case <-time.After(time.Second):
		t.Fatal("Write remained blocked after late ignored Dial")
	}
	waitFor(t, time.Second, func() bool { return candidate.closes.Load() == 1 })
	if conn.published.Load() != nil {
		t.Fatal("late ignored Dial published a conn")
	}
	if candidate.closes.Load() != 1 {
		t.Fatalf("candidate closed %d times, want exactly 1", candidate.closes.Load())
	}
}

func TestCloseBeforeWriteDoesNotDial(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	dialer := &barrierDialer{entered: entered, release: release, conn: &countingConn{}}
	conn := NewConn(context.Background(), dialer, &HttpProxy{Addr: "proxy.example:8080"}, "example.com:443", "tcp")
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	n, err := conn.Write([]byte("client hello"))
	if n != 0 || err == nil {
		t.Fatalf("Write after Close = (%d, %v), want error", n, err)
	}
	if dialer.calls.Load() != 0 {
		t.Fatalf("DialContext called %d times after Close-before-Write", dialer.calls.Load())
	}
}

func TestPublishConnRejectedAfterCloseDiscardsLocalCandidate(t *testing.T) {
	candidate := &countingConn{}
	conn := NewConn(context.Background(), noopDialer{}, &HttpProxy{Addr: "proxy.example:8080"}, "example.com:443", "tcp")
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := conn.publishConn(candidate, false); got != publishRejected {
		t.Fatalf("publishConn after Close = %v, want rejected", got)
	}
	if conn.published.Load() != nil {
		t.Fatal("rejected publish installed a conn")
	}
}

func TestPublishConnAndCloseExactlyOnceOwnership(t *testing.T) {
	for i := 0; i < 200; i++ {
		candidate := &countingConn{}
		conn := NewConn(context.Background(), noopDialer{}, &HttpProxy{Addr: "proxy.example:8080"}, "example.com:443", "tcp")
		conn.life.Store(connLifeHandshaking)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			switch conn.publishConn(candidate, false) {
			case publishRejected:
				conn.discardCandidate(candidate)
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			_ = conn.Close()
		}()
		close(start)
		wg.Wait()
		if got := candidate.closes.Load(); got != 1 {
			t.Fatalf("iteration %d: candidate closed %d times, want exactly 1", i, got)
		}
	}
}

func TestCloseDoesNotAcquireShakeMutex(t *testing.T) {
	conn := NewConn(context.Background(), noopDialer{}, &HttpProxy{Addr: "proxy.example:8080"}, "example.com:443", "tcp")
	conn.muShake.Lock()
	done := make(chan struct{})
	go func() {
		_ = conn.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		conn.muShake.Unlock()
		t.Fatal("Close blocked on muShake")
	}
	conn.muShake.Unlock()
}

func TestCloseUnblocksHandshakeRead(t *testing.T) {
	conn := NewConn(context.Background(), &recordingDialer{conn: &recordingConn{}}, &HttpProxy{Addr: "proxy.example:8080"}, "example.com:443", "tcp")
	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 8))
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("Read after Close: %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read remained blocked after Close")
	}
}

func TestHTTP2LogicalCloseDoesNotClosePooledPhysicalConn(t *testing.T) {
	physical := &closeCountConn{}
	pr, pw := io.Pipe()
	logical := newHTTP2Conn(physical, pw, pr, nil)
	c := NewConn(context.Background(), &recordingDialer{conn: physical}, &HttpProxy{Addr: "proxy.example:443", https: true}, "example.com:443", "tcp")
	if c.publishConn(logical, true) != publishOK {
		t.Fatal("failed to publish logical h2 conn")
	}
	c.cancelShakeFinished()

	if err := c.Close(); err != nil && err != io.ErrClosedPipe {
		t.Fatalf("logical Close: %v", err)
	}
	if physical.closes.Load() != 0 {
		t.Fatalf("physical conn closed %d times, want 0", physical.closes.Load())
	}
}

func TestHTTP2LogicalCloseClosesRequestPipeAndResponseBody(t *testing.T) {
	physical := &closeCountConn{}
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pr.Close() })
	body := &closeCountReadCloser{Reader: bytes.NewReader(nil)}
	logical := newHTTP2Conn(physical, pw, body, nil)
	c := NewConn(context.Background(), &recordingDialer{conn: physical}, &HttpProxy{Addr: "proxy.example:443", https: true}, "example.com:443", "tcp")
	if c.publishConn(logical, true) != publishOK {
		t.Fatal("failed to publish logical h2 conn")
	}
	c.cancelShakeFinished()

	if err := c.Close(); err != nil && err != io.ErrClosedPipe {
		t.Fatalf("logical Close: %v", err)
	}
	if _, err := pw.Write([]byte("x")); err == nil {
		t.Fatal("request pipe still writable after logical Close")
	}
	if body.closes.Load() != 1 {
		t.Fatalf("resp.Body closed %d times, want 1", body.closes.Load())
	}
	if physical.closes.Load() != 0 {
		t.Fatalf("physical conn closed %d times, want 0", physical.closes.Load())
	}
}

func TestHTTP2HandshakeContextDoesNotAbortPublishedStream(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	received := make(chan string, 2)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		server := http2.Server{}
		server.ServeConn(serverSide, &http2.ServeConnOpts{Handler: stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			w.WriteHeader(stdhttp.StatusOK)
			w.(stdhttp.Flusher).Flush()
			buf := make([]byte, 3)
			for range 2 {
				if _, err := io.ReadFull(r.Body, buf); err != nil {
					return
				}
				received <- string(buf)
			}
		})})
	}()

	transport := &http2.Transport{}
	h2Client, err := transport.NewClientConn(clientSide)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	oldPool := connPool
	connPool = newH2ConnsPool()
	t.Cleanup(func() {
		connPool = oldPool
		_ = h2Client.Close()
		_ = clientSide.Close()
		_ = serverSide.Close()
		select {
		case <-serverDone:
		case <-time.After(time.Second):
		}
	})

	const proxyAddr = "proxy.example:443"
	key := "|tcp|" + proxyAddr
	conns := newLockedList()
	conns.l.PushFront(&h2Conn{rawConn: clientSide, h2Conn: h2Client})
	connPool.h2ConnsPool[key] = conns

	dialer := &recordingDialer{}
	conn := NewConn(context.Background(), dialer, &HttpProxy{Addr: proxyAddr, https: true}, "target.example:443", "tcp")
	if n, err := conn.Write([]byte("one")); err != nil || n != 3 {
		t.Fatalf("first Write = (%d, %v), want (3, nil)", n, err)
	}
	if dialer.calls != 0 {
		t.Fatalf("dialer called %d times despite cached H2 connection", dialer.calls)
	}
	select {
	case got := <-received:
		if got != "one" {
			t.Fatalf("first proxy payload = %q, want one", got)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy did not receive first payload")
	}

	if n, err := conn.Write([]byte("two")); err != nil || n != 3 {
		t.Fatalf("second Write = (%d, %v), want (3, nil)", n, err)
	}
	select {
	case got := <-received:
		if got != "two" {
			t.Fatalf("second proxy payload = %q, want two", got)
		}
	case <-time.After(time.Second):
		t.Fatal("published H2 stream was aborted with the handshake context")
	}
	if err := conn.Close(); err != nil && err != io.ErrClosedPipe {
		t.Fatalf("Close: %v", err)
	}
}

type closeCountReadCloser struct {
	io.Reader
	closes atomic.Int32
}

func (c *closeCountReadCloser) Close() error {
	c.closes.Add(1)
	return nil
}

type closeCountConn struct {
	recordingConn
	closes atomic.Int32
}

func (c *closeCountConn) Close() error {
	c.closes.Add(1)
	return nil
}
func (c *closeCountConn) LocalAddr() net.Addr  { return nil }
func (c *closeCountConn) RemoteAddr() net.Addr { return nil }

type recordingDialer struct {
	conn  netproxy.Conn
	calls int
}

func (d *recordingDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	d.calls++
	return d.conn, nil
}

type recordingConn struct {
	writes bytes.Buffer
}

func (c *recordingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *recordingConn) Write(p []byte) (int, error)      { return c.writes.Write(p) }
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

type recordingConnWithRead struct {
	recordingConn
	read *bytes.Buffer
}

func (c *recordingConnWithRead) Read(p []byte) (int, error) {
	if c.read == nil {
		return 0, io.EOF
	}
	return c.read.Read(p)
}

func TestH2PoolClosesRawConnOnUnsupportedALPN(t *testing.T) {
	cert := mustSelfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"foo"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
		_ = c.(*tls.Conn).Handshake()
	}()

	raw, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"foo"},
		ServerName:         "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	dialer := &recordingDialer{conn: raw}
	pool := newH2ConnsPool()
	_, _, err = pool.GetConn(context.Background(), dialer, "proxy.example:443", "tcp")
	if err == nil {
		t.Fatal("expected unsupported ALPN error")
	}
	if !strings.Contains(err.Error(), "unsupported application layer protocol") {
		t.Fatalf("err = %v", err)
	}
	if _, writeErr := raw.Write([]byte{1}); writeErr == nil {
		t.Fatal("client rawConn still writable after unsupported ALPN")
	}

	select {
	case serverConn := <-accepted:
		done := make(chan error, 1)
		go func() {
			_, readErr := serverConn.Read(make([]byte, 1))
			done <- readErr
		}()
		select {
		case readErr := <-done:
			if readErr == nil {
				t.Fatal("server still readable after unsupported ALPN; client rawConn was not closed")
			}
			var ne net.Error
			if errors.As(readErr, &ne) && ne.Timeout() {
				t.Fatal("server Read timed out; client rawConn was not closed")
			}
		case <-time.After(time.Second):
			t.Fatal("server Read remained blocked; client rawConn was not closed")
		}
		_ = serverConn.Close()
	case <-time.After(time.Second):
		t.Fatal("server did not accept")
	}
}

func mustSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"example.com"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: mustMarshalEC(t, key),
	}))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mustMarshalEC(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
