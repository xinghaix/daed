package juicity

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/infra/clientring"
	"github.com/daeuniverse/outbound/protocol/trojanc"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/congestion"
)

type juicityTestQUICConn struct {
	ctx          context.Context
	cancel       context.CancelFunc
	openStream   func() (quic.Stream, error)
	closed       atomic.Bool
	contextCalls atomic.Int32
	onContext    func(n int32)
}

func (c *juicityTestQUICConn) AcceptStream(context.Context) (quic.Stream, error) {
	return nil, errors.New("unused")
}

func (c *juicityTestQUICConn) AcceptUniStream(context.Context) (quic.ReceiveStream, error) {
	return nil, errors.New("unused")
}

func (c *juicityTestQUICConn) OpenStream() (quic.Stream, error) {
	if c.openStream != nil {
		return c.openStream()
	}
	return nil, errors.New("unused")
}

func (c *juicityTestQUICConn) OpenStreamSync(context.Context) (quic.Stream, error) {
	return c.OpenStream()
}

func (c *juicityTestQUICConn) OpenUniStream() (quic.SendStream, error) {
	return nil, errors.New("unused")
}

func (c *juicityTestQUICConn) OpenUniStreamSync(context.Context) (quic.SendStream, error) {
	return nil, errors.New("unused")
}

func (c *juicityTestQUICConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *juicityTestQUICConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *juicityTestQUICConn) CloseWithError(quic.ApplicationErrorCode, string) error {
	c.closed.Store(true)
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

func (c *juicityTestQUICConn) Context() context.Context {
	n := c.contextCalls.Add(1)
	if c.onContext != nil {
		c.onContext(n)
	}
	if c.ctx != nil {
		return c.ctx
	}
	return context.Background()
}

func (c *juicityTestQUICConn) ConnectionState() quic.ConnectionState {
	return quic.ConnectionState{}
}

func (c *juicityTestQUICConn) SendDatagram([]byte) error {
	return nil
}

func (c *juicityTestQUICConn) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, errors.New("unused")
}

func (c *juicityTestQUICConn) SetCongestionControl(congestion.CongestionControl) {}

func (c *juicityTestQUICConn) ReleaseDatagram([]byte) {}

type juicityTestStream struct {
	ctx     context.Context
	writeFn func([]byte) (int, error)
}

func (s *juicityTestStream) StreamID() quic.StreamID {
	return 0
}

func (s *juicityTestStream) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (s *juicityTestStream) Write(p []byte) (int, error) {
	if s.writeFn != nil {
		return s.writeFn(p)
	}
	return len(p), nil
}

func (s *juicityTestStream) Close() error {
	return nil
}

func (s *juicityTestStream) CancelRead(quic.StreamErrorCode) {}

func (s *juicityTestStream) CancelWrite(quic.StreamErrorCode) {}

func (s *juicityTestStream) Context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

func (s *juicityTestStream) SetDeadline(time.Time) error {
	return nil
}

func (s *juicityTestStream) SetReadDeadline(time.Time) error {
	return nil
}

func (s *juicityTestStream) SetWriteDeadline(time.Time) error {
	return nil
}

func TestIsStreamLimitReached(t *testing.T) {
	if !isStreamLimitReached(&quic.StreamLimitReachedError{}) {
		t.Fatal("expected typed stream-limit error to be detected")
	}
	if !isStreamLimitReached(errors.New("too many open streams")) {
		t.Fatal("expected stream-limit message to be detected")
	}
	if isStreamLimitReached(errors.New("connection closed")) {
		t.Fatal("did not expect unrelated error to be detected as stream-limit")
	}
}

func TestGetQuicConnDialFailureDoesNotDeadlock(t *testing.T) {
	clientCtx, clientCancel := context.WithCancel(context.Background())
	defer clientCancel()

	client := &clientImpl{
		ClientOption: &ClientOption{
			TlsConfig: &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h3"},
				ServerName:         "localhost",
			},
			QuicConfig: &quic.Config{},
			Ctx:        clientCtx,
			Cancel:     clientCancel,
		},
	}

	detached := make(chan struct{})
	client.detachCallback = func() {
		close(detached)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	udpConn := pc.(*net.UDPConn)
	defer func() { _ = udpConn.Close() }()

	raddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:1")
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := client.getQuicConn(ctx, nil, func(context.Context, netproxy.Dialer) (*quic.Transport, net.Addr, error) {
			return &quic.Transport{Conn: udpConn}, raddr, nil
		})
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected getQuicConn to fail with canceled context")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("getQuicConn deadlocked on transport dial failure")
	}

	// A per-attempt dial failure (here: the caller context was cancelled)
	// must stay retryable: the shared client is not detached, its context
	// is not cancelled, and the next attempt dials again instead of failing
	// fast with ErrClientClosed.
	select {
	case <-detached:
		t.Fatal("failed dial must not detach the client")
	default:
	}
	select {
	case <-clientCtx.Done():
		t.Fatal("failed dial must not cancel the client context")
	default:
	}

	if _, err := udpConn.WriteToUDP([]byte("x"), raddr); err == nil {
		t.Fatal("expected failed dial path to close the underlay UDP socket")
	}

	errCh2 := make(chan error, 1)
	go func() {
		_, err := client.getQuicConn(context.Background(), nil, func(context.Context, netproxy.Dialer) (*quic.Transport, net.Addr, error) {
			return nil, nil, errors.New("second dial also fails")
		})
		errCh2 <- err
	}()
	select {
	case err := <-errCh2:
		if err == nil {
			t.Fatal("expected second getQuicConn attempt to fail")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second getQuicConn attempt deadlocked")
	}
}

func TestGetQuicConnRejectsClosedCachedConnection(t *testing.T) {
	clientCtx, clientCancel := context.WithCancel(context.Background())
	defer clientCancel()
	quicCtx, quicCancel := context.WithCancel(context.Background())
	quicCancel()

	client := &clientImpl{
		ClientOption: &ClientOption{
			Ctx:    clientCtx,
			Cancel: clientCancel,
		},
		quicConn: &juicityTestQUICConn{ctx: quicCtx},
	}

	_, err := client.getQuicConn(context.Background(), nil, nil)
	if !errors.Is(err, common.ErrClientClosed) {
		t.Fatalf("expected ErrClientClosed, got %v", err)
	}
	if client.quicConn != nil {
		t.Fatal("expected closed cached QUIC connection to be dropped")
	}
	select {
	case <-clientCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("expected client context to be canceled")
	}
}

func TestClientRingRetriesAfterClosedStream(t *testing.T) {
	staleCtx, staleCancel := context.WithCancel(context.Background())
	defer staleCancel()
	freshCtx, freshCancel := context.WithCancel(context.Background())
	defer freshCancel()
	var mu sync.Mutex
	var dialed []*clientImpl

	staleClient := &clientImpl{
		ClientOption: &ClientOption{
			Ctx:    staleCtx,
			Cancel: staleCancel,
		},
		quicConn: &juicityTestQUICConn{
			openStream: func() (quic.Stream, error) {
				return nil, errors.New("connection closed")
			},
		},
	}
	freshClient := &clientImpl{
		ClientOption: &ClientOption{
			Ctx:    freshCtx,
			Cancel: freshCancel,
		},
		quicConn: &juicityTestQUICConn{
			openStream: func() (quic.Stream, error) {
				return &juicityTestStream{}, nil
			},
		},
	}

	r := newClientRing(func(func(int64)) *clientImpl {
		mu.Lock()
		defer mu.Unlock()
		if len(dialed) == 0 {
			dialed = append(dialed, staleClient)
			return staleClient
		}
		dialed = append(dialed, freshClient)
		return freshClient
	}, 0)

	// Prime the ring with the stale client (a failure on a freshly created
	// node returns directly without walking), so the real dial below fails
	// on it and fails over to a fresh client.
	if err := r.ring.TryNext(func(*clientring.Node[*clientImpl]) error { return common.ErrHoldOn }); err == nil {
		t.Fatal("priming TryNext() = nil, want hold-on")
	}

	conn, err := r.DialContext(context.Background(), &trojanc.Metadata{
		Metadata: protocol.Metadata{
			Type:     protocol.MetadataTypeDomain,
			Hostname: "example.com",
			Port:     443,
			IsClient: true,
		},
		Network: "tcp",
	}, nil, nil)
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if conn == nil {
		t.Fatal("expected retry to return a connection")
	}
	select {
	case <-staleCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("expected stale client to be canceled")
	}
}

func TestClientRingCloseCancelsClientsAndClearsRing(t *testing.T) {
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel1()
	defer cancel2()
	client1 := &clientImpl{ClientOption: &ClientOption{Ctx: ctx1, Cancel: cancel1}}
	client2 := &clientImpl{ClientOption: &ClientOption{Ctx: ctx2, Cancel: cancel2}}
	var mu sync.Mutex
	dialed := 0
	r := newClientRing(func(func(int64)) *clientImpl {
		mu.Lock()
		defer mu.Unlock()
		if dialed == 0 {
			dialed++
			return client1
		}
		dialed++
		return client2
	}, 0)
	// Prime the ring with one client, then fail on it so a second client
	// is inserted and the attempt succeeds there.
	if err := r.ring.TryNext(func(*clientring.Node[*clientImpl]) error { return common.ErrHoldOn }); err == nil {
		t.Fatal("priming TryNext() = nil, want hold-on")
	}
	attempts := 0
	if err := r.ring.TryNext(func(*clientring.Node[*clientImpl]) error {
		attempts++
		if attempts == 1 {
			return common.ErrHoldOn
		}
		return nil
	}); err != nil {
		t.Fatalf("second TryNext() error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}

	if err := r.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := r.ring.Len(); got != 0 {
		t.Fatalf("ring not cleared: len=%d", got)
	}
	select {
	case <-ctx1.Done():
	case <-time.After(time.Second):
		t.Fatal("client1 context was not canceled")
	}
	select {
	case <-ctx2.Done():
	case <-time.After(time.Second):
		t.Fatal("client2 context was not canceled")
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

type tempNetError struct{ msg string }

func (e tempNetError) Error() string   { return e.msg }
func (e tempNetError) Timeout() bool   { return true }
func (e tempNetError) Temporary() bool { return true }

func newJuicityTestClient(t *testing.T, conn quic.Connection) *clientImpl {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &clientImpl{
		ClientOption: &ClientOption{
			Ctx:    ctx,
			Cancel: cancel,
		},
		quicConn: conn,
	}
}

func TestHandleIfConnectionClosedKeepsTunnelOnTemporaryErrors(t *testing.T) {
	origin := &juicityTestQUICConn{ctx: context.Background()}
	client := newJuicityTestClient(t, origin)

	cases := []error{
		context.Canceled,
		context.DeadlineExceeded,
		fmt.Errorf("open stream: %w", context.Canceled),
		fmt.Errorf("join: %w", errors.Join(context.DeadlineExceeded, errors.New("udp"))),
		tempNetError{msg: "temporarily unavailable"},
		fmt.Errorf("wrap: %w", tempNetError{msg: "timeout"}),
	}
	for _, err := range cases {
		if client.handleIfConnectionClosed(err, origin) {
			t.Fatalf("temporary error %v closed the tunnel", err)
		}
		if client.quicConn != origin {
			t.Fatalf("temporary error %v dropped quicConn", err)
		}
		if origin.closed.Load() {
			t.Fatalf("temporary error %v closed origin conn", err)
		}
		select {
		case <-client.Ctx.Done():
			t.Fatalf("temporary error %v canceled client context", err)
		default:
		}
	}
}

func TestHandleIfConnectionClosedClosesOnlyOriginConn(t *testing.T) {
	origin := &juicityTestQUICConn{ctx: context.Background()}
	replacement := &juicityTestQUICConn{ctx: context.Background()}
	client := newJuicityTestClient(t, replacement)

	if client.handleIfConnectionClosed(errors.New("application closed"), origin) {
		t.Fatal("stale origin error must not close the replacement tunnel")
	}
	if client.quicConn != replacement {
		t.Fatal("replacement quicConn was dropped")
	}
	if replacement.closed.Load() {
		t.Fatal("replacement conn was closed")
	}
	if origin.closed.Load() {
		t.Fatal("stale origin should not be closed by identity mismatch")
	}
	select {
	case <-client.Ctx.Done():
		t.Fatal("stale origin error canceled the live client")
	default:
	}

	client.quicConn = origin
	if !client.handleIfConnectionClosed(errors.New("application closed"), origin) {
		t.Fatal("permanent origin error should close the tunnel")
	}
	if client.quicConn != nil {
		t.Fatal("expected origin quicConn to be cleared")
	}
	if !origin.closed.Load() {
		t.Fatal("expected origin conn CloseWithError")
	}
	select {
	case <-client.Ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("expected permanent error to cancel client context")
	}
}

func TestDialContextTemporaryOpenStreamDoesNotCloseTunnel(t *testing.T) {
	origin := &juicityTestQUICConn{
		ctx: context.Background(),
		openStream: func() (quic.Stream, error) {
			return nil, fmt.Errorf("open: %w", context.Canceled)
		},
	}
	client := newJuicityTestClient(t, origin)

	_, err := client.DialContext(context.Background(), &trojanc.Metadata{
		Metadata: protocol.Metadata{IsClient: true, Hostname: "example.com", Port: 443},
		Network:  "tcp",
	}, nil, nil)
	if err == nil {
		t.Fatal("expected OpenStream error")
	}
	if errors.Is(err, common.ErrClientClosed) {
		t.Fatalf("temporary OpenStream error returned closed client: %v", err)
	}
	if client.quicConn != origin || origin.closed.Load() {
		t.Fatal("temporary OpenStream error closed the shared tunnel")
	}
}

func TestUnderlayAuthenticationWriterReportsEachWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &clientImpl{ClientOption: &ClientOption{
		Ctx:          ctx,
		Cancel:       cancel,
		UnderlayAuth: make(chan *UnderlayAuth, 1),
	}}
	conn := &juicityTestQUICConn{ctx: context.Background()}
	stream := &juicityTestStream{}
	done := make(chan struct{})
	go func() {
		client.writeUnderlayAuthentications(conn, stream, client.UnderlayAuth)
		close(done)
	}()

	auth := &UnderlayAuth{
		IV:  make([]byte, CipherConf.SaltLen),
		Psk: make([]byte, CipherConf.KeyLen),
		Metadata: &trojanc.Metadata{
			Metadata: protocol.Metadata{Type: protocol.MetadataTypeDomain, Hostname: "example.com", Port: 443},
			Network:  "tcp",
		},
		result: make(chan error, 1),
	}
	client.UnderlayAuth <- auth
	select {
	case err := <-auth.result:
		if err != nil {
			t.Fatalf("authentication write: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("authentication writer did not report the write result")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("authentication writer did not stop with the client context")
	}
}

func TestUnderlayAuthenticationWritersAreConnectionBound(t *testing.T) {
	clientCtx, cancelClient := context.WithCancel(context.Background())
	defer cancelClient()
	client := &clientImpl{ClientOption: &ClientOption{Ctx: clientCtx, Cancel: cancelClient}}
	oldCtx, cancelOld := context.WithCancel(context.Background())
	newCtx, cancelNew := context.WithCancel(context.Background())
	defer cancelOld()
	defer cancelNew()
	oldCh := make(chan *UnderlayAuth, 1)
	newCh := make(chan *UnderlayAuth, 1)
	var oldWrites atomic.Int32
	var newWrites atomic.Int32
	oldDone := make(chan struct{})
	newDone := make(chan struct{})
	go func() {
		client.writeUnderlayAuthentications(
			&juicityTestQUICConn{ctx: oldCtx},
			&juicityTestStream{writeFn: func(p []byte) (int, error) { oldWrites.Add(1); return len(p), nil }},
			oldCh,
		)
		close(oldDone)
	}()
	go func() {
		client.writeUnderlayAuthentications(
			&juicityTestQUICConn{ctx: newCtx},
			&juicityTestStream{writeFn: func(p []byte) (int, error) { newWrites.Add(1); return len(p), nil }},
			newCh,
		)
		close(newDone)
	}()

	auth := &UnderlayAuth{
		IV:  make([]byte, CipherConf.SaltLen),
		Psk: make([]byte, CipherConf.KeyLen),
		Metadata: &trojanc.Metadata{
			Metadata: protocol.Metadata{Type: protocol.MetadataTypeDomain, Hostname: "example.com", Port: 443},
			Network:  "tcp",
		},
		result: make(chan error, 1),
	}
	newCh <- auth
	select {
	case err := <-auth.result:
		if err != nil {
			t.Fatalf("new connection auth write: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("new connection auth writer did not respond")
	}
	if oldWrites.Load() != 0 || newWrites.Load() != 1 {
		t.Fatalf("auth used wrong writer: old=%d new=%d", oldWrites.Load(), newWrites.Load())
	}
	cancelOld()
	cancelNew()
	select {
	case <-oldDone:
	case <-time.After(time.Second):
		t.Fatal("old auth writer did not stop")
	}
	select {
	case <-newDone:
	case <-time.After(time.Second):
		t.Fatal("new auth writer did not stop")
	}
}

func TestDialAuthDoesNotCloseReplacementOnOriginDone(t *testing.T) {
	originCtx, originCancel := context.WithCancel(context.Background())
	defer originCancel()
	enteredSelect := make(chan struct{}, 1)
	origin := &juicityTestQUICConn{
		ctx: originCtx,
		onContext: func(n int32) {
			// getQuicConn observes Context once; DialAuth observes it again
			// when entering the UnderlayAuth select.
			if n == 2 {
				select {
				case enteredSelect <- struct{}{}:
				default:
				}
			}
		},
	}
	replacement := &juicityTestQUICConn{ctx: context.Background()}
	client := newJuicityTestClient(t, origin)
	client.UnderlayAuth = make(chan *UnderlayAuth)

	errCh := make(chan error, 1)
	go func() {
		_, _, err := client.DialAuth(context.Background(), &trojanc.Metadata{
			Metadata: protocol.Metadata{IsClient: true, Hostname: "example.com", Port: 0},
			Network:  "udp",
		}, nil, nil)
		errCh <- err
	}()

	select {
	case <-enteredSelect:
	case <-time.After(time.Second):
		t.Fatal("DialAuth did not observe origin context for UnderlayAuth select")
	}
	client.connMutex.Lock()
	client.quicConn = replacement
	client.connMutex.Unlock()
	originCancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected DialAuth to fail after origin context is done")
		}
		if errors.Is(err, common.ErrClientClosed) {
			t.Fatalf("origin-done DialAuth closed the live client: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DialAuth did not return after origin context was canceled")
	}
	if client.quicConn != replacement {
		t.Fatal("replacement quicConn was dropped")
	}
	if replacement.closed.Load() {
		t.Fatal("replacement conn was closed")
	}
	select {
	case <-client.Ctx.Done():
		t.Fatal("origin-done DialAuth canceled the live client")
	default:
	}
}

func TestHandleIfConnectionClosedNilOriginDoesNotCloseCurrent(t *testing.T) {
	current := &juicityTestQUICConn{ctx: context.Background()}
	client := newJuicityTestClient(t, current)
	if client.handleIfConnectionClosed(errors.New("application closed"), nil) {
		t.Fatal("nil origin must not close the current tunnel")
	}
	if client.quicConn != current || current.closed.Load() {
		t.Fatal("nil origin closed the live connection")
	}
}

func TestDialContextStreamLimitDoesNotCloseTunnel(t *testing.T) {
	origin := &juicityTestQUICConn{
		ctx: context.Background(),
		openStream: func() (quic.Stream, error) {
			return nil, &quic.StreamLimitReachedError{}
		},
	}
	client := newJuicityTestClient(t, origin)

	_, err := client.DialContext(context.Background(), &trojanc.Metadata{
		Metadata: protocol.Metadata{IsClient: true, Hostname: "example.com", Port: 443},
		Network:  "tcp",
	}, nil, nil)
	if !errors.Is(err, common.ErrTooManyOpenStreams) {
		t.Fatalf("error = %v, want ErrTooManyOpenStreams", err)
	}
	if client.quicConn != origin || origin.closed.Load() {
		t.Fatal("stream-limit error closed the shared tunnel")
	}
}

func TestNewDialerKeepsDatagramsDisabled(t *testing.T) {
	d, err := NewDialer(nil, protocol.Header{
		User:         "00000000-0000-0000-0000-000000000000",
		Password:     "passwd",
		ProxyAddress: "127.0.0.1:443",
		Feature1:     "bbr",
		TlsConfig:    &tls.Config{},
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	jd := d.(*Dialer)
	cli := jd.clientRing.newClient(func(int64) {})
	if cli.QuicConfig == nil {
		t.Fatal("expected QUIC config")
	}
	if cli.QuicConfig.EnableDatagrams {
		t.Fatal("juicity must keep EnableDatagrams=false")
	}
}
