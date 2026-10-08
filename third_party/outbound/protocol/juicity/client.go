package juicity

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	outbounderrors "github.com/daeuniverse/outbound/common/errors"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/trojanc"
	"github.com/daeuniverse/outbound/protocol/tuic"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/olicesx/quic-go"
)

var (
	CipherConf = ciphers.AeadCiphersConf["chacha20-poly1305"]
)

const (
	UnderlaySaltLen = 32
)

func init() {
	if CipherConf.SaltLen != UnderlaySaltLen {
		panic("CipherConf.SaltLen != IvSize")
	}
}

type UnderlayAuth struct {
	IV       []byte
	Psk      []byte
	Metadata *trojanc.Metadata
	result   chan error
}

func (a *UnderlayAuth) PackFromPool() (buf pool.PB) {
	buf = pool.Get(a.Metadata.Len() + len(a.IV) + len(a.Psk))
	copy(buf, a.IV)
	copy(buf[len(a.IV):], a.Psk)
	a.Metadata.PackTo(buf[len(a.IV)+len(a.Psk):])
	return buf
}

func (a *UnderlayAuth) Unpack(r io.Reader) (n int, err error) {
	var _n int
	a.IV = make([]byte, CipherConf.SaltLen)
	if _n, err = io.ReadFull(r, a.IV); err != nil {
		return 0, err
	}
	n += _n
	a.Psk = make([]byte, CipherConf.KeyLen)
	if _n, err = io.ReadFull(r, a.Psk); err != nil {
		return 0, err
	}
	n += _n
	a.Metadata = &trojanc.Metadata{}
	if _n, err = a.Metadata.Unpack(r); err != nil {
		return 0, err
	}
	n += _n
	return n, nil
}

type ClientOption struct {
	TlsConfig            *tls.Config
	QuicConfig           *quic.Config
	Uuid                 [16]byte
	Password             string
	CongestionController string
	CWND                 uint64
	Ctx                  context.Context
	Cancel               func()
	UnderlayAuth         chan *UnderlayAuth
}

type clientImpl struct {
	*ClientOption

	quicConn  quic.Connection
	underConn net.PacketConn
	connMutex sync.Mutex

	detachCallback func()
}

func (t *clientImpl) getQuicConn(ctx context.Context, dialer netproxy.Dialer, dialFn common.DialFunc) (quic.Connection, error) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.quicConn != nil {
		select {
		case <-t.quicConn.Context().Done():
			t.closeConnectionLocked(quicContextErr(t.quicConn.Context()))
			return nil, common.ErrClientClosed
		default:
		}
		return t.quicConn, nil
	}
	transport, addr, err := dialFn(ctx, dialer)
	if err != nil {
		return nil, err
	}
	quicConn, err := transport.Dial(ctx, addr, t.TlsConfig, t.QuicConfig)
	if err != nil {
		// A failed dial is attempt-scoped: the caller context may have been
		// cancelled (a routine dial timeout) or the handshake hit a transient
		// failure. Poisoning the shared client (t.Cancel + detach) here would
		// permanently kill the node for every user over one failed attempt —
		// the neighboring failure paths below only tear down this transport,
		// and the next getQuicConn call dials again.
		_ = transport.Close()
		if transport.Conn != nil {
			_ = transport.Conn.Close()
		}
		return nil, err
	}

	common.SetCongestionController(quicConn, t.CongestionController, t.CWND)

	uniStream, err := quicConn.OpenUniStreamSync(ctx)
	if err != nil {
		_ = quicConn.CloseWithError(tuic.ProtocolError, err.Error())
		_ = transport.Close()
		if transport.Conn != nil {
			_ = transport.Conn.Close()
		}
		return nil, err
	}
	if err = t.writeAuthenticationHeader(quicConn, uniStream); err != nil {
		_ = uniStream.Close()
		_ = quicConn.CloseWithError(tuic.ProtocolError, err.Error())
		_ = transport.Close()
		if transport.Conn != nil {
			_ = transport.Conn.Close()
		}
		return nil, err
	}

	authCh := make(chan *UnderlayAuth, 64)
	t.underConn = transport.Conn
	t.quicConn = quicConn
	t.UnderlayAuth = authCh
	go t.writeUnderlayAuthentications(quicConn, uniStream, authCh)
	return quicConn, nil
}

func (t *clientImpl) writeAuthenticationHeader(quicConn quic.Connection, uniStream quic.SendStream) (err error) {
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	token, err := tuic.GenToken(quicConn.ConnectionState(), t.Uuid, t.Password)
	if err != nil {
		return err
	}
	err = tuic.NewAuthenticate(t.Uuid, token, Version0).WriteTo(buf)
	if err != nil {
		return err
	}
	_, err = buf.WriteTo(uniStream)
	return err
}

func (t *clientImpl) writeUnderlayAuthentications(quicConn quic.Connection, uniStream quic.SendStream, authCh <-chan *UnderlayAuth) {
	defer func() { _ = uniStream.Close() }()
	for {
		var auth *UnderlayAuth
		select {
		case <-t.Ctx.Done():
			return
		case <-quicConn.Context().Done():
			return
		case auth = <-authCh:
		}
		buf := auth.PackFromPool()
		_, err := uniStream.Write(buf)
		buf.Put()
		auth.result <- err
		if err != nil {
			_ = t.Close()
			return
		}
	}
}

func (t *clientImpl) Close() error {
	t.connMutex.Lock()
	select {
	case <-t.Ctx.Done():
		t.connMutex.Unlock()
		return nil
	default:
		t.Cancel()
	}
	if t.detachCallback != nil {
		go t.detachCallback()
		t.detachCallback = nil
	}
	t.connMutex.Unlock()
	// Give 10s for closing.
	time.AfterFunc(10*time.Second, func() {
		t.connMutex.Lock()
		defer t.connMutex.Unlock()
		if t.quicConn != nil {
			_ = t.quicConn.CloseWithError(tuic.ProtocolError, common.ErrClientClosed.Error())
			t.quicConn = nil
		}
		if t.underConn != nil {
			_ = t.underConn.Close()
			t.underConn = nil
		}
	})
	return nil
}

func (t *clientImpl) DialContext(ctx context.Context, metadata *trojanc.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (*Conn, error) {
	select {
	case <-t.Ctx.Done():
		return nil, common.ErrClientClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	quicConn, err := t.getQuicConn(ctx, dialer, dialFn)
	if err != nil {
		if errors.Is(err, common.ErrClientClosed) {
			return nil, err
		}
		return nil, fmt.Errorf("getQuicConn: %w", err)
	}
	quicStream, err := quicConn.OpenStream()
	if err != nil {
		if isStreamLimitReached(err) {
			return nil, common.ErrTooManyOpenStreams
		}
		if t.handleIfConnectionClosed(err, quicConn) {
			return nil, common.ErrClientClosed
		}
		return nil, fmt.Errorf("OpenStream: %w", err)
	}
	stream := NewConn(
		quicStream,
		metadata,
		nil,
		quicConn.Context().Done(),
	)
	return stream, nil
}

// handleIfConnectionClosed detaches the connection from the client pool and
// closes it when a permanent error (non-temporary) is encountered, matching
// the recovery pattern proven in hysteria2. originConn is the connection that
// produced err; a replacement must not be torn down for a stale failure.
func (t *clientImpl) handleIfConnectionClosed(err error, originConn quic.Connection) bool {
	if err == nil {
		return false
	}
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) {
		return false
	}
	if outbounderrors.IsTemporaryError(err) {
		return false
	}
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.quicConn != originConn {
		return false
	}
	t.closeConnectionLocked(err)
	return true
}

func quicContextErr(ctx context.Context) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return common.ErrClientClosed
}

func (t *clientImpl) closeConnectionLocked(err error) {
	if t.detachCallback != nil {
		go t.detachCallback()
		t.detachCallback = nil
	}
	if t.Cancel != nil {
		if t.Ctx != nil {
			select {
			case <-t.Ctx.Done():
			default:
				t.Cancel()
			}
		} else {
			t.Cancel()
		}
	}
	if t.quicConn != nil {
		errStr := common.ErrClientClosed.Error()
		if err != nil {
			errStr = err.Error()
		}
		_ = t.quicConn.CloseWithError(tuic.ProtocolError, errStr)
		t.quicConn = nil
	}
	if t.underConn != nil {
		_ = t.underConn.Close()
		t.underConn = nil
	}
}

func isStreamLimitReached(err error) bool {
	var streamLimitPtr *quic.StreamLimitReachedError
	if errors.As(err, &streamLimitPtr) {
		return true
	}
	var streamLimit quic.StreamLimitReachedError
	return errors.As(err, &streamLimit) || outbounderrors.IsStreamExhausted(err)
}

func (t *clientImpl) DialAuth(ctx context.Context, metadata *trojanc.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (iv []byte, psk []byte, err error) {
	select {
	case <-t.Ctx.Done():
		return nil, nil, common.ErrClientClosed
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}
	var quicConn quic.Connection
	var authCh chan *UnderlayAuth
	for {
		quicConn, err = t.getQuicConn(ctx, dialer, dialFn)
		if err != nil {
			if errors.Is(err, common.ErrClientClosed) {
				return nil, nil, err
			}
			return nil, nil, fmt.Errorf("getQuicConn: %w", err)
		}
		t.connMutex.Lock()
		if t.quicConn == quicConn {
			authCh = t.UnderlayAuth
			t.connMutex.Unlock()
			break
		}
		t.connMutex.Unlock()
	}
	iv = make([]byte, CipherConf.SaltLen)
	psk = make([]byte, CipherConf.KeyLen)
	iv[0], iv[1] = 0, 0
	_, _ = fastrand.Read(iv[2:])
	_, _ = fastrand.Read(psk)
	auth := &UnderlayAuth{
		IV:       iv,
		Psk:      psk,
		Metadata: metadata,
		result:   make(chan error, 1),
	}
	select {
	case authCh <- auth:
	case <-quicConn.Context().Done():
		// The QUIC connection itself is gone. Detach that origin even if the
		// context cause looks like a cancellation, but never close a replacement.
		err := quicContextErr(quicConn.Context())
		t.connMutex.Lock()
		if t.quicConn == quicConn {
			t.closeConnectionLocked(err)
			t.connMutex.Unlock()
			return nil, nil, common.ErrClientClosed
		}
		t.connMutex.Unlock()
		return nil, nil, err
	case <-t.Ctx.Done():
		return nil, nil, common.ErrClientClosed
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	select {
	case err = <-auth.result:
		if err != nil {
			return nil, nil, err
		}
		return iv, psk, nil
	case <-quicConn.Context().Done():
		return nil, nil, quicContextErr(quicConn.Context())
	case <-t.Ctx.Done():
		return nil, nil, common.ErrClientClosed
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

func (t *clientImpl) setOnClose(f func()) {
	t.detachCallback = f
}
