package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"github.com/daeuniverse/outbound/pkg/coalesce"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/bufferred_conn"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

const (
	sessionReadBufferSize     = 4 << 10
	maxIdleSessions           = 1
	idleSessionTimeout        = 30 * time.Second
	idleSessionCheckInterval  = 10 * time.Second
	idleSessionProbeThreshold = 3 * time.Second
	idleSessionProbeTimeout   = 2 * time.Second
)

func init() {
	protocol.Register("anytls", NewDialer)
}

type Dialer struct {
	proxyAddress string
	nextDialer   netproxy.Dialer
	metadata     protocol.Metadata
	key          []byte
	tlsConfig    *tls.Config
	padding      atomic.Pointer[paddingFactory]

	sessionCounter atomic.Uint64

	idleSessionLock sync.Mutex
	idleSessions    map[uint64]*session
	sessions        map[uint64]*session
	closed          bool
	janitorDone     chan struct{}
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}
	sum := sha256.Sum256([]byte(header.Password))
	d := &Dialer{
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
		metadata:     metadata,
		key:          sum[:],
		tlsConfig:    header.TlsConfig,
		idleSessions: make(map[uint64]*session),
		sessions:     make(map[uint64]*session),
		janitorDone:  make(chan struct{}),
	}
	d.padding.Store(DefaultPaddingFactory.Load())
	go d.runIdleJanitor()
	return d, nil
}

func (d *Dialer) UnwrapDialer() netproxy.Dialer {
	return d.nextDialer
}

func (d *Dialer) watchSession(s *session) {
	for {
		select {
		case <-s.Done():
			d.idleSessionLock.Lock()
			if current, ok := d.idleSessions[s.seq]; ok && current == s {
				delete(d.idleSessions, s.seq)
			}
			if current, ok := d.sessions[s.seq]; ok && current == s {
				delete(d.sessions, s.seq)
			}
			d.idleSessionLock.Unlock()
			return
		case <-s.closeStreamChan:
			if !s.isReusableIdle() {
				continue
			}
			var closeSession bool
			d.idleSessionLock.Lock()
			if d.closed {
				closeSession = true
			} else {
				if _, ok := d.idleSessions[s.seq]; !ok {
					if len(d.idleSessions) >= maxIdleSessions {
						closeSession = true
					} else {
						d.idleSessions[s.seq] = s
					}
				}
			}
			d.idleSessionLock.Unlock()
			if closeSession {
				_ = s.Close()
			}
		}
	}
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp", "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.IsClient = d.metadata.IsClient
		if magicNetwork.Network == "udp" {
			mdata.Hostname = "sp.v2.udp-over-tcp.arpa"
		}
		tcpNetwork := netproxy.MagicNetwork{
			Network: "tcp",
			Mark:    magicNetwork.Mark,
			Mptcp:   magicNetwork.Mptcp,
		}.Encode()

		s, err := d.getSession(ctx, tcpNetwork)
		if err != nil {
			return nil, err
		}
		if magicNetwork.Network == "udp" {
			streamAddr := net.JoinHostPort(mdata.Hostname, strconv.Itoa(int(mdata.Port)))
			packetStream, err := s.newPacketStream(streamAddr, addr)
			if err != nil {
				_ = s.Close()
				return nil, err
			}
			return packetStream, nil
		}
		stream, err := s.newStream(addr)
		if err != nil {
			_ = s.Close()
			return nil, err
		}
		return stream, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
}

func (d *Dialer) getSession(ctx context.Context, tcpNetwork string) (*session, error) {
	for {
		candidate, err := d.popIdleSessionForReuse()
		if err != nil {
			return nil, err
		}
		if candidate == nil {
			break
		}

		now := time.Now()
		if candidate.idleTimedOut(now, idleSessionTimeout) {
			_ = candidate.Close()
			continue
		}
		if candidate.needsIdleProbe(now, idleSessionProbeThreshold) && !candidate.probeIdleHealth(idleSessionProbeTimeout) {
			_ = candidate.Close()
			continue
		}
		return candidate, nil
	}

	rawConn, err := d.nextDialer.DialContext(ctx, tcpNetwork, d.proxyAddress)
	if err != nil {
		return nil, err
	}
	conn, ok := rawConn.(net.Conn)
	if !ok {
		_ = rawConn.Close()
		return nil, fmt.Errorf("anytls requires net.Conn, got %T", rawConn)
	}

	// Coalesce TLS records: crypto/tls issues one socket write per record;
	// the coalescer batches the records of one write burst into one write.
	coConn := coalesce.New(conn)
	tlsConn := tls.Client(coConn, d.tlsConfig)
	if err := netproxy.HandshakeWithContext(ctx, tlsConn); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	// The TLS handshake writes through the coalescer; drain it so the
	// handshake bytes actually leave before the authentication packet.
	if err := coConn.Flush(); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	buf, err := buildAuthenticationPacket(d.key, d.padding.Load())
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	defer pool.Put(buf)
	restoreDeadline, err := netproxy.ApplyConnDeadlineFromContext(ctx, tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	defer restoreDeadline()
	if _, err := tlsConn.Write(buf); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	// The session read loop owns this buffer and releases it only after its
	// final Read returns. Creating it after authentication avoids failure-path
	// allocations for sessions that are never published.
	bufferedConn := bufferred_conn.NewBufferedConnSize(tlsConn, sessionReadBufferSize)
	seq := d.sessionCounter.Add(1)
	s := newSessionWithPadding(bufferedConn, seq, &d.padding)
	s.flusher = coConn
	d.idleSessionLock.Lock()
	if d.closed {
		d.idleSessionLock.Unlock()
		_ = s.Close()
		bufferedConn.ReleaseReader()
		return nil, net.ErrClosed
	}
	d.sessions[seq] = s
	d.idleSessionLock.Unlock()
	go d.watchSession(s)

	go func() { _ = s.run() }()

	return s, nil
}

func buildAuthenticationPacket(key []byte, padding *paddingFactory) (pool.PB, error) {
	paddingLen := 0
	if sizes := padding.GenerateRecordPayloadSizes(0); len(sizes) > 0 {
		paddingLen = sizes[0]
	}
	if paddingLen < 0 || paddingLen > maxFramePayloadSize {
		return nil, fmt.Errorf("invalid anytls authentication padding length: %d", paddingLen)
	}

	buffer := pool.Get(len(key) + 2 + paddingLen)
	copy(buffer, key)
	binary.BigEndian.PutUint16(buffer[len(key):], uint16(paddingLen))
	clear(buffer[len(key)+2:])
	return buffer, nil
}

func (d *Dialer) popIdleSessionForReuse() (*session, error) {
	d.idleSessionLock.Lock()
	defer d.idleSessionLock.Unlock()
	if d.closed {
		return nil, net.ErrClosed
	}
	for seq, s := range d.idleSessions {
		delete(d.idleSessions, seq)
		if s.closed.Load() || s.activeStreams.Load() != 0 || !s.state.CompareAndSwap(sessionStateIdle, sessionStateActive) {
			continue
		}
		return s, nil
	}
	return nil, nil
}

func (d *Dialer) runIdleJanitor() {
	ticker := time.NewTicker(idleSessionCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			d.closeExpiredIdleSessions(time.Now())
		case <-d.janitorDone:
			return
		}
	}
}

func (d *Dialer) closeExpiredIdleSessions(now time.Time) {
	var expired []*session
	d.idleSessionLock.Lock()
	for seq, s := range d.idleSessions {
		if s.closed.Load() || s.idleTimedOut(now, idleSessionTimeout) {
			delete(d.idleSessions, seq)
			expired = append(expired, s)
		}
	}
	d.idleSessionLock.Unlock()
	for _, s := range expired {
		_ = s.Close()
	}
}

func (d *Dialer) Close() error {
	d.idleSessionLock.Lock()
	if d.closed {
		d.idleSessionLock.Unlock()
		return nil
	}
	d.closed = true
	if d.janitorDone != nil {
		close(d.janitorDone)
	}
	sessions := make([]*session, 0, len(d.sessions))
	for _, s := range d.sessions {
		sessions = append(sessions, s)
	}
	d.idleSessions = make(map[uint64]*session)
	d.sessions = make(map[uint64]*session)
	d.idleSessionLock.Unlock()

	for _, s := range sessions {
		_ = s.Close()
	}
	return nil
}
