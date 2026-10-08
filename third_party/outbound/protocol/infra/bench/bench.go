// Package bench provides a unified data-path benchmark harness driven solely
// through the public netproxy.Conn / netproxy.Dialer interfaces, so protocols
// can be measured without changing any of their public APIs.
package bench

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// DiscardConn implements netproxy.Conn: Write drops data and returns immediately,
// Read returns EOF. It isolates the protocol-layer write path (encrypt + frame)
// from underlying IO and read-side cost.
var _ netproxy.Conn = (*DiscardConn)(nil)

type DiscardConn struct{}

func NewDiscardConn() *DiscardConn { return &DiscardConn{} }

func (DiscardConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (DiscardConn) Write(p []byte) (int, error)      { return len(p), nil }
func (DiscardConn) Close() error                     { return nil }
func (DiscardConn) SetDeadline(time.Time) error      { return nil }
func (DiscardConn) SetReadDeadline(time.Time) error  { return nil }
func (DiscardConn) SetWriteDeadline(time.Time) error { return nil }

// NetDiscardConn implements net.Conn (not just netproxy.Conn) for protocols whose
// underlying transport expects net.Conn (e.g. anytls session). Write discards,
// Read returns EOF, addresses return a stub.
var _ net.Conn = (*NetDiscardConn)(nil)

type NetDiscardConn struct{}

func NewNetDiscardConn() *NetDiscardConn { return &NetDiscardConn{} }

func (NetDiscardConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (NetDiscardConn) Write(p []byte) (int, error)      { return len(p), nil }
func (NetDiscardConn) Close() error                     { return nil }
func (NetDiscardConn) LocalAddr() net.Addr              { return netStubAddr{} }
func (NetDiscardConn) RemoteAddr() net.Addr             { return netStubAddr{} }
func (NetDiscardConn) SetDeadline(time.Time) error      { return nil }
func (NetDiscardConn) SetReadDeadline(time.Time) error  { return nil }
func (NetDiscardConn) SetWriteDeadline(time.Time) error { return nil }

type netStubAddr struct{}

func (netStubAddr) Network() string { return "stub" }
func (netStubAddr) String() string  { return "bench-stub" }

// TCPHarness describes a stream protocol attachment point driven by the unified
// benchmark. Adapters live in each protocol's _test.go and call the protocol's
// existing public constructor, so no protocol API is modified.
type TCPHarness interface {
	Name() string
	// NewConn wraps the given underlying conn with a protocol-layer conn used to
	// measure steady-state read/write. The returned conn must implement netproxy.Conn.
	NewConn(underlying netproxy.Conn) (netproxy.Conn, error)
}

// RunTCPWriteBench drives a steady-state write benchmark: payload is repeatedly
// written through the protocol layer into a discarding underlying conn. The same
// conn is reused to exclude dial/handshake cost and focus on per-byte encrypt+frame.
func RunTCPWriteBench(b *testing.B, h TCPHarness, payloadSize int) {
	b.Helper()
	payload := make([]byte, payloadSize)
	conn, err := h.NewConn(NewDiscardConn())
	if err != nil {
		b.Fatalf("%s NewConn: %v", h.Name(), err)
	}
	b.SetBytes(int64(payloadSize))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(payload); err != nil {
			b.Fatalf("%s Write: %v", h.Name(), err)
		}
	}
}

// RunTCPDialWriteBench drives a first-write benchmark: each iteration rebuilds the
// conn then writes once. It surfaces dial-time cost (handshake / key derivation /
// header serialization) plus the first frame.
func RunTCPDialWriteBench(b *testing.B, h TCPHarness, payloadSize int) {
	b.Helper()
	payload := make([]byte, payloadSize)
	b.SetBytes(int64(payloadSize))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := h.NewConn(NewDiscardConn())
		if err != nil {
			b.Fatalf("%s NewConn: %v", h.Name(), err)
		}
		if _, err := conn.Write(payload); err != nil {
			b.Fatalf("%s Write: %v", h.Name(), err)
		}
	}
}

// UDPDatagramHarness describes a datagram protocol attachment point for the
// receive hot path. Adapters feed a pre-built wire-format message into the
// protocol's internal parse/dispatch function, mirroring the existing
// processDatagram-style micro-benchmarks but behind a uniform contract.
type UDPDatagramHarness interface {
	Name() string
	// BuildDatagram returns a wire-format datagram carrying payloadSize bytes of
	// application data, as it would arrive from the transport (e.g. QUIC).
	BuildDatagram(b *testing.B, payloadSize int) []byte
	// ProcessDatagram consumes one datagram the same way the live receive loop does.
	ProcessDatagram(msg []byte)
}

// RunUDPDatagramBench drives the UDP receive hot path: a pre-built datagram is
// parsed on every iteration. No network, no transport connection — this isolates
// the per-datagram protocol parse + dispatch cost that runs once per inbound packet.
func RunUDPDatagramBench(b *testing.B, h UDPDatagramHarness, payloadSize int) {
	b.Helper()
	msg := h.BuildDatagram(b, payloadSize)
	b.SetBytes(int64(payloadSize))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.ProcessDatagram(msg)
	}
}
