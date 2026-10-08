package proto

import (
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	bytesbuffer "github.com/daeuniverse/outbound/pool/bytes"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
	"github.com/daeuniverse/outbound/protocol/shadowsocks_stream"
)

// markerPacketConn is a netproxy.PacketConn whose only variable behaviour is
// the optional destructive write-deadline declaration.
type markerPacketConn struct {
	marker bool
}

func (c *markerPacketConn) Read(_ []byte) (int, error) { return 0, io.EOF }
func (c *markerPacketConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *markerPacketConn) ReadFrom(_ []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}

func (c *markerPacketConn) WriteTo(p []byte, _ string) (int, error) {
	return len(p), nil
}
func (c *markerPacketConn) Close() error                       { return nil }
func (c *markerPacketConn) SetDeadline(_ time.Time) error      { return nil }
func (c *markerPacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *markerPacketConn) SetWriteDeadline(_ time.Time) error { return nil }
func (c *markerPacketConn) WriteDeadlineClosesSession() bool   { return c.marker }

// noopProtocol is a minimal IProtocol stub: the constructor only stores it.
type noopProtocol struct{}

func (p *noopProtocol) InitWithServerInfo(_ *ServerInfo)          {}
func (p *noopProtocol) Encode(data []byte) ([]byte, error)        { return data, nil }
func (p *noopProtocol) Decode(data []byte) ([]byte, int, error)   { return data, len(data), nil }
func (p *noopProtocol) EncodePkt(_ *bytesbuffer.Buffer) error     { return nil }
func (p *noopProtocol) DecodePkt(data []byte) (pool.Bytes, error) { return nil, nil }
func (p *noopProtocol) SetData(_ interface{})                     {}
func (p *noopProtocol) GetData() interface{}                      { return nil }
func (p *noopProtocol) GetOverhead() int                          { return 0 }

// PacketConn delegates SetWriteDeadline to the wrapped transport unchanged
// (production: the dialer wraps shadowsocks_stream.DialUdpTransport, whose
// own forward would otherwise be erased by this outer layer), so its
// destructive-write-deadline declaration must follow that transport in both
// directions. Built through the real NewPacketConn constructor.
func TestPacketConnForwardsWriteDeadlineBehavior(t *testing.T) {
	destructive, err := NewPacketConn(&markerPacketConn{marker: true}, &noopProtocol{}, "1.2.3.4:53")
	if err != nil {
		t.Fatalf("NewPacketConn() error = %v", err)
	}
	if !netproxy.WriteDeadlineClosesSession(destructive) {
		t.Fatal("SSR proto PacketConn must forward a true WriteDeadlineClosesSession of its wrapped transport")
	}
	normal, err := NewPacketConn(&markerPacketConn{marker: false}, &noopProtocol{}, "1.2.3.4:53")
	if err != nil {
		t.Fatalf("NewPacketConn() error = %v", err)
	}
	if netproxy.WriteDeadlineClosesSession(normal) {
		t.Fatal("SSR proto PacketConn must forward a false WriteDeadlineClosesSession of its wrapped transport")
	}
}

// The real production chain: the dialer wraps a shadowsocks_stream.UdpConn
// (whose own forward was fixed earlier) in this SSR PacketConn. The outer
// layer must not erase the inner declaration in either direction.
func TestPacketConnForwardsRealShadowsocksStreamChain(t *testing.T) {
	cipher, err := ciphers.NewStreamCipher("aes-128-cfb", "test-password")
	if err != nil {
		t.Fatalf("NewStreamCipher() error = %v", err)
	}
	innerAddr, err := socks.ParseAddr("5.6.7.8:53")
	if err != nil {
		t.Fatalf("ParseAddr() error = %v", err)
	}
	newChain := func(marker bool) *PacketConn {
		t.Helper()
		inner := shadowsocks_stream.NewUdpConn(&markerPacketConn{marker: marker}, cipher, innerAddr, "proxy.example.com:8388")
		wrapped, err := NewPacketConn(inner, &noopProtocol{}, "1.2.3.4:53")
		if err != nil {
			t.Fatalf("NewPacketConn() error = %v", err)
		}
		return wrapped
	}

	if !netproxy.WriteDeadlineClosesSession(newChain(true)) {
		t.Fatal("SSR outer layer must not erase a true declaration of the inner shadowsocks_stream conn")
	}
	if netproxy.WriteDeadlineClosesSession(newChain(false)) {
		t.Fatal("SSR outer layer must not erase a false declaration of the inner shadowsocks_stream conn")
	}
}
