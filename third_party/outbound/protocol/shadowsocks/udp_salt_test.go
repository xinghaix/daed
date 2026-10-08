package shadowsocks

import (
	"bytes"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/protocol"
)

type capturingPacketConn struct {
	mu     sync.Mutex
	writes [][]byte
}

func (c *capturingPacketConn) Read([]byte) (int, error) { return 0, nil }
func (c *capturingPacketConn) Write(p []byte) (int, error) {
	return c.WriteTo(p, "")
}
func (c *capturingPacketConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, nil
}
func (c *capturingPacketConn) WriteTo(p []byte, _ string) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	copied := make([]byte, len(p))
	copy(copied, p)
	c.writes = append(c.writes, copied)
	return len(p), nil
}
func (c *capturingPacketConn) Close() error                     { return nil }
func (c *capturingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *capturingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *capturingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestUdpConnWriteToUsesFreshSaltPerPacket(t *testing.T) {
	conf := ciphers.AeadCiphersConf["aes-128-gcm"]
	if conf == nil {
		t.Fatal("missing aes-128-gcm")
	}
	underlay := &capturingPacketConn{}
	conn, err := NewUdpConn(underlay, "127.0.0.1:8388", protocol.Metadata{
		Type:     protocol.MetadataTypeIPv4,
		Hostname: "203.0.113.10",
		Port:     53,
		Cipher:   "aes-128-gcm",
	}, make([]byte, conf.KeyLen), nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := conn.WriteTo([]byte("one"), "203.0.113.10:53"); err != nil {
		t.Fatalf("first WriteTo: %v", err)
	}
	if _, err := conn.WriteTo([]byte("two"), "203.0.113.10:53"); err != nil {
		t.Fatalf("second WriteTo: %v", err)
	}

	underlay.mu.Lock()
	defer underlay.mu.Unlock()
	if len(underlay.writes) != 2 {
		t.Fatalf("writes = %d, want 2", len(underlay.writes))
	}
	saltLen := conf.SaltLen
	if len(underlay.writes[0]) < saltLen || len(underlay.writes[1]) < saltLen {
		t.Fatalf("captured packets too short: %d, %d", len(underlay.writes[0]), len(underlay.writes[1]))
	}
	if bytes.Equal(underlay.writes[0][:saltLen], underlay.writes[1][:saltLen]) {
		t.Fatal("two UDP packets reused the same salt prefix")
	}
}
