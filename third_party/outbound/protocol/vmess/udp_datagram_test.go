package vmess

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

type bufferConn struct {
	*bytes.Buffer
}

func (c *bufferConn) Close() error                     { return nil }
func (c *bufferConn) SetDeadline(time.Time) error      { return nil }
func (c *bufferConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufferConn) SetWriteDeadline(time.Time) error { return nil }

var _ netproxy.Conn = (*bufferConn)(nil)

func TestReadFromClampsPacketAddrPayload(t *testing.T) {
	payload := []byte("0123456789")
	addr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("203.0.113.10:53"))
	addrLen := UDPAddrToPacketAddrLength(addr)
	buf := make([]byte, addrLen+len(payload))
	if err := PutPacketAddr(buf, addr); err != nil {
		t.Fatal(err)
	}
	copy(buf[addrLen:], payload)
	framed := make([]byte, 2+len(buf))
	framed[0] = byte(len(buf) >> 8)
	framed[1] = byte(len(buf))
	copy(framed[2:], buf)

	c := &Conn{
		Conn: &bufferConn{Buffer: bytes.NewBuffer(framed)},
		metadata: Metadata{
			Metadata: protocol.Metadata{Type: protocol.MetadataTypeDomain, Hostname: SeqPacketMagicAddress},
			Network:  "udp",
		},
		dialTgt:         "203.0.113.10:53",
		dialTgtAddrPort: netip.MustParseAddrPort("203.0.113.10:53"),
	}
	c.initRead.Do(func() {})
	c.readChunkSizeParser = PlainChunkSizeParser{}
	c.readPaddingGenerator = PlainPaddingGenerator{}
	c.readNonceGenerator = func() []byte { return make([]byte, 12) }
	c.readBodyCipher = identityAEAD{}
	small := make([]byte, 4)
	n, gotAddr, err := c.ReadFrom(small)
	if err == nil {
		t.Fatal("expected buf size error")
	}
	if n != 4 {
		t.Fatalf("n = %d, want 4", n)
	}
	if gotAddr.String() != "203.0.113.10:53" {
		t.Fatalf("addr = %v", gotAddr)
	}
}

func TestReadFromDoesNotSplitLeftoverAsSecondDatagram(t *testing.T) {
	chunk := []byte("abcdefghij")
	c := &Conn{
		Conn: &bufferConn{Buffer: bytes.NewBuffer(nil)},
		metadata: Metadata{
			Metadata: protocol.Metadata{},
			Network:  "udp",
		},
		leftToRead:         chunk,
		readNonceGenerator: func() []byte { return make([]byte, 12) },
		dialTgt:            "203.0.113.10:53",
		dialTgtAddrPort:    netip.MustParseAddrPort("203.0.113.10:53"),
	}
	c.initRead.Do(func() {})
	first := make([]byte, 4)
	n, _, err := c.ReadFrom(first)
	if err != io.ErrShortBuffer {
		t.Fatalf("first ReadFrom err = %v, want ErrShortBuffer", err)
	}
	if n != 0 {
		t.Fatalf("truncated datagram delivered: n=%d %q", n, first[:n])
	}
	second := make([]byte, 16)
	n, _, err = c.ReadFrom(second)
	if err != io.EOF && err != nil {
		t.Fatalf("second ReadFrom: %v", err)
	}
	if n != 0 {
		t.Fatalf("leftover delivered as second datagram: %q", second[:n])
	}
}

type identityAEAD struct{}

func (identityAEAD) NonceSize() int { return 12 }
func (identityAEAD) Overhead() int  { return 0 }
func (identityAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	out := make([]byte, len(dst)+len(plaintext))
	copy(out, dst)
	copy(out[len(dst):], plaintext)
	return out
}
func (identityAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	out := make([]byte, len(dst)+len(ciphertext))
	copy(out, dst)
	copy(out[len(dst):], ciphertext)
	return out, nil
}
