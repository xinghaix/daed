package shadowsocks

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"golang.org/x/crypto/hkdf"
)

// captureConn records every Write so tests can decrypt the wire frames.
type captureConn struct {
	netproxy.Conn
	written [][]byte
}

func (c *captureConn) Write(p []byte) (int, error) {
	c.written = append(c.written, append([]byte(nil), p...))
	return len(p), nil
}

func (c *captureConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return nil }
func (c *captureConn) RemoteAddr() net.Addr             { return nil }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

// decryptFirstChunk replays the receiver side for the first chunk of a
// stream: salt -> subkey -> AEAD open of [len][tag][payload][tag].
func decryptFirstChunk(t *testing.T, conf *ciphers.CipherConf, masterKey, wire []byte) []byte {
	t.Helper()
	if len(wire) < conf.SaltLen+2+conf.TagLen {
		t.Fatalf("wire too short: %d", len(wire))
	}
	salt := wire[:conf.SaltLen]
	kdf := hkdf.New(sha1.New, masterKey, salt, ShadowsocksReusedInfo)
	subKey := make([]byte, conf.KeyLen)
	if _, err := io.ReadFull(kdf, subKey); err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	ciph, err := conf.NewCipher(subKey)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	off := conf.SaltLen
	// The chunk length itself is AEAD-encrypted: open it first to learn the
	// payload size, then open the payload. Chunk nonces start at zero and
	// increment little-endian per chunk, so chunk 0 uses an all-zero nonce.
	nonce := make([]byte, ciph.NonceSize())
	lenPlain, err := ciph.Open(make([]byte, 0, 2), nonce,
		wire[off:off+2+conf.TagLen], nil)
	if err != nil {
		t.Fatalf("open length: %v", err)
	}
	length := int(binary.BigEndian.Uint16(lenPlain))
	off += 2 + conf.TagLen
	if len(wire) < off+length+conf.TagLen {
		t.Fatalf("wire truncated for payload: need %d have %d",
			off+length+conf.TagLen, len(wire))
	}
	common.BytesIncLittleEndian(nonce)
	plain := make([]byte, 0, length)
	plain, err = ciph.Open(plain[:0], nonce, wire[off:off+length+conf.TagLen], nil)
	if err != nil {
		t.Fatalf("open chunk: %v", err)
	}
	return plain
}

// TestTCPClientFirstWriteCarriesTargetHeader locks the invariant behind the
// trojan ss-chain fix: only a client-mode TCPConn prefixes its first write
// with the packed target address; server mode sends raw payload.
func TestTCPClientFirstWriteCarriesTargetHeader(t *testing.T) {
	conf := ciphers.AeadCiphersConf["aes-128-gcm"]
	masterKey := common.EVPBytesToKey("secret-password", conf.KeyLen)

	for _, tc := range []struct {
		name       string
		isClient   bool
		wantHeader bool
	}{
		{"client-prefixes-target-header", true, true},
		{"server-sends-raw-payload", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &captureConn{}
			conn, err := NewTCPConn(fake, protocol.Metadata{
				Type:     protocol.MetadataTypeDomain,
				Hostname: "example.com",
				Port:     443,
				Cipher:   "aes-128-gcm",
				IsClient: tc.isClient,
			}, masterKey, nil)
			if err != nil {
				t.Fatalf("NewTCPConn: %v", err)
			}
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatalf("Write: %v", err)
			}

			var wire []byte
			for _, frame := range fake.written {
				wire = append(wire, frame...)
			}
			plain := decryptFirstChunk(t, conf, masterKey, wire)
			header := append([]byte{0x03, byte(len("example.com"))}, []byte("example.com")...)
			header = binary.BigEndian.AppendUint16(header, 443)
			has := bytes.HasPrefix(plain, header)
			if has != tc.wantHeader {
				t.Fatalf("payload %q: target header present = %v, want %v",
					plain, has, tc.wantHeader)
			}
		})
	}
}
