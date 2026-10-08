package vmess

import (
	"bytes"
	"io"
	"testing"
	"time"
)

type vmessReadConn struct {
	*bytes.Reader
}

func (c *vmessReadConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *vmessReadConn) Close() error                { return nil }
func (c *vmessReadConn) SetDeadline(time.Time) error { return nil }
func (c *vmessReadConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *vmessReadConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestConnSteadyStateReadHasNoAllocations(t *testing.T) {
	key := make([]byte, 16)
	aead, err := NewAesGcm(key)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 16)
	writeNonce := GenerateChunkNonce(iv, uint32(aead.NonceSize()))
	payload := make([]byte, 1024)
	const reads = 101
	var wire bytes.Buffer
	parser := PlainChunkSizeParser{}
	for range reads {
		var size [2]byte
		parser.Encode(uint16(len(payload)+aead.Overhead()), size[:])
		wire.Write(size[:])
		wire.Write(aead.Seal(nil, writeNonce(), payload, nil))
	}

	conn := &Conn{
		Conn:                 &vmessReadConn{Reader: bytes.NewReader(wire.Bytes())},
		readBodyCipher:       aead,
		readNonceGenerator:   GenerateChunkNonce(iv, uint32(aead.NonceSize())),
		readChunkSizeParser:  PlainChunkSizeParser{},
		readPaddingGenerator: PlainPaddingGenerator{},
	}
	conn.initRead.Do(func() {})
	decrypted := make([]byte, len(payload))
	var readErr error
	allocs := testing.AllocsPerRun(reads-1, func() {
		_, readErr = io.ReadFull(conn, decrypted)
	})
	if readErr != nil {
		t.Fatal(readErr)
	}
	if allocs != 0 {
		t.Fatalf("steady-state VMess Read allocations = %v, want 0", allocs)
	}
}
