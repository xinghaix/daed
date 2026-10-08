package shadowsocks

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/protocol"
)

func TestTCPConnReusableWriteFrame(t *testing.T) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	if conf == nil {
		t.Fatal("missing aes-256-gcm cipher config")
	}
	masterKey := make([]byte, conf.KeyLen)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatal(err)
	}

	plaintext := make([]byte, 1024)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	clientMeta := protocol.Metadata{
		Cipher:   "aes-256-gcm",
		IsClient: true,
		Type:     protocol.MetadataTypeIPv4,
		Hostname: "203.0.113.10",
		Port:     443,
	}
	serverMeta := protocol.Metadata{
		Cipher:   "aes-256-gcm",
		IsClient: false,
		Type:     protocol.MetadataTypeIPv4,
		Hostname: "203.0.113.10",
		Port:     443,
	}

	clientMock := &mockConn{}
	client, err := NewTCPConn(clientMock, clientMeta, masterKey, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if cap(client.writeFrame) == 0 {
		t.Fatal("expected reusable write frame after subsequent write")
	}
	frameCap := cap(client.writeFrame)
	if _, err := client.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if cap(client.writeFrame) != frameCap {
		t.Fatalf("write frame capacity changed: got %d want %d", cap(client.writeFrame), frameCap)
	}

	serverMock := &mockConn{readBuf: clientMock.writeBuf}
	server, err := NewTCPConn(serverMock, serverMeta, masterKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.ReadMetadata(); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(plaintext)*3)
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat(plaintext, 3)
	if !bytes.Equal(got, want) {
		t.Fatal("decrypted payload mismatch after reusable write frame")
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if client.writeFrame != nil {
		t.Fatal("expected writeFrame to be released on Close")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTCPConnWriteFrameOverflowUsesHeap(t *testing.T) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	if conf == nil {
		t.Fatal("missing aes-256-gcm cipher config")
	}
	masterKey := make([]byte, conf.KeyLen)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatal(err)
	}

	client, err := NewTCPConn(&mockConn{}, protocol.Metadata{
		Cipher:   "aes-256-gcm",
		IsClient: true,
		Type:     protocol.MetadataTypeIPv4,
		Hostname: "203.0.113.10",
		Port:     443,
	}, masterKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	small := make([]byte, 1024)
	if _, err := client.Write(small); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(small); err != nil {
		t.Fatal(err)
	}
	reusedCap := cap(client.writeFrame)
	if reusedCap == 0 {
		t.Fatal("expected reusable write frame")
	}

	huge := make([]byte, maxReusableWriteFrameSize)
	if _, err := client.Write(huge); err != nil {
		t.Fatal(err)
	}
	if cap(client.writeFrame) != reusedCap {
		t.Fatalf("overflow write mutated reusable frame: got cap %d want %d", cap(client.writeFrame), reusedCap)
	}
}
