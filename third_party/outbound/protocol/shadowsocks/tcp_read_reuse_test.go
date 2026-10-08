package shadowsocks

import (
	"io"
	"testing"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/protocol"
)

func TestTCPConnSteadyStateReadHasNoAllocations(t *testing.T) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	payload := make([]byte, 1024)
	clientMetadata := protocol.Metadata{
		Cipher:   "aes-256-gcm",
		Type:     protocol.MetadataTypeIPv4,
		Hostname: "203.0.113.10",
		Port:     443,
	}
	serverMetadata := clientMetadata

	clientWire := &mockConn{}
	client, err := NewTCPConn(clientWire, clientMetadata, masterKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.metadata.IsClient = true
	const reads = 101
	for range reads {
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
	}

	serverWire := &mockConn{readBuf: clientWire.writeBuf}
	server, err := NewTCPConn(serverWire, serverMetadata, masterKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.ReadMetadata(); err != nil {
		t.Fatal(err)
	}
	decrypted := make([]byte, len(payload))
	var readErr error
	allocs := testing.AllocsPerRun(reads-1, func() {
		_, readErr = io.ReadFull(server, decrypted)
	})
	if readErr != nil {
		t.Fatal(readErr)
	}
	if allocs != 0 {
		t.Fatalf("steady-state Read allocations = %v, want 0", allocs)
	}
}
