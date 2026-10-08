package trojanc

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol"
)

func TestClientReadDoesNotConsumeRequestHeader(t *testing.T) {
	payload := []byte("payload-bytes")
	raw := bytes.NewBuffer(payload)
	c := &Conn{
		Conn:     &bufferConn{Buffer: raw},
		metadata: Metadata{Metadata: protocol.Metadata{IsClient: true}, Network: "tcp"},
	}
	c.onceWrite.Store(true) // skip the client-side request-header write on first Read
	got := make([]byte, len(payload))
	n, err := c.Read(got)
	if err != nil && err != io.EOF {
		t.Fatalf("client Read: %v", err)
	}
	if string(got[:n]) != string(payload) {
		t.Fatalf("client Read consumed a request header: got %q want %q", got[:n], payload)
	}
}

func TestServerReadParsesRequestHeaderThenPayload(t *testing.T) {
	server := &Conn{
		Conn:     &captureConn{},
		metadata: Metadata{Metadata: protocol.Metadata{IsClient: false}, Network: "tcp"},
		pass:     getPasswordHash("secret"),
	}
	clientUnderlay := &captureConn{}
	client := &Conn{
		Conn: clientUnderlay,
		metadata: Metadata{
			Metadata: protocol.Metadata{
				Type:     protocol.MetadataTypeIPv4,
				Hostname: "203.0.113.10",
				Port:     443,
				IsClient: true,
			},
			Network: "tcp",
		},
		pass: getPasswordHash("secret"),
	}
	payload := []byte("hello-from-client")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("client Write: %v", err)
	}

	server.Conn = &bufferConn{Buffer: bytes.NewBuffer(clientUnderlay.Bytes())}
	got := make([]byte, len(payload))
	n, err := server.Read(got)
	if err != nil && err != io.EOF {
		t.Fatalf("server Read: %v", err)
	}
	if string(got[:n]) != string(payload) {
		t.Fatalf("server payload = %q, want %q", got[:n], payload)
	}
	if server.metadata.Hostname != "203.0.113.10" {
		t.Fatalf("parsed hostname = %q", server.metadata.Hostname)
	}
	if server.metadata.Port != 443 {
		t.Fatalf("parsed port = %d", server.metadata.Port)
	}
}

func TestHeaderErrorIsStickyAfterPartialConsume(t *testing.T) {
	// 10 bytes is enough to start the 56-byte password, then EOF.
	raw := bytes.NewBuffer([]byte("short-head"))
	c := &Conn{
		Conn:     &bufferConn{Buffer: raw},
		metadata: Metadata{Metadata: protocol.Metadata{IsClient: false}, Network: "tcp"},
		pass:     getPasswordHash("secret"),
	}
	_, err := c.Read(make([]byte, 8))
	if err == nil {
		t.Fatal("expected header read error")
	}
	_, err2 := c.Read(make([]byte, 8))
	if err2 != err {
		t.Fatalf("second Read = %v, want sticky %v", err2, err)
	}
}

func TestServerRoleConcurrentReadParsesHeaderOnce(t *testing.T) {
	serverUnderlay, clientUnderlay := net.Pipe()
	t.Cleanup(func() {
		_ = serverUnderlay.Close()
		_ = clientUnderlay.Close()
	})

	server := &Conn{
		Conn:     serverUnderlay,
		metadata: Metadata{Metadata: protocol.Metadata{IsClient: false}, Network: "tcp"},
		pass:     getPasswordHash("secret"),
	}
	client := &Conn{
		Conn: clientUnderlay,
		metadata: Metadata{
			Metadata: protocol.Metadata{
				Type:     protocol.MetadataTypeIPv4,
				Hostname: "203.0.113.10",
				Port:     443,
				IsClient: true,
			},
			Network: "tcp",
		},
		pass: getPasswordHash("secret"),
	}

	payload := []byte("hello-from-client-0123456789abcd")
	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		_ = clientUnderlay.Close()
		writeErr <- err
	}()

	var wg sync.WaitGroup
	got := make([][]byte, 2)
	errs := make([]error, 2)
	ns := make([]int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			buf := make([]byte, len(payload))
			n, err := server.Read(buf)
			got[i], ns[i], errs[i] = buf, n, err
		}(i)
	}
	wg.Wait()
	if err := <-writeErr; err != nil {
		t.Fatalf("client Write: %v", err)
	}

	delivered := 0
	for i := 0; i < 2; i++ {
		if errs[i] != nil && errs[i] != io.EOF {
			t.Fatalf("server Read[%d]: %v", i, errs[i])
		}
		delivered += ns[i]
	}
	if delivered != len(payload) {
		t.Fatalf("delivered %d bytes, want %d (header was consumed twice)", delivered, len(payload))
	}
	if server.metadata.Hostname != "203.0.113.10" || server.metadata.Port != 443 {
		t.Fatalf("parsed metadata = %s:%d", server.metadata.Hostname, server.metadata.Port)
	}
}

func TestClientRoleConcurrentReadWriteOnceWrite(t *testing.T) {
	underlay, peer := net.Pipe()
	t.Cleanup(func() {
		_ = underlay.Close()
		_ = peer.Close()
	})
	c := &Conn{
		Conn: underlay,
		metadata: Metadata{
			Metadata: protocol.Metadata{
				Type:     protocol.MetadataTypeIPv4,
				Hostname: "192.0.2.10",
				Port:     443,
				IsClient: true,
			},
			Network: "tcp",
		},
		pass: getPasswordHash("secret"),
	}

	payload := []byte("first-write")
	errCh := make(chan error, 2)
	go func() {
		_, _ = io.Copy(io.Discard, peer)
	}()
	go func() {
		_, err := c.Write(payload)
		errCh <- err
	}()
	go func() {
		buf := make([]byte, 8)
		_, err := c.Read(buf)
		if err == io.EOF {
			err = nil
		}
		errCh <- err
	}()

	time.AfterFunc(200*time.Millisecond, func() { _ = peer.Close() })
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("concurrent Read/Write: %v", err)
		}
	}
}
