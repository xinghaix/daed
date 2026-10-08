package juicity

import (
	"bytes"
	"io"
	"sync"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/trojanc"
	"github.com/olicesx/quic-go"
)

type bufferStream struct {
	juicityTestStream
	buf *bytes.Buffer
}

func (s *bufferStream) Read(p []byte) (int, error) {
	if s.buf == nil {
		return 0, io.EOF
	}
	return s.buf.Read(p)
}

func (s *bufferStream) Write(p []byte) (int, error) {
	if s.buf == nil {
		s.buf = &bytes.Buffer{}
	}
	return s.buf.Write(p)
}

var _ quic.Stream = (*bufferStream)(nil)

func TestClientReadDoesNotConsumeRequestHeader(t *testing.T) {
	payload := []byte("payload-bytes")
	stream := &bufferStream{buf: bytes.NewBuffer(payload)}
	c := NewConn(stream, &trojanc.Metadata{
		Metadata: protocol.Metadata{IsClient: true},
		Network:  "tcp",
	}, nil, nil)
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
	clientStream := &bufferStream{buf: &bytes.Buffer{}}
	client := NewConn(clientStream, &trojanc.Metadata{
		Metadata: protocol.Metadata{
			Type:     protocol.MetadataTypeIPv4,
			Hostname: "203.0.113.10",
			Port:     443,
			IsClient: true,
		},
		Network: "tcp",
	}, nil, nil)
	payload := []byte("hello-from-client")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("client Write: %v", err)
	}

	server := NewConn(&bufferStream{buf: bytes.NewBuffer(clientStream.buf.Bytes())}, &trojanc.Metadata{
		Metadata: protocol.Metadata{IsClient: false},
	}, nil, nil)
	got := make([]byte, len(payload))
	n, err := server.Read(got)
	if err != nil && err != io.EOF {
		t.Fatalf("server Read: %v", err)
	}
	if string(got[:n]) != string(payload) {
		t.Fatalf("server payload = %q, want %q", got[:n], payload)
	}
	if server.Metadata.Hostname != "203.0.113.10" {
		t.Fatalf("parsed hostname = %q", server.Metadata.Hostname)
	}
}

func TestHeaderErrorIsStickyAfterPartialConsume(t *testing.T) {
	stream := &bufferStream{buf: bytes.NewBuffer([]byte{3})} // network=udp, then EOF before addr
	c := NewConn(stream, &trojanc.Metadata{
		Metadata: protocol.Metadata{IsClient: false},
	}, nil, nil)
	_, err := c.Read(make([]byte, 8))
	if err == nil {
		t.Fatal("expected header read error")
	}
	_, err2 := c.Read(make([]byte, 8))
	if err2 != err {
		t.Fatalf("second Read = %v, want sticky %v", err2, err)
	}
}

// serialBufferStream serializes underlay Read the way TCP/QUIC streams do.
// The race under test is in Conn header state, not the byte source.
type serialBufferStream struct {
	bufferStream
	mu sync.Mutex
}

func (s *serialBufferStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bufferStream.Read(p)
}

func TestServerRoleConcurrentReadParsesHeaderOnce(t *testing.T) {
	clientStream := &bufferStream{buf: &bytes.Buffer{}}
	client := NewConn(clientStream, &trojanc.Metadata{
		Metadata: protocol.Metadata{
			Type:     protocol.MetadataTypeIPv4,
			Hostname: "203.0.113.10",
			Port:     443,
			IsClient: true,
		},
		Network: "tcp",
	}, nil, nil)
	payload := []byte("hello-from-client-0123456789abcd")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("client Write: %v", err)
	}

	serverStream := &serialBufferStream{bufferStream: bufferStream{buf: bytes.NewBuffer(clientStream.buf.Bytes())}}
	server := NewConn(serverStream, &trojanc.Metadata{
		Metadata: protocol.Metadata{IsClient: false},
	}, nil, nil)

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
	if server.Metadata.Hostname != "203.0.113.10" {
		t.Fatalf("parsed hostname = %q", server.Metadata.Hostname)
	}
}
