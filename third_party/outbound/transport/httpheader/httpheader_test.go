package httpheader

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestConnWritesOneRequestHeaderAndStripsOneResponseHeader(t *testing.T) {
	clientRaw, server := net.Pipe()
	client := newConn(clientRaw, "front.example", "/transport")
	defer client.Close()

	serverErr := make(chan error, 1)
	go func() {
		defer server.Close()
		reader := bufio.NewReader(server)
		req, err := http.ReadRequest(reader)
		if err != nil {
			serverErr <- err
			return
		}
		if req.Method != http.MethodGet || req.URL.RequestURI() != "/transport" {
			serverErr <- errors.New("unexpected request line")
			return
		}
		if req.Host != "front.example" || req.Header.Get("Pragma") != "no-cache" {
			serverErr <- errors.New("unexpected request headers")
			return
		}

		payload := make([]byte, len("first-second"))
		if _, err := io.ReadFull(reader, payload); err != nil {
			serverErr <- err
			return
		}
		if string(payload) != "first-second" {
			serverErr <- errors.New("unexpected payload")
			return
		}
		if _, err := io.WriteString(server, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nreply"); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	if n, err := client.Write([]byte("first-")); err != nil || n != len("first-") {
		t.Fatalf("first Write() = %d, %v", n, err)
	}
	if n, err := client.Write([]byte("second")); err != nil || n != len("second") {
		t.Fatalf("second Write() = %d, %v", n, err)
	}

	reply := make([]byte, len("reply"))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if string(reply) != "reply" {
		t.Fatalf("Read() = %q, want reply", reply)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestConnRejectsOversizedResponseHeader(t *testing.T) {
	clientRaw, server := net.Pipe()
	client := newConn(clientRaw, defaultHost, "/")
	defer client.Close()

	go func() {
		defer server.Close()
		_, _ = server.Write([]byte(strings.Repeat("x", maxResponseHeader+1)))
	}()

	_, err := client.Read(make([]byte, 1))
	if !errors.Is(err, errResponseHeaderTooLarge) {
		t.Fatalf("Read() error = %v, want errResponseHeaderTooLarge", err)
	}
}

func TestConnReadDeadlineDoesNotStickHeaderError(t *testing.T) {
	clientRaw, server := net.Pipe()
	defer server.Close()
	client := newConn(clientRaw, defaultHost, "/")
	defer client.Close()

	_ = client.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, err := client.Read(make([]byte, 4))
	if err == nil {
		t.Fatal("expected read deadline")
	}

	_ = client.SetReadDeadline(time.Time{})
	go func() {
		_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\n\r\nbody")
	}()
	buf := make([]byte, 4)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("Read after clearing deadline: %v (sticky header error?)", err)
	}
	if string(buf[:n]) != "body" {
		t.Fatalf("Read() = %q, want body", buf[:n])
	}
}

func TestNewDialerAppliesCompatibleDefaults(t *testing.T) {
	dialer, err := NewDialer(nil, "", "transport")
	if err != nil {
		t.Fatalf("NewDialer() error = %v", err)
	}
	if dialer.host != defaultHost || dialer.path != "/transport" {
		t.Fatalf("NewDialer() host/path = %q %q", dialer.host, dialer.path)
	}
}
