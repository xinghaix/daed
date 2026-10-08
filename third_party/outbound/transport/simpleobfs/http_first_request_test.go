package simpleobfs

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// recordingConn captures everything written to it and can be told to fail
// writes on demand, so the obfs first-request path can be driven without a
// network.
type recordingConn struct {
	written   []byte
	writeErr  error
	writeCall int
}

func (c *recordingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) LocalAddr() net.Addr              { return nil }
func (c *recordingConn) RemoteAddr() net.Addr             { return nil }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

func (c *recordingConn) Write(p []byte) (int, error) {
	c.writeCall++
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.written = append(c.written, p...)
	return len(p), nil
}

func newRecordingObfs(host, port string) (*HTTPObfs, *recordingConn) {
	rc := &recordingConn{}
	o := NewHTTPObfs(&netproxy.FakeNetConn{Conn: rc}, host, port, "/")
	return o.(*HTTPObfs), rc
}

// TestHTTPObfsWriteMalformedHostDoesNotPanic is the P1-6 regression: a host
// containing a space makes http.NewRequest return an error, and the pre-fix
// code dereferenced the resulting nil request (panic). The error must instead
// surface to the caller so the dial attempt fails visibly.
func TestHTTPObfsWriteMalformedHostDoesNotPanic(t *testing.T) {
	for _, host := range []string{
		"bad host",        // space in authority
		"bad\thost",       // tab in authority
		"exa\x00mple.com", // NUL in authority
	} {
		o, rc := newRecordingObfs(host, "8388")
		n, err := func() (int, error) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("host %q: Write panicked: %v", host, r)
				}
			}()
			return o.Write([]byte("payload"))
		}()
		if err == nil {
			t.Fatalf("host %q: Write() error = nil, want a build error", host)
		}
		if n != 0 {
			t.Fatalf("host %q: Write() = %d, want 0 on error", host, n)
		}
		if len(rc.written) != 0 {
			t.Fatalf("host %q: %d bytes written, want none", host, len(rc.written))
		}
		// A failed first request must not be recorded as sent: the retry
		// still has to emit the obfs handshake.
		if !o.firstRequest {
			t.Fatalf("host %q: firstRequest cleared despite a failed request build", host)
		}
	}
}

// TestHTTPObfsBareIPv6HostIsBracketed pins the IPv6 authority form: a bare
// IPv6 literal in the URL is not a valid authority, and the Host header must
// carry the bracketed form.
func TestHTTPObfsBareIPv6HostIsBracketed(t *testing.T) {
	for _, tc := range []struct {
		name string
		host string
		port string
		want string
	}{
		{"bare-ipv6-nonstandard-port", "::1", "8388", "GET / HTTP/1.1\r\nHost: [::1]:8388\r\n"},
		{"bare-ipv6-scheme-port", "::1", "80", "GET / HTTP/1.1\r\nHost: [::1]\r\n"},
		{"bracketed-ipv6", "[::1]", "8388", "GET / HTTP/1.1\r\nHost: [::1]:8388\r\n"},
		{"bracketed-ipv6-scheme-port", "[::1]", "80", "GET / HTTP/1.1\r\nHost: [::1]\r\n"},
		// net/http renders req.Host without the zone identifier (it writes
		// req.URL.Host, which Go parses as "[fe80::1]:8388"): a zone-scoped
		// destination never reaches the wire. The point here is that it no
		// longer fails to build at all.
		{"zone-id", "fe80::1%eth0", "8388", "GET / HTTP/1.1\r\nHost: [fe80::1]:8388\r\n"},
		{"hostname", "example.com", "8388", "GET / HTTP/1.1\r\nHost: example.com:8388\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, rc := newRecordingObfs(tc.host, tc.port)
			n, err := o.Write([]byte("payload"))
			if err != nil {
				t.Fatalf("Write() error = %v", err)
			}
			if n != 7 {
				t.Fatalf("Write() = %d, want 7", n)
			}
			got := string(rc.written)
			if !strings.HasPrefix(got, tc.want) {
				t.Fatalf("request start = %q, want prefix %q", got, tc.want)
			}
			if !strings.HasSuffix(got, "payload") {
				t.Fatalf("request = %q, want the payload appended", got)
			}
		})
	}
}

// TestHTTPObfsWriteFailureKeepsFirstRequest pins the P1-6 ordering fix: when
// req.Write fails, firstRequest must stay set. The pre-fix code cleared it
// unconditionally, so a retry wrote the payload bare and the peer never saw an
// obfs handshake.
func TestHTTPObfsWriteFailureKeepsFirstRequest(t *testing.T) {
	o, rc := newRecordingObfs("example.com", "8388")
	writeErr := errors.New("synthetic write failure")
	rc.writeErr = writeErr

	if _, err := o.Write([]byte("first")); !errors.Is(err, writeErr) {
		t.Fatalf("Write() error = %v, want %v", err, writeErr)
	}
	if !o.firstRequest {
		t.Fatalf("firstRequest = false after a failed first write, want true")
	}

	rc.writeErr = nil
	if _, err := o.Write([]byte("retry")); err != nil {
		t.Fatalf("retry Write() error = %v", err)
	}
	got := string(rc.written)
	if !strings.HasPrefix(got, "GET / HTTP/1.1\r\n") {
		t.Fatalf("retry write = %q, want a fresh obfs request", got)
	}
	if !strings.HasSuffix(got, "retry") {
		t.Fatalf("retry write = %q, want the retry payload", got)
	}
	if o.firstRequest {
		t.Fatalf("firstRequest = true after a successful write, want false")
	}

	// Once the handshake is out, later writes are raw payloads.
	rc.written = nil
	if _, err := o.Write([]byte("plain")); err != nil {
		t.Fatalf("second Write() error = %v", err)
	}
	if got := string(rc.written); got != "plain" {
		t.Fatalf("post-handshake write = %q, want the bare payload", got)
	}
}
