package client

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/olicesx/quic-go"
)

// Embedding the interfaces leaves unexpected calls visible as test failures.
type fastOpenStream struct {
	quic.Stream
	mu                          sync.Mutex
	response                    *bytes.Reader
	readDeadline, writeDeadline time.Time
	beforeRead                  func()
}

func (s *fastOpenStream) Read(p []byte) (int, error) {
	if s.beforeRead != nil {
		s.beforeRead()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.readDeadline.IsZero() && !time.Now().Before(s.readDeadline) {
		return 0, os.ErrDeadlineExceeded
	}
	return s.response.Read(p)
}

func (s *fastOpenStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *fastOpenStream) SetDeadline(d time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readDeadline, s.writeDeadline = d, d
	return nil
}
func (s *fastOpenStream) SetReadDeadline(d time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readDeadline = d
	return nil
}
func (s *fastOpenStream) SetWriteDeadline(d time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeDeadline = d
	return nil
}
func (s *fastOpenStream) deadlines() (time.Time, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readDeadline, s.writeDeadline
}

type fastOpenQUICConn struct {
	closeTrackingQuicConn
	stream *fastOpenStream
}

func (c *fastOpenQUICConn) OpenStream() (quic.Stream, error) { return c.stream, nil }

func newFastOpenTestConn(t *testing.T, deadline time.Time, response []byte) (*tcpConn, *fastOpenStream) {
	t.Helper()
	s := &fastOpenStream{response: bytes.NewReader(response)}
	q := &fastOpenQUICConn{closeTrackingQuicConn: closeTrackingQuicConn{ctx: context.Background()}, stream: s}
	c := &clientImpl{config: &Config{FastOpen: true}, conn: q}
	ctx := context.Background()
	if !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	conn, err := c.TCP("example.com:443", ctx)
	if err != nil {
		t.Fatal(err)
	}
	return conn.(*tcpConn), s
}

func TestFastOpenPreservesCallerDeadlines(t *testing.T) {
	for _, mode := range []string{"both", "separate", "during", "clear", "no-dial-deadline", "error"} {
		t.Run(mode, func(t *testing.T) {
			dial := time.Now().Add(time.Hour)
			if mode == "no-dial-deadline" {
				dial = time.Time{}
			}
			response := []byte{0, 0, 0, 'x'}
			if mode == "error" {
				response = nil
			}
			c, s := newFastOpenTestConn(t, dial, response)
			rd, wd := time.Now().Add(2*time.Hour), time.Now().Add(3*time.Hour)
			if mode == "both" {
				wd = rd
			}
			if mode == "clear" {
				rd, wd = time.Time{}, time.Time{}
			}
			set := func() error {
				if mode == "both" {
					return c.SetDeadline(rd)
				}
				if err := c.SetReadDeadline(rd); err != nil {
					return err
				}
				return c.SetWriteDeadline(wd)
			}
			if mode == "during" {
				var once sync.Once
				s.beforeRead = func() {
					once.Do(func() {
						done := make(chan error, 1)
						go func() { done <- set() }()
						if err := <-done; err != nil {
							t.Fatal(err)
						}
					})
				}
			} else if err := set(); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 1)
			n, err := c.Read(buf)
			if mode == "error" {
				if err == nil {
					t.Fatal("expected response error")
				}
			} else if err != nil || n != 1 || buf[0] != 'x' {
				t.Fatalf("Read = %d, %v, %q", n, err, buf)
			}
			gotRead, gotWrite := s.deadlines()
			if !gotRead.Equal(rd) || !gotWrite.Equal(wd) {
				t.Fatalf("deadlines = %v / %v, want %v / %v", gotRead, gotWrite, rd, wd)
			}
		})
	}
}

func TestFastOpenConcurrentReads(t *testing.T) {
	const readers = 16
	response := append([]byte{0, 0, 0}, bytes.Repeat([]byte{'x'}, readers)...)
	c, _ := newFastOpenTestConn(t, time.Now().Add(time.Hour), response)
	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 1)
			if n, err := c.Read(buf); err != nil || n != 1 || buf[0] != 'x' {
				t.Errorf("Read = %d, %v, %q", n, err, buf)
			}
		}()
	}
	wg.Wait()
}

func TestFastOpenHonorsEarlierCallerReadDeadline(t *testing.T) {
	c, _ := newFastOpenTestConn(t, time.Now().Add(time.Hour), []byte{0, 0, 0, 'x'})
	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read error = %v, want deadline exceeded", err)
	}
}

func TestFastOpenExpiredDialDeadline(t *testing.T) {
	dial := time.Now().Add(50 * time.Millisecond)
	c, _ := newFastOpenTestConn(t, dial, []byte{0, 0, 0, 'x'})
	if err := c.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	<-time.After(time.Until(dial))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read error = %v, want expired dial deadline", err)
	}
}

func TestFastOpenHandshakeKeepsDialDeadline(t *testing.T) {
	for _, clear := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "caller-clears"}[clear], func(t *testing.T) {
			dial := time.Now().Add(time.Hour)
			c, s := newFastOpenTestConn(t, dial, []byte{0, 0, 0, 'x'})
			if clear {
				if err := c.SetDeadline(time.Time{}); err != nil {
					t.Fatal(err)
				}
			}
			s.beforeRead = func() {
				rd, _ := s.deadlines()
				if !rd.Equal(dial) {
					t.Errorf("handshake deadline = %v, want %v", rd, dial)
				}
			}
			if err := c.readFastOpenResponse(); err != nil {
				t.Fatal(err)
			}
			rd, wd := s.deadlines()
			if !rd.IsZero() || !wd.IsZero() {
				t.Fatalf("dial deadlines remain after handshake: %v / %v", rd, wd)
			}
		})
	}
}
