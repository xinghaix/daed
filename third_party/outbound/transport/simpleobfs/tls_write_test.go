package simpleobfs

import (
	"io"
	"net"
	"testing"
	"time"
)

type shortErrConn struct{}

func (shortErrConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (shortErrConn) Write(p []byte) (int, error)      { return 1, io.ErrClosedPipe }
func (shortErrConn) Close() error                     { return nil }
func (shortErrConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (shortErrConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (shortErrConn) SetDeadline(time.Time) error      { return nil }
func (shortErrConn) SetReadDeadline(time.Time) error  { return nil }
func (shortErrConn) SetWriteDeadline(time.Time) error { return nil }

func TestTLSObfsWriteDoesNotReportSuccessOnShortWrite(t *testing.T) {
	to := &TLSObfs{Conn: shortErrConn{}, server: "example.com", firstRequest: false}
	n, err := to.Write([]byte("hello"))
	if err == nil {
		t.Fatal("expected underlay write error")
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
}
