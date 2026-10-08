package obfs

import (
	"io"
	"net"
	"testing"
	"time"
)

type idObfs struct{}

func (idObfs) SetServerInfo(*ServerInfo)                {}
func (idObfs) GetServerInfo() *ServerInfo               { return &ServerInfo{} }
func (idObfs) Encode(data []byte) ([]byte, error)       { return data, nil }
func (idObfs) Decode(data []byte) ([]byte, bool, error) { return data, false, nil }
func (idObfs) SetData(interface{})                      {}
func (idObfs) GetData() interface{}                     { return nil }

type shortErrConn struct{}

func (shortErrConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (shortErrConn) Write(p []byte) (int, error)      { return 1, io.ErrClosedPipe }
func (shortErrConn) Close() error                     { return nil }
func (shortErrConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (shortErrConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (shortErrConn) SetDeadline(time.Time) error      { return nil }
func (shortErrConn) SetReadDeadline(time.Time) error  { return nil }
func (shortErrConn) SetWriteDeadline(time.Time) error { return nil }

func TestWriteDoesNotReportSuccessOnShortWrite(t *testing.T) {
	c := &Conn{Conn: shortErrConn{}, Obfs: idObfs{}, init: true}
	n, err := c.Write([]byte("hello"))
	if err == nil {
		t.Fatal("expected underlay write error")
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
	_, err = c.Write([]byte("again"))
	if err != net.ErrClosed {
		t.Fatalf("second Write err = %v, want net.ErrClosed", err)
	}
}
