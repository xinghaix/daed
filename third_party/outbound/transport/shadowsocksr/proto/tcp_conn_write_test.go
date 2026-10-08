package proto

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/pool/bytes"
)

type idProto struct{}

func (idProto) InitWithServerInfo(*ServerInfo)          {}
func (idProto) Encode(data []byte) ([]byte, error)      { return data, nil }
func (idProto) Decode(data []byte) ([]byte, int, error) { return data, 0, nil }
func (idProto) EncodePkt(*bytes.Buffer) error           { return nil }
func (idProto) DecodePkt([]byte) (pool.Bytes, error)    { return nil, nil }
func (idProto) SetData(interface{})                     {}
func (idProto) GetData() interface{}                    { return nil }
func (idProto) GetOverhead() int                        { return 0 }

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
	c := &Conn{Conn: shortErrConn{}, Protocol: idProto{}}
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
