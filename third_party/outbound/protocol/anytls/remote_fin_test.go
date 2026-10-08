package anytls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/pool"
)

func reviewFrame(cmd byte, sid uint32, data []byte) []byte {
	b := make([]byte, headerOverHeadSize+len(data))
	b[0] = cmd
	binary.BigEndian.PutUint32(b[1:5], sid)
	binary.BigEndian.PutUint16(b[5:7], uint16(len(data)))
	copy(b[headerOverHeadSize:], data)
	return b
}

func TestReviewAnyTLSRemoteFINPreservesQueuedData(t *testing.T) {
	local, remote := net.Pipe()
	s := newSession(local, 1)
	st := newStream(s, 1)
	if err := s.addStream(st); err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- s.run() }()
	defer func() {
		_ = remote.Close()
		_ = s.Close()
		<-runDone
	}()
	payload := []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody")
	wire := append(reviewFrame(cmdPSH, 1, payload), reviewFrame(cmdFIN, 1, nil)...)
	_ = remote.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := remote.Write(wire); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.closeStreamChan:
	case <-time.After(time.Second):
		t.Fatal("FIN was not processed")
	}
	// Session retirement after FIN must not discard the stream's response.
	_ = s.Close()
	defer st.Close()
	buf := make([]byte, 128)
	n, err := st.Read(buf)
	if !bytes.Equal(buf[:n], payload) || err != nil {
		t.Fatalf("PSH followed by FIN: Read = (%q, %v), want (%q, nil)", buf[:n], err, payload)
	}
}

func TestReviewAnyTLSRemoteFINPreservesPartiallyReadData(t *testing.T) {
	s := newSession(&recordingConn{}, 1)
	st := newStream(s, 1)
	if err := s.addStream(st); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer st.Close()
	chunk := pool.Get(6)
	copy(chunk, "abcdef")
	if err := st.enqueue(chunk); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ab" {
		t.Fatalf("first read = %q", buf)
	}
	if err := st.remoteClose(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(st)
	if string(got) != "cdef" || err != nil {
		t.Fatalf("remaining data after FIN = (%q, %v), want (cdef, nil)", got, err)
	}
}

func TestSessionClosePreservesReceivedData(t *testing.T) {
	for _, fin := range []bool{false, true} {
		t.Run(fmt.Sprint(fin), func(t *testing.T) {
			wire := append(reviewFrame(cmdPSH, 1, []byte("abc")), reviewFrame(cmdPSH, 1, []byte("def"))...)
			if fin {
				wire = append(wire, reviewFrame(cmdFIN, 1, nil)...)
			}
			s := newSession(&scriptedReadConn{recordingConn: &recordingConn{}, reader: bytes.NewReader(wire)}, 1)
			st := newStream(s, 1)
			if err := s.addStream(st); err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if err := s.run(); !errors.Is(err, io.EOF) {
				t.Fatalf("run = %v", err)
			}
			got, err := io.ReadAll(st)
			if string(got) != "abcdef" {
				t.Fatalf("received %q, want abcdef", got)
			}
			if fin && err != nil || !fin && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("ReadAll error = %v", err)
			}
			if st.readBufPB != nil || len(st.inbound) != 0 {
				t.Fatal("drained stream retained buffers")
			}
		})
	}
}

func TestLocalCloseAfterFINReleasesUnreadBuffers(t *testing.T) {
	s := newSession(&recordingConn{}, 1)
	st := newStream(s, 1)
	if err := s.addStream(st); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for range 2 {
		chunk := pool.Get(6)
		copy(chunk, "abcdef")
		if err := st.enqueue(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Read(make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	_ = st.remoteClose()
	if st.readBufPB == nil || len(st.inbound) != 1 {
		t.Fatal("FIN discarded unread buffers")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); _ = st.Close(); _ = st.remoteClose(); _ = s.Close() }()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("repeated close deadlocked")
	}
	if st.readBufPB != nil || len(st.readBuf) != 0 || len(st.inbound) != 0 {
		t.Fatal("local Close retained unread buffers")
	}
	if n, _ := st.Read(make([]byte, 8)); n != 0 {
		t.Fatal("local Close allowed buffered data")
	}
}
