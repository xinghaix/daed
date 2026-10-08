package meek

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type assemblerClient struct {
	tripper Tripper

	config *config
}

const maxFailedPolls = 8

func newAssemblerClient(tripper Tripper, config *config) *assemblerClient {
	return &assemblerClient{
		tripper: tripper,
		config:  config,
	}
}

func (c *assemblerClient) NewSession(ctx context.Context) (Session, error) {
	sessionID := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, sessionID)
	if err != nil {
		return nil, err
	}

	sessionContext, finish := context.WithCancel(ctx)

	session := &assemblerClientSession{
		sessionID:  sessionID,
		ctx:        sessionContext,
		tripper:    c.tripper,
		finish:     finish,
		readBuffer: bytes.NewBuffer(nil),
		writerChan: make(chan []byte),
		readerChan: make(chan []byte, 16),
		assembler:  c,
	}

	go session.keepRunning()

	return session, nil
}

type assemblerClientSession struct {
	sessionID        []byte
	currentWriteWait int

	assembler  *assemblerClient
	tripper    Tripper
	readBuffer *bytes.Buffer
	writerChan chan []byte
	readerChan chan []byte
	ctx        context.Context
	finish     func()

	// deadlineMu guards deadlineTimer. Deadlines are enforced at session
	// granularity: firing one calls finish, which closes the session so all
	// pending and subsequent I/O fail. Per-direction deadlines are not
	// representable over the polling transport beneath, so all three
	// Set*Deadline collapse onto the same timer.
	deadlineMu    sync.Mutex
	deadlineTimer *time.Timer
}

func (s *assemblerClientSession) setSessionDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	defer s.deadlineMu.Unlock()
	if s.deadlineTimer != nil {
		s.deadlineTimer.Stop()
		s.deadlineTimer = nil
	}
	if t.IsZero() {
		return nil
	}
	s.deadlineTimer = time.AfterFunc(time.Until(t), s.finish)
	return nil
}

func (s *assemblerClientSession) SetDeadline(t time.Time) error {
	return s.setSessionDeadline(t)
}

func (s *assemblerClientSession) SetReadDeadline(t time.Time) error {
	return s.setSessionDeadline(t)
}

func (s *assemblerClientSession) SetWriteDeadline(t time.Time) error {
	return s.setSessionDeadline(t)
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior.
// SetWriteDeadline delegates to SetDeadline, which arms a session-wide timer
// whose expiry calls finish and closes the whole session: every pending and
// subsequent read and write fails. That is the destructive semantics the
// marker exists to expose, so deadline-arming callers (e.g. dae's
// UdpEndpoint) must not arm it merely to probe for a stalled write.
func (s *assemblerClientSession) WriteDeadlineClosesSession() bool {
	return true
}

func (s *assemblerClientSession) keepRunning() {
	s.currentWriteWait = int(s.assembler.config.InitialPollingIntervalMs)
	for s.ctx.Err() == nil {
		s.runOnce()
	}
}

func (s *assemblerClientSession) runOnce() {
	sendBuffer := bytes.NewBuffer(nil)
	if s.currentWriteWait != 0 {
		waitTimer := time.NewTimer(time.Millisecond * time.Duration(s.currentWriteWait))
		waitForFirstWrite := true
	copyFromWriterLoop:
		for {
			select {
			case <-s.ctx.Done():
				return
			case data := <-s.writerChan:
				sendBuffer.Write(data)
				if sendBuffer.Len() >= int(s.assembler.config.MaxWriteSize) {
					break copyFromWriterLoop
				}
				if waitForFirstWrite {
					waitForFirstWrite = false
					waitTimer.Reset(time.Millisecond * time.Duration(s.assembler.config.WaitSubsequentWriteMs))
				}
			case <-waitTimer.C:
				break copyFromWriterLoop
			}
		}
		waitTimer.Stop()
	}

	firstRound := true
	pollConnection := true
	for sendBuffer.Len() != 0 || firstRound {
		firstRound = false
		sendAmount := sendBuffer.Len()
		if sendAmount > int(s.assembler.config.MaxWriteSize) {
			sendAmount = int(s.assembler.config.MaxWriteSize)
		}
		data := sendBuffer.Next(sendAmount)
		if len(data) != 0 {
			pollConnection = false
		}
		failedPolls := 0
		for {
			ctx, cancel := netproxy.NewDialTimeoutContextFrom(s.ctx)
			resp, err := s.tripper.RoundTrip(ctx, Request{Data: data, ConnectionTag: s.sessionID})
			cancel()
			if err != nil {
				if s.ctx.Err() != nil {
					return
				}
				failedPolls++
				if failedPolls >= maxFailedPolls {
					s.finish()
					return
				}
				time.Sleep(time.Millisecond * time.Duration(s.assembler.config.FailedRetryIntervalMs))
				continue
			}
			if len(resp.Data) != 0 {
				select {
				case <-s.ctx.Done():
					return
				case s.readerChan <- resp.Data:
				}
			}
			if len(resp.Data) != 0 {
				pollConnection = false
			}
			break
		}
	}
	if pollConnection {
		s.currentWriteWait = int(s.assembler.config.BackoffFactor * float32(s.currentWriteWait))
		if s.currentWriteWait > int(s.assembler.config.MaxPollingIntervalMs) {
			s.currentWriteWait = int(s.assembler.config.MaxPollingIntervalMs)
		}
		if s.currentWriteWait < int(s.assembler.config.MinPollingIntervalMs) {
			s.currentWriteWait = int(s.assembler.config.MinPollingIntervalMs)
		}
	} else {
		s.currentWriteWait = int(0)
	}
}

func (s *assemblerClientSession) Read(p []byte) (n int, err error) {
	for s.readBuffer.Len() == 0 {
		select {
		case <-s.ctx.Done():
			return 0, io.EOF
		case data := <-s.readerChan:
			s.readBuffer.Write(data)
		}
	}
	// The buffer is non-empty here, so this only returns (0, io.EOF) for an
	// empty p probe; never fabricate (0, nil), which callers read as EOF.
	return s.readBuffer.Read(p)
}

func (s *assemblerClientSession) Write(p []byte) (n int, err error) {
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case <-s.ctx.Done():
		return 0, s.ctx.Err()
	case s.writerChan <- buf:
		return len(p), nil
	}
}

func (s *assemblerClientSession) Close() error {
	s.deadlineMu.Lock()
	if s.deadlineTimer != nil {
		s.deadlineTimer.Stop()
		s.deadlineTimer = nil
	}
	s.deadlineMu.Unlock()
	s.finish()
	return nil
}
