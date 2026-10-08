package bbr3

import (
	"sync"
	"testing"
	"time"

	"github.com/olicesx/quic-go/congestion"
)

// TestSenderAccessorsTolerateConcurrentRecalc is the P3-55 guard: quic-go reads
// Mode/PacingRate/GetCongestionWindow/CanSend/InSlowStart from its own goroutine
// while the run loop drives recalc from the packet path. Stale reads are fine;
// torn reads are not. Run under -race, which is where the pre-atomic fields
// reported a data race.
func TestSenderAccessorsTolerateConcurrentRecalc(t *testing.T) {
	s := newTestSender(0)
	// A saturated estimate so recalc produces a non-degenerate window.
	seedEstimate(s.model, 10_000_000)

	const (
		readers = 8
		iters   = 2000
	)
	var (
		readersWG sync.WaitGroup
		writerWG  sync.WaitGroup
		stop      = make(chan struct{})
	)

	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		now := time.Now()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Drive the writer the way the ack path does.
			now = now.Add(time.Millisecond)
			s.model.bytesInFlight = 12000
			s.OnCongestionEventEx(12000, now, []congestion.AckedPacketInfo{{
				PacketNumber: congestion.PacketNumber(now.UnixNano() % 1000),
				BytesAcked:   1200,
			}}, nil)
		}
	}()

	for i := 0; i < readers; i++ {
		readersWG.Add(1)
		go func() {
			defer readersWG.Done()
			for j := 0; j < iters; j++ {
				// Every accessor must be safe to call at any time. The values
				// are checked for sanity only: a stale value is acceptable,
				// an impossible one is not.
				if got := s.GetCongestionWindow(); got < 0 {
					t.Errorf("negative cwnd: %d", got)
					return
				}
				// PacingRate is an unsigned rate, so a negative value is not
				// representable; recalc always stores at least MinPacingRate,
				// so zero is the impossible value this type can express.
				if got := s.PacingRate(); got == 0 {
					t.Error("zero pacing rate")
					return
				}
				_ = s.CanSend(12000)
				_ = s.InSlowStart()
				_ = s.InRecovery()
				// SendRecordStats is read by telemetry, so it must be as safe as
				// the rest. The two values are separate atomic loads and recalc
				// can run between them, so they may not agree with each other;
				// only impossible values are a failure.
				if retained, capacity, _ := s.SendRecordStats(); retained < 0 || capacity < 1 {
					t.Errorf("impossible send-record stats: retained=%d capacity=%d", retained, capacity)
					return
				}
				if got := s.Mode(); got == "" {
					t.Error("empty mode string")
					return
				}
			}
		}()
	}

	// Let the readers finish, then stop the writer and wait for it to exit, so
	// the test does not leave a goroutine touching the sender after it ends.
	readersWG.Wait()
	close(stop)
	writerWG.Wait()
}
