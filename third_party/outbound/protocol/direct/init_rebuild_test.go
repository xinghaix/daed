package direct

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

func resetGlobalDirectDialers() {
	globalDirectDialers.Store(nil)
}

func publishedPair() *DirectDialers {
	return globalDirectDialers.Load()
}

func TestInitDirectDialersRebuildsOnLaterCalls(t *testing.T) {
	t.Cleanup(resetGlobalDirectDialers)

	InitDirectDialers("")
	first := publishedPair()
	if first == nil || first.Symmetric == nil || first.Fullcone == nil {
		t.Fatal("expected dialers after first InitDirectDialers")
	}
	if first.Symmetric.(*directDialer).Option.FallbackDNS != "" {
		t.Fatalf("first fallback = %q, want empty", first.Symmetric.(*directDialer).Option.FallbackDNS)
	}

	InitDirectDialers("1.1.1.1:53")
	second := publishedPair()
	if second == nil {
		t.Fatal("expected dialers after second InitDirectDialers")
	}
	if second.Symmetric == first.Symmetric {
		t.Fatal("second InitDirectDialers reused the first symmetric dialer")
	}
	if second.Fullcone == first.Fullcone {
		t.Fatal("second InitDirectDialers reused the first fullcone dialer")
	}
	got := second.Symmetric.(*directDialer).Option.FallbackDNS
	if got != "1.1.1.1:53" {
		t.Fatalf("rebuilt fallback = %q, want 1.1.1.1:53", got)
	}
	if second.Fullcone.(*directDialer).Option.FallbackDNS != "1.1.1.1:53" {
		t.Fatalf("fullcone fallback = %q", second.Fullcone.(*directDialer).Option.FallbackDNS)
	}
}

func TestNewDirectDialersDoesNotPublishGlobals(t *testing.T) {
	t.Cleanup(resetGlobalDirectDialers)

	before := publishedPair()
	pair := NewDirectDialers("8.8.8.8:53")
	if pair.Symmetric == nil || pair.Fullcone == nil {
		t.Fatal("expected constructed pair")
	}
	if pair.Symmetric.(*directDialer).Option.FallbackDNS != "8.8.8.8:53" {
		t.Fatalf("symmetric fallback = %q", pair.Symmetric.(*directDialer).Option.FallbackDNS)
	}
	if pair.Fullcone.(*directDialer).Option.FallbackDNS != "8.8.8.8:53" {
		t.Fatalf("fullcone fallback = %q", pair.Fullcone.(*directDialer).Option.FallbackDNS)
	}
	if pair.Symmetric.(*directDialer).Option.FullCone {
		t.Fatal("constructed Symmetric is FullCone")
	}
	if !pair.Fullcone.(*directDialer).Option.FullCone {
		t.Fatal("constructed Fullcone is not FullCone")
	}
	if publishedPair() != before {
		t.Fatal("NewDirectDialers published a global snapshot")
	}

	InitDirectDialers("1.1.1.1:53")
	global := publishedPair()
	if global == nil {
		t.Fatal("expected global snapshot after InitDirectDialers")
	}
	if global.Symmetric == pair.Symmetric || global.Fullcone == pair.Fullcone {
		t.Fatal("explicit pair leaked into the published snapshot")
	}
}

func TestDirectDialersPairIsInternallyConsistent(t *testing.T) {
	t.Cleanup(resetGlobalDirectDialers)

	InitDirectDialers("9.9.9.9:53")
	pair := publishedPair()
	if pair == nil {
		t.Fatal("expected published pair")
	}
	sym := pair.Symmetric.(*directDialer)
	full := pair.Fullcone.(*directDialer)
	if sym.Option.FallbackDNS != full.Option.FallbackDNS {
		t.Fatalf("mixed fallback: symmetric=%q fullcone=%q", sym.Option.FallbackDNS, full.Option.FallbackDNS)
	}
	if sym.Option.FullCone == full.Option.FullCone {
		t.Fatal("pair members share the same FullCone flag")
	}
	if lazy := (&lazyDirectDialer{fullcone: false}).getDialer(); lazy != pair.Symmetric {
		t.Fatal("lazy symmetric view diverged from published pair")
	}
	if lazy := (&lazyDirectDialer{fullcone: true}).getDialer(); lazy != pair.Fullcone {
		t.Fatal("lazy fullcone view diverged from published pair")
	}
}

func TestInitDirectDialersConcurrentInitAndRead(t *testing.T) {
	t.Cleanup(resetGlobalDirectDialers)

	const readers = 32
	const writers = 8
	const iterations = 200

	var wg sync.WaitGroup
	var mixed atomic.Int32
	start := make(chan struct{})

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				pair := loadGlobalDirectDialers()
				if pair == nil || pair.Symmetric == nil || pair.Fullcone == nil {
					mixed.Add(1)
					return
				}
				sym, okSym := pair.Symmetric.(*directDialer)
				full, okFull := pair.Fullcone.(*directDialer)
				if !okSym || !okFull {
					mixed.Add(1)
					return
				}
				if sym.Option.FallbackDNS != full.Option.FallbackDNS {
					mixed.Add(1)
					return
				}
				if sym.Option.FullCone || !full.Option.FullCone {
					mixed.Add(1)
					return
				}
				_ = (&lazyDirectDialer{fullcone: j%2 == 0}).getDialer()
			}
		}()
	}

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				fallback := ""
				if (id+j)%2 == 0 {
					fallback = "1.1.1.1:53"
				} else {
					fallback = "8.8.8.8:53"
				}
				InitDirectDialers(fallback)
			}
		}(i)
	}

	close(start)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for concurrent init/read")
	}
	if mixed.Load() != 0 {
		t.Fatalf("observed mixed-generation pair %d times", mixed.Load())
	}
}

func TestNewDirectDialersReusesPacketReceiverRegistry(t *testing.T) {
	pair := NewDirectDialers("")
	sym := pair.Symmetric.(*directDialer)
	full := pair.Fullcone.(*directDialer)
	if sym.receiver != newPacketReceiverRegistry() {
		t.Fatal("symmetric dialer did not reuse the singleton packetReceiver registry")
	}
	if full.receiver != newPacketReceiverRegistry() {
		t.Fatal("fullcone dialer did not reuse the singleton packetReceiver registry")
	}
}

func TestExportedGlobalsRemainLazyViews(t *testing.T) {
	if _, ok := SymmetricDirect.(*lazyDirectDialer); !ok {
		t.Fatalf("SymmetricDirect type = %T, want *lazyDirectDialer", SymmetricDirect)
	}
	if _, ok := FullconeDirect.(*lazyDirectDialer); !ok {
		t.Fatalf("FullconeDirect type = %T, want *lazyDirectDialer", FullconeDirect)
	}
	var _ netproxy.Dialer = SymmetricDirect
	var _ netproxy.Dialer = FullconeDirect
}
