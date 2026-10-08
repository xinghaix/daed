package dialer_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	anytlslink "github.com/daeuniverse/outbound/dialer/anytls"
	_ "github.com/daeuniverse/outbound/dialer/juicity"
	_ "github.com/daeuniverse/outbound/dialer/shadowsocks"
	"github.com/daeuniverse/outbound/netproxy"
	anytlsprotocol "github.com/daeuniverse/outbound/protocol/anytls"
)

var errBorrowedDial = errors.New("borrowed base dial")

type chainBaseDialer struct {
	closes atomic.Int32
}

func (d *chainBaseDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, errBorrowedDial
}

func (d *chainBaseDialer) Close() error {
	d.closes.Add(1)
	return nil
}

func (d *chainBaseDialer) TransportCacheNamespace() string { return "chain-generation" }

func assertAnyTLSClosed(t *testing.T, d netproxy.Dialer) {
	t.Helper()
	if c, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:443"); !errors.Is(err, net.ErrClosed) {
		if c != nil {
			_ = c.Close()
		}
		t.Errorf("AnyTLS after chain cleanup: %v, want net.ErrClosed", err)
	}
}

func TestAnyTLSLinkChainCloseOwnsAllLayers(t *testing.T) {
	var layers []netproxy.Dialer
	dialer.FromLinkRegister("anytls", func(option *dialer.ExtraOption, next netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
		d, p, err := anytlslink.NewAnytls(option, next, link)
		if err == nil {
			layers = append(layers, d)
		}
		return d, p, err
	})
	defer dialer.FromLinkRegister("anytls", anytlslink.NewAnytls)
	defer func() {
		for _, layer := range layers {
			_ = layer.(io.Closer).Close()
		}
	}()
	base := &chainBaseDialer{}
	d, p, err := dialer.NewNetproxyDialerFromLink(base, &dialer.ExtraOption{}, "anytls://pass@127.0.0.1:443#outer->anytls://pass@127.0.0.2:443#inner")
	if err != nil {
		t.Fatal(err)
	}
	if len(layers) != 2 {
		t.Fatalf("constructed %d AnyTLS layers, want 2", len(layers))
	}
	if p.Name != "outer->inner" || p.Protocol != "anytls->anytls" {
		t.Fatalf("unexpected chain property: %+v", p)
	}
	if got := netproxy.TransportCacheNamespace(d); got != "chain-generation" {
		t.Fatalf("cache namespace = %q", got)
	}
	closer, ok := d.(io.Closer)
	if !ok {
		t.Fatalf("chain %T has no Close", d)
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	// Probe the inner layer separately: probing only the closed outer layer
	// would mask an inner janitor that still owns live sessions.
	for _, layer := range layers {
		assertAnyTLSClosed(t, layer)
	}
	if got := base.closes.Load(); got != 0 {
		t.Fatalf("borrowed base closed %d times", got)
	}
}

func TestLinkChainFailureClosesConstructedAnyTLS(t *testing.T) {
	var created []netproxy.Dialer
	// Capture the real constructor's result before the registry returns it.
	// This observes otherwise-unreachable resources on the failure path.
	dialer.FromLinkRegister("lifecycle-anytls", func(option *dialer.ExtraOption, next netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
		d, p, err := anytlslink.NewAnytls(option, next, strings.Replace(link, "lifecycle-anytls:", "anytls:", 1))
		if err == nil {
			created = append(created, d)
		}
		return d, p, err
	})
	defer func() {
		for _, d := range created {
			_ = d.(io.Closer).Close()
		}
	}()
	for _, prefix := range []string{"unknown://x", "invalid scheme", "anytls://%"} {
		t.Run(prefix, func(t *testing.T) {
			base := &chainBaseDialer{}
			before := len(created)
			d, p, err := dialer.NewNetproxyDialerFromLink(base, &dialer.ExtraOption{}, prefix+"->lifecycle-anytls://pass@127.0.0.1:443->lifecycle-anytls://pass@127.0.0.2:443")
			if err == nil || d != nil || p != nil {
				t.Fatalf("failed chain = (%T, %+v, %v)", d, p, err)
			}
			if len(created) != before+2 {
				t.Fatal("test did not construct both AnyTLS layers")
			}
			for _, layer := range created[before:] {
				assertAnyTLSClosed(t, layer)
			}
			if got := base.closes.Load(); got != 0 {
				t.Fatalf("borrowed base closed %d times", got)
			}
		})
	}
}

type countedChainLayer struct {
	netproxy.Dialer
	closes   atomic.Int32
	closeErr error
}

func (d *countedChainLayer) Close() error {
	d.closes.Add(1)
	return d.closeErr
}

func (d *countedChainLayer) UnwrapDialer() netproxy.Dialer { return d.Dialer }

type lookupChainLayer struct{ *countedChainLayer }

func (d *lookupChainLayer) LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("192.0.2.8")}}, nil
}

func TestLinkChainCloseOnceAndPreservesLookup(t *testing.T) {
	errClose := errors.New("layer close error")
	for _, lookup := range []bool{false, true} {
		var layers []*countedChainLayer
		dialer.FromLinkRegister("counted-layer", func(_ *dialer.ExtraOption, next netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
			layer := &countedChainLayer{Dialer: next, closeErr: errClose}
			layers = append(layers, layer)
			var d netproxy.Dialer = layer
			if lookup {
				d = &lookupChainLayer{countedChainLayer: layer}
			}
			return d, &dialer.Property{Link: link}, nil
		})
		base := &chainBaseDialer{}
		d, _, err := dialer.NewNetproxyDialerFromLink(base, &dialer.ExtraOption{}, "counted-layer://outer->counted-layer://inner")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:443"); !errors.Is(err, errBorrowedDial) {
			t.Fatalf("DialContext was not forwarded: %v", err)
		}
		resolver, ok := d.(interface {
			LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error)
		})
		if ok != lookup {
			t.Fatalf("lookup capability = %v, want %v", ok, lookup)
		}
		if ok {
			ips, err := resolver.LookupIPAddr(context.Background(), "tcp", "example.com")
			if err != nil || len(ips) != 1 || ips[0].IP.String() != "192.0.2.8" {
				t.Fatalf("LookupIPAddr = %v, %v", ips, err)
			}
		}
		if got := netproxy.TransportCacheNamespace(d); got != "chain-generation" {
			t.Fatalf("namespace = %q", got)
		}
		closer := d.(io.Closer)
		for range 2 {
			if err := closer.Close(); !errors.Is(err, errClose) {
				t.Fatalf("Close = %v, want layer error", err)
			}
		}
		for _, layer := range layers {
			if got := layer.closes.Load(); got != 1 {
				t.Fatalf("layer closed %d times", got)
			}
		}
		if got := base.closes.Load(); got != 0 {
			t.Fatalf("borrowed base closed %d times", got)
		}
	}
}

func TestSingleLinkKeepsConcreteDialer(t *testing.T) {
	base := &chainBaseDialer{}
	d, _, err := dialer.NewNetproxyDialerFromLink(base, &dialer.ExtraOption{}, "anytls://pass@127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer d.(io.Closer).Close()
	if _, ok := d.(*anytlsprotocol.Dialer); !ok {
		t.Fatalf("single link type = %T", d)
	}
}

type forwardChainLayer struct{ netproxy.Dialer }

func (d *forwardChainLayer) UnwrapDialer() netproxy.Dialer { return d.Dialer }

func TestLinkChainStatelessTopClosesOwnedInner(t *testing.T) {
	var inner *countedChainLayer
	dialer.FromLinkRegister("stateless-top", func(_ *dialer.ExtraOption, next netproxy.Dialer, _ string) (netproxy.Dialer, *dialer.Property, error) {
		return &forwardChainLayer{Dialer: next}, &dialer.Property{}, nil
	})
	dialer.FromLinkRegister("owned-inner", func(_ *dialer.ExtraOption, next netproxy.Dialer, _ string) (netproxy.Dialer, *dialer.Property, error) {
		inner = &countedChainLayer{Dialer: next}
		return inner, &dialer.Property{}, nil
	})
	base := &chainBaseDialer{}
	d, _, err := dialer.NewNetproxyDialerFromLink(base, &dialer.ExtraOption{}, "stateless-top://x->owned-inner://x")
	if err != nil {
		t.Fatal(err)
	}
	closer, ok := d.(io.Closer)
	if !ok {
		t.Fatal("stateless top hid owned inner Close")
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	if got := inner.closes.Load(); got != 1 {
		t.Fatalf("inner closed %d times", got)
	}
	if got := base.closes.Load(); got != 0 {
		t.Fatalf("borrowed base closed %d times", got)
	}
}

func TestLinkChainConstructorAliasesDoNotOwnBorrowedBase(t *testing.T) {
	for _, fail := range []bool{false, true} {
		for _, returnBase := range []bool{false, true} {
			base := &chainBaseDialer{}
			var layer, middle *countedChainLayer
			dialer.FromLinkRegister("alias-middle", func(_ *dialer.ExtraOption, next netproxy.Dialer, _ string) (netproxy.Dialer, *dialer.Property, error) {
				middle = &countedChainLayer{Dialer: next}
				return middle, &dialer.Property{}, nil
			})
			dialer.FromLinkRegister("alias-owned", func(_ *dialer.ExtraOption, next netproxy.Dialer, _ string) (netproxy.Dialer, *dialer.Property, error) {
				layer = &countedChainLayer{Dialer: next}
				return layer, &dialer.Property{}, nil
			})
			dialer.FromLinkRegister("alias-repeat", func(_ *dialer.ExtraOption, next netproxy.Dialer, _ string) (netproxy.Dialer, *dialer.Property, error) {
				if returnBase {
					return base, &dialer.Property{}, nil
				}
				return layer, &dialer.Property{}, nil
			})
			link := "alias-repeat://x->alias-repeat://x->alias-middle://x->alias-owned://x"
			if fail {
				link = "unknown://x->" + link
			}
			d, _, err := dialer.NewNetproxyDialerFromLink(base, &dialer.ExtraOption{}, link)
			if fail {
				if err == nil {
					t.Fatal("expected constructor failure")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				closer, ok := d.(io.Closer)
				if !ok {
					t.Fatal("lost owned layer cleanup")
				}
				for range 2 {
					if err := closer.Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
			if got := base.closes.Load(); got != 0 {
				t.Errorf("borrowed base closed %d times (fail=%v, returnBase=%v)", got, fail, returnBase)
			}
			for _, owned := range []*countedChainLayer{layer, middle} {
				if got := owned.closes.Load(); got != 1 {
					t.Errorf("owned layer closed %d times (fail=%v, returnBase=%v)", got, fail, returnBase)
				}
			}
		}
	}
}

func TestLinkChainDoesNotInventOptionalInterfaces(t *testing.T) {
	base := &chainBaseDialer{}
	var layer *countedChainLayer
	dialer.FromLinkRegister("opaque-owned", func(_ *dialer.ExtraOption, next netproxy.Dialer, _ string) (netproxy.Dialer, *dialer.Property, error) {
		layer = &countedChainLayer{Dialer: next}
		return layer, &dialer.Property{}, nil
	})
	dialer.FromLinkRegister("opaque-top", func(_ *dialer.ExtraOption, next netproxy.Dialer, _ string) (netproxy.Dialer, *dialer.Property, error) {
		return &struct{ netproxy.Dialer }{next}, &dialer.Property{}, nil
	})
	d, _, err := dialer.NewNetproxyDialerFromLink(base, &dialer.ExtraOption{}, "opaque-top://x->opaque-owned://x")
	if err != nil {
		t.Fatal(err)
	}
	defer d.(io.Closer).Close()
	if _, ok := d.(netproxy.DialerUnwrapper); ok {
		t.Error("opaque top gained UnwrapDialer")
	}
	if _, ok := d.(netproxy.TransportCacheNamespaceProvider); ok {
		t.Error("opaque top gained TransportCacheNamespace")
	}
	if _, ok := d.(interface {
		LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error)
	}); ok {
		t.Error("opaque top gained LookupIPAddr")
	}
	if got := netproxy.TransportCacheNamespace(d); got != "" {
		t.Errorf("opaque top cache scope changed to %q", got)
	}
}

type testChainLookup interface {
	LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error)
}

type optionalChainTop struct{ netproxy.Dialer }

func (d *optionalChainTop) UnwrapDialer() netproxy.Dialer   { return d.Dialer }
func (d *optionalChainTop) TransportCacheNamespace() string { return "top-generation" }
func (d *optionalChainTop) LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("192.0.2.9")}}, nil
}

func testOptionalChainTop(mask int, next netproxy.Dialer) netproxy.Dialer {
	caps := &optionalChainTop{Dialer: next}
	plain := &struct{ netproxy.Dialer }{next}
	switch mask {
	case 7:
		return &struct {
			netproxy.Dialer
			netproxy.DialerUnwrapper
			netproxy.TransportCacheNamespaceProvider
			testChainLookup
		}{plain, caps, caps, caps}
	case 3:
		return &struct {
			netproxy.Dialer
			netproxy.DialerUnwrapper
			netproxy.TransportCacheNamespaceProvider
		}{plain, caps, caps}
	case 5:
		return &struct {
			netproxy.Dialer
			netproxy.DialerUnwrapper
			testChainLookup
		}{plain, caps, caps}
	case 6:
		return &struct {
			netproxy.Dialer
			netproxy.TransportCacheNamespaceProvider
			testChainLookup
		}{plain, caps, caps}
	case 1:
		return &struct {
			netproxy.Dialer
			netproxy.DialerUnwrapper
		}{plain, caps}
	case 2:
		return &struct {
			netproxy.Dialer
			netproxy.TransportCacheNamespaceProvider
		}{plain, caps}
	case 4:
		return &struct {
			netproxy.Dialer
			testChainLookup
		}{plain, caps}
	default:
		return plain
	}
}

func TestLinkChainPreservesExactOptionalInterfaces(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		var original netproxy.Dialer
		var inner *countedChainLayer
		dialer.FromLinkRegister("optional-inner", func(_ *dialer.ExtraOption, next netproxy.Dialer, _ string) (netproxy.Dialer, *dialer.Property, error) {
			inner = &countedChainLayer{Dialer: next}
			return inner, &dialer.Property{}, nil
		})
		dialer.FromLinkRegister("optional-top", func(_ *dialer.ExtraOption, next netproxy.Dialer, _ string) (netproxy.Dialer, *dialer.Property, error) {
			original = testOptionalChainTop(mask, next)
			return original, &dialer.Property{}, nil
		})
		base := &chainBaseDialer{}
		d, _, err := dialer.NewNetproxyDialerFromLink(base, &dialer.ExtraOption{}, "optional-top://x->optional-inner://x")
		if err != nil {
			t.Fatal(err)
		}
		defer d.(io.Closer).Close()
		u, hasUnwrap := d.(netproxy.DialerUnwrapper)
		n, hasNamespace := d.(netproxy.TransportCacheNamespaceProvider)
		l, hasLookup := d.(testChainLookup)
		if hasUnwrap != (mask&1 != 0) || hasNamespace != (mask&2 != 0) || hasLookup != (mask&4 != 0) {
			t.Errorf("mask %d: interfaces unwrap=%v namespace=%v lookup=%v", mask, hasUnwrap, hasNamespace, hasLookup)
		}
		if hasUnwrap && u.UnwrapDialer() != original {
			t.Errorf("mask %d: UnwrapDialer did not expose the original top", mask)
		}
		if hasNamespace && n.TransportCacheNamespace() != "top-generation" {
			t.Errorf("mask %d: provider scope changed", mask)
		}
		if netproxy.TransportCacheNamespace(d) != netproxy.TransportCacheNamespace(original) {
			t.Errorf("mask %d: resolved scope changed", mask)
		}
		if hasLookup {
			ips, err := l.LookupIPAddr(context.Background(), "tcp", "example.com")
			if err != nil || len(ips) != 1 || ips[0].IP.String() != "192.0.2.9" {
				t.Errorf("mask %d: LookupIPAddr = %v, %v", mask, ips, err)
			}
		}
		if err := d.(io.Closer).Close(); err != nil {
			t.Fatal(err)
		}
		if inner.closes.Load() != 1 || base.closes.Load() != 0 {
			t.Errorf("mask %d: close counts inner=%d base=%d", mask, inner.closes.Load(), base.closes.Load())
		}
	}
}

func TestLinkChainNoopFailureKeepsBorrowedBase(t *testing.T) {
	dialer.FromLinkRegister("reviewnoop", func(_ *dialer.ExtraOption, next netproxy.Dialer, _ string) (netproxy.Dialer, *dialer.Property, error) {
		return next, &dialer.Property{}, nil
	})
	base := &chainBaseDialer{}
	d, p, err := dialer.NewNetproxyDialerFromLink(base, &dialer.ExtraOption{}, "reviewmissing://x->reviewnoop://x")
	if err == nil || d != nil || p != nil {
		t.Fatalf("unknown->noop = (%T, %+v, %v), want constructor error", d, p, err)
	}
	if got := base.closes.Load(); got != 0 {
		t.Fatalf("borrowed_base_closes=%d, want 0", got)
	}
}

func TestLinkChainNoopOwnedLayerClosesOnce(t *testing.T) {
	dialer.FromLinkRegister("reviewnoop", func(_ *dialer.ExtraOption, next netproxy.Dialer, _ string) (netproxy.Dialer, *dialer.Property, error) {
		return next, &dialer.Property{}, nil
	})
	var inner *countedChainLayer
	dialer.FromLinkRegister("reviewnew", func(_ *dialer.ExtraOption, next netproxy.Dialer, _ string) (netproxy.Dialer, *dialer.Property, error) {
		inner = &countedChainLayer{Dialer: next}
		return inner, &dialer.Property{}, nil
	})
	base := &chainBaseDialer{}
	d, _, err := dialer.NewNetproxyDialerFromLink(base, &dialer.ExtraOption{}, "reviewnoop://x->reviewnew://x")
	if err != nil {
		t.Fatal(err)
	}
	closer, ok := d.(io.Closer)
	if !ok {
		t.Fatalf("noop->new %T lost Close", d)
	}
	for range 2 {
		if err := closer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if got := inner.closes.Load(); got != 1 {
		t.Fatalf("inner_closes=%d, want 1", got)
	}
	if got := base.closes.Load(); got != 0 {
		t.Fatalf("borrowed_base_closes=%d, want 0", got)
	}
}
