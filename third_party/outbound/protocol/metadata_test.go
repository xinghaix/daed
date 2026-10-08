package protocol

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func cacheEntries(cache *sync.Map) (n int) {
	cache.Range(func(any, any) bool {
		n++
		return true
	})
	return n
}

// host returns a distinct IP literal to use as a peer-supplied hostname.
func hostLiteral(i int) string {
	return netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}).String()
}

// withResolver installs a datapath resolver for one test and restores it after.
func withResolver(t *testing.T, resolver func(context.Context, string) (netip.Addr, error)) {
	t.Helper()
	restore := installedDatapathResolver()
	SetDatapathResolver(resolver)
	t.Cleanup(func() { SetDatapathResolver(restore) })
}

// TestDomainIpMappingDefaultResolverHandlesLiterals pins the no-hook path: an
// IP literal resolves without any network access, and the answer matches the
// IP-typed path's plain form.
func TestDomainIpMappingDefaultResolverHandlesLiterals(t *testing.T) {
	var cache sync.Map
	ip := netip.AddrFrom4([4]byte{10, 1, 2, 3})
	m := Metadata{Type: MetadataTypeDomain, Hostname: ip.String(), Port: 53}
	got, err := m.DomainIpMapping(&cache)
	if err != nil {
		t.Fatalf("DomainIpMapping: %v", err)
	}
	if want := netip.AddrPortFrom(ip, 53); got != want {
		t.Fatalf("addr = %v, want %v", got, want)
	}
}

// TestDomainIpMappingBoundsTheCache is the regression guard for the unbounded
// per-connection domain->IP cache. Its key is the hostname carried in a
// received packet's metadata, so it is chosen by the peer: measured on the
// production path, one distinct hostname per datagram retains ~165 bytes, i.e.
// ~33 MB for 200k names on a single UDP association.
func TestDomainIpMappingBoundsTheCache(t *testing.T) {
	var cache sync.Map
	const lookups = maxDomainIpCacheEntries * 4
	for i := 0; i < lookups; i++ {
		ip := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
		m := Metadata{Type: MetadataTypeDomain, Hostname: ip.String(), Port: 53}
		got, err := m.DomainIpMapping(&cache)
		if err != nil {
			t.Fatalf("lookup %d (%s): %v", i, m.Hostname, err)
		}
		if want := netip.AddrPortFrom(ip, 53); got != want {
			t.Fatalf("lookup %d (%s): addr = %v, want %v", i, m.Hostname, got, want)
		}
	}
	if n := cacheEntries(&cache); n > maxDomainIpCacheEntries {
		t.Fatalf("cache holds %d entries after %d distinct hostnames, want <= %d",
			n, lookups, maxDomainIpCacheEntries)
	}
	if n := cacheEntries(&cache); n == 0 {
		t.Fatal("cache stored nothing; the bound must not disable caching")
	}
}

// TestDomainIpMappingEvictsOldestNotNewest pins which end of the cache the bound
// trims. Refusing new entries once full would make every unseen hostname a fresh
// lookup on every datagram, which is the traffic pattern a full-cone association
// produces, so the oldest answer must give way instead.
func TestDomainIpMappingEvictsOldestNotNewest(t *testing.T) {
	withResolver(t, func(_ context.Context, host string) (netip.Addr, error) {
		return netip.ParseAddr(host)
	})
	var cache sync.Map
	const inserted = maxDomainIpCacheEntries + 8
	for i := 0; i < inserted; i++ {
		m := Metadata{Type: MetadataTypeDomain, Hostname: hostLiteral(i), Port: 53}
		if _, err := m.DomainIpMapping(&cache); err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
	}
	if n := cacheEntries(&cache); n > maxDomainIpCacheEntries {
		t.Fatalf("cache holds %d entries, want <= %d", n, maxDomainIpCacheEntries)
	}
	if _, ok := loadDomainIP(&cache, hostLiteral(inserted-1)); !ok {
		t.Fatal("the newest answer was evicted; the bound must drop the oldest entry")
	}
	if _, ok := loadDomainIP(&cache, hostLiteral(0)); ok {
		t.Fatal("the oldest answer survived a full cache")
	}
}

// TestDomainIpMappingRefreshesExpiredAnswers pins the TTL: an answer carried by
// a long-lived association must not outlive domainIPTTL, because it becomes the
// source address of a datagram delivered to the client.
func TestDomainIpMappingRefreshesExpiredAnswers(t *testing.T) {
	calls := 0
	withResolver(t, func(_ context.Context, _ string) (netip.Addr, error) {
		calls++
		return netip.AddrFrom4([4]byte{192, 0, 2, byte(calls)}), nil
	})
	var cache sync.Map
	const name = "stale.example"
	cache.Store(name, domainIPEntry{
		addr:      netip.AddrFrom4([4]byte{198, 51, 100, 1}),
		expiresAt: time.Now().Add(-time.Second),
	})
	m := Metadata{Type: MetadataTypeDomain, Hostname: name, Port: 443}

	got, err := m.DomainIpMapping(&cache)
	if err != nil {
		t.Fatalf("DomainIpMapping: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expired answer was reused: resolver calls = %d, want 1", calls)
	}
	if want := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, 1}), 443); got != want {
		t.Fatalf("addr = %v, want %v", got, want)
	}

	if _, err := m.DomainIpMapping(&cache); err != nil {
		t.Fatalf("second DomainIpMapping: %v", err)
	}
	if calls != 1 {
		t.Fatalf("refreshed answer was not cached: resolver calls = %d, want 1", calls)
	}
}

// TestDomainIpMappingFailureIsASentinel pins the contract a caller relies on to
// drop one datagram instead of tearing the session down, and that a failure
// caches nothing.
func TestDomainIpMappingFailureIsASentinel(t *testing.T) {
	withResolver(t, func(context.Context, string) (netip.Addr, error) {
		return netip.Addr{}, errors.New("no answer")
	})
	var cache sync.Map
	m := Metadata{Type: MetadataTypeDomain, Hostname: "unresolvable.example", Port: 53}
	_, err := m.DomainIpMapping(&cache)
	if !errors.Is(err, ErrDomainResolution) {
		t.Fatalf("err = %v, want it to wrap ErrDomainResolution", err)
	}
	if n := cacheEntries(&cache); n != 0 {
		t.Fatalf("a failed resolution cached %d entries, want 0", n)
	}
}

// TestDomainIpMappingBoundsTheWait pins that the datagram read path cannot block
// on resolution indefinitely: the read loop is per association and, under
// full-cone NAT, serves every destination of that client.
func TestDomainIpMappingBoundsTheWait(t *testing.T) {
	withResolver(t, func(ctx context.Context, _ string) (netip.Addr, error) {
		<-ctx.Done()
		return netip.Addr{}, ctx.Err()
	})
	var cache sync.Map
	m := Metadata{Type: MetadataTypeDomain, Hostname: "slow.example", Port: 53}
	start := time.Now()
	_, err := m.DomainIpMapping(&cache)
	elapsed := time.Since(start)
	if !errors.Is(err, ErrDomainResolution) {
		t.Fatalf("err = %v, want it to wrap ErrDomainResolution", err)
	}
	if elapsed > DatapathResolveTimeout+time.Second {
		t.Fatalf("waited %v, want at most %v", elapsed, DatapathResolveTimeout)
	}
}

// TestDomainIpMappingUsesTheInstalledResolver pins that the embedder's resolver
// view is actually the one consulted.
func TestDomainIpMappingUsesTheInstalledResolver(t *testing.T) {
	called := ""
	withResolver(t, func(_ context.Context, host string) (netip.Addr, error) {
		called = host
		return netip.AddrFrom4([4]byte{203, 0, 113, 7}), nil
	})
	var cache sync.Map
	m := Metadata{Type: MetadataTypeDomain, Hostname: "embedder.example", Port: 443}
	got, err := m.DomainIpMapping(&cache)
	if err != nil {
		t.Fatalf("DomainIpMapping: %v", err)
	}
	if called != "embedder.example" {
		t.Fatalf("resolver saw %q, want the metadata hostname", called)
	}
	if want := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, 7}), 443); got != want {
		t.Fatalf("addr = %v, want %v", got, want)
	}
}

// TestDomainIpMappingLeavesTheIpBranchAlone pins that resolving an IP-typed
// metadata neither consults nor grows the domain cache.
func TestDomainIpMappingLeavesTheIpBranchAlone(t *testing.T) {
	withResolver(t, func(context.Context, string) (netip.Addr, error) {
		t.Error("the domain resolver was consulted for IP-typed metadata")
		return netip.Addr{}, errors.New("unexpected")
	})
	var cache sync.Map
	ip := netip.AddrFrom4([4]byte{1, 2, 3, 4})
	m := Metadata{Type: MetadataTypeIPv4, IP: ip, Hostname: ip.String(), Port: 443}
	got, err := m.DomainIpMapping(&cache)
	if err != nil {
		t.Fatalf("DomainIpMapping: %v", err)
	}
	if want := netip.AddrPortFrom(ip, 443); got != want {
		t.Fatalf("addr = %v, want %v", got, want)
	}
	if n := cacheEntries(&cache); n != 0 {
		t.Fatalf("IP-typed metadata touched the domain cache (%d entries)", n)
	}
}
