package protocol

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type Metadata struct {
	Type     MetadataType
	Hostname string
	Port     uint16
	// IP carries the parsed address for MetadataTypeIPv4/IPv6 so hot paths
	// avoid the Hostname string round-trip. Invalid for other types.
	IP netip.Addr
	// Cmd is valid only if Type is MetadataTypeMsg.
	Cmd      MetadataCmd
	Cipher   string
	IsClient bool
}

// ErrDomainResolution reports that a peer-supplied domain-typed address could
// not be resolved within DatapathResolveTimeout.
//
// The frame it belongs to has already been consumed, so a caller may skip this
// datagram and keep the session: under full-cone NAT one association carries
// every destination of a client, and retiring it because one source address
// could not be resolved would break all of them.
var ErrDomainResolution = errors.New("datapath domain resolution failed")

const (
	// DatapathResolveTimeout bounds one resolution attempt on the datagram read
	// path. The read loop belongs to one association and, for full-cone NAT,
	// serves every destination of that client, so an unbounded lookup stalls all
	// of them; a bounded one costs at most one dropped datagram.
	DatapathResolveTimeout = 2 * time.Second

	// domainIPTTL bounds how long a cached domain->IP answer is reused. The
	// answer becomes the source address of a datagram delivered to the client,
	// so a long-lived association must not pin the address it first saw. The
	// process resolvers do not expose record TTLs, so this is a fixed bound
	// chosen to sit inside a typical record's lifetime.
	domainIPTTL = 60 * time.Second

	// maxDomainIpCacheEntries bounds a domain->IP cache handed to
	// DomainIpMapping. The key is the hostname carried in a received packet's
	// metadata, so it is chosen by the peer, and nothing in the protocol
	// requires a response to use an IP-typed address. Measured on the production
	// path, one distinct hostname per datagram retains ~165 bytes each, i.e.
	// ~33 MB for 200k names on a single UDP association. Past the bound the
	// oldest answer is evicted rather than new ones refused: refusing would turn
	// every unseen hostname into a lookup on every datagram, which is precisely
	// the traffic pattern full-cone NAT produces.
	maxDomainIpCacheEntries = 64
)

// datapathResolver holds the installed resolver.
//
// It is written while an embedder builds or rotates its resolver -- dae does
// this once per generation, i.e. on every reload -- while datagram read loops
// may already be running, so the read path goes through an atomic instead of a
// bare package variable.
var datapathResolver atomic.Pointer[func(ctx context.Context, host string) (netip.Addr, error)]

// SetDatapathResolver installs the resolver used for peer-supplied hostnames on
// the datagram read path, or restores the process resolver with nil.
//
// The resolver must return a real, numeric address, never a synthetic or
// routing-rewritten one: the result is used verbatim as the source address of
// the datagram delivered to the client, and full-cone NAT requires that address
// to be the real remote source.
func SetDatapathResolver(resolve func(ctx context.Context, host string) (netip.Addr, error)) {
	if resolve == nil {
		datapathResolver.Store(nil)
		return
	}
	datapathResolver.Store(&resolve)
}

// installedDatapathResolver returns the installed resolver, or nil.
func installedDatapathResolver() func(context.Context, string) (netip.Addr, error) {
	if p := datapathResolver.Load(); p != nil {
		return *p
	}
	return nil
}

// domainIPEntry is one cached answer. With a fixed TTL the entry closest to
// expiry is also the oldest insertion, so eviction needs no separate ordering.
type domainIPEntry struct {
	addr      netip.Addr
	expiresAt time.Time
}

// resolveDatapathHost resolves host within ctx, through the embedder's resolver
// when one is installed.
func resolveDatapathHost(ctx context.Context, host string) (netip.Addr, error) {
	if resolve := installedDatapathResolver(); resolve != nil {
		return resolve(ctx, host)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, addr := range addrs {
		if addr.IsValid() {
			// Unmap keeps the answer consistent with the IP-typed path, which
			// parses a plain address; the embedding proxy normalises the family
			// before building the datagram it sends to its client either way.
			return addr.Unmap(), nil
		}
	}
	return netip.Addr{}, &net.DNSError{Err: "no address", Name: host, IsNotFound: true}
}

// loadDomainIP returns a live cached answer for host.
func loadDomainIP(cache *sync.Map, host string) (netip.Addr, bool) {
	if cache == nil {
		return netip.Addr{}, false
	}
	value, ok := cache.Load(host)
	if !ok {
		return netip.Addr{}, false
	}
	entry, ok := value.(domainIPEntry)
	if !ok {
		cache.CompareAndDelete(host, value)
		return netip.Addr{}, false
	}
	if time.Now().After(entry.expiresAt) {
		cache.CompareAndDelete(host, value)
		return netip.Addr{}, false
	}
	return entry.addr, true
}

// storeDomainIP caches an answer, keeping the cache at its bound.
func storeDomainIP(cache *sync.Map, host string, addr netip.Addr) {
	if cache == nil {
		return
	}
	entry := domainIPEntry{addr: addr, expiresAt: time.Now().Add(domainIPTTL)}
	if _, loaded := cache.LoadOrStore(host, entry); loaded {
		return
	}
	if domainIPCacheHasRoom(cache) {
		return
	}
	evictDomainIP(cache)
}

// domainIPCacheHasRoom reports whether the cache is within its bound. It counts
// at most maxDomainIpCacheEntries+1 entries, so it stays O(bound), and it runs
// only on a miss -- where a DNS resolution is about to dwarf it.
func domainIPCacheHasRoom(cache *sync.Map) bool {
	n := 0
	cache.Range(func(any, any) bool {
		n++
		return n <= maxDomainIpCacheEntries
	})
	return n <= maxDomainIpCacheEntries
}

// evictDomainIP reclaims one slot, preferring an expired entry and otherwise the
// answer closest to expiry. It runs only while the cache is over its bound.
func evictDomainIP(cache *sync.Map) {
	now := time.Now()
	var expired, oldest any
	var oldestExpiry time.Time
	cache.Range(func(key, value any) bool {
		entry, ok := value.(domainIPEntry)
		if !ok {
			if expired == nil {
				expired = key
			}
			return true
		}
		if now.After(entry.expiresAt) {
			if expired == nil {
				expired = key
			}
			return true
		}
		if oldest == nil || entry.expiresAt.Before(oldestExpiry) {
			oldest, oldestExpiry = key, entry.expiresAt
		}
		return true
	})
	if expired != nil {
		cache.Delete(expired)
		return
	}
	if oldest != nil {
		cache.Delete(oldest)
	}
}

// DomainIpMapping resolves the metadata's destination, caching the domain->IP
// result in the caller's per-connection map. cache must be owned by one
// connection; see maxDomainIpCacheEntries for why its growth is bounded and
// ErrDomainResolution for what a failure means to the caller.
func (m *Metadata) DomainIpMapping(cache *sync.Map) (addrPort netip.AddrPort, err error) {
	if m.Type != MetadataTypeDomain {
		if addrPort, err = m.AddrPort(); err != nil {
			return netip.AddrPort{}, fmt.Errorf("ReadFrom AddrPort: %w", err)
		}
		return addrPort, nil
	}

	if addr, ok := loadDomainIP(cache, m.Hostname); ok {
		return netip.AddrPortFrom(addr, m.Port), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), DatapathResolveTimeout)
	defer cancel()
	addr, err := resolveDatapathHost(ctx, m.Hostname)
	if err != nil {
		// The sentinel is what lets a caller drop this datagram instead of
		// tearing the session down.
		return netip.AddrPort{}, fmt.Errorf("%w: %s: %w", ErrDomainResolution, m.Hostname, err)
	}
	storeDomainIP(cache, m.Hostname, addr)
	return netip.AddrPortFrom(addr, m.Port), nil
}

type MetadataCmd uint8

const (
	MetadataCmdPing MetadataCmd = iota
	MetadataCmdSyncPassages
	MetadataCmdResponse
)

type MetadataType int

const (
	MetadataTypeIPv4 MetadataType = iota
	MetadataTypeIPv6
	MetadataTypeDomain
	MetadataTypeMsg
	MetadataTypeInvalid
)

func ParseMetadata(tgt string) (mdata Metadata, err error) {
	host, strPort, err := net.SplitHostPort(tgt)
	if err != nil {
		return mdata, fmt.Errorf("SplitHostPort: %w", err)
	}
	port, err := strconv.ParseUint(strPort, 10, 16)
	if err != nil {
		return mdata, fmt.Errorf("failed to parse port: %w", err)
	}
	tgtIP, err := netip.ParseAddr(host)
	var typ MetadataType
	if err != nil {
		typ = MetadataTypeDomain
	} else if tgtIP.Is4() {
		typ = MetadataTypeIPv4
	} else {
		typ = MetadataTypeIPv6
	}
	return Metadata{
		Type:     typ,
		Hostname: host,
		Port:     uint16(port),
		IP:       tgtIP,
	}, nil
}

func (m *Metadata) AddrPort() (netip.AddrPort, error) {
	switch m.Type {
	case MetadataTypeIPv4, MetadataTypeIPv6:
		if m.IP.IsValid() {
			return netip.AddrPortFrom(m.IP, m.Port), nil
		}
		ip, err := netip.ParseAddr(m.Hostname)
		if err != nil {
			return netip.AddrPort{}, err
		}
		return netip.AddrPortFrom(ip, m.Port), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("bad metadata type: %v; should be ip", m.Type)
	}
}
