/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
)

// FromLinkCreator constructs a dialer from a link and may return nextDialer unchanged.
// Chain cleanup excludes the borrowed base and closes each distinct owned result once.
type FromLinkCreator func(gOption *ExtraOption, nextDialer netproxy.Dialer, link string) (dialer netproxy.Dialer, property *Property, err error)

var (
	fromLinkCreatorsMu sync.RWMutex
	fromLinkCreators   = make(map[string]FromLinkCreator)
)

// FromLinkRegister installs a link-scheme constructor. Registration
// typically happens in init(), but the map is guarded so runtime
// registration (plugin-style node sources) cannot race the lookup below.
func FromLinkRegister(name string, creator FromLinkCreator) {
	fromLinkCreatorsMu.Lock()
	defer fromLinkCreatorsMu.Unlock()
	fromLinkCreators[name] = creator
}

func NewNetproxyDialerFromLink(d netproxy.Dialer, gOption *ExtraOption, link string) (netproxy.Dialer, *Property, error) {
	/// Get overwritten name.
	overwrittenName, linklike := common.GetTagFromLinkLikePlaintext(link)
	links := strings.Split(linklike, "->")
	p := &Property{
		Name:     "",
		Address:  "",
		Protocol: "",
		Link:     linklike,
	}
	base := d
	var owned []io.Closer
	var ownsIntermediate, transferred bool
	defer func() {
		if !transferred {
			_ = closeDialerLayers(owned)
		}
	}()
	for i := len(links) - 1; i >= 0; i-- {
		if i == 0 {
			ownsIntermediate = len(owned) > 0
		}
		link := strings.TrimSpace(links[i])
		scheme, err := linkScheme(link)
		if err != nil {
			return nil, nil, err
		}
		fromLinkCreatorsMu.RLock()
		creator, ok := fromLinkCreators[scheme]
		fromLinkCreatorsMu.RUnlock()
		if !ok {
			return nil, nil, fmt.Errorf("unexpected link type: %v", scheme)
		}
		var _property *Property
		d, _property, err = creator(gOption, d, link)
		if err != nil {
			return nil, nil, fmt.Errorf("create %v: %w", link, err)
		}
		if closer, ok := d.(io.Closer); ok && !knownChainDialer(d, base, owned) {
			owned = append(owned, closer)
		}
		if p.Name == "" {
			p.Name = _property.Name
		} else {
			p.Name = _property.Name + "->" + p.Name
		}
		if p.Protocol == "" {
			p.Protocol = _property.Protocol
		} else {
			p.Protocol = _property.Protocol + "->" + p.Protocol
		}
		if p.Address == "" {
			p.Address = _property.Address
		} else {
			p.Address = _property.Address + "->" + p.Address
		}
	}
	if overwrittenName != "" {
		p.Name = overwrittenName
	}
	if ownsIntermediate {
		// Wrap only after construction: creators may require concrete types in
		// their internal transport chain. Single links keep their original type.
		d = wrapOwnedChain(&ownedChainDialer{Dialer: d, owned: owned})
	}
	transferred = true
	return d, p, nil
}

// knownChainDialer uses the comparable identity of the library's pointer dialers.
// Guard custom value types so interface comparisons cannot panic.
func knownChainDialer(d, base netproxy.Dialer, owned []io.Closer) bool {
	if !reflect.ValueOf(d).Comparable() {
		return false
	}
	if d == base {
		return true
	}
	for _, previous := range owned {
		if any(d) == any(previous) {
			return true
		}
	}
	return false
}

// ownedChainDialer owns only constructor results, never the borrowed base.
type ownedChainDialer struct {
	netproxy.Dialer
	owned     []io.Closer
	closeOnce sync.Once
	closeErr  error
}

func (d *ownedChainDialer) Close() error {
	d.closeOnce.Do(func() { d.closeErr = closeDialerLayers(d.owned) })
	return d.closeErr
}

func closeDialerLayers(owned []io.Closer) error {
	var err error
	for i := len(owned) - 1; i >= 0; i-- {
		err = stderrors.Join(err, owned[i].Close())
	}
	return err
}

type chainIPLookupDialer interface {
	LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error)
}

// chainUnwrapTop satisfies netproxy.DialerUnwrapper by exposing the wrapped
// original top itself, following the standard wrapper contract. The original
// top keeps its own deeper unwrap results reachable from that hop.
type chainUnwrapTop struct{ top netproxy.Dialer }

func (u chainUnwrapTop) UnwrapDialer() netproxy.Dialer { return u.top }

// Preserve only the optional interfaces the original top actually implements.
// Unwrap exposes the original top; namespace and lookup embed the original
// providers so their results are forwarded unchanged.
func wrapOwnedChain(chain *ownedChainDialer) netproxy.Dialer {
	_, hasUnwrap := chain.Dialer.(netproxy.DialerUnwrapper)
	u := chainUnwrapTop{top: chain.Dialer}
	n, hasNamespace := chain.Dialer.(netproxy.TransportCacheNamespaceProvider)
	l, hasLookup := chain.Dialer.(chainIPLookupDialer)
	switch {
	case hasUnwrap && hasNamespace && hasLookup:
		return &struct {
			*ownedChainDialer
			netproxy.DialerUnwrapper
			netproxy.TransportCacheNamespaceProvider
			chainIPLookupDialer
		}{chain, u, n, l}
	case hasUnwrap && hasNamespace:
		return &struct {
			*ownedChainDialer
			netproxy.DialerUnwrapper
			netproxy.TransportCacheNamespaceProvider
		}{chain, u, n}
	case hasUnwrap && hasLookup:
		return &struct {
			*ownedChainDialer
			netproxy.DialerUnwrapper
			chainIPLookupDialer
		}{chain, u, l}
	case hasNamespace && hasLookup:
		return &struct {
			*ownedChainDialer
			netproxy.TransportCacheNamespaceProvider
			chainIPLookupDialer
		}{chain, n, l}
	case hasUnwrap:
		return &struct {
			*ownedChainDialer
			netproxy.DialerUnwrapper
		}{chain, u}
	case hasNamespace:
		return &struct {
			*ownedChainDialer
			netproxy.TransportCacheNamespaceProvider
		}{chain, n}
	case hasLookup:
		return &struct {
			*ownedChainDialer
			chainIPLookupDialer
		}{chain, l}
	default:
		return chain
	}
}

func linkScheme(link string) (string, error) {
	i := strings.IndexByte(link, ':')
	if i <= 0 || !isSchemeStart(link[0]) {
		return "", fmt.Errorf("missing link scheme")
	}
	for _, c := range link[1:i] {
		if !isSchemeChar(byte(c)) {
			return "", fmt.Errorf("invalid link scheme: %q", link[:i])
		}
	}
	return strings.ToLower(link[:i]), nil
}

func isSchemeStart(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

func isSchemeChar(c byte) bool {
	return isSchemeStart(c) || '0' <= c && c <= '9' || c == '+' || c == '-' || c == '.'
}
