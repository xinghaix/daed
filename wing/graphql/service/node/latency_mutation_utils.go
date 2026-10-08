/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, daeuniverse Organization <team@v2raya.org>
 */

package node

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae-wing/common"
	"github.com/daeuniverse/dae-wing/dae"
	"github.com/daeuniverse/dae-wing/db"
	daecommon "github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/daedns"
	dialer "github.com/daeuniverse/dae/component/outbound/dialer"
	daeConfig "github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/graph-gophers/graphql-go"
	"github.com/sirupsen/logrus"
)

const (
	// latencyProbeConcurrency bounds how many nodes are probed at once across
	// all requests (manual tests and stale-cache refreshes share it), so
	// probes do not compete for bandwidth and skew each other.
	latencyProbeConcurrency = 8

	latencyMethodHandshake = "HANDSHAKE"
	latencyMethodHTTP      = "HTTP"
)

// latencyProbeSlots is the global worker pool.
var latencyProbeSlots = make(chan struct{}, latencyProbeConcurrency)

// latencyProbeGen numbers probe runs; see latencyCacheEntry.gen.
var latencyProbeGen atomic.Uint64

// latencyInflight deduplicates concurrent probes of the same node: later
// requests wait for the running probe instead of starting another one.
var latencyInflight = struct {
	mu    sync.Mutex
	calls map[uint]*latencyCall
}{calls: map[uint]*latencyCall{}}

type latencyCall struct {
	done    chan struct{}
	result  *LatencyResolver // set before done is closed
	waiters int              // guarded by latencyInflight.mu
	cancel  context.CancelFunc
}

// latencyGeoDataDirs are searched for geoip/geosite files referenced by the
// DNS routing rules (the same directories dae is started with).
var latencyGeoDataDirs []string

// SetGeoDataDirs tells latency probes where dae's geodata files live. Call
// it once at startup.
func SetGeoDataDirs(dirs []string) {
	latencyGeoDataDirs = append([]string(nil), dirs...)
}

// latencyProbeEnv is what a probe needs from the selected config.
type latencyProbeEnv struct {
	option *dialer.GlobalOption
	// dnsRouter is dae's DNS router for the selected dns config (nil when
	// it has no routing rules, like in dae). Node server names are resolved
	// through it exactly like dae's own node dialers do: the bootstrap
	// resolver or a node/subscription DNS rule, over sockets carrying
	// so_mark_from_dae, instead of the system resolver, which may be
	// captured by dae itself or answered by a fake-ip DNS on the LAN.
	dnsRouter        *daedns.Router
	subscriptionTags map[uint]string
	// refs counts the creator plus running probes: a probe may outlive the
	// request that started it when another request joined it.
	refs atomic.Int32
	// probe is the per-node probe; tests replace it.
	probe func(ctx context.Context, env *latencyProbeEnv, node *db.Node, gen uint64) *LatencyResolver
}

func newLatencyProbeEnv(ctx context.Context) (*latencyProbeEnv, error) {
	conf, err := latencyProbeConfig(ctx)
	if err != nil {
		return nil, err
	}
	option, err := latencyProbeOption(&conf.Global)
	if err != nil {
		return nil, err
	}
	env := &latencyProbeEnv{option: option, probe: probeNodeLatency}
	env.refs.Store(1)
	router, err := daedns.NewWithOption(discardLogger(), &conf.Global, &conf.Dns, &daedns.NewOption{
		LocationFinder: assets.NewLocationFinder(latencyGeoDataDirs),
		DirectDialer:   option.DirectDialer,
	})
	if err != nil {
		return nil, fmt.Errorf("dns config: %w", err)
	}
	if router != nil {
		env.dnsRouter = router
		option.DaeDNS = router
	}

	var subscriptions []db.Subscription
	if err := db.DB(ctx).Model(&db.Subscription{}).Select("id", "tag").Find(&subscriptions).Error; err != nil {
		env.Close()
		return nil, err
	}
	env.subscriptionTags = make(map[uint]string, len(subscriptions))
	for _, sub := range subscriptions {
		if sub.Tag != nil {
			env.subscriptionTags[sub.ID] = *sub.Tag
		}
	}
	return env, nil
}

func (e *latencyProbeEnv) retain() {
	e.refs.Add(1)
}

// Close drops a reference and releases the DNS router with the last one.
func (e *latencyProbeEnv) Close() {
	if e != nil && e.refs.Add(-1) == 0 && e.dnsRouter != nil {
		_ = e.dnsRouter.Close()
	}
}

func (e *latencyProbeEnv) subscriptionTag(node *db.Node) string {
	if node.SubscriptionID == nil {
		return ""
	}
	return e.subscriptionTags[*node.SubscriptionID]
}

func discardLogger() *logrus.Logger {
	log := logrus.New()
	log.SetOutput(io.Discard)
	return log
}

// TestLatencies probes all nodes (ids == nil) or the given nodes.
func TestLatencies(ctx context.Context, ids *[]graphql.ID) ([]*LatencyResolver, error) {
	nodes, err := latencyProbeNodes(ctx, ids)
	if err != nil {
		return nil, err
	}
	return testNodes(ctx, nodes)
}

// TestSubscriptionLatencies probes every node of a subscription.
func TestSubscriptionLatencies(ctx context.Context, id graphql.ID) ([]*LatencyResolver, error) {
	nodes, err := subscriptionLatencyNodes(ctx, id)
	if err != nil {
		return nil, err
	}
	return testNodes(ctx, nodes)
}

// TestGroupLatencies probes every node of a group: its own nodes plus the
// nodes its subscription bindings match.
func TestGroupLatencies(ctx context.Context, id graphql.ID) ([]*LatencyResolver, error) {
	nodes, err := groupLatencyNodes(ctx, id)
	if err != nil {
		return nil, err
	}
	return testNodes(ctx, nodes)
}

func testNodes(ctx context.Context, nodes []db.Node) ([]*LatencyResolver, error) {
	if len(nodes) == 0 {
		return []*LatencyResolver{}, nil
	}
	env, err := newLatencyProbeEnv(ctx)
	if err != nil {
		return nil, err
	}
	defer env.Close()
	return runLatencyProbes(ctx, env, nodes)
}

// runLatencyProbes probes nodes through the shared worker pool and returns
// their results in order. It returns ctx.Err() when ctx is cancelled; probes
// nobody waits for any more are cancelled as well.
func runLatencyProbes(ctx context.Context, env *latencyProbeEnv, nodes []db.Node) ([]*LatencyResolver, error) {
	results := make([]*LatencyResolver, len(nodes))
	var wg sync.WaitGroup
	for i := range nodes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = awaitNodeLatency(ctx, env, nodes[i])
		}(i)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]*LatencyResolver, 0, len(results))
	for _, r := range results {
		if r != nil {
			out = append(out, r)
		}
	}
	return out, nil
}

// awaitNodeLatency joins (or starts) the probe of one node and waits for it.
// It returns nil if ctx is cancelled first.
func awaitNodeLatency(ctx context.Context, env *latencyProbeEnv, node db.Node) *LatencyResolver {
	latencyInflight.mu.Lock()
	call, ok := latencyInflight.calls[node.ID]
	if !ok {
		probeCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		call = &latencyCall{done: make(chan struct{}), cancel: cancel}
		latencyInflight.calls[node.ID] = call
		gen := latencyProbeGen.Add(1)
		beginLatencyProbe(node.ID, gen, handshakeTargetForLink(node.Link).Kind != "")
		env.retain()
		go runNodeLatency(probeCtx, env, node, gen, call)
	}
	call.waiters++
	latencyInflight.mu.Unlock()

	select {
	case <-call.done:
		latencyInflight.mu.Lock()
		call.waiters--
		latencyInflight.mu.Unlock()
		return cloneLatencyResolver(call.result)
	case <-ctx.Done():
		latencyInflight.mu.Lock()
		call.waiters--
		if call.waiters == 0 {
			// Nobody is interested any more: stop the probe, and let a new
			// request start a fresh one instead of joining a dying probe.
			call.cancel()
			if latencyInflight.calls[node.ID] == call {
				delete(latencyInflight.calls, node.ID)
			}
		}
		latencyInflight.mu.Unlock()
		return nil
	}
}

func runNodeLatency(ctx context.Context, env *latencyProbeEnv, node db.Node, gen uint64, call *latencyCall) {
	defer env.Close()
	defer call.cancel()
	var result *LatencyResolver
	select {
	case latencyProbeSlots <- struct{}{}:
		result = env.probe(ctx, env, &node, gen)
		<-latencyProbeSlots
	case <-ctx.Done():
	}
	if ctx.Err() != nil {
		abortLatencyProbe(node.ID, gen)
		result = nil
	} else if result != nil {
		finishLatencyProbe(gen, result)
	}

	latencyInflight.mu.Lock()
	if latencyInflight.calls[node.ID] == call {
		delete(latencyInflight.calls, node.ID)
	}
	call.result = result
	latencyInflight.mu.Unlock()
	close(call.done)
}

// probeNodeLatency runs the handshake probe then HTTP for one node with a dialer of its
// own, publishing each method's result as soon as it is known.
func probeNodeLatency(ctx context.Context, env *latencyProbeEnv, node *db.Node, gen uint64) *LatencyResolver {
	result := &LatencyResolver{NodeID: node.ID, TestedAtV: time.Now()}
	publish := func(method string, outcome probeOutcome) *ProbeResolver {
		probe := probeResolverFromOutcome(outcome)
		storeLatencyProbe(node.ID, gen, method, probe)
		return probe
	}

	subscriptionTag := env.subscriptionTag(node)
	// Same construction as dae's own node dialers: so_mark_from_dae on every
	// socket and, with a DNS router, dae's resolution of the server name.
	d, err := dialer.NewFromLinkContext(ctx, env.option, dialer.InstanceOption{DisableCheck: true}, node.Link, subscriptionTag)
	if err != nil {
		failed := failedOutcome(fmt.Errorf("invalid node: %w", err))
		result.HandshakeV = publish(latencyMethodHandshake, withMethod(failed, handshakeTargetForLink(node.Link).Kind))
		result.HttpV = publish(latencyMethodHTTP, withMethod(failed, latencyMethodHTTP))
		result.syncLegacyFields()
		return result
	}
	defer func() { _ = d.Close() }()

	soMark := env.option.SoMarkFromDae
	mptcp := env.option.Mptcp

	// Handshake: direct TLS/QUIC handshake or TCP connect to the server.
	address, name := node.Address, node.Name
	if property := d.Property(); property != nil {
		if property.Address != "" {
			address = property.Address
		}
		if property.Name != "" {
			name = property.Name
		}
	}
	directDialer := env.option.DirectDialer
	if directDialer == nil {
		directDialer = direct.SymmetricDirect
	}
	lookup := env.serverLookup(directDialer, node, subscriptionTag, name, address)
	handshake := probeHandshake(ctx, directDialer.DialContext, lookup, address, handshakeTargetForLink(node.Link), soMark, mptcp)
	result.HandshakeV = publish(latencyMethodHandshake, handshake)

	// HTTP: real request through the node.
	var httpOutcome probeOutcome
	if opt, err := env.option.TcpCheckOptionRaw.Option(); err != nil {
		httpOutcome = failedOutcome(err)
	} else {
		httpOutcome = probeHTTPFamilies(ctx, d.DialContext, opt.Url, opt.Ip46, opt.Method, soMark, mptcp)
	}
	httpOutcome.Method = latencyMethodHTTP
	result.HttpV = publish(latencyMethodHTTP, httpOutcome)
	result.syncLegacyFields()
	return result
}

type ipAddrLookuper interface {
	LookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error)
}

// serverLookup resolves a node's server name the way dae's node dialer
// does: through the DNS router's node wrapper when there is one (bootstrap
// resolver or node DNS rule), otherwise through the direct dialer, whose
// resolver sockets carry so_mark_from_dae and bypass dae's own capture.
func (e *latencyProbeEnv) serverLookup(base netproxy.Dialer, node *db.Node, subscriptionTag, name, address string) hostLookup {
	var resolver netproxy.Dialer = base
	host, _, _ := net.SplitHostPort(address)
	if e.dnsRouter != nil {
		wrapped, err := e.dnsRouter.WrapNodeDialer(base, daedns.NodeMeta{
			SubscriptionTag: subscriptionTag,
			Name:            name,
			Link:            node.Link,
			AddressHost:     host,
		})
		if err == nil {
			resolver = wrapped
		}
	}
	network := daecommon.MagicNetwork("tcp", e.option.SoMarkFromDae, e.option.Mptcp)
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		var (
			ipAddrs []net.IPAddr
			err     error
		)
		if l, ok := resolver.(ipAddrLookuper); ok {
			ipAddrs, err = l.LookupIPAddr(ctx, network, host)
		} else {
			ipAddrs, err = net.DefaultResolver.LookupIPAddr(ctx, host)
		}
		if err != nil {
			return nil, err
		}
		ips := make([]netip.Addr, 0, len(ipAddrs))
		for _, a := range ipAddrs {
			if ip, ok := netip.AddrFromSlice(a.IP); ok {
				ips = append(ips, ip.Unmap())
			}
		}
		return ips, nil
	}
}

// latencyProbeConfig parses the selected global and dns config.
func latencyProbeConfig(ctx context.Context) (*daeConfig.Config, error) {
	var configModel db.Config
	if err := db.DB(ctx).Where("selected = ?", true).First(&configModel).Error; err != nil {
		return nil, err
	}
	var dnsSection *string
	var dnsModel db.Dns
	q := db.DB(ctx).Where("selected = ?", true).Limit(1).Find(&dnsModel)
	if q.Error != nil {
		return nil, q.Error
	}
	if q.RowsAffected > 0 {
		dnsSection = &dnsModel.Dns
	}
	return dae.ParseConfig(&configModel.Global, dnsSection, nil)
}

func latencyProbeOption(global *daeConfig.Global) (*dialer.GlobalOption, error) {
	fallbackResolver, err := netip.ParseAddrPort(global.FallbackResolver)
	if err != nil {
		return nil, fmt.Errorf("fallback_resolver %q: %w", global.FallbackResolver, err)
	}
	option := dialer.NewGlobalOption(global, discardLogger())
	directDialers := direct.NewDirectDialers(global.FallbackResolver)
	option.SetRuntimeDependencies(directDialers.Symmetric, directDialers.Fullcone, netutils.NewSystemDNSResolver(fallbackResolver))
	return option, nil
}

func latencyProbeNodes(ctx context.Context, ids *[]graphql.ID) ([]db.Node, error) {
	q := db.DB(ctx).Model(&db.Node{})
	if ids != nil {
		decodedIDs, err := common.DecodeCursorBatch(*ids)
		if err != nil {
			return nil, err
		}
		q = q.Where("id in ?", decodedIDs)
	}

	var nodes []db.Node
	if err := q.Order("id").Find(&nodes).Error; err != nil {
		return nil, err
	}
	return nodes, nil
}

func subscriptionLatencyNodes(ctx context.Context, id graphql.ID) ([]db.Node, error) {
	subscriptionID, err := common.DecodeCursor(id)
	if err != nil {
		return nil, err
	}
	var count int64
	if err := db.DB(ctx).Model(&db.Subscription{}).Where("id = ?", subscriptionID).Count(&count).Error; err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, fmt.Errorf("subscription %v not found", id)
	}
	var nodes []db.Node
	if err := db.DB(ctx).Where("subscription_id = ?", subscriptionID).Order("id").Find(&nodes).Error; err != nil {
		return nil, err
	}
	return nodes, nil
}

func groupLatencyNodes(ctx context.Context, id graphql.ID) ([]db.Node, error) {
	groupID, err := common.DecodeCursor(id)
	if err != nil {
		return nil, err
	}
	var group db.Group
	err = db.DB(ctx).
		Preload("Node").
		Preload("SubscriptionBindings.Subscription.Node").
		Where("id = ?", groupID).
		First(&group).Error
	if err != nil {
		return nil, fmt.Errorf("group %v: %w", id, err)
	}
	seen := make(map[uint]struct{})
	var nodes []db.Node
	add := func(n db.Node) {
		if _, ok := seen[n.ID]; ok {
			return
		}
		seen[n.ID] = struct{}{}
		nodes = append(nodes, n)
	}
	for _, n := range group.Node {
		add(n)
	}
	for _, binding := range group.SubscriptionBindings {
		var re *regexp.Regexp
		if binding.NameFilterRegex != nil && *binding.NameFilterRegex != "" {
			if re, err = regexp.Compile(*binding.NameFilterRegex); err != nil {
				return nil, fmt.Errorf("invalid subscription filter %q: %w", *binding.NameFilterRegex, err)
			}
		}
		for _, n := range binding.Subscription.Node {
			if re == nil || re.MatchString(n.Name) {
				add(n)
			}
		}
	}
	return nodes, nil
}
