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
	"github.com/daeuniverse/dae/common/netutils"
	dialer "github.com/daeuniverse/dae/component/outbound/dialer"
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

	latencyMethodPing = "PING"
	latencyMethodHTTP = "HTTP"
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

// latencyProbeEnv is what a probe needs from the selected config.
type latencyProbeEnv struct {
	option   *dialer.GlobalOption
	resolver *net.Resolver
	// probe is the per-node probe; tests replace it.
	probe func(ctx context.Context, env *latencyProbeEnv, node *db.Node, gen uint64) *LatencyResolver
}

func newLatencyProbeEnv(ctx context.Context) (*latencyProbeEnv, error) {
	option, err := latencyProbeOption(ctx)
	if err != nil {
		return nil, err
	}
	return &latencyProbeEnv{option: option, resolver: net.DefaultResolver, probe: probeNodeLatency}, nil
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
		beginLatencyProbe(node.ID, gen, pingSupported(node.Protocol))
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

// probeNodeLatency runs PING then HTTP for one node with a dialer of its
// own, publishing each method's result as soon as it is known.
func probeNodeLatency(ctx context.Context, env *latencyProbeEnv, node *db.Node, gen uint64) *LatencyResolver {
	result := &LatencyResolver{NodeID: node.ID, TestedAtV: time.Now()}
	publish := func(method string, outcome probeOutcome) *ProbeResolver {
		probe := probeResolverFromOutcome(outcome)
		storeLatencyProbe(node.ID, gen, method, probe)
		return probe
	}

	d, err := dialer.NewFromLinkContext(ctx, env.option, dialer.InstanceOption{DisableCheck: true}, node.Link, "")
	if err != nil {
		failed := failedOutcome(fmt.Errorf("invalid node: %w", err))
		ping := failed
		ping.Unsupported = !pingSupported(node.Protocol)
		result.PingV = publish(latencyMethodPing, ping)
		result.HttpV = publish(latencyMethodHTTP, failed)
		result.syncLegacyFields()
		return result
	}
	defer func() { _ = d.Close() }()

	var soMark uint32
	var mptcp bool
	if network, err := netproxy.ParseMagicNetwork(env.option.TcpCheckOptionRaw.ResolverNetwork); err == nil {
		soMark = network.Mark
		mptcp = network.Mptcp
	}

	// PING: direct TCP connect to the node's server.
	protocol := node.Protocol
	address := node.Address
	if property := d.Property(); property != nil {
		if property.Protocol != "" {
			protocol = property.Protocol
		}
		if property.Address != "" {
			address = property.Address
		}
	}
	var ping probeOutcome
	if !pingSupported(protocol) {
		ping = probeOutcome{Unsupported: true, Message: "not applicable: " + protocol + " has no TCP listener", TestedAt: time.Now()}
	} else {
		directDialer := env.option.DirectDialer
		if directDialer == nil {
			directDialer = direct.SymmetricDirect
		}
		ping = probePing(ctx, directDialer.DialContext, env.resolver, address, soMark, mptcp)
	}
	result.PingV = publish(latencyMethodPing, ping)

	// HTTP: real request through the node.
	var httpOutcome probeOutcome
	if opt, err := env.option.TcpCheckOptionRaw.Option(); err != nil {
		httpOutcome = failedOutcome(err)
	} else {
		httpOutcome = probeHTTPFamilies(ctx, d.DialContext, opt.Url, opt.Ip46, opt.Method, soMark, mptcp)
	}
	result.HttpV = publish(latencyMethodHTTP, httpOutcome)
	result.syncLegacyFields()
	return result
}

func latencyProbeOption(ctx context.Context) (*dialer.GlobalOption, error) {
	var configModel db.Config
	q := db.DB(ctx).Where("selected = ?", true).First(&configModel)
	if q.Error != nil {
		return nil, q.Error
	}

	parsedConfig, err := dae.ParseConfig(&configModel.Global, nil, nil)
	if err != nil {
		return nil, err
	}

	log := logrus.New()
	log.SetOutput(io.Discard)
	fallbackResolver, err := netip.ParseAddrPort(parsedConfig.Global.FallbackResolver)
	if err != nil {
		return nil, fmt.Errorf("fallback_resolver %q: %w", parsedConfig.Global.FallbackResolver, err)
	}
	option := dialer.NewGlobalOption(&parsedConfig.Global, log)
	directDialers := direct.NewDirectDialers(parsedConfig.Global.FallbackResolver)
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
