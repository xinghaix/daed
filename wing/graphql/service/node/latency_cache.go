/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, daeuniverse Organization <team@v2raya.org>
 */

package node

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/daeuniverse/dae-wing/dae"
	"github.com/daeuniverse/dae-wing/db"
	"github.com/graph-gophers/graphql-go"
	"gorm.io/gorm"
)

type latencyCacheEntry struct {
	result    *LatencyResolver
	updatedAt time.Time
	// gen identifies the probe currently allowed to update this entry while
	// it is pending, so a cancelled probe cannot clobber a newer one.
	gen uint64
}

// maxLatencyCacheEntries bounds the cache; the oldest entries are evicted
// first. Entries of removed nodes are also pruned on full queries.
const maxLatencyCacheEntries = 4096

var nodeLatencyCache = struct {
	mu        sync.RWMutex
	refreshMu sync.Mutex
	items     map[uint]latencyCacheEntry
}{
	items: map[uint]latencyCacheEntry{},
}

func cloneLatencyResolver(resolver *LatencyResolver) *LatencyResolver {
	if resolver == nil {
		return nil
	}

	clone := *resolver
	if resolver.LatencyMsV != nil {
		latency := *resolver.LatencyMsV
		clone.LatencyMsV = &latency
	}
	if resolver.MessageV != nil {
		message := *resolver.MessageV
		clone.MessageV = &message
	}
	clone.PingV = cloneProbeResolver(resolver.PingV)
	clone.HttpV = cloneProbeResolver(resolver.HttpV)
	return &clone
}

func storeLatencyResults(results []*LatencyResolver) {
	nodeLatencyCache.mu.Lock()
	defer nodeLatencyCache.mu.Unlock()

	now := time.Now()
	for _, result := range results {
		if result == nil {
			continue
		}
		entry := nodeLatencyCache.items[result.NodeID]
		entry.result = cloneLatencyResolver(result)
		entry.updatedAt = now
		nodeLatencyCache.items[result.NodeID] = entry
	}
	evictOldestLatencyEntriesLocked()
}

// evictOldestLatencyEntriesLocked keeps the cache within its bound.
func evictOldestLatencyEntriesLocked() {
	for len(nodeLatencyCache.items) > maxLatencyCacheEntries {
		var oldestID uint
		var oldest time.Time
		first := true
		for id, entry := range nodeLatencyCache.items {
			if first || entry.updatedAt.Before(oldest) {
				oldestID, oldest, first = id, entry.updatedAt, false
			}
		}
		delete(nodeLatencyCache.items, oldestID)
	}
}

// beginLatencyProbe marks both methods of a node as pending (keeping the
// previous values for display) and returns the generation that may update
// the entry.
func beginLatencyProbe(nodeID uint, gen uint64, pingApplicable bool) {
	nodeLatencyCache.mu.Lock()
	defer nodeLatencyCache.mu.Unlock()
	entry := nodeLatencyCache.items[nodeID]
	if entry.result == nil {
		entry.result = &LatencyResolver{NodeID: nodeID}
	} else {
		entry.result = cloneLatencyResolver(entry.result)
	}
	if entry.result.PingV == nil {
		entry.result.PingV = &ProbeResolver{SupportedV: pingApplicable}
	}
	if entry.result.HttpV == nil {
		entry.result.HttpV = &ProbeResolver{SupportedV: true}
	}
	entry.result.PingV.PendingV = true
	entry.result.HttpV.PendingV = true
	entry.gen = gen
	nodeLatencyCache.items[nodeID] = entry
	evictOldestLatencyEntriesLocked()
}

// storeLatencyProbe publishes one method's result for an in-flight probe.
func storeLatencyProbe(nodeID uint, gen uint64, method string, result *ProbeResolver) {
	nodeLatencyCache.mu.Lock()
	defer nodeLatencyCache.mu.Unlock()
	entry, ok := nodeLatencyCache.items[nodeID]
	if !ok || entry.gen != gen || entry.result == nil {
		return
	}
	entry.result = cloneLatencyResolver(entry.result)
	switch method {
	case latencyMethodPing:
		entry.result.PingV = cloneProbeResolver(result)
	case latencyMethodHTTP:
		entry.result.HttpV = cloneProbeResolver(result)
	}
	entry.result.syncLegacyFields()
	nodeLatencyCache.items[nodeID] = entry
}

// finishLatencyProbe stores the final result of a probe generation.
func finishLatencyProbe(gen uint64, result *LatencyResolver) {
	nodeLatencyCache.mu.Lock()
	defer nodeLatencyCache.mu.Unlock()
	entry, ok := nodeLatencyCache.items[result.NodeID]
	if ok && entry.gen != gen {
		return
	}
	entry.result = cloneLatencyResolver(result)
	entry.updatedAt = time.Now()
	nodeLatencyCache.items[result.NodeID] = entry
	evictOldestLatencyEntriesLocked()
}

// abortLatencyProbe clears the pending flags of a cancelled probe and keeps
// whatever results it already published.
func abortLatencyProbe(nodeID uint, gen uint64) {
	nodeLatencyCache.mu.Lock()
	defer nodeLatencyCache.mu.Unlock()
	entry, ok := nodeLatencyCache.items[nodeID]
	if !ok || entry.gen != gen || entry.result == nil {
		return
	}
	entry.result = cloneLatencyResolver(entry.result)
	for _, probe := range []*ProbeResolver{entry.result.PingV, entry.result.HttpV} {
		if probe != nil {
			probe.PendingV = false
		}
	}
	if entry.result.PingV != nil && entry.result.PingV.TestedAtV.IsZero() &&
		entry.result.HttpV != nil && entry.result.HttpV.TestedAtV.IsZero() {
		// Nothing was ever measured: forget the placeholder.
		delete(nodeLatencyCache.items, nodeID)
		return
	}
	nodeLatencyCache.items[nodeID] = entry
}

// ForgetLatencies drops cached results of removed nodes.
func ForgetLatencies(nodeIDs []uint) {
	nodeLatencyCache.mu.Lock()
	defer nodeLatencyCache.mu.Unlock()
	for _, id := range nodeIDs {
		delete(nodeLatencyCache.items, id)
	}
}

// pruneLatencyCache drops entries whose node no longer exists.
func pruneLatencyCache(existing []db.Node) {
	keep := make(map[uint]struct{}, len(existing))
	for _, node := range existing {
		keep[node.ID] = struct{}{}
	}
	nodeLatencyCache.mu.Lock()
	defer nodeLatencyCache.mu.Unlock()
	for id := range nodeLatencyCache.items {
		if _, ok := keep[id]; !ok {
			delete(nodeLatencyCache.items, id)
		}
	}
}

func snapshotCachedLatencyResults() map[uint]*LatencyResolver {
	nodeLatencyCache.mu.RLock()
	defer nodeLatencyCache.mu.RUnlock()

	results := make(map[uint]*LatencyResolver, len(nodeLatencyCache.items))
	for id, resolver := range nodeLatencyCache.items {
		results[id] = cloneLatencyResolver(resolver.result)
	}
	return results
}

func staleLatencyNodes(nodes []db.Node, interval time.Duration, now time.Time) []db.Node {
	nodeLatencyCache.mu.RLock()
	defer nodeLatencyCache.mu.RUnlock()
	var stale []db.Node
	for _, node := range nodes {
		entry, ok := nodeLatencyCache.items[node.ID]
		if !ok || now.Sub(entry.updatedAt) >= interval {
			stale = append(stale, node)
		}
	}
	return stale
}

func loadRuntimeLatencyResults(ctx context.Context) (map[uint]*LatencyResolver, error) {
	ctl, err := dae.ControlPlane()
	if err != nil {
		if errors.Is(err, dae.ErrControlPlaneNotInit) {
			return map[uint]*LatencyResolver{}, nil
		}
		return nil, err
	}

	snapshots := ctl.SnapshotNodeLatencies()
	if len(snapshots) == 0 {
		return map[uint]*LatencyResolver{}, nil
	}

	links := make([]string, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if snapshot.Link == "" {
			continue
		}
		links = append(links, snapshot.Link)
	}

	if len(links) == 0 {
		return map[uint]*LatencyResolver{}, nil
	}

	var nodes []db.Node
	if err := db.DB(ctx).Where("link in ?", links).Find(&nodes).Error; err != nil {
		return nil, err
	}

	nodesByLink := make(map[string][]db.Node, len(nodes))
	for _, node := range nodes {
		nodesByLink[node.Link] = append(nodesByLink[node.Link], node)
	}

	results := make(map[uint]*LatencyResolver)
	for _, snapshot := range snapshots {
		if snapshot.CheckedAt.IsZero() && snapshot.LatencyMs == nil && snapshot.Message == "no latency result" {
			continue
		}

		matchedNodes, ok := nodesByLink[snapshot.Link]
		if !ok {
			continue
		}

		for _, node := range matchedNodes {
			results[node.ID] = cloneLatencyResolver(&LatencyResolver{
				NodeID:     node.ID,
				LatencyMsV: snapshot.LatencyMs,
				AliveVal:   snapshot.Alive,
				TestedAtV:  snapshot.CheckedAt,
				MessageV:   stringPtr(snapshot.Message),
				// dae's own health check is an HTTP check over the node.
				HttpV: &ProbeResolver{
					OkV:        snapshot.Alive,
					LatencyMsV: snapshot.LatencyMs,
					MessageV:   optionalString(snapshot.Message),
					TestedAtV:  snapshot.CheckedAt,
					SupportedV: true,
				},
			})
		}
	}

	return results, nil
}

func selectedCheckInterval(ctx context.Context) (time.Duration, error) {
	var configModel db.Config
	if err := db.DB(ctx).Where("selected = ?", true).First(&configModel).Error; err != nil {
		return 0, err
	}

	parsedConfig, err := dae.ParseConfig(&configModel.Global, nil, nil)
	if err != nil {
		return 0, err
	}

	if parsedConfig.Global.CheckInterval <= 0 {
		return 30 * time.Second, nil
	}

	return parsedConfig.Global.CheckInterval, nil
}

func refreshLatencyCache(ctx context.Context, nodes []db.Node, all bool) error {
	env, err := newLatencyProbeEnv(ctx)
	if err != nil {
		return err
	}

	if _, err := runLatencyProbes(ctx, env, nodes); err != nil {
		return err
	}

	if all {
		if ctl, err := dae.ControlPlane(); err == nil {
			ctl.TriggerLatencyChecks()
		}
	}

	return nil
}

func refreshLatencyCacheIfNeeded(ctx context.Context, nodes []db.Node, all bool) error {
	interval, err := selectedCheckInterval(ctx)
	if err != nil {
		return err
	}

	if len(staleLatencyNodes(nodes, interval, time.Now())) == 0 {
		return nil
	}

	nodeLatencyCache.refreshMu.Lock()
	defer nodeLatencyCache.refreshMu.Unlock()

	stale := staleLatencyNodes(nodes, interval, time.Now())
	if len(stale) == 0 {
		return nil
	}

	return refreshLatencyCache(ctx, stale, all)
}

func mapsValues(items map[uint]*LatencyResolver) []*LatencyResolver {
	results := make([]*LatencyResolver, 0, len(items))
	for _, item := range items {
		results = append(results, item)
	}
	return results
}

func stringPtr(value string) *string {
	return &value
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// QueryLatencies returns cached latency results. Unless cachedOnly is set,
// nodes whose result is older than check_interval are probed first.
func QueryLatencies(ctx context.Context, ids *[]graphql.ID, cachedOnly bool) ([]*LatencyResolver, error) {
	nodes, err := latencyProbeNodes(ctx, ids)
	if err != nil {
		return nil, err
	}
	if ids == nil {
		pruneLatencyCache(nodes)
	}
	if !cachedOnly {
		if err := refreshLatencyCacheIfNeeded(ctx, nodes, ids == nil); err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	}

	merged := snapshotCachedLatencyResults()
	runtimeResults, err := loadRuntimeLatencyResults(ctx)
	if err != nil {
		return nil, err
	}
	for id, resolver := range runtimeResults {
		if _, ok := merged[id]; !ok {
			merged[id] = resolver
		}
	}

	results := make([]*LatencyResolver, 0, len(nodes))
	for _, node := range nodes {
		if resolver, ok := merged[node.ID]; ok {
			results = append(results, cloneLatencyResolver(resolver))
		}
	}

	return results, nil
}
