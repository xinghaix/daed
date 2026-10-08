package node

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae-wing/common"
	"github.com/daeuniverse/dae-wing/db"
	"github.com/graph-gophers/graphql-go"
	"go.uber.org/goleak"
)

func fakeEnv(probe func(ctx context.Context, node *db.Node) *LatencyResolver) *latencyProbeEnv {
	return &latencyProbeEnv{probe: func(ctx context.Context, _ *latencyProbeEnv, node *db.Node, gen uint64) *LatencyResolver {
		return probe(ctx, node)
	}}
}

func okResult(id uint) *LatencyResolver {
	ms := int32(10)
	now := time.Now()
	r := &LatencyResolver{
		NodeID: id,
		PingV:  &ProbeResolver{OkV: true, LatencyMsV: &ms, TestedAtV: now, SupportedV: true},
		HttpV:  &ProbeResolver{OkV: true, LatencyMsV: &ms, TestedAtV: now, SupportedV: true},
	}
	r.syncLegacyFields()
	return r
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func inflightCount() int {
	latencyInflight.mu.Lock()
	defer latencyInflight.mu.Unlock()
	return len(latencyInflight.calls)
}

func inflightWaiters(id uint) int {
	latencyInflight.mu.Lock()
	defer latencyInflight.mu.Unlock()
	if call, ok := latencyInflight.calls[id]; ok {
		return call.waiters
	}
	return 0
}

func TestLatencyRunnerDedupesConcurrentRequests(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	resetLatencyCache(t)
	var calls atomic.Int32
	release := make(chan struct{})
	env := fakeEnv(func(ctx context.Context, node *db.Node) *LatencyResolver {
		calls.Add(1)
		<-release
		return okResult(node.ID)
	})

	const requests = 5
	results := make([][]*LatencyResolver, requests)
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], _ = runLatencyProbes(context.Background(), env, []db.Node{{ID: 7}})
		}(i)
	}
	waitFor(t, "all requests to join", func() bool { return inflightWaiters(7) == requests })
	if cached := snapshotCachedLatencyResults()[7]; cached == nil || !cached.Testing() {
		t.Fatal("node must be marked as testing while probed")
	}
	close(release)
	wg.Wait()

	if calls.Load() != 1 {
		t.Fatalf("probe ran %d times for concurrent requests, want 1", calls.Load())
	}
	for i, r := range results {
		if len(r) != 1 || r[0].NodeID != 7 || !r[0].AliveVal {
			t.Fatalf("request %d: %+v", i, r)
		}
	}
	if inflightCount() != 0 {
		t.Fatal("in-flight entry leaked")
	}
	cached := snapshotCachedLatencyResults()[7]
	if cached == nil || cached.Testing() || !cached.AliveVal {
		t.Fatalf("final result not cached: %+v", cached)
	}
}

func TestLatencyRunnerBoundsConcurrency(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	resetLatencyCache(t)
	var current, peak atomic.Int32
	env := fakeEnv(func(ctx context.Context, node *db.Node) *LatencyResolver {
		n := current.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		current.Add(-1)
		return okResult(node.ID)
	})
	nodes := make([]db.Node, 40)
	for i := range nodes {
		nodes[i].ID = uint(i + 1)
	}
	// Two overlapping requests share the same global pool.
	var wg sync.WaitGroup
	for _, part := range [][]db.Node{nodes[:20], nodes[20:]} {
		wg.Add(1)
		go func(part []db.Node) {
			defer wg.Done()
			results, err := runLatencyProbes(context.Background(), env, part)
			if err != nil || len(results) != len(part) {
				t.Errorf("results=%d err=%v", len(results), err)
			}
			for i, r := range results {
				if r.NodeID != part[i].ID {
					t.Errorf("result order: got node %d want %d", r.NodeID, part[i].ID)
				}
			}
		}(part)
	}
	wg.Wait()
	if p := peak.Load(); p > latencyProbeConcurrency || p < 2 {
		t.Fatalf("peak concurrency %d, want 2..%d", p, latencyProbeConcurrency)
	}
}

func TestLatencyRunnerCancel(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	resetLatencyCache(t)
	started := make(chan struct{})
	var sawCancel atomic.Bool
	env := fakeEnv(func(ctx context.Context, node *db.Node) *LatencyResolver {
		close(started)
		<-ctx.Done()
		sawCancel.Store(true)
		return okResult(node.ID)
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() {
		_, err := runLatencyProbes(ctx, env, []db.Node{{ID: 3}})
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	waitFor(t, "probe to stop", func() bool { return sawCancel.Load() && inflightCount() == 0 })
	waitFor(t, "placeholder cleanup", func() bool {
		_, ok := snapshotCachedLatencyResults()[3]
		return !ok
	})
}

func TestLatencyRunnerKeepsProbeForRemainingWaiter(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	resetLatencyCache(t)
	release := make(chan struct{})
	var canceled atomic.Bool
	env := fakeEnv(func(ctx context.Context, node *db.Node) *LatencyResolver {
		select {
		case <-release:
		case <-ctx.Done():
			canceled.Store(true)
		}
		return okResult(node.ID)
	})
	ctx1, cancel1 := context.WithCancel(context.Background())
	first := make(chan error)
	go func() {
		_, err := runLatencyProbes(ctx1, env, []db.Node{{ID: 4}})
		first <- err
	}()
	second := make(chan []*LatencyResolver)
	waitFor(t, "first waiter", func() bool { return inflightWaiters(4) == 1 })
	go func() {
		r, _ := runLatencyProbes(context.Background(), env, []db.Node{{ID: 4}})
		second <- r
	}()
	waitFor(t, "second waiter", func() bool { return inflightWaiters(4) == 2 })
	cancel1()
	<-first
	close(release)
	if r := <-second; len(r) != 1 || !r[0].AliveVal || canceled.Load() {
		t.Fatalf("remaining waiter lost its probe: %+v canceled=%v", r, canceled.Load())
	}
}

func TestLatencyProbeGenerations(t *testing.T) {
	resetLatencyCache(t)
	ms := int32(5)
	beginLatencyProbe(1, 10, true)
	r := snapshotCachedLatencyResults()[1]
	if !r.Testing() || !r.PingV.PendingV || !r.HttpV.PendingV {
		t.Fatalf("begin: %+v", r)
	}
	storeLatencyProbe(1, 10, latencyMethodPing, &ProbeResolver{OkV: true, LatencyMsV: &ms, TestedAtV: time.Now(), SupportedV: true})
	r = snapshotCachedLatencyResults()[1]
	if r.PingV.PendingV || *r.PingV.LatencyMsV != 5 || !r.HttpV.PendingV || !r.Testing() {
		t.Fatalf("partial ping result must show while http is pending: ping=%+v http=%+v", r.PingV, r.HttpV)
	}
	// A newer probe takes over; the old generation must not write anymore.
	beginLatencyProbe(1, 11, true)
	storeLatencyProbe(1, 10, latencyMethodHTTP, &ProbeResolver{MessageV: stringPtr("stale"), TestedAtV: time.Now(), SupportedV: true})
	finishLatencyProbe(10, &LatencyResolver{NodeID: 1})
	r = snapshotCachedLatencyResults()[1]
	if !r.HttpV.PendingV || r.HttpV.MessageV != nil {
		t.Fatalf("stale generation overwrote the entry: %+v", r.HttpV)
	}
	if r.PingV.LatencyMsV == nil || *r.PingV.LatencyMsV != 5 {
		t.Fatal("previous ping value must stay visible while re-testing")
	}
	abortLatencyProbe(1, 11)
	r = snapshotCachedLatencyResults()[1]
	if r == nil || r.Testing() || *r.PingV.LatencyMsV != 5 {
		t.Fatalf("abort must keep measured values and clear pending: %+v", r)
	}
}

func TestLatencyCacheBoundsAndCleanup(t *testing.T) {
	resetLatencyCache(t)
	results := make([]*LatencyResolver, 0, maxLatencyCacheEntries+10)
	for i := 1; i <= maxLatencyCacheEntries+10; i++ {
		results = append(results, &LatencyResolver{NodeID: uint(i)})
	}
	storeLatencyResults(results)
	if n := len(snapshotCachedLatencyResults()); n != maxLatencyCacheEntries {
		t.Fatalf("cache size %d, want %d", n, maxLatencyCacheEntries)
	}
	ForgetLatencies([]uint{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	pruneLatencyCache([]db.Node{{ID: 100}, {ID: 101}, {ID: 999999}})
	cached := snapshotCachedLatencyResults()
	if len(cached) > 2 {
		t.Fatalf("prune kept removed nodes: %d entries", len(cached))
	}
	for id := range cached {
		if id != 100 && id != 101 {
			t.Fatalf("unexpected entry %d", id)
		}
	}
}

func TestLatencyNodeSelection(t *testing.T) {
	if err := db.InitDatabase(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	d := db.DB(ctx)
	sub := db.Subscription{Link: "https://example.com/sub"}
	other := db.Subscription{Link: "https://example.com/other"}
	if err := d.Create(&sub).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.Create(&other).Error; err != nil {
		t.Fatal(err)
	}
	mk := func(name string, subID *uint) db.Node {
		n := db.Node{Link: "invalid-" + name, Name: name, SubscriptionID: subID}
		if err := d.Create(&n).Error; err != nil {
			t.Fatal(err)
		}
		return n
	}
	hk := mk("HK 01", &sub.ID)
	jp := mk("JP 01", &sub.ID)
	us := mk("US 01", &other.ID)
	solo := mk("solo", nil)

	got, err := subscriptionLatencyNodes(ctx, common.EncodeCursor(sub.ID))
	if err != nil || fmt.Sprint(nodeIDs(got)) != fmt.Sprint([]uint{hk.ID, jp.ID}) {
		t.Fatalf("subscription nodes: %v err=%v", nodeIDs(got), err)
	}
	if _, err := subscriptionLatencyNodes(ctx, common.EncodeCursor(uint(999))); err == nil {
		t.Fatal("missing subscription must fail")
	}

	group := db.Group{Name: "g", Policy: "min_moving_avg"}
	if err := d.Create(&group).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.Model(&group).Association("Node").Append(&solo, &hk); err != nil {
		t.Fatal(err)
	}
	re := "^HK"
	if err := d.Create(&db.GroupSubscription{GroupID: group.ID, SubscriptionID: sub.ID, NameFilterRegex: &re}).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.Create(&db.GroupSubscription{GroupID: group.ID, SubscriptionID: other.ID}).Error; err != nil {
		t.Fatal(err)
	}
	got, err = groupLatencyNodes(ctx, common.EncodeCursor(group.ID))
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint]bool{solo.ID: true, hk.ID: true, us.ID: true}
	if len(got) != len(want) {
		t.Fatalf("group nodes: %v (HK must be deduplicated, JP filtered)", nodeIDs(got))
	}
	for _, n := range got {
		if !want[n.ID] {
			t.Fatalf("group nodes: unexpected %d in %v", n.ID, nodeIDs(got))
		}
	}
}

func TestLatencyEntryPointsWithInvalidLinks(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent(), goleak.IgnoreAnyFunction("database/sql.(*DB).connectionOpener"))
	resetLatencyCache(t)
	if err := db.InitDatabase(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	d := db.DB(ctx)
	if err := d.Create(&db.Config{Global: "global {}", Selected: true}).Error; err != nil {
		t.Fatal(err)
	}
	sub := db.Subscription{Link: "https://example.com/sub"}
	if err := d.Create(&sub).Error; err != nil {
		t.Fatal(err)
	}
	nodes := []db.Node{{Link: "bogus://a", Name: "a", SubscriptionID: &sub.ID}, {Link: "bogus://b", Name: "b", Protocol: "hysteria2"}}
	if err := d.Create(&nodes).Error; err != nil {
		t.Fatal(err)
	}
	group := db.Group{Name: "g", Policy: "random"}
	if err := d.Create(&group).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.Model(&group).Association("Node").Append(&nodes[1]); err != nil {
		t.Fatal(err)
	}

	check := func(name string, results []*LatencyResolver, err error, ids ...uint) {
		t.Helper()
		if err != nil || len(results) != len(ids) {
			t.Fatalf("%s: results=%v err=%v", name, results, err)
		}
		for i, r := range results {
			if r.NodeID != ids[i] || r.PingV == nil || r.HttpV == nil || r.Testing() || r.AliveVal ||
				r.HttpV.MessageV == nil || r.HttpV.TestedAtV.IsZero() {
				t.Fatalf("%s: bad result %+v", name, r)
			}
		}
	}
	one := []graphql.ID{common.EncodeCursor(nodes[0].ID)}
	results, err := TestLatencies(ctx, &one)
	check("node", results, err, nodes[0].ID)
	results, err = TestSubscriptionLatencies(ctx, common.EncodeCursor(sub.ID))
	check("subscription", results, err, nodes[0].ID)
	results, err = TestGroupLatencies(ctx, common.EncodeCursor(group.ID))
	check("group", results, err, nodes[1].ID)
	if results[0].PingV.SupportedV {
		t.Fatal("PING must be reported as not applicable for UDP-only protocols")
	}
	results, err = TestLatencies(ctx, nil)
	check("all", results, err, nodes[0].ID, nodes[1].ID)

	cached, err := QueryLatencies(ctx, nil, true)
	if err != nil || len(cached) != 2 {
		t.Fatalf("cachedOnly: %v %v", cached, err)
	}
}

func nodeIDs(nodes []db.Node) []uint {
	ids := make([]uint, len(nodes))
	for i, n := range nodes {
		ids[i] = n.ID
	}
	return ids
}
