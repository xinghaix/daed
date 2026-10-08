package grpc

import (
	"context"
	"net"
	"testing"
	"time"

	grpcpkg "google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

func TestCleanGlobalClientConnectionCacheClosesCachedConnections(t *testing.T) {
	globalCCAccess.Lock()
	original := globalCCMap
	globalCCMap = nil
	globalCCAccess.Unlock()
	t.Cleanup(func() {
		globalCCAccess.Lock()
		globalCCMap = original
		globalCCAccess.Unlock()
	})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = lis.Close() }()

	server := grpcpkg.NewServer()
	defer server.Stop()
	go func() { _ = server.Serve(lis) }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cc, err := grpcpkg.DialContext(
		ctx,
		lis.Addr().String(),
		grpcpkg.WithTransportCredentials(insecure.NewCredentials()),
		grpcpkg.WithBlock(),
	)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}

	globalCCAccess.Lock()
	globalCCMap = map[string]*clientConnMeta{
		"test": {cc: cc},
	}
	globalCCAccess.Unlock()

	CleanGlobalClientConnectionCache()

	deadline := time.Now().Add(time.Second)
	for cc.GetState() != connectivity.Shutdown && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if state := cc.GetState(); state != connectivity.Shutdown {
		t.Fatalf("client conn state = %v, want %v", state, connectivity.Shutdown)
	}
}

func TestCleanScopedClientConnectionCacheOnlyClosesMatchingScope(t *testing.T) {
	globalCCAccess.Lock()
	original := globalCCMap
	globalCCMap = nil
	globalCCAccess.Unlock()
	t.Cleanup(func() {
		globalCCAccess.Lock()
		globalCCMap = original
		globalCCAccess.Unlock()
	})

	listener1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen1: %v", err)
	}
	defer func() { _ = listener1.Close() }()
	listener2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen2: %v", err)
	}
	defer func() { _ = listener2.Close() }()

	server1 := grpcpkg.NewServer()
	defer server1.Stop()
	server2 := grpcpkg.NewServer()
	defer server2.Stop()
	go func() { _ = server1.Serve(listener1) }()
	go func() { _ = server2.Serve(listener2) }()

	cc1 := mustDialTestClientConn(t, listener1.Addr().String())
	cc2 := mustDialTestClientConn(t, listener2.Addr().String())
	globalCCAccess.Lock()
	globalCCMap = map[string]*clientConnMeta{
		grpcClientCacheKey("scope-a", "", listener1.Addr().String(), false, 0, false): {cc: cc1},
		grpcClientCacheKey("scope-b", "", listener2.Addr().String(), false, 0, false): {cc: cc2},
	}
	globalCCAccess.Unlock()

	CleanScopedClientConnectionCache("scope-a")

	assertConnState(t, cc1, connectivity.Shutdown)
	if cc2.GetState() == connectivity.Shutdown {
		t.Fatal("expected non-matching scoped client conn to remain open")
	}
}

func mustDialTestClientConn(t *testing.T, address string) *grpcpkg.ClientConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cc, err := grpcpkg.DialContext(ctx, address, grpcpkg.WithTransportCredentials(insecure.NewCredentials()), grpcpkg.WithBlock())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	return cc
}

func assertConnState(t *testing.T, cc *grpcpkg.ClientConn, want connectivity.State) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for cc.GetState() != want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if state := cc.GetState(); state != want {
		t.Fatalf("client conn state = %v, want %v", state, want)
	}
}
