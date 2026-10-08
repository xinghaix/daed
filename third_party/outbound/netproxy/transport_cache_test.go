package netproxy

import (
	"context"
	"testing"
)

type testNamespaceDialer struct {
	namespace string
}

func (d *testNamespaceDialer) DialContext(context.Context, string, string) (Conn, error) {
	return nil, nil
}

func (d *testNamespaceDialer) TransportCacheNamespace() string {
	return d.namespace
}

type testWrapperDialer struct {
	next Dialer
}

func (d *testWrapperDialer) DialContext(context.Context, string, string) (Conn, error) {
	return nil, nil
}

func (d *testWrapperDialer) UnwrapDialer() Dialer {
	return d.next
}

func TestTransportCacheNamespaceUnwrapsDialerChain(t *testing.T) {
	base := &testNamespaceDialer{namespace: "scope-a"}
	wrapped := &testWrapperDialer{next: &testWrapperDialer{next: base}}
	if got := TransportCacheNamespace(wrapped); got != "scope-a" {
		t.Fatalf("TransportCacheNamespace() = %q, want %q", got, "scope-a")
	}
}

func TestTransportCacheNamespaceStopsOnCycle(t *testing.T) {
	first := &testWrapperDialer{}
	second := &testWrapperDialer{next: first}
	first.next = second
	if got := TransportCacheNamespace(first); got != "" {
		t.Fatalf("TransportCacheNamespace() = %q, want empty for cycle", got)
	}
}
