package v2ray_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/dialer/v2ray"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	_ "github.com/daeuniverse/outbound/protocol/vmess"
	"github.com/daeuniverse/outbound/transport/httpheader"
)

func TestSubscriptionVMessTCPHTTPNodesBuildDialers(t *testing.T) {
	const id = "00000000-0000-0000-0000-000000000001"
	fieldShapes := []struct {
		name          string
		version, port any
		aid           any
	}{
		{name: "live mixed fields", version: "2", port: "443", aid: 0},
		{name: "legacy string fields", version: "2", port: "443", aid: "0"},
		{name: "numeric fields", version: 2, port: 443, aid: 0},
		{name: "mixed numeric version", version: 2, port: "443", aid: "0"},
	}
	addresses := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"}
	links := make([]string, 0, len(addresses))
	for i, address := range addresses {
		shape := fieldShapes[i]
		config := map[string]any{
			"v":    shape.version,
			"ps":   shape.name,
			"add":  address,
			"port": shape.port,
			"id":   id,
			"aid":  shape.aid,
			"net":  "tcp",
			"type": "http",
			"host": "",
			"path": "/",
			"tls":  "none",
		}
		payload, err := json.Marshal(config)
		if err != nil {
			t.Fatalf("%s: Marshal() error = %v", shape.name, err)
		}
		link := "vmess://" + base64.RawStdEncoding.EncodeToString(payload)
		parsed, err := v2ray.ParseVmessURL(link)
		if err != nil {
			t.Fatalf("%s: ParseVmessURL() error = %v", shape.name, err)
		}
		if parsed.V != "2" || parsed.Port != "443" || parsed.Aid != "0" {
			t.Fatalf("%s: parsed v/port/aid = %q/%q/%q", shape.name, parsed.V, parsed.Port, parsed.Aid)
		}
		links = append(links, link)
	}

	subscription := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
	parsed, err := dialer.ParseSubscription(subscription)
	if err != nil {
		t.Fatalf("ParseSubscription() error = %v", err)
	}
	if len(parsed) != len(links) {
		t.Fatalf("ParseSubscription() returned %d links, want %d", len(parsed), len(links))
	}

	for i, link := range parsed {
		got, property, err := v2ray.NewV2Ray(&dialer.ExtraOption{}, direct.SymmetricDirect, link)
		if err != nil {
			t.Fatalf("node %d: NewV2Ray() error = %v", i+1, err)
		}
		if property.Protocol != "vmess" {
			t.Fatalf("node %d: protocol = %q", i+1, property.Protocol)
		}
		unwrapper, ok := got.(netproxy.DialerUnwrapper)
		if !ok {
			t.Fatalf("node %d: %T does not expose its transport", i+1, got)
		}
		if _, ok := unwrapper.UnwrapDialer().(*httpheader.Dialer); !ok {
			t.Fatalf("node %d: transport = %T, want *httpheader.Dialer", i+1, unwrapper.UnwrapDialer())
		}
	}
}
