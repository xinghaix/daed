package node

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae-wing/common"
	"github.com/daeuniverse/dae-wing/db"
	"github.com/graph-gophers/graphql-go"
)

// serveSocks5 is a minimal no-auth SOCKS5 CONNECT proxy for tests. It
// counts proxied connections.
func serveSocks5(t *testing.T) (addr string, proxied func() int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	count := 0
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	handle := func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 262)
		if _, err := io.ReadFull(c, buf[:2]); err != nil {
			return // e.g. the PING probe: connect and close
		}
		if _, err := io.ReadFull(c, buf[:buf[1]]); err != nil {
			return
		}
		_, _ = c.Write([]byte{5, 0})
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return
		}
		var host string
		switch buf[3] {
		case 1:
			_, _ = io.ReadFull(c, buf[:4])
			host = net.IP(buf[:4]).String()
		case 3:
			_, _ = io.ReadFull(c, buf[:1])
			n := int(buf[0])
			_, _ = io.ReadFull(c, buf[:n])
			host = string(buf[:n])
		case 4:
			_, _ = io.ReadFull(c, buf[:16])
			host = net.IP(buf[:16]).String()
		default:
			return
		}
		_, _ = io.ReadFull(c, buf[:2])
		port := binary.BigEndian.Uint16(buf[:2])
		up, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), 2*time.Second)
		if err != nil {
			_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		mu.Lock()
		count++
		mu.Unlock()
		_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
		go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
		<-done
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); handle(c) }()
		}
	}()
	return ln.Addr().String(), func() int { mu.Lock(); defer mu.Unlock(); return count }
}

// TestLatencyEndToEndThroughSocks5 runs the real probe (dae dialer from a
// node link) against a local SOCKS5 node: PING hits the proxy port
// directly, HTTP goes through the proxy to tcp_check_url.
func TestLatencyEndToEndThroughSocks5(t *testing.T) {
	resetLatencyCache(t)
	var status atomic.Int32
	status.Store(http.StatusNoContent)
	check := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(status.Load()))
	}))
	defer check.Close()
	proxyAddr, proxied := serveSocks5(t)

	if err := db.InitDatabase(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	d := db.DB(ctx)
	global := func(path string) string {
		return fmt.Sprintf("global {\n tcp_check_url: '%s%s,127.0.0.1'\n tcp_check_http_method: GET\n}", check.URL, path)
	}
	cfg := db.Config{Global: global("/generate_204"), Selected: true}
	if err := d.Create(&cfg).Error; err != nil {
		t.Fatal(err)
	}
	node := db.Node{Link: "socks5://" + proxyAddr + "#local", Name: "local", Address: proxyAddr, Protocol: "socks5"}
	if err := d.Create(&node).Error; err != nil {
		t.Fatal(err)
	}
	ids := []graphql.ID{common.EncodeCursor(node.ID)}

	results, err := TestLatencies(ctx, &ids)
	if err != nil || len(results) != 1 {
		t.Fatalf("results=%v err=%v", results, err)
	}
	r := results[0]
	if r.PingV == nil || !r.PingV.OkV || r.PingV.LatencyMsV == nil || !r.PingV.SupportedV {
		t.Fatalf("ping: %+v", r.PingV)
	}
	if r.HttpV == nil || !r.HttpV.OkV || r.HttpV.LatencyMsV == nil || r.HttpV.MessageV != nil {
		t.Fatalf("http: %+v (message %v)", r.HttpV, deref(r.HttpV.MessageV))
	}
	if !r.AliveVal || r.LatencyMsV == nil || *r.LatencyMsV != *r.HttpV.LatencyMsV {
		t.Fatalf("legacy fields must mirror HTTP: %+v", r)
	}
	if proxied() != 1 {
		t.Fatalf("HTTP probe must go through the node exactly once, proxied %d", proxied())
	}

	// A failing check URL is reported per method.
	status.Store(http.StatusNotFound)
	results, err = TestLatencies(ctx, &ids)
	if err != nil || len(results) != 1 {
		t.Fatalf("results=%v err=%v", results, err)
	}
	r = results[0]
	if !r.PingV.OkV || r.HttpV.OkV || deref(r.HttpV.MessageV) != "HTTP 404" || r.AliveVal {
		t.Fatalf("want PING ok and HTTP 404: ping=%+v http=%+v msg=%q", r.PingV, r.HttpV, deref(r.HttpV.MessageV))
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
