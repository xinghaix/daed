package tls

import (
	"bytes"
	"strconv"
	"testing"
)

// TestSpiderPathRetainedBoundsTheHarvest pins the memory bound on the harvested
// path set. maxSpiderPaths bounds the entry count but not the entry sizes, and
// an href is harvested from a body read with a 1 MiB limit (reality.go
// io.LimitReader(resp.Body, 1<<20)), so a peer that fails REALITY verification
// could otherwise retain maxSpiderPaths * 1 MiB per serverName for the process
// lifetime -- the spider goroutines and their maps are never torn down. The
// byte budget is what closes that, and it is deliberately loose enough that the
// entry cap still binds first for ordinary paths.
func TestSpiderPathRetainedBoundsTheHarvest(t *testing.T) {
	const shortPath = "/news"
	longPath := bytes.Repeat([]byte("a"), 4096)

	if !spiderPathRetained(map[string]bool{}, 0, []byte(shortPath)) {
		t.Fatal("a short path under both bounds was rejected")
	}
	if spiderPathRetained(map[string]bool{}, 0, []byte("/a.b")) {
		t.Fatal("a path containing a dot was accepted; that rule is pre-existing")
	}

	full := make(map[string]bool, maxSpiderPaths)
	for i := 0; i < maxSpiderPaths; i++ {
		full[strconv.Itoa(i)] = true
	}
	if spiderPathRetained(full, 0, []byte(shortPath)) {
		t.Fatalf("the entry cap (%d) did not bind", maxSpiderPaths)
	}

	if spiderPathRetained(map[string]bool{}, maxSpiderBytes, []byte(shortPath)) {
		t.Fatalf("the byte budget (%d) did not bind", maxSpiderBytes)
	}
	if spiderPathRetained(map[string]bool{}, maxSpiderBytes-len(longPath)+1, longPath) {
		t.Fatal("an href that would push the retained bytes over the budget was accepted")
	}
	if !spiderPathRetained(map[string]bool{}, maxSpiderBytes-len(longPath), longPath) {
		t.Fatal("an href that exactly fits the budget was rejected")
	}

	// The budget must not shorten a realistic harvest: the entry cap stays the
	// binding constraint until paths average 256 bytes.
	if maxSpiderBytes < maxSpiderPaths*256 {
		t.Fatalf("byte budget %d is below %d entries x 256 B; it would bind before the entry cap for ordinary paths",
			maxSpiderBytes, maxSpiderPaths)
	}
}
