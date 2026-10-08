package graphql

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/daeuniverse/dae-wing/db"
)

// TestLatencySchemaBindsResolvers checks the latency fields and mutations
// resolve through the real schema.
func TestLatencySchemaBindsResolvers(t *testing.T) {
	if err := db.InitDatabase(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	schema, err := Schema()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), "role", "admin")
	const fields = `{ id latencyMs alive testedAt message testing
		ping { ok latencyMs message testedAt pending supported }
		http { ok latencyMs message testedAt pending supported } }`
	for _, q := range []string{
		`query { nodeLatencies(ids: [], cachedOnly: true) ` + fields + ` }`,
		`mutation { testNodeLatencies(ids: []) ` + fields + ` }`,
	} {
		resp := schema.Exec(ctx, q, "", nil)
		if len(resp.Errors) > 0 {
			t.Fatalf("%s: %v", q, resp.Errors)
		}
		var data map[string][]any
		if err := json.Unmarshal(resp.Data, &data); err != nil {
			t.Fatal(err)
		}
	}
	// Unknown subscription/group IDs are reported as errors.
	for _, q := range []string{
		`mutation { testSubscriptionLatencies(id: "MQ==") { id } }`,
		`mutation { testGroupLatencies(id: "MQ==") { id } }`,
	} {
		if resp := schema.Exec(ctx, q, "", nil); len(resp.Errors) == 0 {
			t.Fatalf("%s: expected an error", q)
		}
	}
}
