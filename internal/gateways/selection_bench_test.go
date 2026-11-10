package gateways

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// benchDefinition is a tool definition of a realistic size: about 2 kB, a
// dozen properties with enums, a pattern and a nested object.
func benchDefinition(name string) []byte {
	props := map[string]any{}
	for i := range 12 {
		props[fmt.Sprintf("field_%02d", i)] = map[string]any{"type": "string", "description": "A field the model fills in for this call, described at some length.",
			"enum": []string{"alpha", "beta", "gamma", "delta"}}
	}
	props["id"] = map[string]any{"type": "string", "pattern": "^[a-z0-9-]{1,64}$"}
	props["options"] = map[string]any{"type": "object", "properties": map[string]any{"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 500}}}
	raw, _ := json.Marshal(map[string]any{"name": name, "description": "Looks something up and returns the matching records.",
		"inputSchema": map[string]any{"type": "object", "properties": props, "required": []string{"id"}}})
	return raw
}

// benchRows is a gateway's selection: n tools of one server, every fifth
// curated with a rename, a fixed argument and an allowed list.
func benchRows(n int) []dbgen.ListGatewaySelectionRow {
	server := dbgen.McpServer{ID: uuid.New(), Slug: "status", Enabled: true, PublishState: "published", AuthMode: "none"}
	rows := make([]dbgen.ListGatewaySelectionRow, n)
	for i := range rows {
		name := fmt.Sprintf("tool_%03d", i)
		def := benchDefinition(name)
		fp := upstream.Fingerprint(def)
		c := dbgen.McpCapability{ID: uuid.New(), ServerID: server.ID, Kind: upstream.KindTool, Name: name, Definition: def, Fingerprint: fp, RequirementMode: "inherit"}
		gc := dbgen.GatewayCapability{CapabilityID: c.ID}
		if i%5 == 0 {
			override := "curated_" + name
			gc.NameOverride, gc.BaseFingerprint = &override, &fp
			gc.Constraints = []byte(`{"field_00":{"fixed":"alpha"},"field_01":{"allowed":["alpha","beta"]}}`)
		}
		rows[i] = dbgen.ListGatewaySelectionRow{McpCapability: c, McpServer: server, GatewayCapability: gc, TeamSlug: "tools", TeamName: "Tools", TeamStatus: "active"}
	}
	return rows
}

// BenchmarkSelected is what every tools/list (and the first lookup of a
// tools/call) does with the selection rows it read: availability, curation
// projection and the caller's view of each.
func BenchmarkSelected(b *testing.B) {
	g := dbgen.Gateway{ID: uuid.New(), OwnerKind: OwnerPlatform, Enabled: true}
	rows := benchRows(200)
	caller := Caller{Access: []string{AccessUserGrant}}
	b.ReportAllocs()
	for b.Loop() {
		items, err := selected(context.Background(), nil, g, false, rows)
		if err != nil {
			b.Fatal(err)
		}
		if offers := Evaluate(g, items, caller); len(offers) != len(rows) {
			b.Fatal("offers missing")
		}
	}
}
