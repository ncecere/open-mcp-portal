package mcpgw

import (
	"encoding/json"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func TestListedToolClassOverridesHintsOnly(t *testing.T) {
	for _, modern := range []bool{false, true} {
		for _, class := range []string{"", "read", "write", "destructive"} {
			raw := []byte(`{"name":"original","annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":true,"title":"Keep"},"inputSchema":{"type":"object"}}`)
			c := dbgen.McpCapability{Kind: "tool", Definition: raw}
			if class != "" {
				c.ToolClass = &class
			}
			offer := gateways.Offer{Selected: gateways.Selected{Capability: c, ExposedName: "server__original"}}
			before := string(c.Definition)
			got, err := listedFor(offer, modern)
			if err != nil {
				t.Fatal(err)
			}
			var def struct {
				Name        string
				Annotations map[string]any
			}
			if err := json.Unmarshal(got, &def); err != nil {
				t.Fatal(err)
			}
			read, destructive := class == "read", class == "" || class == "destructive"
			if def.Name != "server__original" || def.Annotations["readOnlyHint"] != read || def.Annotations["destructiveHint"] != destructive || def.Annotations["idempotentHint"] != true || def.Annotations["title"] != "Keep" {
				t.Fatalf("class %s: %s", class, got)
			}
			if string(c.Definition) != before {
				t.Fatal("stored definition mutated")
			}
		}
	}
}

func TestListedUnclassifiedAndNonToolsUnchanged(t *testing.T) {
	for _, kind := range []string{"tool", "prompt", "resource", "resource_template"} {
		c := dbgen.McpCapability{Kind: kind, Definition: []byte(`{"name":"original"}`)}
		got, err := listed(gateways.Offer{Selected: gateways.Selected{Capability: c, ExposedName: "s__original"}})
		if err != nil {
			t.Fatal(err)
		}
		var def map[string]any
		if err := json.Unmarshal(got, &def); err != nil {
			t.Fatal(err)
		}
		if _, ok := def["annotations"]; ok {
			t.Fatalf("unclassified/non-tool got annotations: %s", got)
		}
	}
}
