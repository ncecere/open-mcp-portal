package mcpgw

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// BenchmarkListed renders the tools of a 200-tool gateway for tools/list:
// each stored definition with its exposed name and class annotations.
func BenchmarkListed(b *testing.B) {
	props := map[string]any{}
	for i := range 12 {
		props[fmt.Sprintf("field_%02d", i)] = map[string]any{"type": "string", "description": "A field the model fills in for this call, described at some length.",
			"enum": []string{"alpha", "beta", "gamma", "delta"}}
	}
	class := "read"
	offers := make([]gateways.Offer, 200)
	for i := range offers {
		name := fmt.Sprintf("tool_%03d", i)
		def, _ := json.Marshal(map[string]any{"name": name, "description": "Looks something up and returns the matching records.",
			"inputSchema": map[string]any{"type": "object", "properties": props}, "outputSchema": map[string]any{"type": "object"}})
		offers[i] = gateways.Offer{Allowed: true, Selected: gateways.Selected{ExposedName: "status__" + name, EffectiveDefinition: def,
			Capability: dbgen.McpCapability{Kind: upstream.KindTool, Name: name, Definition: def, ToolClass: &class}}}
	}
	for _, modern := range []bool{false, true} {
		b.Run(fmt.Sprintf("modern=%t", modern), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				for _, o := range offers {
					if _, err := listedFor(o, modern); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
