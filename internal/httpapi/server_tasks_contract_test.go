package httpapi_test

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
)

func TestServerTaskDiscoveryContractRemainsOptional(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	server := doc.Components.Schemas["McpServer"].Value
	ref := server.Properties["supportsTasks"]
	if ref == nil || ref.Value == nil {
		t.Fatal("missing task discovery property")
	}
	field := ref.Value
	// A schema default makes openapi-typescript emit a required property even
	// when required[] omits it. Keep old responses valid in both generated
	// languages instead of hiding the mismatch by padding browser fixtures.
	if slices.Contains(server.Required, "supportsTasks") || field.Default != nil || !field.ReadOnly {
		t.Fatal("task discovery must be optional read-only metadata without a schema default")
	}
	for _, value := range []any{true, false} {
		if err := field.VisitJSON(value); err != nil {
			t.Fatalf("valid task discovery boolean rejected: %v", err)
		}
	}
	for _, value := range []any{"true", nil, 1} {
		if err := field.VisitJSON(value); err == nil {
			t.Fatalf("invalid task discovery value accepted: %v", value)
		}
	}
	for _, value := range []*bool{nil, boolPointer(false), boolPointer(true)} {
		raw, err := json.Marshal(apitypes.McpServer{SupportsTasks: value})
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		got, present := body["supportsTasks"]
		if value == nil {
			if present {
				t.Fatal("an absent discovery fact must remain absent, not null/true")
			}
		} else if !present || got != *value {
			t.Fatalf("explicit discovery boolean lost: %v", got)
		}
	}
}

func boolPointer(v bool) *bool { return &v }
