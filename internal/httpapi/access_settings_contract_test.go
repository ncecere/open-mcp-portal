package httpapi_test

import (
	"encoding/json"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
)

func TestAccessSettingsResponseMatchesOpenAPI(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(gateways.AccessSettings{Enabled: true, StewardIDs: []uuid.UUID{}, Revision: 7})
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	schema := doc.Components.Schemas["GatewayAccessSettings"].Value
	if err := schema.VisitJSON(value); err != nil {
		t.Fatalf("the actual settings response violates its contract: %v", err)
	}
	value.(map[string]any)["revision"] = "not an integer"
	if err := schema.VisitJSON(value); err == nil {
		t.Fatal("settings response contract did not validate revision")
	}
}
