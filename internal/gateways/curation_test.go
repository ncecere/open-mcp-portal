package gateways

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func TestCurationEditsRequireSession(t *testing.T) {
	for _, raw := range []json.RawMessage{[]byte(`{}`), []byte(`null`)} {
		_, err := prepareCurations(context.Background(), nil, authz.Actor{Kind: authz.KindAutomationToken}, []SelectionInput{{CapabilityID: uuid.New(), Curation: raw}}, nil, map[uuid.UUID]string{})
		api, ok := apperr.As(err)
		if !ok || api.Status != 403 || api.Code != "session_required" {
			t.Fatalf("automation curation: %v", err)
		}
	}
}
func TestCurationAvailabilityFailsClosed(t *testing.T) {
	base := "reviewed"
	for _, tc := range []struct {
		name, fp, definition string
		want                 bool
	}{
		{"current", base, `{"inputSchema":{"type":"object","properties":{"owner":{"type":"string"}}}}`, true},
		{"changed", "fresh", `{"inputSchema":{"type":"object","properties":{"owner":{"type":"string"}}}}`, false},
		{"argument missing", base, `{"inputSchema":{"type":"object","properties":{}}}`, false},
		{"unsupported after change", base, `{"inputSchema":{"type":"object","properties":{"owner":{"$ref":"https://untrusted/schema"}}}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			it := Selected{Capability: dbgen.McpCapability{Kind: "tool", Fingerprint: tc.fp, Definition: []byte(tc.definition)}, Available: true, ExposedName: "default"}
			applyCuration(&it, dbgen.GatewayCapability{BaseFingerprint: &base, Constraints: []byte(`{"owner":{"fixed":"org"}}`)})
			if it.Available != tc.want || it.CurationStale == tc.want {
				t.Fatalf("availability: %+v", it)
			}
			if !tc.want && it.Reason != ReasonCurationStale {
				t.Fatal(it.Reason)
			}
		})
	}
}
