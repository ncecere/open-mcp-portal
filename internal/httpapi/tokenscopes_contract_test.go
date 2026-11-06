package httpapi

import (
	"context"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// The operations that accept automation tokens are exactly those with
// x-omp-token-scopes (decision 58): the generated allow-table matches the
// spec, every entry is a served route, the scopes are valid and minimal, and
// nothing that reads recorded contents, manages tokens or belongs to a
// person (/v1/me/**, notification management) is annotated.
func TestTokenScopesMatchSpecAndRoutes(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	annotated := map[string][]string{}
	ids := map[string]string{}
	var all []string
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			key := strings.ToUpper(method) + " " + path
			all = append(all, key)
			raw, ok := op.Extensions["x-omp-token-scopes"]
			if !ok {
				continue
			}
			list, _ := raw.([]any)
			for _, v := range list {
				annotated[key] = append(annotated[key], v.(string))
			}
			ids[key] = op.OperationID
		}
	}
	if len(annotated) != 68 {
		t.Errorf("the spec annotates %d operations, the design lists 68", len(annotated))
	}
	served := map[string]bool{}
	for _, r := range apiRoutes(Deps{Config: config.Defaults(), Health: NewHealth(nil), Log: testutil.Logger(), Auth: &auth.Service{}}) {
		served[r.pattern()] = true
	}
	valid := map[string]bool{"platform:read": true, "platform:write": true, "servers:read": true, "servers:write": true}
	for key, scopes := range annotated {
		got, ok := apitypes.TokenOperations[key]
		switch {
		case !ok:
			t.Errorf("%s is annotated in the spec but missing from the generated table: run make generate", key)
			continue
		case !slices.Equal(got.Scopes, scopes) || got.OperationID != ids[key]:
			t.Errorf("%s: table %v/%s, spec %v/%s", key, got.Scopes, got.OperationID, scopes, ids[key])
		}
		if !served[key] {
			t.Errorf("%s accepts tokens but is not served", key)
		}
		for _, s := range scopes {
			if !valid[s] {
				t.Errorf("%s: invalid scope %q", key, s)
			}
			// A write scope is never the only way to a read.
			if strings.HasPrefix(key, "GET ") && strings.HasSuffix(s, ":write") && !strings.HasSuffix(key, "/v1/token") {
				t.Errorf("%s is a read but lists %s", key, s)
			}
		}
		switch {
		case strings.HasSuffix(ids[key], "CallPayload"):
			t.Errorf("%s reads recorded contents and must not accept tokens", key)
		case tokenManagement[key]:
			t.Errorf("%s manages tokens and must be session-only", key)
		case strings.Contains(key, "/v1/me"):
			t.Errorf("%s belongs to a person and must not accept tokens", key)
		case strings.Contains(key, "notification"):
			// the admin reads (platform:read) are the designed exception; nothing writes
			if !strings.HasPrefix(key, "GET /v1/admin/") {
				t.Errorf("%s manages notifications and must not accept tokens", key)
			}
		}
	}
	for key := range apitypes.TokenOperations {
		if _, ok := annotated[key]; !ok {
			t.Errorf("%s is in the generated table but the spec does not annotate it", key)
		}
	}
	// Public key publication is anonymous, never a platform-scoped operation.
	if !served["GET /.well-known/omp-audit-keys.json"] {
		t.Fatal("missing anonymous audit key publication")
	}
	if _, ok := apitypes.TokenOperations["GET /.well-known/omp-audit-keys.json"]; ok {
		t.Fatal("public keys must not require token scopes")
	}
	// Existing audit reads retain platform:read.
	for _, key := range []string{"GET /v1/admin/audit/stream", "GET /v1/admin/audit/stream/tip", "GET /v1/admin/audit/verify"} {
		if !slices.Equal(annotated[key], []string{"platform:read"}) {
			t.Fatalf("audit read scope changed: %s", key)
		}
	}
	// Every token-management operation is a served route and not annotated.
	for key := range tokenManagement {
		if !served[key] {
			t.Errorf("%s is listed as token management but not served", key)
		}
	}
	// The per-scope counts of the design.
	count := map[string]int{}
	for key, scopes := range annotated {
		if key == "GET /v1/token" {
			continue
		}
		count[scopes[0]]++
	}
	want := map[string]int{"platform:read": 44, "platform:write": 11, "servers:read": 5, "servers:write": 7}
	if len(count) != len(want) {
		t.Errorf("scopes in use: %v", count)
	}
	for s, n := range want {
		if count[s] != n {
			t.Errorf("%s: %d operations, the design lists %d", s, count[s], n)
		}
	}
	sort.Strings(all)
	// A route the table names must be a real route on /v1 (never /mcp or /oauth).
	for key := range apitypes.TokenOperations {
		if !strings.Contains(key, " /v1/") {
			t.Errorf("%s: tokens authenticate /v1 only", key)
		}
	}
}
