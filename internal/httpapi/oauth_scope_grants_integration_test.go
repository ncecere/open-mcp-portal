package httpapi_test

import (
	"context"
	"testing"
)

func TestOAuthToolScopesGatewayGrantIntersection(t *testing.T) {
	e := scopedOAuthEnv(t)
	p := newPKCE()
	client := e.docs.client("/grant-scopes.json", "Scoped grants", testRedirect)
	q := authQuery(e.app, client, "shared", p, map[string]string{"scope": "omp:read"})
	loc := scopeConsent(t, e.member, q, nil, false)
	status, tokens := scopeExchange(t, e, client, codeFrom(t, e.app, "shared read", loc), p)
	if status != 200 {
		t.Fatal(tokens)
	}
	access := tokens["access_token"].(string)
	for _, tc := range []struct {
		raw  string
		want []string
	}{
		{`{"tools":["status__whoami","status__echo"]}`, []string{"status__whoami"}},
		{`{"classes":["write"]}`, nil},
		{`{}`, nil},
		{`null`, []string{"status__whoami"}},
	} {
		if _, err := e.app.Pool.Exec(context.Background(), `UPDATE gateway_grants SET tool_scope=$1::jsonb WHERE id=$2`, tc.raw, e.grant); err != nil {
			t.Fatal(err)
		}
		for _, modern := range []bool{false, true} {
			wantScopedList(t, e.rtEnv, modern, "shared", access, tc.want...)
			wantScopeDenied(t, e.rtEnv, modern, "shared", access, "status__echo")
		}
	}
}
