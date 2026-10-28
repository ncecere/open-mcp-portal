package httpapi_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestServiceConnectionScopeChallengeNeverEchoesUntrustedValues(t *testing.T) {
	e, _, _, sharedKey, _ := serviceOAuthSetup(t)
	personalKey := newKey(t, e.owner, "personal-challenge").Secret
	// Owned fake credentials only: the resource server reflects the access
	// token it receives and another secret not in response redaction's set.
	refresh := e.as.IssuedRefresh()[0]
	const unreviewed = "unreviewed-scope-sentinel-test-only"
	e.pm.SetProtection(func(p *testutil.Protection) {
		p.WriteScope = unreviewed
		p.Introspect = func(_ context.Context, token string) testutil.Introspection {
			in := e.as.Introspect(token)
			in.Scopes = append(in.Scopes, token, refresh)
			return in
		}
	})
	before := e.scalar(`SELECT count(*)::text FROM provider_connect_requests`)
	for _, principal := range []struct{ name, key string }{{"shared", sharedKey}, {"personal", personalKey}} {
		for _, era := range []string{"legacy", "modern"} {
			t.Run(principal.name+"/"+era, func(t *testing.T) {
				params := map[string]any{"name": "shared-oauth__write", "arguments": map[string]any{}}
				var out map[string]any
				var status int
				if era == "modern" {
					status, _, out = rawModern(t, e.app, "shared-oauth-gw", principal.key, "tools/call", params, nil, nil)
				} else {
					status, _, out = rawMCP(t, e.app, "POST", "shared-oauth-gw", principal.key, rpc(1, "tools/call", params), nil)
				}
				b, _ := json.Marshal(out)
				if status != 200 || !strings.Contains(string(b), `"reason":"insufficient_scope"`) || strings.Contains(string(b), `"scopes"`) {
					t.Fatalf("expected generic scope refusal: %d %s", status, b)
				}
				dump := string(b) + e.logs.String() + e.scalar(`SELECT coalesce(json_agg(a)::text,'') FROM audit_log a`) + e.scalar(`SELECT coalesce(json_agg(c)::text,'') FROM mcp_calls c`)
				for _, secret := range append(append(e.as.Issued(), e.as.IssuedRefresh()...), unreviewed) {
					if strings.Contains(dump, secret) {
						t.Fatal("untrusted challenge scope leaked into response, audit or logs")
					}
				}
			})
		}
	}
	if n := e.scalar(`SELECT count(*)::text FROM provider_connect_requests`); n != before {
		t.Fatal("unreviewed challenge created consent")
	}
	// A normal approved personal step-up still uses configured scopes.
	e.pm.SetProtection(func(p *testutil.Protection) {
		p.WriteScope = "write"
		p.Introspect = func(_ context.Context, token string) testutil.Introspection { return e.as.Introspect(token) }
	})
	code, _, data := rpcErr(e.call(personalKey, "shared-oauth-gw", "shared-oauth__write", nil))
	if code != -32042 || data["elicitations"] == nil {
		t.Fatal("reviewed personal step-up lost consent")
	}
	if n := e.scalar(`SELECT count(*)::text FROM provider_connect_requests WHERE required_scopes @> ARRAY['write']`); n != "1" {
		t.Fatal("reviewed scope was not stored for personal consent")
	}
}
