package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
)

func scopedOAuthEnv(t *testing.T) *oauthEnv {
	t.Helper()
	e := newOAuthEnv(t)
	for name, class := range map[string]string{"whoami": "read", "echo": "write"} {
		if _, err := e.app.Pool.Exec(context.Background(), `UPDATE mcp_capabilities SET tool_class=$1 WHERE server_id=$2 AND name=$3 AND kind='tool'`, class, e.server.Id, name); err != nil {
			t.Fatal(err)
		}
	}
	ids := []string{}
	for _, name := range []string{"whoami", "echo", "check_outage"} {
		ids = append(ids, e.capID(e.owner, e.server, "tool", name))
	}
	e.mustSetCaps(e.owner, e.supportTeamPath, sel(ids...))
	e.mustSetCaps(e.admin, e.shared, sel(ids...))
	return e
}

func scopeConsent(t *testing.T, s *session, q url.Values, scope any, present bool) string {
	t.Helper()
	body := map[string]any{"query": q.Encode(), "decision": "allow"}
	if present {
		body["toolScope"] = scope
	}
	var out struct {
		RedirectURL string `json:"redirectUrl"`
	}
	code, ec := s.call("POST", "/v1/oauth/consent", body, &out, nil)
	mustCode(t, "scope consent", code, ec, 200, "")
	return out.RedirectURL
}
func scopeExchange(t *testing.T, e *oauthEnv, client, code string, p pkce) (int, map[string]any) {
	t.Helper()
	status, out, _ := tokenCall(t, e.app, "/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "code": {code}, "code_verifier": {p.verifier}, "redirect_uri": {testRedirect}})
	return status, out
}
func wantTokenScope(t *testing.T, out map[string]any, want string, present bool) {
	t.Helper()
	got, ok := out["scope"]
	if ok != present || present && got != want {
		t.Fatalf("token scope=%v (present %v), want %q %v; %v", got, ok, want, present, out)
	}
	if out["access_token"] == nil || out["refresh_token"] == nil {
		t.Fatalf("no tokens: %v", out)
	}
}

func TestOAuthToolScopesConsentAndUnrestricted(t *testing.T) {
	e := scopedOAuthEnv(t)
	p := newPKCE()
	client := e.docs.client("/scope.json", "Scoped", testRedirect)
	// Invalid scopes must never bypass safe redirect validation.
	q := authQuery(e.app, client, "support", p, map[string]string{"scope": "bad", "redirect_uri": "https://evil.example/cb"})
	res, body := authorize(t, e.app, e.member, q)
	wantPage(t, "bad redirect first", res, body, "invalid_request")
	q.Set("redirect_uri", testRedirect)
	res, _ = authorize(t, e.app, e.member, q)
	wantRedirectError(t, e.app, "invalid scope", res, "invalid_scope")
	q.Del("scope")
	var view apitypes.OAuthConsent
	code, ec := e.member.call("GET", "/v1/oauth/consent?"+q.Encode(), nil, &view, nil)
	mustCode(t, "unrestricted consent view", code, ec, 200, "")
	if view.RequestedToolScope != nil {
		t.Fatalf("missing scope not unrestricted: %+v", view)
	}
	loc := scopeConsent(t, e.member, q, nil, false)
	status, unrestricted := scopeExchange(t, e, client, codeFrom(t, e.app, "unrestricted", loc), p)
	if status != 200 {
		t.Fatal(unrestricted)
	}
	wantTokenScope(t, unrestricted, "", false)
	wantScopedList(t, e.rtEnv, false, "support", unrestricted["access_token"].(string), "status__check_outage", "status__echo", "status__whoami")
	// Explicit all-three is restricted and therefore excludes unclassified tools.
	q.Set("scope", "omp:destructive omp:write omp:read")
	code, ec = e.member.call("GET", "/v1/oauth/consent?"+q.Encode(), nil, &view, nil)
	mustCode(t, "three-class view", code, ec, 200, "")
	if view.RequestedToolScope == nil || view.RequestedToolScope.Classes == nil || len(*view.RequestedToolScope.Classes) != 3 {
		t.Fatalf("requested view=%+v", view)
	}
	loc = scopeConsent(t, e.member, q, nil, false)
	status, all := scopeExchange(t, e, client, codeFrom(t, e.app, "three classes", loc), p)
	if status != 200 {
		t.Fatal(all)
	}
	wantTokenScope(t, all, "omp:read omp:write omp:destructive", true)
	wantScopedList(t, e.rtEnv, true, "support", all["access_token"].(string), "status__echo", "status__whoami")
	wantScopeDenied(t, e.rtEnv, true, "support", all["access_token"].(string), "status__check_outage")
	if c, _, _ := rawMCP(t, e.app, "POST", "support", unrestricted["access_token"].(string), rpc(1, "tools/list", nil), nil); c != 401 {
		t.Fatalf("old token survived replacement: %d", c)
	}
	// A restricted request may be narrowed to deny-all but not widened or named.
	q.Set("scope", "omp:read")
	for _, scope := range []any{nil, classScope("write"), nameScope("status__whoami"), classScope("bogus")} {
		c, ec := e.member.call("POST", "/v1/oauth/consent", map[string]any{"query": q.Encode(), "decision": "allow", "toolScope": scope}, nil, nil)
		mustCode(t, "invalid consent scope", c, ec, 400, "oauth_invalid_scope")
	}
	loc = scopeConsent(t, e.member, q, map[string]any{}, true)
	status, deny := scopeExchange(t, e, client, codeFrom(t, e.app, "deny all", loc), p)
	if status != 200 {
		t.Fatal(deny)
	}
	wantTokenScope(t, deny, "", true)
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {deny["refresh_token"].(string)}, "scope": {""}}
	for range 2 {
		c, renewed, _ := tokenCall(t, e.app, "/oauth/token", form)
		if c != 200 {
			t.Fatal(renewed)
		}
		wantTokenScope(t, renewed, "", true)
	}
	wantScopedList(t, e.rtEnv, false, "support", deny["access_token"].(string))
	var grants []apitypes.OAuthGrant
	if c := e.member.get("/v1/me/oauth-grants", &grants); c != 200 || len(grants) != 1 || grants[0].ToolScope == nil {
		t.Fatalf("grant view=%d %+v", c, grants)
	}
	if got := e.scalar(`SELECT (after_state->'toolScope')::text FROM audit_log WHERE action='oauth.consent' ORDER BY id DESC LIMIT 1`); got != "{}" {
		t.Fatalf("audit scope=%s", got)
	}
	// Omitted consent scope defaults to the query's requested read ceiling.
	res, _ = authorize(t, e.app, e.member, q)
	if !strings.HasPrefix(res.Header.Get("Location"), "/oauth/consent?") {
		t.Fatal("remembered deny-all silently expanded")
	}
	loc = scopeConsent(t, e.member, q, nil, false)
	status, read := scopeExchange(t, e, client, codeFrom(t, e.app, "read", loc), p)
	if status != 200 {
		t.Fatal(read)
	}
	wantTokenScope(t, read, "omp:read", true)
	// Explicit null is permitted for an unrestricted request (and only then).
	q.Del("scope")
	loc = scopeConsent(t, e.member, q, nil, true)
	status, again := scopeExchange(t, e, client, codeFrom(t, e.app, "clear", loc), p)
	if status != 200 {
		t.Fatal(again)
	}
	wantTokenScope(t, again, "", false)
	// An explicitly empty protocol scope is deny-all, not a missing parameter.
	q.Set("scope", "")
	loc = scopeConsent(t, e.member, q, nil, false)
	status, empty := scopeExchange(t, e, client, codeFrom(t, e.app, "empty scope", loc), p)
	if status != 200 {
		t.Fatal(empty)
	}
	wantTokenScope(t, empty, "", true)
}

func TestOAuthToolScopesTrustedExpansionAndRefresh(t *testing.T) {
	e := scopedOAuthEnv(t)
	client := e.docs.client("/trusted-scopes.json", "Trusted", testRedirect)
	trustClients(t, e, client)
	p := newPKCE()
	q := authQuery(e.app, client, "support", p, nil)
	res, _ := authorize(t, e.app, e.member, q)
	if !strings.HasPrefix(res.Header.Get("Location"), "/oauth/consent?") {
		t.Fatal("first trusted loopback notice disappeared")
	}
	// The human narrows an unrestricted request; future trusted requests do not
	// restore the broader request silently.
	loc := scopeConsent(t, e.member, q, classScope("read"), true)
	status, tokens := scopeExchange(t, e, client, codeFrom(t, e.app, "trusted narrowed", loc), p)
	if status != 200 {
		t.Fatal(tokens)
	}
	wantTokenScope(t, tokens, "omp:read", true)
	res, _ = authorize(t, e.app, e.member, q)
	if !strings.HasPrefix(res.Header.Get("Location"), "/oauth/consent?") {
		t.Fatal("trusted remembered expansion was silent")
	}
	// Same-scope reauthorization is silent and preserves existing tokens/codes.
	q.Set("scope", "omp:read")
	res, _ = authorize(t, e.app, e.member, q)
	pending := codeFrom(t, e.app, "trusted same scope", res.Header.Get("Location"))
	wantScopedList(t, e.rtEnv, false, "support", tokens["access_token"].(string), "status__whoami")
	status, same := scopeExchange(t, e, client, pending, p)
	if status != 200 {
		t.Fatal(same)
	}
	wantTokenScope(t, same, "omp:read", true)
	refresh := tokens["refresh_token"].(string)
	// Different scope (even narrower deny-all) is rejected without rotating.
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {refresh}, "scope": {"omp:write"}}
	for _, s := range []string{"omp:write", "", "omp:read omp:write", "bad"} {
		form.Set("scope", s)
		c, out, _ := tokenCall(t, e.app, "/oauth/token", form)
		wantOAuthError(t, "changed refresh scope", c, out, 400, "invalid_scope")
	}
	form["scope"] = []string{"omp:read", "omp:write"}
	repeatedStatus, repeated, _ := tokenCall(t, e.app, "/oauth/token", form)
	wantOAuthError(t, "repeated refresh scope", repeatedStatus, repeated, 400, "invalid_request")
	form.Set("scope", "omp:read")
	c, rotated, _ := tokenCall(t, e.app, "/oauth/token", form)
	if c != 200 {
		t.Fatal(rotated)
	}
	wantTokenScope(t, rotated, "omp:read", true)
	form.Del("scope")
	c, repeat, _ := tokenCall(t, e.app, "/oauth/token", form)
	if c != 200 {
		t.Fatal(repeat)
	}
	wantTokenScope(t, repeat, "omp:read", true)
	if rotated["access_token"] != repeat["access_token"] || rotated["refresh_token"] != repeat["refresh_token"] {
		t.Fatal("grace repeat minted a different pair")
	}
	wantScopedList(t, e.rtEnv, true, "support", repeat["access_token"].(string), "status__whoami")
	// Expansion to unrestricted replaces the immutable grant and invalidates all
	// old access/refresh tokens, including the pair inside repeat grace.
	q.Del("scope")
	loc = scopeConsent(t, e.member, q, nil, false)
	for _, access := range []string{tokens["access_token"].(string), rotated["access_token"].(string)} {
		if c, _, _ := rawMCP(t, e.app, "POST", "support", access, rpc(1, "tools/list", nil), nil); c != 401 {
			t.Fatal("old access token survived expansion")
		}
	}
	form.Set("refresh_token", refresh)
	c, out, _ := tokenCall(t, e.app, "/oauth/token", form)
	wantOAuthError(t, "old grace refresh after replacement", c, out, 400, "invalid_grant")
	status, unrestricted := scopeExchange(t, e, client, codeFrom(t, e.app, "trusted expansion", loc), p)
	if status != 200 {
		t.Fatal(unrestricted)
	}
	wantTokenScope(t, unrestricted, "", false)
	form.Set("refresh_token", unrestricted["refresh_token"].(string))
	c, renewed, _ := tokenCall(t, e.app, "/oauth/token", form)
	if c != 200 {
		t.Fatal(renewed)
	}
	wantTokenScope(t, renewed, "", false)
	// Both metadata documents advertise exactly the three class strings.
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource/mcp/support"} {
		_, _, raw := getRaw(t, e.app.URL+path)
		var doc struct {
			Scopes []string `json:"scopes_supported"`
		}
		_ = json.Unmarshal(raw, &doc)
		if !slices.Equal(doc.Scopes, []string{"omp:read", "omp:write", "omp:destructive"}) {
			t.Fatalf("metadata %s=%s", path, raw)
		}
	}
}

func TestOAuthToolScopesConcurrentReplacementInvalidatesOldCodes(t *testing.T) {
	e := scopedOAuthEnv(t)
	client := e.docs.client("/concurrent-scopes.json", "Concurrent", testRedirect)
	p := newPKCE()
	q := authQuery(e.app, client, "support", p, nil)
	first := scopeConsent(t, e.member, q, classScope("read"), true)
	status, old := scopeExchange(t, e, client, codeFrom(t, e.app, "first", first), p)
	if status != 200 {
		t.Fatal(old)
	}
	oldPending := codeFrom(t, e.app, "old pending", scopeConsent(t, e.member, q, classScope("read"), true))
	type result struct {
		status int
		raw    []byte
		scope  string
	}
	ch := make(chan result, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, scope := range []string{"write", "destructive"} {
		wg.Add(1)
		go func(scope string) {
			defer wg.Done()
			<-start
			code, raw := e.member.raw("POST", "/v1/oauth/consent", map[string]any{"query": q.Encode(), "decision": "allow", "toolScope": classScope(scope)}, nil)
			ch <- result{code, raw, scope}
		}(scope)
	}
	close(start)
	wg.Wait()
	close(ch)
	if c, out := scopeExchange(t, e, client, oldPending, p); c != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("old pending code survived: %d %v", c, out)
	}
	activeScope := e.scalar(`SELECT tool_scope::text FROM oauth_grants WHERE revoked_at IS NULL AND client_id=$1`, client)
	successes := 0
	for r := range ch {
		if r.status != 200 {
			t.Fatalf("concurrent consent=%d %s", r.status, r.raw)
		}
		var body struct {
			Data struct {
				RedirectURL string `json:"redirectUrl"`
			}
		}
		_ = json.Unmarshal(r.raw, &body)
		code := codeFrom(t, e.app, "concurrent", body.Data.RedirectURL)
		status, out := scopeExchange(t, e, client, code, p)
		if status == 200 {
			successes++
			wantTokenScope(t, out, "omp:"+r.scope, true)
			if !strings.Contains(activeScope, r.scope) {
				t.Fatalf("code widened/rebound to another grant: %s %v", activeScope, out)
			}
		} else if status != http.StatusBadRequest || out["error"] != "invalid_grant" {
			t.Fatalf("replaced code=%d %v", status, out)
		}
	}
	if successes != 1 {
		t.Fatalf("%d surviving codes, want final immutable grant only", successes)
	}
	if c, _, _ := rawMCP(t, e.app, "POST", "support", old["access_token"].(string), rpc(1, "tools/list", nil), nil); c != 401 {
		t.Fatal("old access survived concurrent replacement")
	}
	if n := e.scalar(`SELECT count(*)::text FROM oauth_grants WHERE revoked_at IS NULL AND client_id=$1`, client); n != "1" {
		t.Fatalf("%s active grants", n)
	}
}
