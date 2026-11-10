package httpapi_test

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// OAuth sign-in for MCP clients (docs/phase4-client-auth.md,
// docs/connect-clients.md), end to end with a fake public client whose
// Client ID Metadata Documents a local TLS server serves.

func TestOAuthDiscovery(t *testing.T) {
	app := newTestApp(t, nil)
	base := app.URL
	code, hdr, raw := getRaw(t, base+"/.well-known/oauth-protected-resource/mcp/support")
	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		BearerMethods        []string `json:"bearer_methods_supported"`
	}
	if code != 200 || json.Unmarshal(raw, &prm) != nil || prm.Resource != base+"/mcp/support" || len(prm.AuthorizationServers) != 1 ||
		prm.AuthorizationServers[0] != base || strings.Join(prm.BearerMethods, ",") != "header" || !strings.Contains(hdr.Get("Cache-Control"), "max-age") {
		t.Fatalf("protected resource metadata = %d %s", code, raw)
	}
	// Served for any slug, so it doesn't say which gateways exist; not for junk.
	if code, _, _ := getRaw(t, base+"/.well-known/oauth-protected-resource/mcp/no-such-gateway"); code != 200 {
		t.Errorf("unknown slug = %d", code)
	}
	if code, _, _ := getRaw(t, base+"/.well-known/oauth-protected-resource/mcp/Bad_Slug"); code != 404 {
		t.Errorf("invalid slug = %d", code)
	}
	code, _, raw = getRaw(t, base+"/.well-known/oauth-authorization-server")
	var asm map[string]any
	if code != 200 || json.Unmarshal(raw, &asm) != nil {
		t.Fatalf("server metadata = %d %s", code, raw)
	}
	for k, want := range map[string]any{
		"issuer": base, "authorization_endpoint": base + "/oauth/authorize", "token_endpoint": base + "/oauth/token",
		"registration_endpoint": base + "/oauth/register", "revocation_endpoint": base + "/oauth/revoke",
		"authorization_response_iss_parameter_supported": true, "client_id_metadata_document_supported": true,
	} {
		if asm[k] != want {
			t.Errorf("%s = %v, want %v", k, asm[k], want)
		}
	}
	for k, want := range map[string]string{
		"code_challenge_methods_supported": `["S256"]`, "token_endpoint_auth_methods_supported": `["none"]`,
		"response_types_supported": `["code"]`, "grant_types_supported": `["authorization_code","refresh_token"]`,
	} {
		if b, _ := json.Marshal(asm[k]); string(b) != want {
			t.Errorf("%s = %s, want %s", k, b, want)
		}
	}
	// /mcp/{slug} without a credential names that metadata (RFC 9728 §5.1).
	code, hdr, _ = rawMCP(t, app, "POST", "support", "", rpc(1, "tools/list", nil), nil)
	if code != 401 || hdr.Get("WWW-Authenticate") != `Bearer resource_metadata="`+base+`/.well-known/oauth-protected-resource/mcp/support"` {
		t.Errorf("challenge = %d %q", code, hdr.Get("WWW-Authenticate"))
	}
	// POST-only endpoints answer GET with 405, never the web app; other
	// well-known documents are JSON 404s.
	for _, p := range []string{"/oauth/token", "/oauth/revoke", "/oauth/register"} {
		if code, h, _ := getRaw(t, base+p); code != 405 || h.Get("Allow") != "POST" {
			t.Errorf("GET %s = %d", p, code)
		}
	}
	if code, h, _ := getRaw(t, base+"/.well-known/openid-configuration"); code != 404 || !strings.HasPrefix(h.Get("Content-Type"), "application/json") {
		t.Errorf("openid-configuration = %d %s", code, h.Get("Content-Type"))
	}
	// The consent page is the web app's.
	if code, h, _ := getRaw(t, base+"/oauth/consent?client_id=x"); code != 200 || !strings.HasPrefix(h.Get("Content-Type"), "text/html") {
		t.Errorf("consent page = %d %s", code, h.Get("Content-Type"))
	}
}

func TestOAuthAuthorizeValidation(t *testing.T) {
	e := newOAuthEnv(t)
	app := e.app
	clientID := e.docs.client("/assistant.json", "Test Assistant", testRedirect)
	p := newPKCE()
	ok := func(over map[string]string) url.Values { return authQuery(app, clientID, "support", p, over) }

	// Until the client and its redirect URI are known to be good: a page.
	res, body := authorize(t, app, e.member, ok(map[string]string{"client_id": "https://unknown.invalid/client.json"}))
	wantPage(t, "unfetchable client", res, body, "invalid_client")
	res, body = authorize(t, app, e.member, ok(map[string]string{"client_id": "not-a-client"}))
	wantPage(t, "unknown client", res, body, "invalid_client")
	res, body = authorize(t, app, e.member, ok(map[string]string{"redirect_uri": "https://evil.example/callback"}))
	wantPage(t, "foreign redirect", res, body, "invalid_request")
	res, body = authorize(t, app, e.member, ok(map[string]string{"redirect_uri": ""}))
	wantPage(t, "no redirect", res, body, "invalid_request")
	q := ok(nil)
	q.Add("state", "again")
	res, body = authorize(t, app, e.member, q)
	wantPage(t, "repeated parameter", res, body, "invalid_request")
	res, body = authorize(t, app, e.member, ok(map[string]string{"state": strings.Repeat("s", 1001)}))
	wantPage(t, "long state", res, body, "invalid_request")

	// Afterwards: back to the client, with state and iss.
	res, _ = authorize(t, app, e.member, ok(map[string]string{"code_challenge_method": "plain", "code_challenge": p.verifier}))
	wantRedirectError(t, app, "PKCE plain", res, "invalid_request")
	res, _ = authorize(t, app, e.member, ok(map[string]string{"code_challenge": "", "code_challenge_method": ""}))
	wantRedirectError(t, app, "no PKCE", res, "invalid_request")
	res, _ = authorize(t, app, e.member, ok(map[string]string{"response_type": "token"}))
	wantRedirectError(t, app, "implicit", res, "unsupported_response_type")
	for _, r := range []string{"", app.URL + "/mcp", app.URL + "/mcp/support/", "https://elsewhere.example/mcp/support", app.URL + "/mcp/Support"} {
		res, _ = authorize(t, app, e.member, ok(map[string]string{"resource": r}))
		wantRedirectError(t, app, "resource "+r, res, "invalid_target")
	}

	// Signed out: sign in first (the development sign-in page, which comes
	// back to the authorization request), whatever the gateway.
	for _, slug := range []string{"support", "no-such-gateway"} {
		q := authQuery(app, clientID, slug, p, nil)
		res, _ = authorize(t, app, nil, q)
		if loc := res.Header.Get("Location"); res.StatusCode != 302 || loc != "/?next="+url.QueryEscape("/oauth/authorize?"+q.Encode()) {
			t.Errorf("signed-out authorize %s = %d %q", slug, res.StatusCode, loc)
		}
	}

	// Signed in: the resource must be a gateway they can use now.
	for _, slug := range []string{"no-such-gateway", "shared"} {
		res, _ = authorize(t, app, e.owner, authQuery(app, clientID, slug, p, nil)) // the owner isn't granted "shared"
		wantRedirectError(t, app, "gateway "+slug, res, "invalid_target")
	}
	code, ec := e.owner.call("GET", "/v1/oauth/consent?"+authQuery(app, clientID, "shared", p, nil).Encode(), nil, nil, nil)
	mustCode(t, "consent for a gateway without access", code, ec, 404, "gateway_not_found")
	code, ec = e.owner.call("GET", "/v1/oauth/consent?"+ok(map[string]string{"code_challenge_method": "plain"}).Encode(), nil, nil, nil)
	mustCode(t, "consent for an invalid request", code, ec, 400, "oauth_invalid_request")
	code, ec = e.owner.call("GET", "/v1/oauth/consent?"+ok(map[string]string{"client_id": "nope"}).Encode(), nil, nil, nil)
	mustCode(t, "consent for an unknown client", code, ec, 400, "oauth_invalid_client")
	code, _ = e.app.do("GET", "/v1/oauth/consent?"+ok(nil).Encode(), nil, nil)
	if code != 401 {
		t.Errorf("consent signed out = %d", code)
	}
	code, ec = e.owner.call("PATCH", e.supportTeamPath, map[string]any{"enabled": false}, nil, ifMatch(e.gateway(e.owner, e.supportTeamPath).Revision))
	mustCode(t, "disable", code, ec, 200, "")
	res, _ = authorize(t, app, e.member, ok(nil))
	wantRedirectError(t, app, "disabled gateway", res, "invalid_target")
	// A suspended person gets a page.
	id := e.userID("blair@localhost")
	if _, err := app.Pool.Exec(context.Background(), `UPDATE users SET status = 'suspended' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	res, body = authorize(t, app, e.member, authQuery(app, clientID, "shared", p, nil))
	if res.StatusCode != 400 || !strings.Contains(body, "access_denied") || res.Header.Get("Location") != "" {
		t.Errorf("suspended = %d %s", res.StatusCode, body)
	}
}

func TestOAuthFlowWithMetadataDocument(t *testing.T) {
	e := newOAuthEnv(t)
	app := e.app
	jwks := app.URL + "/.well-known/jwks.json"
	e.fake.SetJWKS(jwks, e.fake.URL())
	clientID := e.docs.client("/assistant.json", "Test Assistant", testRedirect)

	// Signed in: the endpoint sends the browser to the consent page with
	// the same request.
	p := newPKCE()
	q := authQuery(app, clientID, "support", p, nil)
	res, _ := authorize(t, app, e.member, q)
	if loc := res.Header.Get("Location"); res.StatusCode != 302 || loc != "/oauth/consent?"+q.Encode() {
		t.Fatalf("authorize = %d %q", res.StatusCode, loc)
	}
	var view apitypes.OAuthConsent
	if code := e.member.get("/v1/oauth/consent?"+q.Encode(), &view); code != 200 || view.Client.Name != "Test Assistant" ||
		view.Client.Kind != "metadata" || view.Client.Host != strings.TrimPrefix(e.docs.URL, "https://") || view.Client.Trusted ||
		view.Client.Uri == nil || *view.Client.Uri != "https://assistant.example.com" || view.RedirectHost != "127.0.0.1:4567" ||
		view.Remembered || view.Gateway.Slug != "support" || view.Gateway.Url != app.URL+"/mcp/support" {
		t.Fatalf("consent view = %d %+v", code, view)
	}
	// The decision needs the app's CSRF token.
	noCSRF := &session{t: t, app: app, client: e.member.client}
	if code, ec := noCSRF.call("POST", "/v1/oauth/consent", map[string]any{"query": q.Encode(), "decision": "allow"}, nil, nil); code != 403 || ec != "csrf_failed" {
		t.Fatalf("consent without CSRF = %d %s", code, ec)
	}
	// Deny: access_denied back to the client, nothing remembered.
	loc, _ := url.Parse(consent(t, e.member, q, "deny"))
	if loc.Query().Get("error") != "access_denied" || loc.Query().Get("state") != "st-1" || loc.Query().Get("iss") != app.URL || loc.Query().Get("code") != "" {
		t.Fatalf("deny = %s", loc)
	}
	if n := e.scalar(`SELECT count(*)::text FROM oauth_grants`); n != "0" {
		t.Fatalf("grants after deny = %s", n)
	}
	// Allow.
	code := codeFrom(t, app, "allow", consent(t, e.member, q, "allow"))
	// A wrong verifier fails, and uses the code up.
	bad := newPKCE()
	status, out, _ := tokenCall(t, app, "/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code},
		"code_verifier": {bad.verifier}, "redirect_uri": {testRedirect}})
	wantOAuthError(t, "wrong verifier", status, out, 400, "invalid_grant")
	status, out, _ = tokenCall(t, app, "/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code},
		"code_verifier": {p.verifier}, "redirect_uri": {testRedirect}})
	wantOAuthError(t, "code used twice", status, out, 400, "invalid_grant")

	// Remembered: straight back with a code, on another loopback port.
	p2 := newPKCE()
	q2 := authQuery(app, clientID, "support", p2, map[string]string{"redirect_uri": "http://127.0.0.1:5555/callback", "state": "st-2"})
	res, _ = authorize(t, app, e.member, q2)
	loc, _ = url.Parse(res.Header.Get("Location"))
	if res.StatusCode != 302 || loc.Host != "127.0.0.1:5555" || loc.Query().Get("state") != "st-2" || loc.Query().Get("code") == "" {
		t.Fatalf("remembered authorize = %d %s", res.StatusCode, loc)
	}
	if code := e.member.get("/v1/oauth/consent?"+q2.Encode(), &view); code != 200 || !view.Remembered {
		t.Errorf("remembered view = %+v", view)
	}
	// The resource, when sent, must be the code's.
	status, out, _ = tokenCall(t, app, "/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID},
		"code": {loc.Query().Get("code")}, "code_verifier": {p2.verifier}, "redirect_uri": {"http://127.0.0.1:5555/callback"},
		"resource": {app.URL + "/mcp/shared"}})
	wantOAuthError(t, "other resource", status, out, 400, "invalid_target")
	res, _ = authorize(t, app, e.member, q2)
	loc, _ = url.Parse(res.Header.Get("Location"))
	status, out, _ = tokenCall(t, app, "/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID},
		"code": {loc.Query().Get("code")}, "code_verifier": {p2.verifier}, "redirect_uri": {"http://127.0.0.1:5555/callback"},
		"resource": {app.URL + "/mcp/support"}})
	access, _ := out["access_token"].(string)
	refresh, _ := out["refresh_token"].(string)
	if status != 200 || !strings.HasPrefix(access, "ompat_") || !strings.HasPrefix(refresh, "omprt_") {
		t.Fatalf("exchange = %d %v", status, out)
	}
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'oauth.consent' AND metadata->>'how' = 'allowed'`); n != "1" {
		t.Errorf("oauth.consent entries = %s, want 1 (remembered afterwards)", n)
	}
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'oauth.token_issue' AND metadata->>'grantType' = 'authorization_code'
		AND metadata->>'client' = 'Test Assistant' AND actor_kind = 'user'`); n != "1" {
		t.Errorf("oauth.token_issue entries = %s", n)
	}

	// Retired identity input is refused even on a valid ordinary OAuth token,
	// before either era can run as that person or start upstream processing.
	for _, era := range []string{"2025-11-25", "2026-07-28"} {
		before := e.fake.Requests()
		status, _, out := rawMCP(t, app, "POST", "support", access, rpc(1, "tools/call", toolCall("status__whoami", nil)),
			map[string]string{"MCP-Gateway-Identity": "retired-oauth-identity-sentinel", "MCP-Protocol-Version": era})
		if status != 403 || e.fake.Requests() != before {
			t.Fatalf("retired OAuth identity input: %d %v", status, out)
		}
	}

	// The token signs in to its gateway: the identity names the person and the client.
	cs := connect(t, app, "support", access)
	if got := toolNames(t, cs); strings.Join(got, ",") != "status__whoami" {
		t.Fatalf("tools = %v", got)
	}
	r, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "status__whoami"})
	if err != nil || r.IsError {
		t.Fatalf("whoami: %v %+v", err, r)
	}
	var who testutil.WhoamiResult
	_ = json.Unmarshal([]byte(resultText(t, r)), &who)
	c := who.Claims
	if !who.Verified || c["principal_type"] != "user" || c["sub"] != e.userID("blair@localhost") || c["email"] != "blair@localhost" ||
		c["client"] != "Test Assistant" || c["client_verified"] != true || c["gateway"] != "support" {
		t.Fatalf("whoami = %+v", who)
	}
	for _, h := range e.fake.ToolCalls()[0].Header {
		for _, v := range h {
			if strings.Contains(v, access) {
				t.Fatal("the access token reached the server")
			}
		}
	}
	var page apitypes.McpCallPage
	if code := e.owner.get(toolsTeam+"/calls?limit=1", &page); code != 200 || len(page.Items) != 1 {
		t.Fatalf("calls = %d %+v", code, page)
	}
	pr := page.Items[0].Principal
	if pr.Kind != "oauth" || pr.OauthClientName == nil || *pr.OauthClientName != "Test Assistant" || pr.Email == nil ||
		*pr.Email != "blair@localhost" || pr.ApiKeyName != nil || pr.OauthClientVerified == nil || !*pr.OauthClientVerified ||
		pr.ServiceAccountExists != nil {
		t.Errorf("principal = %+v", pr)
	}
	if got := e.scalar(`SELECT oauth_client_kind FROM mcp_calls WHERE principal_kind = 'oauth' ORDER BY id DESC LIMIT 1`); got != "metadata" {
		t.Errorf("recorded client kind = %q", got)
	}

	// Only its own gateway accepts the token (blair may use "shared" too).
	if code, hdr, _ := rawMCP(t, app, "POST", "shared", access, rpc(1, "tools/list", nil), nil); code != 401 ||
		!strings.Contains(hdr.Get("WWW-Authenticate"), `error="invalid_token"`) ||
		!strings.Contains(hdr.Get("WWW-Authenticate"), "/.well-known/oauth-protected-resource/mcp/shared") {
		t.Errorf("token on another gateway = %d %q", code, hdr.Get("WWW-Authenticate"))
	}
	// And never the management API.
	if code, _ := app.do("GET", "/v1/me", nil, map[string]string{"Authorization": "Bearer " + access}); code != 401 {
		t.Errorf("token on /v1/me = %d", code)
	}

	// Refresh rotates. The old refresh token again within the grace period
	// (two refreshes in flight) gets the same pair, not another; after it,
	// reuse revokes the connection.
	status, out, _ = tokenCall(t, app, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refresh}})
	if status != 200 || out["refresh_token"] == refresh || out["access_token"] == access {
		t.Fatalf("refresh = %d %v", status, out)
	}
	first := out
	access2 := out["access_token"].(string)
	status, out, _ = tokenCall(t, app, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"https://other.example/c.json"},
		"refresh_token": {refresh}})
	wantOAuthError(t, "refresh by another client", status, out, 400, "invalid_grant")
	refresh2 := first["refresh_token"].(string)
	status, out, _ = tokenCall(t, app, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refresh}})
	if status != 200 || out["access_token"] != access2 || out["refresh_token"] != refresh2 {
		t.Fatalf("refresh within the grace period = %d %v, want the pair the rotation issued", status, out)
	}
	if code, _, _ := rawMCP(t, app, "POST", "support", access2, rpc(1, "tools/list", nil), nil); code != 200 {
		t.Fatalf("refreshed token = %d", code)
	}
	if _, err := app.Pool.Exec(context.Background(), `UPDATE oauth_tokens SET rotated_at = rotated_at - interval '1 minute' WHERE rotated_at IS NOT NULL`); err != nil {
		t.Fatal(err)
	}
	status, out, _ = tokenCall(t, app, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refresh}})
	wantOAuthError(t, "refresh reuse", status, out, 400, "invalid_grant")
	if code, _, _ := rawMCP(t, app, "POST", "support", access2, rpc(1, "tools/list", nil), nil); code != 401 {
		t.Errorf("after reuse = %d", code)
	}
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'oauth.revoke' AND metadata->>'reason' = 'refresh_reuse'`); n != "1" {
		t.Errorf("reuse revocation audit = %s", n)
	}
	var grants []apitypes.OAuthGrant
	if code := e.member.get("/v1/me/oauth-grants", &grants); code != 200 || len(grants) != 0 {
		t.Errorf("grants after reuse = %d %+v", code, grants)
	}
	// Consent was forgotten with the grant.
	res, _ = authorize(t, app, e.member, q)
	if !strings.HasPrefix(res.Header.Get("Location"), "/oauth/consent?") {
		t.Errorf("after revocation = %q", res.Header.Get("Location"))
	}

	// Tokens are stored as digests only, and appear nowhere else.
	for what, text := range map[string]string{
		"oauth_tokens": e.scalar(`SELECT coalesce(string_agg(row_to_json(o)::text, ''), '') FROM oauth_tokens o`),
		"oauth_codes":  e.scalar(`SELECT coalesce(string_agg(row_to_json(o)::text, ''), '') FROM oauth_codes o`),
		"audit_log":    e.scalar(`SELECT string_agg(row_to_json(a)::text, '') FROM audit_log a`),
		"mcp_calls":    e.scalar(`SELECT string_agg(row_to_json(c)::text, '') FROM mcp_calls c`),
		"logs":         e.logs.String(),
	} {
		for _, secret := range []string{access, refresh, access2, first["refresh_token"].(string), code} {
			if strings.Contains(text, secret) {
				t.Errorf("%s contains a token", what)
			}
		}
		if strings.Contains(text, "ompat_") || strings.Contains(text, "omprt_") {
			t.Errorf("%s contains a token prefix", what)
		}
	}
}
