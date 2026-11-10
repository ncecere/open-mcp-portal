package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestOAuthTrustedRegisteredAndConnectedApps(t *testing.T) {
	e := newOAuthEnv(t)
	app := e.app
	const trustedHTTPS = "https://assistant.example.com/cb"
	cimd := e.docs.client("/trusted.json", "Trusted Assistant", testRedirect, trustedHTTPS)

	// Dynamic registration: public clients only; audited as the system.
	status, out, _ := jsonPost(t, app, "/oauth/register", map[string]any{"client_name": "Old Client", "redirect_uris": []string{testRedirect},
		"client_uri": "https://old.example.com"})
	dcr, _ := out["client_id"].(string)
	if status != 201 || !strings.HasPrefix(dcr, "ompcl_") || out["token_endpoint_auth_method"] != "none" {
		t.Fatalf("register = %d %v", status, out)
	}
	status, out, _ = jsonPost(t, app, "/oauth/register", map[string]any{"redirect_uris": []string{"http://evil.example/cb"}})
	wantOAuthError(t, "http redirect off loopback", status, out, 400, "invalid_redirect_uri")
	status, out, _ = jsonPost(t, app, "/oauth/register", map[string]any{"redirect_uris": []string{testRedirect}, "token_endpoint_auth_method": "client_secret_basic"})
	wantOAuthError(t, "confidential client", status, out, 400, "invalid_client_metadata")
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'oauth.client_register' AND actor_kind = 'system' AND client_ip <> ''
		AND target_type = 'oauth_client'`); n != "1" {
		t.Errorf("client_register audit = %s", n)
	}

	// Trusted clients: metadata documents only.
	var tc apitypes.TrustedClients
	if code := e.auditor.get("/v1/admin/settings/oauth-clients", &tc); code != 200 || len(tc.Clients) != 3 ||
		tc.Clients[1].ClientId != "https://claude.ai/oauth/claude-code-client-metadata" || tc.Clients[2].Label == nil || *tc.Clients[2].Label != "VS Code" {
		t.Fatalf("trusted clients = %d %+v", code, tc)
	}
	put := func(s *session, clients []map[string]any) (int, string) {
		return s.call("PUT", "/v1/admin/settings/oauth-clients", map[string]any{"clients": clients}, &tc, ifMatch(tc.Revision))
	}
	for _, bad := range []string{dcr, "http://claude.ai/x", "https://claude.ai", "https://claude.ai/a?b=c"} {
		code, ec := put(e.admin, []map[string]any{{"clientId": bad}})
		mustCode(t, "trust "+bad, code, ec, 422, "invalid_client_id")
	}
	code, ec := put(e.admin, []map[string]any{{"clientId": cimd}, {"clientId": cimd}})
	mustCode(t, "duplicate", code, ec, 422, "invalid_client_id")
	code, ec = put(e.auditor, []map[string]any{{"clientId": cimd}})
	mustCode(t, "auditor trusts", code, ec, 403, "forbidden")
	code, ec = e.admin.call("PUT", "/v1/admin/settings/oauth-clients", map[string]any{"clients": []any{}}, nil, nil)
	mustCode(t, "no If-Match", code, ec, 428, "")
	code, ec = put(e.admin, []map[string]any{{"clientId": cimd, "label": "Ours"}, {"clientId": "https://claude.ai/oauth/claude-code-client-metadata"}})
	mustCode(t, "trust", code, ec, 200, "")
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'settings.oauth_clients_update' AND target_id = 'oauth_clients'`); n != "1" {
		t.Errorf("settings audit = %s", n)
	}

	// A trusted client skips consent (sign-in is still needed) ...
	p := newPKCE()
	q := authQuery(app, cimd, "support", p, map[string]string{"redirect_uri": trustedHTTPS})
	res, _ := authorize(t, app, nil, q)
	if !strings.HasPrefix(res.Header.Get("Location"), "/?next=") {
		t.Fatalf("trusted, signed out = %q", res.Header.Get("Location"))
	}
	res, _ = authorize(t, app, e.member, q)
	loc, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != 302 || loc.Scheme+"://"+loc.Host+loc.Path != trustedHTTPS || loc.Query().Get("code") == "" {
		t.Fatalf("trusted client with an https redirect = %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	access, _ := exchange(t, app, cimd, loc.Query().Get("code"), p, url.Values{"redirect_uri": {trustedHTTPS}})
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'oauth.consent' AND metadata->>'how' = 'trusted'`); n != "1" {
		t.Errorf("trusted consent audit = %s", n)
	}
	var view apitypes.OAuthConsent
	if e.member.get("/v1/oauth/consent?"+q.Encode(), &view); !view.Client.Trusted || view.Notice {
		t.Errorf("trusted view = %+v", view)
	}
	// ... a registered client never does, and is marked as registered.
	p2 := newPKCE()
	q2 := authQuery(app, dcr, "support", p2, nil)
	res, _ = authorize(t, app, e.member, q2)
	if !strings.HasPrefix(res.Header.Get("Location"), "/oauth/consent?") {
		t.Fatalf("registered client = %q", res.Header.Get("Location"))
	}
	if code := e.member.get("/v1/oauth/consent?"+q2.Encode(), &view); code != 200 || view.Client.Kind != "registered" || view.Client.Trusted ||
		view.Client.Host != "old.example.com" {
		t.Errorf("registered view = %+v", view.Client)
	}
	dcrAccess, dcrRefresh := exchange(t, app, dcr, codeFrom(t, app, "registered", consent(t, e.member, q2, "allow")), p2, nil)
	// Its name is its own claim: the identity says client_verified false, and so does the call log.
	r, err := connect(t, app, "support", dcrAccess).CallTool(context.Background(), &mcp.CallToolParams{Name: "status__whoami"})
	if err != nil || r.IsError {
		t.Fatalf("whoami as a registered client: %v %+v", err, r)
	}
	var who testutil.WhoamiResult
	_ = json.Unmarshal([]byte(resultText(t, r)), &who)
	if who.Claims["client"] != "Old Client" || who.Claims["client_verified"] != false {
		t.Errorf("registered client's identity = %+v", who.Claims)
	}
	var calls apitypes.McpCallPage
	if code := e.owner.get(toolsTeam+"/calls?limit=1", &calls); code != 200 || len(calls.Items) != 1 ||
		calls.Items[0].Principal.OauthClientVerified == nil || *calls.Items[0].Principal.OauthClientVerified {
		t.Errorf("registered client's call = %d %+v", code, calls.Items)
	}

	// Connected apps: the person's own, newest first.
	var grants []apitypes.OAuthGrant
	if code := e.member.get("/v1/me/oauth-grants", &grants); code != 200 || len(grants) != 2 || grants[0].Client.Name != "Old Client" ||
		grants[1].Client.Name != "Trusted Assistant" || !grants[1].Client.Trusted || grants[0].Gateway.Slug != "support" || grants[1].LastUsedAt != nil {
		t.Fatalf("my grants = %d %+v", code, grants)
	}
	if rawCode, _, _ := rawMCP(t, app, "POST", "support", access, rpc(1, "tools/list", nil), nil); rawCode != 200 {
		t.Fatalf("trusted token = %d", rawCode)
	}
	if e.member.get("/v1/me/oauth-grants", &grants); grants[1].LastUsedAt == nil {
		t.Error("last use not recorded")
	}
	if e.owner.get("/v1/me/oauth-grants", &grants); len(grants) != 0 {
		t.Errorf("owner sees %d grants", len(grants))
	}
	blair := e.userID("blair@localhost")
	if code := e.auditor.get("/v1/admin/users/"+blair+"/oauth-grants", &grants); code != 200 || len(grants) != 2 {
		t.Fatalf("admin grants = %d %d", code, len(grants))
	}
	trustedGrant, dcrGrant := grants[1].Id.String(), grants[0].Id.String()
	code, ec = e.member.call("GET", "/v1/admin/users/"+blair+"/oauth-grants", nil, nil, nil)
	mustCode(t, "member reads admin grants", code, ec, 403, "forbidden")
	code, ec = e.auditor.call("DELETE", "/v1/admin/users/"+blair+"/oauth-grants/"+trustedGrant, nil, nil, nil)
	mustCode(t, "auditor disconnects", code, ec, 403, "forbidden")
	code, ec = e.owner.call("DELETE", "/v1/me/oauth-grants/"+trustedGrant, nil, nil, nil)
	mustCode(t, "someone else's grant", code, ec, 404, "grant_not_found")
	code, ec = e.admin.call("GET", "/v1/admin/users/00000000-0000-0000-0000-000000000000/oauth-grants", nil, nil, nil)
	mustCode(t, "unknown user", code, ec, 404, "user_not_found")

	// The revocation endpoint: an access token only itself; a refresh
	// token the whole connection; another client's token nothing.
	status, _, _ = tokenCall(t, app, "/oauth/revoke", url.Values{"token": {dcrAccess}, "client_id": {cimd}})
	if status != 200 {
		t.Fatalf("revoke as another client = %d", status)
	}
	if rawCode, _, _ := rawMCP(t, app, "POST", "support", dcrAccess, rpc(1, "tools/list", nil), nil); rawCode != 200 {
		t.Fatalf("another client revoked it: %d", rawCode)
	}
	tokenCall(t, app, "/oauth/revoke", url.Values{"token": {dcrAccess}, "client_id": {dcr}})
	if rawCode, _, _ := rawMCP(t, app, "POST", "support", dcrAccess, rpc(1, "tools/list", nil), nil); rawCode != 401 {
		t.Fatalf("revoked access token = %d", rawCode)
	}
	status, out, _ = tokenCall(t, app, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {dcr}, "refresh_token": {dcrRefresh}})
	if status != 200 {
		t.Fatalf("refresh after revoking an access token = %d %v", status, out)
	}
	tokenCall(t, app, "/oauth/revoke", url.Values{"token": {out["refresh_token"].(string)}, "client_id": {dcr}})
	if rawCode, _, _ := rawMCP(t, app, "POST", "support", out["access_token"].(string), rpc(1, "tools/list", nil), nil); rawCode != 401 {
		t.Fatalf("connection after revoking its refresh token = %d", rawCode)
	}
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'oauth.revoke' AND metadata->>'reason' = 'client'`); n != "2" {
		t.Errorf("client revocation audits = %s", n)
	}
	status, _, _ = tokenCall(t, app, "/oauth/revoke", url.Values{"token": {"junk"}, "client_id": {dcr}})
	if status != 200 {
		t.Errorf("revoke junk = %d", status)
	}
	_ = dcrGrant

	// A platform admin disconnects the trusted app: its token stops at once.
	code, ec = e.admin.call("DELETE", "/v1/admin/users/"+blair+"/oauth-grants/"+trustedGrant, nil, nil, nil)
	mustCode(t, "admin disconnects", code, ec, 200, "")
	if rawCode, _, _ := rawMCP(t, app, "POST", "support", access, rpc(1, "tools/list", nil), nil); rawCode != 401 {
		t.Errorf("disconnected token = %d", rawCode)
	}
	code, ec = e.member.call("DELETE", "/v1/me/oauth-grants/"+trustedGrant, nil, nil, nil)
	mustCode(t, "disconnect again", code, ec, 404, "grant_not_found")
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'oauth.revoke' AND metadata->>'reason' = 'admin'`); n != "1" {
		t.Errorf("admin revocation audit = %s", n)
	}
	// The person disconnects one themselves.
	a2, _ := connectApp(t, app, e.member, cimd, "shared")
	e.member.get("/v1/me/oauth-grants", &grants)
	code, ec = e.member.call("DELETE", "/v1/me/oauth-grants/"+grants[0].Id.String(), nil, nil, nil)
	mustCode(t, "disconnect", code, ec, 200, "")
	if rawCode, _, _ := rawMCP(t, app, "POST", "shared", a2, rpc(1, "tools/list", nil), nil); rawCode != 401 {
		t.Errorf("token after disconnecting = %d", rawCode)
	}
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'oauth.revoke' AND metadata->>'reason' = 'user'`); n != "1" {
		t.Errorf("user revocation audit = %s", n)
	}
	var audit apitypes.AuditPage
	e.admin.get("/v1/admin/audit?action=oauth.revoke", &audit)
	for _, it := range audit.Items {
		if it.TargetLabel == nil || !strings.Contains(*it.TargetLabel, " · ") {
			t.Errorf("revoke entry label = %v", it.TargetLabel)
		}
	}

	// A registration unused for 30 days expires.
	if _, err := app.Pool.Exec(context.Background(), `UPDATE oauth_clients SET last_used_at = now() - interval '31 days'`); err != nil {
		t.Fatal(err)
	}
	res, body := authorize(t, app, e.member, authQuery(app, dcr, "support", newPKCE(), nil))
	wantPage(t, "expired registration", res, body, "invalid_client")
	jsonPost(t, app, "/oauth/register", map[string]any{"redirect_uris": []string{testRedirect}})
	if n := e.scalar(`SELECT count(*)::text FROM oauth_clients WHERE client_id = $1`, dcr); n != "0" {
		t.Errorf("expired registration kept: %s", n)
	}
}

// Every request with an access token re-checks the person, the grant and
// their access; a refused request never reaches the server.
func TestOAuthRechecksEveryRequest(t *testing.T) {
	cases := []struct {
		name, gateway string
		want          int
		mutate        func(e *oauthEnv)
	}{
		{"suspend user", "support", 401, func(e *oauthEnv) {
			id := e.userID("blair@localhost")
			var u apitypes.UserDetail
			e.admin.get("/v1/admin/users/"+id, &u)
			code, ec := e.admin.call("PATCH", "/v1/admin/users/"+id, map[string]any{"status": "suspended"}, nil, ifMatch(u.User.Revision))
			mustCode(e.t, "suspend", code, ec, 200, "")
		}},
		{"remove from team", "support", 404, func(e *oauthEnv) {
			code, ec := e.owner.call("DELETE", toolsTeam+"/members/"+e.userID("blair@localhost"), nil, nil, nil)
			mustCode(e.t, "remove", code, ec, 200, "")
		}},
		{"remove grant", "shared", 404, func(e *oauthEnv) {
			code, ec := e.admin.call("DELETE", e.shared+"/grants/"+e.grant, nil, nil, nil)
			mustCode(e.t, "remove grant", code, ec, 200, "")
		}},
		{"disconnect", "support", 401, func(e *oauthEnv) {
			var grants []apitypes.OAuthGrant
			e.member.get("/v1/me/oauth-grants", &grants)
			code, ec := e.member.call("DELETE", "/v1/me/oauth-grants/"+grants[0].Id.String(), nil, nil, nil)
			mustCode(e.t, "disconnect", code, ec, 200, "")
		}},
		{"expire token", "support", 401, func(e *oauthEnv) {
			e.app.Pool.Exec(context.Background(), `UPDATE oauth_tokens SET expires_at = now() - interval '1 second' WHERE kind = 'access'`)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newOAuthEnv(t)
			clientID := e.docs.client("/assistant.json", "Test Assistant", testRedirect)
			access, _ := connectApp(t, e.app, e.member, clientID, tc.gateway)
			cs := connect(t, e.app, tc.gateway, access)
			if got := toolNames(t, cs); strings.Join(got, ",") != "status__whoami" {
				t.Fatalf("tools = %v", got)
			}
			tc.mutate(e)
			requests := e.fake.Requests()
			if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "status__whoami"}); err == nil {
				t.Fatal("the call went through")
			}
			code, _, _ := rawMCP(t, e.app, "POST", tc.gateway, access, rpc(1, "tools/call", map[string]any{"name": "status__whoami"}), nil)
			if code != tc.want {
				t.Fatalf("raw call = %d, want %d", code, tc.want)
			}
			if e.fake.Requests() != requests {
				t.Fatal("the refused call reached the server")
			}
		})
	}
}

// Client metadata documents are fetched with the rules of MCP server URLs
// (the address guard; the development allowance lets these tests reach
// 127.0.0.1), no redirects, at most 16 KiB, JSON only, and cached.
func TestOAuthMetadataDocumentRules(t *testing.T) {
	e := newOAuthEnv(t)
	app := e.app
	doc := func(path string, mutate func(m map[string]any)) string {
		id := e.docs.URL + path
		m := map[string]any{"client_id": id, "client_name": "Doc", "redirect_uris": []string{testRedirect}}
		if mutate != nil {
			mutate(m)
		}
		b, _ := json.Marshal(m)
		return e.docs.set(path, docResponse{status: 200, contentType: "application/json", body: string(b)})
	}
	good := doc("/good.json", nil)
	cases := map[string]string{
		"redirect":          e.docs.set("/redirect.json", docResponse{redirect: good}),
		"too big":           doc("/big.json", func(m map[string]any) { m["client_name"] = strings.Repeat("x", 17<<10) }),
		"html":              e.docs.set("/html.json", docResponse{status: 200, contentType: "text/html", body: `{"client_id":"x"}`}),
		"status":            e.docs.set("/gone.json", docResponse{status: 410, contentType: "application/json", body: `{}`}),
		"not json":          e.docs.set("/junk.json", docResponse{status: 200, contentType: "application/json", body: `not json`}),
		"other id":          doc("/other.json", func(m map[string]any) { m["client_id"] = good }),
		"bad redirect uris": doc("/uris.json", func(m map[string]any) { m["redirect_uris"] = []string{"http://evil.example/cb"} }),
		"query":             good + "?x=1",
		"no path":           e.docs.URL + "/",
		"dot path":          e.docs.URL + "/a/../good.json",
	}
	for name, id := range cases {
		res, body := authorize(t, app, e.member, authQuery(app, id, "support", newPKCE(), nil))
		wantPage(t, name, res, body, "invalid_client")
	}
	// The good one works, and is fetched once (cached).
	res, _ := authorize(t, app, e.member, authQuery(app, good, "support", newPKCE(), nil))
	if !strings.HasPrefix(res.Header.Get("Location"), "/oauth/consent?") {
		t.Fatalf("good document = %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	authorize(t, app, e.member, authQuery(app, good, "support", newPKCE(), nil))
	if n := e.docs.hitCount("/good.json"); n != 1 {
		t.Errorf("good document fetched %d times", n)
	}
	// Plain http on a loopback host only with the development allowance:
	// allowed here (the app's loopback APP_URL and DEV_AUTH).
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "http://" + r.Host + "/c.json", "client_name": "Local", "redirect_uris": []string{testRedirect}})
	}))
	defer plain.Close()
	res, _ = authorize(t, app, e.member, authQuery(app, plain.URL+"/c.json", "support", newPKCE(), nil))
	if !strings.HasPrefix(res.Header.Get("Location"), "/oauth/consent?") {
		t.Errorf("http loopback document in development = %d %q", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestOAuthRateLimits(t *testing.T) {
	// Counts belong to clock-aligned minutes, not to a minute after the
	// first request. Even a sub-second burst can straddle the DB clock's
	// boundary. Use the real in-memory Store with its clock seam so each
	// burst stays in one window, while still exercising the HTTP gates.
	boundary := time.Unix(1020, 0)
	var now atomic.Int64 // the HTTP server reads the clock in another goroutine
	now.Store(boundary.Add(-500 * time.Microsecond).UnixNano())
	app := newTestAppDeps(t, nil, testutil.Logger(), func(d *httpapi.Deps) {
		d.RateStore = ratelimit.NewWithClock(func() time.Time { return time.Unix(0, now.Load()) })
	})
	endpoints := []struct {
		name         string
		limit        int
		allowed      int
		allowedError string
		call         func(*testing.T) (int, map[string]any, http.Header)
	}{
		{"register", 10, 201, "", func(t *testing.T) (int, map[string]any, http.Header) {
			return jsonPost(t, app, "/oauth/register", map[string]any{"redirect_uris": []string{testRedirect}})
		}},
		{"token", 60, 400, "invalid_grant", func(t *testing.T) (int, map[string]any, http.Header) {
			return tokenCall(t, app, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"x"}, "refresh_token": {"y"}})
		}},
		{"authorize", 60, 302, "", func(t *testing.T) (int, map[string]any, http.Header) {
			res, body := authorize(t, app, nil, url.Values{"client_id": {"x"}})
			var out map[string]any
			if res.StatusCode == 429 {
				if err := json.Unmarshal([]byte(body), &out); err != nil {
					t.Fatal(err)
				}
			}
			return res.StatusCode, out, res.Header
		}},
		{"revoke", 60, 200, "", func(t *testing.T) (int, map[string]any, http.Header) {
			return tokenCall(t, app, "/oauth/revoke", url.Values{"token": {"x"}, "client_id": {"x"}})
		}},
	}
	for _, phase := range []struct {
		name       string
		now        time.Time
		retryAfter string
	}{
		{"before_boundary", boundary.Add(-500 * time.Microsecond), "1"},
		// Keep the same Store and client address: the next minute must get
		// a fresh allowance, not continue the preceding window's counts.
		{"at_boundary", boundary, "60"},
	} {
		t.Run(phase.name, func(t *testing.T) {
			now.Store(phase.now.UnixNano())
			for _, endpoint := range endpoints {
				t.Run(endpoint.name, func(t *testing.T) {
					for i := 1; i <= endpoint.limit+1; i++ {
						status, out, hdr := endpoint.call(t)
						if i <= endpoint.limit {
							if status != endpoint.allowed || (endpoint.allowedError != "" && out["error"] != endpoint.allowedError) {
								t.Fatalf("request %d = %d %v, want %d %s", i, status, out, endpoint.allowed, endpoint.allowedError)
							}
							if hdr.Get("Retry-After") != "" {
								t.Fatalf("allowed request %d has Retry-After: %q", i, hdr.Get("Retry-After"))
							}
							continue
						}
						if status != 429 || out["error"] != "slow_down" || hdr.Get("Retry-After") != phase.retryAfter {
							t.Fatalf("request %d = %d %v Retry-After=%q, want 429 slow_down Retry-After=%s", i, status, out, hdr.Get("Retry-After"), phase.retryAfter)
						}
						if hdr.Get("Content-Type") != "application/json" || hdr.Get("Cache-Control") != "no-store" || hdr.Get("Pragma") != "no-cache" || hdr.Get("WWW-Authenticate") != "" {
							t.Fatalf("rate-limit response headers = %v", hdr)
						}
					}
				})
			}
		})
	}
}
