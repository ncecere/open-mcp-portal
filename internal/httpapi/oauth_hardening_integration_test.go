package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/migrations"
)

// OAuth hardening of v0.2.2 (docs/threat-model.md H-1, H-3, H-4, H-8;
// decisions 62 and 63), end to end.

// newOAuthEnvConfig is newOAuthEnv with the configuration adjusted first (the
// shared constructors take none): the same people, server and gateways.
func newOAuthEnvConfig(t *testing.T, mutate func(*config.Config)) *oauthEnv {
	t.Helper()
	docs := newDocServer(t)
	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	app := newTestAppDeps(t, mutate, log, trustDocs(docs))
	g := &gwEnv{t: t, app: app, fake: testutil.NewFakeMCP(t), otherFake: testutil.NewFakeMCP(t)}
	g.fake.EnableGatewayTools()
	g.otherFake.EnableGatewayTools()
	g.admin, g.auditor = app.signIn("admin"), app.signIn("auditor")
	g.owner, g.editor, g.member, g.outsider = app.signIn("user"), app.signIn("alex"), app.signIn("blair"), app.signIn("casey")
	createTeam(t, g.admin, "tools", "user@localhost")
	createTeam(t, g.admin, "other", "casey@localhost")
	for email, role := range map[string]string{"alex@localhost": "editor", "blair@localhost": "member"} {
		code, ec := g.owner.call("POST", toolsTeam+"/members", map[string]any{"email": email, "role": role}, nil, nil)
		mustCode(t, "add "+email, code, ec, 201, "")
	}
	g.server = g.createServer(g.owner, "tools", "status", g.fake.URL(), nil)
	g.other = g.createServer(g.outsider, "other", "other-status", g.otherFake.URL(), nil)
	e := &rtEnv{gwEnv: g}
	e.publish(e.owner, e.server)
	whoami := e.capID(e.owner, e.server, "tool", "whoami")
	support := e.createGateway(e.owner, toolsTeam+"/gateways", "support")
	e.supportTeamPath = toolsTeam + "/gateways/" + support.Id.String()
	e.support = "/v1/admin/gateways/" + support.Id.String()
	e.mustSetCaps(e.owner, e.supportTeamPath, sel(whoami))
	shared := e.createGateway(e.admin, "/v1/admin/gateways", "shared")
	e.shared = "/v1/admin/gateways/" + shared.Id.String()
	e.mustSetCaps(e.admin, e.shared, sel(whoami))
	var gr apitypes.GatewayGrant
	code, ec := e.admin.call("POST", e.shared+"/grants", map[string]any{"subjectKind": "user", "userEmail": "blair@localhost"}, &gr, nil)
	mustCode(t, "grant", code, ec, 201, "")
	e.grant = gr.Id.String()
	e.key = newKey(t, e.member, "laptop")
	return &oauthEnv{rtEnv: e, docs: docs, logs: logs}
}

func proxies(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

// trustClients sets the trusted list (platform admin).
func trustClients(t *testing.T, e *oauthEnv, ids ...string) {
	t.Helper()
	var tc apitypes.TrustedClients
	if code := e.admin.get("/v1/admin/settings/oauth-clients", &tc); code != 200 {
		t.Fatalf("trusted clients = %d", code)
	}
	clients := make([]map[string]any, len(ids))
	for i, id := range ids {
		clients[i] = map[string]any{"clientId": id}
	}
	code, ec := e.admin.call("PUT", "/v1/admin/settings/oauth-clients", map[string]any{"clients": clients}, &tc, ifMatch(tc.Revision))
	mustCode(t, "trust", code, ec, 200, "")
}

// codeAt reads the code of an authorization redirect to an http host.
func codeAt(t *testing.T, app *testApp, what, location, host string) string {
	t.Helper()
	loc, err := url.Parse(location)
	if err != nil || loc.Scheme != "http" || loc.Host != host || loc.Query().Get("code") == "" ||
		loc.Query().Get("iss") != app.URL || loc.Query().Get("error") != "" {
		t.Fatalf("%s: redirect %q, want a code for %s", what, location, host)
	}
	return loc.Query().Get("code")
}

// H-3: nothing is fetched, and nothing is told, before sign-in.
func TestOAuthAuthorizeAnonymousFetchesNothing(t *testing.T) {
	e := newOAuthEnv(t)
	app := e.app
	good := e.docs.client("/good.json", "Test Assistant", testRedirect)
	e.docs.set("/gone.json", docResponse{status: 410, contentType: "application/json", body: `{}`})
	e.docs.set("/junk.json", docResponse{status: 200, contentType: "application/json", body: `not json`})
	gone, junk := e.docs.URL+"/gone.json", e.docs.URL+"/junk.json"
	p := newPKCE()

	// Whatever the client, redirect or resource, an anonymous request is
	// sent to sign in with the whole query, the same way, and the document
	// server is never contacted.
	for name, q := range map[string]url.Values{
		"good client":          authQuery(app, good, "support", p, nil),
		"document answers 410": authQuery(app, gone, "support", p, nil),
		"document isn't JSON":  authQuery(app, junk, "support", p, nil),
		"foreign redirect":     authQuery(app, good, "support", p, map[string]string{"redirect_uri": "https://evil.example/cb"}),
		"unreachable host":     authQuery(app, "https://unreachable.invalid/client.json", "support", p, nil),
		"not a client":         authQuery(app, "not-a-client", "support", p, nil),
		"no client":            authQuery(app, "", "support", p, nil),
		"no gateway":           authQuery(app, good, "no-such-gateway", p, nil),
		"no PKCE":              authQuery(app, good, "support", p, map[string]string{"code_challenge": ""}),
		"implicit":             authQuery(app, good, "support", p, map[string]string{"response_type": "token"}),
		"a loopback client_id": authQuery(app, "http://127.0.0.1:1/c.json", "support", p, nil),
	} {
		res, _ := authorize(t, app, nil, q)
		if want := "/?next=" + url.QueryEscape("/oauth/authorize?"+q.Encode()); res.StatusCode != 302 || res.Header.Get("Location") != want {
			t.Errorf("anonymous, %s = %d %q, want a redirect to sign in", name, res.StatusCode, res.Header.Get("Location"))
		}
	}
	for _, path := range []string{"/good.json", "/gone.json", "/junk.json"} {
		if n := e.docs.hitCount(path); n != 0 {
			t.Errorf("the document %s was fetched %d times for anonymous requests", path, n)
		}
	}
	if strings.Contains(e.logs.String(), "metadata document fetched") {
		t.Errorf("a fetch was logged for anonymous requests:\n%s", e.logs.String())
	}

	// A request malformed on its face is refused with one page, which names
	// no reason and no error code: the same bytes for every such request.
	long := authQuery(app, good, "support", p, map[string]string{"state": strings.Repeat("s", 8100)})
	repeated := authQuery(app, good, "support", p, nil)
	repeated.Add("state", "again")
	res1, body1 := authorize(t, app, nil, long)
	res2, body2 := authorize(t, app, nil, repeated)
	if res1.StatusCode != 400 || res2.StatusCode != 400 || body1 != body2 || res1.Header.Get("Location") != "" ||
		strings.Contains(body1, "invalid_request") || strings.Contains(body1, "Error:") || strings.Contains(body1, "repeats") || strings.Contains(body1, "too long") {
		t.Errorf("anonymous malformed requests = %d %d, identical %v:\n%s\n%s", res1.StatusCode, res2.StatusCode, body1 == body2, body1, body2)
	}
	if !strings.Contains(body1, "Can't connect this app") || !strings.HasPrefix(res1.Header.Get("Content-Type"), "text/html") ||
		!strings.Contains(res1.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Errorf("the generic page = %v\n%s", res1.Header, body1)
	}
	if n := e.docs.hitCount("/good.json"); n != 0 {
		t.Errorf("the good document was fetched %d times", n)
	}

	// Signed in, the same requests are looked at as before: the fetch happens
	// once (then it is cached) and failures say why.
	if res, _ := authorize(t, app, e.member, authQuery(app, good, "support", p, nil)); !strings.HasPrefix(res.Header.Get("Location"), "/oauth/consent?") {
		t.Fatalf("signed in = %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if n := e.docs.hitCount("/good.json"); n != 1 {
		t.Errorf("the good document was fetched %d times after sign-in", n)
	}
	res, body := authorize(t, app, e.member, authQuery(app, gone, "support", p, nil))
	wantPage(t, "signed in, document answers 410", res, body, "invalid_client")
	if !strings.Contains(body, "HTTP 410") {
		t.Errorf("a signed-in person is told why: %s", body)
	}
	res, body = authorize(t, app, e.member, long)
	wantPage(t, "signed in, long query", res, body, "invalid_request")
}

// H-3: a source address can make the portal fetch only so many documents a
// minute; documents already cached cost nothing, and another address has its
// own count.
func TestOAuthMetadataFetchCapPerAddress(t *testing.T) {
	e := newOAuthEnvConfig(t, func(c *config.Config) { c.TrustedProxies = proxies(t, "127.0.0.1/32") })
	app := e.app
	first := e.docs.client("/c0.json", "App 0", testRedirect)
	p := newPKCE()
	allowed, refused := 0, 0
	for i := range 45 {
		id := first
		if i > 0 {
			id = e.docs.client(fmt.Sprintf("/c%d.json", i), "App", testRedirect)
		}
		res, body := authorize(t, app, e.member, authQuery(app, id, "support", p, nil))
		switch {
		case strings.HasPrefix(res.Header.Get("Location"), "/oauth/consent?"):
			allowed++
		case res.StatusCode == 429 && strings.Contains(body, "slow_down"):
			refused++
		default:
			t.Fatalf("request %d = %d %q %s", i, res.StatusCode, res.Header.Get("Location"), body)
		}
	}
	// Fixed one-minute windows: a run that crosses a minute boundary gets two.
	if allowed < 20 || allowed > 40 || refused < 5 {
		t.Fatalf("allowed %d, refused %d of 45 distinct documents", allowed, refused)
	}
	if n := e.docs.hitCount("/c0.json"); n != 1 {
		t.Errorf("the first document was fetched %d times", n)
	}
	// A cached document still works at the cap (no fetch, nothing counted) ...
	if res, _ := authorize(t, app, e.member, authQuery(app, first, "support", p, nil)); !strings.HasPrefix(res.Header.Get("Location"), "/oauth/consent?") {
		t.Errorf("cached document at the cap = %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	// ... the consent page's check is counted the same way ...
	late := e.docs.client("/late.json", "Late", testRedirect)
	code, ec := e.member.call("GET", "/v1/oauth/consent?"+authQuery(app, late, "support", p, nil).Encode(), nil, nil, nil)
	if code != 429 || ec != "oauth_slow_down" {
		t.Errorf("consent view at the cap = %d %q", code, ec)
	}
	if n := e.docs.hitCount("/late.json"); n != 0 {
		t.Errorf("a refused fetch reached the document server %d times", n)
	}
	// ... and another address (behind a trusted proxy) has its own.
	other := authQuery(app, e.docs.client("/other-address.json", "Other", testRedirect), "support", p, nil)
	req, _ := http.NewRequest("GET", app.URL+"/oauth/authorize?"+other.Encode(), nil)
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	res, err := (&http.Client{CheckRedirect: noFollow, Jar: e.member.client.Jar}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if !strings.HasPrefix(res.Header.Get("Location"), "/oauth/consent?") {
		t.Errorf("another address = %d %q", res.StatusCode, res.Header.Get("Location"))
	}
}

// H-4: the admin switch.
func TestOAuthRegistrationSwitch(t *testing.T) {
	e := newOAuthEnv(t)
	app := e.app
	body := map[string]any{"client_name": "pi", "redirect_uris": []string{testRedirect}}
	status, out, _ := jsonPost(t, app, "/oauth/register", body)
	dcr, _ := out["client_id"].(string)
	if status != 201 || dcr == "" {
		t.Fatalf("registration while open = %d %v", status, out)
	}
	var tc apitypes.TrustedClients
	if code := e.auditor.get("/v1/admin/settings/oauth-clients", &tc); code != 200 || !tc.OpenRegistration {
		t.Fatalf("default = %d %+v", code, tc)
	}
	set := func(s *session, open bool) (int, string) {
		return s.call("PUT", "/v1/admin/settings/oauth-clients", map[string]any{"clients": tc.Clients, "openRegistration": open}, &tc, ifMatch(tc.Revision))
	}
	if code, ec := set(e.auditor, false); code != 403 {
		t.Fatalf("auditor turns it off = %d %s", code, ec)
	}
	if code, ec := set(e.member, false); code != 403 {
		t.Fatalf("member turns it off = %d %s", code, ec)
	}
	code, ec := set(e.admin, false)
	mustCode(t, "turn off", code, ec, 200, "")
	if tc.OpenRegistration {
		t.Fatalf("after turning off: %+v", tc)
	}
	// Omitting the switch keeps it as it is (a client that only edits the list).
	code, ec = e.admin.call("PUT", "/v1/admin/settings/oauth-clients", map[string]any{"clients": tc.Clients}, &tc, ifMatch(tc.Revision))
	mustCode(t, "save the list only", code, ec, 200, "")
	if tc.OpenRegistration {
		t.Fatalf("saving only the list turned registration back on: %+v", tc)
	}

	// Discovery leaves the endpoint out; the endpoint refuses.
	status2, _, raw := getRaw(t, app.URL+"/.well-known/oauth-authorization-server")
	if status2 != 200 || strings.Contains(string(raw), "registration_endpoint") || !strings.Contains(string(raw), `"client_id_metadata_document_supported":true`) ||
		!strings.Contains(string(raw), "authorization_endpoint") {
		t.Errorf("discovery while closed = %d %s", status2, raw)
	}
	status, out, hdr := jsonPost(t, app, "/oauth/register", body)
	wantOAuthError(t, "registration while closed", status, out, 403, "access_denied")
	if hdr.Get("Cache-Control") != "no-store" || !strings.Contains(out["error_description"].(string), "Client ID Metadata Document") {
		t.Errorf("closed answer = %v %v", out, hdr)
	}
	// Even invalid metadata gets the same answer; nothing is stored or audited.
	status, out, _ = jsonPost(t, app, "/oauth/register", map[string]any{"redirect_uris": []string{"http://evil.example/cb"}})
	wantOAuthError(t, "bad metadata while closed", status, out, 403, "access_denied")
	if n := e.scalar(`SELECT count(*)::text FROM oauth_clients`); n != "1" {
		t.Errorf("%s clients stored", n)
	}
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'settings.oauth_clients_update' AND after_state->>'openRegistration' = 'false'
		AND before_state->>'openRegistration' = 'true'`); n != "1" {
		t.Errorf("settings audit entries with the switch = %s", n)
	}
	// An app registered before still signs in.
	p := newPKCE()
	q := authQuery(app, dcr, "support", p, nil)
	if res, _ := authorize(t, app, e.member, q); !strings.HasPrefix(res.Header.Get("Location"), "/oauth/consent?") {
		t.Errorf("an app registered before = %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	exchange(t, app, dcr, codeFrom(t, app, "registered before", consent(t, e.member, q, "allow")), p, nil)

	// On again.
	code, ec = set(e.admin, true)
	mustCode(t, "turn on", code, ec, 200, "")
	if _, _, raw = getRaw(t, app.URL+"/.well-known/oauth-authorization-server"); !strings.Contains(string(raw), `"registration_endpoint":"`+app.URL+`/oauth/register"`) {
		t.Errorf("discovery while open: %s", raw)
	}
	if status, out, _ = jsonPost(t, app, "/oauth/register", body); status != 201 {
		t.Errorf("registration after turning on = %d %v", status, out)
	}
}

// H-4: a registration nobody used ages out after 24 hours; one that signed
// in lives its 30 days from its last use.
func TestOAuthUnusedRegistrationsAgeOut(t *testing.T) {
	e := newOAuthEnv(t)
	app := e.app
	register := func(name string) string {
		status, out, _ := jsonPost(t, app, "/oauth/register", map[string]any{"client_name": name, "redirect_uris": []string{testRedirect}})
		id, _ := out["client_id"].(string)
		if status != 201 || id == "" {
			t.Fatalf("register %s = %d %v", name, status, out)
		}
		return id
	}
	age := func(id, created, used string) {
		t.Helper()
		if _, err := app.Pool.Exec(context.Background(), `UPDATE oauth_clients SET created_at = now() - $2::interval, last_used_at = now() - $3::interval WHERE client_id = $1`,
			id, created, used); err != nil {
			t.Fatal(err)
		}
	}
	resolves := func(id string) bool {
		t.Helper()
		res, body := authorize(t, app, e.member, authQuery(app, id, "support", newPKCE(), nil))
		// Known: the consent page, or straight back with a code when the person allowed it before.
		if loc := res.Header.Get("Location"); strings.HasPrefix(loc, "/oauth/consent?") || strings.Contains(loc, "code=") {
			return true
		}
		wantPage(t, "unknown registration", res, body, "invalid_client")
		return false
	}

	unused, used := register("Unused"), register("Used")
	p := newPKCE()
	q := authQuery(app, used, "support", p, nil)
	exchange(t, app, used, codeFrom(t, app, "used", consent(t, e.member, q, "allow")), p, nil)
	if n := e.scalar(`SELECT count(*)::text FROM oauth_clients WHERE authorized_at IS NOT NULL`); n != "1" {
		t.Fatalf("authorized registrations = %s, want 1 (the one that received tokens)", n)
	}

	// 23 hours: both are there.
	age(unused, "23 hours", "23 hours")
	age(used, "23 hours", "23 hours")
	if !resolves(unused) || !resolves(used) {
		t.Fatal("a registration under 24 hours old is gone")
	}
	// 25 hours: the one nobody used is gone (and deleted by the next registration), the used one stays.
	age(unused, "25 hours", "25 hours")
	age(used, "25 hours", "25 hours")
	if gotUnused, gotUsed := resolves(unused), resolves(used); gotUnused || !gotUsed {
		t.Fatalf("after 25 hours: unused resolves = %v, used resolves = %v", gotUnused, gotUsed)
	}
	register("Another")
	if n := e.scalar(`SELECT count(*)::text FROM oauth_clients WHERE client_id = $1`, unused); n != "0" {
		t.Errorf("the unused registration was kept: %s", n)
	}
	// A used one lives 30 days from its last use, not 24 hours from creation.
	age(used, "40 days", "29 days")
	if !resolves(used) {
		t.Error("a used registration (last used 29 days ago) is gone")
	}
	age(used, "40 days", "31 days")
	if resolves(used) {
		t.Error("a used registration unused for 31 days is still there")
	}
}

// H-4: one address can hold only so many unused registrations; another
// address is unaffected; using one (or waiting) frees the address.
func TestOAuthRegistrationsPerAddress(t *testing.T) {
	e := newOAuthEnvConfig(t, func(c *config.Config) {
		c.OAuthMaxUnusedClientsPerAddress = 3
		c.TrustedProxies = proxies(t, "127.0.0.1/32")
	})
	app := e.app
	register := func(forwarded string) (int, map[string]any) {
		b, _ := json.Marshal(map[string]any{"client_name": "App", "redirect_uris": []string{testRedirect}})
		req, _ := http.NewRequest("POST", app.URL+"/oauth/register", strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", forwarded)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		out := map[string]any{}
		_ = json.Unmarshal(raw, &out)
		return res.StatusCode, out
	}
	var ids []string
	for i := range 3 {
		status, out := register("198.51.100.1")
		if status != 201 {
			t.Fatalf("registration %d from the first address = %d %v", i+1, status, out)
		}
		ids = append(ids, out["client_id"].(string))
	}
	status, out := register("198.51.100.1")
	desc, _ := out["error_description"].(string)
	if status != 429 || out["error"] != "slow_down" || !strings.Contains(desc, "none of them has been used") {
		t.Fatalf("over the address's share = %d %v", status, out)
	}
	if n := e.scalar(`SELECT count(*)::text FROM oauth_clients WHERE registered_from = '198.51.100.1'`); n != "3" {
		t.Errorf("%s registrations stored for the address", n)
	}
	// Another address is unaffected.
	if status, out := register("198.51.100.2"); status != 201 {
		t.Fatalf("another address = %d %v", status, out)
	}
	// One of the three signs in: it no longer counts against the address.
	p := newPKCE()
	q := authQuery(app, ids[0], "support", p, nil)
	exchange(t, app, ids[0], codeFrom(t, app, "first", consent(t, e.member, q, "allow")), p, nil)
	if status, out := register("198.51.100.1"); status != 201 {
		t.Fatalf("after one was used = %d %v", status, out)
	}
	if status, _ := register("198.51.100.1"); status != 429 {
		t.Fatalf("the address is full again = %d", status)
	}
	// Waiting frees the rest: after 25 hours the unused ones are gone.
	if _, err := app.Pool.Exec(context.Background(), `UPDATE oauth_clients SET created_at = now() - interval '25 hours' WHERE authorized_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	if status, out := register("198.51.100.1"); status != 201 {
		t.Fatalf("after 25 hours = %d %v", status, out)
	}
	// The address is the one the portal saw (the right-most untrusted hop), never a client's own claim.
	if status, out := register("203.0.113.9, 198.51.100.50"); status != 201 {
		t.Fatalf("with a forged first hop = %d %v", status, out)
	}
	if n := e.scalar(`SELECT count(*)::text FROM oauth_clients WHERE registered_from = '198.51.100.50'`); n != "1" {
		t.Errorf("the right-most untrusted hop wasn't recorded: %s", n)
	}
}

// H-1: a trusted client with a loopback redirect (Claude Code on a desktop)
// asks once per person and gateway; one with an https redirect never does.
func TestOAuthTrustedLoopbackFirstUseNotice(t *testing.T) {
	e := newOAuthEnv(t)
	app := e.app
	// Claude Code's shape: a metadata document naming localhost and 127.0.0.1
	// without a port, trusted by an admin; the redirect uses a free port.
	const loopback = "http://localhost:54321/callback"
	cc := e.docs.client("/claude-code.json", "Claude Code", "http://localhost/callback", "http://127.0.0.1/callback", "https://assistant.example.com/cb")
	trustClients(t, e, cc)
	asLoopback := func(p pkce, over map[string]string) url.Values {
		o := map[string]string{"redirect_uri": loopback}
		for k, v := range over {
			o[k] = v
		}
		return authQuery(app, cc, "support", p, o)
	}
	view := func(s *session, q url.Values) apitypes.OAuthConsent {
		t.Helper()
		var v apitypes.OAuthConsent
		if code := s.get("/v1/oauth/consent?"+q.Encode(), &v); code != 200 {
			t.Fatalf("consent view = %d", code)
		}
		return v
	}

	// First sign-in: the notice, not a code.
	p := newPKCE()
	q := asLoopback(p, nil)
	res, _ := authorize(t, app, e.member, q)
	if loc := res.Header.Get("Location"); res.StatusCode != 302 || loc != "/oauth/consent?"+q.Encode() {
		t.Fatalf("first sign-in = %d %q, want the consent page", res.StatusCode, loc)
	}
	if v := view(e.member, q); !v.Notice || !v.Client.Trusted || v.Remembered || v.RedirectHost != "localhost:54321" || v.Client.Name != "Claude Code" {
		t.Fatalf("first-use view = %+v", v)
	}
	// Saying no sends access_denied to the client and remembers nothing.
	deny, _ := url.Parse(consent(t, e.member, q, "deny"))
	if deny.Host != "localhost:54321" || deny.Query().Get("error") != "access_denied" || deny.Query().Get("code") != "" {
		t.Fatalf("deny = %s", deny)
	}
	if n := e.scalar(`SELECT count(*)::text FROM oauth_grants`); n != "0" {
		t.Fatalf("grants after deny = %s", n)
	}
	if res, _ = authorize(t, app, e.member, q); !strings.HasPrefix(res.Header.Get("Location"), "/oauth/consent?") {
		t.Fatalf("after denying = %q", res.Header.Get("Location"))
	}
	// Continuing: the code goes to the loopback address, and the client completes PKCE.
	access, _ := exchange(t, app, cc, codeAt(t, app, "confirmed", consent(t, e.member, q, "allow"), "localhost:54321"), p,
		url.Values{"redirect_uri": {loopback}})
	if code, _, _ := rawMCP(t, app, "POST", "support", access, rpc(1, "tools/list", nil), nil); code != 200 {
		t.Fatalf("the signed-in client's token = %d", code)
	}
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'oauth.grant_confirmed' AND metadata->>'how' = 'confirmed'
		AND metadata->>'name' = 'Claude Code · SUPPORT'`); n != "1" {
		t.Errorf("oauth.grant_confirmed entries = %s", n)
	}
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'oauth.consent'`); n != "0" {
		t.Errorf("oauth.consent entries = %s (the confirmation is its own event)", n)
	}

	// The second sign-in is silent, on any port.
	const loopback2 = "http://localhost:60000/callback"
	p2 := newPKCE()
	q2 := asLoopback(p2, map[string]string{"redirect_uri": loopback2})
	res, _ = authorize(t, app, e.member, q2)
	exchange(t, app, cc, codeAt(t, app, "second sign-in", res.Header.Get("Location"), "localhost:60000"), p2, url.Values{"redirect_uri": {loopback2}})
	if v := view(e.member, q2); v.Notice || !v.Remembered || !v.Client.Trusted {
		t.Errorf("second view = %+v", v)
	}

	// Another person, and another gateway, each confirm once for themselves.
	if res, _ = authorize(t, app, e.owner, asLoopback(newPKCE(), nil)); !strings.HasPrefix(res.Header.Get("Location"), "/oauth/consent?") {
		t.Errorf("another person = %q", res.Header.Get("Location"))
	}
	qShared := authQuery(app, cc, "shared", newPKCE(), map[string]string{"redirect_uri": loopback})
	if res, _ = authorize(t, app, e.member, qShared); !strings.HasPrefix(res.Header.Get("Location"), "/oauth/consent?") {
		t.Errorf("another gateway = %q", res.Header.Get("Location"))
	}
	if v := view(e.member, qShared); !v.Notice {
		t.Errorf("another gateway view = %+v", v)
	}
	// 127.0.0.1 is loopback too.
	if v := view(e.member, authQuery(app, cc, "shared", newPKCE(), map[string]string{"redirect_uri": "http://127.0.0.1:4000/callback"})); !v.Notice {
		t.Errorf("127.0.0.1 view = %+v", v)
	}

	// An https redirect is unaffected: a trusted client goes straight back with a code, on first use.
	qH := authQuery(app, cc, "support", newPKCE(), map[string]string{"redirect_uri": "https://assistant.example.com/cb"})
	res, _ = authorize(t, app, e.owner, qH)
	hl, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != 302 || hl.Scheme+"://"+hl.Host+hl.Path != "https://assistant.example.com/cb" || hl.Query().Get("code") == "" {
		t.Fatalf("https redirect, first use = %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if v := view(e.owner, qH); v.Notice {
		t.Errorf("https redirect view = %+v", v)
	}

	// Disconnecting the app brings the notice back.
	var grants []apitypes.OAuthGrant
	e.member.get("/v1/me/oauth-grants", &grants)
	if len(grants) != 1 || grants[0].Gateway.Slug != "support" {
		t.Fatalf("grants = %+v", grants)
	}
	code, ec := e.member.call("DELETE", "/v1/me/oauth-grants/"+grants[0].Id.String(), nil, nil, nil)
	mustCode(t, "disconnect", code, ec, 200, "")
	q3 := asLoopback(newPKCE(), nil)
	if res, _ = authorize(t, app, e.member, q3); !strings.HasPrefix(res.Header.Get("Location"), "/oauth/consent?") {
		t.Fatalf("after disconnecting = %q", res.Header.Get("Location"))
	}
	if v := view(e.member, q3); !v.Notice || v.Remembered {
		t.Errorf("view after disconnecting = %+v", v)
	}
	consent(t, e.member, q3, "allow")
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'oauth.grant_confirmed'`); n != "2" {
		t.Errorf("oauth.grant_confirmed entries after a second confirmation = %s", n)
	}

	// A client that isn't trusted gets its usual consent page, not the notice.
	plain := e.docs.client("/plain.json", "Plain", "http://localhost/callback")
	if v := view(e.member, authQuery(app, plain, "support", newPKCE(), map[string]string{"redirect_uri": loopback})); v.Notice || v.Client.Trusted {
		t.Errorf("untrusted view = %+v", v)
	}
	// Removing the client from the trusted list sends it back to the usual page.
	trustClients(t, e)
	if v := view(e.owner, asLoopback(newPKCE(), nil)); v.Notice || v.Client.Trusted {
		t.Errorf("after untrusting = %+v", v)
	}
}

// H-8: refresh tokens stop at an absolute lifetime after the person signed
// the app in; signing in again starts a new one.
func TestOAuthRefreshAbsoluteLifetime(t *testing.T) {
	e := newOAuthEnv(t)
	app := e.app
	clientID := e.docs.client("/assistant.json", "Test Assistant", testRedirect)
	refresh := func(token string) (int, map[string]any) {
		status, out, _ := tokenCall(t, app, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {token}})
		return status, out
	}
	authorizedAgo := func(interval string) {
		t.Helper()
		if _, err := app.Pool.Exec(context.Background(), `UPDATE oauth_grants SET authorized_at = now() - $1::interval`, interval); err != nil {
			t.Fatal(err)
		}
	}
	access, refreshToken := connectApp(t, app, e.member, clientID, "support")

	// The Connected apps page says when it expires.
	var grants []apitypes.OAuthGrant
	if code := e.member.get("/v1/me/oauth-grants", &grants); code != 200 || len(grants) != 1 || grants[0].ExpiresAt == nil {
		t.Fatalf("grants = %d %+v", code, grants)
	}
	if d := time.Until(*grants[0].ExpiresAt); d < 179*24*time.Hour || d > 181*24*time.Hour {
		t.Fatalf("expires in %s, want about 180 days", d)
	}

	// 179 days: still fine, and it rotates.
	authorizedAgo("179 days")
	status, out := refresh(refreshToken)
	if status != 200 {
		t.Fatalf("refresh at 179 days = %d %v", status, out)
	}
	refreshToken = out["refresh_token"].(string)
	// 181 days: refused, the connection is revoked with its own reason, the app has to sign in again.
	authorizedAgo("181 days")
	status, out = refresh(refreshToken)
	wantOAuthError(t, "refresh at 181 days", status, out, 400, "invalid_grant")
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'oauth.revoke' AND metadata->>'reason' = 'expired_absolute'`); n != "1" {
		t.Errorf("expiry revocation audit = %s", n)
	}
	if got := e.scalar(`SELECT revoked_reason FROM oauth_grants`); got != "expired_absolute" {
		t.Errorf("revoked_reason = %q", got)
	}
	if code, _, _ := rawMCP(t, app, "POST", "support", access, rpc(1, "tools/list", nil), nil); code != 401 {
		t.Errorf("the old access token = %d", code)
	}
	if code := e.member.get("/v1/me/oauth-grants", &grants); code != 200 || len(grants) != 0 {
		t.Errorf("grants after expiry = %d %+v", code, grants)
	}
	// The person signs in again (the consent was forgotten with the grant): a new lifetime.
	access2, refresh2 := connectApp(t, app, e.member, clientID, "support")
	if code, _, _ := rawMCP(t, app, "POST", "support", access2, rpc(1, "tools/list", nil), nil); code != 200 {
		t.Fatalf("after signing in again = %d", code)
	}
	if status, out = refresh(refresh2); status != 200 {
		t.Fatalf("refresh after signing in again = %d %v", status, out)
	}

	// A remembered grant that is past its lifetime but was never refreshed:
	// signing in again starts a new lifetime (it isn't revoked by that).
	authorizedAgo("181 days")
	p := newPKCE()
	q := authQuery(app, clientID, "support", p, nil)
	res, _ := authorize(t, app, e.member, q) // remembered: straight back with a code
	_, renewed := exchange(t, app, clientID, codeFrom(t, app, "renew", res.Header.Get("Location")), p, nil)
	if status, out = refresh(renewed); status != 200 {
		t.Fatalf("refresh after the grant was renewed = %d %v", status, out)
	}
	if n := e.scalar(`SELECT count(*)::text FROM oauth_grants WHERE revoked_at IS NULL AND authorized_at > now() - interval '1 minute'`); n != "1" {
		t.Errorf("renewed grants = %s", n)
	}
}

// H-8: inside the grace a repeat gets the same pair and mints nothing more;
// the absolute lifetime applies there too; outside it the grant is revoked.
func TestOAuthRefreshGraceReturnsTheSamePair(t *testing.T) {
	e := newOAuthEnv(t)
	app := e.app
	clientID := e.docs.client("/assistant.json", "Test Assistant", testRedirect)
	_, refresh := connectApp(t, app, e.member, clientID, "support")
	call := func(token string) (int, map[string]any) {
		status, out, _ := tokenCall(t, app, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {token}})
		return status, out
	}
	status, first := call(refresh)
	if status != 200 {
		t.Fatalf("refresh = %d %v", status, first)
	}
	tokens := e.scalar(`SELECT count(*)::text FROM oauth_tokens`)
	for i := range 3 {
		status, again := call(refresh)
		if status != 200 || again["access_token"] != first["access_token"] || again["refresh_token"] != first["refresh_token"] {
			t.Fatalf("repeat %d = %d %v, want %v", i+1, status, again, first)
		}
		if exp, _ := again["expires_in"].(float64); exp < 3500 || exp > 3600 {
			t.Errorf("repeat %d expires_in = %v", i+1, again["expires_in"])
		}
	}
	if got := e.scalar(`SELECT count(*)::text FROM oauth_tokens`); got != tokens {
		t.Errorf("tokens before the repeats %s, after %s: a repeat minted more", tokens, got)
	}
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'oauth.token_issue' AND metadata->>'repeat' = 'true'`); n != "3" {
		t.Errorf("repeat audit entries = %s", n)
	}
	// Another person's token gets a pair of its own: a pair is derived from the token presented.
	_, other := connectApp(t, app, e.owner, clientID, "support")
	status, otherOut := call(other)
	if status != 200 || otherOut["refresh_token"] == first["refresh_token"] || otherOut["access_token"] == first["access_token"] {
		t.Fatalf("another person's refresh = %d %v", status, otherOut)
	}
	// The grace is short: a rotated token again after it revokes the grant (and the pair that was issued).
	if _, err := app.Pool.Exec(context.Background(), `UPDATE oauth_tokens SET rotated_at = rotated_at - interval '1 minute' WHERE rotated_at IS NOT NULL`); err != nil {
		t.Fatal(err)
	}
	status, out := call(refresh)
	wantOAuthError(t, "repeat after the grace", status, out, 400, "invalid_grant")
	if status, out = call(first["refresh_token"].(string)); status != 400 {
		t.Errorf("the pair issued for the rotation after a revocation = %d %v", status, out)
	}
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'oauth.revoke' AND metadata->>'reason' = 'refresh_reuse'`); n != "1" {
		t.Errorf("reuse revocations = %s", n)
	}

	// The absolute lifetime also applies to a repeat inside the grace.
	_, r2 := connectApp(t, app, e.member, clientID, "support")
	if status, out = call(r2); status != 200 {
		t.Fatalf("refresh = %d %v", status, out)
	}
	if _, err := app.Pool.Exec(context.Background(), `UPDATE oauth_grants SET authorized_at = now() - interval '200 days' WHERE revoked_at IS NULL AND user_id = $1`, e.userID("blair@localhost")); err != nil {
		t.Fatal(err)
	}
	status, out = call(r2)
	wantOAuthError(t, "repeat past the lifetime", status, out, 400, "invalid_grant")
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'oauth.revoke' AND metadata->>'reason' = 'expired_absolute'`); n != "1" {
		t.Errorf("expiry revocations = %s", n)
	}
}

// H-8: OAUTH_REFRESH_ABSOLUTE_TTL=0 keeps today's behaviour, and the value is honoured.
func TestOAuthRefreshAbsoluteLifetimeConfig(t *testing.T) {
	for name, tc := range map[string]struct {
		ttl    time.Duration
		age    string
		want   int
		expiry bool
	}{
		"off":              {0, "3000 days", 200, false},
		"90 days, inside":  {90 * 24 * time.Hour, "89 days", 200, true},
		"90 days, outside": {90 * 24 * time.Hour, "91 days", 400, true},
	} {
		t.Run(name, func(t *testing.T) {
			e := newOAuthEnvConfig(t, func(c *config.Config) { c.OAuthRefreshAbsoluteTTL = tc.ttl })
			clientID := e.docs.client("/assistant.json", "Test Assistant", testRedirect)
			_, refresh := connectApp(t, e.app, e.member, clientID, "support")
			var grants []apitypes.OAuthGrant
			if code := e.member.get("/v1/me/oauth-grants", &grants); code != 200 || len(grants) != 1 || (grants[0].ExpiresAt != nil) != tc.expiry {
				t.Fatalf("grants = %d %+v", code, grants)
			}
			if _, err := e.app.Pool.Exec(context.Background(), `UPDATE oauth_grants SET authorized_at = now() - $1::interval`, tc.age); err != nil {
				t.Fatal(err)
			}
			status, out, _ := tokenCall(t, e.app, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refresh}})
			if status != tc.want {
				t.Fatalf("refresh = %d %v, want %d", status, out, tc.want)
			}
		})
	}
}

// The upgrade from 0.2.1: grants that existed keep working and get one whole
// lifetime from the migration, however old they are; registered clients that
// signed in are kept, ones nobody used are not.
func TestOAuthMigration00018KeepsWhatWorks(t *testing.T) {
	e := newOAuthEnv(t)
	app := e.app
	ctx := context.Background()
	clientID := e.docs.client("/assistant.json", "Test Assistant", testRedirect)
	_, refresh := connectApp(t, app, e.member, clientID, "support")
	register := func(name string) string {
		_, out, _ := jsonPost(t, app, "/oauth/register", map[string]any{"client_name": name, "redirect_uris": []string{testRedirect}})
		return out["client_id"].(string)
	}
	used, unused := register("Used"), register("Unused")
	p := newPKCE()
	q := authQuery(app, used, "support", p, nil)
	exchange(t, app, used, codeFrom(t, app, "used", consent(t, e.member, q, "allow")), p, nil)

	// Go back to the schema of 0.2.1 (this also runs the migration's Down) and
	// make the data look like an old installation.
	db := stdlib.OpenDBFromPool(app.Pool)
	defer db.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(ctx, 17); err != nil {
		t.Fatalf("down: %v", err)
	}
	for _, stmt := range []string{
		`UPDATE oauth_grants SET created_at = now() - interval '400 days'`,
		`UPDATE oauth_clients SET created_at = now() - interval '200 days', last_used_at = now() - interval '10 days' WHERE client_id = '` + used + `'`,
		`UPDATE oauth_clients SET created_at = now() - interval '3 days' WHERE client_id = '` + unused + `'`,
	} {
		if _, err := app.Pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("up: %v", err)
	}

	if n := e.scalar(`SELECT count(*)::text FROM oauth_grants WHERE authorized_at > now() - interval '1 minute'`); n != "2" {
		t.Errorf("grants with a fresh lifetime = %s, want 2 (both active grants)", n)
	}
	status, out, _ := tokenCall(t, app, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refresh}})
	if status != 200 {
		t.Fatalf("a 400-day-old grant after the upgrade = %d %v", status, out)
	}
	if n := e.scalar(`SELECT count(*)::text FROM oauth_clients WHERE authorized_at IS NOT NULL AND client_id = $1`, used); n != "1" {
		t.Errorf("the registered client that signed in lost its standing")
	}
	res, _ := authorize(t, app, e.member, authQuery(app, used, "support", newPKCE(), nil))
	if loc := res.Header.Get("Location"); !strings.HasPrefix(loc, "/oauth/consent?") && !strings.Contains(loc, "code=") {
		t.Errorf("the used registration after the upgrade = %d %q", res.StatusCode, loc)
	}
	res, body := authorize(t, app, e.member, authQuery(app, unused, "support", newPKCE(), nil))
	wantPage(t, "a registration nobody used for 3 days", res, body, "invalid_client")
	// Open registration stays on.
	var tc apitypes.TrustedClients
	if code := e.admin.get("/v1/admin/settings/oauth-clients", &tc); code != 200 || !tc.OpenRegistration {
		t.Errorf("settings after the upgrade = %d %+v", code, tc)
	}
}
