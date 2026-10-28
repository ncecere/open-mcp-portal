package httpapi_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// OAuth sign-in for MCP clients (docs/phase4-client-auth.md,
// docs/connect-clients.md), end to end with a fake public client whose
// Client ID Metadata Documents a local TLS server serves.

// docResponse is what the document server answers on one path.
type docResponse struct {
	status      int
	contentType string
	body        string
	redirect    string
}

// docServer serves client metadata documents over TLS.
type docServer struct {
	*httptest.Server
	mu    sync.Mutex
	paths map[string]docResponse
	hits  map[string]int
}

func newDocServer(t *testing.T) *docServer {
	d := &docServer{paths: map[string]docResponse{}, hits: map[string]int{}}
	d.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		res, ok := d.paths[r.URL.Path]
		d.hits[r.URL.Path]++
		d.mu.Unlock()
		switch {
		case !ok:
			http.NotFound(w, r)
		case res.redirect != "":
			http.Redirect(w, r, res.redirect, http.StatusFound)
		default:
			w.Header().Set("Content-Type", res.contentType)
			w.WriteHeader(res.status)
			_, _ = io.WriteString(w, res.body)
		}
	}))
	t.Cleanup(d.Close)
	return d
}

func (d *docServer) set(path string, r docResponse) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.paths[path] = r
	return d.URL + path
}

// client publishes a metadata document for a client and returns its ID.
func (d *docServer) client(path, name string, redirects ...string) string {
	id := d.URL + path
	b, _ := json.Marshal(map[string]any{"client_id": id, "client_name": name, "client_uri": "https://assistant.example.com",
		"redirect_uris": redirects, "token_endpoint_auth_method": "none"})
	return d.set(path, docResponse{status: 200, contentType: "application/json", body: string(b)})
}

func (d *docServer) hitCount(path string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.hits[path]
}

// trustDocs makes the app's metadata fetches trust the document server's
// certificate (the address guard stays: the development allowance lets
// them reach 127.0.0.1).
func trustDocs(d *docServer) func(*httpapi.Deps) {
	return func(deps *httpapi.Deps) {
		deps.OAuth.SetMetadataTLS(&tls.Config{RootCAs: d.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs})
	}
}

// pkce is a verifier and its S256 challenge.
type pkce struct{ verifier, challenge string }

func newPKCE() pkce {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	v := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(v))
	return pkce{verifier: v, challenge: base64.RawURLEncoding.EncodeToString(sum[:])}
}

const testRedirect = "http://127.0.0.1:4567/callback"

// authQuery is an authorization request of a client for a gateway, with
// overrides ("" deletes a parameter).
func authQuery(app *testApp, clientID, slug string, p pkce, over map[string]string) url.Values {
	q := url.Values{"client_id": {clientID}, "redirect_uri": {testRedirect}, "response_type": {"code"}, "code_challenge": {p.challenge},
		"code_challenge_method": {"S256"}, "resource": {app.URL + "/mcp/" + slug}, "state": {"st-1"}}
	for k, v := range over {
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
	}
	return q
}

func noFollow(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// authorize calls the authorization endpoint as a browser (s: signed in,
// nil: signed out) without following its redirect.
func authorize(t *testing.T, app *testApp, s *session, q url.Values) (*http.Response, string) {
	t.Helper()
	c := &http.Client{CheckRedirect: noFollow}
	if s != nil {
		c.Jar = s.client.Jar
	}
	res, err := c.Get(app.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

// wantPage checks an authorization error shown as a page, never a redirect.
// The page follows the person's color mode: the app's same-origin
// color-mode script (allowed by its CSP, nothing else is) and dark styles.
func wantPage(t *testing.T, what string, res *http.Response, body, code string) {
	t.Helper()
	if res.StatusCode != 400 || res.Header.Get("Location") != "" || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") ||
		!strings.Contains(body, code) {
		t.Errorf("%s = %d %q %s", what, res.StatusCode, res.Header.Get("Location"), body)
	}
	csp := res.Header.Get("Content-Security-Policy")
	if !strings.Contains(body, `<script src="/color-mode.js"></script>`) || !strings.Contains(body, ":root[data-theme=dark]") ||
		!strings.Contains(body, "prefers-color-scheme:dark") || !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("%s: the page doesn't follow the color mode (CSP %q)", what, csp)
	}
}

// wantRedirectError checks an authorization error sent back to the client.
func wantRedirectError(t *testing.T, app *testApp, what string, res *http.Response, code string) {
	t.Helper()
	loc, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != 302 || loc == nil || loc.Scheme+"://"+loc.Host+loc.Path != testRedirect || loc.Query().Get("error") != code ||
		loc.Query().Get("iss") != app.URL || loc.Query().Get("state") != "st-1" {
		t.Errorf("%s = %d %q, want error %s", what, res.StatusCode, res.Header.Get("Location"), code)
	}
}

// codeFrom reads the code of a successful authorization redirect.
func codeFrom(t *testing.T, app *testApp, what, location string) string {
	t.Helper()
	loc, err := url.Parse(location)
	if err != nil || !strings.HasPrefix(location, "http://127.0.0.1:") || loc.Query().Get("code") == "" ||
		loc.Query().Get("iss") != app.URL || loc.Query().Get("error") != "" {
		t.Fatalf("%s: redirect %q", what, location)
	}
	return loc.Query().Get("code")
}

// consent decides on the consent page and returns where the browser goes.
func consent(t *testing.T, s *session, q url.Values, decision string) string {
	t.Helper()
	var out struct {
		RedirectUrl string `json:"redirectUrl"`
	}
	code, ec := s.call("POST", "/v1/oauth/consent", map[string]any{"query": q.Encode(), "decision": decision}, &out, nil)
	mustCode(t, "consent "+decision, code, ec, 200, "")
	return out.RedirectUrl
}

// tokenCall posts to the token endpoint (form-encoded).
func tokenCall(t *testing.T, app *testApp, path string, form url.Values) (int, map[string]any, http.Header) {
	t.Helper()
	res, err := http.PostForm(app.URL+path, form)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return res.StatusCode, out, res.Header
}

func wantOAuthError(t *testing.T, what string, status int, out map[string]any, wantStatus int, code string) {
	t.Helper()
	if status != wantStatus || out["error"] != code {
		t.Errorf("%s = %d %v, want %d %s", what, status, out, wantStatus, code)
	}
}

// exchange redeems a code and returns the access and refresh tokens.
func exchange(t *testing.T, app *testApp, clientID, code string, p pkce, extra url.Values) (string, string) {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code}, "code_verifier": {p.verifier},
		"redirect_uri": {testRedirect}}
	for k, v := range extra {
		form[k] = v
	}
	status, out, hdr := tokenCall(t, app, "/oauth/token", form)
	access, _ := out["access_token"].(string)
	refresh, _ := out["refresh_token"].(string)
	if status != 200 || !strings.HasPrefix(access, "ompat_") || !strings.HasPrefix(refresh, "omprt_") || out["token_type"] != "Bearer" ||
		out["expires_in"] != float64(3600) || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("exchange = %d %v", status, out)
	}
	return access, refresh
}

// connectApp signs a client in to a gateway (allowing it on the consent
// page unless it is remembered or trusted) and returns its tokens.
func connectApp(t *testing.T, app *testApp, s *session, clientID, slug string) (string, string) {
	t.Helper()
	p := newPKCE()
	q := authQuery(app, clientID, slug, p, nil)
	res, _ := authorize(t, app, s, q)
	loc := res.Header.Get("Location")
	if strings.HasPrefix(loc, "/oauth/consent?") {
		loc = consent(t, s, q, "allow")
	}
	return exchange(t, app, clientID, codeFrom(t, app, "connect "+slug, loc), p, nil)
}

// oauthEnv is a runtime environment (team gateway "support", platform
// gateway "shared" granted to blair, both selecting whoami) with a
// document server whose certificate the app trusts.
type oauthEnv struct {
	*rtEnv
	docs *docServer
	logs *syncBuffer
}

func newOAuthEnv(t *testing.T) *oauthEnv {
	docs := newDocServer(t)
	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return &oauthEnv{rtEnv: newRuntimeEnvHook(t, log, trustDocs(docs)), docs: docs, logs: logs}
}

func getRaw(t *testing.T, u string) (int, http.Header, []byte) {
	t.Helper()
	res, err := (&http.Client{CheckRedirect: noFollow}).Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, b
}

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

func jsonPost(t *testing.T, app *testApp, path string, body any) (int, map[string]any, http.Header) {
	t.Helper()
	b, _ := json.Marshal(body)
	res, err := http.Post(app.URL+path, "application/json", strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return res.StatusCode, out, res.Header
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
