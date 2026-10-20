package httpapi_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/app"
	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

type testApp struct {
	t      *testing.T
	URL    string
	Pool   *pgxpool.Pool
	Client *http.Client
}

var (
	tlsRootsOnce sync.Once
	tlsRoots     *x509.CertPool
)

// testTLSRoots is the CA pool that trusts httptest's TLS servers (they all
// share one certificate, valid for 127.0.0.1, ::1 and example.com).
func testTLSRoots() *x509.CertPool {
	tlsRootsOnce.Do(func() {
		srv := httptest.NewTLSServer(http.NotFoundHandler())
		defer srv.Close()
		tlsRoots = srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	})
	return tlsRoots
}

// testWeb stands in for the built UI.
var testWeb = fstest.MapFS{
	"index.html": {Data: []byte("<!doctype html><html><head><title>x</title></head><body><div id=root></div></body></html>")},
}

// newTestApp serves the whole app over a fresh database, with development
// sign-in on (the test server's URL is loopback).
func newTestApp(t *testing.T, mutate func(*config.Config)) *testApp {
	t.Helper()
	return newTestAppLog(t, mutate, testutil.Logger())
}

// newTestAppLog is newTestApp logging to log.
func newTestAppLog(t *testing.T, mutate func(*config.Config), log *slog.Logger) *testApp {
	t.Helper()
	return newTestAppDeps(t, mutate, log, nil)
}

// newTestAppDeps is newTestAppLog with a hook that adjusts the services
// before the handler is built (nil: none).
func newTestAppDeps(t *testing.T, mutate func(*config.Config), log *slog.Logger, hook func(*httpapi.Deps)) *testApp {
	t.Helper()
	pool, _ := testutil.NewDB(t)
	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)

	cfg := config.Defaults()
	cfg.AppURL, cfg.DevAuth = srv.URL, true
	cfg.DatabaseURL = "unused"
	cfg.EncryptionKey, cfg.APIKeyPepper = testEncryptionKey, testPepper
	cfg.RequestsPerMinute, cfg.LoginAttemptsPerMinute = 100_000, 100_000
	if mutate != nil {
		mutate(&cfg)
	}
	if err := cfg.Validate("serve"); err != nil {
		t.Fatal(err)
	}
	deps, err := app.NewDeps(cfg, pool, log)
	if err != nil {
		t.Fatal(err)
	}
	// Trusted agent platforms' keys are fetched over https only: the test
	// issuers are httptest TLS servers, whose certificate the app trusts here
	// (a test seam; the production rule is unchanged).
	deps.AgentPlatforms.TLS = &tls.Config{RootCAs: testTLSRoots()}
	deps.Health = httpapi.NewHealth(map[string]func(context.Context) error{"postgres": pool.Ping})
	deps.Web, deps.WebBuilt = testWeb, true
	if hook != nil {
		hook(&deps)
	}
	handler = httpapi.NewAPIHandler(deps)

	jar, _ := cookiejar.New(nil)
	return &testApp{t: t, URL: srv.URL, Pool: pool, Client: &http.Client{Jar: jar}}
}

func (a *testApp) do(method, path string, body any, headers map[string]string) (int, []byte) {
	a.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, a.URL+path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", a.URL)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := a.Client.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

func (a *testApp) devLogin(account string) {
	a.t.Helper()
	if code, body := a.do("POST", "/auth/dev", map[string]string{"account": account}, nil); code != 200 {
		a.t.Fatalf("dev login %s: %d %s", account, code, body)
	}
}

func (a *testApp) me() (int, apitypes.Me) {
	a.t.Helper()
	code, body := a.do("GET", "/v1/me", nil, nil)
	var env struct{ Data apitypes.Me }
	if code == 200 {
		if err := json.Unmarshal(body, &env); err != nil {
			a.t.Fatal(err)
		}
	}
	return code, env.Data
}

func errorCode(body []byte) string {
	var env struct{ Error struct{ Code string } }
	_ = json.Unmarshal(body, &env)
	return env.Error.Code
}

func auditActionsInDB(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var actions []string
	rows, err := pool.Query(context.Background(), "SELECT action FROM audit_log ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	return strings.Join(actions, ",")
}

func TestDevLoginSessionAndCSRF(t *testing.T) {
	app := newTestApp(t, nil)
	if code, _ := app.me(); code != 401 {
		t.Fatalf("anonymous /v1/me = %d, want 401", code)
	}
	// optional=true: signed out is data null, not a 401.
	if code, body := app.do("GET", "/v1/me?optional=true", nil, nil); code != 200 || strings.TrimSpace(string(body)) != `{"data":null}` {
		t.Fatalf("anonymous optional /v1/me = %d %s", code, body)
	}
	app.devLogin("admin")
	if code, body := app.do("GET", "/v1/me?optional=true", nil, nil); code != 200 || !strings.Contains(string(body), "admin@localhost") {
		t.Fatalf("signed-in optional /v1/me = %d %s", code, body)
	}
	code, me := app.me()
	if code != 200 || !me.Capabilities.PlatformAdmin || me.Capabilities.PlatformAuditor || me.User.Email != "admin@localhost" || me.CsrfToken == "" {
		t.Fatalf("me = %d %+v", code, me)
	}

	if code, body := app.do("POST", "/auth/logout", nil, nil); code != 403 || errorCode(body) != "csrf_failed" {
		t.Fatalf("logout without CSRF = %d %s", code, body)
	}
	if code, _ := app.do("POST", "/auth/logout", nil, map[string]string{"X-CSRF-Token": me.CsrfToken, "Origin": "https://evil.example"}); code != 403 {
		t.Fatalf("cross-origin logout = %d, want 403", code)
	}
	if code, body := app.do("POST", "/auth/logout", nil, map[string]string{"X-CSRF-Token": me.CsrfToken}); code != 200 {
		t.Fatalf("logout = %d %s", code, body)
	}
	if code, _ := app.me(); code != 401 {
		t.Fatalf("after logout /v1/me = %d, want 401", code)
	}
	if got := auditActionsInDB(t, app.Pool); got != "platform.bootstrap_role,auth.login,auth.logout" {
		t.Fatalf("audit actions = %s", got)
	}
}

// Only the SHA-256 of the session secret is stored, never the cookie value.
func TestSessionSecretIsStoredAsDigest(t *testing.T) {
	app := newTestApp(t, nil)
	app.devLogin("user")
	var cookie string
	for _, c := range app.Client.Jar.Cookies(mustParse(t, app.URL)) {
		if c.Name == "omp_session" {
			cookie = c.Value
		}
	}
	if cookie == "" {
		t.Fatal("no session cookie")
	}
	var digest string
	if err := app.Pool.QueryRow(context.Background(), "SELECT token_digest FROM sessions").Scan(&digest); err != nil {
		t.Fatal(err)
	}
	if digest == cookie || len(digest) != 64 {
		t.Fatalf("stored token %q for cookie %q", digest, cookie)
	}
	// A bearer token is never accepted in place of the cookie.
	if code, _ := app.do("GET", "/v1/me", nil, map[string]string{"Authorization": "Bearer " + cookie}); code != 401 {
		t.Fatalf("bearer accepted: %d", code)
	}
}

func TestDevPersonaRoles(t *testing.T) {
	app := newTestApp(t, nil)
	for account, want := range map[string]apitypes.PlatformRole{"auditor": "platform_auditor", "user": "none", "casey": "none"} {
		app.devLogin(account)
		if _, me := app.me(); me.User.PlatformRole != want {
			t.Errorf("%s role = %s, want %s", account, me.User.PlatformRole, want)
		}
	}
	if code, body := app.do("POST", "/auth/dev", map[string]string{"account": "root"}, nil); code != 400 || errorCode(body) != "unknown_account" {
		t.Errorf("unknown persona = %d %s", code, body)
	}
	if code, body := app.do("POST", "/auth/dev", map[string]any{"account": "user", "role": "platform_admin"}, nil); code != 400 || errorCode(body) != "invalid_json" {
		t.Errorf("unknown field = %d %s", code, body)
	}
	if code, body := app.do("POST", "/auth/dev", map[string]string{"account": "admin"}, map[string]string{"Origin": "https://evil.example"}); code != 403 {
		t.Errorf("cross-origin dev login = %d %s", code, body)
	}
}

func TestDevLoginDisabledOutsideDevAuth(t *testing.T) {
	p := testutil.NewOIDCProvider(t)
	app := newTestApp(t, func(c *config.Config) {
		c.DevAuth = false
		c.OIDC.Issuer, c.OIDC.ClientID, c.OIDC.ClientSecret = p.URL, p.ClientID, p.ClientSecret
	})
	if code, _ := app.do("POST", "/auth/dev", map[string]string{"account": "admin"}, nil); code != 404 {
		t.Fatalf("dev login without DEV_AUTH = %d, want 404", code)
	}
}

func TestBootstrapRoleIsGrantedOnlyOnce(t *testing.T) {
	app := newTestApp(t, nil)
	app.devLogin("admin")
	if _, err := app.Pool.Exec(context.Background(), "UPDATE users SET platform_role = 'none' WHERE email = 'admin@localhost'"); err != nil {
		t.Fatal(err)
	}
	app.devLogin("admin")
	if _, me := app.me(); me.Capabilities.PlatformAdmin {
		t.Fatal("signing in again re-granted a deliberately removed admin role")
	}
}

func TestSuspendedUserIsBlocked(t *testing.T) {
	app := newTestApp(t, nil)
	app.devLogin("user")
	if _, err := app.Pool.Exec(context.Background(), "UPDATE users SET status = 'suspended' WHERE email = 'user@localhost'"); err != nil {
		t.Fatal(err)
	}
	if code, body := app.do("GET", "/v1/me", nil, nil); code != 403 || errorCode(body) != "user_suspended" {
		t.Fatalf("existing session of suspended user = %d %s", code, body)
	}
	if code, body := app.do("POST", "/auth/dev", map[string]string{"account": "user"}, nil); code != 403 || errorCode(body) != "user_suspended" {
		t.Fatalf("suspended sign-in = %d %s", code, body)
	}
}

func oidcApp(t *testing.T, mutate func(*config.Config)) (*testApp, *testutil.OIDCProvider) {
	p := testutil.NewOIDCProvider(t)
	app := newTestApp(t, func(c *config.Config) {
		c.DevAuth = false
		c.OIDC.Issuer, c.OIDC.ClientID, c.OIDC.ClientSecret = p.URL, p.ClientID, p.ClientSecret
		if mutate != nil {
			mutate(c)
		}
	})
	return app, p
}

func TestOIDCLoginFlow(t *testing.T) {
	app, p := oidcApp(t, func(c *config.Config) {
		c.OIDC.BootstrapAdminSubject = "boss-sub"
		c.OIDC.AllowedEmailDomains = []string{"example.com"}
	})
	p.SetClaims(map[string]any{
		"sub": "boss-sub", "email": "Boss@EXAMPLE.com", "email_verified": true,
		"given_name": "Robin", "family_name": "Morgan", "department": []string{"platform"},
		"groups": []any{"sre", "everyone", "", "sre", 7},
	})
	res, err := app.Client.Get(app.URL + "/auth/login?next=/admin/teams")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.Request.URL.Path != "/admin/teams" {
		t.Fatalf("post-login redirect landed on %s", res.Request.URL)
	}
	code, me := app.me()
	if code != 200 || me.User.Email != "boss@example.com" || me.User.DisplayName != "Robin Morgan" || !me.Capabilities.PlatformAdmin {
		t.Fatalf("me = %d %+v", code, me)
	}
	var dept string
	err = app.Pool.QueryRow(context.Background(),
		"SELECT claims->'department'->>0 FROM users WHERE email = 'boss@example.com'").Scan(&dept)
	if err != nil || dept != "platform" {
		t.Fatalf("claims not stored: %q %v", dept, err)
	}
	// The groups claim is stored (valid, distinct entries) for group grants.
	var groups string
	if err := app.Pool.QueryRow(context.Background(),
		"SELECT array_to_string(groups, ',') FROM users WHERE email = 'boss@example.com'").Scan(&groups); err != nil || groups != "everyone,sre" {
		t.Fatalf("groups = %q %v", groups, err)
	}
	// The sign-in state is single-use.
	var pending int
	if err := app.Pool.QueryRow(context.Background(), "SELECT count(*) FROM login_states").Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("login states left = %d %v", pending, err)
	}
	// Signing in again as the same (issuer, subject) keeps one account.
	res, err = app.Client.Get(app.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	var users int
	if err := app.Pool.QueryRow(context.Background(), "SELECT count(*) FROM users").Scan(&users); err != nil || users != 1 {
		t.Fatalf("users = %d %v", users, err)
	}
}

// An invite to a verified address becomes a membership at sign-in.
func TestOIDCSignInAcceptsInvites(t *testing.T) {
	app, p := oidcApp(t, nil)
	ctx := context.Background()
	var teamID string
	if err := app.Pool.QueryRow(ctx, "INSERT INTO teams (slug, name) VALUES ('tools', 'Tools') RETURNING id").Scan(&teamID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Pool.Exec(ctx, "INSERT INTO team_invites (team_id, email, role, expires_at) VALUES ($1, 'new@example.com', 'editor', now() + interval '1 day')", teamID); err != nil {
		t.Fatal(err)
	}
	p.SetClaims(map[string]any{"sub": "n1", "email": "NEW@example.com", "email_verified": true})
	res, err := app.Client.Get(app.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if _, me := app.me(); len(me.Teams) != 1 || me.Teams[0].Slug != "tools" || me.Teams[0].Role != "editor" {
		t.Fatalf("teams = %+v", me.Teams)
	}
}

func TestOIDCOpenRedirectBlocked(t *testing.T) {
	// Each next value would, after sign-in, send the browser off the site: directly, or once the browser drops
	// the tab or newline from "Location: /\t/evil.example" (F-4).
	for _, next := range []string{"//evil.example/steal", "/\t/evil.example", "/%09/evil.example", "/%5cevil.example", "/%2F/evil.example"} {
		app, p := oidcApp(t, nil)
		p.SetClaims(map[string]any{"sub": "u1", "email": "u1@example.com", "email_verified": true})
		res, err := app.Client.Get(app.URL + "/auth/login?next=" + url.QueryEscape(next))
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.Request.URL.Host != strings.TrimPrefix(app.URL, "http://") || res.Request.URL.Path != "/" {
			t.Fatalf("next %q: redirected to %s", next, res.Request.URL)
		}
	}
}

func TestOIDCRejections(t *testing.T) {
	cases := []struct {
		name     string
		claims   map[string]any
		wantCode string
	}{
		{"unverified email", map[string]any{"sub": "a", "email": "a@example.com", "email_verified": false}, "email_required"},
		{"missing email", map[string]any{"sub": "b"}, "email_required"},
		{"domain not allowed", map[string]any{"sub": "c", "email": "c@gmail.com", "email_verified": "true"}, "domain_denied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, p := oidcApp(t, func(c *config.Config) { c.OIDC.AllowedEmailDomains = []string{"example.com"} })
			p.SetClaims(tc.claims)
			res, err := app.Client.Get(app.URL + "/auth/login")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode != 403 || errorCode(body) != tc.wantCode {
				t.Fatalf("got %d %s, want 403 %s", res.StatusCode, body, tc.wantCode)
			}
			if code, _ := app.me(); code != 401 {
				t.Fatalf("a session was created despite rejection")
			}
		})
	}
}

func TestOIDCCallbackRequiresMatchingState(t *testing.T) {
	app, _ := oidcApp(t, nil)
	code, body := app.do("GET", "/auth/callback?code=x&state="+strings.Repeat("a", 43), nil, nil)
	if code != 400 || errorCode(body) != "invalid_state" {
		t.Fatalf("forged callback = %d %s", code, body)
	}
	// Without OIDC configured, login is a 404.
	devApp := newTestApp(t, nil)
	if code, body := devApp.do("GET", "/auth/login", nil, nil); code != 404 || errorCode(body) != "oidc_disabled" {
		t.Fatalf("login without OIDC = %d %s", code, body)
	}
}

func TestAuditLogIsAppendOnly(t *testing.T) {
	app := newTestApp(t, nil)
	app.devLogin("user")
	ctx := context.Background()
	if _, err := app.Pool.Exec(ctx, "UPDATE audit_log SET action = 'x'"); err == nil {
		t.Fatal("audit_log UPDATE succeeded")
	}
	if _, err := app.Pool.Exec(ctx, "DELETE FROM audit_log"); err == nil {
		t.Fatal("audit_log DELETE succeeded without purge flag")
	}
	tx, err := app.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	// omp.audit_purge is the setting a retention job sets for its transaction.
	if _, err := tx.Exec(ctx, "SELECT set_config('omp.audit_purge', 'on', true)"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "DELETE FROM audit_log"); err != nil {
		t.Fatalf("retention purge rejected: %v", err)
	}
	// The setting's name before the rename (migration 00013) still works, for
	// a previous release during a rolling update.
	_ = tx.Rollback(ctx)
	old, err := app.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Rollback(ctx)
	if _, err := old.Exec(ctx, "SELECT set_config('omg.audit_purge', 'on', true)"); err != nil {
		t.Fatal(err)
	}
	if tag, err := old.Exec(ctx, "DELETE FROM audit_log"); err != nil || tag.RowsAffected() == 0 {
		t.Fatalf("purge with the old setting = %v, %v", tag, err)
	}
}

// The public auth config carries the instance identity for the SPA.
func TestAuthConfigInstance(t *testing.T) {
	get := func(app *testApp) apitypes.AuthConfig {
		t.Helper()
		app.Client.Jar = nil // anonymous
		code, body := app.do("GET", "/v1/auth/config", nil, nil)
		var env struct{ Data apitypes.AuthConfig }
		if code != 200 || json.Unmarshal(body, &env) != nil {
			t.Fatalf("auth config = %d %s", code, body)
		}
		return env.Data
	}
	c := get(newTestApp(t, nil))
	d := c.Instance
	if d.Name != "Open MCP Portal" || d.OrgName != "" || d.Theme != apitypes.Neutral || d.LogoUrl != nil || d.SupportUrl != nil {
		t.Errorf("default instance = %+v", d)
	}
	if !c.DevAuthEnabled || c.OidcEnabled || c.LoginUrl != "/auth/login" || len(c.DevAccounts) != 6 || c.TeamRequestUrl != nil {
		t.Errorf("config = %+v", c)
	}
	c = get(newTestApp(t, func(c *config.Config) {
		c.Instance = config.Instance{Name: "Tools Hub", OrgName: "Example Corp", Theme: "neutral",
			LogoURL: "/brand/logo.svg", SupportURL: "mailto:mcp-help@example.com"}
		c.TeamRequestURL = "https://help.example.com/new-team"
	}))
	in := c.Instance
	if in.Name != "Tools Hub" || in.OrgName != "Example Corp" || in.Theme != apitypes.Neutral ||
		in.LogoUrl == nil || *in.LogoUrl != "/brand/logo.svg" || in.SupportUrl == nil || *in.SupportUrl != "mailto:mcp-help@example.com" {
		t.Errorf("instance = %+v", in)
	}
	if c.TeamRequestUrl == nil || *c.TeamRequestUrl != "https://help.example.com/new-team" {
		t.Errorf("config = %+v", c)
	}
}

// The development sign-in list shows the personas as the dev data has them,
// and signing in again keeps a renamed persona's name and email.
func TestDevPersonasKeepTheirNames(t *testing.T) {
	app := newTestApp(t, nil)
	app.devLogin("alex")
	if _, err := app.Pool.Exec(context.Background(),
		"UPDATE users SET display_name = 'Priya Shah', email = 'priya.shah@example.com' WHERE oidc_issuer = 'open-mcp-portal:development' AND oidc_subject = 'alex'"); err != nil {
		t.Fatal(err)
	}
	code, body := app.do("GET", "/v1/auth/config", nil, nil)
	var env struct{ Data apitypes.AuthConfig }
	if code != 200 || json.Unmarshal(body, &env) != nil {
		t.Fatalf("auth config = %d %s", code, body)
	}
	names := map[string]string{}
	for _, a := range env.Data.DevAccounts {
		names[a.Id] = a.Name + " <" + a.Email + ">"
	}
	if names["alex"] != "Priya Shah <priya.shah@example.com>" || names["casey"] != "Casey Dev <casey@localhost>" {
		t.Fatalf("dev accounts = %v", names)
	}
	app.devLogin("alex")
	if _, me := app.me(); me.User.DisplayName != "Priya Shah" || me.User.Email != "priya.shah@example.com" {
		t.Fatalf("after signing in again: %s <%s>", me.User.DisplayName, me.User.Email)
	}
}

// Operational endpoints, security headers and the SPA fallback through the
// whole stack.
func TestOpsAndSPA(t *testing.T) {
	app := newTestApp(t, nil)
	for _, p := range []string{"/healthz", "/readyz"} {
		if code, body := app.do("GET", p, nil, nil); code != 200 || !strings.Contains(string(body), `"status":"ok"`) {
			t.Errorf("%s = %d %s", p, code, body)
		}
	}
	res, err := app.Client.Get(app.URL + "/teams/tools")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("X-Request-ID") == "" || !strings.Contains(res.Header.Get("Content-Security-Policy"), "default-src 'self'") ||
		res.Header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("spa = %d %v", res.StatusCode, res.Header)
	}
	if code, body := app.do("GET", "/v1/nope", nil, nil); code != 404 || errorCode(body) != "not_found" {
		t.Errorf("unknown API path = %d %s", code, body)
	}
}
